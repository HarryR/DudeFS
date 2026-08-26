from __future__ import annotations

from dataclasses import dataclass, field, replace

from .. import quorum
from ..consensus.canonical import bodies_canonical
from ..consensus.settle_round import (
    Anchors,
    SettledBlock,
    SettledBlockWithBodies,
    genesis_stamp,
)
from ..core import crypto
from ..core.errors import DudeError, InvariantError
from ..core.units import Millis
from ..store import Layer, Store, settle
from ..store.layer import Index
from ..store.management import MgmtReader
from ..store.ops import SignedTransaction
from ..store.store import log_element
from ..tunables import Tunables
from . import chain
from .adapter import (
    GetBlocks,
    HeightAsk,
    HeightReply,
    Refused,
    SettledBlockReply,
    SyncMsg,
    SyncRefusal,
)


class FollowerError(DudeError): ...


@dataclass(frozen=True, slots=True)
class HeightReport:
    block_num: Index
    tip_hash: crypto.Digest
    at: Millis


@dataclass(frozen=True, slots=True)
class PullInFlight:
    peer: crypto.PublicKey
    frm: Index
    count: int
    sent_at: Millis


type OutboxItem = tuple[crypto.PublicKey, SyncMsg]


@dataclass(slots=True)
class Follower:
    me: crypto.Keypair
    store: Store
    mgmt_reader: MgmtReader
    tunables: Tunables
    _heads: dict[crypto.PublicKey, HeightReport] = field(default_factory=dict)
    _poll_at: dict[crypto.PublicKey, Millis] = field(default_factory=dict)
    _pulling: PullInFlight | None = None
    _last_ok_at: dict[crypto.PublicKey, Millis] = field(default_factory=dict)
    _last_fail_at: dict[crypto.PublicKey, Millis] = field(default_factory=dict)
    _outbox: list[OutboxItem] = field(default_factory=list)
    _compacted_at: dict[crypto.PublicKey, int] = field(default_factory=dict)

    def add_peer(self, peer: crypto.PublicKey, now: Millis) -> None:
        if peer == self.me.public or peer in self._poll_at:
            return
        self._poll_at[peer] = now

    def remove_peer(self, peer: crypto.PublicKey) -> None:
        self._poll_at.pop(peer, None)
        self._heads.pop(peer, None)
        self._last_ok_at.pop(peer, None)
        self._last_fail_at.pop(peer, None)
        if self._pulling is not None and self._pulling.peer == peer:
            self._pulling = None

    def receive(self, msg: SyncMsg, from_: crypto.PublicKey, now: Millis) -> None:
        if from_ == self.me.public:
            return
        if isinstance(msg, HeightReply):
            self._on_height_reply(msg, from_, now)
        elif isinstance(msg, SettledBlockReply):
            self._on_settled_blocks(msg, from_, now)
        elif isinstance(msg, Refused):
            self._on_refused(msg, from_, now)

    def cancel_pull(self, from_: crypto.PublicKey, now: Millis) -> None:
        if self._pulling is not None and self._pulling.peer == from_:
            self._pulling = None
            self._last_fail_at[from_] = now

    def tick(self, now: Millis) -> None:
        for peer, deadline in list(self._poll_at.items()):
            if now >= deadline:
                self._enqueue(peer, HeightAsk())
                self._poll_at[peer] = now + self.tunables.poll_interval
        p = self._pulling
        if p is not None and now - p.sent_at > self.tunables.pull_timeout:
            self._last_fail_at[p.peer] = now
            self._pulling = None
        if self._pulling is None:
            source = self._pick_pull_source()
            if source is not None:
                self._pull_from(source, now)

    def _pull_from(self, peer: crypto.PublicKey, now: Millis) -> None:
        frm = (self.store.head_block_num() or 0) + 1
        count = self.tunables.pull_batch
        self._enqueue(peer, GetBlocks(frm=frm, count=count))
        self._pulling = PullInFlight(peer, frm, count, now)

    def outbox(self) -> tuple[OutboxItem, ...]:
        drained = tuple(self._outbox)
        self._outbox.clear()
        return drained

    def behind(self, now: Millis) -> bool:
        """`f+1` LIVE witnesses reporting a head ABOVE ours. POSITIVE EVIDENCE, in this direction:
        silence, empty roster, and stale reports all answer False, so a node with no data keeps
        working. Flipping to "f+1 AGREEING with our tip" couples liveness to the height-poll loop
        -- reports age out between buckets and every node quietly stops leading.

        Freshness is the clock's, not the newest report's, or a silent peer vouches for its own
        last word forever. NOT `chain.is_stale`: that gates on the CHAIN advancing, and a stopped
        chain would then prevent any node from restarting it."""
        roster = self.mgmt_reader.roster()
        if not roster:
            return False
        my_num = self.store.head_block_num() or 0
        ahead = 0
        for peer, hr in self._heads.items():
            if peer not in roster:
                continue
            if now - hr.at > self.tunables.freshness_window:
                continue
            if hr.block_num > my_num:
                ahead += 1
        return ahead >= quorum.corroboration(len(roster))

    def _head_bucket(self) -> int:
        n = self.store.head_block_num()
        raw = self.store.settled_at(n) if n is not None else None
        if raw is None:
            return chain.NO_BUCKET
        return SettledBlock.decode(raw).block.bucket

    def _on_height_reply(self, msg: HeightReply, from_: crypto.PublicKey, now: Millis) -> None:
        # NOT credited to `_last_ok_at`: that is the pull-source priority, and answering a poll
        # is not serving a block. Credited here, a peer keeps top priority by replying while
        # failing every pull, and a joiner retries it forever.
        self._heads[from_] = HeightReport(msg.block_num, msg.tip_hash, now)

    def _on_settled_blocks(
        self, msg: SettledBlockReply, from_: crypto.PublicKey, now: Millis
    ) -> None:
        # Only from the peer we asked. An unsolicited run of state, applied, was a real break:
        # a stranger with no grant and no roster seat added itself to a catching-up node's
        # roster with one frame.
        p = self._pulling
        if p is None or from_ != p.peer:
            return
        self._pulling = None
        served = 0
        for offer in msg.payload:
            if offer.block.anchors.block_num != p.frm + served or not self._adopt(offer):
                # A fail mark, NOT a shun (#no-shun-only-priority): the peer stays a candidate
                # and this only orders it behind peers that have not failed. Without it, a
                # peer that SERVES unverifiable blocks -- unlike one that refuses -- kept its
                # claimed head and kept winning the pick, and a fresh joiner with one such
                # peer above it never asked the honest sources at all.
                self._last_fail_at[from_] = now
                return
            served += 1
        if served == 0:
            return
        self._last_ok_at[from_] = now

    def _adopt(self, offer: SettledBlockWithBodies) -> bool:
        """One block: link, quorum proof, bodies, replay, commit. Per block rather than per
        range, because the roster comes from the log and only committing the previous block
        makes its roster change visible (#roster-at-ratification)."""
        sb = offer.block
        walked = chain.advance(self._tip(), (sb,), self.mgmt_reader.roster(), self._require_anchor())
        if isinstance(walked, chain.ChainRefusal):
            return False
        # Equality: a block names exactly what it applied, so bodies short of the hash list
        # mean a withholding sender and a state_root we never saw.
        if frozenset(tx.op_hash for tx in offer.bodies) != frozenset(sb.block.hashes):
            return False
        for tx in offer.bodies:
            if not tx.verify():
                return False
        ordered = bodies_canonical(offer.bodies).txs
        if not self._preview_matches_signed_anchors(ordered, sb.anchors):
            return False
        self.store.commit_block(
            sb.anchors.block_num,
            first_height=self.store.head() + 1,
            block_bytes=sb.encode(),
            block_hash=sb.block_hash,
            batch=ordered,
            auth=self.mgmt_reader,
        )
        return True

    def _on_refused(self, msg: Refused, from_: crypto.PublicKey, now: Millis) -> None:
        p = self._pulling
        if p is None or from_ != p.peer:
            return
        self._pulling = None
        if msg.reason is SyncRefusal.NOT_YET_SETTLED:
            hr = self._heads.get(from_)
            if hr is not None:
                self._heads[from_] = replace(hr, block_num=p.frm - 1)
            source = self._pick_pull_source()
            if source is not None:
                self._pull_from(source, now)
        elif msg.reason is SyncRefusal.COMPACTED and msg.checkpoint_block_num is not None:
            self._compacted_at[from_] = msg.checkpoint_block_num
            self._last_fail_at[from_] = now
        else:
            self._last_fail_at[from_] = now

    def needs_checkpoint(self) -> int | None:
        if not self._compacted_at:
            return None
        my_num = self.store.head_block_num() or 0
        peers_with_heads = {
            p for p in self._heads if self._heads[p].block_num > my_num
        }
        if not peers_with_heads:
            return None
        if all(p in self._compacted_at for p in peers_with_heads):
            return max(self._compacted_at.values())
        return None

    def _enqueue(self, peer: crypto.PublicKey, msg: SyncMsg) -> None:
        self._outbox.append((peer, msg))

    def _pick_pull_source(self) -> crypto.PublicKey | None:
        my_num = self.store.head_block_num() or 0
        candidates = [(peer, hr) for peer, hr in self._heads.items() if hr.block_num > my_num]
        if not candidates:
            return None
        # Fail-recency sits between success-recency and claimed height: a fresh joiner has no
        # ok-history, so height decided alone, and one peer whose pulls always fail -- silent
        # after claiming, or serving garbage -- outbid every honest source forever on the
        # strength of its claim.
        candidates.sort(
            key=lambda p_hr: (
                -self._last_ok_at.get(p_hr[0], 0),
                self._last_fail_at.get(p_hr[0], 0),
                -p_hr[1].block_num,
            )
        )
        return candidates[0][0]

    def _tip(self) -> crypto.Digest:
        return (
            self.store.head_block_hash()
            or genesis_stamp(self._require_anchor())
        )

    def _require_anchor(self) -> crypto.PublicKey:
        anchor = self.store.anchor()
        if anchor is None:
            raise InvariantError("store has no manager anchor; cannot compute genesis stamp")
        return anchor

    def _preview_matches_signed_anchors(
        self,
        bodies: tuple[SignedTransaction, ...],
        expected: Anchors,
    ) -> bool:
        layer = Layer(self.store)
        screened = settle.apply_to(layer, bodies, self.mgmt_reader)
        if screened.rejects:
            return False
        layer.freeze()
        base_head = self.store.head()
        acc_log = self.store.log_accumulator()
        for i, tx in enumerate(screened.survivors):
            acc_log = crypto.acc_add(acc_log, log_element(base_head + i + 1, tx.op_hash))
        computed = Anchors(
            block_num=expected.block_num,
            height=base_head + len(screened.survivors),
            prev_block=expected.prev_block,
            state_root=layer.state_root(),
            acc_state=layer.accumulator(),
            acc_log=acc_log,
        )
        return computed == expected


def serve_height(store: Store) -> HeightReply:
    with store.snapshot() as r:
        tip = r.head_block_hash()
        if tip is None:
            anchor = r.anchor()
            if anchor is None:
                raise InvariantError("serving HEIGHT from a store that was never provisioned")
            tip = genesis_stamp(anchor)
        return HeightReply(block_num=r.head_block_num() or 0, tip_hash=tip)


def serve_getblocks(store: Store, req: GetBlocks, cap: int) -> SyncMsg:
    out: list[SettledBlockWithBodies] = []
    for n in range(req.frm, req.frm + max(0, min(req.count, cap))):
        raw = store.settled_at(n)
        if raw is None:
            break
        out.append(
            SettledBlockWithBodies(block=SettledBlock.decode(raw), bodies=store.bodies_of_block(n))
        )
    if not out:
        oldest = store.oldest_block_num()
        if oldest is not None and req.frm < oldest:
            return Refused(
                reason=SyncRefusal.COMPACTED,
                checkpoint_block_num=oldest,
            )
        return Refused(reason=SyncRefusal.NOT_YET_SETTLED)
    return SettledBlockReply(payload=tuple(out))
