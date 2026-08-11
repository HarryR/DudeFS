from __future__ import annotations

from dataclasses import dataclass, field, replace

from .. import quorum
from ..consensus.canonical import bodies_canonical
from ..consensus.settle_round import (
    Anchors,
    SettledBlock,
    SettledBlockWithBodies,
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
    mgmt: MgmtReader
    tunables: Tunables
    _heads: dict[crypto.PublicKey, HeightReport] = field(default_factory=dict)
    _poll_at: dict[crypto.PublicKey, Millis] = field(default_factory=dict)
    _pulling: PullInFlight | None = None
    _last_ok_at: dict[crypto.PublicKey, Millis] = field(default_factory=dict)
    _last_fail_at: dict[crypto.PublicKey, Millis] = field(default_factory=dict)
    _outbox: list[OutboxItem] = field(default_factory=list)

    def add_peer(self, peer: crypto.PublicKey, now: Millis) -> None:
        if peer == self.me.public:
            return
        self._poll_at[peer] = now

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
        """`f+1` LIVE witnesses reporting a head ABOVE ours. POSITIVE EVIDENCE, and the direction
        is the whole point: silence, an empty roster and reports too old to trust all answer
        False, so a node that knows nothing keeps working.

        Asked the other way round -- `f+1` witnesses AGREEING with our tip -- it reads almost the
        same and fails the opposite way. Gating block production on that couples the cluster's
        liveness to the height-poll loop: reports age out between buckets and every node quietly
        stops leading, which is how it was first written and what made a 3-node cluster produce
        nothing at all.

        Freshness is the clock's, not the newest report's: measured against the reports we happen
        to hold, a peer that fell silent kept vouching for its own last word forever.

        NOT `chain.is_stale`, which asks whether the CHAIN is advancing -- a different fact, and
        one this must not carry: a stopped chain keeps every node's head stale, so gating on it
        would stop every node from restarting the chain."""
        roster = self.mgmt.roster()
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
            return chain.TrustedHead.genesis(self._require_anchor()).bucket
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
        walked = chain.advance(self._tip(), (sb,), self.mgmt.roster(), self._require_anchor())
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
            auth=self.mgmt,
        )
        return True

    def _on_refused(self, msg: Refused, from_: crypto.PublicKey, now: Millis) -> None:
        """EVERY member gets a case, and there is no wildcard: the reason used to be discarded
        outright, which made the refusal a round trip that bought nothing."""
        p = self._pulling
        if p is None or from_ != p.peer:
            return
        self._pulling = None
        match msg.reason:
            case SyncRefusal.NOT_YET_SETTLED:
                # They reported a head above ours and do not have the block. Correct the claim
                # rather than shun them (#no-shun-only-priority) -- which also takes them out of
                # the candidate set, so the immediate retry cannot pick the same peer -- and
                # spend this tick on someone else instead of waiting for the next one.
                hr = self._heads.get(from_)
                if hr is not None:
                    self._heads[from_] = replace(hr, block_num=p.frm - 1)
                source = self._pick_pull_source()
                if source is not None:
                    self._pull_from(source, now)
            case (
                SyncRefusal.INVALID
                | SyncRefusal.UNKNOWN
                | SyncRefusal.NO_STATE
                | SyncRefusal.UNKNOWN_STORE
                | SyncRefusal.MALFORMED_QUERY
                | SyncRefusal.FORK_DETECTED
                | SyncRefusal.INTERNAL
            ):
                pass  # nothing this peer can do for us now; the next tick picks a source

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
        """The hash our next block must chain to. ONE spelling of "no block yet" -- this and
        `serve_height` disagreed, so two fresh nodes read each other as forked."""
        return (
            self.store.head_block_hash()
            or chain.TrustedHead.genesis(self._require_anchor()).block_hash
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
        screened = settle.apply_to(layer, bodies, self.mgmt)
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
    tip = store.head_block_hash()
    if tip is None:
        anchor = store.anchor()
        if anchor is None:
            raise InvariantError("serving HEIGHT from a store that was never provisioned")
        tip = chain.TrustedHead.genesis(anchor).block_hash
    return HeightReply(block_num=store.head_block_num() or 0, tip_hash=tip)


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
        return Refused(reason=SyncRefusal.NOT_YET_SETTLED)
    return SettledBlockReply(payload=tuple(out))
