from __future__ import annotations

from dataclasses import dataclass, field

from .. import quorum
from ..consensus.settle_round import (
    Anchors,
    SettledBlock,
    SettledBlockWithBodies,
    _settle_payload,
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
from ..tunables import SyncTunables
from .adapter import (
    GetBlock,
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
    block_num: Index
    sent_at: Millis


type OutboxItem = tuple[crypto.PublicKey, SyncMsg]


@dataclass(slots=True)
class Follower:
    me: crypto.Keypair
    store: Store
    mgmt: MgmtReader
    tunables: SyncTunables
    _heads: dict[crypto.PublicKey, HeightReport] = field(default_factory=dict)
    _poll_at: dict[crypto.PublicKey, Millis] = field(default_factory=dict)
    _pulling: PullInFlight | None = None
    _last_ok_at: dict[crypto.PublicKey, Millis] = field(default_factory=dict)
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
            self._on_settled_block(msg, from_, now)
        elif isinstance(msg, Refused):
            self._on_refused(msg, from_, now)

    def cancel_pull(self, from_: crypto.PublicKey) -> None:
        if self._pulling is not None and self._pulling.peer == from_:
            self._pulling = None

    def tick(self, now: Millis) -> None:
        for peer, deadline in list(self._poll_at.items()):
            if now >= deadline:
                self._enqueue(peer, HeightAsk())
                self._poll_at[peer] = now + self.tunables.poll_interval
        p = self._pulling
        if p is not None and now - p.sent_at > self.tunables.pull_timeout:
            self._pulling = None
        if self._pulling is None:
            source = self._pick_pull_source()
            if source is not None:
                target_num = (self.store.head_block_num() or 0) + 1
                self._enqueue(source, GetBlock(n=target_num))
                self._pulling = PullInFlight(source, target_num, now)

    def outbox(self) -> tuple[OutboxItem, ...]:
        drained = tuple(self._outbox)
        self._outbox.clear()
        return drained

    def caught_up(self) -> bool:
        roster = self.mgmt.roster()
        n = len(roster)
        if n == 0:
            return False
        threshold = quorum.corroboration(n)
        my_num = self.store.head_block_num() or 0
        my_tip = self.store.head_block_hash() or genesis_stamp(self._require_anchor())
        matches = 0
        latest_now = self._last_now()
        for peer, hr in self._heads.items():
            if peer not in roster:
                continue
            if latest_now - hr.at > self.tunables.freshness_window:
                continue
            if hr.block_num == my_num and hr.tip_hash == my_tip:
                matches += 1
        return matches >= threshold

    def _on_height_reply(self, msg: HeightReply, from_: crypto.PublicKey, now: Millis) -> None:
        self._heads[from_] = HeightReport(msg.block_num, msg.tip_hash, now)
        self._last_ok_at[from_] = now

    def _on_settled_block(  # noqa: PLR0911 -- verification pipeline is intentionally linear
        self,
        msg: SettledBlockReply,
        from_: crypto.PublicKey,
        now: Millis,
    ) -> None:
        p = self._pulling
        if p is None or from_ != p.peer:
            return
        sbwb = msg.payload
        sb = sbwb.block
        if sb.anchors.block_num != p.block_num:
            self._pulling = None
            return
        expected_prev = self.store.head_block_hash()
        if expected_prev is None:
            expected_prev = genesis_stamp(self._require_anchor())
        if sb.anchors.prev_block != expected_prev:
            self._pulling = None
            return
        body_hashes = frozenset(tx.op_hash for tx in sbwb.bodies)
        slice_hashes = frozenset(sb.block.hashes)
        if not body_hashes.issubset(slice_hashes):
            self._pulling = None
            return
        for tx in sbwb.bodies:
            if not tx.verify():
                self._pulling = None
                return
        if not self.mgmt.authorises(sb.multisig, _settle_payload(sb.block.slice_hash, sb.anchors)):
            self._pulling = None
            return
        bodies_ordered = tuple(sorted(sbwb.bodies, key=lambda tx: tx.op_hash))
        if not self._preview_matches_signed_anchors(bodies_ordered, sb.anchors):
            self._pulling = None
            return
        first_height = self.store.head() + 1
        block_bytes = sb.encode()
        self.store.commit_block(
            sb.anchors.block_num,
            first_height=first_height,
            block_bytes=block_bytes,
            block_hash=sb.block_hash,
            batch=bodies_ordered,
            auth=self.mgmt,
        )
        self._last_ok_at[from_] = now
        self._pulling = None

    def _on_refused(
        self,
        msg: Refused,  # noqa: ARG002 -- reason kept for future per-reason handling
        from_: crypto.PublicKey,
        now: Millis,  # noqa: ARG002 -- reserved for refusal-latency telemetry
    ) -> None:
        p = self._pulling
        if p is None or from_ != p.peer:
            return
        self._pulling = None

    def _enqueue(self, peer: crypto.PublicKey, msg: SyncMsg) -> None:
        self._outbox.append((peer, msg))

    def _pick_pull_source(self) -> crypto.PublicKey | None:
        my_num = self.store.head_block_num() or 0
        candidates = [(peer, hr) for peer, hr in self._heads.items() if hr.block_num > my_num]
        if not candidates:
            return None
        candidates.sort(key=lambda p_hr: (-self._last_ok_at.get(p_hr[0], 0), -p_hr[1].block_num))
        return candidates[0][0]

    def _require_anchor(self) -> crypto.PublicKey:
        anchor = self.store.anchor()
        if anchor is None:
            raise InvariantError("store has no manager anchor; cannot compute genesis stamp")
        return anchor

    def _last_now(self) -> Millis:
        return max(
            (hr.at for hr in self._heads.values()),
            default=0,
        )

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
    block_num = store.head_block_num() or 0
    tip_hash = store.head_block_hash() or crypto.Digest(bytes(32))
    return HeightReply(block_num=block_num, tip_hash=tip_hash)


def serve_getblock(store: Store, req: GetBlock) -> SyncMsg:
    block_bytes = store.settled_at(req.n)
    if block_bytes is None:
        return Refused(reason=SyncRefusal.NOT_YET_SETTLED)
    sb = SettledBlock.decode(block_bytes)
    bodies = store.bodies_of_block(req.n)
    return SettledBlockReply(payload=SettledBlockWithBodies(block=sb, bodies=bodies))
