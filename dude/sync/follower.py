from __future__ import annotations

from abc import ABC
from collections.abc import Callable
from dataclasses import dataclass, replace

from .. import quorum
from ..consensus.canonical import bodies_canonical
from ..consensus.settle_round import (
    Anchors,
    SettledBlock,
    SettledBlockWithBodies,
    genesis_stamp,
)
from ..core import crypto
from ..core.errors import InvariantError
from ..core.event_loop import Event, EventLoop, Scheduled
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


class FollowerEvent(Event, ABC):
    __slots__ = ()


@dataclass(frozen=True, slots=True)
class PeerMessage(FollowerEvent):
    msg: SyncMsg
    frm: crypto.PublicKey


@dataclass(frozen=True, slots=True)
class PeerAdded(FollowerEvent):
    peer: crypto.PublicKey


@dataclass(frozen=True, slots=True)
class PeerRemoved(FollowerEvent):
    peer: crypto.PublicKey


@dataclass(frozen=True, slots=True)
class PullCancelled(FollowerEvent):
    peer: crypto.PublicKey


@dataclass(frozen=True, slots=True)
class PollPeer(FollowerEvent):
    peer: crypto.PublicKey


@dataclass(frozen=True, slots=True)
class PullExpiry(FollowerEvent):
    peer: crypto.PublicKey
    sent_at: Millis


@dataclass(frozen=True, slots=True)
class SendToPeer(FollowerEvent):
    peer: crypto.PublicKey
    msg: SyncMsg


class BlockCommitted(FollowerEvent):
    __slots__ = ()


# -- data ------------------------------------------------------------------


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


# -- the follower ----------------------------------------------------------


class Follower:
    __slots__ = (
        "_compacted_at",
        "_heads",
        "_last_fail_at",
        "_last_ok_at",
        "_loop",
        "_on_commit",
        "_on_send",
        "_poll_timers",
        "_pull_timer",
        "_pulling",
        "me",
        "mgmt_reader",
        "store",
        "tunables",
    )

    def __init__(
        self,
        me: crypto.Keypair,
        store: Store,
        mgmt_reader: MgmtReader,
        tunables: Tunables,
        on_send: Callable[[SendToPeer], None],
        on_commit: Callable[[BlockCommitted], None] = lambda _: None,
    ) -> None:
        self.me = me
        self.store = store
        self.mgmt_reader = mgmt_reader
        self.tunables = tunables
        self._heads: dict[crypto.PublicKey, HeightReport] = {}
        self._poll_timers: dict[crypto.PublicKey, Scheduled] = {}
        self._pulling: PullInFlight | None = None
        self._pull_timer: Scheduled | None = None
        self._last_ok_at: dict[crypto.PublicKey, Millis] = {}
        self._last_fail_at: dict[crypto.PublicKey, Millis] = {}
        self._compacted_at: dict[crypto.PublicKey, int] = {}
        self._on_send = on_send
        self._on_commit = on_commit

        self._loop: EventLoop[FollowerEvent] = EventLoop()
        self._loop.register(PeerMessage, self._on_peer_message)
        self._loop.register(PeerAdded, self._on_peer_added)
        self._loop.register(PeerRemoved, self._on_peer_removed)
        self._loop.register(PullCancelled, self._on_pull_cancelled)
        self._loop.register(PollPeer, self._on_poll_peer)
        self._loop.register(PullExpiry, self._on_pull_expiry)
        self._loop.register(SendToPeer, self._on_send_to_peer)
        self._loop.register(BlockCommitted, self._on_block_committed)

    def post(self, event: FollowerEvent) -> None:
        self._loop.post(event)

    def start(self) -> None:
        self._loop.start()

    def stop(self) -> None:
        self._loop.stop()

    # -- event handlers --------------------------------------------------------

    def _on_send_to_peer(self, event: SendToPeer) -> None:
        self._on_send(event)

    def _on_block_committed(self, event: BlockCommitted) -> None:
        self._on_commit(event)

    def _on_peer_added(self, event: PeerAdded) -> None:
        if event.peer == self.me.public or event.peer in self._poll_timers:
            return
        self._schedule_poll(event.peer, Millis.now())

    def _on_peer_removed(self, event: PeerRemoved) -> None:
        timer = self._poll_timers.pop(event.peer, None)
        if timer is not None:
            timer.cancel()
        self._heads.pop(event.peer, None)
        self._last_ok_at.pop(event.peer, None)
        self._last_fail_at.pop(event.peer, None)
        if self._pulling is not None and self._pulling.peer == event.peer:
            self._cancel_pull_timer()
            self._pulling = None

    def _on_peer_message(self, event: PeerMessage) -> None:
        if event.frm == self.me.public:
            return
        now = Millis.now()
        if isinstance(event.msg, HeightReply):
            self._on_height_reply(event.msg, event.frm, now)
        elif isinstance(event.msg, SettledBlockReply):
            self._on_settled_blocks(event.msg, event.frm, now)
        elif isinstance(event.msg, Refused):
            self._on_refused(event.msg, event.frm, now)

    def _on_pull_cancelled(self, event: PullCancelled) -> None:
        if self._pulling is not None and self._pulling.peer == event.peer:
            self._cancel_pull_timer()
            self._pulling = None
            self._last_fail_at[event.peer] = Millis.now()
            self._try_pull()

    def _on_poll_peer(self, event: PollPeer) -> None:
        if event.peer not in self._poll_timers:
            return
        self._loop.post(SendToPeer(event.peer, HeightAsk()))
        self._schedule_poll(event.peer, Millis.now() + self.tunables.poll_interval)

    def _on_pull_expiry(self, event: PullExpiry) -> None:
        p = self._pulling
        if p is None or p.peer != event.peer or p.sent_at != event.sent_at:
            return
        self._pulling = None
        self._pull_timer = None
        self._last_fail_at[p.peer] = Millis.now()
        self._try_pull()

    # -- timer management ------------------------------------------------------

    def _schedule_poll(self, peer: crypto.PublicKey, at: Millis) -> None:
        old = self._poll_timers.get(peer)
        if old is not None:
            old.cancel()
        self._poll_timers[peer] = self._loop.schedule(at, PollPeer(peer))

    def _cancel_pull_timer(self) -> None:
        if self._pull_timer is not None:
            self._pull_timer.cancel()
            self._pull_timer = None

    # -- sync logic (unchanged from tick-based version) ------------------------

    def _on_height_reply(self, msg: HeightReply, from_: crypto.PublicKey, now: Millis) -> None:
        self._heads[from_] = HeightReport(msg.block_num, msg.tip_hash, now)
        self._try_pull()

    def _on_settled_blocks(
        self, msg: SettledBlockReply, from_: crypto.PublicKey, now: Millis
    ) -> None:
        p = self._pulling
        if p is None or from_ != p.peer:
            return
        self._cancel_pull_timer()
        self._pulling = None
        served = 0
        for offer in msg.payload:
            if offer.block.anchors.block_num != p.frm + served or not self._adopt(offer):
                self._last_fail_at[from_] = now
                return
            served += 1
        if served == 0:
            return
        self._last_ok_at[from_] = now
        self._try_pull()

    def _adopt(self, offer: SettledBlockWithBodies) -> bool:
        sb = offer.block
        walked = chain.advance(
            self._tip(), (sb,), self.mgmt_reader.roster(), self._require_anchor()
        )
        if isinstance(walked, chain.ChainRefusal):
            return False
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
        self._on_commit(BlockCommitted())
        return True

    def _on_refused(self, msg: Refused, from_: crypto.PublicKey, now: Millis) -> None:
        p = self._pulling
        if p is None or from_ != p.peer:
            return
        self._cancel_pull_timer()
        self._pulling = None
        if msg.reason is SyncRefusal.NOT_YET_SETTLED:
            hr = self._heads.get(from_)
            if hr is not None:
                self._heads[from_] = replace(hr, block_num=p.frm - 1)
            self._try_pull()
        elif msg.reason is SyncRefusal.COMPACTED and msg.checkpoint_block_num is not None:
            self._compacted_at[from_] = msg.checkpoint_block_num
            self._last_fail_at[from_] = now
        else:
            self._last_fail_at[from_] = now

    def _try_pull(self) -> None:
        if self._pulling is not None:
            return
        source = self._pick_pull_source()
        if source is not None:
            self._pull_from(source, Millis.now())

    def _pull_from(self, peer: crypto.PublicKey, now: Millis) -> None:
        frm = (self.store.head_block_num() or 0) + 1
        count = self.tunables.pull_batch
        self._loop.post(SendToPeer(peer, GetBlocks(frm=frm, count=count)))
        self._pulling = PullInFlight(peer, frm, count, now)
        self._cancel_pull_timer()
        self._pull_timer = self._loop.schedule(
            now + self.tunables.pull_timeout, PullExpiry(peer, now)
        )

    # -- queries (called from outside, read-only) ------------------------------

    def behind(self, now: Millis) -> bool:
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

    def needs_checkpoint(self) -> int | None:
        if not self._compacted_at:
            return None
        my_num = self.store.head_block_num() or 0
        peers_with_heads = {p for p in self._heads if self._heads[p].block_num > my_num}
        if not peers_with_heads:
            return None
        if all(p in self._compacted_at for p in peers_with_heads):
            return max(self._compacted_at.values())
        return None

    def compacted_peers(self) -> tuple[crypto.PublicKey, ...]:
        return tuple(self._compacted_at)

    def clear_compacted(self) -> None:
        self._compacted_at.clear()

    # -- internals -------------------------------------------------------------

    def _pick_pull_source(self) -> crypto.PublicKey | None:
        my_num = self.store.head_block_num() or 0
        candidates = [(peer, hr) for peer, hr in self._heads.items() if hr.block_num > my_num]
        if not candidates:
            return None
        candidates.sort(
            key=lambda p_hr: (
                -self._last_ok_at.get(p_hr[0], 0),
                self._last_fail_at.get(p_hr[0], 0),
                -p_hr[1].block_num,
            )
        )
        return candidates[0][0]

    def _tip(self) -> crypto.Digest:
        return self.store.head_block_hash() or genesis_stamp(self._require_anchor())

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
