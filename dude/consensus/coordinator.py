from __future__ import annotations

import logging
from abc import ABC
from collections.abc import Callable
from dataclasses import dataclass

from ..core import crypto
from ..core.errors import DudeError, InvariantError
from ..core.event_loop import Event, EventLoop, Scheduled
from ..core.units import Bucket, Millis
from ..net.envelope import Verb
from ..net.postman import Encodable, recipients
from ..store import settle
from ..store.layer import Index, Layer
from ..store.management import MgmtReader
from ..store.ops import SignedTransaction
from ..store.store import Store, log_element
from ..tunables import Tunables
from .canonical import CanonicalBatch
from .mempool import Mempool, Refusal
from .round import Block, Bodies, Round, RoundAdapterError, RoundMsg
from .settle_round import (
    Anchors,
    SettleAdapterError,
    SettleRound,
    SettleSig,
    genesis_stamp,
)

_log = logging.getLogger(__name__)


# -- events ----------------------------------------------------------------


class CoordinatorEvent(Event, ABC):
    __slots__ = ()


@dataclass(frozen=True, slots=True)
class RoundMessage(CoordinatorEvent):
    frm: crypto.PublicKey
    verb: Verb
    body: bytes


@dataclass(frozen=True, slots=True)
class SettleMessage(CoordinatorEvent):
    frm: crypto.PublicKey
    verb: Verb
    body: bytes


class RoundClose(CoordinatorEvent):
    __slots__ = ("bucket",)

    def __init__(self, bucket: Bucket) -> None:
        self.bucket = bucket


class RoundAbandon(CoordinatorEvent):
    __slots__ = ("bucket",)

    def __init__(self, bucket: Bucket) -> None:
        self.bucket = bucket


class SettleAbandon(CoordinatorEvent):
    __slots__ = ("slice_hash",)

    def __init__(self, slice_hash: crypto.Digest) -> None:
        self.slice_hash = slice_hash


class BucketTick(CoordinatorEvent):
    __slots__ = ()


@dataclass(frozen=True, slots=True)
class SendConsensus(CoordinatorEvent):
    peer: crypto.PublicKey
    msg: Encodable


class BlockSettled(CoordinatorEvent):
    __slots__ = ()


# -- internal ---------------------------------------------------------------


@dataclass(slots=True)
class _Settling:
    bucket: Bucket
    block: Block
    layer: Layer
    applied: tuple[SignedTransaction, ...]
    surviving: tuple[SignedTransaction, ...]
    anchors: Anchors
    first_height: Index
    settle_round: SettleRound


# -- coordinator ------------------------------------------------------------


class Coordinator:
    __slots__ = (
        "_bucket_timer",
        "_force_close",
        "_loop",
        "_on_send",
        "_on_settled",
        "_round_abandon_timer",
        "_round_close_timer",
        "_settle_abandon_timer",
        "_settle_stalls",
        "behind",
        "current_bucket",
        "current_round",
        "me",
        "mempool",
        "settling",
        "store",
        "tunables",
    )

    def __init__(
        self,
        me: crypto.Keypair,
        store: Store,
        tunables: Tunables,
        behind: Callable[[Millis], bool],
        on_send: Callable[[SendConsensus], None],
        on_settled: Callable[[BlockSettled], None],
    ) -> None:
        self.me = me
        self.store = store
        self.tunables = tunables
        self.behind = behind
        self._on_send = on_send
        self._on_settled = on_settled

        self.mempool = Mempool(tunables)
        self.current_round: Round | None = None
        self.settling: _Settling | None = None
        self.current_bucket: Bucket = -1
        self._settle_stalls = 0
        self._force_close = False

        self._round_close_timer: Scheduled[CoordinatorEvent] | None = None
        self._round_abandon_timer: Scheduled[CoordinatorEvent] | None = None
        self._settle_abandon_timer: Scheduled[CoordinatorEvent] | None = None
        self._bucket_timer: Scheduled[CoordinatorEvent] | None = None

        self._loop: EventLoop[CoordinatorEvent] = EventLoop()
        self._loop.register(RoundMessage, self._on_round_msg)
        self._loop.register(SettleMessage, self._on_settle_msg)
        self._loop.register(RoundClose, self._on_round_close)
        self._loop.register(RoundAbandon, self._on_round_abandon)
        self._loop.register(SettleAbandon, self._on_settle_abandon_event)
        self._loop.register(BucketTick, self._on_bucket_tick)
        self._loop.register(BlockSettled, self._on_block_settled)

    # -- lifecycle -------------------------------------------------------------

    def post(self, event: CoordinatorEvent) -> None:
        self._loop.post(event)

    def start(self) -> None:
        self._loop.start()
        now = Millis.now()
        if self.current_bucket < 0:
            self.current_bucket = self._bucket_of(now)
        self._loop.post(BucketTick())

    def stop(self) -> None:
        self._loop.stop()

    # -- synchronous (not routed through the loop) -----------------------------

    def submit(self, tx: SignedTransaction, now: Millis) -> Refusal | None:
        if not self.in_roster:
            return Refusal.NOT_IN_ROSTER
        return self.mempool.admit(tx, now, self.store, self.mgmt_reader)

    def set_immediate(self, enabled: bool = True) -> None:
        self._force_close = enabled
        if enabled:
            self._loop.post(BucketTick())

    # -- outbound event handlers -----------------------------------------------

    def _on_block_settled(self, event: BlockSettled) -> None:
        self._on_settled(event)

    # -- properties ------------------------------------------------------------

    @property
    def mgmt_reader(self) -> MgmtReader:
        return MgmtReader(self.store.mgmt_session())

    @property
    def in_roster(self) -> bool:
        return self.mgmt_reader.is_member(self.me.public)

    def _bucket_of(self, now: Millis) -> Bucket:
        return self.tunables.bucket(now)

    def _prev_block(self) -> crypto.Digest:
        prev = self.store.head_block_hash()
        if prev is not None:
            return prev
        manager = self.store.anchor()
        if manager is None:
            raise InvariantError("store has no manager anchor; cannot compute genesis stamp")
        return genesis_stamp(manager)

    def _close_by(self, bucket: Bucket) -> Millis:
        return self._abandon_by(bucket) - self.tunables.cut_reserve

    def _abandon_by(self, bucket: Bucket) -> Millis:
        return self.tunables.bucket_start(bucket + 2)

    # -- timer scheduling ------------------------------------------------------

    def _cancel_round_timers(self) -> None:
        if self._round_close_timer is not None:
            self._round_close_timer.cancel()
            self._round_close_timer = None
        if self._round_abandon_timer is not None:
            self._round_abandon_timer.cancel()
            self._round_abandon_timer = None

    def _cancel_settle_timer(self) -> None:
        if self._settle_abandon_timer is not None:
            self._settle_abandon_timer.cancel()
            self._settle_abandon_timer = None

    def _schedule_bucket_tick(self, now: Millis) -> None:
        if self._bucket_timer is not None:
            self._bucket_timer.cancel()
        next_boundary = self.tunables.bucket_start(self.current_bucket + 1)
        if next_boundary <= now:
            self._loop.post(BucketTick())
            self._bucket_timer = None
        else:
            self._bucket_timer = self._loop.schedule(next_boundary, BucketTick())

    # -- inbound event handlers ------------------------------------------------

    def _catch_up(self, now: Millis) -> None:
        if self.settling is not None:
            self.settling.settle_round.tick(now)
            self._flush_settle()
            self._check_settled()
        if self.current_round is not None:
            self.current_round.tick(now)
            self._flush_round()
            if self.current_round is not None and self.current_round.abandoned():
                self._cancel_round_timers()
                self.current_round = None
        self._check_ratified()
        self._close_current_bucket(now)

    def _on_round_msg(self, event: RoundMessage) -> None:
        try:
            bucket = RoundMsg.bucket_of(event.body)
        except RoundAdapterError:
            return
        now = Millis.now()
        self._catch_up(now)
        r = self.current_round
        if r is None or r.bucket() != bucket:
            return
        try:
            if event.verb is Verb.BODIES:
                self._absorb_bodies(event.frm, event.verb, event.body, r)
            else:
                msg = RoundMsg.decode(event.verb, event.body)
                r.receive(msg, from_=event.frm, now=Millis.now())
        except RoundAdapterError:
            return
        self._flush_round()
        self._check_ratified()

    def _absorb_bodies(
        self, frm: crypto.PublicKey, verb: Verb, body: bytes, r: Round
    ) -> None:
        msg = RoundMsg.decode(verb, body)
        if not isinstance(msg, Bodies):
            return
        good = tuple(
            tx
            for tx in msg.txs
            if self.mempool.valid_for_bucket(tx, r.bucket(), self.store, self.mgmt_reader) is None
        )
        r.absorb(msg, frm, good)

    def _on_settle_msg(self, event: SettleMessage) -> None:
        try:
            sh = SettleSig.slice_hash_of(event.body)
        except SettleAdapterError:
            return
        now = Millis.now()
        self._catch_up(now)
        if self.settling is None or self.settling.block.slice_hash != sh:
            return
        try:
            msg = SettleSig.decode(event.verb, event.body)
            self.settling.settle_round.receive(msg, from_=event.frm, now=now)
        except SettleAdapterError:
            return
        self._flush_settle()
        self._check_settled()

    def _on_round_close(self, event: RoundClose) -> None:
        r = self.current_round
        if r is None or r.bucket() != event.bucket:
            return
        now = Millis.now()
        r.tick(now)
        self._flush_round()
        self._check_ratified()

    def _on_round_abandon(self, event: RoundAbandon) -> None:
        r = self.current_round
        if r is None or r.bucket() != event.bucket:
            return
        now = Millis.now()
        r.tick(now)
        if r.abandoned():
            self._cancel_round_timers()
            self.current_round = None

    def _on_settle_abandon_event(self, event: SettleAbandon) -> None:
        s = self.settling
        if s is None or s.block.slice_hash != event.slice_hash:
            return
        now = Millis.now()
        s.settle_round.tick(now)
        if s.settle_round.abandoned():
            self._cancel_settle_timer()
            self._do_settle_abandoned()

    def _on_bucket_tick(self, _event: BucketTick) -> None:
        now = Millis.now()
        self._close_current_bucket(now)
        self._schedule_bucket_tick(now)

    # -- flush outboxes as events ----------------------------------------------

    def _flush_round(self) -> None:
        r = self.current_round
        if r is None:
            return
        roster = r.roster()
        for target, msg in r.outbox():
            for peer in recipients(target, roster, self.me.public):
                self._on_send(SendConsensus(peer, msg))

    def _flush_settle(self) -> None:
        s = self.settling
        if s is None:
            return
        roster = s.settle_round.roster()
        for target, msg in s.settle_round.outbox():
            for peer in recipients(target, roster, self.me.public):
                self._on_send(SendConsensus(peer, msg))

    # -- state transitions -----------------------------------------------------

    def _check_ratified(self) -> None:
        if (
            self.current_round is not None
            and self.current_round.ratified() is not None
            and self.settling is None
        ):
            try:
                self._promote_to_settling(Millis.now())
            except DudeError as e:
                raise InvariantError(f"promote to settling raised mid-transition: {e}") from e

    def _check_settled(self) -> None:
        s = self.settling
        if s is None:
            return
        if s.settle_round.settled() is not None:
            self._cancel_settle_timer()
            self._do_settled()
        elif s.settle_round.abandoned():
            self._cancel_settle_timer()
            self._do_settle_abandoned()

    def _close_current_bucket(self, now: Millis) -> None:
        forced = self._force_close
        closed = self.current_bucket if forced else self._bucket_of(now) - 1
        if self.current_round is not None:
            return
        if closed < self.current_bucket:
            return
        if not forced and now >= self._close_by(closed):
            self.current_bucket = closed + 1
            return
        if not forced and self.behind(now):
            self.current_bucket = closed + 1
            return
        self._open_round(closed, self.mempool.snapshot(), now)
        self.current_bucket = closed + 1

    def _open_round(self, bucket: Bucket, frozen: Mempool, now: Millis) -> None:
        if not self.in_roster:
            return
        roster = self.mgmt_reader.roster()
        r = Round(
            bucket=bucket,
            me=self.me,
            roster=roster,
            prev_block=self._prev_block(),
            now=now,
            close_by=self._close_by(bucket),
            abandon_by=self._abandon_by(bucket),
            screen=self._screen_slice,
        )
        r.add_local(frozen.all_bodies().values())
        self.current_round = r

        self._round_close_timer = self._loop.schedule(
            self._close_by(bucket), RoundClose(bucket)
        )
        self._round_abandon_timer = self._loop.schedule(
            self._abandon_by(bucket), RoundAbandon(bucket)
        )

        self._flush_round()

    def _screen_slice(self, candidate: CanonicalBatch) -> frozenset[crypto.Digest]:
        already = self.store.has_settled(*(tx.op_hash for tx in candidate))
        fresh = tuple(tx for tx in candidate if tx.op_hash not in already)
        survivors = settle.apply_to(Layer(self.store), fresh, self.mgmt_reader).survivors
        for tx in survivors:
            grant = self.mgmt_reader.grant_of(tx.author)
            if grant is not None and grant.role.isolated:
                return frozenset({tx.op_hash})
        return frozenset(tx.op_hash for tx in survivors)

    def _promote_to_settling(self, now: Millis) -> None:
        r = self.current_round
        if r is None:
            raise InvariantError("_promote_to_settling with no in-flight Round")
        block = r.ratified()
        if block is None:
            raise InvariantError("_promote_to_settling with unratified Round")
        if not self.in_roster:
            self._cancel_round_timers()
            self.current_round = None
            return
        bucket = r.bucket()
        slice_txs = r.slice_bodies()
        surviving = r.surviving()
        if self._prev_block() != r.prev_block():
            self._cancel_round_timers()
            self.current_round = None
            return
        roster = self.mgmt_reader.roster()

        layer = Layer(self.store)
        screened = settle.apply_to(layer, slice_txs, self.mgmt_reader)
        if screened.rejects:
            _log.error(
                "promote screen disagreed with cut screen at bucket %d: %r",
                bucket,
                screened.rejects,
            )
            self._cancel_round_timers()
            self.current_round = None
            return
        applied = screened.survivors

        layer.freeze()

        base_head = self.store.head()
        height = base_head + len(applied)
        prev_block_num = self.store.head_block_num() or 0
        block_num = prev_block_num + 1
        acc_log = self.store.log_accumulator()
        for i, tx in enumerate(applied):
            acc_log = crypto.acc_add(acc_log, log_element(base_head + i + 1, tx.op_hash))
        anchors = Anchors(
            block_num=block_num,
            height=height,
            prev_block=r.prev_block(),
            state_root=layer.state_root(),
            acc_state=layer.accumulator(),
            acc_log=acc_log,
        )

        sr = SettleRound(
            block,
            self.me,
            roster,
            anchors,
            now,
            abandon_by=self._abandon_by(bucket),
        )
        self.settling = _Settling(
            bucket=bucket,
            block=block,
            layer=layer,
            applied=applied,
            surviving=surviving,
            anchors=anchors,
            first_height=base_head + 1,
            settle_round=sr,
        )
        self._cancel_round_timers()
        self.current_round = None

        self._settle_abandon_timer = self._loop.schedule(
            self._abandon_by(bucket), SettleAbandon(block.slice_hash)
        )

        self._flush_settle()

    def _do_settled(self) -> None:
        s = self.settling
        if s is None:
            raise InvariantError("_do_settled called with no settling slot")

        settled = s.settle_round.settled()
        if settled is None:
            raise InvariantError("_do_settled fired but SettleRound has no SettledBlock")
        block_bytes = settled.encode()
        block_hash = settled.block_hash
        self.store.commit_block(
            s.anchors.block_num,
            first_height=s.first_height,
            block_bytes=block_bytes,
            block_hash=block_hash,
            batch=s.applied,
            auth=self.mgmt_reader,
        )

        _expect_anchors(s.anchors, self.store)
        self.mempool.evict_settled(self.store)
        self.settling = None
        self._settle_stalls = 0

        self._loop.post(BlockSettled())
        self._loop.post(BucketTick())

    def _do_settle_abandoned(self) -> None:
        s = self.settling
        if s is None:
            raise InvariantError("_do_settle_abandoned called with no settling slot")
        divergences = s.settle_round.divergences()
        self.settling = None

        if not divergences:
            self._settle_stalls = 0
            return
        self._settle_stalls += 1
        _log.warning(
            "settlement abandoned with divergent anchors at bucket %d (%d consecutive): %s",
            s.bucket,
            self._settle_stalls,
            [(pk.hex()[:8], a) for pk, a in divergences],
        )


def _expect_anchors(signed: Anchors, store: Store) -> None:
    if store.head() != signed.height:
        raise InvariantError(f"post-settle head {store.head()} != signed height {signed.height}")
    if store.state_root() != signed.state_root:
        raise InvariantError("post-settle state_root differs from signed anchors")
    if store.accumulator() != signed.acc_state:
        raise InvariantError("post-settle A_state differs from signed anchors")
    if store.log_accumulator() != signed.acc_log:
        raise InvariantError("post-settle A_log differs from signed anchors")
