from __future__ import annotations

import logging
from collections.abc import Callable
from dataclasses import dataclass, field

from ..core import crypto
from ..core.errors import DudeError, InvariantError
from ..core.units import Bucket, Millis
from ..net.envelope import Verb
from ..store import Layer, Store, settle
from ..store.layer import Index
from ..store.management import MgmtReader
from ..store.ops import SignedTransaction
from ..store.store import log_element
from ..tunables import Tunables
from .canonical import CanonicalBatch
from .mempool import Mempool, Refusal
from .round import Block, Bodies, Round, RoundAdapterError, RoundMsg
from .round_adapter import RoundAdapter
from .settle_adapter import SettleAdapter
from .settle_round import Anchors, SettleAdapterError, SettleRound, SettleSig, genesis_stamp

_log = logging.getLogger(__name__)


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


@dataclass(slots=True)
class Coordinator:
    me: crypto.Keypair
    store: Store
    adapter: RoundAdapter
    settle_adapter: SettleAdapter
    tunables: Tunables

    behind: Callable[[Millis], bool]
    """`Follower.behind`. REQUIRED, never defaulted: a default is wrong for whichever caller
    forgets it, and the symptom -- a node leading a bucket over a chain it does not hold, or a
    cluster silently producing nothing -- is invisible from inside this class."""

    # ONE OF EACH, NEVER A QUEUE. Turning any of these three into a collection is a different
    # protocol, not an optimisation.
    mempool: Mempool = field(init=False)
    current_round: Round | None = field(init=False, default=None)
    settling: _Settling | None = field(init=False, default=None)
    current_bucket: Bucket = field(init=False, default=-1)
    _settle_stalls: int = field(init=False, default=0)
    _force_close: bool = field(init=False, default=False)

    def __post_init__(self) -> None:
        self.mempool = Mempool(self.tunables)

    def set_immediate(self, enabled: bool = True) -> None:
        self._force_close = enabled

    @property
    def mgmt_reader(self) -> MgmtReader:
        return MgmtReader(self.store.mgmt_session())

    def _bucket_of(self, now: Millis) -> Bucket:
        return self.tunables.bucket(now)

    def _prev_block(self) -> crypto.Digest:
        """The Round is keyed on this and the anchors carry it; they MUST be the same value, or
        the block's own quorum did not agree what it follows."""
        prev = self.store.head_block_hash()
        if prev is not None:
            return prev
        manager = self.store.anchor()
        if manager is None:
            raise InvariantError("store has no manager anchor; cannot compute genesis stamp")
        return genesis_stamp(manager)

    # THE CADENCE GRID. During window W:
    #
    #     Mempool(W) collects | Round(W-1) converges holdings, cuts a slice, settles it
    #
    # Round(B) opens at W=B+1 and lives entirely inside that window; phase 2 gets whatever
    # `cut_reserve` leaves. Every deadline is bucket arithmetic and NONE is measured from `now`:
    # measured from `now`, each node runs on its own phase, and nodes that fall out of step never
    # share a bucket again.

    def _close_by(self, bucket: Bucket) -> Millis:
        return self._abandon_by(bucket) - self.tunables.cut_reserve

    def _abandon_by(self, bucket: Bucket) -> Millis:
        return self.tunables.bucket_start(bucket + 2)

    @property
    def in_roster(self) -> bool:
        """Whether we hold a seat RIGHT NOW. The Follower can adopt a roster change at any tick,
        so this is read at each decision rather than cached at construction."""
        return self.mgmt_reader.is_member(self.me.public)

    def submit(self, tx: SignedTransaction, now: Millis) -> Refusal | None:
        if not self.in_roster:
            # A non-member ACCEPTED submissions and then discarded its whole mempool at the
            # bucket boundary -- rotation happens before _open_round declines -- so the
            # client held an ACCEPTED for a tx that vanished without a trace. Refused here,
            # the client knows to try a roster member instead.
            return Refusal.NOT_IN_ROSTER
        return self.mempool.admit(tx, now, self.store, self.mgmt_reader)

    def on_round_msg(self, frm: crypto.PublicKey, verb: Verb, body: bytes, now: Millis) -> None:
        try:
            bucket = RoundMsg.bucket_of(body)
        except RoundAdapterError:
            return
        self.tick(now)
        r = self.current_round
        if r is None or r.bucket() != bucket:
            return
        try:
            if verb is Verb.BODIES:
                self._absorb_bodies(frm, verb, body, r, now)
            else:
                self.adapter.deliver(frm, verb, body, r, now)
        except RoundAdapterError:
            return

    def _absorb_bodies(
        self, frm: crypto.PublicKey, verb: Verb, body: bytes, r: Round, _now: Millis
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

    def on_settle_msg(self, frm: crypto.PublicKey, verb: Verb, body: bytes, now: Millis) -> None:
        try:
            sh = SettleSig.slice_hash_of(body)
        except SettleAdapterError:
            return
        self.tick(now)
        if self.settling is None or self.settling.block.slice_hash != sh:
            return
        try:
            self.settle_adapter.deliver(frm, verb, body, self.settling.settle_round, now)
        except SettleAdapterError:
            return

    def tick(self, now: Millis) -> None:
        if self.current_bucket < 0:
            self.current_bucket = self._bucket_of(now)

        if self.settling is not None:
            self.settling.settle_round.tick(now)
            self.settle_adapter.flush(self.settling.settle_round, now)
            if self.settling.settle_round.settled() is not None:
                self._on_settled(now)
            elif self.settling.settle_round.abandoned():
                self._on_settle_abandoned(now)

        if self.current_round is not None:
            self.current_round.tick(now)
            self.adapter.flush(self.current_round, now)
            if self.current_round.abandoned():
                self._on_round_abandoned(now)

        if (
            self.current_round is not None
            and self.current_round.ratified() is not None
            and self.settling is None
        ):
            try:
                self._promote_to_settling(now)
            except DudeError as e:
                # NOT CATCHABLE. Promote refuses by returning; anything that RAISES past that
                # point is the evaluator, the SMT or an accumulator failing, which is corruption
                # or non-determinism rather than a peer's fault. Left as a DudeError it was
                # swallowed at the crash-only boundary and the bucket's agreed work disappeared
                # in silence. Fatal means the supervisor respawns us and the Follower resyncs --
                # which is the only way to actually rely on core machinery not failing.
                raise InvariantError(f"promote to settling raised mid-transition: {e}") from e

        self._close_current_bucket(now)

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
            return  # follower-only: Round refuses `me not in roster`, and the raise would tear
            # down the node's tick. Sit out consensus and let the Follower catch us up.
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
        self.adapter.flush(r, now)

    def _screen_slice(self, candidate: CanonicalBatch) -> frozenset[crypto.Digest]:
        """Which of `candidate`'s op_hashes this node can actually apply. Returns membership, not
        bodies -- Round filters the canonical candidate by this set, so "narrow" and "in apply
        order" are structural rather than asserted.

        The already-settled filter is a LOG read and has to happen here: `apply_to` works over an
        Overlay, which has no log, so a transaction settled in an earlier block would re-apply and
        surface only at commit as an anchors mismatch.

        Deterministic across the quorum because every member screens the same canonical batch
        against the same committed base -- a node on a different base is not a participant, it is
        a node that needs to catch up."""
        already = self.store.settled_hashes(tuple(tx.op_hash for tx in candidate))
        fresh = tuple(tx for tx in candidate if tx.op_hash not in already)
        survivors = settle.apply_to(Layer(self.store), fresh, self.mgmt_reader).survivors
        for tx in survivors:
            grant = self.mgmt_reader.grant_of(tx.author)
            if grant is not None and grant.role.isolated:
                return frozenset({tx.op_hash})
        return frozenset(tx.op_hash for tx in survivors)

    def _on_round_abandoned(self, _now: Millis) -> None:
        if self.current_round is None:
            raise InvariantError("_on_round_abandoned called with no in-flight Round")
        self.current_round = None

    def _promote_to_settling(self, now: Millis) -> None:
        """REFUSE FIRST, THEN COMMIT. Every decline sits above the first mutation; everything
        below it is core machinery whose failure is not a peer's fault. Interleaving the two lets
        a raise between them clear the round without assigning `settling` -- the bucket's work
        vanishes with no error at the crash-only boundary."""
        r = self.current_round
        if r is None:
            raise InvariantError("_promote_to_settling with no in-flight Round")
        block = r.ratified()
        if block is None:
            raise InvariantError("_promote_to_settling with unratified Round")
        if not self.in_roster:
            # The Follower adopted a roster change removing us between open and promote. The
            # round is void: the remaining quorum settles this block and we adopt it as any
            # follower does. What the round held is NOT re-admitted -- a node without a seat
            # cannot open a round, is refused at `submit`, and has no way to hand its mempool
            # to anyone, so re-admitting only reads as a recovery it cannot perform. Clients
            # holding an ACCEPTED from us lose it; that is what losing the seat means.
            self.current_round = None
            return
        bucket = r.bucket()
        slice_txs = r.slice_bodies()
        surviving = r.surviving()
        if self._prev_block() != r.prev_block():
            self.current_round = None
            return
        roster = self.mgmt_reader.roster()

        layer = Layer(self.store)
        screened = settle.apply_to(layer, slice_txs, self.mgmt_reader)
        if screened.rejects:
            # LOCAL non-determinism: the same screen ran at the cut against the same base and
            # agreed. Other ratifiers settle without us; we adopt via the Follower. Crashing
            # would take an honest node down for its own anomaly.
            _log.error(
                "promote screen disagreed with cut screen at bucket %d: %r",
                bucket,
                screened.rejects,
            )
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
        self.current_round = None  # released only now that `settling` holds the ratified block
        self.settle_adapter.flush(sr, now)

    def _on_settled(self, _now: Millis) -> None:
        s = self.settling
        if s is None:
            raise InvariantError("_on_settled called with no settling slot")

        settled = s.settle_round.settled()
        if settled is None:
            raise InvariantError("_on_settled fired but SettleRound has no SettledBlock")
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

    def _on_settle_abandoned(self, _now: Millis) -> None:
        s = self.settling
        if s is None:
            raise InvariantError("_on_settle_abandoned called with no settling slot")
        divergences = s.settle_round.divergences()
        self.settling = None

        if not divergences:
            # Absence heals on its own: no log, no counter.
            self._settle_stalls = 0
            return
        self._settle_stalls += 1
        # Divergence needs an operator, not a crash: crashing takes an honest node down for a
        # peer's state, and restart resets the counter without fixing anything.
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
        # NOT catchable: a mismatch means our evaluator produced different mutations between
        # preview and commit, which is non-determinism, not a peer's fault.
        raise InvariantError("post-settle A_log differs from signed anchors")
