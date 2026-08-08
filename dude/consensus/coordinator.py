from __future__ import annotations

from collections.abc import Callable
from dataclasses import dataclass, field

from ..core import crypto
from ..core.errors import InvariantError
from ..core.units import Millis
from ..net.envelope import SignedEnvelope
from ..store import Layer, Store, settle
from ..store.layer import Index
from ..store.management import MgmtReader
from ..store.ops import SignedTransaction
from ..store.store import log_element
from ..tunables import Tunables
from .mempool import Bucket, Mempool, Refusal
from .round import Block, Round, RoundAdapterError, RoundMsg
from .round_adapter import RoundAdapter
from .settle_adapter import SettleAdapter
from .settle_round import Anchors, SettleAdapterError, SettleRound, SettleSig, genesis_stamp


@dataclass(slots=True)
class _Settling:
    bucket: Bucket
    block: Block
    layer: Layer
    applied: tuple[SignedTransaction, ...]
    dropped: tuple[SignedTransaction, ...]
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
    reflood: Callable[[SignedTransaction, Millis], None] | None = None

    mempool: Mempool = field(init=False)
    current_round: Round | None = field(init=False, default=None)
    settling: _Settling | None = field(init=False, default=None)
    current_bucket: Bucket = field(init=False, default=-1)

    def __post_init__(self) -> None:
        self.mempool = Mempool(self.tunables.mempool)

    @property
    def mgmt(self) -> MgmtReader:
        return MgmtReader(self.store)

    def _bucket_of(self, now: Millis) -> Bucket:
        return self.tunables.mempool.bucket(now)

    def _close_by(self, now: Millis) -> Millis:
        return now + self.tunables.mempool.delta

    def _abandon_by(self, close_by: Millis) -> Millis:
        """The abandonment beat MUST land on a bucket boundary, or the pipeline stages drift out
        of phase and blocks queue behind `settling`."""
        return close_by + self.tunables.mempool.delta

    def _settle_abandon_by(self, now: Millis) -> Millis:
        return now + self.tunables.mempool.delta

    def submit(self, tx: SignedTransaction, now: Millis) -> Refusal | None:
        return self.mempool.admit(tx, now, self.store, self.mgmt)

    def on_round_msg(self, env: SignedEnvelope, now: Millis) -> None:
        """MUST advance state to `now` before dispatching. Dispatch routes on `current_round`'s
        bucket, so a peer's HELD/SIG arriving in the gap before our own scheduled tick was
        dropped as "no matching Round" -- every node signed empty slices on buckets the whole
        cluster held the same tx for, and it looked like packet loss at every layer."""
        try:
            bucket = RoundMsg.bucket_of(env.env.body)
        except RoundAdapterError:
            return
        self.tick(now)
        r = self.current_round
        if r is None or r.bucket() != bucket:
            return
        try:
            self.adapter.deliver(env, r, now)
        except RoundAdapterError:
            return

    def on_settle_msg(self, env: SignedEnvelope, now: Millis) -> None:
        try:
            sh = SettleSig.slice_hash_of(env.env.body)
        except SettleAdapterError:
            return
        self.tick(now)
        if self.settling is None or self.settling.block.slice_hash != sh:
            return
        try:
            self.settle_adapter.deliver(env, self.settling.settle_round, now)
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
            self._promote_to_settling(now)

        self._close_current_bucket(now)

    def _close_current_bucket(self, now: Millis) -> None:
        while self.current_bucket < self._bucket_of(now) and self.current_round is None:
            frozen = self.mempool
            self.mempool = Mempool(self.tunables.mempool)
            self._open_round(self.current_bucket, frozen, now)
            self.current_bucket += 1

    def _open_round(self, bucket: Bucket, frozen: Mempool, now: Millis) -> None:
        roster = self.mgmt.roster()
        if self.me.public not in roster:
            return  # follower-only: Round refuses `me not in roster`, and the raise would tear
            # down the node's tick. Sit out consensus and let the Follower catch us up.
        close_by = self._close_by(now)
        r = Round(
            bucket=bucket,
            me=self.me,
            roster=roster,
            now=now,
            close_by=close_by,
            abandon_by=self._abandon_by(close_by),
        )
        r.add_local(frozen.all_bodies().values())
        self.current_round = r
        self.adapter.flush(r, now)

    def _on_round_abandoned(self, now: Millis) -> None:
        r = self.current_round
        if r is None:
            raise InvariantError("_on_round_abandoned called with no in-flight Round")
        for tx in r.surviving():
            refusal = self.mempool.admit(tx, now, self.store, self.mgmt)
            if refusal is None and self.reflood is not None:
                self.reflood(tx, now)
        self.current_round = None

    def _promote_to_settling(self, now: Millis) -> None:
        r = self.current_round
        if r is None:
            raise InvariantError("_promote_to_settling with no in-flight Round")
        block = r.ratified()
        if block is None:
            raise InvariantError("_promote_to_settling with unratified Round")
        bucket = r.bucket()
        slice_txs = r.slice_bodies()
        surviving = r.surviving()
        self.current_round = None

        already = self.store.settled_hashes(tuple(tx.op_hash for tx in slice_txs))
        slice_txs = tuple(tx for tx in slice_txs if tx.op_hash not in already)

        layer = Layer(self.store)
        screened = settle.apply_to(layer, slice_txs, self.mgmt)
        applied = screened.survivors
        dropped_from_slice = tuple(rej.tx for rej in screened.rejects)

        layer.freeze()

        base_head = self.store.head()
        height = base_head + len(applied)
        prev_block_num = self.store.head_block_num() or 0
        block_num = prev_block_num + 1
        acc_log = self.store.log_accumulator()
        for i, tx in enumerate(applied):
            acc_log = crypto.acc_add(acc_log, log_element(base_head + i + 1, tx.op_hash))
        prev = self.store.head_block_hash()
        if prev is None:
            manager = self.store.anchor()
            if manager is None:
                raise InvariantError("store has no manager anchor; cannot compute genesis stamp")
            prev = genesis_stamp(manager)
        anchors = Anchors(
            block_num=block_num,
            height=height,
            prev_block=prev,
            state_root=layer.state_root(),
            acc_state=layer.accumulator(),
            acc_log=acc_log,
        )

        sr = SettleRound(
            block,
            self.me,
            self.mgmt.roster(),
            anchors,
            now,
            abandon_by=self._settle_abandon_by(now),
        )
        self.settling = _Settling(
            bucket=bucket,
            block=block,
            layer=layer,
            applied=applied,
            dropped=dropped_from_slice,
            surviving=surviving,
            anchors=anchors,
            first_height=base_head + 1,
            settle_round=sr,
        )
        self.settle_adapter.flush(sr, now)

    def _on_settled(self, now: Millis) -> None:
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
            auth=self.mgmt,
        )

        _expect_anchors(s.anchors, self.store)

        for tx in (*s.surviving, *s.dropped):
            refusal = self.mempool.admit(tx, now, self.store, self.mgmt)
            if refusal is None and self.reflood is not None:
                self.reflood(tx, now)

        self.settling = None

    def _on_settle_abandoned(self, now: Millis) -> None:
        s = self.settling
        if s is None:
            raise InvariantError("_on_settle_abandoned called with no settling slot")
        for tx in (*s.applied, *s.dropped, *s.surviving):
            refusal = self.mempool.admit(tx, now, self.store, self.mgmt)
            if refusal is None and self.reflood is not None:
                self.reflood(tx, now)
        self.settling = None


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
