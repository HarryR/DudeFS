# dude.coordinator -- the per-node lifecycle for Rounds, SettleRounds, Mempools, and commit.
#
# WHAT IT OWNS. The currently-collecting Mempool. Rounds in flight (bucket -> frozen mempool +
# Round). A queue of ratified blocks awaiting settlement, in bucket order. At most one live
# SettleRound at a time, plus the OPEN Layer previewing its slice. Also owns the bucket-boundary
# swap and the RATIFIED -> SETTLED -> COMMIT sequencing.
#
# WHAT IT DOES NOT OWN. The Round protocol (`dude.round`), the SettleRound protocol
# (`dude.settle_round`), the wire encodings (`dude.net.round_adapter`,
# `dude.net.settle_adapter`), transports (`dude.net.postman`), and the log (`dude.store`). This
# module composes them.
#
# THE L5 FLOW, top to bottom:
#
#     1. Round(N) ratifies -> Block(bucket=N, slice_hash, hashes).
#     2. Enqueue (bucket=N, block, frozen_mempool) in `pending`.
#     3. If no SettleRound is currently running AND pending has an item, promote the smallest-
#        bucket entry to `settling`:
#          a. Build ordered slice txs by looking up bodies from the frozen mempool.
#          b. Layer(base=store), evaluate the slice into it via settle.apply_to, freeze it.
#          c. Compute Anchors: height = store.head + len(applied), state_root = layer.state_root,
#             acc_state = layer.accumulator, acc_log projected from Store + applied op_hashes.
#          d. Construct SettleRound(block, me, roster, anchors, now).
#     4. Drive open SettleRound on tick: flush outbound SETTLE_SIGs, check `settled()`.
#     5. On SETTLED:
#          a. Commit the applied slice txs via store.apply -- deterministic re-evaluation
#             produces the same effects, so the projected anchors match Store's post-apply state.
#          b. Safety-check: Store's new anchors match the SETTLED anchors (InvariantError if not
#             -- that would mean our evaluator is non-deterministic between preview and commit).
#          c. Re-admit non-slice-and-non-applying txs through the mempool's one door.
#          d. Clear `settling`; the next tick starts the next pending entry (if any).
#
# SETTLEMENT IS SERIAL PER BUCKET. Per SPECv2 #pipelining: blocks settle in bucket order. If
# Round(N+1) ratifies before Round(N) has SETTLED, N+1's block waits in `pending`. Not a
# concurrency requirement -- a monotone-height requirement. Speculative pipelining via stacked
# Layers is the SPEC target (#pipelining-via-frozen-layers) but not implemented in Stage 3.

from __future__ import annotations

from collections.abc import Callable
from dataclasses import dataclass, field

from .core import crypto
from .core.errors import InvariantError
from .mempool import Mempool, Refusal
from .net.envelope import SignedEnvelope
from .net.round_adapter import RoundAdapter, RoundAdapterError, bucket_of
from .net.settle_adapter import SettleAdapter, SettleAdapterError, slice_hash_of
from .round import Block, Bucket, Round
from .settle_round import Anchors, SettleRound, _slice_id_of
from .store import Layer, Store, settle
from .store.management import Management
from .store.ops import SignedTransaction
from .store.store import log_element
from .tunables import Tunables

type Millis = int


@dataclass(slots=True)
class _Settling:
    """The one SettleRound currently in flight, along with everything needed to commit it."""

    bucket: Bucket
    block: Block
    frozen: Mempool
    layer: Layer
    applied: tuple[SignedTransaction, ...]
    """Slice txs the preview accepted, in the order they will be committed."""
    dropped: tuple[SignedTransaction, ...]
    """Slice txs the preview rejected (guard/authority failure against the pre-apply state).
    These re-enter the current mempool on SETTLED, alongside non-slice txs."""
    anchors: Anchors
    """The anchors we signed. Compared to the SETTLED block's anchors -- a mismatch here would
    mean our own evaluator produced different mutations between preview and commit, which is
    non-determinism and MUST NOT be catchable as a routine error."""
    settle_round: SettleRound


@dataclass(slots=True)
class Coordinator:
    """One node's consensus + settlement driver.

    Constructed once per node. Node hands it inbound HELD/SIG envelopes via `on_round_msg`,
    inbound SETTLE_SIG envelopes via `on_settle_msg`, inbound SUBMITs via `submit`, and a tick
    every round via `tick`."""

    me: crypto.Keypair
    store: Store
    adapter: RoundAdapter
    settle_adapter: SettleAdapter
    tunables: Tunables
    reflood: Callable[[SignedTransaction, Millis], None] | None = None
    """Callback the Coordinator invokes to re-broadcast a fall-through tx after settlement.

    A tx that was in the ratified slice but dropped in the preview (guard falsified by a
    bucket-mate that settled first), or a non-slice tx in the frozen mempool, re-enters this
    node's current mempool via #fall-through-through-the-door. But local re-admission does NOT
    reach peers: a tx that only THIS node holds cannot form a quorum in any future bucket. So
    the Coordinator asks Node to re-broadcast the body via SUBMIT, restoring the shape SUBMIT
    re-flood originally established (peers hold what the author gave one of us). Optional
    because tests may not need it; production always passes one."""

    mempool: Mempool = field(init=False)
    rounds: dict[Bucket, tuple[Mempool, Round]] = field(init=False, default_factory=dict)
    pending: list[tuple[Bucket, Block, Mempool]] = field(init=False, default_factory=list)
    """Ratified blocks waiting to be settled, in bucket order. Enqueued on Round ratification;
    dequeued when `settling` opens up."""
    settling: _Settling | None = field(init=False, default=None)
    current_bucket: Bucket = field(init=False, default=-1)
    """The bucket the currently-collecting mempool is for. `-1` means "no bucket yet"."""

    def __post_init__(self) -> None:
        self.mempool = Mempool(self.tunables.mempool)

    @property
    def mgmt(self) -> Management:
        """Fresh per call: the store may have moved since last time."""
        return Management(self.store)

    def _bucket_of(self, now: Millis) -> Bucket:
        return self.tunables.mempool.bucket(now)

    def _close_by(self, now: Millis) -> Millis:
        """When the Round opening at `now` should stop collecting and finalize. One bucket width
        ahead -- enough for HELD to disseminate before finalize triggers on the next tick."""
        return now + self.tunables.mempool.delta

    # -- inbound ----------------------------------------------------------------------------- #

    def submit(self, tx: SignedTransaction, now: Millis) -> Refusal | None:
        """A client transaction offered to this node. Admits to the currently-live Mempool."""
        return self.mempool.admit(tx, now, self.store, self.mgmt)

    def on_round_msg(self, env: SignedEnvelope, now: Millis) -> None:
        """A HELD or SIG envelope from a peer. Route to the Round for its bucket, dropping
        anything for a bucket this node is not currently running."""
        try:
            bucket = bucket_of(env.env.body)
        except RoundAdapterError:
            return  # malformed body, dropped
        entry = self.rounds.get(bucket)
        if entry is None:
            return  # unknown bucket: already settled or not opened yet -- routine
        _frozen, r = entry
        try:
            self.adapter.deliver(env, r, now)
        except RoundAdapterError:
            return  # malformed body, dropped

    def on_settle_msg(self, env: SignedEnvelope, now: Millis) -> None:
        """A SETTLE_SIG envelope from a peer. Route to the currently-settling block if the
        slice_hash matches, drop otherwise. If we are behind (peer's slice is for a bucket we
        have not ratified yet), the sig is dropped -- gossip will catch us up naturally when
        we ratify our own view of that bucket."""
        try:
            sh = slice_hash_of(env.env.body)
        except SettleAdapterError:
            return
        if self.settling is None or _slice_id_of(self.settling.block) != sh:
            return  # not for the block we are settling
        try:
            self.settle_adapter.deliver(env, self.settling.settle_round, now)
        except SettleAdapterError:
            return

    # -- the driver -------------------------------------------------------------------------- #

    def tick(self, now: Millis) -> None:
        """Advance every open Round; drive the current SettleRound; open new Rounds for any
        bucket boundary crossed; promote a pending ratified block to settling when the slot
        is free; commit on SETTLED."""
        if self.current_bucket < 0:
            self.current_bucket = self._bucket_of(now)

        # Swap on bucket boundaries.
        while self.current_bucket < self._bucket_of(now):
            frozen = self.mempool
            self.mempool = Mempool(self.tunables.mempool)
            self._open_round(self.current_bucket, frozen, now)
            self.current_bucket += 1

        # Drive open Rounds; move ratified ones to `pending`.
        for bucket in list(self.rounds):
            _frozen, r = self.rounds[bucket]
            r.tick(now)
            self.adapter.flush(r, now)
            block = r.ratified()
            if block is not None:
                self._on_ratified(bucket, block, _frozen)

        # Drive the current SettleRound; commit on SETTLED.
        if self.settling is not None:
            self.settling.settle_round.tick(now)
            self.settle_adapter.flush(self.settling.settle_round, now)
            settled = self.settling.settle_round.settled()
            if settled is not None:
                self._on_settled(now)

        # Promote a pending block to settling if the slot is free.
        if self.settling is None and self.pending:
            self._start_settling(now)

    def _open_round(self, bucket: Bucket, frozen: Mempool, now: Millis) -> None:
        """Instantiate a Round for `bucket`, seed it with what the frozen Mempool held."""
        r = Round(
            bucket=bucket,
            me=self.me,
            roster=self.mgmt.node_set(),
            now=now,
            close_by=self._close_by(now),
        )
        r.add_local(_all_hashes(frozen))
        self.rounds[bucket] = (frozen, r)
        self.adapter.flush(r, now)

    def _on_ratified(self, bucket: Bucket, block: Block, frozen: Mempool) -> None:
        """A Round has ratified. Enqueue in `pending` for settlement; retire the Round entry.

        Enqueue in bucket order so `_start_settling` always picks the smallest -- monotone-
        height per SPECv2 #pipelining."""
        self.pending.append((bucket, block, frozen))
        self.pending.sort(key=lambda entry: entry[0])
        del self.rounds[bucket]

    def _start_settling(self, now: Millis) -> None:
        """Promote pending[0] to `settling`: build the Layer preview, compute anchors, construct
        the SettleRound, emit our own SettleSig."""
        bucket, block, frozen = self.pending.pop(0)

        # Look up bodies for the ratified slice.
        bodies_by_hash = {
            tx.op_hash: tx for _b, txs in frozen.pending.items() for tx in txs.values()
        }
        missing = [h for h in block.hashes if h not in bodies_by_hash]
        if missing:
            raise InvariantError(
                f"bucket {bucket} ratified {len(missing)} tx(s) this node does not hold locally; "
                f"gossip-by-hash + FETCH not yet implemented"
            )
        slice_txs = tuple(bodies_by_hash[h] for h in block.hashes)

        # Filter already-settled txs. Round does not check log state -- it ratifies over
        # mempool hashes -- so a slice may contain a tx that has already landed in the log
        # via an earlier bucket's settlement. `store.apply` drops these at commit time
        # (op_hash UNIQUE), and if the preview counted them in `applied`, the projected
        # height would exceed what actually commits -- signing anchors nobody can reproduce.
        already = self.store._settled_hashes(tuple(tx.op_hash for tx in slice_txs))  # noqa: SLF001
        slice_txs = tuple(tx for tx in slice_txs if tx.op_hash not in already)

        # Preview the slice into an OPEN Layer over Store.
        layer = Layer(self.store)
        screened = settle.apply_to(layer, slice_txs, self.mgmt)
        applied = screened.survivors
        dropped_from_slice = tuple(r.tx for r in screened.rejects)

        # Freeze the layer -- projected anchors are stable now.
        layer.freeze()

        # Compute anchors. Height = store.head after this block commits. A_log projected by
        # adding log_element for each applied tx at its future settled index.
        base_head = self.store.head()
        height = base_head + len(applied)
        acc_log = self.store.log_accumulator()
        for i, tx in enumerate(applied):
            acc_log = crypto.acc_add(acc_log, log_element(base_head + i + 1, tx.op_hash))
        anchors = Anchors(
            height=height,
            state_root=layer.state_root(),
            acc_state=layer.accumulator(),
            acc_log=acc_log,
        )

        # Construct SettleRound. It signs its own anchors and queues its own SettleSig.
        sr = SettleRound(block, self.me, self.mgmt.node_set(), anchors, now)
        self.settling = _Settling(
            bucket=bucket,
            block=block,
            frozen=frozen,
            layer=layer,
            applied=applied,
            dropped=dropped_from_slice,
            anchors=anchors,
            settle_round=sr,
        )
        # Emit our own SettleSig immediately so peers can start counting toward quorum.
        self.settle_adapter.flush(sr, now)

    def _on_settled(self, now: Millis) -> None:
        """A quorum has agreed on our anchors. Commit the applied slice txs to Store, safety-
        check that Store's post-apply anchors match what we signed, re-admit fall-through txs,
        clear the settling slot."""
        s = self.settling
        if s is None:
            raise InvariantError("_on_settled called with no settling slot")

        if s.applied:
            self.store.apply(s.applied, auth=self.mgmt)

        # Safety-check: Store's post-apply anchors must match what we signed. If they do not,
        # our evaluator is non-deterministic between preview and commit -- a bug of ours.
        # InvariantError, per #failure-domains, so no `except DudeError` can swallow it.
        _expect_anchors(s.anchors, self.store)

        # Re-admit non-slice and slice-dropped txs through the one admission door, and
        # re-broadcast each so peers hold them too -- otherwise a tx that only this node
        # carried after ratifying an empty slice would stay isolated for every future bucket.
        applied_hashes = {tx.op_hash for tx in s.applied}
        for op_hash, tx in _all_bodies(s.frozen).items():
            if op_hash in applied_hashes:
                continue
            refusal = self.mempool.admit(tx, now, self.store, self.mgmt)
            if refusal is None and self.reflood is not None:
                self.reflood(tx, now)

        self.settling = None


# ------------------------------------------------------------------------------------------- #
# Helpers                                                                                     #
# ------------------------------------------------------------------------------------------- #


def _all_hashes(m: Mempool) -> frozenset[crypto.Digest]:
    """Every op_hash currently in the mempool, across whatever internal bucket keys it holds
    them under. Round takes a single set."""
    return frozenset(op_hash for txs in m.pending.values() for op_hash in txs)


def _all_bodies(m: Mempool) -> dict[crypto.Digest, SignedTransaction]:
    """Every tx currently in the mempool, keyed by op_hash. Used to re-admit fall-throughs
    (non-slice and slice-dropped) via the one door on SETTLED."""
    return {tx.op_hash: tx for _b, txs in m.pending.items() for tx in txs.values()}


def _expect_anchors(signed: Anchors, store: Store) -> None:
    """Store's post-apply anchors MUST match what we signed. Any mismatch means our evaluator
    produced different mutations between preview and commit -- non-determinism we cannot
    tolerate. InvariantError, so it terminates the process rather than getting caught at the
    crash-only boundary (#failure-domains)."""
    if store.head() != signed.height:
        raise InvariantError(f"post-settle head {store.head()} != signed height {signed.height}")
    if store.state_root() != signed.state_root:
        raise InvariantError("post-settle state_root differs from signed anchors")
    if store.accumulator() != signed.acc_state:
        raise InvariantError("post-settle A_state differs from signed anchors")
    if store.log_accumulator() != signed.acc_log:
        raise InvariantError("post-settle A_log differs from signed anchors")
