# dude.coordinator -- the per-node lifecycle for Rounds, SettleRounds, Mempools, and commit.
#
# WHAT IT OWNS. The currently-collecting Mempool. Rounds in flight (bucket -> Round; the Round
# carries its own bodies so no Mempool sidecar is retained). A queue of ratified blocks awaiting
# settlement, in bucket order. At most one live SettleRound at a time, plus the OPEN Layer
# previewing its slice. Also owns the bucket-boundary swap, the RATIFIED -> SETTLED -> COMMIT
# sequencing, and the ABANDONED-round fall-through re-admission (#endorser-refuses-stale).
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

from ..core import crypto
from ..core.errors import InvariantError
from ..core.units import Millis
from ..net.envelope import SignedEnvelope
from ..store import Layer, Store, settle
from ..store.layer import Index
from ..store.management import Management
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
    """The one SettleRound currently in flight, along with everything needed to commit it."""

    bucket: Bucket
    block: Block
    layer: Layer
    applied: tuple[SignedTransaction, ...]
    """Slice txs the preview accepted, in the order they will be committed."""
    dropped: tuple[SignedTransaction, ...]
    """Slice txs the preview rejected (guard/authority failure against the pre-apply state).
    These re-enter the current mempool on SETTLED, alongside `surviving`."""
    surviving: tuple[SignedTransaction, ...]
    """Non-slice txs (held by Round but not included in the ratified slice). Re-enter the
    current mempool on SETTLED via #fall-through-through-the-door, alongside `dropped`."""
    anchors: Anchors
    """The anchors we signed. Compared to the SETTLED block's anchors -- a mismatch here would
    mean our own evaluator produced different mutations between preview and commit, which is
    non-determinism and MUST NOT be catchable as a routine error."""
    first_height: Index
    """`store.head() + 1` at settle-start -- the log-idx the first tx of this block will land
    at. Written into the block table so a joiner replaying via `bodies_of_block` fetches the
    correct entry range without inferring the base offset from prior blocks."""
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
    rounds: dict[Bucket, Round] = field(init=False, default_factory=dict)
    """Open Rounds by bucket. No Mempool held alongside -- Round now carries its own bodies
    (`Round.add_local` takes SignedTransactions, not just hashes), so the L5 preview and
    fall-through paths read directly off the Round without a frozen-Mempool sidecar."""
    pending: list[
        tuple[Bucket, Block, tuple[SignedTransaction, ...], tuple[SignedTransaction, ...]]
    ] = field(init=False, default_factory=list)
    """Ratified blocks waiting to be settled, in bucket order. Tuple: `(bucket, block,
    slice_bodies, surviving)` -- everything the settling + fall-through paths need, sourced
    from the Round on ratification. Enqueued on Round ratification; dequeued when `settling`
    opens up."""
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

    def _abandon_by(self, close_by: Millis) -> Millis:
        """Deadline for the Round opening now: if still in FINALIZE at this point, abandon and
        push everything back through the mempool door (#endorser-refuses-stale). Derived as
        `close_by + w_valid_margin` so no honest node is still trying to sign a slice whose
        txs have aged past `w_valid` -- the mempool's own admission floor refuses those, so
        the round-level check reduces to a cadence timeout with no per-tx dance."""
        return close_by + self.tunables.mempool.w_valid_margin

    # -- inbound ----------------------------------------------------------------------------- #

    def submit(self, tx: SignedTransaction, now: Millis) -> Refusal | None:
        """A client transaction offered to this node. Admits to the currently-live Mempool."""
        return self.mempool.admit(tx, now, self.store, self.mgmt)

    def on_round_msg(self, env: SignedEnvelope, now: Millis) -> None:
        """A HELD or SIG envelope from a peer. Route to the Round for its bucket, dropping
        anything for a bucket this node is not currently running."""
        try:
            bucket = RoundMsg.bucket_of(env.env.body)
        except RoundAdapterError:
            return  # malformed body, dropped
        r = self.rounds.get(bucket)
        if r is None:
            return  # unknown bucket: already settled or not opened yet -- routine
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
            sh = SettleSig.slice_hash_of(env.env.body)
        except SettleAdapterError:
            return
        if self.settling is None or self.settling.block.slice_hash != sh:
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

        # Drive open Rounds; move ratified ones to `pending`, drop abandoned ones after
        # re-admitting their held txs (#endorser-refuses-stale + #fall-through-through-the-door).
        for bucket in list(self.rounds):
            r = self.rounds[bucket]
            r.tick(now)
            self.adapter.flush(r, now)
            if r.ratified() is not None:
                self._on_ratified(bucket, r)
            elif r.abandoned():
                self._on_abandoned(bucket, r, now)

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
        """Instantiate a Round for `bucket`, seed it with the transactions the frozen Mempool
        held.

        Bodies flow into Round via `add_local(all_bodies)`, not just hashes -- Round carries
        the SignedTransactions itself so possession is structural and the slice we sign is by
        construction backed by txs we can produce for settlement.

        SKIPS QUIETLY if we are not in the roster. A follower-only node (a fresh joiner, a
        node granted read-only membership, a node whose stake in the roster has been removed
        pending re-onboarding) still ticks the coordinator every cycle but MUST NOT try to
        open a Round it cannot participate in -- Round refuses `me not in roster` at
        construction, and the exception would tear down the node's tick. Correct behaviour is
        to sit out consensus and let the Follower catch us up; if a subsequent block grants
        us into the roster, the next bucket boundary opens a Round normally."""
        roster = self.mgmt.roster()
        if self.me.public not in roster:
            return
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
        self.rounds[bucket] = r
        self.adapter.flush(r, now)

    def _on_ratified(self, bucket: Bucket, r: Round) -> None:
        """A Round has ratified. Enqueue in `pending` for settlement; retire the Round entry.

        Bodies for slice + surviving come straight from the Round -- no Mempool sidecar. Enqueue
        in bucket order so `_start_settling` always picks the smallest -- monotone-height per
        SPECv2 #pipelining."""
        block = r.ratified()
        if block is None:  # unreachable: caller only calls after checking ratified()
            raise InvariantError("_on_ratified called with unratified Round")
        self.pending.append((bucket, block, r.slice_bodies(), r.surviving()))
        self.pending.sort(key=lambda entry: entry[0])
        del self.rounds[bucket]

    def _on_abandoned(self, bucket: Bucket, r: Round, now: Millis) -> None:
        """A Round has abandoned (`abandon_by` passed without ratification). No block enters
        `pending` -- nothing settles for this bucket. Every tx the Round held goes back through
        the current-mempool door: some re-enter and go to a later bucket; anything past
        `w_valid` on our clock is refused there for free (#endorser-refuses-stale +
        #fall-through-through-the-door). Re-broadcast the re-admitted ones so peers hold them
        too, same reasoning as the SETTLED fall-through path."""
        for tx in r.surviving():
            refusal = self.mempool.admit(tx, now, self.store, self.mgmt)
            if refusal is None and self.reflood is not None:
                self.reflood(tx, now)
        del self.rounds[bucket]

    def _start_settling(self, now: Millis) -> None:
        """Promote pending[0] to `settling`: build the Layer preview, compute anchors, construct
        the SettleRound, emit our own SettleSig."""
        bucket, block, slice_txs, surviving = self.pending.pop(0)

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

        # Compute anchors. `height` = store.head after this block commits (log-idx of last tx).
        # `block_num` = monotone per-block counter, prior + 1 (or 1 for the first ever block).
        # A_log projected by adding log_element for each applied tx at its future settled index.
        base_head = self.store.head()
        height = base_head + len(applied)
        prev_block_num = self.store.head_block_num() or 0
        block_num = prev_block_num + 1
        acc_log = self.store.log_accumulator()
        for i, tx in enumerate(applied):
            acc_log = crypto.acc_add(acc_log, log_element(base_head + i + 1, tx.op_hash))
        # Chain link. `prev_block` is `H(prev_settled_block.encode())` -- the previous SETTLED
        # block's hash -- or the genesis stamp for block 1 (#genesis-stamp-anchors-the-chain).
        # `head_block_hash` returns None on the first settlement of an empty store; that is the
        # only case genesis applies.
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

        # Construct SettleRound. It signs its own anchors and queues its own SettleSig.
        sr = SettleRound(block, self.me, self.mgmt.roster(), anchors, now)
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
        # Emit our own SettleSig immediately so peers can start counting toward quorum.
        self.settle_adapter.flush(sr, now)

    def _on_settled(self, now: Millis) -> None:
        """A quorum has agreed on our anchors. Commit the applied slice txs to Store atomically
        with the SETTLED block bytes, safety-check that Store's post-apply anchors match what we
        signed, re-admit fall-through txs, clear the settling slot."""
        s = self.settling
        if s is None:
            raise InvariantError("_on_settled called with no settling slot")

        # The SettledBlock is what the quorum agreed on. Its bytes go in the same SQL
        # transaction as the tx applies (#atomic-write): a crash between the two would leave
        # entries with no block record and sync could not serve them.
        settled = s.settle_round.settled()
        if settled is None:
            raise InvariantError("_on_settled fired but SettleRound has no SettledBlock")
        block_bytes = settled.encode()
        # block_hash is SIG-INDEPENDENT (chain identity, not wire-bytes hash) -- see
        # SettledBlock.block_hash. Two nodes with the same slice + anchors compute the same
        # hash regardless of which sig subset they hold.
        block_hash = settled.block_hash
        self.store.commit_block(
            s.anchors.block_num,
            first_height=s.first_height,
            block_bytes=block_bytes,
            block_hash=block_hash,
            batch=s.applied,
            auth=self.mgmt,
        )

        # Safety-check: Store's post-apply anchors must match what we signed. If they do not,
        # our evaluator is non-deterministic between preview and commit -- a bug of ours.
        # InvariantError, per #failure-domains, so no `except DudeError` can swallow it.
        _expect_anchors(s.anchors, self.store)

        # Re-admit surviving + slice-dropped txs through the one admission door, and re-broadcast
        # each so peers hold them too -- otherwise a tx that only this node carried after
        # ratifying an empty slice would stay isolated for every future bucket. Sources: Round's
        # `surviving()` (bodies held-but-not-included) + the settle preview's own `dropped`
        # (slice txs whose guards falsified against the pre-apply state).
        for tx in (*s.surviving, *s.dropped):
            refusal = self.mempool.admit(tx, now, self.store, self.mgmt)
            if refusal is None and self.reflood is not None:
                self.reflood(tx, now)

        self.settling = None


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
