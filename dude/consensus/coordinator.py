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
    current_round: Round | None = field(init=False, default=None)
    """The one in-flight Round (#one-of-each-in-flight). None between buckets. Holds the
    Round from open through either ratification-and-promotion or abandonment. If a Round
    ratifies while `settling` is still occupied, it stays here holding the ratified Block
    until settling clears and promotion happens on the next tick -- no queue."""
    settling: _Settling | None = field(init=False, default=None)
    """The one in-flight SettleRound (#one-of-each-in-flight). None between blocks. Clears
    on either SETTLED (commit) or ABANDONED (fall-through)."""
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
        """Deadline for the Round opening now: `close_by + delta` -- one bucket width after
        `close_by`, so the abandonment beat aligns with the next bucket boundary
        (#one-of-each-in-flight). If still in FINALIZE at this point, abandon and push
        everything back through the mempool door (#endorser-refuses-stale +
        #fall-through-through-the-door)."""
        return close_by + self.tunables.mempool.delta

    def _settle_abandon_by(self, now: Millis) -> Millis:
        """Deadline for the SettleRound opening now: `now + delta` -- one bucket after the
        Round ratified. Aligns settlement to the same beat as Round (#one-of-each-in-flight),
        so the pipeline advances one stage per bucket boundary and no queue forms behind
        `settling`. If no quorum by then, ABANDONED; slice txs re-enter the mempool via
        fall-through, block position frees for the next Round's Block."""
        return now + self.tunables.mempool.delta

    # -- inbound ----------------------------------------------------------------------------- #

    def submit(self, tx: SignedTransaction, now: Millis) -> Refusal | None:
        """A client transaction offered to this node. Admits to the currently-live Mempool."""
        return self.mempool.admit(tx, now, self.store, self.mgmt)

    def on_round_msg(self, env: SignedEnvelope, now: Millis) -> None:
        """A HELD or SIG envelope from a peer. Route to the in-flight Round if its bucket
        matches, drop otherwise. Under #one-of-each-in-flight there is exactly one Round in
        flight at a time; a message for a different bucket is either a stragler from a
        past-done bucket or gossip from a peer ahead of us.

        CALLER CONTRACT: `tick(now)` must have run at (or after) `now` before this call, so
        `current_round` reflects the bucket the driver would open at `now`. `Node._run`
        does this by ticking before dispatching every inbound frame; without it, a HELD/SIG
        for the current bucket that arrived microseconds before this node's own scheduled
        tick was dropped, and consensus stalled on any tx the whole cluster held (see
        `Node._run`'s docstring for the found-and-fixed writeup)."""
        try:
            bucket = RoundMsg.bucket_of(env.env.body)
        except RoundAdapterError:
            return  # malformed body, dropped
        r = self.current_round
        if r is None or r.bucket() != bucket:
            return  # no matching Round: truly past or truly future -- routine
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
        """Advance the three-stage pipeline (#one-of-each-in-flight):
          1. Mempool -- collecting (always).
          2. Round -- agreeing (one at a time).
          3. Settle -- settling (one at a time).

        Each stage takes ~one bucket width. At bucket boundaries the pipeline advances:
        Settle finishes (commit or fall-through), Round's ratified Block promotes into the
        just-freed Settle slot, Mempool freezes into a fresh Round, new Mempool opens."""
        if self.current_bucket < 0:
            self.current_bucket = self._bucket_of(now)

        # Advance the in-flight Settle. Its abandon_by aligns with the next bucket boundary,
        # so at tick-time it is either SETTLED (commit) or transitions to ABANDONED (fall-
        # through) exactly when we need the slot for the next promotion.
        if self.settling is not None:
            self.settling.settle_round.tick(now)
            self.settle_adapter.flush(self.settling.settle_round, now)
            if self.settling.settle_round.settled() is not None:
                self._on_settled(now)
            elif self.settling.settle_round.abandoned():
                self._on_settle_abandoned(now)

        # Advance the in-flight Round. Same cadence: abandon_by hits at the next bucket
        # boundary. On ratification the Block will promote to the (now-cleared) settle slot
        # below; on abandon its held txs re-enter the mempool.
        if self.current_round is not None:
            self.current_round.tick(now)
            self.adapter.flush(self.current_round, now)
            if self.current_round.abandoned():
                self._on_round_abandoned(now)

        # Promote a ratified Round to the settling slot if both are available. If the Round
        # ratified while settling was still busy (early-ratify + slow-settle), promotion
        # waits until this tick when settling has cleared -- no queue is needed because
        # only one Round is ever in flight at a time.
        if (
            self.current_round is not None
            and self.current_round.ratified() is not None
            and self.settling is None
        ):
            self._promote_to_settling(now)

        # Swap on bucket boundaries: freeze the current mempool into a Round, open a fresh
        # mempool for the next bucket. Only if the previous Round has fully cleared -- if
        # `current_round` still holds a ratified block waiting for settling to free, this
        # bucket boundary is skipped and the current mempool keeps collecting; the txs join
        # the eventual next Round when the pipeline unblocks.
        while self.current_bucket < self._bucket_of(now) and self.current_round is None:
            frozen = self.mempool
            self.mempool = Mempool(self.tunables.mempool)
            self._open_round(self.current_bucket, frozen, now)
            self.current_bucket += 1

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
        self.current_round = r
        self.adapter.flush(r, now)

    def _on_round_abandoned(self, now: Millis) -> None:
        """The in-flight Round timed out without ratifying. Every tx it held goes back through
        the mempool door -- some re-enter for a later bucket, some are past-`w_valid` and get
        refused there (#endorser-refuses-stale + #fall-through-through-the-door). Clears
        `current_round` so the next bucket boundary can open a fresh Round
        (#one-of-each-in-flight)."""
        r = self.current_round
        if r is None:  # unreachable: caller only calls when current_round exists
            raise InvariantError("_on_round_abandoned called with no in-flight Round")
        for tx in r.surviving():
            refusal = self.mempool.admit(tx, now, self.store, self.mgmt)
            if refusal is None and self.reflood is not None:
                self.reflood(tx, now)
        self.current_round = None

    def _promote_to_settling(self, now: Millis) -> None:
        """Move the ratified Block out of `current_round` and into a fresh SettleRound in the
        `settling` slot (#one-of-each-in-flight). Clears `current_round` so the next bucket
        boundary opens a new one. Builds the Layer preview, computes anchors, constructs the
        SettleRound with its own abandon_by (one bucket ahead), emits our own SettleSig."""
        r = self.current_round
        if r is None:  # unreachable: caller only calls when current_round exists
            raise InvariantError("_promote_to_settling with no in-flight Round")
        block = r.ratified()
        if block is None:
            raise InvariantError("_promote_to_settling with unratified Round")
        bucket = r.bucket()
        slice_txs = r.slice_bodies()
        surviving = r.surviving()
        self.current_round = None

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
        dropped_from_slice = tuple(rej.tx for rej in screened.rejects)

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
        # abandon_by is one bucket ahead of now per _settle_abandon_by; aligns with the
        # pipeline cadence per SPEC anchor one-of-each-in-flight; if quorum does not
        # converge in that window the Settle abandons and the slice txs re-enter the mempool.
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

    def _on_settle_abandoned(self, now: Millis) -> None:
        """The in-flight SettleRound timed out without quorum on anchors (#one-of-each-in-flight
        + #settlement-may-hang). No block commits. Every tx the Settle previewed goes back
        through the mempool door -- both `applied` (accepted by the preview evaluator) and
        `dropped` (rejected by the preview) -- because NONE of them actually landed in the
        log. Same fall-through as SETTLED, minus the commit.

        Also re-admits `surviving` (Round-held txs that were never in the slice) because the
        Round handed them to us and we'd otherwise lose them.

        Slot clears; next tick's promotion opens the next Round's Block for a fresh attempt
        at the same block position (the eventual SETTLED block claims `block_num = head+1`,
        which does not advance across abandonment)."""
        s = self.settling
        if s is None:  # unreachable: caller only calls when settling exists
            raise InvariantError("_on_settle_abandoned called with no settling slot")
        for tx in (*s.applied, *s.dropped, *s.surviving):
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
