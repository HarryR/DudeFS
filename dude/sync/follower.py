# dude.sync.follower -- the follower state machine. See SPECv2 (#sync-layer-no-compaction).
#
# WHAT ONE FOLLOWER DOES. Given a Store, a Management view, and a set of peers, drive the
# node's head to the cluster's current head by:
#   * periodically polling peers with `HeightAsk` to learn where they are;
#   * when any peer reports higher, pulling `GetBlock(my_head + 1)` from that peer;
#   * on `SettledBlockReply`, verifying (chain link + settle_sigs + body-block correspondence +
#     body sigs + preview-anchors-match) and committing atomically;
#   * repeating until `caught_up()` -- `f+1` fresh distinct peer replies at `(my_block_num,
#     my_tip_hash)`.
#
# SANS-I/O DISCIPLINE. Same shape as Round and SettleRound: `tick(now)`, `receive(msg, from_,
# now)`, `outbox()`. Postman is the impure edge (via `SyncAdapter`). Nothing here reads a
# clock, opens a socket, or spawns anything. Messages in and out are `SyncMsg` values, not
# raw `(verb, body)` pairs; decode failures are the wire's problem, not the state machine's.
#
# WHAT IT DOES NOT DO. Serve inbound HEIGHT / GETBLOCK -- those are stateless functions
# (`serve_height`, `serve_getblock`) called by Node's handlers. Produce SETTLED blocks -- that
# is `Coordinator`'s job. Store persistence -- `Store.commit_block` is the durable path, called
# once per verified pulled block.
#
# COORDINATOR AND FOLLOWER DO NOT REFERENCE EACH OTHER. They share the Store as the meeting
# point (Coordinator produces, Follower consumes; Coordinator's next tick sees the head
# Follower advanced). Same discipline as Settlement-does-not-cross-Mempool applied at the
# L4/L6 boundary (#sync-in-its-own-module).

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
from ..store.management import Management
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


class FollowerError(DudeError):
    """A misuse of the Follower API (called out of order, contradictory input). Not for peer
    misbehaviour -- that is a silent drop, tracked via `_bad_sources`. Not for invariant
    violation -- that is `InvariantError`."""


@dataclass(frozen=True, slots=True)
class HeightReport:
    """A peer's last reported height. `at` is when we RECEIVED it, so freshness accounts for
    reply latency; `block_num` and `tip_hash` are the reported (chain-verifiable at pull time)
    head."""

    block_num: Index
    tip_hash: crypto.Digest
    at: Millis


@dataclass(frozen=True, slots=True)
class PullInFlight:
    """A GetBlock request awaiting its SettledBlockReply / Refused reply. `sent_at` is when we
    posted the request, for `pull_timeout` accounting."""

    peer: crypto.PublicKey
    block_num: Index
    sent_at: Millis


type OutboxItem = tuple[crypto.PublicKey, SyncMsg]


@dataclass(slots=True)
class Follower:
    """One node's sync driver. Constructed once by Node; ticks alongside Coordinator; consumes
    and produces `SyncMsg` values at its `receive`/`outbox` boundary; touches Store only through
    `commit_block`.

    NOT thread-safe. Neither is Coordinator; both live inside a single-threaded Node."""

    me: crypto.Keypair
    store: Store
    mgmt: Management
    tunables: SyncTunables
    _heads: dict[crypto.PublicKey, HeightReport] = field(default_factory=dict)
    _poll_at: dict[crypto.PublicKey, Millis] = field(default_factory=dict)
    _pulling: PullInFlight | None = None
    _bad_sources: set[crypto.PublicKey] = field(default_factory=set)
    """Peers dropped from the pull-source pool: they served a bad block, refused when they
    said they had the height, or reported a divergent tip. Still polled (in case telemetry
    cares) but not asked to serve GetBlock. In-memory only -- persistence is a post-L6 arc
    (SPECv2 #sync-safety-vs-full-bft)."""
    _outbox: list[OutboxItem] = field(default_factory=list)

    # -- membership ------------------------------------------------------------------------- #

    def add_peer(self, peer: crypto.PublicKey, now: Millis) -> None:
        """Register a peer to poll. Idempotent: a re-add resets the poll deadline so a
        just-discovered peer is polled at once rather than at the next natural cycle."""
        if peer == self.me.public:
            return  # never poll ourselves
        self._poll_at[peer] = now

    # -- inputs ----------------------------------------------------------------------------- #

    def receive(self, msg: SyncMsg, from_: crypto.PublicKey, now: Millis) -> None:
        """One inbound sync message from a peer -- typed `SyncMsg`, dispatched on runtime type.

        Every drop site carries an `#XXX:` comment naming what was dropped and why, so the
        rejection is visible in code rather than implicit in a bare return."""
        if from_ == self.me.public:
            # XXX: dropped -- our own key. Shouldn't happen (Postman routes by destination), but
            # a defensive check keeps a self-inflicted feedback loop impossible.
            return
        if isinstance(msg, HeightReply):
            self._on_height_reply(msg, from_, now)
        elif isinstance(msg, SettledBlockReply):
            self._on_settled_block(msg, from_, now)
        elif isinstance(msg, Refused):
            self._on_refused(msg, from_, now)
        # XXX: dropped -- `HeightAsk` and `GetBlock` are the answering side's concern; the
        # Follower is the ASKING side. Node's dispatcher routes those to `serve_*` helpers.

    def on_bad_reply(self, from_: crypto.PublicKey) -> None:
        """The wire got a reply from `from_` that didn't decode. Drop as a pull source and
        clear any in-flight pull to this peer. Called by Node when `decode` fails on
        SETTLED_BLOCK -- a peer serving garbage is not a decoder concern, it's a source
        concern."""
        self._drop_source(from_)

    def tick(self, now: Millis) -> None:
        """Advance time. Poll peers whose deadline has passed; time out an in-flight pull that
        exceeded `pull_timeout`; start a pull if we are behind."""
        # 1. Poll due peers.
        for peer, deadline in list(self._poll_at.items()):
            if now >= deadline:
                self._enqueue(peer, HeightAsk())
                self._poll_at[peer] = now + self.tunables.poll_interval
        # 2. Pull timeout: if we've been waiting too long, give up on this peer for this pull.
        p = self._pulling
        if p is not None and now - p.sent_at > self.tunables.pull_timeout:
            # XXX: dropped -- peer did not answer in time. This peer stays polled (its
            # HeightReply is still evidence toward caught_up) but is a `_bad_sources` for now;
            # a future refinement could track "unhelpful for this block_num" instead of a
            # blanket drop.
            self._bad_sources.add(p.peer)
            self._pulling = None
        # 3. If not pulling and any healthy peer is above us, pull.
        if self._pulling is None:
            source = self._pick_pull_source()
            if source is not None:
                target_num = (self.store.head_block_num() or 0) + 1
                self._enqueue(source, GetBlock(n=target_num))
                self._pulling = PullInFlight(source, target_num, now)

    # -- outputs ---------------------------------------------------------------------------- #

    def outbox(self) -> tuple[OutboxItem, ...]:
        """Drain queued outbound messages for the adapter to send."""
        drained = tuple(self._outbox)
        self._outbox.clear()
        return drained

    def caught_up(self) -> bool:
        """True iff `f+1` fresh distinct peer replies agree on `(my_block_num, my_tip_hash)`
        (SPECv2 #height-poll-is-the-trigger, #freshness-needs-many). A fresh joiner with no
        roster yet has `n == 0`, in which case `quorum.size` cannot be computed -- returns
        False, keep pulling."""
        roster = self.mgmt.roster()
        n = len(roster)
        if n == 0:
            return False  # can't compute f+1 without a roster
        threshold = quorum.DEFAULT.size(n) - quorum.DEFAULT.tolerates(n)  # `f + 1`
        my_num = self.store.head_block_num() or 0
        my_tip = self.store.head_block_hash() or genesis_stamp(self._require_anchor())
        matches = 0
        latest_now = self._last_now()
        for peer, hr in self._heads.items():
            if peer not in roster:
                continue  # non-roster peers don't count toward the safety threshold
            if latest_now - hr.at > self.tunables.freshness_window:
                continue  # stale report; peer has gone quiet
            if hr.block_num == my_num and hr.tip_hash == my_tip:
                matches += 1
        return matches >= threshold

    # -- inbound dispatch ------------------------------------------------------------------- #

    def _on_height_reply(self, msg: HeightReply, from_: crypto.PublicKey, now: Millis) -> None:
        # Fork detection: same block_num as ours but different tip means we're on different
        # chains (#poll-detects-divergent-tips). Drop as a sync source, keep the report for
        # observability.
        my_num = self.store.head_block_num() or 0
        my_tip = self.store.head_block_hash()
        if my_tip is not None and msg.block_num == my_num and msg.tip_hash != my_tip:
            self._bad_sources.add(from_)
        self._heads[from_] = HeightReport(msg.block_num, msg.tip_hash, now)

    def _on_settled_block(  # noqa: PLR0911 -- verification pipeline is intentionally linear
        self,
        msg: SettledBlockReply,
        from_: crypto.PublicKey,
        now: Millis,  # noqa: ARG002 -- reserved for pull-latency telemetry
    ) -> None:
        p = self._pulling
        if p is None or from_ != p.peer:
            # XXX: dropped -- unsolicited SettledBlockReply, or from a peer we didn't ask.
            # Only the currently-pulled peer's reply counts.
            return
        sbwb = msg.payload
        sb = sbwb.block
        # -- Verify block_num matches what we asked for --
        if sb.anchors.block_num != p.block_num:
            self._drop_source(from_)
            return
        # -- Verify chain link against our current head (or genesis for the first block) --
        expected_prev = self.store.head_block_hash()
        if expected_prev is None:
            expected_prev = genesis_stamp(self._require_anchor())
        if sb.anchors.prev_block != expected_prev:
            self._drop_source(from_)
            return
        # -- Verify body-block correspondence (bodies are a subset of slice hashes) --
        body_hashes = frozenset(tx.op_hash for tx in sbwb.bodies)
        slice_hashes = frozenset(sb.block.hashes)
        if not body_hashes.issubset(slice_hashes):
            self._drop_source(from_)
            return
        # -- Verify each body's own signature --
        for tx in sbwb.bodies:
            if not tx.verify():
                self._drop_source(from_)
                return
        # Authorize the block. Management encapsulates the multisig verify (against the
        # current roster) AND the manager-slot override (against `store.anchor()`); a True
        # here means the block is authoritative by one path or the other, and Follower does
        # not need to know which. Manager-authored bodies then flow through the evaluator
        # via `Management.may_write`'s anchor-is-always-authorised rule -- no `auth=None`
        # bypass anywhere.
        if not self.mgmt.authorization(
            sb.signers, sb.settle_sigs, _settle_payload(sb.block.slice_hash, sb.anchors)
        ):
            self._drop_source(from_)
            return
        # Preview via Layer, verify computed anchors match signed anchors, THEN commit. This
        # is the peer-omission catch: a peer serving a subset of the real applied set would
        # produce different projected anchors and we drop before touching Store.
        bodies_ordered = tuple(sorted(sbwb.bodies, key=lambda tx: tx.op_hash))
        if not self._preview_matches_signed_anchors(bodies_ordered, sb.anchors):
            self._drop_source(from_)
            return
        # -- Commit. `first_height` is `store.head() + 1` at this moment (mirrors
        #    coordinator's `base_head + 1`), since we're about to apply bodies_ordered.
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
        self._pulling = None

    def _on_refused(
        self,
        msg: Refused,  # noqa: ARG002 -- reason kept for future per-reason handling
        from_: crypto.PublicKey,
        now: Millis,  # noqa: ARG002 -- reserved for refusal-latency telemetry
    ) -> None:
        p = self._pulling
        if p is None or from_ != p.peer:
            # XXX: dropped -- refusal to something we didn't ask, or from a peer we didn't ask.
            return
        # For now, any refusal clears the pull and marks the peer as unhelpful. A future
        # refinement could keep the peer as a source but skip THIS block_num against them
        # (NOT_YET_SETTLED means "try again later against this peer", UNKNOWN means "never
        # ask them again"). Keeping the two treatments identical avoids a state explosion
        # until scenarios demand the distinction.
        self._bad_sources.add(from_)
        self._pulling = None

    # -- internals -------------------------------------------------------------------------- #

    def _enqueue(self, peer: crypto.PublicKey, msg: SyncMsg) -> None:
        self._outbox.append((peer, msg))

    def _drop_source(self, peer: crypto.PublicKey) -> None:
        """Move a peer to `_bad_sources` and clear any in-flight pull to that peer."""
        self._bad_sources.add(peer)
        if self._pulling is not None and self._pulling.peer == peer:
            self._pulling = None

    def _pick_pull_source(self) -> crypto.PublicKey | None:
        """Highest-reporting healthy peer above our head, or None. Ties broken arbitrarily
        (dict order, which Python guarantees is insertion-order stable)."""
        my_num = self.store.head_block_num() or 0
        best: tuple[Index, crypto.PublicKey] | None = None
        for peer, hr in self._heads.items():
            if peer in self._bad_sources:
                continue
            if hr.block_num <= my_num:
                continue
            if best is None or hr.block_num > best[0]:
                best = (hr.block_num, peer)
        return best[1] if best else None

    def _require_anchor(self) -> crypto.PublicKey:
        """The manager pubkey. Must be present -- a node without an anchor is unprovisioned
        and cannot verify anything."""
        anchor = self.store.anchor()
        if anchor is None:
            raise InvariantError("store has no manager anchor; cannot compute genesis stamp")
        return anchor

    def _last_now(self) -> Millis:
        """The most recent `now` we've observed. Used by `caught_up()` to reason about
        HeightReport freshness without reading a clock."""
        return max(
            (hr.at for hr in self._heads.values()),
            default=0,
        )

    def _preview_matches_signed_anchors(
        self,
        bodies: tuple[SignedTransaction, ...],
        expected: Anchors,
    ) -> bool:
        """Replay bodies through a Layer over Store, compute anchors, compare against the
        producer-signed anchors. Mirrors `Coordinator._start_settling`'s anchor computation
        so a joiner's projection is byte-identical to the producer's when the bodies are the
        original applied set.

        A False here means the peer served bodies that don't reproduce the signed anchors --
        omission, substitution, or reordering. Drop-worthy, NOT InvariantError (which is
        reserved for our own preview-vs-commit divergence, per
        #settlement-self-divergence-is-invariant)."""
        layer = Layer(self.store)
        screened = settle.apply_to(layer, bodies, self.mgmt)
        if screened.rejects:
            # A body the producer applied got rejected by our evaluator -- either state
            # divergence (bug in our prior blocks) or peer misbehaviour. Treat as drop.
            return False
        layer.freeze()
        base_head = self.store.head()
        acc_log = self.store.log_accumulator()
        for i, tx in enumerate(screened.survivors):
            acc_log = crypto.acc_add(acc_log, log_element(base_head + i + 1, tx.op_hash))
        computed = Anchors(
            block_num=expected.block_num,  # we're verifying the CONTENT anchors, not this label
            height=base_head + len(screened.survivors),
            prev_block=expected.prev_block,  # already chain-verified above
            state_root=layer.state_root(),
            acc_state=layer.accumulator(),
            acc_log=acc_log,
        )
        return computed == expected


# --------------------------------------------------------------------------------------------- #
# Answering side: pure functions for HeightAsk / GetBlock requests.                             #
#                                                                                                #
# Node's dispatcher calls these; they touch the Store but hold no state, so they don't belong    #
# on Follower. Placed here so all sync logic sits under `dude.sync`.                             #
# --------------------------------------------------------------------------------------------- #


def serve_height(store: Store) -> HeightReply:
    """Answer an inbound `HeightAsk`. Returns a `HeightReply` with our head block_num and its
    identity hash. On a store with no SETTLED blocks yet, replies `(0, zero-digest)` -- the
    requester interprets this as 'peer holds nothing beyond what I have'."""
    block_num = store.head_block_num() or 0
    tip_hash = store.head_block_hash() or crypto.Digest(bytes(32))
    return HeightReply(block_num=block_num, tip_hash=tip_hash)


def serve_getblock(store: Store, req: GetBlock) -> SyncMsg:
    """Answer an inbound `GetBlock`. Returns `SettledBlockReply` (block + bodies) if we hold
    this block, else `Refused` with a reason (NOT_YET_SETTLED for absent blocks)."""
    block_bytes = store.settled_at(req.n)
    if block_bytes is None:
        return Refused(reason=SyncRefusal.NOT_YET_SETTLED)
    # Decode our own persisted block, re-wrap with bodies, return typed.
    sb = SettledBlock.decode(block_bytes)
    bodies = store.bodies_of_block(req.n)
    return SettledBlockReply(payload=SettledBlockWithBodies(block=sb, bodies=bodies))
