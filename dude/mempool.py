# dude.mempool — candidate transactions, and the slice proposed from them. See ../MEMPOOL.md.
#
# SANS-I/O AND CLOCK-FREE EXCEPT WHERE STATED. `now` is a parameter, never read from the system
# here, so a test drives a decade of buckets in microseconds and a replay is bit-identical. Nothing
# in this module opens a socket or touches storage.
#
# THE INVARIANT THE WHOLE DESIGN RESTS ON (MEMPOOL.md §8): **the clock may choose, it may not
# judge.** It is consulted in exactly two places — `admit` (the door) and `propose` (what to offer).
# It appears nowhere in verifying a proposal, and settlement is by log index. So a node whose clock
# is skewed proposes badly and accepts correctly, which is why it follows a quorum result rather
# than being told to. Any clock read outside those two methods is a bug — specifically the bug that
# converts skew from a throughput cost into a liveness or safety failure.

from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum

from .core import crypto
from .store import ops, settle
from .store.layer import Reader

type Bucket = int
type Millis = int


@dataclass(frozen=True, slots=True)
class Tunables:
    """Timing, as MEMPOOL.md §7.5 rules it: values that belong in the management store so they are
    consensus-agreed at a log position, rather than in a per-node file that can silently drift.

    The defaults are a well-connected deployment. A mixnet carrying the durability measures is a
    different delta, which is the entire reason these are not constants."""

    delta: Millis = 1_000
    """Bucket width. `bucket = ts / delta`, so boundaries are COMPUTED, never negotiated — there
    is no protocol for agreeing where a bucket starts.

    FLOOR: `timing.BUCKET_FLOOR` (850 ms at the declared quantities) — a bucket narrower than
    dissemination closes before its transactions could have reached the nodes that must propose
    them. 1 s is the next round value above it.

    Changing this re-buckets everything: a change must land on a boundary aligned to both the old
    and the new value or bucket ids are ambiguous across it. Raising is safe; lowering can strand
    in-flight proposals."""

    w_admit: Millis = 30_000
    """The door. A transaction is refused if its `ts` is further than this from the receiving node's
    now, in either direction.

    FLOOR: `timing.ADMISSION_FLOOR` (25.6 s) — the client's tolerated clock error plus a round trip.
    This is also the REPLAY bound: a captured transaction stays admittable for roughly this long, so
    generosity above the floor is paid for in replay window rather than in latency."""

    w_valid_margin: Millis = 3_250
    """`w_valid = w_admit + this`, the whole of the difference. A transaction admitted at the very
    edge of `w_admit` is endorsed a wave or two later, so endorsement needs that much more room. It
    is a pipeline margin, NOT a second tier of trust.

    FLOOR: `timing.endorse_margin(delta)` = 3·delta + skew = 3_250. It was 3_000 — **below its own
    floor**, so a transaction admitted at the edge of the window could be refused by endorsers while
    still inside the round it was admitted for. Found by deriving it."""

    @property
    def w_valid(self) -> Millis:
        return self.w_admit + self.w_valid_margin

    @property
    def evict_after(self) -> Millis:
        """How long a transaction may be held. EQUAL to `w_valid`, and derived rather than set.

        A transaction cannot be endorsed once `|now - ts| > w_valid`, so holding one past that is
        not generosity — it is retaining what can never settle. It was 300 s against a 33 s
        endorsable lifetime: 9x dead weight, and that surplus was exactly the window in which a
        stale compare-and-swap could be re-proposed if its value happened to come back.

        A property, not a field, so the two cannot drift apart again."""
        return self.w_valid

    def bucket(self, ts: Millis) -> Bucket:
        return ts // self.delta

    def bucket_start(self, b: Bucket) -> Millis:
        return b * self.delta


# --------------------------------------------------------------------------------------------- #
# Admission                                                                                     #
# --------------------------------------------------------------------------------------------- #


class Refusal(Enum):
    """Why the door refused — a CLOSED set, not a free string.

    Named reasons rather than a bool because the caller must tell a client "your clock is wrong"
    apart from "your transaction is invalid": the first is the ONE clock fault with a built-in
    signal (§8), and a client can only self-correct if the refusal says which it was.

    Closed rather than strings because this is a domain the layer above branches on and reports: an
    open set cannot be matched exhaustively, cannot be counted into a metric without typos, and
    drifts the moment two modules spell the same condition differently. `StrEnum`, so it still reads
    in a log.
    Plain `Enum`, deliberately NOT `StrEnum`: these never go on the wire, so the string would be a
    value nobody marshals, and `StrEnum` members ARE `str`s — which is how a comparison across two
    unrelated reason enums that happen to share a spelling came out True. Plain members compare
    False against each other and against bare strings, so a stray `== "guard"` fails loudly instead
    of silently passing. `StrEnum` is for values that are their own serialised form; `Scheme` and
    `Role` earn it, this does not.
    """

    INVALID = "invalid"
    """RESERVED, and never returned by this package. Declared FIRST so that a port to Go — where
    these become integers and a struct field's zero value is whatever member happens to be 0 —
    lands its zero value on a named invalid rather than on a real one. Without it, a zero-valued
    field silently means the first member: a bug that does not exist in Python and is very hard to
    see in review.

    Not dead code: it is load-bearing in the target, and Python's own `Enum(0)` has no meaning to
    guard. Treat receiving it as a decode fault."""

    TOO_OLD = "ts-too-old"
    TOO_NEW = "ts-too-new"
    DUPLICATE = "duplicate"
    UNSIGNED = "signature"


TOO_OLD = Refusal.TOO_OLD
TOO_NEW = Refusal.TOO_NEW
DUPLICATE = Refusal.DUPLICATE
UNSIGNED = Refusal.UNSIGNED


def tx_id(tx: ops.SignedTransaction) -> crypto.Digest:
    """A transaction's identity — `op_hash`, THE STORE'S OWN content address, deliberately not a
    second scheme of this module's invention.

    That sharing is load-bearing. Dedup on this id, not the clock, is the primary replay defence
    (§1.2), and it only works if the mempool and the log agree on what "the same transaction" means.
    A mempool-local identity would let a transaction be a duplicate here and a fresh entry there.
    `w_valid` then exists only to keep the replayable window inside the horizon over which that
    dedup still answers, since compaction eventually collects the entry."""
    return tx.op_hash


@dataclass(slots=True)
class Mempool:
    """Candidate transactions, bucketed by `ts / delta`.

    Holds no lock, no socket and no store handle: a caller drives it, and `dude.net` will carry what
    it produces. `settled` ids are remembered so a re-offered transaction is refused as a duplicate
    without consulting storage."""

    tunables: Tunables = field(default_factory=Tunables)
    pending: dict[Bucket, dict[crypto.Digest, ops.SignedTransaction]] = field(default_factory=dict)
    arrived: dict[crypto.Digest, Millis] = field(default_factory=dict)
    settled: set[crypto.Digest] = field(default_factory=set)
    highest_proposed: Bucket = -1
    """Monotone, and MUST be persisted by the caller (§8).

    A backward clock step — NTP correction, VM resume, leap second — would otherwise re-enter a
    bucket already proposed for and emit a SECOND batch for it, which is exactly the equivocation
    §4.1 convicts on, with no malice involved. Tens of seconds is the realistic magnitude, so this
    is a small durability obligation guarding against self-conviction."""

    # -- the door ----------------------------------------------------------------------------- #

    def admit(self, tx: ops.SignedTransaction, now: Millis) -> Refusal | None:
        """Judge a client's clock — the only place that happens (§1.1).

        `None` means admitted; anything else is the reason. NOT a `Refusal.ADMITTED` member: an
        enumeration of refusals must not contain "was not refused", or iterating it yields a bogus
        entry that every exhaustive match and every metric has to special-case. It also stops
        falsiness doing implicit work — the stringly-typed trick this enum replaced — and matches
        `Policy.before_send`, so the codebase has one spelling of "no objection" rather than two.

        A refusal is the *desired* outcome for a broken client: it is told, immediately, by every
        node it talks to.

        LATE IS NOT STRANDED. A transaction whose derived bucket has already passed is carried
        forward to the current one, so a client running behind settles a few buckets further ahead
        than its own clock suggests — bounded by `w_admit`. The bucket is a floor, not an exclusion
        window, so nothing that passes this gate can be stranded by arithmetic.

        UNSETTLED (MEMPOOL.md §9.0). The alternative is to DROP rather than relocate, leaving the
        client to monitor its transactions and re-issue on whatever logic its application wants.
        That is arguably better: it stops a node quietly moving a transaction to a bucket other than
        the one its author signed for. This method implements carry-forward; do not treat that as
        decided."""
        t = self.tunables
        if now - tx.ts > t.w_admit:
            return Refusal.TOO_OLD
        if tx.ts - now > t.w_admit:
            return Refusal.TOO_NEW
        if not tx.verify():
            return Refusal.UNSIGNED
        ident = tx_id(tx)
        if ident in self.settled or ident in self.arrived:
            return Refusal.DUPLICATE

        landed = max(t.bucket(tx.ts), t.bucket(now))
        self.pending.setdefault(landed, {})[ident] = tx
        self.arrived[ident] = now
        return None

    def endorsable(self, tx: ops.SignedTransaction, now: Millis) -> bool:
        """The check an ENDORSER applies to a transaction inside someone else's proposal (§1.2).

        `w_valid`, never `w_admit`. Re-applying the door would require all `q` endorsers' windows to
        agree on every member, so any skew would kill otherwise-valid slices; admission is the
        admitting node's business. This wider bound exists only to stop an unguarded write being
        replayable indefinitely."""
        return abs(now - tx.ts) <= self.tunables.w_valid

    # -- proposing ---------------------------------------------------------------------------- #

    def propose(
        self, bucket: Bucket, reader: Reader, auth: settle.Authoriser | None = None
    ) -> tuple[ops.SignedTransaction, ...]:
        """The batch this node offers for `bucket`: its eligible transactions, screened.

        DETERMINISTIC ORDER, so the largest intersection needs no search (MEMPOOL.md §3.1). Two
        nodes applying this rule to the same eligible set produce identical batches, and to
        *different* eligible sets produce batches differing only by the transactions each actually
        holds — one is a subset of the other rather than diverging. The intersection, obtained by
        construction. It also retires the ECMH-powerset idea: naming a subset is 32 bytes and free,
        but *inverting* a name costs 2^n, and nothing needs inverting because whoever names a subset
        can enumerate it.

        Screened through `settle.would_apply` so a batch is not offered containing transactions that
        cannot land — the same evaluator the store and the client use, so all three agree."""
        candidates = tuple(tx for _, tx in sorted(self.pending.get(bucket, {}).items(), key=_order))
        survivors, _ = settle.would_apply(reader, candidates, auth)
        return survivors

    def may_propose(self, bucket: Bucket) -> bool:
        """One batch per node per bucket (§4.1), and never backwards.

        This is what makes equivocation impossible rather than merely punishable: honest signers
        refuse a second batch for a bucket, so with quorum intersection `2q - n > f` two conflicting
        batches can never both be confirmed. No trusted counter is needed — precisely the
        distinction for which TrInc is shelved as a non-fit."""
        return bucket > self.highest_proposed

    def mark_proposed(self, bucket: Bucket) -> None:
        self.highest_proposed = max(self.highest_proposed, bucket)

    # -- after settlement --------------------------------------------------------------------- #

    def retire(self, txs: tuple[ops.SignedTransaction, ...]) -> None:
        """Forget transactions that made it into the log."""
        for tx in txs:
            ident = tx_id(tx)
            self.settled.add(ident)
            self.arrived.pop(ident, None)
            self._unhold(ident)
        self._sweep_empty()

    def reenter(
        self,
        rejects: tuple[tuple[ops.SignedTransaction, settle.Verdict], ...],
        now: Millis,
    ) -> tuple[ops.SignedTransaction, ...]:
        """Return rejects to the mempool, dropping what can never land. Returns what was dropped.

        REJECT REASONS ARE NOT EQUALLY FINAL, and this is where MEMPOOL.md §5's distinction earns
        its keep. "Cannot be applied given settled state" reads as "drop it", but only a bad
        signature is permanently dead: an `authority` reject becomes valid when a grant is
        re-issued, and a `guard` reject when the predicate becomes true again. Evicting on the
        verdict alone would discard transactions that are merely EARLY.

        So: keep and re-screen, and evict on age instead."""
        dropped: list[ops.SignedTransaction] = []
        for tx, verdict in rejects:
            ident = tx_id(tx)
            arrived = self.arrived.get(ident, now)
            # `settle.Reason`, NOT this module's `Refusal.UNSIGNED`. They happen to share the string
            # "signature", so the old comparison worked BY COINCIDENCE across two unrelated
            # enumerations — exactly the class of bug typing these was meant to remove.
            permanent = verdict.why is settle.Reason.SIGNATURE
            if permanent or now - arrived > self.tunables.evict_after:
                dropped.append(tx)
                self.arrived.pop(ident, None)
                self._unhold(ident)
                continue
            # Carry forward means MOVE, not copy. Omitting the removal left a copy in the old bucket
            # every round, so a transaction that kept bouncing accumulated one entry per round and
            # would be offered in several buckets at once — caught by a test, not by review.
            self._unhold(ident)
            landed = max(self.tunables.bucket(tx.ts), self.tunables.bucket(now))
            self.pending.setdefault(landed, {})[ident] = tx
            self.arrived.setdefault(ident, arrived)
        self._sweep_empty()
        return tuple(dropped)

    def evict(self, now: Millis) -> tuple[ops.SignedTransaction, ...]:
        """Age-based eviction (§5), the shape Bitcoin's mempool expiry has run for years. Holding a
        transaction until its guards happen to come true is correct; holding it forever is a
        denial-of-service."""
        horizon = self.tunables.evict_after
        gone: list[ops.SignedTransaction] = []
        for held in self.pending.values():
            for ident, tx in tuple(held.items()):
                if now - self.arrived.get(ident, now) > horizon:
                    gone.append(tx)
                    del held[ident]
                    self.arrived.pop(ident, None)
        self._sweep_empty()
        return tuple(gone)

    # -- introspection ------------------------------------------------------------------------ #

    def accumulator(self, bucket: Bucket) -> crypto.Accumulator:
        """ECMH over the bucket's transaction ids: 32 bytes naming this exact set.

        Equal accumulators mean identical sets in O(1), which is the short-circuit that makes gossip
        cheap. It deliberately does NOT support recovering the difference — that needs a sketch
        (PinSketch/IBLT), and MEMPOOL.md §3.2 declines them: Erlay pays 3.15s -> 5.75s relay latency
        for its bandwidth saving, and here wave latency IS finality latency."""
        acc = crypto.ACC_IDENTITY
        for ident in self.pending.get(bucket, {}):
            acc = crypto.acc_add(acc, crypto.acc_element(ident))
        return acc

    def buckets(self) -> tuple[Bucket, ...]:
        """Sorted — never mapping order, which Go randomises (portability, not style)."""
        return tuple(sorted(b for b, held in self.pending.items() if held))

    def __len__(self) -> int:
        return sum(len(held) for held in self.pending.values())

    def _unhold(self, ident: crypto.Digest) -> None:
        """Remove from every bucket. A transaction is held in exactly one, but sweeping all of them
        makes that an invariant this class maintains rather than one a caller must respect."""
        for held in self.pending.values():
            held.pop(ident, None)

    def _sweep_empty(self) -> None:
        for b in [b for b, held in self.pending.items() if not held]:
            del self.pending[b]


def _order(item: tuple[crypto.Digest, ops.SignedTransaction]) -> tuple[int, bytes]:
    """`(ts, id)` — the deterministic total order proposals are cut from.

    OPEN (MEMPOOL.md §9.1): ordering by `ts` means a client can gain priority by BACKDATING within
    `w_admit`, which is the only clock fault that is profitable rather than merely costly. With no
    fee auction the prize is winning CAS races on a contended key. The alternative is ordering by id
    alone, which removes the advantage and any `ts` fairness with it."""
    ident, tx = item
    return tx.ts, bytes(ident)
