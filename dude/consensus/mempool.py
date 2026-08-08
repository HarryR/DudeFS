# dude.mempool — candidate transactions, and the slice proposed from them. See SPEC.md (#mempool).
#
# SANS-I/O and clock-free: `now` is a parameter, so a test drives a decade of buckets in
# microseconds and a replay is bit-identical.
#
# THE INVARIANT THE WHOLE DESIGN RESTS ON (#timing): **the clock may choose, it may not judge.**
# It is consulted in exactly two places -- `admit` (the door) and `propose` (what to offer) --
# and nowhere in verifying a proposal, since settlement is by log index. A node with a skewed
# clock therefore proposes badly and accepts correctly. Any clock read outside those two methods
# is the bug that turns skew from a throughput cost into a liveness or safety failure.

from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum
from typing import Protocol

from ..core import crypto
from ..core.units import Millis
from ..store import ops, settle
from ..store.layer import Reader

type Bucket = int


@dataclass(frozen=True, slots=True)
class Tunables:
    """Timing, as #timing rules it: values that belong in the management store so they are
    consensus-agreed at a log position, rather than in a per-node file that can silently drift.

    The defaults are a well-connected deployment. A mixnet carrying the durability measures is a
    different delta, which is the entire reason these are not constants."""

    delta: Millis = 1_000
    """Bucket width. `bucket = ts / delta`, so boundaries are COMPUTED, never negotiated — there
    is no protocol for agreeing where a bucket starts.

    FLOOR: `timing.dissemination` (850 ms at the declared quantities) — a bucket narrower than
    dissemination closes before its transactions could have reached the nodes that must propose
    them. 1 s is the next round value above it.

    Changing this re-buckets everything: a change must land on a boundary aligned to both the old
    and the new value or bucket ids are ambiguous across it. Raising is safe; lowering can strand
    in-flight proposals."""

    w_admit: Millis = 30_000
    """The door. A transaction is refused if its `ts` is further than this from the receiving node's
    now, in either direction.

    FLOOR: `timing.admission_floor` (25.6 s) — the client's tolerated clock error plus a round trip.
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
    """Why the door refused — a CLOSED set (#no-exceptions-for-control-flow). Plain `Enum`, not
    `StrEnum`, for the reason given at `net.link.Refused`.

    Named reasons rather than a bool because a client must be able to tell "your clock is wrong"
    from "your transaction is invalid": the first is the ONE clock fault with a built-in signal
    (§8), and a client can only self-correct if the refusal says which it was."""

    INVALID = "invalid"
    """Reserved ordinal 0, never returned (#no-exceptions-for-control-flow)."""

    TOO_OLD = "ts-too-old"
    TOO_NEW = "ts-too-new"
    DUPLICATE = "duplicate"
    UNSIGNED = "signature"
    CANNOT_APPLY = "cannot-apply"
    """Its guards do not hold, or its author is not authorised, against COMMITTED state.

    Refused at the door rather than carried: one that cannot apply now would not have landed even
    if a batch chose it, so admitting it costs the client the one thing it wanted -- an answer.

    Distinct from `settle.Reason.GUARD`, the same condition as the EVALUATOR reports it. Two
    enumerations, one for the door and one for settlement, never compared."""


TOO_OLD = Refusal.TOO_OLD
TOO_NEW = Refusal.TOO_NEW
DUPLICATE = Refusal.DUPLICATE
UNSIGNED = Refusal.UNSIGNED
CANNOT_APPLY = Refusal.CANNOT_APPLY


class Ledger(Reader, Protocol):
    """What the admission door reads: live state, plus whether a content address has already
    settled. `Reader` alone is not enough -- #dedup-content-address puts log membership at the
    door, and a log is not a state view. Declared by the consumer, like `settle.Authoriser`.

    IT MAKES THE WRONG THING UNSAYABLE: a `Layer` reads state but holds no log, so admitting
    against an overlay -- screening with no way to see what has already landed -- is a type error
    rather than something a caller must remember."""

    def has_settled(self, op_hash: crypto.Digest) -> bool: ...


@dataclass(slots=True)
class Mempool:
    """Currently-collecting mempool: one bucket window's worth of candidate transactions,
    keyed by content address.

    A CONTAINER WITH ONE DOOR AND NOTHING ELSE. Lifecycle -- window close, freeze-with-Round,
    fall-through after settlement, body lookup at apply time -- lives in `dude.coordinator`. This
    class does not know Round or Settlement exist, or that its own window has closed. The
    Coordinator builds a fresh one per bucket; the frozen predecessor dies with the Round it
    seeded (#settlement-does-not-cross-mempool)."""

    tunables: Tunables = field(default_factory=Tunables)
    pending: dict[Bucket, dict[crypto.Digest, ops.SignedTransaction]] = field(default_factory=dict)

    # -- the door ----------------------------------------------------------------------------- #

    def valid(
        self,
        tx: ops.SignedTransaction,
        now: Millis,
        reader: Ledger,
        auth: settle.Authoriser,
    ) -> Refusal | None:
        """MAY THIS BE IN THE MEMPOOL? `None` means yes; anything else is the reason.

        ONE PREDICATE, AT EVERY DOOR. A client submitting and a reject returning from settlement
        ask the same question, so they run the same code -- two policies that agree today is how
        they stop agreeing later. `settle.would_apply` is the evaluator the store, the proposer
        and a client all use, so the four agree by construction.

        IT CONSULTS STATE, and did not: the window and the signature were checked and the
        predicates were not, so a transaction whose guards were already false was admitted,
        carried, proposed, screened out at `propose`, and left only when it aged out. The client
        learned nothing until it timed out.

        NOT the already-held check, which belongs to `admit`: that is not a fact about the
        transaction, and a reject returning is not a duplicate of itself."""
        t = self.tunables
        if now - tx.ts > t.w_admit:
            return Refusal.TOO_OLD
        if tx.ts - now > t.w_admit:
            return Refusal.TOO_NEW
        if not tx.verify():
            return Refusal.UNSIGNED
        if reader.has_settled(tx.op_hash):
            return Refusal.DUPLICATE
        if settle.would_apply(reader, (tx,), auth).rejects:
            return Refusal.CANNOT_APPLY
        return None

    def admit(
        self,
        tx: ops.SignedTransaction,
        now: Millis,
        reader: Ledger,
        auth: settle.Authoriser,
    ) -> Refusal | None:
        """The door a CLIENT knocks on: `valid`, plus "do we hold it already", plus the insert.
        `None` means admitted.

        LATE IS NOT STRANDED. A transaction whose derived bucket has passed is carried forward to
        the current one -- bounded by `w_admit`. The bucket is a floor, not an exclusion window."""
        if any(tx.op_hash in held for held in self.pending.values()):
            return Refusal.DUPLICATE
        if (why := self.valid(tx, now, reader, auth)) is not None:
            return why
        t = self.tunables
        landed = max(t.bucket(tx.ts), t.bucket(now))
        self.pending.setdefault(landed, {})[tx.op_hash] = tx
        return None

    # -- introspection ------------------------------------------------------------------------ #

    def buckets(self) -> tuple[Bucket, ...]:
        """Sorted -- never mapping order, which Go randomises (portability, not style)."""
        return tuple(sorted(b for b, held in self.pending.items() if held))

    def all_hashes(self) -> frozenset[crypto.Digest]:
        """Every op_hash held, flattened. Keeping the flatten here is what lets the internal
        bucket layout change without any caller noticing."""
        return frozenset(op_hash for txs in self.pending.values() for op_hash in txs)

    def all_bodies(self) -> dict[crypto.Digest, ops.SignedTransaction]:
        """Every tx held, by op_hash. Re-admits fall-throughs on SETTLED through the one door
        (#fall-through-through-the-door)."""
        return {tx.op_hash: tx for txs in self.pending.values() for tx in txs.values()}

    def __len__(self) -> int:
        return sum(len(held) for held in self.pending.values())
