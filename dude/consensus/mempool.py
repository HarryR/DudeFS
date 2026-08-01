# dude.mempool — candidate transactions, and the slice proposed from them. See SPEC.md (#mempool).
#
# SANS-I/O AND CLOCK-FREE EXCEPT WHERE STATED. `now` is a parameter, never read from the system
# here, so a test drives a decade of buckets in microseconds and a replay is bit-identical. Nothing
# in this module opens a socket or touches storage.
#
# THE INVARIANT THE WHOLE DESIGN RESTS ON (#timing): **the clock may choose, it may not
# judge.** It is consulted in exactly two places — `admit` (the door) and `propose` (what to offer).
# It appears nowhere in verifying a proposal, and settlement is by log index. So a node whose clock
# is skewed proposes badly and accepts correctly, which is why it follows a quorum result rather
# than being told to. Any clock read outside those two methods is a bug — specifically the bug that
# converts skew from a throughput cost into a liveness or safety failure.

from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum

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
    CANNOT_APPLY = "cannot-apply"
    """Its guards do not hold, or its author is not authorised, against COMMITTED state.

    Refused at the door rather than carried: a transaction that cannot apply now would not have
    landed even if a batch chose it, so admitting it buys the client nothing and costs it the one
    thing it wanted, an answer.

    Distinct from `settle.Reason.GUARD`, which is the same condition as the evaluator reports it:
    two enumerations, one for the door and one for settlement, never compared. See this enum's own
    note about two spellings that matched by accident."""


TOO_OLD = Refusal.TOO_OLD
TOO_NEW = Refusal.TOO_NEW
DUPLICATE = Refusal.DUPLICATE
UNSIGNED = Refusal.UNSIGNED
CANNOT_APPLY = Refusal.CANNOT_APPLY


@dataclass(slots=True)
class Mempool:
    """Currently-collecting mempool: one bucket window's worth of candidate transactions,
    keyed by content address.

    THIS CLASS IS A CONTAINER WITH ONE DOOR AND NOTHING ELSE. Lifecycle -- window close,
    freeze-with-Round, fall-through re-entry after settlement, body lookup at apply time --
    lives in `dude.coordinator`. This class does not know Round exists, does not know
    Settlement exists, does not know its own window has closed. The Coordinator constructs a
    fresh instance at every bucket boundary; the frozen predecessor goes with the Round it
    seeded and dies when that Round retires (SPECv2 #settlement-does-not-cross-mempool)."""

    tunables: Tunables = field(default_factory=Tunables)
    pending: dict[Bucket, dict[crypto.Digest, ops.SignedTransaction]] = field(default_factory=dict)

    # -- the door ----------------------------------------------------------------------------- #

    def valid(
        self,
        tx: ops.SignedTransaction,
        now: Millis,
        reader: Reader,
        auth: settle.Authoriser | None = None,
    ) -> Refusal | None:
        """MAY THIS BE IN THE MEMPOOL? `None` means yes; anything else is the reason.

        ONE PREDICATE, AT EVERY DOOR `[H]`: *"the mempool entry validity requirements must be
        consistently applied."* A client submitting and a reject returning from settlement ask the
        same question, so they run the same code. Two policies that agree today is how they stop
        agreeing later.

        IT CONSULTS STATE, and did not `[H]`: *"something that can't possibly be applied to the
        current state would never be valid even if it were chosen by a batch."* The window and the
        signature were checked and the predicates were not, so a transaction whose guards were
        already false was admitted, carried, proposed, screened out at `propose`, and left only when
        it aged out. The client learned nothing until it timed out.

        `settle.would_apply` is the evaluator the store, the proposer and a client all use, so the
        four agree by construction rather than by four implementations agreeing today.

        NOT the duplicate check, which belongs to `admit`: "already held" is not a fact about the
        transaction, and a reject returning is not a duplicate of itself."""
        t = self.tunables
        if now - tx.ts > t.w_admit:
            return Refusal.TOO_OLD
        if tx.ts - now > t.w_admit:
            return Refusal.TOO_NEW
        if not tx.verify():
            return Refusal.UNSIGNED
        if settle.would_apply(reader, (tx,), auth).rejects:
            return Refusal.CANNOT_APPLY
        return None

    def admit(
        self,
        tx: ops.SignedTransaction,
        now: Millis,
        reader: Reader,
        auth: settle.Authoriser | None = None,
    ) -> Refusal | None:
        """The door a CLIENT knocks on: `valid`, plus "do we hold it already", plus the insert.

        `None` means admitted; anything else is the reason.

        LATE IS NOT STRANDED. A transaction whose derived bucket has already passed is carried
        forward to the current one, so a client running behind settles a few buckets further
        ahead than its own clock suggests -- bounded by `w_admit`. The bucket is a floor, not
        an exclusion window."""
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
        """Every op_hash currently held, flattened across buckets. Round takes a single set;
        keeping the flatten here means callers don't need to know how holdings are laid out
        internally -- change the layout, this method changes, nothing else does."""
        return frozenset(op_hash for txs in self.pending.values() for op_hash in txs)

    def all_bodies(self) -> dict[crypto.Digest, ops.SignedTransaction]:
        """Every tx currently held, keyed by op_hash. Used to re-admit fall-throughs on SETTLED
        via the one door (#fall-through-through-the-door). Same internal-layout guarantee as
        `all_hashes`."""
        return {tx.op_hash: tx for txs in self.pending.values() for tx in txs.values()}

    def __len__(self) -> int:
        return sum(len(held) for held in self.pending.values())
