# dude.store.settle — deciding whether a transaction may land. See SPEC.md (#settlement).
#
# PURE. Takes a `Reader`, returns a verdict and the mutations that would result. No store, no
# SQLite, no clock, no I/O — which is what makes it usable in three places that look different
# but are the same question:
#
#   * the MEMPOOL, screening candidates speculatively (thousands of times, nothing durable);
#   * SETTLEMENT, deciding what a round admits;
#   * a CLIENT, checking its own transaction before submitting it.
#
# One evaluator, so all three agree. The previous package answered that question in several
# places with different answers, and the differences were where its worst defects lived.
#
# EVALUATION IS A SEQUENCE, exactly as if each step were applied directly to the store — see
# #one-write-vocabulary. Step N's guards, and step N's AUTHORITY, see state as evolved by steps
# 1..N-1. That is what makes *authorise -> use it -> revoke it* one atomic transaction rather
# than three, and why there is one behavioural model instead of one for the store and another
# for transactions.
#
# NOT here: replay. A replayer applies without re-adjudicating (#replay-does-not-readjudicate) so it
# never calls
# this — a separation that is now structural rather than a rule to remember.

from __future__ import annotations

from dataclasses import dataclass
from enum import Enum
from typing import NamedTuple, Protocol

from ..core import crypto
from ..core.errors import DudeError
from . import ops
from .layer import Layer, Reader, holds


class Authoriser(Protocol):
    """Whether an identity may write a store, **as of the state in `reader`**.

    Taking the reader per call is the whole point: during evaluation it is the transaction's own
    layer, so a grant made by an earlier step is visible to a later step's check.
    `dude.store.management.Management` satisfies this."""

    def may_write(self, reader: Reader, who: crypto.PublicKey, store_id: int) -> bool: ...


class Reason(Enum):
    """Why a transaction did not land — a CLOSED set, because callers BRANCH on it.

    `Mempool.reenter` decides permanent-drop versus keep-and-re-screen from this value, so a typo
    silently changes eviction policy rather than producing a wrong log line. That is the difference
    between a stringly-typed reason that is merely untidy and one that is load-bearing.
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

    SIGNATURE = "signature"
    """Permanently dead: a signature cannot start matching later."""
    AUTHORITY = "authority"
    """May become satisfiable — a grant can be re-issued."""
    GUARD = "guard"
    """May become satisfiable — a predicate can become true again."""
    RELOCATION = "relocation"
    """A `Move` that does not match live state, or whose credential does not vouch for it.

    May become satisfiable: the value may move again, or a correct credential may be supplied."""
    SETTLED = "settled"
    """Permanently dead, and NOT a failure: this transaction is already in the log.

    It exists because a transaction can now reach a node by two roads — settlement through the
    quorum, and log transfer from a peer that got there first (#collect-whole-segment). A node
    catching up while the same bucket settles will see both. `entry.op_hash UNIQUE` is what makes a
    settled transaction unrepeatable, and without this it enforced that by raising out of a frame
    handler: a routine race, reported as corruption."""


@dataclass(frozen=True, slots=True)
class Verdict:
    """Why a transaction may or may not land. `step` names WHICH step failed, because "the third
    write was unauthorised" is actionable where "authority" alone is not.

    NO `ok` FIELD. It used to carry one, which duplicated the negation of `why` and made two
    representations of the same fact constructible — `Verdict(True, "guard")` was expressible and
    meaningless. `ok` is now derived, so success has exactly one spelling: no reason."""

    why: Reason | None = None
    step: int | None = None

    @property
    def ok(self) -> bool:
        return self.why is None

    def __bool__(self) -> bool:
        return self.ok


OK = Verdict()


def evaluate(
    reader: Reader, tx: ops.SignedTransaction, auth: Authoriser | None = None
) -> tuple[Verdict, Layer]:
    """Walk `tx`'s step log against a fresh layer over `reader`.

    Returns the verdict and the layer. On success the layer holds the resulting mutations in order,
    ready to be committed by whoever owns persistence; on failure it is simply discarded, which is
    the whole of "rollback" — nothing was written anywhere.

    Signature first: self-contained, always checkable, so there is never an excuse to defer it."""
    layer = Layer(reader)
    if not tx.verify():
        return Verdict(Reason.SIGNATURE), layer
    for i, step in enumerate(tx.steps):
        m = step.mutation
        if isinstance(m, ops.Move):
            # NO AUTHORITY CHECK, deliberately: a relocation asserts nothing, so there is nothing
            # to be authorised for. What it must be instead is TRUE, which `_relocates` decides
            # from live state and the credential rather than from who signed the envelope.
            if not _relocates(layer, m, auth):
                return Verdict(Reason.RELOCATION, i), layer
        elif auth is not None and not auth.may_write(layer, tx.author, m.store):
            return Verdict(Reason.AUTHORITY, i), layer
        for g in step.guards:
            if not holds(layer, g):
                return Verdict(Reason.GUARD, i), layer
        layer.apply(m)
    return OK, layer


def _relocates(reader: Reader, m: ops.Move, auth: Authoriser | None) -> bool:
    """Is this move honest — and, in the management store, still vouched for?

    Two questions, and the second is the one #management-is-cleartext rows exist to survive.
    Collection eventually forgets the entry that first set a roster row, so a joiner replaying a
    compacted log would have only the quorum's word for the roster — and the roster is what defines
    the quorum. The credential carries the manager's signature forward with the row, so the chain
    back to the manager key survives any amount of compaction.

    The credential is checked against LIVE state and CURRENT authority: a valid signature from an
    author authorised now, over a transaction that sets this key to the value it presently holds.
    An old signature over a value nobody holds any more vouches for nothing."""
    if reader.get(m.store, m.name) is None:
        return False  # nothing to move; a move cannot create
    if m.store != ops.STORE_MANAGEMENT:
        return True  # data rows derive their authority from management state, which is preserved
    return _vouches(reader, m, auth)


def _vouches(reader: Reader, m: ops.Move, auth: Authoriser | None) -> bool:
    held = reader.get(m.store, m.name)
    if held is None or not m.credential:
        return False
    try:
        cred = ops.SignedTransaction.decode(m.credential)
    except DudeError:
        return False
    if not cred.verify():
        return False
    if auth is not None and not auth.may_write(reader, cred.author, m.store):
        return False
    want = ops.value_digest(held.value)
    return any(
        step.mutation.store == m.store
        and step.mutation.name == m.name
        and isinstance(step.mutation, ops.Set)
        and ops.value_digest(step.mutation.value) == want
        for step in cred.steps
    )


class Reject(NamedTuple):
    """A transaction that would not land, with the verdict saying why."""

    tx: ops.SignedTransaction
    verdict: Verdict


class Screened(NamedTuple):
    """The result of screening a batch. Named because the old signature —
    `tuple[tuple[Tx, ...], tuple[tuple[Tx, Verdict], ...]]` — could be unpacked backwards without
    error, and reads as noise in any language."""

    survivors: tuple[ops.SignedTransaction, ...]
    rejects: tuple[Reject, ...]


def would_apply(
    reader: Reader, batch: tuple[ops.SignedTransaction, ...], auth: Authoriser | None = None
) -> Screened:
    """Screen a whole batch without touching anything.

    Ordered, and later transactions see earlier survivors — because each is evaluated over a layer
    that has absorbed them. This is what a mempool runs to decide what is worth carrying, and what
    a client runs to find out whether its own transaction will land."""
    base = Layer(reader)
    keep: list[ops.SignedTransaction] = []
    drop: list[Reject] = []
    for tx in batch:
        verdict, layer = evaluate(base, tx, auth)
        if verdict:
            base.absorb(layer)
            keep.append(tx)
        else:
            drop.append(Reject(tx, verdict))
    return Screened(tuple(keep), tuple(drop))
