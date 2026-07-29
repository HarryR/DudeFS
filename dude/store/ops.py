# dude — the operation vocabulary. See ../SPEC.md §1.
#
# The whole write surface, and it is deliberately this small (#one-write-vocabulary, RISC not CISC):
#
#   mutations   set(name, value) | del(name)                     1.4
#
# NAMES ARE ARBITRARY-LENGTH BYTES. A 32-byte derived token (crypto.NameToken) is the DATA-STORE
# CONVENTION, not a store-level constraint: the management store holds cleartext paths like
# b"node/<pubkey>" because #management-is-cleartext makes control operations readable, and because a
# node must be
# able to ENUMERATE node records by prefix — neither of which works with opaque fixed-width digests.
#   predicates  absent(store, name) | holds(store, name, digest)  1.6b
#   the step    Step(guards, mutation) — a write CARRYING its guards    1.4
#   the unit    Transaction — an ORDERED LOG of steps, composable       1.4a
#               SignedTransaction — the same, authored and signed
#
# Anything compound is a transaction of these, never a new operation kind. There is no add_node,
# no rotate, no remove_node — each of those is N primitives in one atomic transaction.
#
# A PREDICATE CARRIES ITS OWN STORE, so a transaction may read one store while writing another —
# a data write conditional on management state, for instance. Reads are open; the ACL governs
# WRITES (#coarse-acl). And a key's identity is the PAIR (store, name): the same name token in two
# stores is two different keys, which is why `effects` and `reads` are keyed by the pair.
#
# WHAT AN AUTHOR SIGNS, and what it cannot: the author signs its content — store, timestamp,
# predicates, mutations. It does NOT sign its position, because a settled index does not exist
# until the batch settles (#position-is-not-authored). Chain pointers and the settled index are
# attached by
# settlement and live beside the entry, never inside its signature (11.2b).

from __future__ import annotations

from dataclasses import dataclass

from ..core import codec, crypto
from ..core.errors import DudeError


class OpError(DudeError):
    """A malformed operation: bad arity, unknown tag, wrong field type. Hostile input at a decode
    boundary is EXPECTED input (see crashonly.py), so it is typed rather than an untyped crash."""


# --------------------------------------------------------------------------- #
# Stores — the coarse ACL domain (#coarse-acl). A small cleartext integer, so a   #
# node can check `author may write store` without ever seeing a key.           #
# --------------------------------------------------------------------------- #

STORE_MANAGEMENT = 0
STORE_DATA = 1  # 1+ are data stores

# There is deliberately NO compaction store (#coarse-acl): compaction is behind-the-scenes storage
# machinery, not an ACL domain, and no client write can address it. The compactor's grant is over
# an operation KIND, not a store.


# --------------------------------------------------------------------------- #
# Mutations                                                                    #
# --------------------------------------------------------------------------- #

_SET = b"s"
_DEL = b"d"


@dataclass(frozen=True, slots=True)
class Set:
    """Write `value` at `name` in `store`. `value` is ciphertext to everyone below the client
    (#per-item-key); `store` is cleartext so authority is checkable blind (9.3b)."""

    store: int
    name: bytes
    value: bytes

    def encode(self) -> list:
        return [_SET, self.store, self.name, self.value]


@dataclass(frozen=True, slots=True)
class Del:
    """Remove `name`. A DISTINCT primitive, not `set(name, b"")` — #one-write-vocabulary keeps
    *absent* and
    *holds empty bytes* different facts, and collapsing them makes the difference unstateable."""

    store: int
    name: bytes

    def encode(self) -> list:
        return [_DEL, self.store, self.name]


type Mutation = Set | Del


def _mutation_from(v: codec.Bencodable) -> Mutation:
    p = codec.as_seq(v)
    tag = codec.as_bytes(p[0]) if p else b""
    if tag == _SET:
        p = codec.as_seq(v, 4)
        return Set(codec.as_int(p[1]), codec.as_bytes(p[2]), codec.as_bytes(p[3]))
    if tag == _DEL:
        p = codec.as_seq(v, 3)
        return Del(codec.as_int(p[1]), codec.as_bytes(p[2]))
    raise OpError(f"unknown mutation tag {tag!r}")


# --------------------------------------------------------------------------- #
# Predicates (#predicates — v1 is these two)                                     #
# --------------------------------------------------------------------------- #

_ABSENT = b"a"
_HOLDS = b"h"

# Entry kinds, as stored in the log (#collection-is-a-log-entry: a compaction is an entry like any
# other).
KIND_TRANSACTION = 0
KIND_COMPACTION = 1
_KIND_COMPACTION = b"compact"


@dataclass(frozen=True, slots=True)
class Absent:
    """`name` has no value in `store`. Distinct from holding empty bytes."""

    store: int
    name: bytes

    def encode(self) -> list:
        return [_ABSENT, self.store, self.name]


@dataclass(frozen=True, slots=True)
class Holds:
    """`name` holds a value whose ciphertext digests to `digest`.

    The author QUOTES a fingerprint of the bytes it read — it never derives what the ciphertext
    ought to be (#random-nonce). That is what lets the nonce be random, so a key's value cardinality
    is not observable, while a node still evaluates the predicate by comparison alone."""

    store: int
    name: bytes
    digest: crypto.Digest

    def encode(self) -> list:
        return [_HOLDS, self.store, self.name, self.digest]


type Predicate = Absent | Holds


def _predicate_from(v: codec.Bencodable) -> Predicate:
    p = codec.as_seq(v)
    tag = codec.as_bytes(p[0]) if p else b""
    if tag == _ABSENT:
        p = codec.as_seq(v, 3)
        return Absent(codec.as_int(p[1]), codec.as_bytes(p[2]))
    if tag == _HOLDS:
        p = codec.as_seq(v, 4)
        return Holds(
            codec.as_int(p[1]),
            codec.as_bytes(p[2]),
            crypto.Digest(codec.as_bytes(p[3])),
        )
    raise OpError(f"unknown predicate tag {tag!r}")


def value_digest(ciphertext: bytes) -> crypto.Digest:
    """The fingerprint a `Holds` predicate quotes. One place, so a predicate written by a client
    and evaluated by a node cannot disagree about what was digested."""
    return crypto.h(ciphertext)


# --------------------------------------------------------------------------- #
# Transaction — the atomic unit (#last-write-wins)                                    #
# --------------------------------------------------------------------------- #


@dataclass(frozen=True, slots=True)
class Step:
    """One mutation and the guards that must hold **immediately before it**.

    #one-write-vocabulary says a write *carries* its predicates, and the attachment is the point. A
    transaction is a LOG of steps, evaluated in sequence exactly as if each were applied
    directly to the store, so step N's guards see steps 1..N-1. Hoisting every guard up to
    the transaction gives a second model with different behaviour from the store's — which
    is how "set A, then act on what A now is" becomes inexpressible, and two models with
    different behaviour is one model too many."""

    guards: tuple[Predicate, ...]
    mutation: Mutation

    def encode(self) -> list:
        return [[g.encode() for g in self.guards], self.mutation.encode()]

    @classmethod
    def decode(cls, v: codec.Bencodable) -> Step:
        p = codec.as_seq(v, 2)
        return cls(tuple(_predicate_from(x) for x in codec.as_seq(p[0])), _mutation_from(p[1]))


@dataclass(frozen=True, slots=True)
class Transaction:
    """An **ordered log of guarded steps**. Unsigned, store-agnostic, composable.

    Atomic (#last-write-wins): invalidated if any constituent cannot be applied — for any
    reason, authority
    included — so it lands whole or not at all, across however many stores it touches.

    Evaluated with in-transaction read-uncommitted isolation, against a `store.Layer`. That is what
    makes *authorise → use the authorisation → revoke it* expressible as ONE atomic unit.

    **Composable**: `a + b` concatenates the logs. Only defined on UNSIGNED transactions — signing
    yields a different type, so adding to a signed one is a type error rather than a warning."""

    steps: tuple[Step, ...] = ()

    def __add__(self, other: Transaction) -> Transaction:
        if not isinstance(other, Transaction):
            return NotImplemented
        return Transaction(self.steps + other.steps)

    def then(self, mutation: Mutation, *guards: Predicate) -> Transaction:
        """Append one guarded step; reads left-to-right in order of application."""
        return Transaction((*self.steps, Step(tuple(guards), mutation)))

    def sign(self, kp: crypto.Keypair, ts: int) -> SignedTransaction:
        """Bind an identity and a clock, and sign. `ts` is the author's own clock (#buckets) — the
        bucket follows from it, so it is signed content."""
        return SignedTransaction(kp.public, ts, self, kp.sign(_body(kp.public, ts, self.steps)))

    @property
    def mutations(self) -> tuple[Mutation, ...]:
        return tuple(st.mutation for st in self.steps)

    @property
    def guards(self) -> tuple[Predicate, ...]:
        return tuple(g for st in self.steps for g in st.guards)

    def writes(self) -> tuple[tuple[int, bytes], ...]:
        """Every `(store, key)` written, in order."""
        seen: dict[tuple[int, bytes], None] = {}
        for m in self.mutations:
            seen.setdefault((m.store, m.name), None)
        return tuple(seen)

    def reads(self) -> tuple[tuple[int, bytes], ...]:
        """Every `(store, key)` a guard depends on."""
        seen: dict[tuple[int, bytes], None] = {}
        for g in self.guards:
            seen.setdefault((g.store, g.name), None)
        return tuple(seen)

    def stores(self) -> frozenset[int]:
        """Every store written. Authority is per-step against the evolving state, not once against
        this set — but the set is what a mempool screens on cheaply (#coarse-acl)."""
        return frozenset(st for st, _ in self.writes())

    def effects(self) -> dict[tuple[int, bytes], crypto.Digest | None]:
        """Post-state per `(store, key)`: a digest if present, `None` if absent. Later steps win,
        because the log is ordered (#last-write-wins)."""
        out: dict[tuple[int, bytes], crypto.Digest | None] = {}
        for m in self.mutations:
            out[(m.store, m.name)] = value_digest(m.value) if isinstance(m, Set) else None
        return out


def writes(*mutations: Mutation) -> Transaction:
    """A transaction of unguarded writes — the common shape for an API emitting a fragment."""
    return Transaction(tuple(Step((), m) for m in mutations))


def _body(author: crypto.PublicKey, ts: int, steps: tuple[Step, ...]) -> bytes:
    """The canonical bytes an author signs. Position is absent by construction: a settled index does
    not exist yet, and reaching for one is #position-is-not-authored's bug."""
    return codec.encode([author, ts, [st.encode() for st in steps]])


@dataclass(frozen=True, slots=True)
class SignedTransaction:
    """A transaction bound to an author and a clock, and signed. The wire and log form.

    A different type from `Transaction` rather than the same type with an optional signature:
    "maybe signed" is an ambiguous `None` standing in for two states, the shape that produced the
    previous package's worst safety bug. An unsigned value cannot reach `Store.apply`."""

    author: crypto.PublicKey
    ts: int
    txn: Transaction
    sig: crypto.Signature

    @property
    def steps(self) -> tuple[Step, ...]:
        return self.txn.steps

    @property
    def raw(self) -> bytes:
        return codec.encode([_body(self.author, self.ts, self.steps), self.sig])

    @property
    def op_hash(self) -> crypto.Digest:
        """Content address — over the bytes as received (#content-address)."""
        return crypto.h(self.raw)

    def verify(self) -> bool:
        return self.author.verify(_body(self.author, self.ts, self.steps), self.sig)

    @classmethod
    def decode(cls, raw: bytes) -> SignedTransaction:
        """Decode and TYPE-CHECK. The signature is the caller's to verify: the two failures mean
        different things and a caller may want only one."""
        outer = codec.as_seq(codec.decode(raw), 2)
        body = codec.as_seq(codec.decode(codec.as_bytes(outer[0])), 3)
        return cls(
            crypto.PublicKey(codec.as_bytes(body[0])),
            codec.as_int(body[1]),
            Transaction(tuple(Step.decode(x) for x in codec.as_seq(body[2]))),
            crypto.Signature(codec.as_bytes(outer[1])),
        )

    def writes(self) -> tuple[tuple[int, bytes], ...]:
        return self.txn.writes()

    def reads(self) -> tuple[tuple[int, bytes], ...]:
        return self.txn.reads()

    def stores(self) -> frozenset[int]:
        return self.txn.stores()

    def effects(self) -> dict[tuple[int, bytes], crypto.Digest | None]:
        return self.txn.effects()


def _satisfied_by(pred: Predicate, post: crypto.Digest | None) -> bool:
    """Would `pred` hold against a key left in state `post`?"""
    if isinstance(pred, Absent):
        return post is None
    return post is not None and post == pred.digest


def falsifies(a: SignedTransaction, b: SignedTransaction) -> bool:
    """Would `a`'s effects invalidate any of `b`'s predicates? Compared per `(store, key)`, so a
    name in one store never falsifies a predicate about the same name in another."""
    eff = a.effects()
    return any(
        (p.store, p.name) in eff and not _satisfied_by(p, eff[(p.store, p.name)])
        for p in b.txn.guards
    )


# --------------------------------------------------------------------------- #
# Compaction — the other kind of log entry (#collection-is-a-log-entry)                         #
# --------------------------------------------------------------------------- #


type LogEntry = SignedTransaction | Compaction
"""What a log entry may be. Closed by construction: a transaction, or a collection."""


@dataclass(frozen=True, slots=True)
class Compaction:
    """A consensus-agreed log entry that COLLECTS ONE SEGMENT, whole.

    It declares a single segment id and nothing else. That is the whole change from the entry-level
    design it replaces, and it is why so much machinery disappeared: there is no scattered drop set,
    no chain to splice, and no per-entry accumulator arithmetic, because a segment IS a run by
    construction and its accumulator is one value to subtract.

    Collecting is refused while the segment holds live values (see `Store.collect`). Those
    stragglers
    migrate forward first, which is what keeps `A_state` invariant across a collection — and
    there is
    always at least one class of them, since genesis grants and roster rows live for the lifetime of
    the log."""

    segment: int
    height: int = 0
    """The log position this collection attests. A snapshot has no memory of how many entries
    produced it, so height cannot be derived and must be carried."""

    acc_state: crypto.Accumulator = crypto.ACC_IDENTITY
    """The fold AFTER collecting. Collection is state-preserving, so this equals the fold before —
    which is exactly what makes it checkable by anyone still holding the segment."""

    signers: crypto.SignerBitmap = crypto.NO_SIGNERS
    sigs: tuple[crypto.Signature, ...] = ()
    """The quorum's ratification. Not decoration: collection deletes the joiner's only other
    verification path, so a collection nobody signed is a collection nobody can check.
    `attested` reports the plain complaint — "no signature" — rather than failing later and
    obscurely."""

    def attest_bytes(self) -> bytes:
        """What the quorum signs: the claim, without the signatures over it."""
        return codec.encode([KIND_COMPACTION, self.segment, self.height, self.acc_state])

    def attested(self, roster: list[crypto.PublicKey]) -> str | None:
        """`None` if the ratification holds, else why not — in words a log line can carry."""
        if not self.sigs:
            return "no signature"
        if len(self.signers) != crypto.bitmap_size(len(roster)):
            return "signer bitmap does not match the roster"
        if not crypto.Ed25519ListMultiSig.verify(
            self.signers, list(self.sigs), self.attest_bytes(), roster
        ):
            return "a signature does not match its named signer"
        return None

    def encode(self) -> bytes:
        return codec.encode(
            [
                KIND_COMPACTION,
                self.segment,
                self.height,
                self.acc_state,
                self.signers,
                list(self.sigs),
            ]
        )

    @property
    def raw(self) -> bytes:
        return self.encode()

    @property
    def op_hash(self) -> crypto.Digest:
        return crypto.h(self.raw)

    @classmethod
    def decode(cls, raw: bytes) -> Compaction:
        p = codec.as_seq(codec.decode(raw), 6)
        if codec.as_int(p[0]) != KIND_COMPACTION:
            raise OpError("not a compaction entry")
        return cls(
            codec.as_int(p[1]),
            codec.as_int(p[2]),
            crypto.Accumulator(codec.as_bytes(p[3])),
            crypto.SignerBitmap(codec.as_bytes(p[4])),
            tuple(crypto.Signature(codec.as_bytes(s)) for s in codec.as_seq(p[5])),
        )


def conflicts(a: SignedTransaction, b: SignedTransaction) -> bool:
    """Are `a` and `b` mutually exclusive? **Only if one would invalidate the other's predicates.**

    A pure function of the two envelopes (#settlement), so two honest nodes holding different
    mempools always agree — it consults no state, because at endorsement time there is none (2.9).
    But it IS value-dependent, and two cases show why "touches the same key" is the wrong rule:

    * **Two unconditional writes to one key do NOT conflict.** Neither carries a predicate, so
      nothing is invalidated; both settle and the deterministic order decides the final value.
      That is a race, not an exclusion, and dropping one of them would be losing a write nobody
      asked to be protected.
    * **A write establishing exactly what the other expects does NOT conflict.** If `a` sets K to
      a value digesting to `d` and `b` requires `holds(K, d)`, then `b`'s predicate holds *after*
      `a` — they compose rather than exclude."""
    return falsifies(a, b) or falsifies(b, a)
