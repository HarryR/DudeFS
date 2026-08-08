from __future__ import annotations

from dataclasses import dataclass

from ..core import codec, crypto
from ..core.errors import DudeError


class OpError(DudeError): ...


STORE_MANAGEMENT = 0
STORE_DATA = 1


EPOCH_NONE = 0

_SET = b"s"
_DEL = b"d"


@dataclass(frozen=True, slots=True)
class Set:
    store: int
    name: bytes
    value: bytes
    epoch: int = EPOCH_NONE

    def encode(self) -> list:
        return [_SET, self.store, self.name, self.value, self.epoch]


@dataclass(frozen=True, slots=True)
class Del:
    store: int
    name: bytes

    def encode(self) -> list:
        return [_DEL, self.store, self.name]


type Mutation = Set | Del


def _mutation_from(v: codec.Bencodable) -> Mutation:
    p = codec.as_seq(v)
    tag = codec.as_bytes(p[0]) if p else b""
    if tag == _SET:
        p = codec.as_seq(v, 5)
        return Set(
            codec.as_int(p[1]), codec.as_bytes(p[2]), codec.as_bytes(p[3]), codec.as_int(p[4])
        )
    if tag == _DEL:
        p = codec.as_seq(v, 3)
        return Del(codec.as_int(p[1]), codec.as_bytes(p[2]))
    raise OpError(f"unknown mutation tag {tag!r}")


_ABSENT = b"a"
_HOLDS = b"h"


@dataclass(frozen=True, slots=True)
class Absent:
    store: int
    name: bytes

    def encode(self) -> list:
        return [_ABSENT, self.store, self.name]


@dataclass(frozen=True, slots=True)
class Holds:
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
    return crypto.h(ciphertext)


@dataclass(frozen=True, slots=True)
class Step:
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
    steps: tuple[Step, ...] = ()

    def __add__(self, other: Transaction) -> Transaction:
        if not isinstance(other, Transaction):
            return NotImplemented
        return Transaction(self.steps + other.steps)

    def then(self, mutation: Mutation, *guards: Predicate) -> Transaction:
        return Transaction((*self.steps, Step(tuple(guards), mutation)))

    def sign(self, kp: crypto.Keypair, ts: int) -> SignedTransaction:
        return SignedTransaction(
            kp.public, ts, self, kp.sign(_body_bytes(kp.public, ts, self.steps))
        )

    @property
    def mutations(self) -> tuple[Mutation, ...]:
        return tuple(st.mutation for st in self.steps)

    @property
    def guards(self) -> tuple[Predicate, ...]:
        return tuple(g for st in self.steps for g in st.guards)

    def writes(self) -> tuple[tuple[int, bytes], ...]:
        seen: dict[tuple[int, bytes], None] = {}
        for m in self.mutations:
            seen.setdefault((m.store, m.name), None)
        return tuple(seen)

    def reads(self) -> tuple[tuple[int, bytes], ...]:
        seen: dict[tuple[int, bytes], None] = {}
        for g in self.guards:
            seen.setdefault((g.store, g.name), None)
        return tuple(seen)

    def stores(self) -> frozenset[int]:
        return frozenset(st for st, _ in self.writes())

    def effects(self) -> dict[tuple[int, bytes], crypto.Digest | None]:
        out: dict[tuple[int, bytes], crypto.Digest | None] = {}
        for m in self.mutations:
            out[(m.store, m.name)] = value_digest(m.value) if isinstance(m, Set) else None
        return out


def writes(*mutations: Mutation) -> Transaction:
    return Transaction(tuple(Step((), m) for m in mutations))


def _body_bytes(author: crypto.PublicKey, ts: int, steps: tuple[Step, ...]) -> bytes:
    return codec.encode([author, ts, [st.encode() for st in steps]])


@dataclass(frozen=True, slots=True)
class SignedTransaction:
    author: crypto.PublicKey
    ts: int
    txn: Transaction
    sig: crypto.Signature

    @property
    def steps(self) -> tuple[Step, ...]:
        return self.txn.steps

    @property
    def _body(self) -> bytes:
        return _body_bytes(self.author, self.ts, self.steps)

    @property
    def raw(self) -> bytes:
        return codec.encode([self._body, self.sig])

    @property
    def op_hash(self) -> crypto.Digest:
        return crypto.h(self.raw)

    def verify(self) -> bool:
        return self.author.verify(self._body, self.sig)

    @classmethod
    def decode(cls, raw: bytes) -> SignedTransaction:
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


type LogEntry = SignedTransaction
