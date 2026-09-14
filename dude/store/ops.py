from __future__ import annotations

import enum
import typing
from abc import ABC, abstractmethod
from dataclasses import dataclass
from typing import NamedTuple, Self

from ..core import codec, crypto
from .errors import StoreError


class OpError(StoreError): ...


STORE_MANAGEMENT = 0
STORE_DATA = 1


EPOCH_NONE = 0


class Sealed(NamedTuple):
    token: bytes
    ciphertext: bytes
    epoch: int


class Held(NamedTuple):
    value: bytes
    epoch: int
    cred: bytes

    def encode(self) -> bytes:
        return codec.encode([self.value, self.epoch, self.cred])

    @classmethod
    def decode(cls, raw: bytes) -> Self:
        parts = codec.as_seq(codec.decode(raw), 3)
        return cls(codec.as_bytes(parts[0]), codec.as_int(parts[1]), codec.as_bytes(parts[2]))


MAX_NAME_BYTES = 128


class OpType(bytes, enum.Enum):
    SET = b"s"
    DEL = b"d"
    ABSENT = b"a"
    HOLDS = b"h"
    EXISTS = b"e"
    HOLDS_ANY = b"A"


type EncodedOp = tuple[OpType, *tuple[codec.Bencodable, ...]]


class Mutation(ABC):
    store: int
    name: bytes

    @abstractmethod
    def encode(self) -> EncodedOp: ...

    registry: typing.ClassVar[dict[bytes, type[Self]]] = {}

    @classmethod
    def decode(cls, v: codec.Bencodable) -> Self:
        p = codec.as_seq(v)
        tag = codec.as_bytes(p[0]) if p else b""
        sub = cls.registry.get(tag)
        if sub is None:
            raise OpError(f"unknown mutation tag {tag!r}")
        return sub.decode(v)


@dataclass(frozen=True, slots=True)
class Set(Mutation):
    store: int
    name: bytes
    value: bytes
    epoch: int = EPOCH_NONE

    def encode(self) -> EncodedOp:
        return (OpType.SET, self.store, self.name, self.value, self.epoch)

    @classmethod
    def decode(cls, v: codec.Bencodable) -> Self:
        p = codec.as_seq(v, 5)
        return cls(
            codec.as_int(p[1]), codec.as_bytes(p[2]), codec.as_bytes(p[3]), codec.as_int(p[4])
        )


Mutation.registry[OpType.SET] = Set


@dataclass(frozen=True, slots=True)
class Del(Mutation):
    store: int
    name: bytes

    def encode(self) -> EncodedOp:
        return (OpType.DEL, self.store, self.name)

    @classmethod
    def decode(cls, v: codec.Bencodable) -> Self:
        p = codec.as_seq(v, 3)
        return cls(codec.as_int(p[1]), codec.as_bytes(p[2]))


Mutation.registry[OpType.DEL] = Del


class Predicate(ABC):
    store: int
    name: bytes

    @abstractmethod
    def encode(self) -> EncodedOp: ...

    registry: typing.ClassVar[dict[bytes, type[Self]]] = {}

    @classmethod
    def decode(cls, v: codec.Bencodable) -> Self:
        p = codec.as_seq(v)
        tag = codec.as_bytes(p[0]) if p else b""
        sub = cls.registry.get(tag)
        if sub is None:
            raise OpError(f"unknown predicate tag {tag!r}")
        return sub.decode(v)


@dataclass(frozen=True, slots=True)
class Absent(Predicate):
    store: int
    name: bytes

    def encode(self) -> EncodedOp:
        return (OpType.ABSENT, self.store, self.name)

    @classmethod
    def decode(cls, v: codec.Bencodable) -> Self:
        p = codec.as_seq(v, 3)
        return cls(codec.as_int(p[1]), codec.as_bytes(p[2]))


Predicate.registry[OpType.ABSENT] = Absent


@dataclass(frozen=True, slots=True)
class Holds(Predicate):
    store: int
    name: bytes
    digest: crypto.Digest

    def encode(self) -> EncodedOp:
        return (OpType.HOLDS, self.store, self.name, self.digest)

    @classmethod
    def decode(cls, v: codec.Bencodable) -> Self:
        p = codec.as_seq(v, 4)
        return cls(
            codec.as_int(p[1]),
            codec.as_bytes(p[2]),
            crypto.Digest(codec.as_bytes(p[3])),
        )


Predicate.registry[OpType.HOLDS] = Holds


@dataclass(frozen=True, slots=True)
class Exists(Predicate):
    store: int
    name: bytes

    def encode(self) -> EncodedOp:
        return (OpType.EXISTS, self.store, self.name)

    @classmethod
    def decode(cls, v: codec.Bencodable) -> Self:
        p = codec.as_seq(v, 3)
        return cls(codec.as_int(p[1]), codec.as_bytes(p[2]))


Predicate.registry[OpType.EXISTS] = Exists


@dataclass(frozen=True, slots=True)
class HoldsAny(Predicate):
    store: int
    name: bytes
    digests: tuple[crypto.Digest, ...]

    def encode(self) -> EncodedOp:
        return (OpType.HOLDS_ANY, self.store, self.name, self.digests)

    @classmethod
    def decode(cls, v: codec.Bencodable) -> Self:
        p = codec.as_seq(v, 4)
        return cls(
            codec.as_int(p[1]),
            codec.as_bytes(p[2]),
            tuple(crypto.Digest(codec.as_bytes(d)) for d in codec.as_seq(p[3])),
        )


Predicate.registry[OpType.HOLDS_ANY] = HoldsAny


def value_digest(ciphertext: bytes) -> crypto.Digest:
    return crypto.h(ciphertext)


@dataclass(frozen=True, slots=True)
class Step:
    guards: tuple[Predicate, ...]
    mutation: Mutation
    soft: bool = False

    def encode(self) -> tuple[tuple[EncodedOp, ...], EncodedOp, int]:
        guards = tuple(g.encode() for g in self.guards)
        return (guards, self.mutation.encode(), int(self.soft))

    @classmethod
    def decode(cls, v: codec.Bencodable) -> Self:
        p = codec.as_seq(v, 3)
        guards = tuple(Predicate.decode(x) for x in codec.as_seq(p[0]))
        mutation = Mutation.decode(p[1])
        soft = codec.as_int(p[2]) != 0
        return cls(guards, mutation, soft)


@dataclass(frozen=True, slots=True)
class Transaction:
    steps: tuple[Step, ...] = ()

    def __add__(self, other: Transaction) -> Transaction:
        if not isinstance(other, Transaction):
            return NotImplemented
        return Transaction(self.steps + other.steps)

    def then(self, mutation: Mutation, *guards: Predicate) -> Transaction:
        return Transaction((*self.steps, Step(tuple(guards), mutation)))

    def then_soft(self, mutation: Mutation, *guards: Predicate) -> Transaction:
        return Transaction((*self.steps, Step(tuple(guards), mutation, soft=True)))

    def encode(self) -> bytes:
        return codec.encode(tuple(st.encode() for st in self.steps))

    @classmethod
    def decode(cls, raw: bytes) -> Transaction:
        return cls(tuple(Step.decode(s) for s in codec.as_seq(codec.decode(raw))))

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
    return codec.encode((author, ts, tuple(st.encode() for st in steps)))


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
