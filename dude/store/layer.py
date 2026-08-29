from abc import ABC, abstractmethod
from collections.abc import Iterator
from typing import Any, NamedTuple

from ..core import codec, crypto
from . import ops, smt
from .errors import StoreError


class LayerError(StoreError): ...


type Index = int


class PathRow(NamedTuple):
    store: int
    name: bytes
    value: bytes
    credential: bytes
    epoch: int


class Held(NamedTuple):
    value: bytes
    epoch: int
    cred: bytes

    def encode(self) -> bytes:
        return codec.encode([self.value, self.epoch, self.cred])

    @classmethod
    def decode(cls, raw: bytes) -> "Held":
        parts = codec.as_seq(codec.decode(raw), 3)
        return cls(codec.as_bytes(parts[0]), codec.as_int(parts[1]), codec.as_bytes(parts[2]))


class BlockHead(NamedTuple):
    block_num: Index
    block_hash: crypto.Digest

    def encode(self) -> bytes:
        return codec.encode([self.block_num, self.block_hash])

    @classmethod
    def decode(cls, raw: bytes) -> "BlockHead":
        parts = codec.as_seq(codec.decode(raw), 2)
        return cls(codec.as_int(parts[0]), crypto.Digest(codec.as_bytes(parts[1])))


class Reader(ABC):
    @abstractmethod
    def get(self, store: int, name: bytes) -> Held | None: ...
    @abstractmethod
    def anchor(self) -> crypto.PublicKey: ...


class Ledger(Reader):
    @abstractmethod
    def has_settled(self, op_hash: crypto.Digest) -> bool: ...


class View(Reader):
    @abstractmethod
    def accumulator(self) -> crypto.Accumulator: ...
    @abstractmethod
    def state_root(self) -> crypto.Digest: ...
    @abstractmethod
    def hash_under(self, prefix: bytes, depth: int) -> crypto.Digest: ...
    @abstractmethod
    def _rows_in_path_range(self, lo: bytes, hi: bytes) -> Iterator[PathRow]: ...
    @property
    @abstractmethod
    def is_frozen(self) -> bool: ...


class Overlay[B: Reader](Reader):
    """Buffered mutations over any `Reader`. Reads see the delta, then the base.

    It computes NO roots, and that is the point: a root is only meaningful once every base
    beneath it is frozen, and an overlay's base is whatever it was handed. Asking one for a
    root is a type error rather than a rule a caller has to remember.
    """

    _base: B

    def __init__(self, base: B) -> None:
        self._base = base
        self._delta: dict[tuple[int, bytes], Held | None] = {}
        self._log: list[ops.Mutation] = []
        self._frozen = False

    def anchor(self) -> crypto.PublicKey:
        return self._base.anchor()

    def get(self, store: int, name: bytes) -> Held | None:
        key = (store, name)
        if key not in self._delta:
            return self._base.get(store, name)
        return self._delta[key]

    @property
    def is_frozen(self) -> bool:
        return self._frozen

    def freeze(self) -> None:
        self._frozen = True

    def apply(self, m: ops.Mutation, cred: bytes) -> None:
        if self._frozen:
            raise LayerError("frozen; no more mutations")
        self._delta[(m.store, m.name)] = (
            Held(m.value, m.epoch, cred) if isinstance(m, ops.Set) else None
        )
        self._log.append(m)

    @property
    def mutations(self) -> tuple[ops.Mutation, ...]:
        return tuple(self._log)

    def absorb(self, child: "Overlay[Any]") -> None:
        if self._frozen:
            raise LayerError("frozen; cannot absorb")
        self._delta.update(child._delta)
        self._log.extend(child._log)


class Layer(Overlay[View]):
    """An `Overlay` that can also compute roots, which is why its base MUST be frozen
    (#frozen-base-for-layer): a root taken over a base that can still move is a root that
    lies. Enforced at the constructor, so it is not a rule a caller has to remember.
    """

    def __init__(self, base: View) -> None:
        if not base.is_frozen:
            raise LayerError(
                "Layer base must be frozen (SPECv2 #frozen-base-for-layer); "
                "call base.freeze() first, or use an Overlay for speculative evaluation"
            )
        super().__init__(base)
        self._smt_memo: dict[tuple[int, bytes], crypto.Digest] = {}

    def accumulator(self) -> crypto.Accumulator:
        from .store import element  # noqa: PLC0415 — store imports layer, so this is deferred

        acc = self._base.accumulator()
        for (st, name), held in self._delta.items():
            was = self._base.get(st, name)
            if was is not None:
                acc = crypto.acc_sub(acc, element(st, name, was.value, was.epoch))
            if held is not None:
                acc = crypto.acc_add(acc, element(st, name, held.value, held.epoch))
        return acc

    def state_root(self) -> crypto.Digest:
        return self.hash_under(bytes(crypto.DIGEST_SIZE), 0)

    def hash_under(self, prefix: bytes, depth: int) -> crypto.Digest:
        lo, hi = smt.bounds(prefix, depth)
        if not self._delta_touches_range(lo, hi):
            return self._base.hash_under(prefix, depth)
        memo_key = (depth, lo)
        if memo_key in self._smt_memo:
            return self._smt_memo[memo_key]
        effective = self._effective_leaves(lo, hi, at_most=2)
        if not effective:
            result = smt.EMPTY
        elif len(effective) == 1:
            result = effective[0][1]
        else:
            left, right = (
                smt.bounds(prefix, depth + 1)[0],
                smt.bounds(smt.with_bit(prefix, depth, 1), depth + 1)[0],
            )
            left_hash = self.hash_under(left, depth + 1)
            right_hash = self.hash_under(right, depth + 1)
            result = smt.branch_hash(depth, lo, left_hash, right_hash)
        if self._frozen:
            self._smt_memo[memo_key] = result
        return result

    def _delta_touches_range(self, lo: bytes, hi: bytes) -> bool:
        return any(lo <= smt.path_of(st, name) <= hi for st, name in self._delta)

    def _effective_leaves(
        self, lo: bytes, hi: bytes, at_most: int
    ) -> list[tuple[bytes, crypto.Digest]]:
        delta_paths = {
            smt.path_of(st, name): (st, name, held)
            for (st, name), held in self._delta.items()
            if lo <= smt.path_of(st, name) <= hi
        }
        base_leaves: list[tuple[bytes, crypto.Digest]] = []
        for st, name, value, cred, epoch in self._base_rows_in_range(lo, hi):
            path = smt.path_of(st, name)
            if path in delta_paths:
                continue
            base_leaves.append((path, smt.leaf_hash(path, crypto.h(value), crypto.h(cred), epoch)))
        delta_leaves: list[tuple[bytes, crypto.Digest]] = []
        for path, entry in delta_paths.items():
            held = entry[2]
            if held is not None:
                delta_leaves.append(
                    (
                        path,
                        smt.leaf_hash(path, crypto.h(held.value), crypto.h(held.cred), held.epoch),
                    )
                )
        merged = sorted(base_leaves + delta_leaves, key=lambda pl: pl[0])
        return merged[:at_most]

    def _base_rows_in_range(self, lo: bytes, hi: bytes) -> Iterator[PathRow]:
        yield from self._base._rows_in_path_range(lo, hi)

    def _rows_in_path_range(self, lo: bytes, hi: bytes) -> Iterator[PathRow]:
        delta_by_path = {
            smt.path_of(st, name): (st, name, held)
            for (st, name), held in self._delta.items()
            if lo <= smt.path_of(st, name) <= hi
        }
        merged: dict[bytes, PathRow] = {}
        for st, name, value, cred, epoch in self._base_rows_in_range(lo, hi):
            path = smt.path_of(st, name)
            if path in delta_by_path:
                continue
            merged[path] = PathRow(st, name, value, cred, epoch)
        for path, (st, name, held) in delta_by_path.items():
            if held is not None:
                merged[path] = PathRow(st, name, held.value, held.cred, held.epoch)
        for path in sorted(merged):
            yield merged[path]


def holds(reader: Reader, pred: ops.Predicate) -> bool:
    cur = reader.get(pred.store, pred.name)
    if isinstance(pred, ops.Absent):
        return cur is None
    return cur is not None and ops.value_digest(cur.value) == pred.digest
