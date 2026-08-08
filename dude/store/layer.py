from __future__ import annotations

from collections.abc import Iterator
from typing import NamedTuple, Protocol, cast

from ..core import crypto
from . import ops, smt


class LayerError(Exception): ...


type Index = int


PENDING: Index = -1


class Held(NamedTuple):
    provenance: Index
    value: bytes
    epoch: int

    cred: bytes


class Row(NamedTuple):
    name: bytes
    provenance: Index
    value: bytes
    epoch: int = ops.EPOCH_NONE


class Reader(Protocol):
    def get(self, store: int, name: bytes) -> Held | None: ...

    def prefix(self, store: int, pre: bytes) -> Iterator[Row]: ...


class View(Reader, Protocol):
    def accumulator(self) -> crypto.Accumulator: ...

    def state_root(self) -> crypto.Digest: ...

    def hash_under(self, prefix: bytes, depth: int) -> crypto.Digest: ...

    @property
    def is_frozen(self) -> bool: ...


class Layer:
    def __init__(self, base: View):
        if not base.is_frozen:
            raise LayerError(
                "Layer base must be frozen (SPECv2 #frozen-base-for-layer); "
                "call base.freeze() first, or use Layer.speculative for evaluation overlays"
            )
        self._init(base)

    @classmethod
    def speculative(cls, base: Reader) -> Layer:
        layer = cls.__new__(cls)
        layer._init(cast(View, base))  # noqa: SLF001 — factory constructing its own type
        return layer

    def _init(self, base: View) -> None:
        self._base = base
        self._delta: dict[tuple[int, bytes], Held | None] = {}
        self._log: list[ops.Mutation] = []
        self._frozen = False
        self._smt_memo: dict[tuple[int, bytes], crypto.Digest] = {}

    def get(self, store: int, name: bytes) -> Held | None:
        key = (store, name)
        if key not in self._delta:
            return self._base.get(store, name)
        return self._delta[key]

    def prefix(self, store: int, pre: bytes) -> Iterator[Row]:
        rows: dict[bytes, Row] = {r.name: r for r in self._base.prefix(store, pre)}
        for (st, name), held in self._delta.items():
            if st != store or not name.startswith(pre):
                continue
            if held is None:
                rows.pop(name, None)
            else:
                rows[name] = Row(name, held.provenance, held.value, held.epoch)
        for name in sorted(rows):
            yield rows[name]

    @property
    def is_frozen(self) -> bool:
        return self._frozen

    def freeze(self) -> None:
        self._frozen = True

    def accumulator(self) -> crypto.Accumulator:
        from .store import element  # noqa: PLC0415 — store imports layer, so this is deferred

        acc = self._base.accumulator()
        for (st, name), held in self._delta.items():
            was = self._base.get(st, name)
            if was is not None:
                acc = crypto.acc_sub(acc, element(st, name, was.value))
            if held is not None:
                acc = crypto.acc_add(acc, element(st, name, held.value))
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
        for st, name, value, cred in self._base_rows_in_range(lo, hi):
            path = smt.path_of(st, name)
            if path in delta_paths:
                continue
            base_leaves.append((path, smt.leaf_hash(path, crypto.h(value), crypto.h(cred))))
        delta_leaves: list[tuple[bytes, crypto.Digest]] = []
        for path, entry in delta_paths.items():
            held = entry[2]
            if held is not None:
                delta_leaves.append(
                    (path, smt.leaf_hash(path, crypto.h(held.value), crypto.h(held.cred)))
                )
        merged = sorted(base_leaves + delta_leaves, key=lambda pl: pl[0])
        return merged[:at_most]

    def _base_rows_in_range(
        self, lo: bytes, hi: bytes
    ) -> Iterator[tuple[int, bytes, bytes, bytes]]:
        rows_fn = getattr(self._base, "_rows_in_path_range", None)
        if rows_fn is None:
            raise LayerError(
                "base does not expose _rows_in_path_range; every View in a Layer stack must "
                "provide a path-range scan"
            )
        yield from rows_fn(lo, hi)

    def _rows_in_path_range(
        self, lo: bytes, hi: bytes
    ) -> Iterator[tuple[int, bytes, bytes, bytes]]:
        delta_by_path = {
            smt.path_of(st, name): (st, name, held)
            for (st, name), held in self._delta.items()
            if lo <= smt.path_of(st, name) <= hi
        }
        merged: dict[bytes, tuple[int, bytes, bytes, bytes]] = {}
        for st, name, value, cred in self._base_rows_in_range(lo, hi):
            path = smt.path_of(st, name)
            if path in delta_by_path:
                continue
            merged[path] = (st, name, value, cred)
        for path, (st, name, held) in delta_by_path.items():
            if held is not None:
                merged[path] = (st, name, held.value, held.cred)
        for path in sorted(merged):
            yield merged[path]

    def apply(self, m: ops.Mutation, cred: bytes) -> None:
        if self._frozen:
            raise LayerError("Layer is frozen; no more mutations")
        self._delta[(m.store, m.name)] = (
            Held(PENDING, m.value, m.epoch, cred) if isinstance(m, ops.Set) else None
        )
        self._log.append(m)

    @property
    def mutations(self) -> tuple[ops.Mutation, ...]:
        return tuple(self._log)

    def absorb(self, child: Layer) -> None:
        if self._frozen:
            raise LayerError("Layer is frozen; cannot absorb")
        self._delta.update(child._delta)
        self._log.extend(child._log)


def holds(reader: Reader, pred: ops.Predicate) -> bool:
    cur = reader.get(pred.store, pred.name)
    if isinstance(pred, ops.Absent):
        return cur is None
    return cur is not None and ops.value_digest(cur[1]) == pred.digest


def _prefix_upper(pre: bytes) -> bytes | None:
    for i in range(len(pre) - 1, -1, -1):
        if pre[i] != 0xFF:
            return pre[:i] + bytes([pre[i] + 1])
    return None
