from __future__ import annotations

from dataclasses import dataclass
from typing import TYPE_CHECKING, Self

from ..core import codec, crypto
from ..core.errors import DudeError
from . import ops
from .errors import StoreError

if TYPE_CHECKING:
    from ..session import Session


class ManagedMapError(StoreError): ...


class MapAcc:
    __slots__ = ("_acc", "_prefix")

    def __init__(self, prefix: bytes, acc: crypto.Accumulator | None = None) -> None:
        self._acc = acc if acc is not None else crypto.Accumulator(crypto.ACC_IDENTITY)
        self._prefix = prefix

    @staticmethod
    def _element(prefix: bytes, key: bytes) -> crypto.Accumulator:
        return crypto.acc_element(codec.encode([prefix, key]))

    def add(self, key: bytes) -> MapAcc:
        return MapAcc(self._prefix, crypto.acc_add(self._acc, self._element(self._prefix, key)))

    def sub(self, key: bytes) -> MapAcc:
        return MapAcc(self._prefix, crypto.acc_sub(self._acc, self._element(self._prefix, key)))

    @property
    def value(self) -> crypto.Accumulator:
        return self._acc


@dataclass(frozen=True, slots=True)
class MapMeta:
    count: int
    acc: crypto.Accumulator
    raw: bytes

    @staticmethod
    def encode(count: int, acc: MapAcc) -> bytes:
        return codec.encode([count, acc.value])

    @classmethod
    def decode(cls, raw: bytes) -> Self:
        p = codec.as_seq(codec.decode(raw), 2)
        return cls(codec.as_int(p[0]), crypto.Accumulator(codec.as_bytes(p[1])), raw)


@dataclass(frozen=True, slots=True)
class MapEntry:
    index: int
    value: bytes
    raw: bytes

    @staticmethod
    def encode(index: int, value: bytes) -> bytes:
        return codec.encode([index, value])

    @classmethod
    def decode(cls, raw: bytes) -> Self:
        p = codec.as_seq(codec.decode(raw), 2)
        return cls(codec.as_int(p[0]), codec.as_bytes(p[1]), raw)


class ManagedMap:
    __slots__ = ("_session", "prefix")

    def __init__(self, prefix: bytes, session: Session) -> None:
        self.prefix = prefix
        self._session = session

    def _meta_name(self) -> bytes:
        return self.prefix + b"\x00"

    def _index_name(self, idx: int) -> bytes:
        return self.prefix + b"\x01" + idx.to_bytes(4, "big")

    def entry_name(self, key: bytes) -> bytes:
        return self.prefix + b"\x02" + key

    def _get(self, name: bytes) -> bytes | None:
        rec = self._session.get(name)
        if rec.absent:
            return None
        return rec.value

    # -- reads (all point reads) --------------------------------------------

    def meta(self) -> MapMeta | None:
        raw = self._get(self._meta_name())
        if raw is None:
            return None
        return MapMeta.decode(raw)

    def entry(self, key: bytes) -> MapEntry | None:
        raw = self._get(self.entry_name(key))
        if raw is None:
            return None
        try:
            return MapEntry.decode(raw)
        except (DudeError, ValueError, IndexError):
            return None

    def key_at(self, idx: int) -> bytes | None:
        return self._get(self._index_name(idx))

    def keys(self) -> list[bytes]:
        m = self.meta()
        if m is None:
            return []
        out: list[bytes] = []
        for i in range(m.count):
            k = self.key_at(i)
            if k is not None:
                out.append(k)
        return out

    def items(self) -> list[tuple[bytes, bytes]]:
        out: list[tuple[bytes, bytes]] = []
        for key in self.keys():
            e = self.entry(key)
            if e is not None:
                out.append((key, e.value))
        return out

    # -- writes (return Transaction, caller applies) ------------------------

    def tx_add(self, key: bytes, value: bytes, current: MapMeta | None) -> ops.Transaction:
        s = self._session.store_id
        count = current.count if current else 0
        new_acc = MapAcc(self.prefix, current.acc if current else None).add(key)
        new_meta = MapMeta.encode(count + 1, new_acc)

        meta_guard: ops.Predicate = (
            ops.Holds(s, self._meta_name(), ops.value_digest(current.raw))
            if current
            else ops.Absent(s, self._meta_name())
        )

        return ops.Transaction(
            (
                ops.Step((meta_guard,), ops.Set(s, self._meta_name(), new_meta)),
                ops.Step((), ops.Set(s, self._index_name(count), key)),
                ops.Step(
                    (ops.Absent(s, self.entry_name(key)),),
                    ops.Set(s, self.entry_name(key), MapEntry.encode(count, value)),
                ),
            )
        )

    def tx_remove(
        self,
        key: bytes,
        current: MapMeta,
        victim: MapEntry,
        last_key: bytes,
        last_entry: MapEntry,
    ) -> ops.Transaction:
        s = self._session.store_id
        last_idx = current.count - 1
        new_acc = MapAcc(self.prefix, current.acc).sub(key)
        new_meta = MapMeta.encode(last_idx, new_acc)

        steps: list[ops.Step] = [
            ops.Step(
                (ops.Holds(s, self._meta_name(), ops.value_digest(current.raw)),),
                ops.Set(s, self._meta_name(), new_meta),
            ),
            ops.Step((), ops.Del(s, self.entry_name(key))),
            ops.Step((), ops.Del(s, self._index_name(last_idx))),
        ]

        if victim.index != last_idx:
            steps.append(
                ops.Step(
                    (),
                    ops.Set(s, self._index_name(victim.index), last_key),
                )
            )
            steps.append(
                ops.Step(
                    (),
                    ops.Set(
                        s,
                        self.entry_name(last_key),
                        MapEntry.encode(victim.index, last_entry.value),
                    ),
                )
            )

        return ops.Transaction(tuple(steps))

    def tx_update(self, key: bytes, new_value: bytes, current: MapEntry) -> ops.Transaction:
        s = self._session.store_id
        return ops.Transaction(
            (
                ops.Step(
                    (ops.Holds(s, self.entry_name(key), ops.value_digest(current.raw)),),
                    ops.Set(s, self.entry_name(key), MapEntry.encode(current.index, new_value)),
                ),
            )
        )

    # -- batch: multiple adds/removes in one transaction ---------------------

    def tx_add_entry(self, key: bytes, value: bytes, index: int) -> ops.Transaction:
        s = self._session.store_id
        return ops.Transaction(
            (
                ops.Step((), ops.Set(s, self._index_name(index), key)),
                ops.Step(
                    (ops.Absent(s, self.entry_name(key)),),
                    ops.Set(s, self.entry_name(key), MapEntry.encode(index, value)),
                ),
            )
        )

    def tx_meta_write(
        self,
        new_count: int,
        new_acc: MapAcc,
        current: MapMeta | None,
    ) -> ops.Transaction:
        s = self._session.store_id
        new_meta = MapMeta.encode(new_count, new_acc)
        guard: ops.Predicate = (
            ops.Holds(s, self._meta_name(), ops.value_digest(current.raw))
            if current
            else ops.Absent(s, self._meta_name())
        )
        return ops.Transaction((ops.Step((guard,), ops.Set(s, self._meta_name(), new_meta)),))

    def batch_add(
        self,
        entries: tuple[tuple[bytes, bytes], ...],
    ) -> ops.Transaction:
        meta = self.meta()
        count = meta.count if meta else 0
        acc = MapAcc(self.prefix, meta.acc if meta else None)
        tx = ops.Transaction(())
        for key, value in entries:
            tx = tx + self.tx_add_entry(key, value, count)
            acc = acc.add(key)
            count += 1
        return tx + self.tx_meta_write(count, acc, meta)

    # -- convenience: read + compose in one call ----------------------------

    def add(self, key: bytes, value: bytes) -> ops.Transaction:
        return self.tx_add(key, value, self.meta())

    def remove(self, key: bytes) -> ops.Transaction:
        m = self.meta()
        if m is None:
            raise ManagedMapError("remove from empty map")
        victim = self.entry(key)
        if victim is None:
            raise ManagedMapError(f"key not in map: {key!r}")
        last_idx = m.count - 1
        last_key = self.key_at(last_idx)
        if last_key is None:
            raise ManagedMapError(f"index slot {last_idx} missing")
        last_entry = self.entry(last_key)
        if last_entry is None:
            raise ManagedMapError(f"entry for last key {last_key!r} missing")
        return self.tx_remove(key, m, victim, last_key, last_entry)

    def update(self, key: bytes, new_value: bytes) -> ops.Transaction:
        current = self.entry(key)
        if current is None:
            raise ManagedMapError(f"key not in map: {key!r}")
        return self.tx_update(key, new_value, current)
