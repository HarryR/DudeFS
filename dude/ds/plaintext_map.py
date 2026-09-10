from collections.abc import Iterator

from ..session import Record, Session, collect_guards
from ..store.ops import EPOCH_NONE, Del, Predicate, Set, Step, Transaction
from . import Map


class PlaintextMap(Map):
    __slots__ = ("_session", "prefix")

    def __init__(self, prefix: bytes, session: Session) -> None:
        self.prefix = prefix
        self._session = session

    @property
    def store_id(self) -> int:
        return self._session.store_id

    def full_name(self, key: bytes) -> bytes:
        return self.prefix + key

    # -- reads -----------------------------------------------------------------

    def get(self, key: bytes) -> Record:
        return self._session.get(self.full_name(key), plaintext=True)

    def count(self) -> int:
        return self._session.count_prefix(self.prefix)

    def nth(self, n: int, *, descending: bool = False) -> tuple[bytes, Record] | None:
        result = self._session.nth_prefix(self.prefix, n, descending=descending)
        if result is None:
            return None
        name, held = result
        key = name[len(self.prefix) :]
        return key, Record(
            name=name,
            store_id=self._session.store_id,
            token=name,
            value=held.value,
            raw=held.value,
            epoch=held.epoch,
            absent=False,
        )

    def keys(self) -> Iterator[bytes]:
        for i in range(self.count()):
            result = self.nth(i)
            if result is None:
                break
            yield result[0]

    def records(self) -> Iterator[tuple[bytes, Record]]:
        for i in range(self.count()):
            result = self.nth(i)
            if result is None:
                break
            yield result

    def items(self) -> Iterator[tuple[bytes, bytes]]:
        for key, rec in self.records():
            yield key, rec.value

    # -- transaction builders (caller submits) ---------------------------------

    def tx_put(
        self,
        key: bytes,
        value: bytes,
        *guards: Predicate | Record,
        expect: Record | None = None,
        absent: bool = False,
    ) -> Transaction:
        name = self.full_name(key)
        s = self._session.store_id
        all_guards = collect_guards(s, name, guards, expect, absent)
        return Transaction((Step(all_guards, Set(s, name, value, EPOCH_NONE)),))

    def tx_delete(
        self,
        key: bytes,
        *guards: Predicate | Record,
        expect: Record | None = None,
    ) -> Transaction:
        name = self.full_name(key)
        s = self._session.store_id
        all_guards = collect_guards(s, name, guards, expect, False)
        return Transaction((Step(all_guards, Del(s, name)),))
