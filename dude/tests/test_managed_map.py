from __future__ import annotations

import unittest
from dataclasses import dataclass

from ..store import ops
from ..store.layer import Held
from ..store.managed import ManagedMap

STORE = 1


@dataclass(frozen=True, slots=True)
class _Record:
    value: bytes
    absent: bool


class MemSession:
    """Minimal Session-like interface for testing ManagedMap in isolation."""

    def __init__(self, store_id: int = STORE) -> None:
        self.store_id = store_id
        self._rows: dict[tuple[int, bytes], Held] = {}

    @property
    def anchor(self):
        raise NotImplementedError

    def get(self, name: bytes) -> _Record:
        held = self._rows.get((self.store_id, name))
        if held is None:
            return _Record(value=b"", absent=True)
        return _Record(value=held.value, absent=False)

    def apply(self, tx: ops.Transaction) -> bool:
        for step in tx.steps:
            for guard in step.guards:
                if isinstance(guard, ops.Absent):
                    if (guard.store, guard.name) in self._rows:
                        return False
                elif isinstance(guard, ops.Holds):
                    held = self._rows.get((guard.store, guard.name))
                    if held is None or ops.value_digest(held.value) != guard.digest:
                        return False
        for step in tx.steps:
            m = step.mutation
            if isinstance(m, ops.Set):
                self._rows[(m.store, m.name)] = Held(m.value, m.epoch, b"")
            elif isinstance(m, ops.Del):
                self._rows.pop((m.store, m.name), None)
        return True


class TestManagedMap(unittest.TestCase):

    def setUp(self) -> None:
        self.session = MemSession()
        self.m = ManagedMap(b"test/", self.session)

    def test_empty_map(self) -> None:
        self.assertIsNone(self.m.meta())
        self.assertEqual(self.m.keys(), [])
        self.assertEqual(self.m.items(), [])
        self.assertIsNone(self.m.entry(b"x"))

    def test_add_one(self) -> None:
        tx = self.m.add(b"alice", b"value_a")
        self.assertTrue(self.session.apply(tx))
        meta = self.m.meta()
        assert meta is not None
        self.assertEqual(meta.count, 1)
        self.assertEqual(self.m.keys(), [b"alice"])
        e = self.m.entry(b"alice")
        assert e is not None
        self.assertEqual(e.value, b"value_a")
        self.assertEqual(e.index, 0)

    def test_add_three(self) -> None:
        for name in (b"alice", b"bob", b"carol"):
            tx = self.m.add(name, name.upper())
            self.assertTrue(self.session.apply(tx))
        meta = self.m.meta()
        assert meta is not None
        self.assertEqual(meta.count, 3)
        self.assertEqual(sorted(self.m.keys()), [b"alice", b"bob", b"carol"])
        items = dict(self.m.items())
        self.assertEqual(items[b"bob"], b"BOB")

    def test_duplicate_add_refused(self) -> None:
        self.assertTrue(self.session.apply(self.m.add(b"alice", b"v")))
        tx = self.m.add(b"alice", b"v2")
        self.assertFalse(self.session.apply(tx))

    def test_remove_only_element(self) -> None:
        self.assertTrue(self.session.apply(self.m.add(b"alice", b"v")))
        tx = self.m.remove(b"alice")
        self.assertTrue(self.session.apply(tx))
        self.assertEqual(self.m.meta().count, 0)
        self.assertEqual(self.m.keys(), [])
        self.assertIsNone(self.m.entry(b"alice"))

    def test_remove_last_element(self) -> None:
        for name in (b"a", b"b", b"c"):
            self.assertTrue(self.session.apply(self.m.add(name, name)))
        tx = self.m.remove(b"c")
        self.assertTrue(self.session.apply(tx))
        self.assertEqual(self.m.meta().count, 2)
        self.assertEqual(sorted(self.m.keys()), [b"a", b"b"])

    def test_remove_middle_swaps_last_in(self) -> None:
        for name in (b"a", b"b", b"c"):
            self.assertTrue(self.session.apply(self.m.add(name, name)))
        tx = self.m.remove(b"a")
        self.assertTrue(self.session.apply(tx))
        self.assertEqual(self.m.meta().count, 2)
        keys = self.m.keys()
        self.assertEqual(sorted(keys), [b"b", b"c"])
        c_entry = self.m.entry(b"c")
        assert c_entry is not None
        self.assertEqual(c_entry.index, 0)
        self.assertIsNone(self.m.entry(b"a"))

    def test_remove_then_add_reuses_slot(self) -> None:
        for name in (b"a", b"b", b"c"):
            self.assertTrue(self.session.apply(self.m.add(name, name)))
        self.assertTrue(self.session.apply(self.m.remove(b"b")))
        self.assertTrue(self.session.apply(self.m.add(b"d", b"d")))
        self.assertEqual(self.m.meta().count, 3)
        self.assertEqual(sorted(self.m.keys()), [b"a", b"c", b"d"])

    def test_update_value(self) -> None:
        self.assertTrue(self.session.apply(self.m.add(b"k", b"old")))
        tx = self.m.update(b"k", b"new")
        self.assertTrue(self.session.apply(tx))
        e = self.m.entry(b"k")
        assert e is not None
        self.assertEqual(e.value, b"new")
        self.assertEqual(e.index, 0)

    def test_update_does_not_change_meta(self) -> None:
        self.assertTrue(self.session.apply(self.m.add(b"k", b"old")))
        meta_before = self.m.meta()
        self.assertTrue(self.session.apply(self.m.update(b"k", b"new")))
        meta_after = self.m.meta()
        assert meta_before is not None and meta_after is not None
        self.assertEqual(meta_before.count, meta_after.count)
        self.assertEqual(meta_before.acc, meta_after.acc)

    def test_concurrent_add_conflicts(self) -> None:
        tx1 = self.m.add(b"alice", b"v1")
        tx2 = self.m.add(b"bob", b"v2")
        self.assertTrue(self.session.apply(tx1))
        self.assertFalse(self.session.apply(tx2))

    def test_concurrent_remove_conflicts(self) -> None:
        for name in (b"a", b"b", b"c"):
            self.assertTrue(self.session.apply(self.m.add(name, name)))
        tx1 = self.m.remove(b"a")
        tx2 = self.m.remove(b"b")
        self.assertTrue(self.session.apply(tx1))
        self.assertFalse(self.session.apply(tx2))

    def test_concurrent_update_conflicts(self) -> None:
        self.assertTrue(self.session.apply(self.m.add(b"k", b"v")))
        tx1 = self.m.update(b"k", b"new1")
        tx2 = self.m.update(b"k", b"new2")
        self.assertTrue(self.session.apply(tx1))
        self.assertFalse(self.session.apply(tx2))

    def test_update_and_add_do_not_conflict(self) -> None:
        self.assertTrue(self.session.apply(self.m.add(b"k", b"v")))
        tx_update = self.m.update(b"k", b"new")
        tx_add = self.m.add(b"k2", b"v2")
        self.assertTrue(self.session.apply(tx_update))
        self.assertTrue(self.session.apply(tx_add))

    def test_accumulator_changes_on_add(self) -> None:
        self.assertTrue(self.session.apply(self.m.add(b"a", b"v")))
        acc1 = self.m.meta().acc
        self.assertTrue(self.session.apply(self.m.add(b"b", b"v")))
        acc2 = self.m.meta().acc
        self.assertNotEqual(acc1, acc2)

    def test_accumulator_restores_after_remove(self) -> None:
        self.assertTrue(self.session.apply(self.m.add(b"a", b"v")))
        acc_one = self.m.meta().acc
        self.assertTrue(self.session.apply(self.m.add(b"b", b"v")))
        self.assertTrue(self.session.apply(self.m.remove(b"b")))
        acc_back = self.m.meta().acc
        self.assertEqual(acc_one, acc_back)

    def test_iterate_large(self) -> None:
        for i in range(20):
            k = f"key_{i:03d}".encode()
            self.assertTrue(self.session.apply(self.m.add(k, k)))
        self.assertEqual(self.m.meta().count, 20)
        self.assertEqual(len(self.m.keys()), 20)
        for i in range(0, 20, 3):
            k = f"key_{i:03d}".encode()
            self.assertTrue(self.session.apply(self.m.remove(k)))
        remaining = self.m.keys()
        self.assertEqual(len(remaining), 13)
        for k in remaining:
            e = self.m.entry(k)
            assert e is not None
            self.assertEqual(e.value, k)


if __name__ == "__main__":
    unittest.main()
