from __future__ import annotations

import unittest

from ..store import ops
from ..store.layer import Held
from ..store.managed import ManagedMap

STORE = 1


class MemReader:
    """In-memory point-readable store for testing ManagedMap in isolation."""

    def __init__(self) -> None:
        self._rows: dict[tuple[int, bytes], Held] = {}

    def get(self, store: int, name: bytes) -> Held | None:
        return self._rows.get((store, name))

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


# ---------------------------------------------------------------------------
# Tests
# ---------------------------------------------------------------------------


class TestManagedMap(unittest.TestCase):

    def setUp(self) -> None:
        self.store = MemReader()
        self.m = ManagedMap(b"test/", STORE)

    def test_empty_map(self) -> None:
        self.assertIsNone(self.m.meta(self.store))
        self.assertEqual(self.m.keys(self.store), [])
        self.assertEqual(self.m.items(self.store), [])
        self.assertIsNone(self.m.entry(self.store, b"x"))

    def test_add_one(self) -> None:
        tx = self.m.add(self.store, b"alice", b"value_a")
        self.assertTrue(self.store.apply(tx))
        meta = self.m.meta(self.store)
        assert meta is not None
        self.assertEqual(meta.count, 1)
        self.assertEqual(self.m.keys(self.store), [b"alice"])
        e = self.m.entry(self.store, b"alice")
        assert e is not None
        self.assertEqual(e.value, b"value_a")
        self.assertEqual(e.index, 0)

    def test_add_three(self) -> None:
        for name in (b"alice", b"bob", b"carol"):
            tx = self.m.add(self.store, name, name.upper())
            self.assertTrue(self.store.apply(tx))
        meta = self.m.meta(self.store)
        assert meta is not None
        self.assertEqual(meta.count, 3)
        self.assertEqual(sorted(self.m.keys(self.store)), [b"alice", b"bob", b"carol"])
        items = dict(self.m.items(self.store))
        self.assertEqual(items[b"bob"], b"BOB")

    def test_duplicate_add_refused(self) -> None:
        self.assertTrue(self.store.apply(self.m.add(self.store, b"alice", b"v")))
        tx = self.m.add(self.store, b"alice", b"v2")
        self.assertFalse(self.store.apply(tx))

    def test_remove_only_element(self) -> None:
        self.assertTrue(self.store.apply(self.m.add(self.store, b"alice", b"v")))
        tx = self.m.remove(self.store, b"alice")
        self.assertTrue(self.store.apply(tx))
        self.assertEqual(self.m.meta(self.store).count, 0)
        self.assertEqual(self.m.keys(self.store), [])
        self.assertIsNone(self.m.entry(self.store, b"alice"))

    def test_remove_last_element(self) -> None:
        for name in (b"a", b"b", b"c"):
            self.assertTrue(self.store.apply(self.m.add(self.store, name, name)))
        tx = self.m.remove(self.store, b"c")
        self.assertTrue(self.store.apply(tx))
        self.assertEqual(self.m.meta(self.store).count, 2)
        self.assertEqual(sorted(self.m.keys(self.store)), [b"a", b"b"])

    def test_remove_middle_swaps_last_in(self) -> None:
        for name in (b"a", b"b", b"c"):
            self.assertTrue(self.store.apply(self.m.add(self.store, name, name)))
        tx = self.m.remove(self.store, b"a")
        self.assertTrue(self.store.apply(tx))
        self.assertEqual(self.m.meta(self.store).count, 2)
        keys = self.m.keys(self.store)
        self.assertEqual(sorted(keys), [b"b", b"c"])
        c_entry = self.m.entry(self.store, b"c")
        assert c_entry is not None
        self.assertEqual(c_entry.index, 0)
        self.assertIsNone(self.m.entry(self.store, b"a"))

    def test_remove_then_add_reuses_slot(self) -> None:
        for name in (b"a", b"b", b"c"):
            self.assertTrue(self.store.apply(self.m.add(self.store, name, name)))
        self.assertTrue(self.store.apply(self.m.remove(self.store, b"b")))
        self.assertTrue(self.store.apply(self.m.add(self.store, b"d", b"d")))
        self.assertEqual(self.m.meta(self.store).count, 3)
        self.assertEqual(sorted(self.m.keys(self.store)), [b"a", b"c", b"d"])

    def test_update_value(self) -> None:
        self.assertTrue(self.store.apply(self.m.add(self.store, b"k", b"old")))
        tx = self.m.update(self.store, b"k", b"new")
        self.assertTrue(self.store.apply(tx))
        e = self.m.entry(self.store, b"k")
        assert e is not None
        self.assertEqual(e.value, b"new")
        self.assertEqual(e.index, 0)

    def test_update_does_not_change_meta(self) -> None:
        self.assertTrue(self.store.apply(self.m.add(self.store, b"k", b"old")))
        meta_before = self.m.meta(self.store)
        self.assertTrue(self.store.apply(self.m.update(self.store, b"k", b"new")))
        meta_after = self.m.meta(self.store)
        assert meta_before is not None and meta_after is not None
        self.assertEqual(meta_before.count, meta_after.count)
        self.assertEqual(meta_before.acc, meta_after.acc)

    def test_concurrent_add_conflicts(self) -> None:
        tx1 = self.m.add(self.store, b"alice", b"v1")
        tx2 = self.m.add(self.store, b"bob", b"v2")
        self.assertTrue(self.store.apply(tx1))
        self.assertFalse(self.store.apply(tx2))

    def test_concurrent_remove_conflicts(self) -> None:
        for name in (b"a", b"b", b"c"):
            self.assertTrue(self.store.apply(self.m.add(self.store, name, name)))
        tx1 = self.m.remove(self.store, b"a")
        tx2 = self.m.remove(self.store, b"b")
        self.assertTrue(self.store.apply(tx1))
        self.assertFalse(self.store.apply(tx2))

    def test_concurrent_update_conflicts(self) -> None:
        self.assertTrue(self.store.apply(self.m.add(self.store, b"k", b"v")))
        tx1 = self.m.update(self.store, b"k", b"new1")
        tx2 = self.m.update(self.store, b"k", b"new2")
        self.assertTrue(self.store.apply(tx1))
        self.assertFalse(self.store.apply(tx2))

    def test_update_and_add_do_not_conflict(self) -> None:
        self.assertTrue(self.store.apply(self.m.add(self.store, b"k", b"v")))
        tx_update = self.m.update(self.store, b"k", b"new")
        tx_add = self.m.add(self.store, b"k2", b"v2")
        self.assertTrue(self.store.apply(tx_update))
        self.assertTrue(self.store.apply(tx_add))

    def test_accumulator_changes_on_add(self) -> None:
        self.assertTrue(self.store.apply(self.m.add(self.store, b"a", b"v")))
        acc1 = self.m.meta(self.store).acc
        self.assertTrue(self.store.apply(self.m.add(self.store, b"b", b"v")))
        acc2 = self.m.meta(self.store).acc
        self.assertNotEqual(acc1, acc2)

    def test_accumulator_restores_after_remove(self) -> None:
        self.assertTrue(self.store.apply(self.m.add(self.store, b"a", b"v")))
        acc_one = self.m.meta(self.store).acc
        self.assertTrue(self.store.apply(self.m.add(self.store, b"b", b"v")))
        self.assertTrue(self.store.apply(self.m.remove(self.store, b"b")))
        acc_back = self.m.meta(self.store).acc
        self.assertEqual(acc_one, acc_back)

    def test_iterate_large(self) -> None:
        for i in range(20):
            k = f"key_{i:03d}".encode()
            self.assertTrue(self.store.apply(self.m.add(self.store, k, k)))
        self.assertEqual(self.m.meta(self.store).count, 20)
        self.assertEqual(len(self.m.keys(self.store)), 20)
        for i in range(0, 20, 3):
            k = f"key_{i:03d}".encode()
            self.assertTrue(self.store.apply(self.m.remove(self.store, k)))
        remaining = self.m.keys(self.store)
        self.assertEqual(len(remaining), 13)
        for k in remaining:
            e = self.m.entry(self.store, k)
            assert e is not None
            self.assertEqual(e.value, k)


if __name__ == "__main__":
    unittest.main()
