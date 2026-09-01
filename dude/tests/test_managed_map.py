from __future__ import annotations

import unittest

from ..session import Settled, Refused
from ..store import ops
from ..store.managed import ManagedMap
from .cluster import Cluster


class TestManagedMap(unittest.TestCase):
    def setUp(self) -> None:
        self.c = Cluster(nodes=3, mgmt=1)
        self.s = self.c.replicas[0].session(store_id=ops.STORE_MANAGEMENT)
        self.m = ManagedMap(b"test/", self.s)

    def tearDown(self) -> None:
        self.c.close()

    def _apply(self, tx: ops.Transaction) -> bool:
        result = self.s.submit(tx).wait()
        if isinstance(result, Settled):
            self.c.wait_settled(result)
            return True
        if isinstance(result, Refused):
            return False
        raise AssertionError(f"expected Settled or Refused, got {result!r}")

    def test_empty_map(self) -> None:
        self.assertIsNone(self.m.meta())
        self.assertEqual(self.m.keys(), [])
        self.assertEqual(self.m.items(), [])
        self.assertIsNone(self.m.entry(b"x"))

    def test_add_one(self) -> None:
        self.assertTrue(self._apply(self.m.add(b"alice", b"value_a")))
        meta = self.m.meta()        
        self.assertIsNotNone(meta)
        assert meta is not None
        self.assertEqual(meta.count, 1)
        self.assertEqual(self.m.keys(), [b"alice"])
        e = self.m.entry(b"alice")        
        self.assertIsNotNone(e)
        assert e is not None
        self.assertEqual(e.value, b"value_a")
        self.assertEqual(e.index, 0)

    def test_add_three(self) -> None:
        for name in (b"alice", b"bob", b"carol"):
            self.assertTrue(self._apply(self.m.add(name, name.upper())))
        meta = self.m.meta()
        self.assertIsNotNone(meta)
        assert meta is not None
        self.assertEqual(meta.count, 3)
        self.assertEqual(sorted(self.m.keys()), [b"alice", b"bob", b"carol"])
        items = dict(self.m.items())
        self.assertEqual(items[b"bob"], b"BOB")

    def test_duplicate_add_refused(self) -> None:
        self.assertTrue(self._apply(self.m.add(b"alice", b"v")))
        self.assertFalse(self._apply(self.m.add(b"alice", b"v2")))

    def test_remove_only_element(self) -> None:
        self.assertTrue(self._apply(self.m.add(b"alice", b"v")))
        self.assertTrue(self._apply(self.m.remove(b"alice")))
        meta = self.m.meta()
        self.assertIsNotNone(meta)
        assert meta is not None
        self.assertEqual(meta.count, 0)
        self.assertEqual(self.m.keys(), [])
        self.assertIsNone(self.m.entry(b"alice"))

    def test_remove_last_element(self) -> None:
        for name in (b"a", b"b", b"c"):
            self.assertTrue(self._apply(self.m.add(name, name)))
        self.assertTrue(self._apply(self.m.remove(b"c")))
        meta = self.m.meta()
        self.assertIsNotNone(meta)
        assert meta is not None
        self.assertEqual(meta.count, 2)
        self.assertEqual(sorted(self.m.keys()), [b"a", b"b"])

    def test_remove_middle_swaps_last_in(self) -> None:
        for name in (b"a", b"b", b"c"):
            self.assertTrue(self._apply(self.m.add(name, name)))
        self.assertTrue(self._apply(self.m.remove(b"a")))
        meta = self.m.meta()
        self.assertIsNotNone(meta)
        assert meta is not None
        self.assertEqual(meta.count, 2)
        keys = self.m.keys()
        self.assertEqual(sorted(keys), [b"b", b"c"])
        c_entry = self.m.entry(b"c")
        self.assertIsNotNone(c_entry)
        assert c_entry is not None
        self.assertEqual(c_entry.index, 0)
        self.assertIsNone(self.m.entry(b"a"))

    def test_remove_then_add_reuses_slot(self) -> None:
        for name in (b"a", b"b", b"c"):
            self.assertTrue(self._apply(self.m.add(name, name)))
        self.assertTrue(self._apply(self.m.remove(b"b")))
        self.assertTrue(self._apply(self.m.add(b"d", b"d")))
        meta = self.m.meta()
        assert meta is not None
        self.assertIsNotNone(meta)
        self.assertEqual(meta.count, 3)
        self.assertEqual(sorted(self.m.keys()), [b"a", b"c", b"d"])

    def test_update_value(self) -> None:
        self.assertTrue(self._apply(self.m.add(b"k", b"old")))
        self.assertTrue(self._apply(self.m.update(b"k", b"new")))
        e = self.m.entry(b"k")
        assert e is not None
        self.assertIsNotNone(e)
        self.assertEqual(e.value, b"new")
        self.assertEqual(e.index, 0)

    def test_update_does_not_change_meta(self) -> None:
        self.assertTrue(self._apply(self.m.add(b"k", b"old")))
        meta_before = self.m.meta()
        self.assertTrue(self._apply(self.m.update(b"k", b"new")))
        meta_after = self.m.meta()
        assert meta_before is not None and meta_after is not None
        self.assertEqual(meta_before.count, meta_after.count)
        self.assertEqual(meta_before.acc, meta_after.acc)

    def test_concurrent_add_conflicts(self) -> None:
        tx1 = self.m.add(b"alice", b"v1")
        tx2 = self.m.add(b"bob", b"v2")
        self.assertTrue(self._apply(tx1))
        self.assertFalse(self._apply(tx2))

    def test_concurrent_remove_conflicts(self) -> None:
        for name in (b"a", b"b", b"c"):
            self.assertTrue(self._apply(self.m.add(name, name)))
        tx1 = self.m.remove(b"a")
        tx2 = self.m.remove(b"b")
        self.assertTrue(self._apply(tx1))
        self.assertFalse(self._apply(tx2))

    def test_concurrent_update_conflicts(self) -> None:
        self.assertTrue(self._apply(self.m.add(b"k", b"v")))
        tx1 = self.m.update(b"k", b"new1")
        tx2 = self.m.update(b"k", b"new2")
        self.assertTrue(self._apply(tx1))
        self.assertFalse(self._apply(tx2))

    def test_update_and_add_do_not_conflict(self) -> None:
        self.assertTrue(self._apply(self.m.add(b"k", b"v")))
        tx_update = self.m.update(b"k", b"new")
        tx_add = self.m.add(b"k2", b"v2")
        self.assertTrue(self._apply(tx_update))
        self.assertTrue(self._apply(tx_add))

    def test_accumulator_changes_on_add(self) -> None:
        self.assertTrue(self._apply(self.m.add(b"a", b"v")))
        acc1 = self.m.meta().acc
        self.assertTrue(self._apply(self.m.add(b"b", b"v")))
        acc2 = self.m.meta().acc
        self.assertNotEqual(acc1, acc2)

    def test_accumulator_restores_after_remove(self) -> None:
        self.assertTrue(self._apply(self.m.add(b"a", b"v")))
        acc_one = self.m.meta().acc
        self.assertTrue(self._apply(self.m.add(b"b", b"v")))
        self.assertTrue(self._apply(self.m.remove(b"b")))
        acc_back = self.m.meta().acc
        self.assertEqual(acc_one, acc_back)

    def test_iterate_after_churn(self) -> None:
        for i in range(5):
            k = f"key_{i}".encode()
            self.assertTrue(self._apply(self.m.add(k, k)))
        self.assertTrue(self._apply(self.m.remove(b"key_1")))
        self.assertTrue(self._apply(self.m.remove(b"key_3")))
        remaining = self.m.keys()
        self.assertEqual(len(remaining), 3)
        for k in remaining:
            e = self.m.entry(k)
            assert e is not None
            self.assertEqual(e.value, k)


if __name__ == "__main__":
    unittest.main()
