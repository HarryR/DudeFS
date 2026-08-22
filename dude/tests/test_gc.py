from __future__ import annotations

import unittest

from dude.tests.cluster import Cluster


class TestStoreGC(unittest.TestCase):

    def setUp(self) -> None:
        self.c = Cluster(nodes=3, mgmt=1)
        self.s = self.c.mgmt_nodes[0].session()

    def tearDown(self) -> None:
        self.c.close()

    def test_gc_preserves_live_and_removes_history(self):
        for i in range(5):
            self.s.put(f"k{i}", f"v{i}".encode()).wait()
        self.c.wait_block(4)

        store = self.c.nodes[0].store
        pre_acc = store.accumulator()
        pre_root = store.state_root()
        pre_head = store.head()
        pre_block_num = store.head_block_num()

        pivot = 3
        entries_deleted = store.gc_below(pivot)
        self.assertGreater(entries_deleted, 0)

        self.assertEqual(store.accumulator(), pre_acc)
        self.assertEqual(store.state_root(), pre_root)
        self.assertEqual(store.head(), pre_head)
        self.assertEqual(store.head_block_num(), pre_block_num)

        for i in range(5):
            rec = self.s.get(f"k{i}")
            self.assertFalse(rec.absent, f"k{i} missing from live after GC")

        with store.snapshot() as r:
            lowest_block = r._conn.execute(
                "SELECT MIN(block_num) FROM block"
            ).fetchone()[0]
            self.assertEqual(lowest_block, pivot)

    def test_gc_at_nonexistent_block_is_noop(self):
        self.c.wait_block(2)
        store = self.c.nodes[0].store
        deleted = store.gc_below(9999)
        self.assertEqual(deleted, 0)

    def test_gc_keeps_pivot_block(self):
        self.s.put("x", b"y").wait()
        self.c.wait_block(3)

        store = self.c.nodes[0].store
        pivot = 2
        store.gc_below(pivot)

        self.assertIsNotNone(store.settled_at(pivot))
        self.assertIsNone(store.settled_at(1))

    def test_gc_does_not_break_post_gc_settlement(self):
        self.s.put("before", b"gc").wait()
        self.c.wait_block(3)

        for n in self.c.nodes:
            n.store.gc_below(2)

        self.s.put("after", b"gc").wait()
        self.c.wait_block(5)

        rec = self.s.get("after")
        self.assertFalse(rec.absent)
        self.assertEqual(rec.value, b"gc")


if __name__ == "__main__":
    unittest.main()
