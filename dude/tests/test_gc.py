from __future__ import annotations

import unittest

from dude.tests.cluster import Cluster


class TestStoreGC(unittest.TestCase):
    def setUp(self) -> None:
        self.c = Cluster(nodes=3, mgmt=1)
        self.s = self.c.replicas[0].session()

    def tearDown(self) -> None:
        self.c.close()

    def test_gc_preserves_live_and_removes_history(self):
        last = None
        for i in range(5):
            last = self.s.put(f"k{i}", f"v{i}".encode()).wait()
        self.c.wait_settled(last)

        store = self.c.nodes[0].store
        pre_acc = store.accumulator()
        pre_root = store.state_root()
        pre_head = store.head()
        pre_block_num = store.head_block_num()

        pivot = store.head_block_num() - 1
        entries_deleted = store.gc_below(pivot)
        self.assertGreater(entries_deleted, 0)

        self.assertEqual(store.accumulator(), pre_acc)
        self.assertEqual(store.state_root(), pre_root)
        self.assertEqual(store.head(), pre_head)
        self.assertEqual(store.head_block_num(), pre_block_num)

        for i in range(5):
            token = self.s.token(f"k{i}")
            held = store.get(self.s.store_id, token)
            self.assertIsNotNone(held, f"k{i} missing from live after GC")

        self.assertEqual(store.oldest_block_num(), pivot)

    def test_gc_at_nonexistent_block_is_noop(self):
        store = self.c.nodes[0].store
        deleted = store.gc_below(9999)
        self.assertEqual(deleted, 0)

    def test_gc_keeps_pivot_block(self):
        result = self.s.put("x", b"y").wait()
        self.c.wait_settled(result)

        store = self.c.nodes[0].store
        pivot = store.head_block_num()
        store.gc_below(pivot)

        self.assertIsNotNone(store.settled_at(pivot))
        self.assertIsNone(store.settled_at(0))

    def test_gc_does_not_break_post_gc_settlement(self):
        result = self.s.put("before", b"gc").wait()
        self.c.wait_settled(result)

        for n in self.c.nodes:
            n.store.gc_below(n.store.head_block_num())

        self.c.wait_settled(self.s.put("after", b"gc").wait())

        token = self.s.token("after")
        held = self.c.nodes[0].store.get(self.s.store_id, token)
        self.assertIsNotNone(held, "post-GC write not on consensus node")


if __name__ == "__main__":
    unittest.main()
