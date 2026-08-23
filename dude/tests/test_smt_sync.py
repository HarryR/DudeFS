from __future__ import annotations

import unittest

from dude.core import crypto
from dude.store import Store
from dude.store.layer import PathRow
from dude.store.smt_sync import Chunk, TreeExporter, TreeImporter, TreeSyncError
from dude.store.store import element


def _populate(store: Store, n: int, value_size: int = 64) -> crypto.Accumulator:
    acc = crypto.ACC_IDENTITY
    with store.write() as w:
        for i in range(n):
            name = crypto.h(i.to_bytes(4, "big"))
            value = crypto.random_bytes(value_size)
            cred = crypto.random_bytes(48)
            w.insert_live_row(PathRow(1, name, value, cred, 0))
            acc = crypto.acc_add(acc, element(1, name, value, 0))
        w._set_meta("acc", acc)
    return acc


class TestSmtSync(unittest.TestCase):

    def _round_trip(self, src: Store, budget: int) -> Store:
        src_root = src.state_root()
        with src.snapshot() as reader:
            chunks = list(TreeExporter(reader, max_chunk_bytes=budget).chunks())

        dst = Store()
        with dst.write() as writer:
            importer = TreeImporter(writer, expected_root=src_root)
            for chunk in chunks:
                importer.load(chunk)
            importer.verify()
        return dst

    def test_round_trip_root_matches(self):
        src = Store()
        _populate(src, 50)
        src_root = src.state_root()
        self.assertNotEqual(src_root, crypto.Digest(bytes(32)))

        dst = self._round_trip(src, budget=100_000)
        self.assertEqual(dst.state_root(), src_root)

    def test_adaptive_splitting(self):
        src = Store()
        _populate(src, 100, value_size=256)

        with src.snapshot() as reader:
            big = list(TreeExporter(reader, 1_000_000).chunks())
            small = list(TreeExporter(reader, 1_000).chunks())
        self.assertGreater(len(small), len(big))

    def test_empty_store(self):
        src = Store()
        with src.snapshot() as reader:
            chunks = list(TreeExporter(reader, 100_000).chunks())
        self.assertEqual(chunks, [])

    def test_single_key(self):
        src = Store()
        _populate(src, 1)
        src_root = src.state_root()

        with src.snapshot() as reader:
            chunks = list(TreeExporter(reader, 100_000).chunks())
        self.assertEqual(len(chunks), 1)
        self.assertEqual(len(chunks[0].rows), 1)

        dst = self._round_trip(src, budget=100_000)
        self.assertEqual(dst.state_root(), src_root)

    def test_tampered_value_rejected(self):
        src = Store()
        _populate(src, 10)
        src_root = src.state_root()

        with src.snapshot() as reader:
            chunks = list(TreeExporter(reader, 100_000).chunks())
        original = chunks[0]
        bad_row = original.rows[0]._replace(value=crypto.random_bytes(64))
        tampered = Chunk(
            original.depth, original.prefix, original.subtree_hash,
            (bad_row, *original.rows[1:]),
        )

        dst = Store()
        with dst.write() as writer:
            importer = TreeImporter(writer, expected_root=src_root)
            with self.assertRaises(TreeSyncError):
                importer.load(tampered)

    def test_accumulator_survives(self):
        src = Store()
        src_acc = _populate(src, 50)

        dst = self._round_trip(src, budget=100_000)

        dst_acc = crypto.ACC_IDENTITY
        with dst.snapshot() as reader:
            for row in reader.subtree_rows(bytes(crypto.DIGEST_SIZE), 0):
                dst_acc = crypto.acc_add(
                    dst_acc, element(row.store, row.name, row.value, row.epoch)
                )
        self.assertEqual(dst_acc, src_acc)

    def test_all_values_readable(self):
        src = Store()
        _populate(src, 30)

        original: dict[tuple[int, bytes], bytes] = {}
        with src.snapshot() as reader:
            for row in reader.subtree_rows(bytes(crypto.DIGEST_SIZE), 0):
                original[(row.store, row.name)] = row.value

        dst = self._round_trip(src, budget=100_000)

        with dst.snapshot() as reader:
            imported = list(reader.subtree_rows(bytes(crypto.DIGEST_SIZE), 0))
        self.assertEqual(len(imported), len(original))
        for row in imported:
            self.assertEqual(original[(row.store, row.name)], row.value)

    def test_final_root_mismatch_detected(self):
        src = Store()
        _populate(src, 10)
        wrong_root = crypto.h(b"wrong")

        with src.snapshot() as reader:
            chunks = list(TreeExporter(reader, 100_000).chunks())

        dst = Store()
        with dst.write() as writer:
            importer = TreeImporter(writer, expected_root=wrong_root)
            for chunk in chunks:
                importer.load(chunk)
            with self.assertRaises(TreeSyncError):
                importer.verify()

    def test_chunks_cover_all_rows(self):
        src = Store()
        _populate(src, 200, value_size=256)

        with src.snapshot() as reader:
            for budget in [500, 2_000, 50_000, 1_000_000]:
                chunks = list(TreeExporter(reader, budget).chunks())
                total_rows = sum(len(c.rows) for c in chunks)
                self.assertEqual(total_rows, 200, f"budget={budget}")


if __name__ == "__main__":
    unittest.main()
