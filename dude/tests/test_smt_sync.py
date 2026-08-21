from __future__ import annotations

import os
import sqlite3
import tempfile
import unittest

from dude.core import crypto
from dude.store import Store
from dude.store.smt import Tree, path_of
from dude.store.smt_sync import Chunk, TreeExporter, TreeImporter, TreeSyncError
from dude.store.store import _SCHEMA, element


def _populate(store: Store, n: int, value_size: int = 64) -> crypto.Accumulator:
    acc = crypto.ACC_IDENTITY
    with store.write() as w:
        for i in range(n):
            name = crypto.h(i.to_bytes(4, "big"))
            value = crypto.random_bytes(value_size)
            cred = crypto.random_bytes(48)
            path = path_of(1, name)
            w._conn.execute(
                "INSERT OR REPLACE INTO live (store, name, value, epoch, path, cred)"
                " VALUES (?,?,?,?,?,?)",
                (1, name, value, 0, path, cred),
            )
            acc = crypto.acc_add(acc, element(1, name, value, 0))
        w._set_meta("acc", acc)
    return acc


def _receiver_db():
    fd, path = tempfile.mkstemp(suffix=".sqlite")
    os.close(fd)
    conn = sqlite3.connect(path, isolation_level=None)
    conn.execute("PRAGMA journal_mode=WAL")
    conn.executescript(_SCHEMA)
    return conn, path


class TestSmtSync(unittest.TestCase):

    def _round_trip(self, src: Store, budget: int) -> sqlite3.Connection:
        src_root = src.state_root()
        exporter = TreeExporter(src.db, max_chunk_bytes=budget)
        chunks = list(exporter.chunks())

        dst_conn, dst_path = _receiver_db()
        self.addCleanup(dst_conn.close)
        self.addCleanup(os.unlink, dst_path)

        importer = TreeImporter(dst_conn, expected_root=src_root)
        for chunk in chunks:
            importer.load(chunk)
        importer.verify()
        return dst_conn

    def test_round_trip_root_matches(self):
        src = Store()
        _populate(src, 50)
        src_root = src.state_root()
        self.assertNotEqual(src_root, crypto.Digest(bytes(32)))

        dst_conn = self._round_trip(src, budget=100_000)
        self.assertEqual(Tree(dst_conn).root(), src_root)

    def test_adaptive_splitting(self):
        src = Store()
        _populate(src, 100, value_size=256)

        big = list(TreeExporter(src.db, 1_000_000).chunks())
        small = list(TreeExporter(src.db, 1_000).chunks())
        self.assertGreater(len(small), len(big))

    def test_empty_store(self):
        src = Store()
        chunks = list(TreeExporter(src.db, 100_000).chunks())
        self.assertEqual(chunks, [])

    def test_single_key(self):
        src = Store()
        _populate(src, 1)
        src_root = src.state_root()

        chunks = list(TreeExporter(src.db, 100_000).chunks())
        self.assertEqual(len(chunks), 1)
        self.assertEqual(len(chunks[0].rows), 1)

        dst_conn = self._round_trip(src, budget=100_000)
        self.assertEqual(Tree(dst_conn).root(), src_root)

    def test_tampered_value_rejected(self):
        src = Store()
        _populate(src, 10)
        src_root = src.state_root()

        chunks = list(TreeExporter(src.db, 100_000).chunks())
        original = chunks[0]
        bad_row = original.rows[0]._replace(value=crypto.random_bytes(64))
        tampered = Chunk(
            original.depth, original.prefix, original.subtree_hash,
            (bad_row, *original.rows[1:]),
        )

        dst_conn, dst_path = _receiver_db()
        self.addCleanup(dst_conn.close)
        self.addCleanup(os.unlink, dst_path)

        importer = TreeImporter(dst_conn, expected_root=src_root)
        with self.assertRaises(TreeSyncError):
            importer.load(tampered)

    def test_accumulator_survives(self):
        src = Store()
        src_acc = _populate(src, 50)

        dst_conn = self._round_trip(src, budget=100_000)

        dst_acc = crypto.ACC_IDENTITY
        for st, name, value, epoch in dst_conn.execute(
            "SELECT store, name, value, epoch FROM live"
        ).fetchall():
            dst_acc = crypto.acc_add(dst_acc, element(int(st), name, value, int(epoch)))
        self.assertEqual(dst_acc, src_acc)

    def test_all_values_readable(self):
        src = Store()
        _populate(src, 30)

        original: dict[tuple[int, bytes], bytes] = {}
        for st, name, value in src.db.execute("SELECT store, name, value FROM live").fetchall():
            original[(int(st), bytes(name))] = bytes(value)

        dst_conn = self._round_trip(src, budget=100_000)

        for st, name, value in dst_conn.execute("SELECT store, name, value FROM live").fetchall():
            self.assertEqual(original[(int(st), bytes(name))], bytes(value))
        self.assertEqual(
            dst_conn.execute("SELECT COUNT(*) FROM live").fetchone()[0],
            len(original),
        )

    def test_final_root_mismatch_detected(self):
        src = Store()
        _populate(src, 10)
        wrong_root = crypto.h(b"wrong")

        chunks = list(TreeExporter(src.db, 100_000).chunks())

        dst_conn, dst_path = _receiver_db()
        self.addCleanup(dst_conn.close)
        self.addCleanup(os.unlink, dst_path)

        importer = TreeImporter(dst_conn, expected_root=wrong_root)
        for chunk in chunks:
            importer.load(chunk)
        with self.assertRaises(TreeSyncError):
            importer.verify()

    def test_chunks_cover_all_rows(self):
        src = Store()
        _populate(src, 200, value_size=256)

        for budget in [500, 2_000, 50_000, 1_000_000]:
            chunks = list(TreeExporter(src.db, budget).chunks())
            total_rows = sum(len(c.rows) for c in chunks)
            self.assertEqual(total_rows, 200, f"budget={budget}")


if __name__ == "__main__":
    unittest.main()
