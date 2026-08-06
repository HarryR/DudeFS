"""Store snapshot / writer isolation semantics under threading.

The Store split is only useful if SQLite WAL actually gives us what we've been asserting:
  - Reader snapshots pin a consistent view across every read inside the scope.
  - Concurrent readers each get their own independent snapshot.
  - The writer serialises across threads.
  - The in-memory Store (backed by a tempfile) supports all of the above.

Each test here isolates ONE of those properties. If any fails, the whole reader/writer
split's premise is wrong -- we'd be back to hoping about isolation rather than knowing.
"""

from __future__ import annotations

import threading
import time
import unittest

from dude.core import crypto
from dude.store import ops
from dude.store.management import Management
from dude.store.store import Store

D = ops.STORE_DATA


def _tx(kp, key: bytes, value: bytes, ts: int = 1) -> ops.SignedTransaction:
    return ops.writes(ops.Set(D, key, value)).sign(kp, ts)


class TestSnapshotPinsAView(unittest.TestCase):
    """A reader's snapshot MUST return the same value across every read in the scope, even
    while a concurrent writer commits a change to that value. The whole reason the split
    exists -- composed reads (Management.change_roster and its ilk) don't see mid-flight
    writer commits."""

    def test_snapshot_pins_a_value_that_a_concurrent_writer_changes(self):
        mgr = crypto.Keypair.generate()
        store = Store()
        try:
            store.provision(mgr.public)
            mgmt = Management(store)
            key = crypto.h(b"pinned-key")
            # Land a first value we can pin a snapshot at.
            store.apply((_tx(mgr, key, b"v0"),), auth=mgmt)

            # Reader thread: hold a snapshot, read the key twice with a writer commit in
            # between. The reader MUST see the same v0 both times.
            barrier_before_read2 = threading.Event()
            writer_committed = threading.Event()
            observed: dict[str, bytes | None] = {}

            def reader():
                with store.snapshot() as r:
                    held = r.get(D, key)
                    observed["first"] = held.value if held else None
                    barrier_before_read2.set()
                    writer_committed.wait(timeout=5.0)
                    held = r.get(D, key)
                    observed["second"] = held.value if held else None

            def writer():
                barrier_before_read2.wait(timeout=5.0)
                store.apply((_tx(mgr, key, b"v1", ts=2),), auth=mgmt)
                writer_committed.set()

            reader_thread = threading.Thread(target=reader)
            writer_thread = threading.Thread(target=writer)
            reader_thread.start()
            writer_thread.start()
            reader_thread.join(timeout=5.0)
            writer_thread.join(timeout=5.0)

            self.assertEqual(observed["first"], b"v0", "reader's initial read")
            self.assertEqual(
                observed["second"],
                b"v0",
                "reader's second read INSIDE the same snapshot must still see v0 "
                "even though the writer committed v1",
            )
            # After the scope closes, a fresh snapshot sees the new value.
            final = store.get(D, key)
            assert final is not None
            self.assertEqual(final.value, b"v1")
        finally:
            store.close()


class TestConcurrentSnapshotsAreIndependent(unittest.TestCase):
    """Two threads opening snapshots at different moments around a writer commit each see
    the state as of their OWN BEGIN. Proves WAL gives us per-connection snapshots, not a
    shared single-writer view."""

    def test_two_snapshots_captured_around_a_write_diverge(self):
        mgr = crypto.Keypair.generate()
        store = Store()
        try:
            store.provision(mgr.public)
            mgmt = Management(store)
            key = crypto.h(b"divergent")
            store.apply((_tx(mgr, key, b"before"),), auth=mgmt)

            snap_a_opened = threading.Event()
            write_done = threading.Event()
            observed: dict[str, bytes | None] = {}

            def reader_before():
                with store.snapshot() as r:
                    snap_a_opened.set()
                    write_done.wait(timeout=5.0)
                    held = r.get(D, key)
                    observed["before"] = held.value if held else None

            def reader_after():
                snap_a_opened.wait(timeout=5.0)
                write_done.wait(timeout=5.0)
                # Fresh snapshot AFTER the write.
                with store.snapshot() as r:
                    held = r.get(D, key)
                    observed["after"] = held.value if held else None

            def writer():
                snap_a_opened.wait(timeout=5.0)
                store.apply((_tx(mgr, key, b"after", ts=2),), auth=mgmt)
                write_done.set()

            threads = [
                threading.Thread(target=reader_before),
                threading.Thread(target=reader_after),
                threading.Thread(target=writer),
            ]
            for t in threads:
                t.start()
            for t in threads:
                t.join(timeout=5.0)

            self.assertEqual(observed["before"], b"before")
            self.assertEqual(observed["after"], b"after")
        finally:
            store.close()


class TestWriterSerialisesAcrossThreads(unittest.TestCase):
    """Two threads racing `store.write()` -- the second's `with` blocks on the writer lock
    until the first exits. Both txs land in order. Proves the writer lock does what it
    claims (SQLite would refuse concurrent BEGIN IMMEDIATE on shared connections, but the
    lock makes serialisation explicit and testable)."""

    def test_two_concurrent_writers_serialise_and_both_land(self):
        mgr = crypto.Keypair.generate()
        store = Store()
        try:
            store.provision(mgr.public)
            mgmt = Management(store)
            key_a = crypto.h(b"a")
            key_b = crypto.h(b"b")

            def writer_a():
                store.apply((_tx(mgr, key_a, b"A"),), auth=mgmt)

            def writer_b():
                # Give A a slight head start so we're actually racing on the lock, not
                # on OS thread scheduling.
                time.sleep(0.005)
                store.apply((_tx(mgr, key_b, b"B", ts=2),), auth=mgmt)

            threads = [threading.Thread(target=writer_a), threading.Thread(target=writer_b)]
            for t in threads:
                t.start()
            for t in threads:
                t.join(timeout=5.0)

            # Both keys landed, both retrievable.
            got_a = store.get(D, key_a)
            got_b = store.get(D, key_b)
            assert got_a is not None and got_b is not None
            self.assertEqual(got_a.value, b"A")
            self.assertEqual(got_b.value, b"B")
        finally:
            store.close()


class TestInMemoryStoreIsAShareableWALDb(unittest.TestCase):
    """`Store()` (no path) uses a tempfile-backed WAL DB so the writer and every reader
    connection see the same DB with real snapshot isolation. Revert-check: if we replaced
    that with a naive `sqlite3.connect(':memory:')`, each connection would open a fresh
    empty DB and this test would fail."""

    def test_reader_connection_sees_writer_committed_data(self):
        mgr = crypto.Keypair.generate()
        store = Store()
        try:
            store.provision(mgr.public)
            mgmt = Management(store)
            key = crypto.h(b"shareable")
            store.apply((_tx(mgr, key, b"landed"),), auth=mgmt)

            # A fresh snapshot on a different reader connection sees the writer's commit.
            with store.snapshot() as r:
                held = r.get(D, key)
                assert held is not None
                self.assertEqual(held.value, b"landed")
                self.assertEqual(r.anchor(), mgr.public)
        finally:
            store.close()


if __name__ == "__main__":
    unittest.main()
