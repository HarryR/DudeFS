# HANDOFF-R5 WP-5 (concurrency) + WP-6 (durable restart). These run against REAL
# temp-file stores so the two-connection WAL path is exercised — the `:memory:`
# fallback is a single connection and would not surface these behaviors.
#
# WP-5 is the regression net for the three bugs the refactor closed: the maintenance
# / serve data race (a reader and writer racing one shared connection), read-
# uncommitted (a reader seeing a writer's uncommitted state), and the RMW slot race
# (two accepts both "winning" a slot). WP-6 proves a file-backed daemon resumes from
# disk instead of re-syncing from genesis.

import os
import sqlite3
import tempfile
import threading
import unittest

from dudefs import artifacts as A
from dudefs import crypto as C
from dudefs.acceptor import Acceptor
from dudefs.daemon import NodeDaemon
from dudefs.store import ChainStore, StoreBusy, StoreClosed
from tests._builders import World

NOW = 100
KEY = b"jobs/1"


def _file_store(d: str, name: str = "s.db") -> ChainStore:
    return ChainStore(os.path.join(d, name))


class TestWALConcurrency(unittest.TestCase):
    def test_read_snapshot_is_stable_across_a_concurrent_commit(self):
        # WAL MVCC: a read_txn pins ONE committed snapshot; a writer committing while
        # the read transaction is open cannot change what it sees (no read-uncommitted,
        # no torn compound read). The reader and writer are separate connections. The
        # commit runs on a SEPARATE thread — same-store txn nesting on one thread is a
        # footgun the store now forbids (a read_txn's reader connection would not even
        # see the write's uncommitted rows); real concurrency is cross-thread anyway.
        w = World(seed=1, n_clients=1)
        with tempfile.TemporaryDirectory() as d:
            s = _file_store(d)
            with s.write_txn() as tx:
                tx.put_op_raw(w.blind(0, [], [[A.Mutation.SET, b"k", b"0"]]))

            def _commit_second() -> None:
                with s.write_txn() as wtx:
                    wtx.put_op_raw(w.blind(0, [], [[A.Mutation.SET, b"k", b"1"]]))

            with s.read_txn() as rtx:
                self.assertEqual(len(rtx.all_ops()), 1)  # snapshot fixed here
                t = threading.Thread(target=_commit_second)  # a writer commits mid-read
                t.start()
                t.join()
                self.assertEqual(len(rtx.all_ops()), 1)  # STILL 1 — snapshot pinned
            with s.read_txn() as rtx:  # a fresh transaction sees the new committed op
                self.assertEqual(len(rtx.all_ops()), 2)
            s.close()

    def test_concurrent_readers_and_writer_never_corrupt_or_raise(self):
        # The data race the shared-connection design had: a maintenance write thread
        # and serving read threads on one store. With the reader/writer split + WAL,
        # they run concurrently with no ProgrammingError / torn read, and the final
        # state is exactly the writes that were made.
        w = World(seed=2, n_clients=1)
        with tempfile.TemporaryDirectory() as d:
            s = _file_store(d)
            ops = [w.blind(0, [], [[A.Mutation.SET, b"k", bytes([i])]]) for i in range(60)]
            errors: list[Exception] = []

            def writer() -> None:
                try:
                    for op in ops:
                        with s.write_txn() as tx:
                            tx.put_op_raw(op)
                except Exception as e:  # noqa: BLE001 — the test IS the assertion
                    errors.append(e)

            def reader() -> None:
                try:
                    for _ in range(300):
                        with s.read_txn() as tx:
                            _ = len(tx.all_ops())  # a compound scan under the snapshot
                except Exception as e:  # noqa: BLE001
                    errors.append(e)

            threads = [threading.Thread(target=writer)]
            threads += [threading.Thread(target=reader) for _ in range(3)]
            for t in threads:
                t.start()
            for t in threads:
                t.join()
            self.assertEqual(errors, [])  # no torn reads / locked-database / crashes
            with s.read_txn() as tx:
                self.assertEqual(len(tx.all_ops()), 60)  # every write landed
            s.close()

    def test_concurrent_slot_accepts_yield_exactly_one_winner(self):
        # The RMW race the write transaction closes: two threads ACCEPT DIFFERENT ops
        # at the SAME (tag, ballot). The acceptor's get_slot -> decide -> write_slot is
        # one write_txn, so the writer lock serializes them: exactly one is accepted,
        # the other hits the equivocation guard — never two decided (B1 under real
        # concurrency, on a real file store).
        w = World(seed=3, n_clients=2)
        with tempfile.TemporaryDirectory() as d:
            nsk = bytes([200] * 32)
            acc = Acceptor(nsk, C.SIGNER.public(nsk), _file_store(d), 0, 10**9)
            guards = [[A.Guard.ABSENT, KEY]]
            op_a = w.cas(0, KEY, A.VERSION_ABSENT, 0, guards, [[A.Mutation.SET, KEY, b"A"]])
            op_b = w.cas(1, KEY, A.VERSION_ABSENT, 0, guards, [[A.Mutation.SET, KEY, b"B"]])
            self.assertEqual(op_a.slot_tag, op_b.slot_tag)  # same slot, two contenders
            tag = op_a.slot_tag
            assert tag is not None
            ballot = A.Ballot(1, b"x")
            results: dict[str, object] = {}

            def do(name: str, op: A.Op) -> None:
                results[name] = acc.on_accept(tag, ballot, op, NOW)

            ta = threading.Thread(target=do, args=("A", op_a))
            tb = threading.Thread(target=do, args=("B", op_b))
            ta.start()
            tb.start()
            ta.join()
            tb.join()
            receipts = [v for v in results.values() if isinstance(v, A.Receipt)]
            self.assertEqual(len(receipts), 1)  # exactly one op decided the slot
            with acc.store.read_txn() as tx:  # the durable slot agrees with the winner
                self.assertEqual(tx.get_slot(tag).accepted_op, receipts[0].op_hash)
            acc.store.close()


class TestTxnNestingGuard(unittest.TestCase):
    # Same-store, same-thread transaction nesting is a footgun (write-in-write
    # deadlocks; read-inside-write silently reads the last committed snapshot, not the
    # write's own uncommitted rows). The store forbids all four combinations up front.
    def test_all_same_store_nestings_raise(self):
        with tempfile.TemporaryDirectory() as d:
            s = _file_store(d)
            for outer, inner in (
                (s.write_txn, s.write_txn),
                (s.read_txn, s.read_txn),
                (s.write_txn, s.read_txn),
                (s.read_txn, s.write_txn),
            ):
                with outer():
                    with self.assertRaises(RuntimeError):
                        with inner():
                            pass
            s.close()

    def test_different_stores_on_one_thread_are_allowed(self):
        # the guard is per-store; the sim's two-store merge nests legitimately.
        w = World(seed=6, n_clients=1)
        with tempfile.TemporaryDirectory() as d:
            a, b = _file_store(d, "a.db"), _file_store(d, "b.db")
            with a.write_txn() as ta:
                with b.read_txn() as tb:  # different store — fine
                    ta.put_op_raw(w.blind(0, [], [[A.Mutation.SET, b"k", b"0"]]))
                    self.assertEqual(len(tb.all_ops()), 0)
            a.close()
            b.close()

    def test_a_raised_guard_does_not_poison_the_thread(self):
        # after a nesting attempt raises, the thread can still open a fresh txn.
        with tempfile.TemporaryDirectory() as d:
            s = _file_store(d)
            with s.read_txn():
                with self.assertRaises(RuntimeError):
                    with s.read_txn():
                        pass
            with s.write_txn() as tx:  # thread flag was cleared — this works
                self.assertEqual(len(tx.all_ops()), 0)
            s.close()


class TestTxnFailureAndClose(unittest.TestCase):
    def test_write_txn_rollback_preserves_the_body_exception_and_store_stays_usable(self):
        # A mid-txn failure must ROLL BACK (the op is not durable) AND propagate the
        # ORIGINAL exception — not a "cannot rollback" mask — and leave the writer
        # connection usable for the next txn (the guarded-rollback path).
        class Boom(Exception):
            pass

        w = World(seed=7, n_clients=1)
        with tempfile.TemporaryDirectory() as d:
            s = _file_store(d)
            with self.assertRaises(Boom):
                with s.write_txn() as tx:
                    tx.put_op_raw(w.blind(0, [], [[A.Mutation.SET, b"k", b"0"]]))
                    raise Boom  # the real error the caller must see
            with s.read_txn() as tx:
                self.assertEqual(len(tx.all_ops()), 0)  # rolled back, not persisted
            with s.write_txn() as tx:  # connection not wedged — next txn works
                tx.put_op_raw(w.blind(0, [], [[A.Mutation.SET, b"k", b"1"]]))
            with s.read_txn() as tx:
                self.assertEqual(len(tx.all_ops()), 1)
            s.close()

    def test_txns_on_a_closed_store_raise_storeclosed_and_close_is_idempotent(self):
        with tempfile.TemporaryDirectory() as d:
            s = _file_store(d)
            s.close()
            with self.assertRaises(StoreClosed):
                with s.write_txn():
                    pass
            with self.assertRaises(StoreClosed):
                with s.read_txn():
                    pass
            s.close()  # idempotent — a second close is a no-op, not a raise

    def test_cross_process_write_contention_raises_storebusy_chaining_the_cause(self):
        # Two ChainStores on ONE file = two processes' worth of connections. While one
        # holds the write lock (BEGIN IMMEDIATE -> RESERVED), the other's write cannot
        # take it and, past its busy_timeout, surfaces a TYPED StoreBusy (not a leaked
        # sqlite3.OperationalError), with the sqlite error chained as __cause__.
        with tempfile.TemporaryDirectory() as d:
            path = os.path.join(d, "s.db")
            holder = ChainStore(path)
            contender = ChainStore(path, busy_timeout_ms=50)  # fail fast instead of 5s
            with holder.write_txn():  # RESERVED lock held on the file
                with self.assertRaises(StoreBusy) as cm:
                    with contender.write_txn():
                        pass
                self.assertIsInstance(cm.exception.__cause__, sqlite3.OperationalError)
            holder.close()
            contender.close()


class TestDurableRestart(unittest.TestCase):
    def test_store_resumes_ops_and_checkpoint_from_disk(self):
        # WP-6: a file-backed store reopened on the same path resumes its ops AND the
        # durable checkpoint horizon — it is not empty (the property `:memory:` hides).
        w = World(seed=4, n_clients=1)
        with tempfile.TemporaryDirectory() as d:
            path = os.path.join(d, "s.db")
            s = ChainStore(path)
            op = w.blind(0, [], [[A.Mutation.SET, b"k", b"v"]])
            with s.write_txn() as tx:
                tx.append(op)
                tx.adopt_checkpoint(A.Baseline({op.author: (0, op.op_hash)}, {}), A.HLC(9, 0))
            s.close()  # process restart

            s2 = ChainStore(path)
            with s2.read_txn() as tx:
                self.assertIsNotNone(tx.get_op(op.op_hash))  # resumed from disk
                self.assertEqual(tx.get_horizon(), A.HLC(9, 0))  # checkpoint durable
            s2.close()

    def test_node_daemon_restart_resumes_from_disk_not_genesis(self):
        # WP-6: a file-backed node that accepted a write, when restarted on the SAME
        # store path, still HOLDS that op — it resumes from disk rather than starting
        # empty and re-syncing from genesis over gossip. (Contrast test_demo's restart,
        # which is a fresh :memory: store that MUST re-join via gossip.)
        w = World(seed=5, n_clients=1)
        nsk = bytes([200] * 32)
        roster = [C.SIGNER.public(nsk)]
        with tempfile.TemporaryDirectory() as d:
            path = os.path.join(d, "node.db")

            def _node() -> NodeDaemon:
                return NodeDaemon(
                    nsk,
                    roster[0],
                    path,
                    roster=roster,
                    manager_pub=w.mgr_pub,
                    control_ops=w.control_ops,  # seeds the client's WRITE cert (authz)
                    clock=lambda: NOW,
                    delta_ms=10**9,
                )

            nd = _node()
            op = w.blind(0, [], [[A.Mutation.SET, b"k", b"v"]])
            r = nd.acc.on_submit(op, NOW)  # a blind write, accepted + committed to disk
            self.assertIsInstance(r, A.Receipt)
            nd.close()  # kill -9

            nd2 = _node()  # RESTART on the same durable path
            with nd2.store.read_txn() as tx:
                self.assertIsNotNone(tx.get_op(op.op_hash))  # still held — resumed, not empty
            nd2.close()


if __name__ == "__main__":
    unittest.main()
