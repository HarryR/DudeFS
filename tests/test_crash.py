# WP2.4 — crash-restart at the persistence boundaries (RESILIENCE §0/§1.2).
#
# The node's durability domain is its ChainStore (one sqlite db): slot state, the
# attested floor, ops/receipts. The invariant is SIGN-AFTER-FSYNC — every mutating
# acceptor verb COMMITs before it signs, so no receipt/promise/watermark ever
# outlives the durable state that justified it. A "crash" here = drop the in-memory
# Acceptor and reopen the store; a clean restart re-derives from durable state and
# re-issues idempotently (never a contradiction). A crash BEFORE a COMMIT rolls
# back (sqlite), never a partial write.

import os
import tempfile
import unittest

from dudefs import artifacts as A
from dudefs import crypto as C
from dudefs.acceptor import Acceptor
from dudefs.store import ChainStore
from tests._builders import World

NOW = 1_000
SK = bytes([210] * 32)


def _acc(path, delta=10_000):
    return Acceptor(SK, C.SIGNER.public(SK), ChainStore(path), config_epoch=0, delta_ms=delta)


def _op(w):
    return w.cas(
        0, b"k", A.VERSION_ABSENT, 0, [[A.Guard.ABSENT, b"k"]], [[A.Mutation.SET, b"k", b"v"]]
    )


class TestCrashRestart(unittest.TestCase):
    def test_accept_is_durable_and_reissue_is_idempotent(self):
        # sign-after-fsync: on_accept COMMITs the op + slot state before signing, so
        # a crash right after leaves durable state; a retransmitted ACCEPT after
        # restart re-issues the IDENTICAL receipt — never a second, contradictory one.
        with tempfile.TemporaryDirectory() as d:
            path = os.path.join(d, "s.db")
            acc = _acc(path)
            w = World(seed=1, n_clients=1)
            op = _op(w)
            assert isinstance(op, A.Slotted)
            b = A.Ballot(1, b"x")
            r1 = acc.on_accept(op.slot_tag, b, op, NOW)
            assert isinstance(r1, A.Receipt)
            acc.store.close()  # CRASH (durable state persisted by the COMMIT)

            acc2 = _acc(path)  # RESTART on the same durable store
            with acc2.store.read_txn() as tx:
                self.assertEqual(tx.get_slot(op.slot_tag).accepted_op, op.op_hash)
                self.assertIsNotNone(tx.get_op(op.op_hash))
            r2 = acc2.on_accept(op.slot_tag, b, op, NOW)  # retransmit re-accept
            assert isinstance(r2, A.Receipt)
            self.assertEqual((r1.ballot, r1.sig), (r2.ballot, r2.sig))  # idempotent

    def test_promise_survives_restart_quorum_intersection_stands(self):
        # on_prepare COMMITs the promised ballot before signing the promise. After a
        # crash+restart the node still REFUSES a lower ballot (Nack) — the quorum
        # intersection Paxos leans on survives the restart.
        with tempfile.TemporaryDirectory() as d:
            path = os.path.join(d, "s.db")
            acc = _acc(path)
            w = World(seed=2, n_clients=1)
            tag = _op(w).slot_tag
            assert tag is not None
            p1 = acc.on_prepare(tag, A.Ballot(5, b"x"))
            self.assertIsInstance(p1, A.Promise)
            acc.store.close()  # CRASH after the promise COMMIT

            acc2 = _acc(path)  # RESTART
            r = acc2.on_prepare(tag, A.Ballot(3, b"y"))  # a LOWER ballot
            self.assertNotIsInstance(r, A.Promise)  # Nack: promised-5 survived the crash

    def test_floor_survives_crash_restart_and_never_regresses(self):
        # the attested watermark floor is durable; a watermark issued at an EARLIER
        # clock after restart does not regress it (B3 across a restart).
        with tempfile.TemporaryDirectory() as d:
            path = os.path.join(d, "s.db")
            acc = _acc(path, delta=50)
            wm1 = acc.issue_watermark(1_000)  # floor 950, attested persisted
            acc.store.close()  # CRASH

            acc2 = _acc(path, delta=50)  # RESTART
            with acc2.store.read_txn() as tx:
                self.assertEqual(tx.get_attested(), wm1.floor)  # attested durable
            wm2 = acc2.issue_watermark(500)  # earlier clock
            self.assertGreaterEqual(wm2.floor, wm1.floor)  # never regressed

    def test_reserved_issue_seq_survives_crash_no_burn(self):
        # finding 18(b): a seq is reserved WITH its justification in one COMMIT,
        # BEFORE signing. A crash after the reservation but before the receipt is
        # stored re-derives the identical receipt on restart (Ed25519 is
        # deterministic) and reuses the seq — the issuance chain stays gapless.
        with tempfile.TemporaryDirectory() as d:
            path = os.path.join(d, "s.db")
            w = World(seed=6, n_clients=1)
            op = _op(w)
            assert isinstance(op, A.Slotted)
            b = A.Ballot(1, b"x")
            store = ChainStore(path)
            with store.write_txn() as tx:
                seq = tx.reserve_receipt_seq(op.op_hash, b)  # committed
            before = A.Receipt.issue(SK, C.SIGNER.public(SK), op.op_hash, 0, b, seq)
            store.close()  # CRASH before the receipt is stored

            store2 = ChainStore(path)  # RESTART
            with store2.write_txn() as tx:
                self.assertEqual(tx.reserve_receipt_seq(op.op_hash, b), seq)  # same seq
            after = A.Receipt.issue(SK, C.SIGNER.public(SK), op.op_hash, 0, b, seq)
            self.assertEqual(before.sig, after.sig)  # deterministic re-derive
            with store2.read_txn() as tx:
                self.assertTrue(tx.issuance_gapless())  # no gap opened

    def test_mid_gc_crash_rolls_back_committed_gc_is_durable(self):
        # gc_checkpoint drops the dead set in ONE COMMIT. A crash BEFORE that commit
        # rolls back (no partial GC); a committed GC survives restart.
        with tempfile.TemporaryDirectory() as d:
            path = os.path.join(d, "s.db")
            store = ChainStore(path)
            w = World(seed=3, n_clients=1)
            op = _op(w)
            with store.write_txn() as tx:
                tx.append(op)

            # crash mid-GC: DELETE inside an OPEN transaction, then close without a
            # COMMIT -> sqlite rolls back the uncommitted write (the atomicity a
            # write_txn gives gc_checkpoint). Poke the writer connection directly to
            # stage the partial state a crash would leave.
            store._writer.execute("BEGIN")
            store._writer.execute("DELETE FROM ops WHERE op_hash=?", (op.op_hash,))
            store.close()
            store2 = ChainStore(path)
            with store2.read_txn() as tx:
                self.assertIsNotNone(tx.get_op(op.op_hash))  # partial GC rolled back

            with store2.write_txn() as tx:
                tx.gc_checkpoint([op.op_hash])  # a full, committed GC
            store2.close()
            store3 = ChainStore(path)
            with store3.read_txn() as tx:
                self.assertIsNone(tx.get_op(op.op_hash))  # durable


if __name__ == "__main__":
    unittest.main()
