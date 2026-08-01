# Tests for dude.mempool and dude.quorum. See SPEC.md (#mempool).
#
# Every test drives `now` explicitly. Nothing here sleeps or reads a system clock, which is the
# point of the mempool taking `now` as a parameter: a decade of buckets costs microseconds, and a
# clock fault is a value rather than an environment to reproduce.

from __future__ import annotations

import unittest

from ..consensus.mempool import (
    DUPLICATE,
    TOO_NEW,
    TOO_OLD,
    UNSIGNED,
    Mempool,
    Tunables,
    tx_id,
)
from ..core import crypto
from ..quorum import MAJORITY, MAJORITY_PLUS, TWO_THIRDS, QuorumError, satisfied, size
from ..store import Store, ops

D = ops.STORE_DATA
M = ops.STORE_MANAGEMENT
T0 = 1_700_000_000_000  # a fixed epoch, so bucket ids in assertions are stable


def name(s: str) -> bytes:
    return crypto.h(s.encode())


def write(kp: crypto.Keypair, key: str, value: bytes, ts: int) -> ops.SignedTransaction:
    return ops.writes(ops.Set(D, name(key), value)).sign(kp, ts)


class TestQuorum(unittest.TestCase):
    def test_intersection_is_the_fault_budget(self):
        """A rule is a statement about tolerable faults, not a comfort level."""
        self.assertEqual(size(4, TWO_THIRDS), 3)
        self.assertEqual(TWO_THIRDS.intersection(4), 2)
        self.assertEqual(TWO_THIRDS.tolerates(4), 1)

    def test_three_nodes_tolerate_no_collusion(self):
        """Worth pinning because it is counter-intuitive and the old package demoed on 3 nodes:
        two-thirds of 3 is 2, so two quorums overlap in ONE node, which need not be honest."""
        self.assertEqual(size(3, TWO_THIRDS), 2)
        self.assertEqual(TWO_THIRDS.tolerates(3), 0)
        self.assertEqual(MAJORITY.tolerates(3), 0)

    def test_safety_and_liveness_move_in_opposite_directions(self):
        """`tolerates` alone is a trap: `majority+1` at n=4 wants 4 of 4, so its safety overlap
        looks excellent while one node rebooting stops the cluster. Both numbers have to be read."""
        self.assertEqual(size(4, MAJORITY_PLUS), 4)  # unanimity
        self.assertEqual(MAJORITY_PLUS.tolerates(4), 3)  # safety: looks superb
        self.assertEqual(MAJORITY_PLUS.spare(4), 0)  # liveness: nothing may be down
        self.assertEqual(TWO_THIRDS.spare(4), 1)  # the same n, one node may fail

    def test_refuses_vacuous_and_unsatisfiable(self):
        """`n=0` must raise, not return 0: a quorum satisfied by nobody agreeing finalises
        everything."""
        with self.assertRaises(QuorumError):
            size(0)
        with self.assertRaises(QuorumError):
            size(1, MAJORITY_PLUS)  # needs 2 of 1

    def test_satisfied(self):
        self.assertFalse(satisfied(10, 6))
        self.assertTrue(satisfied(10, 7))


class TestBuckets(unittest.TestCase):
    def test_boundaries_are_computed_not_negotiated(self):
        """#buckets: two nodes derive the same bucket for the same transaction with ZERO
        communication, because the bucket is arithmetic on the transaction's own timestamp."""
        a, b = Tunables(delta=1_000), Tunables(delta=1_000)
        for ts in (T0, T0 + 1, T0 + 999, T0 + 1_000, T0 + 5_500):
            self.assertEqual(a.bucket(ts), b.bucket(ts))
        self.assertEqual(a.bucket(T0 + 999) - a.bucket(T0), 0)
        self.assertEqual(a.bucket(T0 + 1_000) - a.bucket(T0), 1)

    def test_w_valid_is_w_admit_plus_a_margin(self):
        """Not a second tier — a pipeline allowance, same order of magnitude (§1.2)."""
        t = Tunables(w_admit=30_000, w_valid_margin=3_000)
        self.assertEqual(t.w_valid, 33_000)
        self.assertLess(t.w_valid, 2 * t.w_admit)


class TestAdmission(unittest.TestCase):
    def setUp(self):
        self.kp = crypto.Keypair.generate()
        self.t = Tunables(delta=1_000, w_admit=30_000)
        self.mp = Mempool(self.t)
        self.store = Store()  # the door consults state, so it needs one

    def _admit(self, tx, now=T0):
        return self.mp.admit(tx, now, self.store)

    def test_clock_faults_are_named_not_merely_refused(self):
        """A client self-corrects only if the refusal says WHICH way its clock is wrong (§1.1)."""
        self.assertEqual(self._admit(write(self.kp, "a", b"v", T0 - 60_000)), TOO_OLD)
        self.assertEqual(self._admit(write(self.kp, "b", b"v", T0 + 60_000)), TOO_NEW)
        self.assertIsNone(self._admit(write(self.kp, "c", b"v", T0)))

    def test_late_is_carried_forward_not_stranded(self):
        """§1.1's floor-not-window rule. A slow client's transaction lands in the CURRENT bucket,
        so it settles a few buckets later than its own clock suggests — never stranded in a bucket
        that has already gone."""
        late = write(self.kp, "late", b"v", T0 - 20_000)  # inside w_admit, 20 buckets back
        self.assertIsNone(self._admit(late))
        self.assertEqual(self.mp.buckets(), (self.t.bucket(T0),))
        self.assertNotIn(self.t.bucket(T0 - 20_000), self.mp.buckets())

    def test_early_client_waits_in_its_own_future_bucket(self):
        """The mirror case: a fast client's transaction lands where its `ts` says, ahead of now."""
        early = write(self.kp, "early", b"v", T0 + 20_000)
        self.assertIsNone(self._admit(early))
        self.assertEqual(self.mp.buckets(), (self.t.bucket(T0 + 20_000),))

    def test_unsigned_and_duplicate(self):
        tx = write(self.kp, "x", b"v", T0)
        forged = ops.SignedTransaction(tx.author, tx.ts, tx.txn, crypto.Signature(bytes(64)))
        self.assertEqual(self._admit(forged), UNSIGNED)
        self.assertIsNone(self._admit(tx))
        self.assertEqual(self._admit(tx), DUPLICATE)

    def test_identity_is_the_store_s_own(self):
        """Dedup is the primary replay defence, and it only works because both sides agree on what
        "the same transaction" is (§1.2). A mempool-local id would break that silently."""
        tx = write(self.kp, "x", b"v", T0)
        self.assertEqual(tx_id(tx), tx.op_hash)


if __name__ == "__main__":
    unittest.main()
