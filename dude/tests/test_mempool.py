# Tests for dude.mempool and dude.quorum. See SPEC.md (#mempool).
#
# Every test drives `now` explicitly. Nothing here sleeps or reads a system clock, which is the
# point of the mempool taking `now` as a parameter: a decade of buckets costs microseconds, and a
# clock fault is a value rather than an environment to reproduce.

from __future__ import annotations

import unittest

from ..consensus.mempool import (
    CANNOT_APPLY,
    DUPLICATE,
    TOO_NEW,
    TOO_OLD,
    UNSIGNED,
    Mempool,
    Refusal,
)
from ..core import crypto
from ..core.units import Millis
from ..quorum import (
    QuorumError,
    corroboration,
    intersection,
    max_domain,
    satisfied,
    size,
    spare,
    tolerates,
    would_brick,
)
from ..store import Store, ops, settle
from ..tunables import Tunables

D = ops.STORE_DATA
DK = crypto.NameToken(crypto.h(b"k"))
DJ = crypto.NameToken(crypto.h(b"j"))
"""Data-store names are 32-byte tokens: a node must not be able to read a key name, and
`evaluate` refuses any other width."""
M = ops.STORE_MANAGEMENT
T0 = Millis(1_700_000_000_000)


def name(s: str) -> bytes:
    return crypto.h(s.encode())


def write(kp: crypto.Keypair, key: str, value: bytes, ts: int) -> ops.SignedTransaction:
    return ops.writes(ops.Set(D, name(key), value)).sign(kp, ts)


class TestQuorum(unittest.TestCase):
    """The rule is two-thirds (#quorum-gate). Not configurable per node -- deployment
    flexibility lives in the roster size, not in the rule."""

    def test_intersection_is_the_fault_budget(self):
        """A quorum is a statement about tolerable faults, not a comfort level."""
        self.assertEqual(size(4), 3)
        self.assertEqual(intersection(4), 2)
        self.assertEqual(tolerates(4), 1)

    def test_three_nodes_tolerate_no_collusion(self):
        """Worth pinning because it is counter-intuitive: two-thirds of 3 is 2, so two quorums
        overlap in ONE node, which need not be honest -- so `tolerates(3) == 0`. This is why
        `corroboration(3) == 1`: a single honest fresh witness is enough at n=3."""
        self.assertEqual(size(3), 2)
        self.assertEqual(tolerates(3), 0)
        self.assertEqual(corroboration(3), 1)

    def test_safety_and_liveness_move_in_opposite_directions(self):
        """`tolerates` alone is a trap. At n=11 two-thirds gives spare=3 and tolerates=4, so
        SAFETY (byzantine bound) is 4 while LIVENESS (crash bound) is only 3. Both matter."""
        self.assertEqual(size(11), 8)
        self.assertEqual(tolerates(11), 4)  # safety: 4 collusion allowed
        self.assertEqual(spare(11), 3)  # liveness: 3 crashes allowed
        # max_domain is the tighter of the two, i.e. what production really has to live under.
        self.assertEqual(max_domain(11), 3)

    def test_refuses_vacuous(self):
        """`n=0` must raise, not return 0: a quorum satisfied by nobody agreeing finalises
        everything."""
        with self.assertRaises(QuorumError):
            size(0)

    def test_satisfied(self):
        self.assertFalse(satisfied(10, 6))
        self.assertTrue(satisfied(10, 7))

    def test_would_brick_at_small_n(self):
        """n<3 leaves every node required for quorum. One reboot removes progress."""
        self.assertTrue(would_brick(1))
        self.assertTrue(would_brick(2))
        self.assertFalse(would_brick(3))
        self.assertFalse(would_brick(11))


class TestBuckets(unittest.TestCase):
    def test_boundaries_are_computed_not_negotiated(self):
        """#buckets: two nodes derive the same bucket for the same transaction with ZERO
        communication, because the bucket is arithmetic on the transaction's own timestamp."""
        a, b = Tunables(rtt_max=Millis(200)), Tunables(rtt_max=Millis(200))
        d = a.block_time
        self.assertEqual(a.block_time, b.block_time, "the same inputs must derive the same block")
        for ts in (T0, T0 + 1, T0 + d - 1, T0 + d, T0 + d * 5 + d // 2):
            self.assertEqual(a.bucket(ts), b.bucket(ts))
        self.assertEqual(a.bucket(T0 + d - 1) - a.bucket(T0), 0)
        self.assertEqual(a.bucket(T0 + d) - a.bucket(T0), 1)


class TestAdmission(unittest.TestCase):
    def setUp(self):
        self.kp = crypto.Keypair.generate()
        self.t = Tunables(rtt_max=Millis(200))
        self.mp = Mempool(self.t)
        self.store = Store()  # the door consults state, so it needs one
        self.store.provision(self.kp.public)  # kp is the anchor => may_write returns True
        self.mgmt = self.store.mgmt_reader

    def _admit(self, tx, now=T0):
        return self.mp.admit(tx, now, self.store, self.mgmt)

    def test_a_transaction_repeating_one_operation_is_refused_at_the_door(self):
        """One operation, once. A repeated mutation applies twice in the preview that computes a
        block's anchors and once in the store, so it costs a log position of disagreement between
        what a block is signed for and what it settles. Both halves dedup, so this is not what
        holds that -- it refuses the shape at the door rather than letting every later stage carry
        the question."""
        m = ops.Set(ops.STORE_DATA, DK, b"v")
        doubled = ops.writes(m, m).sign(self.kp, T0)
        self.assertEqual(self._admit(doubled), Refusal.REPEATED_OP)
        self.assertIsNone(self._admit(ops.writes(m).sign(self.kp, T0)), "the single op is fine")

    def test_a_badly_shaped_data_row_is_refused_at_the_door_too(self):
        """The rules live in `settle.evaluate`, which serves BOTH this door and settlement -- so
        one check binds both and they cannot come apart the way the duplicate rules did. Admission
        reports `CANNOT_APPLY`, since it forwards the evaluator's refusal rather than restating
        which of its rules fired."""
        plaintext = ops.writes(ops.Set(ops.STORE_DATA, b"config/thing", b"v")).sign(self.kp, T0)
        self.assertEqual(self._admit(plaintext), CANNOT_APPLY)

        wrong_epoch = ops.writes(ops.Set(ops.STORE_DATA, DK, b"v", 3)).sign(self.kp, T0)
        self.assertEqual(self._admit(wrong_epoch), CANNOT_APPLY)

        ok = ops.writes(ops.Set(ops.STORE_DATA, DK, b"v")).sign(self.kp, T0)
        self.assertIsNone(self._admit(ok), "a token at the current epoch must pass the door")

    def test_clock_faults_are_named_not_merely_refused(self):
        """A client self-corrects only if the refusal says WHICH way its clock is wrong (§1.1)."""
        beyond = self.t.w_admit + 1
        self.assertEqual(self._admit(write(self.kp, "a", b"v", T0 - beyond)), TOO_OLD)
        self.assertEqual(self._admit(write(self.kp, "b", b"v", T0 + beyond)), TOO_NEW)
        self.assertIsNone(self._admit(write(self.kp, "c", b"v", T0)))

    def test_late_is_carried_forward_not_stranded(self):
        """§1.1's floor-not-window rule. A slow client's transaction lands in the CURRENT bucket,
        so it settles a few buckets later than its own clock suggests — never stranded in a bucket
        that has already gone."""
        lag = self.t.w_admit // 2
        late = write(self.kp, "late", b"v", T0 - lag)
        self.assertIsNone(self._admit(late))
        self.assertEqual(self.mp.buckets(), (self.t.bucket(T0),))
        self.assertNotIn(self.t.bucket(T0 - lag), self.mp.buckets())

    def test_early_client_waits_in_its_own_future_bucket(self):
        """The mirror case: a fast client's transaction lands where its `ts` says, ahead of now."""
        lead = self.t.w_admit // 2
        early = write(self.kp, "early", b"v", T0 + lead)
        self.assertIsNone(self._admit(early))
        self.assertEqual(self.mp.buckets(), (self.t.bucket(T0 + lead),))

    def test_unsigned_and_duplicate(self):
        tx = write(self.kp, "x", b"v", T0)
        forged = ops.SignedTransaction(tx.author, tx.ts, tx.txn, crypto.Signature(bytes(64)))
        self.assertEqual(self._admit(forged), UNSIGNED)
        self.assertIsNone(self._admit(tx))
        self.assertEqual(self._admit(tx), DUPLICATE)

    def test_a_transaction_already_in_the_log_is_refused(self):
        """#dedup-content-address: a settled tx MUST NOT enter the mempool. Property of the
        door: dedup against `pending` alone lets a settled UNGUARDED tx sail through, burn a
        slice slot, and vanish silently to the client."""
        tx = write(self.kp, "settled", b"v", T0)
        self.store.apply((tx,), auth=self.mgmt)
        self.assertEqual(self.store.head(), 1, "precondition: the tx is in the log")
        # A fresh mempool -- nothing in `pending`, so only the log can refuse this.
        self.assertEqual(Mempool(self.t).admit(tx, T0, self.store, self.mgmt), DUPLICATE)

    def test_the_door_refuses_a_settled_tx_that_would_still_apply(self):
        """The unguarded case stated as its own property, because it is the one the previous
        shape could not catch: `would_apply` says yes (a bare `set` re-applies cleanly against
        any state), so ONLY log membership distinguishes it."""
        tx = write(self.kp, "idempotent", b"v", T0)
        self.assertFalse(
            settle.would_apply(self.store, (tx,), self.mgmt).rejects,
            "precondition: this tx applies cleanly, so the evaluator cannot refuse it",
        )
        self.store.apply((tx,), auth=self.mgmt)
        self.assertFalse(
            settle.would_apply(self.store, (tx,), self.mgmt).rejects,
            "precondition: it STILL applies cleanly once settled -- unguarded, so nothing "
            "about committed state falsifies it",
        )
        self.assertEqual(Mempool(self.t).admit(tx, T0, self.store, self.mgmt), DUPLICATE)


if __name__ == "__main__":
    unittest.main()
