# Tests for dude.mempool and dude.quorum. See ../../MEMPOOL.md.
#
# Every test drives `now` explicitly. Nothing here sleeps or reads a system clock, which is the
# point of the mempool taking `now` as a parameter: a decade of buckets costs microseconds, and a
# clock fault is a value rather than an environment to reproduce.

from __future__ import annotations

import unittest

from ..core import crypto
from ..mempool import (
    DUPLICATE,
    TOO_NEW,
    TOO_OLD,
    UNSIGNED,
    Mempool,
    Tunables,
    tx_id,
)
from ..quorum import MAJORITY, MAJORITY_PLUS, TWO_THIRDS, QuorumError, satisfied, size
from ..store import Store, ops, settle
from ..store.management import Management, Role

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
        """MEMPOOL.md §1: two nodes derive the same bucket for the same transaction with ZERO
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

    def test_clock_faults_are_named_not_merely_refused(self):
        """A client self-corrects only if the refusal says WHICH way its clock is wrong (§1.1)."""
        self.assertEqual(self.mp.admit(write(self.kp, "a", b"v", T0 - 60_000), T0), TOO_OLD)
        self.assertEqual(self.mp.admit(write(self.kp, "b", b"v", T0 + 60_000), T0), TOO_NEW)
        self.assertIsNone(self.mp.admit(write(self.kp, "c", b"v", T0), T0))

    def test_late_is_carried_forward_not_stranded(self):
        """§1.1's floor-not-window rule. A slow client's transaction lands in the CURRENT bucket,
        so it settles a few buckets later than its own clock suggests — never stranded in a bucket
        that has already gone."""
        late = write(self.kp, "late", b"v", T0 - 20_000)  # inside w_admit, 20 buckets back
        self.assertIsNone(self.mp.admit(late, T0))
        self.assertEqual(self.mp.buckets(), (self.t.bucket(T0),))
        self.assertNotIn(self.t.bucket(T0 - 20_000), self.mp.buckets())

    def test_early_client_waits_in_its_own_future_bucket(self):
        """The mirror case: a fast client's transaction lands where its `ts` says, ahead of now."""
        early = write(self.kp, "early", b"v", T0 + 20_000)
        self.assertIsNone(self.mp.admit(early, T0))
        self.assertEqual(self.mp.buckets(), (self.t.bucket(T0 + 20_000),))

    def test_unsigned_and_duplicate(self):
        tx = write(self.kp, "x", b"v", T0)
        forged = ops.SignedTransaction(tx.author, tx.ts, tx.txn, crypto.Signature(bytes(64)))
        self.assertEqual(self.mp.admit(forged, T0), UNSIGNED)
        self.assertIsNone(self.mp.admit(tx, T0))
        self.assertEqual(self.mp.admit(tx, T0), DUPLICATE)

    def test_identity_is_the_store_s_own(self):
        """Dedup is the primary replay defence, and it only works because both sides agree on what
        "the same transaction" is (§1.2). A mempool-local id would break that silently."""
        tx = write(self.kp, "x", b"v", T0)
        self.assertEqual(tx_id(tx), tx.op_hash)

    def test_endorsers_use_w_valid_never_w_admit(self):
        """§1.2. A transaction admitted at the very edge of `w_admit` is endorsed a wave later, so
        re-applying the door would refuse a slice member that was legitimately admitted."""
        edge = write(self.kp, "edge", b"v", T0 - self.t.w_admit)
        self.assertIsNone(self.mp.admit(edge, T0))
        later = T0 + self.t.w_valid_margin  # a couple of waves on
        self.assertGreater(later - edge.ts, self.t.w_admit)  # the door would now refuse it...
        self.assertTrue(self.mp.endorsable(edge, later))  # ...but endorsement does not


class TestProposal(unittest.TestCase):
    def setUp(self):
        self.store = Store()
        self.mgr = crypto.Keypair.generate()
        self.mgmt = Management(self.store)
        self.store.apply(
            (
                self.mgmt.authorise(
                    self.mgr.public,
                    Role.MANAGER,
                    frozenset({M, D}),
                    frozenset(),
                    self.mgr.prove_possession(),
                ).sign(self.mgr, T0),
            )
        )
        self.t = Tunables(delta=1_000, w_admit=30_000)

    def _pool(self, txs) -> Mempool:
        mp = Mempool(self.t)
        for tx in txs:
            assert mp.admit(tx, T0) is None
        return mp

    def test_the_intersection_needs_no_search(self):
        """MEMPOOL.md §3.1, the finding that retires the ECMH powerset.

        Two nodes cutting from the same deterministic order produce batches that differ ONLY by the
        transactions each actually holds — one is a subsequence of the other, not a divergent
        selection. So the largest intersection is obtained by construction, and no node ever has to
        enumerate 2^n subsets to find it."""
        txs = [write(self.mgr, f"k{i}", b"v", T0 + i) for i in range(6)]
        full = self._pool(txs)
        partial = self._pool([tx for i, tx in enumerate(txs) if i != 3])  # missing one
        b = self.t.bucket(T0)

        a_batch = full.propose(b, self.store, self.mgmt)
        b_batch = partial.propose(b, self.store, self.mgmt)

        a_ids = [tx_id(t) for t in a_batch]
        b_ids = [tx_id(t) for t in b_batch]
        self.assertEqual(len(a_ids), 6)
        self.assertEqual(len(b_ids), 5)
        self.assertEqual([i for i in a_ids if i in set(b_ids)], b_ids)  # subsequence, order intact

    def test_order_is_deterministic_across_insertion_order(self):
        """Same set, different arrival order, identical batch — else two nodes with the same
        holdings would still propose differently."""
        txs = [write(self.mgr, f"k{i}", b"v", T0 + (i % 3)) for i in range(6)]
        b = self.t.bucket(T0)
        first = self._pool(txs).propose(b, self.store, self.mgmt)
        second = self._pool(list(reversed(txs))).propose(b, self.store, self.mgmt)
        self.assertEqual([tx_id(t) for t in first], [tx_id(t) for t in second])

    def test_proposal_is_screened_so_it_cannot_offer_the_unlandable(self):
        """`settle.would_apply` is the same evaluator the store and the client use, so a batch never
        contains a transaction that would be rejected on arrival."""
        stranger = crypto.Keypair.generate()  # never granted anything
        good = write(self.mgr, "ok", b"v", T0)
        bad = write(stranger, "nope", b"v", T0)
        mp = self._pool([good, bad])
        batch = mp.propose(self.t.bucket(T0), self.store, self.mgmt)
        self.assertEqual([tx_id(t) for t in batch], [tx_id(good)])

    def test_backward_clock_step_cannot_equivocate(self):
        """§8's realistic fault: NTP correction or VM resume moves the clock back tens of seconds. A
        second batch for a bucket already proposed for is exactly what §4.1 convicts on, so it must
        be impossible rather than merely punished."""
        mp = self._pool([write(self.mgr, "a", b"v", T0)])
        b = self.t.bucket(T0)
        self.assertTrue(mp.may_propose(b))
        mp.mark_proposed(b)
        self.assertFalse(mp.may_propose(b))  # same bucket again
        self.assertFalse(mp.may_propose(b - 30))  # clock stepped back 30s
        self.assertTrue(mp.may_propose(b + 1))  # forward is fine

    def test_accumulator_detects_difference_in_32_bytes(self):
        """The O(1) short-circuit that makes gossip cheap: equal accumulators mean equal sets. It
        deliberately does not RECOVER the difference — that needs a sketch, which §3.2 declines."""
        txs = [write(self.mgr, f"k{i}", b"v", T0 + i) for i in range(4)]
        b = self.t.bucket(T0)
        same = self._pool(list(reversed(txs))).accumulator(b)
        self.assertEqual(self._pool(txs).accumulator(b), same)
        self.assertEqual(len(same), crypto.ACC_SIZE)
        self.assertNotEqual(self._pool(txs[:3]).accumulator(b), same)


class TestReentry(unittest.TestCase):
    def setUp(self):
        self.kp = crypto.Keypair.generate()
        self.t = Tunables(delta=1_000, w_admit=30_000)  # evict_after derives from w_valid
        self.mp = Mempool(self.t)

    def test_reject_reasons_are_not_equally_final(self):
        """MEMPOOL.md §5. "Cannot be applied given settled state" reads as "drop it", but only a bad
        signature is permanently dead — `guard` and `authority` both become satisfiable again, so
        evicting on the verdict would discard transactions that are merely EARLY."""
        guarded = write(self.kp, "g", b"v", T0)
        unauthorised = write(self.kp, "a", b"v", T0)
        forged = write(self.kp, "s", b"v", T0)
        for tx in (guarded, unauthorised, forged):
            self.assertIsNone(self.mp.admit(tx, T0))

        dropped = self.mp.reenter(
            (
                (guarded, settle.Verdict(settle.Reason.GUARD, 0)),
                (unauthorised, settle.Verdict(settle.Reason.AUTHORITY, 0)),
                (forged, settle.Verdict(settle.Reason.SIGNATURE)),
            ),
            T0,
        )
        self.assertEqual([tx_id(t) for t in dropped], [tx_id(forged)])
        self.assertEqual(len(self.mp), 2)

    def test_a_kept_reject_lands_in_a_current_bucket(self):
        """Re-entry carries forward like admission does, so a reject cannot be parked in a bucket
        that will never be proposed again."""
        tx = write(self.kp, "g", b"v", T0)
        self.mp.admit(tx, T0)
        later = T0 + 10_000
        self.mp.reenter(((tx, settle.Verdict(settle.Reason.GUARD, 0)),), later)
        self.assertEqual(self.mp.buckets(), (self.t.bucket(later),))

    def test_eviction_is_by_age_not_by_verdict(self):
        """Holding a transaction until its guards come true is correct; holding it forever is a
        denial-of-service. Bitcoin's mempool expiry has the same shape."""
        tx = write(self.kp, "g", b"v", T0)
        self.mp.admit(tx, T0)
        self.assertEqual(self.mp.evict(T0 + 30_000), ())  # still young
        gone = self.mp.evict(T0 + 90_000)
        self.assertEqual([tx_id(t) for t in gone], [tx_id(tx)])
        self.assertEqual(len(self.mp), 0)

    def test_age_is_measured_from_arrival_and_survives_reentry(self):
        """Otherwise a transaction bounced through settlement resets its own clock and lives for
        ever — the eviction horizon has to be immune to re-entry."""
        tx = write(self.kp, "g", b"v", T0)
        self.mp.admit(tx, T0)
        for t in range(10_000, 60_000, 10_000):
            self.mp.reenter(((tx, settle.Verdict(settle.Reason.GUARD, 0)),), T0 + t)
        self.assertEqual(len(self.mp), 1)
        self.assertEqual(len(self.mp.evict(T0 + 90_000)), 1)

    def test_retire_forgets_and_then_refuses_as_duplicate(self):
        tx = write(self.kp, "x", b"v", T0)
        self.mp.admit(tx, T0)
        self.mp.retire((tx,))
        self.assertEqual(len(self.mp), 0)
        self.assertEqual(self.mp.buckets(), ())
        self.assertEqual(self.mp.admit(tx, T0), DUPLICATE)


if __name__ == "__main__":
    unittest.main()
