# M3 end-to-end (IMPLEMENTATION §6): CAS at n=3/5 over the fault-injecting
# transport, with the harness asserting the invariants that hold continuously —
# rev 5 cross-ballot B1 (at most ONE op ever decided per slot), B2 durability,
# B3 floor monotonicity. Seeds 5 (n=3) and 11 (n=5) are the two fast-path
# collision cases that minted two QCs before rev 5 dropped the fast path; they
# are kept as regression tests asserting exactly one decided op. Names carry the
# FORMAL hypothesis ids; every run is a pure function of its seed (replayable).

import unittest

from dudefs import fold
from dudefs import quorum as Q
from dudefs.sim.harness import Sim
from dudefs.transports.memory import Faults
from tests._builders import World
from tests._cluster import creation_op

CHAOS = Faults(loss=0.25, dup=0.2, delay_lo=1, delay_hi=6)


def _applied_winner(sim: Sim, w: World, slot: bytes):
    """Fold every op that got a QC for `slot` (with its authorizing control
    chain); return (applied_op_hashes, foldresult). The committed set is exactly
    what a client would fold — so this is the real CAS-success verdict."""
    decided = [op for h in sim.decided_ops(slot) if (op := sim.get_op(h)) is not None]
    r = fold.fold([*w.all_control(), *decided], w.keyring, w.genesis)
    applied = [h for h, v in r.verdicts.items() if v is fold.Verdict.APPLIED]
    return applied, r


class TestHappyPath(unittest.TestCase):
    def test_B1_single_cas_one_rtt(self):
        sim = Sim(seed=1, n=3)
        w = World(seed=1, n_clients=1)
        op = creation_op(w, 0, b"v")
        assert op.slot_tag is not None
        r = sim.commit(op)
        sim.run()
        self.assertIsInstance(r.outcome, Q.Committed)
        assert isinstance(r.outcome, Q.Committed)
        self.assertTrue(r.outcome.qc.verify(sim.roster))
        self.assertEqual(sim.decided_ops(op.slot_tag), {op.op_hash})  # uncontended: one QC
        self.assertTrue(sim.trace)  # transitions traced from day one


class TestContention(unittest.TestCase):
    def test_B1_two_clients_one_slot_single_decree(self):
        # Regression: seed 5 / n=3 minted two QCs under the old fast path. rev 5
        # (two-phase only) decides exactly one op; the loser learns the winner.
        sim = Sim(seed=5, n=3, faults=CHAOS)
        w = World(seed=5, n_clients=2)
        a = creation_op(w, 0, b"A")
        b = creation_op(w, 1, b"B")
        assert a.slot_tag is not None
        self.assertEqual(a.slot_tag, b.slot_tag)  # true contention on one slot
        ra, rb = sim.commit(a), sim.commit(b)
        sim.run()
        # LIVENESS (NOTES item 23, resolved): both duelers terminate — randomized
        # backoff + a round timeout keep a loser from wedging under loss.
        self.assertTrue(ra.done and rb.done)
        # SAFETY (the fast-path regression): exactly one op is ever decided for
        # the slot, cross-ballot, and it folds `applied`.
        self.assertEqual(len(sim.decided_ops(a.slot_tag)), 1)
        decided = next(iter(sim.decided_ops(a.slot_tag)))
        for o in (ra.outcome, rb.outcome):  # any client that decided agrees
            if isinstance(o, Q.LostSlot):
                self.assertEqual(o.winner, decided)
            if isinstance(o, Q.Committed):
                self.assertEqual(o.qc.op_hash, decided)
        applied, r = _applied_winner(sim, w, a.slot_tag)
        self.assertEqual(applied, [decided])
        self.assertEqual(r.state.get(b"k"), b"A" if decided == a.op_hash else b"B")

    def test_B1_contention_always_terminates_single_decree(self):
        # NOTES item 23: the dueling-proposer liveness fix (backoff + round
        # timeout) must hold across seeds, not just seed 5. Every scenario:
        # both clients terminate, and at most one op is ever decided.
        for seed in range(20):
            for n in (3, 5):
                sim = Sim(seed=seed, n=n, faults=CHAOS)
                w = World(seed=seed, n_clients=2)
                a, b = creation_op(w, 0, b"A"), creation_op(w, 1, b"B")
                ra, rb = sim.commit(a), sim.commit(b)
                sim.run()
                assert a.slot_tag is not None
                self.assertTrue(ra.done and rb.done, f"seed={seed} n={n}: a dueler wedged")
                self.assertLessEqual(len(sim.decided_ops(a.slot_tag)), 1, f"seed={seed} n={n}")


class TestSplitVoteRegression(unittest.TestCase):
    def test_B1_split_vote_recovery_converges_n5(self):
        # Two regressions in one: (1) the rev-1 deadlock — 3 proposers contend one
        # slot at n=5, recovery ballots MUST converge/terminate, never wedge; and
        # (2) the rev-5 fast-path collision — seed 11 / n=5 minted two QCs before
        # the fast path was dropped. Now exactly one op decides.
        sim = Sim(seed=11, n=5, faults=CHAOS)
        w = World(seed=11, n_clients=3)
        ops = [creation_op(w, i, bytes([65 + i])) for i in range(3)]
        slot = ops[0].slot_tag
        assert slot is not None
        runners = [sim.commit(op) for op in ops]
        sim.run()
        self.assertTrue(all(r.done for r in runners), "recovery wedged — B1 liveness")
        self.assertEqual(len(sim.decided_ops(slot)), 1)  # B1: exactly one decided
        decided = next(iter(sim.decided_ops(slot)))
        self.assertIn(decided, {op.op_hash for op in ops})
        applied, _ = _applied_winner(sim, w, slot)
        self.assertEqual(applied, [decided])


class TestFinalityAndVerdict(unittest.TestCase):
    def test_B3_finality_then_applied_verdict(self):
        # δ=5 so floors pass the op's small hlc quickly; clean link keeps the
        # SUBMIT inside the skew window.
        sim = Sim(seed=2, n=3, delta=5)
        w = World(seed=2, n_clients=1)
        op = creation_op(w, 0, b"v")
        assert op.slot_tag is not None
        rc = sim.commit(op)
        sim.run()
        self.assertIsInstance(rc.outcome, Q.Committed)

        rf = sim.finalize(op.hlc)
        sim.run()
        self.assertIsInstance(rf.outcome, Q.Final)
        assert isinstance(rf.outcome, Q.Final)
        self.assertLessEqual(op.hlc, rf.outcome.frontier)

        # verdict correctness: the finalized CAS folds `applied`, key holds value.
        applied, r = _applied_winner(sim, w, op.slot_tag)
        self.assertEqual(applied, [op.op_hash])
        self.assertEqual(r.verdicts[op.op_hash], fold.Verdict.APPLIED)
        self.assertEqual(r.state.get(b"k"), b"v")


if __name__ == "__main__":
    unittest.main()
