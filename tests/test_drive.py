# HANDOFF-R9 §1 — the StepDriver proof. The successor to `_harness.Sim`, driving the
# REAL Commit/Finalize machines over REAL Acceptors with NO transport retransmit: a
# lost message is recovered ONLY by the machine's round-timeout escalation (quorum.py
# :279), exactly as production `client._drive`. These are the cases most sensitive to
# that removal — single-decree under loss+dup+reorder, and dueling-proposer termination
# across seeds. If escalation alone drives them to a commit, the driver is faithful; a
# wedge here would be the §6.3 finding (add retransmit to the PRODUCT, never the harness).

import unittest

from dudefs import artifacts as A
from dudefs import fold
from dudefs import quorum as Q
from dudefs.transports.memory import Faults
from tests._builders import World
from tests._cluster import creation_op
from tests._drive import StepDriver

CHAOS = Faults(loss=0.25, dup=0.2, delay_lo=1, delay_hi=6)


def _applied_winner(drv: StepDriver, w: World, slot: bytes):
    """Fold every op that got a QC for `slot` (with its authorizing control chain);
    return (applied_op_hashes, foldresult) — the real CAS-success verdict."""
    decided = [op for h in drv.decided_ops(slot) if (op := drv.get_op(h)) is not None]
    r = fold.fold([*w.all_control(), *decided], w.keyring, w.genesis)
    applied = [h for h, v in r.verdicts.items() if v is fold.Verdict.APPLIED]
    return applied, r


class TestStepDriverProof(unittest.TestCase):
    def test_happy_path_single_cas_commits(self):
        drv = StepDriver(seed=1, n=3)
        w = World(seed=1, n_clients=1)
        op = creation_op(w, 0, b"v")
        assert isinstance(op, A.Slotted)
        p = drv.commit(op)
        drv.run()
        self.assertIsInstance(p.outcome, Q.Committed)
        assert isinstance(p.outcome, Q.Committed)
        self.assertTrue(p.outcome.qc.verify(drv.roster))
        self.assertEqual(drv.decided_ops(op.slot_tag), {op.op_hash})  # uncontended: one QC
        self.assertTrue(drv.trace)  # transitions traced from day one

    def test_contention_under_chaos_single_decree_via_escalation(self):
        # Two clients duel one slot under loss+dup+reorder, driven ONLY by the machine's
        # escalation (no retransmit). Both must terminate and exactly one op decides —
        # the proof that escalation alone recovers loss for a real commit.
        drv = StepDriver(seed=5, n=3, faults=CHAOS)
        w = World(seed=5, n_clients=2)
        a = creation_op(w, 0, b"A")
        b = creation_op(w, 1, b"B")
        assert isinstance(a, A.Slotted) and isinstance(b, A.Slotted)
        self.assertEqual(a.slot_tag, b.slot_tag)  # true contention on one slot
        ra, rb = drv.commit(a), drv.commit(b)
        drv.run()
        self.assertTrue(ra.done and rb.done, "a dueler wedged WITHOUT retransmit — §6.3 finding")
        self.assertEqual(len(drv.decided_ops(a.slot_tag)), 1)
        decided = next(iter(drv.decided_ops(a.slot_tag)))
        for o in (ra.outcome, rb.outcome):
            if isinstance(o, Q.LostSlot):
                self.assertEqual(o.winner, decided)
            if isinstance(o, Q.Committed):
                self.assertEqual(o.qc.op_hash, decided)
        applied, r = _applied_winner(drv, w, a.slot_tag)
        self.assertEqual(applied, [decided])

    def test_contention_terminates_single_decree_across_seeds(self):
        # The dueling-proposer liveness fix (backoff + round timeout) must hold across
        # seeds WITHOUT the sim's retransmit crutch. Every scenario: both clients
        # terminate, and at most one op is ever decided.
        for seed in range(20):
            for n in (3, 5):
                drv = StepDriver(seed=seed, n=n, faults=CHAOS)
                w = World(seed=seed, n_clients=2)
                a, b = creation_op(w, 0, b"A"), creation_op(w, 1, b"B")
                ra, rb = drv.commit(a), drv.commit(b)
                drv.run()
                assert isinstance(a, A.Slotted)
                self.assertTrue(ra.done and rb.done, f"seed={seed} n={n}: a dueler wedged")
                self.assertLessEqual(len(drv.decided_ops(a.slot_tag)), 1, f"seed={seed} n={n}")


if __name__ == "__main__":
    unittest.main()
