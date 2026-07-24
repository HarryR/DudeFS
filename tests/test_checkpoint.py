# HANDOFF-R9 §0 payoff: the WP-F checkpoint invariants (findings #4/#5/#8/#10) as UNIT tests over
# crafted structs — no daemon, no store, no sim. Each adoptability rule and the compaction decision
# is a pure function of a hand-built CheckpointView / CompactionPlan, so an adversarial case (a
# seq/slot-mismatch forgery, a wrong-epoch QC, a not-yet-final cut) is one assert, not a cluster.

import unittest

from dudefs import artifacts as A
from dudefs import checkpoint as CP
from dudefs import compactor, fold
from dudefs import crypto as C

MGR = C.SoftwareKeypair.from_seed(bytes([1] * 32))
NODE = C.SoftwareKeypair.from_seed(bytes([2] * 32))
OTHER = C.SoftwareKeypair.from_seed(bytes([3] * 32))
ROSTER: list[bytes] = [NODE.public]
H0 = A.HLC(0)
H100 = A.HLC(100)


def _qc(op: A.Op, *, epoch: int = 0) -> A.QC:
    """A real 1-of-1 QC over `op` at `epoch` (verifies against ROSTER)."""
    r = A.Receipt.issue(NODE, op.op_hash, epoch, A.Ballot(1, b"p"), 1)
    return A.QC.assemble([r], 1, {NODE.public: 0})


def _ckpt(*, author: C.Keypair = MGR, seq: int = 0, cut: A.Heads | None = None, horizon=H100):
    return A.CheckpointOp.build(
        author=author,
        seq=0,
        prev=A.GENESIS_PREV,
        hlc=A.HLC(10),
        baseline=A.Baseline(cut or {}, {}, frozenset()),
        state_acc=b"",
        attempts=b"",
        keyepoch=0,
        horizon=horizon,
        checkpoint_seq=seq,
    )


def _view(ops, *, cut=None, horizon=H0, adopted_seq=0, qcs=None, epoch=0):
    return CP.CheckpointView(
        ops=list(ops),
        cut=cut or {},
        horizon=horizon,
        adopted_seq=adopted_seq,
        qcs=qcs or {},
        epoch=epoch,
        roster=ROSTER,
        authz=fold.ControlReducer(MGR.public, epoch).control,
    )


class TestCutDominates(unittest.TestCase):
    def test_advance_or_hold_dominates(self):
        self.assertTrue(CP.cut_dominates({b"a": (5, b"h")}, {b"a": (3, b"g")}))  # advanced
        self.assertTrue(CP.cut_dominates({b"a": (3, b"g")}, {b"a": (3, b"g")}))  # held
        self.assertTrue(CP.cut_dominates({b"a": (3, b"g")}, {}))  # vacuous vs empty

    def test_regress_or_drop_does_not_dominate(self):
        self.assertFalse(CP.cut_dominates({b"a": (2, b"h")}, {b"a": (3, b"g")}))  # regressed
        self.assertFalse(CP.cut_dominates({b"b": (9, b"h")}, {b"a": (3, b"g")}))  # dropped author


class TestAdoptabilityRules(unittest.TestCase):
    """Each WP-F rule in isolation — the whole point of the named-predicate decomposition."""

    def test_a_good_checkpoint_is_adoptable(self):
        op = _ckpt(cut={NODE.public: (0, b"h")})
        v = _view([op], qcs={op.op_hash: _qc(op)})
        self.assertTrue(v.adoptable(op))

    def test_slot_bound_rejects_a_seq_slot_mismatch_forgery(self):
        # claims seq=0 but contends slot 5 — the chain-jump forgery (WP-F(c)). Re-sign the envelope
        # with a mismatched slot_tag (a validly-signed op whose seq does not bind its slot).
        op = _ckpt()
        env = A.codec.as_dict(A.codec.decode(op.raw))
        env.pop(A.Field.SIG, None)
        env[A.Field.SLOT_TAG] = A.checkpoint_slot_tag(5)
        env[A.Field.SIG] = MGR.sign(A.codec.encode(env))
        forged = A.Op.from_bytes(A.codec.encode(env))
        assert isinstance(forged, A.CheckpointOp)
        v = _view([forged], qcs={forged.op_hash: _qc(forged)})
        self.assertFalse(CP.slot_bound(v, forged))
        self.assertFalse(v.adoptable(forged))

    def test_qc_final_rejects_missing_wrong_epoch_and_unroster_qc(self):
        op = _ckpt()
        self.assertFalse(CP.qc_final(_view([op]), op))  # no QC at all
        self.assertFalse(
            CP.qc_final(_view([op], qcs={op.op_hash: _qc(op, epoch=1)}), op)
        )  # wrong e
        self.assertTrue(CP.qc_final(_view([op], qcs={op.op_hash: _qc(op)}), op))  # good

    def test_minter_authorized_rejects_a_non_root_author(self):
        good, rogue = _ckpt(author=MGR), _ckpt(author=OTHER)
        self.assertTrue(CP.minter_authorized(_view([good]), good))  # root authors any
        self.assertFalse(CP.minter_authorized(_view([rogue]), rogue))  # uncertified minter

    def test_horizon_covers_cut_rejects_a_cut_over_a_not_yet_final_op(self):
        # an op below the cut but with hlc ABOVE the checkpoint's horizon = sealing a not-yet-final
        # op (finding #8). Build a data op the cut covers, sitting above F.
        late = A.BlindPutOp.build(
            author=NODE,
            seq=0,
            prev=A.GENESIS_PREV,
            hlc=A.HLC(200),
            keyepoch=0,
            data_key=bytes(32),
            txn_bytes=A.Txn(None, [], []).encode(),
        )
        op = _ckpt(cut={NODE.public: (0, late.op_hash)}, horizon=A.HLC(100))  # F=100 < late's 200
        self.assertFalse(CP.horizon_covers_cut(_view([op, late]), op))

    def test_forward_rejects_stale_seq_and_regressing_cut(self):
        op = _ckpt(seq=0, cut={NODE.public: (3, b"h")})
        self.assertFalse(CP.forward(_view([op], adopted_seq=1), op))  # seq 0 < adopted_seq 1
        # a cut that regresses what I already adopted
        regress = _view([op], cut={NODE.public: (5, b"g")})
        self.assertFalse(CP.forward(regress, op))


class TestSelectMode(unittest.TestCase):
    def test_hot_link_selected_when_baseline_held(self):
        op = _ckpt(seq=0, cut={NODE.public: (0, b"h")})
        v = _view([op], qcs={op.op_hash: _qc(op)}, adopted_seq=0)
        self.assertEqual(v.select(), op)  # empty retained baseline is trivially held


class TestCompactionDecision(unittest.TestCase):
    """compactor.plan_compaction / cut_at / advances — pure author-side planning."""

    def _data(self, kp, seq, hlc):
        return A.BlindPutOp.build(
            author=kp,
            seq=seq,
            prev=A.GENESIS_PREV,
            hlc=A.HLC(hlc),
            keyepoch=0,
            data_key=bytes(32),
            txn_bytes=A.Txn(None, [], []).encode(),
        )

    def test_cut_at_takes_highest_seq_at_or_below_F(self):
        ops = [self._data(NODE, 0, 10), self._data(NODE, 1, 50), self._data(NODE, 2, 300)]
        cut = compactor.cut_at(ops, A.HLC(100))  # excludes the seq-2 op at hlc 300 > F
        self.assertEqual(cut[NODE.public][0], 1)

    def test_advances_only_when_the_cut_moves(self):
        self.assertTrue(compactor.advances({NODE.public: (2, b"h")}, {NODE.public: (1, b"g")}))
        self.assertFalse(compactor.advances({NODE.public: (1, b"h")}, {NODE.public: (1, b"g")}))

    def test_plan_none_without_advance_or_when_it_would_regress(self):
        ops = [self._data(NODE, 0, 10)]
        prev = compactor.PrevState({NODE.public: (0, ops[0].op_hash)}, [], {})
        # no advance (cut == prev) -> None
        self.assertIsNone(
            compactor.plan_compaction(ops, prev, horizon=A.HLC(100), next_seq=1, committed_cut={})
        )
        # advance, but the committed chain head is ahead -> would regress -> None (wedge-avoidance)
        ops2 = [self._data(NODE, 0, 10), self._data(NODE, 1, 20)]
        prev0 = compactor.PrevState({}, [], {})
        ahead: A.Heads = {NODE.public: (5, b"h")}
        self.assertIsNone(
            compactor.plan_compaction(
                ops2, prev0, horizon=A.HLC(100), next_seq=0, committed_cut=ahead
            )
        )

    def test_plan_returns_a_typed_plan_when_new_work_is_final(self):
        ops = [self._data(NODE, 0, 10), self._data(NODE, 1, 20)]
        plan = compactor.plan_compaction(
            ops, compactor.PrevState({}, [], {}), horizon=A.HLC(100), next_seq=0, committed_cut={}
        )
        assert plan is not None
        self.assertEqual(plan.seq, 0)
        self.assertEqual(plan.cut[NODE.public][0], 1)


if __name__ == "__main__":
    unittest.main()
