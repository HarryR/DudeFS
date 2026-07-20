# WP4 — the fumbling-manager suite (RESILIENCE §2.3, the self-inflicted gorilla).
# An honest-but-confused root; global invariants: no silent divergence, ≤1 roster
# activation per epoch (B4), committed data survives OR surfaces as loud QC-vs-
# manifest disclosure. WP4 COMPOSES already-landed mechanisms (WP1.7's fence,
# WP2.2's partitions) — nothing new is implemented here.

import unittest

from dudefs import artifacts as A
from dudefs import crypto as C
from dudefs import quorum as Q
from dudefs.handlers import control as ctl
from dudefs.sim.harness import Sim
from dudefs.transports.memory import Link, NetworkLinks
from tests._builders import World

NOW = 100


def _create(w, ci, key, val):
    return w.cas(
        ci, key, A.VERSION_ABSENT, 0, [[A.Guard.ABSENT, key]], [[A.Mutation.SET, key, val]]
    )


def _recovery_pair(msk, mpub, roster, from_epoch=0):
    """A root-signed recovery pair: a recovery checkpoint + a ROSTER op naming it
    via `recovery` (substitutes for the joint certificate, WP1.7 / NOTES 36a)."""
    ckpt = A.Op.build(
        author_sk=msk,
        author_pub=mpub,
        cls_=A.OpClass.CONTROL,
        seq=0,
        prev=A.GENESIS_PREV,
        hlc=A.HLC(500, 0),
        deps=[],
        authz=b"root",
        keyepoch=0,
        payload=ctl.checkpoint_body({}, b"recover", [], {}, b"", 0, A.HLC(0, 0)),
    )
    rop = A.Op.build(
        author_sk=msk,
        author_pub=mpub,
        cls_=A.OpClass.CONTROL,
        seq=1,
        prev=ckpt.op_hash,
        hlc=A.HLC(501, 0),
        deps=[],
        authz=b"root",
        keyepoch=0,
        payload=ctl.roster_body(from_epoch, roster, {}, recovery=ckpt.op_hash),
    )
    return ckpt, rop


class TestMistakenRecovery(unittest.TestCase):
    """WP4.7: a manager on the MINORITY side of a partition runs recovery while the
    old quorum is alive. The fence trigger (WP1.7) is only composed here — pre-heal
    divergence is bounded to the partition; on heal the old world parks; the
    over-window e=0 commit survives as a QC below the new epoch (loud disclosure)."""

    def test_mistaken_recovery_parks_old_world_on_heal(self):
        net = NetworkLinks(default=Link(base_ms=2, jitter_ms=1))
        sim = Sim(seed=10, n=3, net=net)
        w = World(seed=10, n_clients=1)
        msk, mpub = w.mgr_sk, w.mgr_pub
        MAJ = -2
        sim.partition([0], [1, 2])  # node 0 (confused manager's side) | {1,2} (live quorum)
        net.cut(MAJ, 0)  # the majority client reaches only {1,2}

        # the live majority keeps committing at e=0 — the data the manager wrongly
        # presumes lost (this is what makes the recovery "mistaken").
        op = _create(w, 0, b"k", b"live")
        r = sim.commit(op, src_id=MAJ)
        sim.run()
        self.assertIsInstance(r.outcome, Q.Committed)
        assert isinstance(r.outcome, Q.Committed)
        self.assertEqual(r.outcome.qc.config_epoch, 0)  # committed in the OLD epoch

        # the minority manager runs recovery: a root-signed fence activates e+1 on
        # node 0 only (no joint QC — a quorum is presumed gone).
        ckpt, rop = _recovery_pair(msk, mpub, [sim.roster[0]])
        self.assertTrue(sim._raw[0].acc.on_recovery_fence(rop, ckpt, 1, ckpt.op_hash, mpub))
        # PRE-HEAL: divergence bounded to the partition — only node 0 advanced.
        self.assertEqual([sim._raw[i].acc.epoch for i in range(3)], [1, 0, 0])

        # HEAL: the fence propagates; everyone who SEES it parks the old epoch.
        net.down.clear()
        for i in (1, 2):
            self.assertTrue(sim._raw[i].acc.on_recovery_fence(rop, ckpt, 1, ckpt.op_hash, mpub))
        self.assertEqual([sim._raw[i].acc.epoch for i in range(3)], [1, 1, 1])  # parked

        # old-epoch receipting stops: a fresh accept on a majority node stamps e+1.
        op2 = _create(w, 0, b"k2", b"x")
        assert op2.slot_tag is not None
        rc = sim._raw[1].acc.on_accept(op2.slot_tag, A.Ballot(1, b"z"), op2, NOW)
        assert isinstance(rc, A.Receipt)
        self.assertEqual(rc.config_epoch, 1)

        # OVER-WINDOW disclosure: the e=0 commit SURVIVES (committed data is durable,
        # B2) and its QC verifies at the now-PARKED epoch 0 < active 1 — a
        # contradiction against the recovery manifest, attributable to the recovery op.
        self.assertTrue(r.outcome.qc.verify(sim.roster))
        self.assertLess(r.outcome.qc.config_epoch, sim._raw[1].acc.epoch)

    def test_recovery_fence_is_root_only_under_partition(self):
        # a DELEGATE cannot fiat-activate even while partitioned (WP1.7 root-only,
        # composed): the acceptor refuses a non-root-signed pair, so no split-brain.
        sim = Sim(seed=11, n=3)
        w = World(seed=11, n_clients=0)
        dsk = bytes([123] * 32)
        dpub = C.SIGNER.public(dsk)
        ckpt, rop = _recovery_pair(dsk, dpub, [sim.roster[0]])  # delegate-signed
        self.assertFalse(sim._raw[0].acc.on_recovery_fence(rop, ckpt, 1, ckpt.op_hash, w.mgr_pub))
        self.assertEqual(sim._raw[0].acc.epoch, 0)  # never activated


if __name__ == "__main__":
    unittest.main()
