# WP4 — the fumbling-manager suite (RESILIENCE §2.3, the self-inflicted gorilla).
# An honest-but-confused root; global invariants: no silent divergence, ≤1 roster
# activation per epoch (B4), committed data survives OR surfaces as loud QC-vs-
# manifest disclosure. WP4 COMPOSES already-landed mechanisms (WP1.7's fence,
# WP2.2's partitions) — nothing new is implemented here.

import os
import random
import tempfile
import unittest

from dudefs import artifacts as A
from dudefs import crypto as C
from dudefs import quorum as Q
from dudefs.acceptor import Acceptor, Rejected
from dudefs.handlers import control as ctl
from dudefs.sim.harness import Sim
from dudefs.sim.personas import EquivocatingAcceptor
from dudefs.store import AppendStatus, ChainStore, EvidenceKind
from dudefs.transports.memory import Link, NetworkLinks
from tests._builders import World
from tests._cluster import creation_op

NOW = 100
NSK = bytes([220] * 32)


def _node(path, delta=10_000):
    return Acceptor(NSK, C.SIGNER.public(NSK), ChainStore(path), config_epoch=0, delta_ms=delta)


def _roster(msk, mpub, roster, seq, prev, epoch=0, hlc=100):
    return A.Op.build(
        author_sk=msk,
        author_pub=mpub,
        cls_=A.OpClass.CONTROL,
        seq=seq,
        prev=prev,
        hlc=A.HLC(hlc, 0),
        deps=[],
        authz=b"root",
        keyepoch=0,
        payload=ctl.roster_body(epoch, roster, {}),
        slot_tag=A.roster_slot_tag(epoch),
    )


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

    def test_over_window_commit_mints_lost_commit(self):
        # ruling 41(b): the over-window e=0 commit — below the recovery fence and
        # absent from its (empty) manifest — mints a persistent LOST_COMMIT record,
        # the recovery op's cryptographic receipt of the durability it broke.
        net = NetworkLinks(default=Link(base_ms=2, jitter_ms=1))
        sim = Sim(seed=12, n=3, net=net)
        w = World(seed=12, n_clients=1)
        msk, mpub = w.mgr_sk, w.mgr_pub
        MAJ = -2
        sim.partition([0], [1, 2])
        net.cut(MAJ, 0)
        op = _create(w, 0, b"k", b"live")
        r = sim.commit(op, src_id=MAJ)
        sim.run()
        assert isinstance(r.outcome, Q.Committed)

        # the recovery fence (empty manifest — presumes everything lost) activates e+1
        ckpt, _rop = _recovery_pair(msk, mpub, [sim.roster[0]])
        # an auditor holds the orphaned QC and the recovery fence; it discloses
        store = sim._raw[0].acc.store
        store.put_qc(r.outcome.qc)
        proofs = store.detect_lost_commits(1, ckpt.op_hash, frozenset())  # retained = {}
        self.assertEqual(len(proofs), 1)
        self.assertEqual(proofs[0].qc.op_hash, op.op_hash)
        self.assertTrue(proofs[0].verify(sim.roster, frozenset()))  # genuine, orphaned
        self.assertTrue(any(k == EvidenceKind.LOST_COMMIT for k, _ in store.evidence()))
        self.assertEqual(store.detect_lost_commits(1, ckpt.op_hash, frozenset()), [])  # idempotent

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


class TestFumblingManager(unittest.TestCase):
    """WP4.1/4.3/4.2 — the cheap composition scenarios. Global invariant: ≤1 roster
    activation per epoch (B4); an abandoned flow never half-activates."""

    def test_retry_storm_is_idempotent_one_activation(self):
        # the SAME roster op resubmitted N times, with a crash-restart interleaved,
        # is idempotent: one accepted slot op, one (identical) receipt, one activation.
        w = World(seed=1, n_clients=0)
        rop = _roster(w.mgr_sk, w.mgr_pub, [C.SIGNER.public(NSK)], seq=0, prev=A.GENESIS_PREV)
        assert rop.slot_tag is not None
        b = A.Ballot(1, b"m")
        with tempfile.TemporaryDirectory() as d:
            path = os.path.join(d, "s.db")
            acc = _node(path)
            rs = [acc.on_roster_accept(rop.slot_tag, b, rop, {}, 1, NOW) for _ in range(3)]
            acc.store.close()  # crash mid-storm
            acc2 = _node(path)  # restart; the storm continues
            rs.append(acc2.on_roster_accept(rop.slot_tag, b, rop, {}, 1, NOW))
            self.assertTrue(all(isinstance(r, A.Receipt) for r in rs))
            self.assertEqual(len({r.sig for r in rs if isinstance(r, A.Receipt)}), 1)  # one receipt
            self.assertEqual(acc2.store.get_slot(rop.slot_tag).accepted_op, rop.op_hash)

    def test_double_press_exactly_one_activates_across_crash(self):
        # two DIFFERENT roster ops for one from_epoch (a crashed-and-retried manager
        # with a new plan): the roster slot decides exactly one (B4); the loser can
        # never activate out of e=0, and the decision survives a crash.
        w = World(seed=2, n_clients=0)
        pubX, pubY = C.SIGNER.public(bytes([1] * 32)), C.SIGNER.public(bytes([2] * 32))
        a_op = _roster(w.mgr_sk, w.mgr_pub, [pubX], seq=0, prev=A.GENESIS_PREV)
        b_op = _roster(w.mgr_sk, w.mgr_pub, [pubY], seq=1, prev=a_op.op_hash)  # a new plan
        assert a_op.slot_tag is not None
        tag, b = a_op.slot_tag, A.Ballot(1, b"m")
        with tempfile.TemporaryDirectory() as d:
            path = os.path.join(d, "s.db")
            acc = _node(path)
            self.assertIsInstance(acc.on_roster_accept(tag, b, a_op, {}, 1, NOW), A.Receipt)
            # B at the same (tag, ballot) on a node that accepted A -> guard
            self.assertIsInstance(acc.on_roster_accept(tag, b, b_op, {}, 1, NOW), Rejected)
            acc.store.close()  # crash
            acc2 = _node(path)  # restart: the decision is durable
            p = acc2.on_prepare(tag, A.Ballot(2, b"r"))  # recovery MUST re-propose A
            assert isinstance(p, A.Promise)
            self.assertEqual(p.accepted_op_hash, a_op.op_hash)  # B can never win

    def test_abandoned_flow_never_half_activates(self):
        # a roster op accepted at only a MINORITY before the manager crashes never
        # activates any node — activation needs the joint certificate, not a receipt.
        sim = Sim(seed=3, n=3)
        w = World(seed=3, n_clients=0)
        rop = _roster(w.mgr_sk, w.mgr_pub, [sim.roster[0]], seq=0, prev=A.GENESIS_PREV)
        assert rop.slot_tag is not None
        r = sim._raw[0].acc.on_roster_accept(rop.slot_tag, A.Ballot(1, b"m"), rop, {}, 1, NOW)
        self.assertIsInstance(r, A.Receipt)  # a possession receipt under e+1...
        # ...but NO node advanced its epoch — the abandoned flow half-activated nothing
        self.assertEqual([sim._raw[i].acc.epoch for i in range(3)], [0, 0, 0])


class TestAmnesiacManager(unittest.TestCase):
    """WP4.6: a manager that re-authors its own seq WITHOUT the DESIGN §4 amnesia
    procedure forks; a fresh-seq continuation (the procedure) does not."""

    def test_reused_seq_forks_fresh_seq_does_not(self):
        w = World(seed=41, n_clients=0)
        px, py, pz = (C.SIGNER.public(bytes([k] * 32)) for k in (1, 2, 3))
        o0 = w._mgr_op(ctl.roster_body(0, [px], {}))  # seq 0
        o1 = w._mgr_op(ctl.roster_body(1, [py], {}))  # seq 1 — the amnesia PROCEDURE
        store = ChainStore()
        self.assertTrue(store.append(o0))
        self.assertTrue(store.append(o1))
        self.assertEqual(store.evidence(), [])  # fresh-seq continuation: no fork

        w._mseq, w._mprev = 0, A.GENESIS_PREV  # WITHOUT the procedure: forget + rewind
        o0b = w._mgr_op(ctl.roster_body(0, [pz], {}))  # seq 0 again, different -> FORK
        res = store.append(o0b)
        self.assertEqual(res.status, AppendStatus.FORK)
        assert res.evidence is not None
        self.assertEqual(res.evidence.seq, 0)
        self.assertTrue(res.evidence.verify())


class TestButtonMasher(unittest.TestCase):
    """WP4.8: 'I hit all the buttons without keeping track.' Seeded random chaos —
    partitions × contended commits × an occasional equivocator — with the sim's
    CONTINUOUS invariants (relaxed B1, B3) plus B2 at run-end doing the asserting;
    finishing without a raise IS the proof. Per run: heal converges, and any
    assembled proof is correctly attributed (a double vote to the persona; an
    all-honest run mints nothing)."""

    def test_invariants_hold_under_random_chaos(self):
        for seed in range(15):
            rng = random.Random(seed)
            net = NetworkLinks(default=Link(base_ms=2, jitter_ms=1))
            has_persona = rng.random() < 0.4
            personas: dict[int, type[Acceptor]] = {0: EquivocatingAcceptor} if has_persona else {}
            sim = Sim(seed=seed, n=3, net=net, personas=personas)
            w = World(seed=seed, n_clients=5)
            if rng.random() < 0.4:  # a random partition
                g = [rng.randrange(3)]
                sim.partition(g, [x for x in range(3) if x not in g])
            # contended commits on ONE slot by DISTINCT clients (each a seq-0
            # create — same-client second creates would gap the chain, which the
            # seq-based gossip delta can't heal, an inherent M4 limitation).
            for i in range(rng.randint(1, 4)):
                sim.commit(creation_op(w, i, bytes([i + 1])), round_timeout_ms=50, max_rounds=6)
            sim.run()  # relaxed B1 + B3 continuous, B2 at end: not raising is the proof

            net.down.clear()
            for _ in range(6):
                sim.gossip_round()
            self.assertTrue(sim.converged(), f"seed {seed}: heal did not converge")
            # every assembled double vote is a TRUE accusation against the persona;
            # an all-honest run mints nothing.
            for pf in sim._raw[1].acc.store.detect_double_votes():
                self.assertTrue(pf.verify())
                self.assertEqual(pf.signer, sim.roster[0])
            if not has_persona:
                self.assertEqual(sim.evidence(), [], f"seed {seed}: honest run minted evidence")


if __name__ == "__main__":
    unittest.main()
