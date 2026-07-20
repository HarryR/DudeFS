# WP3 — adversarial node personas (IMPLEMENTATION §6.4 / RESILIENCE §3). Each
# persona is a misbehaving sim node; the test asserts BOTH containment (honest
# state unaffected) AND evidence (the violation mints a portable proof — B6
# becomes an assertion). TEE profile (NOTES 35): node personas are the priority.

import unittest

from dudefs import artifacts as A
from dudefs import fold, gossip
from dudefs.sim.harness import Sim
from dudefs.sim.personas import EquivocatingAcceptor
from dudefs.store import EvidenceKind
from tests._builders import World
from tests._cluster import creation_op

NOW = 100


class TestEquivocator(unittest.TestCase):
    """WP3.1: a node that signs two ops at one (tag, ballot). Its own two receipts
    are a portable DOUBLE_VOTE proof; honest state collapses the duplicates."""

    def test_double_vote_mints_evidence_and_state_is_contained(self):
        sim = Sim(seed=1, n=3, personas={0: EquivocatingAcceptor})
        w = World(seed=1, n_clients=2)
        a = creation_op(w, 0, b"A")  # key k
        b = creation_op(w, 1, b"B")  # key k -> SAME slot as a
        assert a.slot_tag is not None
        self.assertEqual(a.slot_tag, b.slot_tag)
        tag, ballot = a.slot_tag, A.Ballot(1, b"x")

        # the equivocator signs BOTH at one ballot (an honest node would refuse b)
        ra = sim.nodes[0].accept(tag, ballot, a)
        rb = sim.nodes[0].accept(tag, ballot, b)
        self.assertIsInstance(ra, A.Receipt)
        self.assertIsInstance(rb, A.Receipt)

        # a third party (honest node 1) gossips in the equivocator's ops+receipts
        # and ASSEMBLES the proof (B6): a portable, self-verifying DOUBLE_VOTE.
        gossip.merge(sim._raw[1].acc.store, sim._raw[0].acc.store)
        proofs = sim._raw[1].acc.store.detect_double_votes()
        self.assertEqual(len(proofs), 1)
        self.assertTrue(proofs[0].verify())
        self.assertEqual(proofs[0].signer, sim.roster[0])  # attributed to the equivocator
        minted = sim._raw[1].acc.store.evidence()
        self.assertTrue(any(k == EvidenceKind.DOUBLE_VOTE for k, _ in minted))

        # detection is idempotent — re-running mints nothing new
        self.assertEqual(sim._raw[1].acc.store.detect_double_votes(), [])

        # CONTAINMENT: a single equivocator never reached a quorum for either op
        # (B1 at the quorum level never fired), and the fold collapses the double
        # vote to exactly ONE winner per slot — honest state is unaffected.
        self.assertEqual(sim.decided_ops(tag), set())
        r = fold.fold([*w.all_control(), a, b], w.keyring, w.genesis)
        self.assertIn(r.state.get(b"k"), (b"A", b"B"))  # one value, never both

    def test_equivocator_alone_does_not_trip_quorum_b1(self):
        # the honest B1 continuous check (quorum-level) must NOT fire for a lone
        # equivocator: it holds only its own two receipts, never a quorum's.
        sim = Sim(seed=2, n=3, personas={1: EquivocatingAcceptor})
        w = World(seed=2, n_clients=2)
        a, b = creation_op(w, 0, b"A"), creation_op(w, 1, b"B")
        assert a.slot_tag is not None
        ballot = A.Ballot(1, b"y")
        sim.nodes[1].accept(a.slot_tag, ballot, a)
        sim.nodes[1].accept(a.slot_tag, ballot, b)  # would raise if B1 tripped
        self.assertEqual(sim.decided_ops(a.slot_tag), set())


if __name__ == "__main__":
    unittest.main()
