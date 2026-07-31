# The angel of monotonicity: peers keep the evidence, and a node cannot un-say what it signed.
#
# A node's own claim about its height is worth nothing on its own — the value is that PEERS hold it,
# so a rollback is a pair of signed statements that contradict each other and travels as evidence
# wherever it is carried.

from __future__ import annotations

import unittest

from ..core import crypto
from ..net.transports import name_of
from ..store import attest, ops, smt
from .cluster import DELTA, T0, WINDOW, Cluster, D


class TestTheAngelDuty(unittest.TestCase):
    """Attestation in a cluster (#monotonicity, #cross-attestation). The point of building this
    against real nodes rather than in isolation is that the keeping is what matters: evidence has
    to end up somewhere other than the culprit."""

    def setUp(self):
        self.c = Cluster()
        self.client = self.c.mgr

    def _write(self, n: int, now: int = T0) -> int:
        for i in range(n):
            tx = ops.writes(ops.Set(D, crypto.h(f"k{i}".encode()), b"v")).sign(self.client, now)
            self.c.submit(self.client, tx, to=i % len(self.c.nodes), now=now)
            self.c.pump(now)
            now += DELTA
            self.c.pump(now)
        return now

    def test_peers_hold_evidence_the_culprit_never_gave_them(self):
        """The whole reason for cross-attestation. Accountability must not depend on a client
        having happened to be watching — the accident this catches is a snapshot restored at 04:00,
        which is precisely when nobody is."""
        now = self._write(3)
        for node in self.c.nodes:
            node.probe(now)
        self.c.pump(now)

        for i, node in enumerate(self.c.nodes):
            heard = {s.by for s in node.store.sightings()}
            peers = {n.me.public for n in self.c.nodes} - {node.me.public}
            self.assertEqual(heard, peers, f"node {i} is keeping nothing about its peers")

    def test_a_rolled_back_node_is_convicted_by_its_peers(self):
        """A restore regresses the height. Nobody prevents it; everyone can prove it afterwards,
        and conviction is terminal for the identity."""
        now = self._write(4)
        victim = self.c.nodes[0]
        for node in self.c.nodes:
            node.probe(now)
        self.c.pump(now)

        rolled_back = attest.Attestation(
            victim.store.attestation(now).seq
            + 5,  # a restored image still moves its counter forward
            1,  # ...but its head went backwards
            crypto.acc_element(b"stale"),
            crypto.acc_element(b"stale"),
        )
        signed = attest.SignedAttestation.make(victim.me, rolled_back)

        watcher = self.c.nodes[1]
        found = watcher.store.witness(signed)
        assert found is not None, "the peer did not notice a regression it had the evidence for"
        self.assertEqual(found.fault, attest.Fault.REGRESSION)
        self.assertEqual(found.culprit, victim.me.public)
        self.assertIn(victim.me.public, watcher.shunned())

    def test_evidence_is_transitive(self):
        """A node that never spoke to the culprit can still convict it: sightings are relayed
        verbatim, so the pair travels even where the link does not."""
        now = self._write(3)
        a, b, c = self.c.nodes
        self.c.board.cut(name_of(a.me.public), name_of(c.me.public))
        self.c.board.cut(name_of(c.me.public), name_of(a.me.public))

        for node in self.c.nodes:
            node.probe(now)
        self.c.pump(now)
        self.assertIsNotNone(b.store.sighting(a.me.public), "B never heard A directly")

        forged = attest.SignedAttestation.make(
            a.me,
            attest.Attestation(
                a.store.attestation(now).seq + 5,
                1,
                crypto.acc_element(b"x"),
                crypto.acc_element(b"x"),
            ),
        )
        b.store.witness(forged)
        # C asks, B answers. Evidence is PULLED like every other body in this system, so it
        # travels on the next probe round rather than being pushed at anyone.
        for node in self.c.nodes:
            node.probe(now + DELTA)
        self.c.pump(now + DELTA)
        self.assertIn(a.me.public, c.shunned(), "C could not convict a node it cannot even reach")

    def test_a_partition_convicts_nobody(self):
        """The failure mode that would eat the cluster. Cut every link and let the nodes run: they
        look stalled to each other, and staleness is not a fault."""
        now = self._write(3)
        for one in self.c.keys:
            for other in self.c.keys:
                if one.public != other.public:
                    self.c.board.cut(name_of(one.public), name_of(other.public))
        for _ in range(3):
            for node in self.c.nodes:
                node.probe(now)
            self.c.pump(now)
            now += DELTA

        for i, node in enumerate(self.c.nodes):
            self.assertEqual(node.shunned(), frozenset(), f"node {i} shunned over a partition")

    def test_an_honest_cluster_convicts_nobody(self):
        """Run the thing normally and nothing is ever proved against anyone. Stated as a test
        because the cost of a false conviction is a permanently dead paid-for node."""
        now = T0
        for _ in range(4):
            now = self._write(2, now)
            for node in self.c.nodes:
                node.probe(now)
            self.c.pump(now)
            now += DELTA

        for i, node in enumerate(self.c.nodes):
            self.assertEqual(node.shunned(), frozenset(), f"node {i} convicted an honest peer")

    def test_a_restart_does_not_convict(self):
        """The interlock, end to end: attest, drop the claim as a crash would, attest again. The
        counter skips and nothing is provable — a gap is free where reuse is fatal."""
        now = self._write(2)
        node, watcher = self.c.nodes[0], self.c.nodes[1]
        watcher.store.witness(node.attestation(now))
        node.store.attestation(now)  # built, never signed: the process died here
        self.assertIsNone(watcher.store.witness(node.attestation(now)))
        self.assertEqual(watcher.shunned(), frozenset())

    def test_a_single_node_can_be_held_to_its_own_root(self):
        """The floor is what a quorum vouches for; the root in an attestation is what ONE node
        stakes its identity on. A client can check a key against the node's current state and, if
        the node lied, keep a signed statement saying so."""
        now = self._write(4)
        node = self.c.nodes[0]
        said = node.attestation(now)
        self.assertTrue(said.verify())

        k0 = crypto.h(b"k0")
        held = node.store.get(D, k0)
        assert held is not None
        self.assertTrue(
            smt.verify(said.claim.root, D, k0, (held.value, held.cred), node.store.prove(D, k0))
        )
        self.assertTrue(
            smt.verify(
                said.claim.root, D, b"nothing-here", None, node.store.prove(D, b"nothing-here")
            )
        )
        self.assertFalse(
            smt.verify(
                said.claim.root,
                D,
                k0,
                (b"not what it holds", held.cred),
                node.store.prove(D, k0),
            )
        )

    def test_the_floor_needs_more_than_one_answer(self):
        """#freshness-needs-many, in a cluster: a lone responder does not answer the freshness
        question at all, and the max is taken over f+1."""
        now = self._write(3)
        node = self.c.nodes[0]
        self.assertIsNone(node.floor(need=4, now=now), "four distinct answers do not exist here")
        for n in self.c.nodes:
            n.probe(now)
        self.c.pump(now)
        self.assertIsNotNone(node.floor(need=3, now=now))

    def test_one_link_is_enough_to_gather_the_whole_cluster(self):
        """THE SINGLE-LINK CLIENT, back in scope without a priest (#freshness-is-gathered).

        A client reaching exactly ONE node still ends up holding f+1 statements, each signed by the
        node that made it. The relay can withhold or replay; it holds no key but its own, so it
        cannot forge, and the client checks every signature itself."""
        now = self._write(3)
        for node in self.c.nodes:
            node.probe(now)
        self.c.pump(now)

        relay = self.c.nodes[0]
        bundle = relay.gathered(now)
        self.assertEqual(len({a.by for a in bundle}), 3, "one link did not reach the cluster")
        for one in bundle:
            self.assertTrue(one.verify(), "a relayed statement lost its own signature")
        self.assertIsNotNone(
            attest.attested_floor(bundle, 3, now, WINDOW, roster=list(relay.roster()))
        )

    def test_a_starved_client_sees_that_it_is_starved(self):
        """The gain, stated as the failure it prevents. A relay that goes quiet cannot make a
        client believe it is current -- the bundle it holds ages in plain sight."""
        now = self._write(3)
        for node in self.c.nodes:
            node.probe(now)
        self.c.pump(now)
        relay = self.c.nodes[0]
        bundle = relay.gathered(now)

        much_later = now + WINDOW * 10
        self.assertIsNone(
            attest.attested_floor(bundle, 3, much_later, WINDOW, roster=list(relay.roster()))
        )
        self.assertIsNone(attest.staleness(bundle, much_later, WINDOW))
        self.assertEqual(attest.staleness(bundle, now + 5_000, WINDOW), 5_000)

    def test_a_node_reports_how_long_since_it_heard_from_anyone(self):
        """Peers only. A node's own statement carries the clock it is asking about, so counting it
        would report zero forever and measure nothing."""
        now = self._write(2)
        node = self.c.nodes[0]
        # Nobody called `probe` here: `tick` does it on its own cadence, which is what keeps the
        # duty from being machinery that only ever runs because a test asked it to.
        self.assertIsNotNone(node.staleness(now), "the probe cadence never fired")

        node.probe(now)
        self.c.pump(now)
        self.assertEqual(node.staleness(now), 0)
        self.assertEqual(node.staleness(now + 20_000), 20_000)
        self.assertIsNone(node.staleness(now + WINDOW * 10), "an old view still read as fresh")

    def test_a_shunned_node_cannot_make_up_the_quorum_it_is_checked_against(self):
        """Shunned keys are dropped BEFORE counting, not after — otherwise a convicted node would
        still be one of the f+1 answers that are supposed to check it."""
        now = self._write(3)
        node, victim = self.c.nodes[0], self.c.nodes[1]
        for n in self.c.nodes:
            n.probe(now)
        self.c.pump(now)
        self.assertIsNotNone(node.floor(need=3, now=now))

        node.store.witness(
            attest.SignedAttestation.make(
                victim.me,
                attest.Attestation(999, 0, crypto.acc_element(b"x"), crypto.acc_element(b"x")),
            )
        )
        self.assertIn(victim.me.public, node.shunned())
        self.assertIsNone(node.floor(need=3, now=now), "a convicted node still counted toward f+1")

    def test_the_roster_is_untouched_by_shunning(self):
        """A local read policy. Shunning must not thin the quorum — a heavily-shunned cluster
        stalls, which is the safe direction, rather than proceeding on fewer signatures."""
        self._write(2)
        node, victim = self.c.nodes[0], self.c.nodes[1]
        before = node.roster()
        node.store.witness(
            attest.SignedAttestation.make(
                victim.me,
                attest.Attestation(999, 0, crypto.acc_element(b"x"), crypto.acc_element(b"x")),
            )
        )
        self.assertIn(victim.me.public, node.shunned())
        self.assertEqual(node.roster(), before, "shunning changed the roster")
        self.assertIn(victim.me.public, node.roster())


if __name__ == "__main__":
    unittest.main()
