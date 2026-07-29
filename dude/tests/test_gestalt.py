# The gestalt: every layer, joined, in one process.
#
# Each part below has its own tests and passes them in isolation. THIS file exists to answer the
# different question — whether isolation was the right decomposition — by making a transaction go
# the whole way: client -> envelope -> seal -> transport -> postman -> mempool -> propose ->
# quorum -> settle -> log, on three nodes at once.
#
# No sockets, no threads, no sleeping. `now` is an integer the test advances, so a whole cluster's
# round is deterministic and a partition is a value.

from __future__ import annotations

import unittest

from ..core import crypto
from ..net import Verb
from ..net.envelope import Envelope, Frame, seal
from ..net.transports import InProc, Switchboard, address_of, name_of
from ..node import HANDLED, REPLIES, UNIMPLEMENTED, Node
from ..store import Store, attest, ops, smt
from ..store.management import Management, Role
from ..tunables import DEFAULT

WINDOW = DEFAULT.attest.fresh_within

D = ops.STORE_DATA
M = ops.STORE_MANAGEMENT
T0 = 1_700_000_000_000
DELTA = DEFAULT.mempool.delta


class Cluster:
    """Three nodes and a switchboard. Deliberately not a fixture helper with options — a cluster you
    can configure is a cluster whose test failures need debugging first."""

    def __init__(self, size: int = 3):
        self.board = Switchboard()
        self.mgr = crypto.Keypair.generate()
        self.keys = [crypto.Keypair.generate() for _ in range(size)]
        self.nodes: list[Node] = []

        # One genesis log, replayed into each node's store, so every node starts from the SAME
        # roster and the same manager grant — membership is log state, not configuration.
        genesis = self._genesis()
        for kp in self.keys:
            store = Store()
            # The anchor: the manager's own grant has to precede the authority that checks it.
            store.apply(genesis, auth=None)
            node = Node(kp, store)
            self.board.bind(name_of(kp.public))
            self.nodes.append(node)
        for node in self.nodes:
            for other in self.keys:
                if other.public != node.me.public:
                    node.connect(other.public, InProc(name_of(node.me.public), self.board))

    def _genesis(self) -> tuple[ops.SignedTransaction, ...]:
        mgmt = Management(Store())
        tx = mgmt.authorise(
            self.mgr.public,
            Role.MANAGER,
            frozenset({M, D}),
            frozenset(),
            self.mgr.prove_possession(),
        )
        for kp in self.keys:
            tx = tx + mgmt.authorise(
                kp.public, Role.NODE, frozenset({D}), frozenset(), kp.prove_possession()
            )
            tx = tx + mgmt.add_node(kp.public, (address_of(kp.public).encode(),))
        return (tx.sign(self.mgr, T0),)

    def pump(self, now: int, rounds: int = 6) -> None:
        """Advance every node, then deliver everything in flight, `rounds` times.

        Delivery is explicit rather than a side effect of sending: the switchboard queues, so
        nothing recurses and the call stack never becomes the scheduler."""
        for _ in range(rounds):
            for node in self.nodes:
                node.tick(now)
            for node in self.nodes:
                for frame in self.board.drain(name_of(node.me.public)):
                    node.receive(frame, now)

    def submit(self, client: crypto.Keypair, tx: ops.SignedTransaction, to: int, now: int) -> None:
        """A client hands a transaction to ONE node — the whole point of the protocol being that it
        needs a link to one node, not to all of them."""
        node = self.nodes[to]
        env = Envelope(node.me.public, Verb.SUBMIT, b"c" * 16, tx.raw).sign(client, now)
        node.receive(seal(env), now)


class TestGestalt(unittest.TestCase):
    def setUp(self):
        self.c = Cluster()
        self.client = self.c.mgr  # the manager is already authorised to write the data store

    def test_one_transaction_reaches_every_log(self):
        """The whole system, end to end. Submitted to node 0 only; settled on all three."""
        key = crypto.h(b"hello")
        tx = ops.writes(ops.Set(D, key, b"world")).sign(self.client, T0)

        self.c.submit(self.client, tx, to=0, now=T0)
        self.c.pump(T0)  # disseminate within the bucket
        self.c.pump(T0 + DELTA)  # the bucket closes: propose, endorse, settle

        for i, node in enumerate(self.c.nodes):
            got = node.store.get(D, key)
            assert got is not None, f"node {i} did not settle it"
            self.assertEqual(got.value, b"world", f"node {i} settled the wrong value")

    def test_every_node_settles_the_same_log(self):
        """Not merely "all have the value" — the same operations at the same indices, which is what
        the accumulator is for. Two nodes agreeing on a value while disagreeing on history is the
        failure this catches and a value check does not."""
        for n in range(3):
            tx = ops.writes(ops.Set(D, crypto.h(f"k{n}".encode()), f"v{n}".encode())).sign(
                self.client, T0 + n
            )
            self.c.submit(self.client, tx, to=n, now=T0)
        self.c.pump(T0)
        self.c.pump(T0 + DELTA)

        accs = {node.store.accumulator() for node in self.c.nodes}
        heads = {node.store.head() for node in self.c.nodes}
        self.assertEqual(len(accs), 1, "nodes disagree on state")
        self.assertEqual(len(heads), 1, "nodes disagree on log length")

    def test_a_partitioned_node_still_settles_through_the_others(self):
        """Node 2 cannot hear node 0 directly. It must still learn the transaction, because the
        client needs a link to ONE node and the rest is the cluster's problem."""
        a, c = name_of(self.c.keys[0].public), name_of(self.c.keys[2].public)
        self.c.board.cut(a, c)
        self.c.board.cut(c, a)

        key = crypto.h(b"partitioned")
        tx = ops.writes(ops.Set(D, key, b"relayed")).sign(self.client, T0)
        self.c.submit(self.client, tx, to=0, now=T0)
        self.c.pump(T0)
        self.c.pump(T0 + DELTA)

        got = self.c.nodes[2].store.get(D, key)
        self.assertIsNotNone(got, "the partitioned node never learned it")

    def test_an_unauthorised_client_is_refused_everywhere(self):
        """Authority is log state, so a stranger is refused by every node without any of them
        conferring about it."""
        stranger = crypto.Keypair.generate()
        key = crypto.h(b"nope")
        tx = ops.writes(ops.Set(D, key, b"x")).sign(stranger, T0)
        self.c.submit(stranger, tx, to=0, now=T0)
        self.c.pump(T0)
        self.c.pump(T0 + DELTA)

        for i, node in enumerate(self.c.nodes):
            self.assertIsNone(node.store.get(D, key), f"node {i} settled an unauthorised write")

    def test_garbage_costs_a_frame_and_nothing_else(self):
        """The crash-only boundary: hostile bytes are an expected outcome at a decode boundary, so
        a peer sending rubbish loses its frame while the node keeps serving."""
        node = self.c.nodes[0]
        junk = Frame(crypto.screen_tag(node.me.public, b"junk"), crypto.SealedBlob(b"junk"))
        node.receive(junk, T0)  # must not raise

        key = crypto.h(b"after-junk")
        tx = ops.writes(ops.Set(D, key, b"still-alive")).sign(self.client, T0)
        self.c.submit(self.client, tx, to=0, now=T0)
        self.c.pump(T0)
        self.c.pump(T0 + DELTA)
        self.assertIsNotNone(node.store.get(D, key), "the node stopped working after junk")


class TestVerbCoverage(unittest.TestCase):
    """What the node does and does not answer, pinned.

    A test rather than a comment because the interesting property is that the set does not drift:
    add a `Verb` and it lands in `UNIMPLEMENTED` and this fails, instead of falling through a
    default branch and being discovered when a peer sends it."""

    def test_every_verb_is_accounted_for(self):
        self.assertEqual(HANDLED | REPLIES | UNIMPLEMENTED, frozenset(Verb))
        self.assertFalse(HANDLED & REPLIES)

    def test_the_unimplemented_set_is_exactly_gossip_and_sync(self):
        """Two clusters, and both are known work rather than open questions:

        * `ANNOUNCE` / `FETCH` — MEMPOOL.md §3's flood-announce-pull-bodies dissemination. Today a
          transaction spreads by re-flooding the whole `SUBMIT`, which works and does not scale.
        * `PULL` / `ENTRIES` — SPEC §8 log transfer, which is what BOOTSTRAP needs: a joining node
          holds the manager key and one address, and learns the log from it. `FRONTIER` was the
          third of these and is now built, because the attestation duty needed exactly its
          question — "where are you now" (#cross-attestation)."""
        self.assertEqual(
            UNIMPLEMENTED,
            {Verb.ANNOUNCE, Verb.FETCH, Verb.PULL, Verb.ENTRIES},
        )

    def test_an_unimplemented_verb_is_ignored_not_fatal(self):
        """A peer sending a verb we have not built must cost its message and nothing more."""
        node, other = self.c.nodes[0], self.c.nodes[1]
        env = Envelope(node.me.public, Verb.FETCH, b"z" * 16).sign(other.me, T0)
        node.receive(seal(env), T0)  # must not raise

        key = crypto.h(b"after-unimplemented")
        tx = ops.writes(ops.Set(D, key, b"fine")).sign(self.client, T0)
        self.c.submit(self.client, tx, to=0, now=T0)
        self.c.pump(T0)
        self.c.pump(T0 + DELTA)
        self.assertIsNotNone(node.store.get(D, key))

    def setUp(self):
        self.c = Cluster()
        self.client = self.c.mgr


if __name__ == "__main__":
    unittest.main()


class TestClusterCollection(unittest.TestCase):
    """Collection, in a cluster. Everything above was end-to-end but never touched a compaction
    path; `Store.collect` was only ever unit-tested alone. This is the first time nodes have to
    AGREE that a segment may be forgotten."""

    WIDTH = 8

    def setUp(self):
        self.c = Cluster()
        self.client = self.c.mgr
        for node in self.c.nodes:
            # Narrow segments so a handful of writes ages one out. Width has to exceed the number
            # of stragglers migrated in one go, or migration -- which writes at the HEAD -- lands
            # part of its own output back inside the segment it is draining.
            node.store.SEGMENT_WIDTH = self.WIDTH

    def _churn(self, n: int) -> int:
        """Overwrite one key repeatedly, so early entries are entirely superseded. Returns `now`.

        A settled bucket will not reopen, so each write needs its own bucket -- which is also the
        realistic shape: this is a register rewritten over time, not a burst."""
        now = T0
        for i in range(n):
            tx = ops.writes(ops.Set(D, crypto.h(b"hot"), f"v{i}".encode())).sign(self.client, now)
            self.c.submit(self.client, tx, to=i % len(self.c.nodes), now=now)
            self.c.pump(now)
            now += DELTA
            self.c.pump(now)
        return now

    def _drain(self, seg: int, now: int) -> None:
        """Every node migrates the segment's stragglers forward for itself. Same values, so
        `A_state` is unchanged -- which is exactly why the nodes still agree afterwards."""
        for node in self.c.nodes:
            node.store.migrate(seg, node.me, now)

    def test_every_node_collects_and_they_stay_identical(self):
        """The property the design rests on: a segment is forgotten by all three, and `A_state`
        still agrees afterwards. Collection must lose history without losing state."""
        now = self._churn(12)
        self._drain(0, now)
        before = {n.store.accumulator() for n in self.c.nodes}

        for node in self.c.nodes:
            self.assertEqual(node.maybe_collect(now), 0, "every node found segment 0 collectable")
        self.c.pump(now)

        for i, node in enumerate(self.c.nodes):
            self.assertNotIn(0, node.store.segments(), f"node {i} did not collect")
        self.assertEqual({n.store.accumulator() for n in self.c.nodes}, before, "state moved")
        self.assertEqual(len({n.store.head() for n in self.c.nodes}), 1, "log lengths diverged")

    def test_one_node_noticing_is_enough(self):
        """No distinguished proposer, and no requirement that everyone notice: one node proposes,
        the others ratify what they can recompute, and all three collect."""
        now = self._churn(12)
        self._drain(0, now)

        self.assertEqual(self.c.nodes[0].maybe_collect(now), 0)
        self.c.pump(now)

        for i, node in enumerate(self.c.nodes):
            self.assertNotIn(0, node.store.segments(), f"node {i} did not collect")

    def test_concurrent_proposals_are_byte_identical(self):
        """Two nodes proposing the same segment is harmless because the claim is a function of the
        segment and the fold, not of who spoke first -- so their signatures POOL rather than split
        the quorum between two rival claims."""
        now = self._churn(12)
        self._drain(0, now)
        a, b = self.c.nodes[0], self.c.nodes[1]

        self.assertEqual(a.maybe_collect(now), 0)
        self.assertEqual(b.maybe_collect(now), 0)
        self.assertEqual(a.collecting[0].attest_bytes(), b.collecting[0].attest_bytes())
        self.c.pump(now)
        for node in self.c.nodes:
            self.assertNotIn(0, node.store.segments())

    def test_a_wrong_fold_is_refused(self):
        """Ratification happens WHILE the evidence still exists. A peer that recomputes a different
        fold signs nothing -- and after collection nobody could ever have checked it."""
        now = self._churn(12)
        self._drain(0, now)
        liar, honest = self.c.nodes[0], self.c.nodes[1]

        forged = ops.Compaction(0, honest.store.head(), crypto.ACC_IDENTITY)  # not the real fold
        env = Envelope(honest.me.public, Verb.COLLECT, b"z" * 16, forged.attest_bytes())
        honest.receive(seal(env.sign(liar.me, now)), now)

        self.assertNotIn(forged.attest_bytes(), honest.shares, "signed a fold it cannot reproduce")
        self.assertIn(0, honest.store.segments(), "and collected on one node's word")

    def test_collection_gives_every_node_an_attested_floor(self):
        """Where C1 meets C2. Before the first collection there is no floor at all and a node has
        only its own head, which is a hint; afterwards every node carries a quorum-signed height
        that cannot be forged upward (#monotonicity)."""
        now = self._churn(12)
        self._drain(0, now)
        for node in self.c.nodes:
            self.assertEqual(node.store.floor(), 0, "a floor before any checkpoint existed")

        self.assertEqual(self.c.nodes[0].maybe_collect(now), 0)
        self.c.pump(now)

        floors = set()
        for i, node in enumerate(self.c.nodes):
            ck = node.store.checkpoint()
            assert ck is not None, f"node {i} collected without keeping the checkpoint"
            self.assertIsNone(ck.attested(list(node.roster())), f"node {i}: floor not ratified")
            self.assertEqual(node.attestation(now).claim.floor, ck.height)
            floors.add(ck.height)
        self.assertEqual(len(floors), 1, "nodes disagree about the attested floor")

    def test_the_floor_never_drops(self):
        """The retention is monotone at exactly one place, so a node cannot adopt an older
        checkpoint than the one it has already attested -- which would read as a regression and
        convict it."""
        now = self._churn(12)
        self._drain(0, now)
        node = self.c.nodes[0]
        self.assertEqual(node.maybe_collect(now), 0)
        self.c.pump(now)
        was = node.store.floor()
        self.assertGreater(was, 0)

        # Straight at `_collect`: the public path would refuse this marker on other grounds and
        # the guard under test would never be reached.
        stale = ops.Compaction(0, 1, node.store.accumulator())
        node.store._collect(1, at=node.store.head() + 1, marker=stale)
        self.assertEqual(node.store.floor(), was, "an older checkpoint lowered the floor")

    def test_the_checkpoint_carries_a_state_root_a_client_can_use(self):
        """The point of putting the root in the checkpoint: a client holding nothing but a
        quorum-signed height can be shown that one key holds one value, and that another key holds
        nothing at all (#state-root). `acc_state` can do neither."""
        now = self._churn(12)
        self._drain(0, now)
        self.assertEqual(self.c.nodes[0].maybe_collect(now), 0)
        self.c.pump(now)

        node = self.c.nodes[0]
        ck = node.store.checkpoint()
        assert ck is not None
        self.assertIsNone(ck.attested(list(node.roster())), "the root is not quorum-signed")

        hot = crypto.h(b"hot")
        held = node.store.get(D, hot)
        assert held is not None
        self.assertTrue(smt.verify(ck.root, D, hot, held.value, node.store.prove(D, hot)))
        self.assertTrue(
            smt.verify(ck.root, D, b"never-written", None, node.store.prove(D, b"never-written"))
        )

    def test_a_wrong_root_is_refused_like_a_wrong_fold(self):
        """Ratification covers the root too. A node that claims a height and a fold it really has,
        with a root it does not, gets no signature -- otherwise the quorum would be vouching for a
        commitment nobody checked."""
        now = self._churn(12)
        self._drain(0, now)
        liar, honest = self.c.nodes[0], self.c.nodes[1]

        forged = ops.Compaction(0, honest.store.head(), honest.store.accumulator(), smt.EMPTY)
        env = Envelope(honest.me.public, Verb.COLLECT, b"z" * 16, forged.attest_bytes())
        honest.receive(seal(env.sign(liar.me, now)), now)

        self.assertNotIn(forged.attest_bytes(), honest.shares, "signed a root it did not recompute")
        self.assertIn(0, honest.store.segments())

    def test_a_partitioned_node_does_not_collect_alone(self):
        """One node is not a quorum, however sure it is. Collection is irreversible, so the node
        that cannot reach its peers must simply keep the segment."""
        now = self._churn(12)
        self._drain(0, now)
        lone = name_of(self.c.keys[0].public)
        for other in self.c.keys[1:]:
            self.c.board.cut(lone, name_of(other.public))
            self.c.board.cut(name_of(other.public), lone)

        self.assertEqual(self.c.nodes[0].maybe_collect(now), 0, "it may still PROPOSE")
        self.c.pump(now)
        self.assertIn(0, self.c.nodes[0].store.segments(), "no quorum, no collection")


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
        self.assertTrue(smt.verify(said.claim.root, D, k0, held.value, node.store.prove(D, k0)))
        self.assertTrue(
            smt.verify(
                said.claim.root, D, b"nothing-here", None, node.store.prove(D, b"nothing-here")
            )
        )
        self.assertFalse(
            smt.verify(said.claim.root, D, k0, b"not what it holds", node.store.prove(D, k0))
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
        self.assertIsNotNone(attest.attested_floor(bundle, 3, now, WINDOW))

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
        self.assertIsNone(attest.attested_floor(bundle, 3, much_later, WINDOW))
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
