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
from ..store import Store, ops
from ..store.management import Management, Role
from ..tunables import DEFAULT

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
        * `FRONTIER` / `PULL` / `ENTRIES` — SPEC §8 log transfer, which is what BOOTSTRAP needs: a
          joining node holds the manager key and one address, and learns the log from it."""
        self.assertEqual(
            UNIMPLEMENTED,
            {Verb.ANNOUNCE, Verb.FETCH, Verb.FRONTIER, Verb.PULL, Verb.ENTRIES},
        )

    def test_an_unimplemented_verb_is_ignored_not_fatal(self):
        """A peer sending a verb we have not built must cost its message and nothing more."""
        node, other = self.c.nodes[0], self.c.nodes[1]
        env = Envelope(node.me.public, Verb.FRONTIER, b"z" * 16).sign(other.me, T0)
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
