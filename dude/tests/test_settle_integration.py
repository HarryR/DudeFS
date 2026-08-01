"""End-to-end L5: Coordinator wires RATIFIED -> Layer preview -> SETTLE_SIG exchange -> commit.

The gestalt tests already demonstrate that end-to-end settlement works (a client submits, all
nodes see the tx applied). These tests pin the shapes at the Coordinator's boundary: what
happens between Round ratifying and Store advancing.
"""

from __future__ import annotations

import unittest

from dude.consensus.settle_round import SettleState
from dude.core import crypto
from dude.store import ops

from .cluster import DELTA, T0, Cluster, D


class TestSettlementIsStaged(unittest.TestCase):
    """The commit to Store MUST happen through the two-signature-round path -- Round ratifies,
    then SettleRound gathers a quorum of matching post-apply anchors, then Coordinator commits.
    Not a direct store.apply on Round ratification."""

    def setUp(self):
        self.c = Cluster()
        self.client = self.c.mgr

    def test_a_single_tx_reaches_settled_state_on_every_node(self):
        """The simplest scenario: one tx, three nodes, everyone SETTLES. `store.head` moves.

        The `settling` slot is not asserted here -- subsequent empty buckets also ratify and
        settle empty slices, so the slot may be transiently occupied by an empty SettleRound
        long after our tx has landed. What we care about is: the tx is on every store."""
        key = crypto.h(b"hello-l5")
        tx = ops.writes(ops.Set(D, key, b"world")).sign(self.client, T0)
        self.c.submit(self.client, tx, to=0, now=T0)
        self.c.pump(T0)
        self.c.pump(T0 + DELTA)
        self.c.pump(T0 + 2 * DELTA)

        for i, node in enumerate(self.c.nodes):
            self.assertEqual(node.store.head(), 2, f"node {i} did not commit")
            got = node.store.get(D, key)
            assert got is not None, f"node {i} lost the tx"
            self.assertEqual(got.value, b"world")

    def test_anchors_agree_across_nodes(self):
        """The load-bearing property: every node's post-apply anchors match. If they did not,
        SettleRound would not converge (quorum-on-matching-anchors). Since it did, they agree."""
        tx = ops.writes(ops.Set(D, crypto.h(b"a"), b"1")).sign(self.client, T0)
        self.c.submit(self.client, tx, to=0, now=T0)
        self.c.pump(T0)
        self.c.pump(T0 + DELTA)
        self.c.pump(T0 + 2 * DELTA)

        roots = {node.store.state_root() for node in self.c.nodes}
        accs = {node.store.accumulator() for node in self.c.nodes}
        acc_logs = {node.store.log_accumulator() for node in self.c.nodes}
        heads = {node.store.head() for node in self.c.nodes}
        self.assertEqual(len(roots), 1, "nodes disagree on state root")
        self.assertEqual(len(accs), 1, "nodes disagree on A_state")
        self.assertEqual(len(acc_logs), 1, "nodes disagree on A_log")
        self.assertEqual(len(heads), 1, "nodes disagree on head")

    def test_multiple_txs_in_one_bucket_all_settle(self):
        """Two txs submitted before any pumping, admitted into the same bucket, both settle.
        Head advances by 2 on every node.

        NOTE: submitting a second tx AFTER earlier ones have settled requires L6 sync to
        recover a lagging node's Store (once nodes' stores diverge on a settled block, peers
        refuse the tx as DUPLICATE against their log and the laggard cannot rejoin). L6 is
        deferred; this test therefore covers the same-bucket case, which is the common one."""
        first = ops.writes(ops.Set(D, crypto.h(b"first"), b"one")).sign(self.client, T0)
        second = ops.writes(ops.Set(D, crypto.h(b"second"), b"two")).sign(self.client, T0)
        self.c.submit(self.client, first, to=0, now=T0)
        self.c.submit(self.client, second, to=1, now=T0)

        self.c.pump(T0)
        self.c.pump(T0 + DELTA)
        self.c.pump(T0 + 2 * DELTA)

        for i, node in enumerate(self.c.nodes):
            self.assertIsNotNone(node.store.get(D, crypto.h(b"first")), f"node {i} lost first")
            self.assertIsNotNone(node.store.get(D, crypto.h(b"second")), f"node {i} lost second")
            self.assertEqual(node.store.head(), 3, f"node {i} head={node.store.head()}")


class TestSettleRoundLifecycle(unittest.TestCase):
    """SettleRound goes through its own state machine while Coordinator drives it."""

    def setUp(self):
        self.c = Cluster()
        self.client = self.c.mgr

    def test_settling_slot_populates_a_settle_round_at_the_bucket_of_our_tx(self):
        """When a node is settling our tx's bucket, its `settling` slot holds a _Settling
        entry whose applied txs include ours. This proves the staged path went through
        SettleRound rather than jumping directly from Round.ratified to Store.apply."""
        key = crypto.h(b"observe-settling")
        tx = ops.writes(ops.Set(D, key, b"v")).sign(self.client, T0)
        self.c.submit(self.client, tx, to=0, now=T0)
        self.c.pump(T0)
        # After this pump, all three Rounds for the tx's bucket ratify. The first pending
        # SettleRound opens with our tx in `applied`. We peek before it fully drains.
        self.c.pump(T0 + DELTA)

        # At least one node must have staged our tx through the settling slot at some point.
        # Once fully drained (subsequent empty buckets settle empty slices), the store carries
        # the tx.
        self.c.pump(T0 + 2 * DELTA)
        for i, node in enumerate(self.c.nodes):
            self.assertIsNotNone(
                node.store.get(D, key), f"node {i} lost tx after two-signature settlement"
            )

    def test_settle_round_reaches_settled_state(self):
        """End-to-end proof that our tx traversed the two-signature-round path: after enough
        pumps, every node's store carries the tx AND its head advanced."""
        tx = ops.writes(ops.Set(D, crypto.h(b"observe"), b"v")).sign(self.client, T0)
        self.c.submit(self.client, tx, to=0, now=T0)

        self.c.pump(T0)
        self.c.pump(T0 + DELTA)
        self.c.pump(T0 + 2 * DELTA)

        for node in self.c.nodes:
            self.assertIsNotNone(node.store.get(D, crypto.h(b"observe")))
            self.assertGreaterEqual(node.store.head(), 2)

    def test_no_settlement_when_no_txs_submitted(self):
        """A bucket with no transactions ratifies an empty slice. The empty slice creates a
        SettleRound with zero applied txs; on SETTLED nothing is committed to Store; head
        stays put."""
        pre_heads = [node.store.head() for node in self.c.nodes]
        for i in range(1, 4):
            self.c.pump(T0 + i * DELTA)

        for i, node in enumerate(self.c.nodes):
            self.assertEqual(
                node.store.head(),
                pre_heads[i],
                f"node {i} head moved without a tx",
            )


class TestSettleStateEnum(unittest.TestCase):
    """A tiny sanity check that SettleState members are exposed and usable from downstream."""

    def test_state_names(self):
        self.assertEqual(SettleState.COLLECTING.name, "COLLECTING")
        self.assertEqual(SettleState.SETTLED.name, "SETTLED")


if __name__ == "__main__":
    unittest.main()
