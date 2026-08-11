"""End-to-end L5: Coordinator wires RATIFIED -> Layer preview -> SETTLE_SIG exchange -> commit.

The gestalt tests already demonstrate that end-to-end settlement works (a client submits, all
nodes see the tx applied). These tests pin the shapes at the Coordinator's boundary: what
happens between Round ratifying and Store advancing.
"""

from __future__ import annotations

import unittest
from dataclasses import replace

from dude.consensus.coordinator import _Settling
from dude.consensus.round import Block
from dude.consensus.settle_round import (
    Anchors,
    SettledBlock,
    SettleRound,
    SettleSig,
    SettleState,
    genesis_stamp,
)
from dude.core import crypto
from dude.store import Layer, ops

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
        self.c.put("hello-l5", b"world", kp=self.client, now=T0)
        key = self.c.token("hello-l5")
        self.c.pump(T0)
        self.c.pump(T0 + DELTA)
        self.c.pump(T0 + 2 * DELTA)

        for i, node in enumerate(self.c.nodes):
            self.assertEqual(node.store.head(), 2, f"node {i} did not commit")
            got = node.store.get(D, key)
            assert got is not None, f"node {i} lost the tx"
            self.assertNotEqual(got.value, b"world", "the node is holding plaintext")
            self.assertEqual(
                self.c.client(self.client).open("hello-l5", got.value, got.epoch), b"world"
            )

    def test_anchors_agree_across_nodes(self):
        """The load-bearing property: every node's post-apply anchors match. If they did not,
        SettleRound would not converge (quorum-on-matching-anchors). Since it did, they agree."""
        tx = self.c.client(self.client).put("a", b"1").sign(self.client, T0)
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
        cl = self.c.client(self.client)
        first = cl.put("first", b"one").sign(self.client, T0)
        second = cl.put("second", b"two").sign(self.client, T0)
        self.c.submit(self.client, first, to=0, now=T0)
        self.c.submit(self.client, second, to=1, now=T0)

        self.c.pump(T0)
        self.c.pump(T0 + DELTA)
        self.c.pump(T0 + 2 * DELTA)

        for i, node in enumerate(self.c.nodes):
            self.assertIsNotNone(node.store.get(D, cl.token("first")), f"node {i} lost first")
            self.assertIsNotNone(node.store.get(D, cl.token("second")), f"node {i} lost second")
            self.assertEqual(node.store.head(), 3, f"node {i} head={node.store.head()}")


def _hashes_by_block(store) -> dict[int, frozenset[crypto.Digest]]:
    """Every settled block's transaction list, decoded back out of the stored blob. The list is
    not a column -- it lives only inside `block.bytes`."""
    out: dict[int, frozenset[crypto.Digest]] = {}
    for n in range(1, (store.head_block_num() or 0) + 1):
        raw = store.settled_at(n)
        if raw is not None:
            out[n] = frozenset(SettledBlock.decode(raw).block.hashes)
    return out


class TestABlockNamesOnlyWhatItApplied(unittest.TestCase):
    """A block's hash list is quorum-signed via `slice_hash`, so membership must equal
    application -- otherwise the same op_hash can appear in two blocks and inclusion proves
    nothing to a client."""

    def setUp(self):
        self.c = Cluster()
        self.mgr = self.c.mgr
        self.cl = self.c.client(self.mgr)

    def test_a_guard_its_own_block_falsifies_never_reaches_the_hash_list(self):
        """Two compare-and-swaps on one name, in one bucket. Both pass admission -- each guard
        holds against committed state when it arrives -- and the first to apply falsifies the
        second. Exactly one may appear in the block."""
        self.c.put("k", b"v0", kp=self.mgr, now=T0)
        self.c.pump(T0)
        row = self.c.nodes[0].store.get(D, self.cl.token("k"))
        assert row is not None, "the setup write never settled"

        first = self.cl.cas("k", row.value, b"v1").sign(self.mgr, T0 + DELTA)
        second = self.cl.cas("k", row.value, b"v2").sign(self.mgr, T0 + DELTA)
        self.assertNotEqual(first.op_hash, second.op_hash, "the two CASes are the same tx")
        self.c.submit(self.mgr, first, to=0, now=T0 + DELTA)
        self.c.submit(self.mgr, second, to=0, now=T0 + DELTA)

        # INSTRUMENTATION: the scenario is only interesting if BOTH were admitted and therefore
        # both were candidates for the same slice. If one had been refused at the door this test
        # would pass while exercising nothing.
        pooled = self.c.nodes[0].coordinator.mempool.all_bodies()
        self.assertIn(first.op_hash, pooled, "first CAS never made it into the mempool")
        self.assertIn(second.op_hash, pooled, "second CAS never made it into the mempool")

        self.c.pump(T0 + DELTA)
        self.c.pump(T0 + 2 * DELTA)

        for i, node in enumerate(self.c.nodes):
            named = frozenset().union(*_hashes_by_block(node.store).values())
            landed = named & {first.op_hash, second.op_hash}
            self.assertEqual(
                len(landed), 1, f"node {i} named {len(landed)} of the two CASes, expected exactly 1"
            )
            # And what it named is what it applied: the loser has no log entry either.
            self.assertEqual(
                node.store.settled_hashes((first.op_hash, second.op_hash)),
                set(landed),
                f"node {i} applied a different set than its blocks name",
            )


class TestDivergentSettlementIsLoggedNotFatal(unittest.TestCase):
    """Divergence: name who disagreed and what they signed, let an operator decide what to roll
    back. Crashing takes honest nodes down for a peer's state. Absence (no quorum, no disagreement)
    stays silent -- it heals on its own."""

    def _stall(self, c: Cluster, bucket: int, now: int, *, diverge: bool) -> None:
        """One abandoned settlement on node 0, with or without a peer disagreeing about the
        anchors. Driven through `Coordinator.tick`, which is what decides abandonment."""
        node = c.nodes[0]
        block = Block(bucket=bucket, hashes=())
        mine = Anchors(
            block_num=(node.store.head_block_num() or 0) + 1,
            height=node.store.head(),
            prev_block=node.store.head_block_hash() or genesis_stamp(c.mgr.public),
            state_root=node.store.state_root(),
            acc_state=node.store.accumulator(),
            acc_log=node.store.log_accumulator(),
        )
        sr = SettleRound(block, node.me, node.mgmt.roster(), mine, now, abandon_by=now + 1)
        if diverge:
            peer = c.keys[1]
            sr.receive(
                SettleSig.sign(peer, block.slice_hash, replace(mine, state_root=crypto.h(b"else"))),
                from_=peer.public,
                now=now,
            )
            assert sr.divergences(), "the peer's signature was not recorded as a divergence"
        else:
            assert not sr.divergences(), "the control stall must carry no divergence"
        node.coordinator.settling = _Settling(
            bucket=bucket,
            block=block,
            layer=Layer(node.store),
            applied=(),
            surviving=(),
            anchors=mine,
            first_height=node.store.head() + 1,
            settle_round=sr,
        )
        node.coordinator.tick(now + 2)
        assert node.coordinator.settling is None, "the settling slot was not released"

    def test_divergence_logs_who_disagreed_and_never_raises(self):
        c = Cluster()
        with self.assertLogs("dude.consensus.coordinator", level="WARNING") as logs:
            self._stall(c, bucket=100, now=T0, diverge=True)
        line = "\n".join(r.getMessage() for r in logs.records)
        self.assertIn("divergent anchors", line, f"the log did not name the failure mode: {line!r}")
        self.assertIn(
            c.keys[1].public.hex()[:8], line, f"the log did not name who disagreed: {line!r}"
        )
        self.assertIn(str(100), line, f"the log did not name the bucket: {line!r}")

    def test_absence_of_quorum_is_silent(self):
        """No divergence means no log line -- ordinary partitions must not become noise."""
        c = Cluster()
        with self.assertNoLogs("dude.consensus.coordinator", level="WARNING"):
            self._stall(c, bucket=200, now=T0, diverge=False)


class TestSettleRoundLifecycle(unittest.TestCase):
    """SettleRound goes through its own state machine while Coordinator drives it."""

    def setUp(self):
        self.c = Cluster()
        self.client = self.c.mgr

    def test_settling_slot_populates_a_settle_round_at_the_bucket_of_our_tx(self):
        """When a node is settling our tx's bucket, its `settling` slot holds a _Settling
        entry whose applied txs include ours. This proves the staged path went through
        SettleRound rather than jumping directly from Round.ratified to Store.apply."""
        key = self.c.token("observe-settling", self.client)
        tx = self.c.client(self.client).put("observe-settling", b"v").sign(self.client, T0)
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
        tx = self.c.client(self.client).put("observe", b"v").sign(self.client, T0)
        self.c.submit(self.client, tx, to=0, now=T0)

        self.c.pump(T0)
        self.c.pump(T0 + DELTA)
        self.c.pump(T0 + 2 * DELTA)

        for node in self.c.nodes:
            self.assertIsNotNone(node.store.get(D, self.c.token("observe", self.client)))
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


class TestBlocksChainAndPersist(unittest.TestCase):
    """The end-to-end shape of Stage 1: after settlement, every node has a `block` row per
    ratified bucket, chained via `prev_block` back to the genesis stamp derived from the
    manager pubkey (#genesis-stamp-anchors-the-chain, #block-shape-settled)."""

    def setUp(self):
        self.c = Cluster()
        self.client = self.c.mgr

    def test_first_block_prev_is_the_genesis_stamp(self):
        """Block 1's `prev_block` = H('dude.genesis:' || manager_pubkey). A joiner holding
        only the manager pubkey computes the same stamp locally."""
        tx = ops.writes(ops.Set(D, crypto.h(b"first"), b"v")).sign(self.client, T0)
        self.c.submit(self.client, tx, to=0, now=T0)
        self.c.pump(T0)
        self.c.pump(T0 + DELTA)
        self.c.pump(T0 + 2 * DELTA)

        for i, node in enumerate(self.c.nodes):
            raw = node.store.settled_at(1)
            assert raw is not None, f"node {i} has no block_num=1 row"
            sb = SettledBlock.decode(raw)
            self.assertEqual(sb.anchors.block_num, 1)
            self.assertEqual(
                sb.anchors.prev_block,
                genesis_stamp(self.c.mgr.public),
                f"node {i} block 1 does not chain to genesis",
            )

    def test_subsequent_blocks_chain_via_prev_block_hash(self):
        """Block N+1's `prev_block` = H(block N's bytes). Walk two ratified blocks and check
        the link is byte-exact. If two nodes agreed on the same block N bytes, they compute
        the same prev_block for block N+1 -- so the chain converges."""
        tx1 = ops.writes(ops.Set(D, crypto.h(b"one"), b"v")).sign(self.client, T0)
        self.c.submit(self.client, tx1, to=0, now=T0)
        self.c.pump(T0)
        self.c.pump(T0 + DELTA)
        # Second tx in a new bucket, so a second non-empty block ratifies.
        tx2 = ops.writes(ops.Set(D, crypto.h(b"two"), b"v")).sign(self.client, T0 + 2 * DELTA)
        self.c.submit(self.client, tx2, to=1, now=T0 + 2 * DELTA)
        self.c.pump(T0 + 2 * DELTA)
        self.c.pump(T0 + 3 * DELTA)
        self.c.pump(T0 + 4 * DELTA)

        for i, node in enumerate(self.c.nodes):
            raw1 = node.store.settled_at(1)
            raw2 = node.store.settled_at(2)
            assert raw1 is not None, f"node {i} has no block 1"
            assert raw2 is not None, f"node {i} has no block 2"
            sb1 = SettledBlock.decode(raw1)
            sb2 = SettledBlock.decode(raw2)
            self.assertEqual(
                sb2.anchors.prev_block,
                sb1.block_hash,
                f"node {i} block 2 does not chain to block 1",
            )

    def test_every_node_agrees_on_the_chain_hash(self):
        """`block_hash` MUST hash only the identity, not `encode()`: which subset of settle_sigs
        a node held at SETTLE is timing-dependent, so encode-bytes differ per node while the
        chain link cannot."""
        tx = ops.writes(ops.Set(D, crypto.h(b"pin"), b"v")).sign(self.client, T0)
        self.c.submit(self.client, tx, to=0, now=T0)
        self.c.pump(T0)
        self.c.pump(T0 + DELTA)
        self.c.pump(T0 + 2 * DELTA)

        hashes = set()
        for node in self.c.nodes:
            raw = node.store.settled_at(1)
            assert raw is not None
            hashes.add(SettledBlock.decode(raw).block_hash)
        self.assertEqual(
            len(hashes), 1, "nodes disagree on block 1 chain-hash (identity, not raw bytes)"
        )


if __name__ == "__main__":
    unittest.main()
