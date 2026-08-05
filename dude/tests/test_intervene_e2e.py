"""End-to-end test for `intervene()` (#anchor-is-the-axiom + #manager-sig-overrides-quorum).

The scenario: the manager holds the anchor cold-key. They call `intervene()` against ONE node's
store, which commits a manager-signed block directly (bypassing consensus). The rest of the
cluster sees that node's head advance via routine HEIGHT polls, pulls the new block via
GETBLOCK, verifies it against the anchor slot in `Management.authorization`, and commits.

This is the load-bearing property: an operator holding the anchor key can push a block into
one node, and normal sync propagates it to every other node with no special path -- no
"emergency intervention" wire flag, no evaluator branch, just the same Follower verify-and-
commit pipeline that pulls any other SETTLED block.

The test drives ONLY the sync path (Follower + Postman + frame delivery), skipping Coordinator
ticks. In production, intervene() is used when the cluster is hung -- Coordinator wouldn't be
producing new blocks. Driving both would race the intervene block against fresh consensus
blocks and produce a divergent chain (unavoidable while both mechanisms compete for block_num
= head+1). The sync-only pump matches the actual use case AND isolates the property being
tested: intervene block reaches every node via the ordinary sync verify-and-commit pipeline.
"""

from __future__ import annotations

import unittest

from dude.consensus.bootstrap import intervene
from dude.consensus.settle_round import SettledBlock
from dude.core import crypto
from dude.store.management import Cert, Role

from .cluster import DELTA, Cluster, D


def _sync_only_pump(c: Cluster, now: int, iterations: int = 30) -> int:
    """Drive Follower + Postman + frame delivery ONLY. Coordinator does NOT tick -- so the
    cluster's consensus doesn't advance during the sync propagation. Mimics production use of
    intervene() where the cluster is hung (Coordinator making no progress) and the operator
    uses the anchor key to push a block that sync then propagates."""
    for _ in range(iterations):
        for node in c.nodes:
            node.follower.tick(now)
            # Post the Follower's outbox to the mailbox (same as Node.tick() does after
            # follower.tick). Follower is otherwise disconnected from the wire.
            node._flush_follower(now)
            node.postman.tick(now)
        # Deliver frames from each node's own transport inbox.
        for node in c.nodes:
            frames = c._transports[node.me.public].receive()
            for frame in frames:
                node.receive(frame, now)
        now += DELTA
    return now


class TestIntervenePropagatesViaSync(unittest.TestCase):
    """Manager signs a block into node 0's store via `intervene()`. Nodes 1 and 2 pick it up
    through the normal sync path (HEIGHT poll → GETBLOCK → verify → commit)."""

    def test_intervene_on_one_node_propagates_via_sync(self):
        c = Cluster()
        # Baseline: every node holds block 1 (the bootstrap block) and agrees on the head.
        assert c.nodes[0].store.head_block_num() == 1
        assert c.nodes[1].store.head_block_num() == 1
        assert c.nodes[2].store.head_block_num() == 1

        # A fresh client identity that the manager will grant into the cluster via
        # intervention. Any deterministic tx would do; a grant makes the effect observable
        # in Management.grant_of() after propagation.
        new_client = crypto.Keypair.generate()
        pop = new_client.prove_possession()
        grant_tx = (
            c.nodes[0]
            .mgmt.authorise(
                new_client.public,
                Role.CLIENT,
                stores=frozenset({D}),
                pop=pop,
                cert=Cert.sign_grant(c.mgr, new_client.public, Role.CLIENT),
            )
            .sign(c.mgr, c._clock)
        )

        # Manager pushes a block onto node 0 via intervene(). This commits directly; node 0's
        # head advances to block_num=2 immediately, bypassing consensus. Its store now has a
        # block the other two nodes have never heard of.
        intervene(c.nodes[0].store, c.mgr, bodies=(grant_tx,), bucket=999)
        self.assertEqual(c.nodes[0].store.head_block_num(), 2)
        self.assertEqual(c.nodes[1].store.head_block_num(), 1)
        self.assertEqual(c.nodes[2].store.head_block_num(), 1)

        # Drive sync only (no Coordinator). Nodes 1 and 2 poll HEIGHT; node 0 replies "I'm
        # at 2"; nodes 1 and 2 pull block 2 via GETBLOCK; verify via Management.authorization
        # (which accepts the manager slot); commit. No special wire path, no special verifier.
        _sync_only_pump(c, c._clock, iterations=30)

        # Every node now holds block 2 via the ordinary sync path.
        for i, node in enumerate(c.nodes):
            self.assertEqual(
                node.store.head_block_num(), 2, f"node {i} did not sync intervene block"
            )

        # Every node computes the same block_hash for block 2 -- proves the sync-received
        # block matches the manager-signed original byte-for-byte. Identity portion only;
        # wire bytes may differ per node depending on sig subset, but block_hash is
        # sig-independent per SPEC anchor block-shape-settled.
        block_hashes = set()
        for node in c.nodes:
            raw = node.store.settled_at(2)
            assert raw is not None
            block_hashes.add(SettledBlock.decode(raw).block_hash)
        self.assertEqual(len(block_hashes), 1, "nodes disagree on block 2 identity")

        # And the grant is visible in every node's Management view -- proves the tx applied,
        # not just that the block bytes were stored.
        for i, node in enumerate(c.nodes):
            grant = node.mgmt.grant_of(new_client.public)
            self.assertIsNotNone(grant, f"node {i} did not apply the intervene grant")
            assert grant is not None
            self.assertIs(grant.role, Role.CLIENT)


if __name__ == "__main__":
    unittest.main()
