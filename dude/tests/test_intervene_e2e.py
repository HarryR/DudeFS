"""A manager-signed `intervene()` block on ONE node must reach every other node via ordinary
Follower sync -- no special wire flag, no evaluator branch. Drives sync only; production uses
intervene when Coordinator is hung, and driving both would race the manager block against
fresh consensus."""

from __future__ import annotations

import unittest

from dude.consensus.bootstrap import intervene
from dude.consensus.settle_round import SettledBlock
from dude.core import crypto
from dude.store.management import Cert, MgmtWriter, Role

from .cluster import DELTA, Cluster, D


def _sync_only_pump(c: Cluster, now: int, iterations: int = 30) -> int:
    """Drive Follower + Postman + frame delivery ONLY. Coordinator does NOT tick -- so the
    cluster's consensus doesn't advance during the sync propagation. Mimics production use of
    intervene() where the cluster is hung (Coordinator making no progress) and the operator
    uses the anchor key to push a block that sync then propagates."""
    for _ in range(iterations):
        # Quiesce at each instant before advancing time: replies posted mid-handling must be
        # delivered before a ttl bounded well below DELTA reaps them.
        for _ in range(len(c.nodes) + 1):
            delivered = False
            for node in c.nodes:
                node.follower.tick(now)
                # Post the Follower's outbox to the mailbox (same as Node.tick() does after
                # follower.tick). Follower is otherwise disconnected from the wire.
                node._flush_follower(now)
                node.postman.tick(now)
            # Deliver frames from each node's own listener via the public drain() API.
            for node in c.nodes:
                for inbound in c.listeners[node.me.public].drain():
                    node.receive(inbound.frame, now, session=inbound.session)
                    delivered = True
            if not delivered:
                break
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

        # TWO fresh client identities, granted in one intervention. Two, and passed in
        # REVERSE hash order, deliberately: the follower replays a block's bodies sorted by
        # op_hash, so an intervene() that applied caller order produced anchors no peer's
        # preview reproduced -- the block propagated to nobody, and a single-tx test could
        # never see it. A grant makes the effect observable in grant_of() after propagation.
        new_clients = [crypto.Keypair.generate() for _ in range(2)]
        grant_txs = tuple(
            MgmtWriter(c.nodes[0].store)
            .authorise(
                kp.public,
                Role.CLIENT_RW,
                stores=frozenset({D}),
                pop=kp.prove_possession(),
                cert=Cert.sign_grant(c.mgr, kp.public, Role.CLIENT_RW),
            )
            .sign(c.mgr, c._clock)
            for kp in new_clients
        )
        misordered = tuple(sorted(grant_txs, key=lambda t: t.op_hash, reverse=True))

        # Manager pushes a block onto node 0 via intervene(). This commits directly; node 0's
        # head advances to block_num=2 immediately, bypassing consensus. Its store now has a
        # block the other two nodes have never heard of.
        intervene(c.nodes[0].store, c.mgr, bodies=misordered, bucket=999)
        self.assertEqual(c.nodes[0].store.head_block_num(), 2)
        self.assertEqual(c.nodes[1].store.head_block_num(), 1)
        self.assertEqual(c.nodes[2].store.head_block_num(), 1)

        # Drive sync only (no Coordinator). Nodes 1 and 2 poll HEIGHT; node 0 replies "I'm
        # at 2"; nodes 1 and 2 pull block 2 via GETBLOCK; verify via the shared chain walk
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

        # And both grants are visible in every node's management view -- proves the txs
        # applied, not just that the block bytes were stored.
        for i, node in enumerate(c.nodes):
            for kp in new_clients:
                grant = node.mgmt.grant_of(kp.public)
                self.assertIsNotNone(grant, f"node {i} did not apply the intervene grant")
                assert grant is not None
                self.assertIs(grant.role, Role.CLIENT_RW)


if __name__ == "__main__":
    unittest.main()
