"""End-to-end sync test: a fresh 4th node joins a running cluster and catches up.

Exercises the full stack: real Node dispatch of HEIGHT/HEIGHT_REPLY/GETBLOCK/SETTLED_BLOCK,
real Postman mailbox correlation for the request/reply pairs, real Follower verify-and-commit.
The direct-wired follower tests in test_sync.py cover the state machine's behaviour; this test
proves that the Node dispatch wiring reaches it correctly through the wire stack.
"""

from __future__ import annotations

import unittest

from dude.consensus.settle_round import SettledBlock
from dude.core import crypto
from dude.net.address import Endpoint
from dude.net.transports import InProcListener, address_of, name_of
from dude.node import Node
from dude.store import Store, ops

from .cluster import DELTA, T0, Cluster, D


def _produce_blocks(c: Cluster, n: int) -> int:
    """Submit txs and pump until block_num >= n on every cluster node. Returns final `now`."""
    now = T0
    submissions = 0
    while any((node.store.head_block_num() or 0) < n for node in c.nodes):
        tx = ops.writes(ops.Set(D, crypto.h(f"e2e-{submissions}".encode()), b"v")).sign(c.mgr, now)
        c.submit(c.mgr, tx, to=0, now=now)
        c.pump(now)
        submissions += 1
        now += DELTA
        if submissions > 30:
            raise AssertionError(f"cluster failed to produce {n} blocks")
    return now


class TestFreshNodeJoinsClusterAndCatchesUp(unittest.TestCase):
    """The core L6 promise end-to-end: a node arriving with only the manager pubkey attaches
    to the cluster, polls HEIGHT, pulls blocks via GETBLOCK, and lands at the head."""

    def test_joiner_catches_up_via_the_wire(self):
        c = Cluster()
        _produce_blocks(c, 3)
        producer_head = c.nodes[0].store.head_block_num()
        assert producer_head is not None and producer_head >= 3

        # A joiner starting with only the manager pubkey -- no bootstrap, no genesis.
        # Construct the listener explicitly, matching what a production `main()` would do
        # (one listener per identity, drained via the pump); the send side is Postman's own.
        joiner_kp = crypto.Keypair.generate()
        joiner_store = Store()
        joiner_store.provision(c.mgr.public)
        joiner_listener = InProcListener(name_of(joiner_kp.public))
        joiner = Node(joiner_kp, joiner_store)

        # Bootstrap-outside-the-roster wiring: reconciliation from `mgmt.roster()`
        # doesn't add the joiner to node 0's peers (joiner isn't in the roster yet), and
        # doesn't add node 0 to the joiner's peers (joiner's store is empty). Both sides
        # need a manual bootstrap peer added directly to postman + follower.
        joiner.postman.add_peer(
            c.nodes[0].me.public,
            (Endpoint(address_of(c.nodes[0].me.public)),),
        )
        joiner.follower.add_peer(c.nodes[0].me.public, now=0)
        c.nodes[0].postman.add_peer(
            joiner_kp.public,
            (Endpoint(address_of(joiner_kp.public)),),
        )

        # Pump time forward with all four nodes. Each pump: tick every node (drives their
        # follower + coordinator), quiesce dissemination via each listener's `.drain()`.
        # The joiner's tick fires HEIGHT polls; node 0 answers; joiner pulls; verifies;
        # commits; repeat. Round enforces monotone `now`, so start from wherever the
        # cluster's own clock ended up.
        listeners_by_node = {
            **c.listeners,
            joiner_kp.public: joiner_listener,
        }
        now = c._clock
        for _ in range(20):
            for node in [*c.nodes, joiner]:
                node.tick(now)
            for _ in range(10):
                delivered = 0
                for node in [*c.nodes, joiner]:
                    node.postman.tick(now)
                for node in [*c.nodes, joiner]:
                    for inbound in listeners_by_node[node.me.public].drain():
                        node.receive(inbound.frame, now, session=inbound.session)
                        delivered += 1
                if delivered == 0:
                    break
            if (joiner_store.head_block_num() or 0) >= producer_head:
                break
            now += DELTA

        # Joiner reached (at least) the producer's head. It may be higher because the cluster
        # continues to produce empty blocks during our pump loop, but MUST NOT be lower.
        joiner_head = joiner_store.head_block_num() or 0
        self.assertGreaterEqual(
            joiner_head,
            producer_head,
            f"joiner did not catch up: joiner={joiner_head} producer={producer_head}",
        )
        # Chain integrity: for every block up to joiner's head that node 0 also holds, the
        # sig-independent identity hashes must match. This proves the joiner is on the same
        # chain as the cluster.
        overlap = min(joiner_head, c.nodes[0].store.head_block_num() or 0)
        self.assertGreater(overlap, 0, "no overlap between joiner and node 0 heads")
        for n in range(1, overlap + 1):
            j_bytes = joiner_store.settled_at(n)
            p_bytes = c.nodes[0].store.settled_at(n)
            assert j_bytes is not None and p_bytes is not None
            self.assertEqual(
                SettledBlock.decode(j_bytes).block_hash,
                SettledBlock.decode(p_bytes).block_hash,
                f"chain diverged at block_num={n}",
            )
        # Joiner's roster ends up matching the cluster's.
        joiner_roster = joiner_store.mgmt.roster()
        producer_roster = c.nodes[0].store.mgmt.roster()
        self.assertEqual(set(joiner_roster), set(producer_roster))


if __name__ == "__main__":
    unittest.main()
