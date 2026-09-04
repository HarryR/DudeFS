from __future__ import annotations

import time
import unittest

from ..consensus.bootstrap import bootstrap, compose_genesis
from ..core import codec, crypto
from ..core.units import Millis
from ..net.envelope import Verb
from ..net.postman import Postman
from ..net.transports.inproc import InProcNexus
from ..node import Node
from ..store import Store, ops
from ..tunables import Tunables

T0 = Millis(1_700_000_000_000)
TUNABLES = Tunables(rtt_max=Millis(50), clock_skew=Millis(25), held_convergence_max=2)


def _provision_cluster(
    nexus: InProcNexus,
    anchor: crypto.Keypair,
    node_keys: list[crypto.Keypair],
) -> tuple[list[Node], Postman]:
    node_endpoints = [(kp.public, (nexus.endpoint_for(kp.public),)) for kp in node_keys]

    nodes: list[Node] = []
    for kp in node_keys:
        store = Store()
        store.provision(anchor.public)
        n = Node(kp, store, TUNABLES)
        nexus.attach(n)
        n.start()
        nodes.append(n)

    genesis_bodies = compose_genesis(anchor=anchor, node_endpoints=node_endpoints, ts=T0)
    scratch = Store()
    scratch.provision(anchor.public)
    settled = bootstrap(scratch, anchor, genesis_bodies, bucket=TUNABLES.bucket(T0))
    genesis_wire = codec.encode([settled.block.encode(), [tx.raw for tx in settled.bodies]])

    anchor_postman = Postman(anchor, TUNABLES)
    nexus.attach(anchor_postman)
    for pub, endpoints in node_endpoints:
        anchor_postman.add_peer(pub, endpoints)
    anchor_postman.start()

    for pub, _ in node_endpoints:
        anchor_postman.send_raw(pub, Verb.PROVISION, genesis_wire, TUNABLES.ttl_exchange)

    deadline = time.monotonic() + 5.0
    provisioned: set[crypto.PublicKey] = set()
    while len(provisioned) < len(node_keys) and time.monotonic() < deadline:
        for output in anchor_postman.drain_output(timeout=0.1):
            for d in output.delivered:
                if d.verb == Verb.ACCEPTED:
                    provisioned.add(d.frm)

    if len(provisioned) != len(node_keys):
        anchor_postman.stop()
        for n in nodes:
            n.stop()
        raise AssertionError(
            f"only {len(provisioned)}/{len(node_keys)} nodes acknowledged PROVISION"
        )

    return nodes, anchor_postman


class TestLiveProvisioning(unittest.TestCase):
    def test_anchor_provisions_nodes_over_wire(self) -> None:
        nexus = InProcNexus()
        anchor = crypto.Keypair.generate()
        node_keys = [crypto.Keypair.generate() for _ in range(3)]
        nodes, anchor_postman = _provision_cluster(nexus, anchor, node_keys)

        try:
            anchor_postman.stop()
            expected_roster = tuple(sorted(kp.public for kp in node_keys))
            for n in nodes:
                self.assertIsNotNone(n.store.head_block_num())
                self.assertEqual(n.store.mgmt_reader.roster(), expected_roster)
        finally:
            for n in nodes:
                n.stop()

    def test_consensus_works_after_provisioning(self) -> None:
        nexus = InProcNexus()
        anchor = crypto.Keypair.generate()
        node_keys = [crypto.Keypair.generate() for _ in range(3)]
        nodes, anchor_postman = _provision_cluster(nexus, anchor, node_keys)

        try:
            anchor_postman.stop()

            tx = ops.writes(ops.Set(ops.STORE_MANAGEMENT, b"test-key", b"test-val")).sign(
                anchor, Millis.now()
            )

            refusal = nodes[0].coordinator.submit(tx, Millis.now())
            self.assertIsNone(refusal, f"submit refused: {refusal}")

            budget = TUNABLES.block_time.as_seconds * 10
            tick = TUNABLES.tick_interval.as_seconds
            deadline = time.monotonic() + budget
            while time.monotonic() < deadline:
                if all(n.store.has_settled(tx.op_hash) for n in nodes):
                    break
                time.sleep(tick)
            else:
                settled_on = [i for i, n in enumerate(nodes) if n.store.has_settled(tx.op_hash)]
                block_nums = [(n.store.head_block_num() or 0) for n in nodes]
                self.fail(
                    f"not settled after {budget:.1f}s: "
                    f"settled_on={settled_on}, block_nums={block_nums}"
                )

            state_roots = {n.store.state_root() for n in nodes}
            self.assertEqual(len(state_roots), 1, "state roots diverged after settlement")
        finally:
            for n in nodes:
                n.stop()


if __name__ == "__main__":
    unittest.main()
