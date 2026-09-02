from __future__ import annotations

import shutil
import tempfile
import time
import unittest
from pathlib import Path

from ..cli.state import save_anchor, save_keypair, store_path
from ..consensus.bootstrap import bootstrap, compose_genesis
from ..core import codec, crypto
from ..core.units import Millis
from ..net.envelope import Verb
from ..net.postman import Postman
from ..net.transports.inproc import InProcListener, InProcNexus
from ..node import Node
from ..store import Store
from ..tunables import Tunables

T0 = Millis(1_700_000_000_000)
TUNABLES = Tunables(rtt_max=Millis(50), clock_skew=Millis(25), held_convergence_max=2)


class TestLiveProvisioning(unittest.TestCase):
    def test_anchor_provisions_nodes_over_wire(self) -> None:
        nexus = InProcNexus()
        anchor = crypto.Keypair.generate()
        node_keys = [crypto.Keypair.generate() for _ in range(3)]

        dirs = [tempfile.mkdtemp() for _ in node_keys]
        for kp, d in zip(node_keys, dirs, strict=True):
            save_keypair(Path(d), kp)
            save_anchor(Path(d), anchor.public)

        node_endpoints = [(kp.public, (nexus.endpoint_for(kp.public),)) for kp in node_keys]

        nodes: list[Node] = []
        stores: list[Store] = []
        inprocs = [InProcListener(kp.public, nexus) for kp in node_keys]
        try:
            for kp, d, ip in zip(node_keys, dirs, inprocs, strict=True):
                anchor_pub = crypto.PublicKey((Path(d) / "anchor.pub").read_bytes())
                store = Store(store_path(Path(d)))
                store.provision(anchor_pub)
                stores.append(store)
                n = Node(kp, store, TUNABLES)
                n.add_acceptor(ip)
                n.add_dialer(ip)
                n.start()
                nodes.append(n)

            for n in nodes:
                self.assertIsNone(n.store.head_block_num())

            genesis_bodies = compose_genesis(
                anchor=anchor,
                node_endpoints=node_endpoints,
                ts=T0,
            )
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
            provisioned = set()
            while len(provisioned) < len(node_keys) and time.monotonic() < deadline:
                for output in anchor_postman.drain_output(timeout=0.1):
                    for d in output.delivered:
                        if d.verb == Verb.ACCEPTED:
                            provisioned.add(d.frm)

            anchor_postman.stop()

            self.assertEqual(len(provisioned), len(node_keys))

            expected_roster = tuple(sorted(kp.public for kp in node_keys))
            for n in nodes:
                self.assertIsNotNone(n.store.head_block_num())
                self.assertEqual(n.store.mgmt_reader.roster(), expected_roster)
        finally:
            for n in nodes:
                n.stop()
            for s in stores:
                s.close()
            for d in dirs:
                shutil.rmtree(d)


if __name__ == "__main__":
    unittest.main()
