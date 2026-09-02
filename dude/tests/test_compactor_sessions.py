from __future__ import annotations

import unittest

from dude.core import crypto
from dude.net.postman import Postman
from dude.store import ops
from dude.store.checkpoint import CheckpointMeta
from dude.store.management import Cert, MgmtWriter, Role
from dude.sync.lite_client import LightClient
from dude.tests.cluster import Cluster


class TestCompactorFromReplicaNode(unittest.TestCase):
    def test_replica_compactor_submits_pivot(self):
        c = Cluster(nodes=3, mgmt=1)
        try:
            s = c.replicas[0].session()
            last = None
            for i in range(3):
                last = s.put(f"k{i}", f"v{i}".encode()).wait()
            c.wait_settled(last)

            anchor_node = c.boot_replica(c.anchor)
            c.wait_head(c.nodes[0].store.head(), nodes=[anchor_node])
            w = anchor_node.store.mgmt_writer

            compactor_kp = crypto.Keypair.generate()
            grant = w.authorise(
                compactor_kp.public,
                Role.COMPACTOR,
                stores=frozenset({ops.STORE_MANAGEMENT}),
                pop=compactor_kp.prove_possession(),
                cert=Cert.sign_grant(c.anchor, compactor_kp.public, Role.COMPACTOR),
            )
            c.wait_settled(anchor_node.session().submit(grant).wait())

            compactor_node = c.boot_replica(compactor_kp)
            c.wait_head(c.nodes[0].store.head(), nodes=[compactor_node])
            cs = compactor_node.session(store_id=ops.STORE_MANAGEMENT)

            block_num = c.nodes[0].store.head_block_num() or 0
            c.wait_settled(cs.submit(MgmtWriter(cs).compact(block_num)).wait())

            held = c.nodes[0].store.get(ops.STORE_MANAGEMENT, b"compact")
            self.assertIsNotNone(held)
        finally:
            c.close()


class TestCompactorFromLightClient(unittest.TestCase):
    def test_light_client_compactor_submits_pivot(self):
        c = Cluster(nodes=3, mgmt=1, rw=0)
        try:
            s = c.replicas[0].session()
            last = None
            for i in range(3):
                last = s.put(f"k{i}", f"v{i}".encode()).wait()
            c.wait_settled(last)

            anchor_node = c.boot_replica(c.anchor)
            c.wait_head(c.nodes[0].store.head(), nodes=[anchor_node])
            w = anchor_node.store.mgmt_writer

            compactor_kp = crypto.Keypair.generate()
            grant = w.authorise(
                compactor_kp.public,
                Role.COMPACTOR,
                stores=frozenset({ops.STORE_MANAGEMENT}),
                pop=compactor_kp.prove_possession(),
                cert=Cert.sign_grant(c.anchor, compactor_kp.public, Role.COMPACTOR),
            )
            c.wait_settled(anchor_node.session().submit(grant).wait())

            postman = Postman(compactor_kp, c.tunables)
            c.nexus.attach(postman)
            lc = LightClient(me=compactor_kp, anchor=c.anchor.public, postman=postman)
            for node in c.nodes:
                lc.add_bootstrap_peer(
                    node.me.public,
                    (c.nexus.endpoint_for(node.me.public),),
                )
            lc.start()
            lc.bootstrap()

            cs = lc.session(store_id=ops.STORE_MANAGEMENT)
            assert lc.trusted_state is not None
            block_num = lc.trusted_state.head.anchors.block_num
            c.wait_settled(cs.submit(MgmtWriter(cs).compact(block_num)).wait())

            held = c.nodes[0].store.get(ops.STORE_MANAGEMENT, b"compact")
            self.assertIsNotNone(held)

            assert lc.trusted_state is not None
            sb = lc.trusted_state.head
            grant_cert = Cert.sign_grant(
                c.anchor,
                compactor_kp.public,
                Role.COMPACTOR,
            )
            meta = CheckpointMeta.create(
                settled_block_bytes=sb.encode(),
                anchor=c.anchor.public,
                compactor=compactor_kp,
                grant_cert=grant_cert,
            )
            self.assertIsNone(meta.verify_compactor(c.anchor.public))

            lc.stop()
        finally:
            c.close()


if __name__ == "__main__":
    unittest.main()
