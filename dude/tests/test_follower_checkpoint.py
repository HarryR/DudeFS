from __future__ import annotations

import unittest

from dude.core import crypto
from dude.store import ops
from dude.store.checkpoint import CheckpointMeta
from dude.store.management import Cert, MgmtWriter, Role
from dude.sync.checkpoint_server import CheckpointServer
from dude.tests.cluster import Cluster


class TestColdJoinerCatchesUpViaCheckpoint(unittest.TestCase):
    def test_joiner_downloads_checkpoint_and_converges(self):
        c = Cluster(nodes=3, mgmt=1)
        try:
            s = c.replicas[0].session()
            last = None
            for i in range(5):
                last = s.put(f"k{i}", f"v{i}".encode()).wait()
            c.wait_settled(last)

            anchor_node = c.boot_replica(c.anchor)
            c.wait_head(c.nodes[0].store.head(), nodes=[anchor_node])
            anchor_s = anchor_node.session()
            compactor_kp = crypto.Keypair.generate()
            w = anchor_node.store.mgmt_writer
            c.wait_settled(
                anchor_s.submit(
                    w.authorise(
                        compactor_kp.public,
                        Role.COMPACTOR,
                        stores=frozenset({ops.STORE_MANAGEMENT}),
                        pop=compactor_kp.prove_possession(),
                        cert=Cert.sign_grant(c.anchor, compactor_kp.public, Role.COMPACTOR),
                    )
                ).wait()
            )

            compactor_node = c.boot_replica(compactor_kp)
            c.wait_head(c.nodes[0].store.head(), nodes=[compactor_node])
            cs = compactor_node.session(store_id=ops.STORE_MANAGEMENT)
            c.wait_settled(
                cs.submit(MgmtWriter(cs).compact(c.nodes[0].store.head_block_num() or 0)).wait()
            )

            source = c.nodes[0]
            grant_cert = Cert.sign_grant(c.anchor, compactor_kp.public, Role.COMPACTOR)
            with source.store.snapshot() as reader:
                pivot = reader.head_block_num()
                assert pivot is not None
                sb_bytes = reader.settled_at(pivot)
                assert sb_bytes is not None
                meta = CheckpointMeta.create(
                    settled_block_bytes=sb_bytes,
                    anchor=c.anchor.public,
                    compactor=crypto.Keypair.from_seed(compactor_kp.seed),
                    grant_cert=grant_cert,
                )
            srv = CheckpointServer.create_and_persist(source.store, meta)
            source.checkpoint_server = srv

            for n in c.nodes:
                assert pivot is not None
                n.store.gc_below(pivot)

            joiner_kp = crypto.Keypair.generate()
            c.wait_settled(
                anchor_s.submit(
                    w.authorise(
                        joiner_kp.public,
                        Role.MANAGER,
                        stores=frozenset({ops.STORE_MANAGEMENT, ops.STORE_DATA}),
                        pop=joiner_kp.prove_possession(),
                        cert=Cert.sign_grant(c.anchor, joiner_kp.public, Role.MANAGER),
                    )
                ).wait()
            )

            joiner = c.boot_replica(joiner_kp)
            c.wait_head(c.nodes[0].store.head(), nodes=[joiner])

            self.assertEqual(
                joiner.store.accumulator(),
                source.store.accumulator(),
            )
            self.assertEqual(
                joiner.store.state_root(),
                source.store.state_root(),
            )
        finally:
            c.close()


if __name__ == "__main__":
    unittest.main()
