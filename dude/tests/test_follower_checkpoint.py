from __future__ import annotations

import time
import unittest

from dude.core import crypto
from dude.session import Settled
from dude.store import ops
from dude.store.checkpoint import CheckpointMeta
from dude.store.management import Cert, MgmtReader, MgmtWriter, Role
from dude.store.smt_sync import TreeExporter, TreeImporter
from dude.sync.checkpoint_adapter import GetChunks
from dude.sync.checkpoint_server import CheckpointServer
from dude.tests.cluster import Cluster


class TestFollowerCheckpointFallback(unittest.TestCase):

    def test_follower_detects_compacted_and_resets(self):
        c = Cluster(nodes=3, mgmt=1)
        try:
            s = c.replicas[0].session()
            for i in range(5):
                s.put(f"k{i}", f"v{i}".encode()).wait()
            c.wait_block(4)

            anchor_node = c.boot_replica(c.anchor)
            c.wait_head(c.nodes[0].store.head(), nodes=[anchor_node])
            anchor_s = anchor_node.session()
            compactor_kp = crypto.Keypair.generate()
            w = MgmtWriter(anchor_node.store)
            grant_tx = w.authorise(
                compactor_kp.public,
                Role.COMPACTOR,
                stores=frozenset({ops.STORE_MANAGEMENT}),
                pop=compactor_kp.prove_possession(),
                cert=Cert.sign_grant(c.anchor, compactor_kp.public, Role.COMPACTOR),
            )
            result = anchor_s.submit(grant_tx).wait()
            self.assertIsInstance(result, Settled)
            c.wait_head(c.nodes[0].store.head())

            compactor_node = c.boot_replica(compactor_kp)
            c.wait_head(c.nodes[0].store.head(), nodes=[compactor_node])
            cs = compactor_node.session()
            result = cs.compact(c.nodes[0].store.head_block_num() or 0).wait()
            self.assertIsInstance(result, Settled)
            c.wait_head(c.nodes[0].store.head())

            source = c.nodes[0]
            grant_cert = Cert.sign_grant(
                c.anchor, compactor_kp.public, Role.COMPACTOR,
            )
            with source.store.snapshot() as reader:
                pivot = reader.head_block_num()
                sb_bytes = reader.settled_at(pivot)
                meta = CheckpointMeta.create(
                    settled_block_bytes=sb_bytes,
                    anchor=c.anchor.public,
                    compactor=crypto.Keypair.from_seed(compactor_kp.seed),
                    grant_cert=grant_cert,
                )
                chunks = tuple(
                    TreeExporter(reader, max_chunk_bytes=50_000).chunks()
                )
            srv = CheckpointServer(meta, chunks, batch_size=5)
            source.checkpoint_server = srv

            for i in range(3):
                s.put(f"post-{i}", f"pp{i}".encode()).wait()
            c.wait_head(c.nodes[0].store.head())

            for n in c.nodes:
                n.store.gc_below(pivot)

            joiner_kp = crypto.Keypair.generate()
            joiner_grant = w.authorise(
                joiner_kp.public,
                Role.CLIENT_RW,
                stores=frozenset({ops.STORE_DATA}),
                pop=joiner_kp.prove_possession(),
                cert=Cert.sign_grant(c.anchor, joiner_kp.public, Role.CLIENT_RW),
            )
            result = anchor_s.submit(joiner_grant).wait()
            self.assertIsInstance(result, Settled)
            c.wait_head(c.nodes[0].store.head())
            late_joiner = c.boot_replica(joiner_kp)

            deadline = time.monotonic() + 15.0
            checkpoint_num = None
            while time.monotonic() < deadline:
                checkpoint_num = late_joiner.follower.needs_checkpoint()
                if checkpoint_num is not None:
                    break
                time.sleep(0.05)
            self.assertIsNotNone(
                checkpoint_num, "follower did not detect compaction",
            )

            meta_reply = srv.serve_meta()
            restored_meta = CheckpointMeta.decode(meta_reply.meta_bytes)
            why = restored_meta.verify_compactor(c.anchor.public)
            self.assertIsNone(why, f"compactor verify: {why}")

            with late_joiner.store.write() as w:
                w.reset_for_checkpoint()
                importer = TreeImporter(w, expected_root=restored_meta.state_root)
                offset = 0
                while True:
                    reply = srv.serve_chunks(GetChunks(offset=offset))
                    for chunk in reply.chunks:
                        importer.load(chunk)
                    if not reply.more:
                        break
                    offset += len(reply.chunks)
                importer.verify()
                w.bootstrap_checkpoint(
                    restored_meta.anchor, restored_meta.settled_block_bytes,
                )

            roster = tuple(sorted(MgmtReader(late_joiner.store).roster()))
            why = restored_meta.verify_quorum(roster)
            self.assertIsNone(why, f"quorum verify: {why}")

            c.wait_head(
                c.nodes[0].store.head(), nodes=[late_joiner],
            )

            self.assertEqual(
                late_joiner.store.accumulator(),
                source.store.accumulator(),
            )
            self.assertEqual(
                late_joiner.store.state_root(),
                source.store.state_root(),
            )
        finally:
            c.close()


if __name__ == "__main__":
    unittest.main()
