from __future__ import annotations

import unittest

from dude.core import crypto
from dude.session import Settled
from dude.store import Store, ops
from dude.store.checkpoint import CheckpointMeta
from dude.store.management import Cert, MgmtReader, MgmtWriter, Role
from dude.store.smt_sync import TreeImporter
from dude.sync.checkpoint_adapter import (
    CheckpointMetaReply,
    ChunksReply,
    GetCheckpoint,
    GetChunks,
)
from dude.sync.checkpoint_server import CheckpointServer
from dude.tests.cluster import Cluster


class TestCheckpointWire(unittest.TestCase):

    def _boot_with_data(self):
        c = Cluster(nodes=3, mgmt=1)
        s = c.replicas[0].session()
        for i in range(5):
            s.put(f"k{i}", f"v{i}".encode()).wait()
        c.wait_block(4)
        return c, s

    def _grant_and_pivot(self, c):
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
        if not isinstance(result, Settled):
            raise AssertionError(f"grant: {result!r}")  # noqa: TRY004
        c.wait_head(c.nodes[0].store.head())

        compactor_node = c.boot_replica(compactor_kp)
        c.wait_head(c.nodes[0].store.head(), nodes=[compactor_node])
        cs = compactor_node.session()
        result = cs.compact(c.nodes[0].store.head_block_num() or 0).wait()
        if not isinstance(result, Settled):
            raise AssertionError(f"pivot: {result!r}")  # noqa: TRY004
        c.wait_head(c.nodes[0].store.head())
        return compactor_kp

    def _install_checkpoint_server(self, c, compactor_kp):
        node = c.nodes[0]
        grant_cert = Cert.sign_grant(c.anchor, compactor_kp.public, Role.COMPACTOR)
        with node.store.snapshot() as reader:
            pivot = reader.head_block_num()
            sb_bytes = reader.settled_at(pivot)
            meta = CheckpointMeta.create(
                settled_block_bytes=sb_bytes,
                anchor=c.anchor.public,
                compactor=crypto.Keypair.from_seed(compactor_kp.seed),
                grant_cert=grant_cert,
            )
        srv = CheckpointServer.create_and_persist(
            node.store, meta, max_chunk_bytes=10_000, batch_size=3,
        )
        node.checkpoint_server = srv
        return meta

    def test_checkpoint_adapter_roundtrip(self):
        get_cp = GetCheckpoint()
        _verb, body = get_cp.encode()
        self.assertEqual(body, b"")

        get_ch = GetChunks(offset=5)
        _verb, body = get_ch.encode()
        decoded = GetChunks.decode(body)
        self.assertEqual(decoded.offset, 5)

    def test_serve_meta_and_chunks(self):
        c, _s = self._boot_with_data()
        try:
            compactor_kp = self._grant_and_pivot(c)
            self._install_checkpoint_server(c, compactor_kp)

            srv = c.nodes[0].checkpoint_server
            meta_reply = srv.serve_meta()
            self.assertIsInstance(meta_reply, CheckpointMetaReply)
            restored = CheckpointMeta.decode(meta_reply.meta_bytes)
            self.assertIsNone(restored.verify_compactor(c.anchor.public))

            all_chunks = []
            offset = 0
            while True:
                reply = srv.serve_chunks(GetChunks(offset=offset))
                self.assertIsInstance(reply, ChunksReply)
                all_chunks.extend(reply.chunks)
                if not reply.more:
                    break
                offset += len(reply.chunks)
            self.assertGreater(len(all_chunks), 0)
        finally:
            c.close()

    def test_full_checkpoint_load_from_server(self):
        c, _s = self._boot_with_data()
        try:
            compactor_kp = self._grant_and_pivot(c)
            self._install_checkpoint_server(c, compactor_kp)

            srv = c.nodes[0].checkpoint_server
            meta_reply = srv.serve_meta()
            restored_meta = CheckpointMeta.decode(meta_reply.meta_bytes)

            why = restored_meta.verify_compactor(c.anchor.public)
            self.assertIsNone(why, f"compactor verify: {why}")

            dst = Store()
            with dst.write() as w:
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

            roster = tuple(sorted(MgmtReader(dst).roster()))
            why = restored_meta.verify_quorum(roster)
            self.assertIsNone(why, f"quorum verify: {why}")

            source = c.nodes[0].store
            self.assertEqual(dst.accumulator(), source.accumulator())
            self.assertEqual(dst.state_root(), source.state_root())
        finally:
            c.close()

    def test_chunks_reply_encodes_and_decodes(self):
        c, _s = self._boot_with_data()
        try:
            compactor_kp = self._grant_and_pivot(c)
            self._install_checkpoint_server(c, compactor_kp)

            srv = c.nodes[0].checkpoint_server
            first_batch = srv.serve_chunks(GetChunks(offset=0))
            self.assertGreater(len(first_batch.chunks), 0)

            reply = ChunksReply(chunks=first_batch.chunks[:2], more=True)
            _verb, body = reply.encode()
            decoded = ChunksReply.decode(body)
            self.assertEqual(len(decoded.chunks), len(reply.chunks))
            self.assertTrue(decoded.more)
            for orig, dec in zip(reply.chunks, decoded.chunks, strict=True):
                self.assertEqual(orig.depth, dec.depth)
                self.assertEqual(orig.subtree_hash, dec.subtree_hash)
                self.assertEqual(len(orig.rows), len(dec.rows))
        finally:
            c.close()


if __name__ == "__main__":
    unittest.main()
