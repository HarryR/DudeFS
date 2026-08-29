from __future__ import annotations

import unittest

from dude.consensus.settle_round import SettledBlock
from dude.core import crypto
from dude.store import Store
from dude.store.checkpoint import CheckpointMeta
from dude.store.management import Cert, Role
from dude.store.smt_sync import TreeExporter, TreeImporter
from dude.tests.cluster import Cluster


class TestCheckpointRoundTrip(unittest.TestCase):
    def _make_cluster_with_data(self, n_keys: int = 5):
        c = Cluster(nodes=3, mgmt=1)
        s = c.replicas[0].session()
        last = None
        for i in range(n_keys):
            last = s.put(f"key-{i}", f"value-{i}".encode()).wait()
        c.wait_settled(last)
        c.close()
        return c

    def _checkpoint_at_head(self, source: Store, anchor: crypto.Keypair):
        compactor_kp = crypto.Keypair.generate()
        grant_cert = Cert.sign_grant(anchor, compactor_kp.public, Role.COMPACTOR)

        with source.snapshot() as reader:
            pivot = reader.head_block_num()
            sb_bytes = reader.settled_at(pivot)
            meta = CheckpointMeta.create(
                settled_block_bytes=sb_bytes,
                anchor=anchor.public,
                compactor=compactor_kp,
                grant_cert=grant_cert,
            )
            chunks = list(TreeExporter(reader, max_chunk_bytes=50_000).chunks())

        return meta, chunks, pivot

    def _load_checkpoint(self, meta: CheckpointMeta, chunks: list, anchor_pub):
        why = meta.verify_compactor(anchor_pub)
        if why is not None:
            raise AssertionError(f"compactor verify failed: {why}")

        dst = Store()
        with dst.write() as w:
            importer = TreeImporter(w, expected_root=meta.state_root)
            for chunk in chunks:
                importer.load(chunk)
            importer.verify()
            w.bootstrap_checkpoint(meta.anchor, meta.settled_block_bytes)

        roster = tuple(sorted(dst.mgmt_reader.roster()))
        why = meta.verify_quorum(roster)
        if why is not None:
            raise AssertionError(f"quorum verify failed: {why}")

        return dst

    def _replay_above(self, source: Store, dst: Store, pivot: int):
        head_num = source.head_block_num()
        mgmt = dst.mgmt_reader
        for n in range(pivot + 1, (head_num or 0) + 1):
            sb_bytes = source.settled_at(n)
            if sb_bytes is None:
                continue
            sb = SettledBlock.decode(sb_bytes)
            bodies = source.bodies_of_block(n)
            dst.commit_block(
                sb.anchors.block_num,
                first_height=dst.head() + 1,
                block_bytes=sb_bytes,
                block_hash=sb.block_hash,
                batch=bodies,
                auth=mgmt,
            )

    def test_checkpoint_produces_matching_state(self):
        c = self._make_cluster_with_data(5)
        source = c.nodes[0].store

        meta, chunks, _pivot = self._checkpoint_at_head(source, c.anchor)
        dst = self._load_checkpoint(meta, chunks, c.anchor.public)

        self.assertEqual(dst.accumulator(), source.accumulator())
        self.assertEqual(dst.log_accumulator(), source.log_accumulator())
        self.assertEqual(dst.state_root(), source.state_root())

    def test_post_pivot_replay_matches(self):
        c = Cluster(nodes=3, mgmt=1)
        s = c.replicas[0].session()
        last = None
        for i in range(3):
            last = s.put(f"early-{i}", f"v{i}".encode()).wait()
        c.wait_settled(last)

        source = c.nodes[0].store
        meta, chunks, pivot = self._checkpoint_at_head(source, c.anchor)

        for i in range(3):
            last = s.put(f"late-{i}", f"v{i}".encode()).wait()
        c.wait_settled(last)
        c.close()

        dst = self._load_checkpoint(meta, chunks, c.anchor.public)
        self._replay_above(source, dst, pivot)

        self.assertEqual(dst.accumulator(), source.accumulator())
        self.assertEqual(dst.log_accumulator(), source.log_accumulator())
        self.assertEqual(dst.state_root(), source.state_root())
        self.assertEqual(dst.head(), source.head())
        self.assertEqual(dst.head_block_num(), source.head_block_num())

    def test_holds_guards_pass_after_checkpoint(self):
        c = Cluster(nodes=3, mgmt=1)
        s = c.replicas[0].session()
        c.wait_settled(s.put("guarded", b"v1").wait())

        source = c.nodes[0].store
        meta, chunks, pivot = self._checkpoint_at_head(source, c.anchor)

        rec = s.get("guarded")
        c.wait_settled(s.put("guarded", b"v2", expect=rec).wait())
        c.close()

        dst = self._load_checkpoint(meta, chunks, c.anchor.public)
        self._replay_above(source, dst, pivot)

        self.assertEqual(dst.accumulator(), source.accumulator())
        self.assertEqual(dst.state_root(), source.state_root())

    def test_all_values_readable_after_checkpoint(self):
        c = self._make_cluster_with_data(8)
        source = c.nodes[0].store

        meta, chunks, _pivot = self._checkpoint_at_head(source, c.anchor)
        dst = self._load_checkpoint(meta, chunks, c.anchor.public)

        root_prefix = bytes(crypto.DIGEST_SIZE)
        with source.snapshot() as r:
            src_rows = r.subtree_rows(root_prefix, 0)
        with dst.snapshot() as r:
            dst_rows = r.subtree_rows(root_prefix, 0)
        self.assertEqual(len(dst_rows), len(src_rows))
        for s_row, d_row in zip(src_rows, dst_rows, strict=True):
            self.assertEqual(s_row, d_row)

    def test_gc_then_checkpoint_then_replay(self):
        c = Cluster(nodes=3, mgmt=1)
        s = c.replicas[0].session()
        last = None
        for i in range(5):
            last = s.put(f"k{i}", f"v{i}".encode()).wait()
        c.wait_settled(last)

        source = c.nodes[0].store
        meta, chunks, pivot = self._checkpoint_at_head(source, c.anchor)

        for i in range(3):
            last = s.put(f"post-{i}", f"p{i}".encode()).wait()
        c.wait_settled(last)
        c.close()

        source.gc_below(pivot)
        dst = self._load_checkpoint(meta, chunks, c.anchor.public)
        self._replay_above(source, dst, pivot)

        self.assertEqual(dst.accumulator(), source.accumulator())
        self.assertEqual(dst.state_root(), source.state_root())
        self.assertEqual(dst.head(), source.head())


if __name__ == "__main__":
    unittest.main()
