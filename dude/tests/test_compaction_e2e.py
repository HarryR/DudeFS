from __future__ import annotations

import unittest

from dude.consensus.settle_round import SettledBlock
from dude.core import crypto
from dude.store import Store, ops
from dude.store.checkpoint import CheckpointMeta
from dude.session import Settled
from dude.store.management import (
    Cert,
    MgmtWriter,
    Role,
)
from dude.store.smt_sync import TreeExporter, TreeImporter
from dude.tests.cluster import Cluster


class TestCompactionEndToEnd(unittest.TestCase):

    def _boot(self):
        c = Cluster(nodes=3, mgmt=1)
        s = c.replicas[0].session()
        return c, s

    def _grant_compactor(self, c):
        kp = crypto.Keypair.generate()
        anchor_node = c.boot_replica(c.anchor)
        c.wait_head(c.nodes[0].store.head(), nodes=[anchor_node])
        anchor_s = anchor_node.session()
        w = anchor_node.store.mgmt_writer
        c.wait_settled(
            anchor_s.submit(w.authorise(
                kp.public,
                Role.COMPACTOR,
                stores=frozenset({ops.STORE_MANAGEMENT}),
                pop=kp.prove_possession(),
                cert=Cert.sign_grant(c.anchor, kp.public, Role.COMPACTOR),
            )).wait(),
        )
        return kp

    def _compactor_session(self, c, compactor_kp):
        rn = c.boot_replica(compactor_kp)
        c.wait_head(c.nodes[0].store.head(), nodes=[rn])
        return rn.session(store_id=ops.STORE_MANAGEMENT)

    def _submit_pivot(self, c, cs):
        block_num = c.nodes[0].store.head_block_num() or 0
        c.wait_settled(cs.submit(MgmtWriter(cs).compact(block_num)).wait())

    def _checkpoint_from(self, store, anchor):
        compactor_kp = crypto.Keypair.generate()
        grant_cert = Cert.sign_grant(anchor, compactor_kp.public, Role.COMPACTOR)
        with store.snapshot() as reader:
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

    def _load_from_checkpoint(self, meta, chunks, anchor_pub):
        why = meta.verify_compactor(anchor_pub)
        if why is not None:
            raise AssertionError(f"compactor verify: {why}")
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
            raise AssertionError(f"quorum verify: {why}")
        return dst

    def _replay_above(self, source, dst, pivot):
        mgmt = dst.mgmt_reader
        for n in range(pivot + 1, (source.head_block_num() or 0) + 1):
            sb_bytes = source.settled_at(n)
            if sb_bytes is None:
                continue
            sb = SettledBlock.decode(sb_bytes)
            dst.commit_block(
                sb.anchors.block_num,
                first_height=dst.head() + 1,
                block_bytes=sb_bytes,
                block_hash=sb.block_hash,
                batch=source.bodies_of_block(n),
                auth=mgmt,
            )

    def test_full_compaction_through_consensus(self):
        c, s = self._boot()
        try:
            last = None
            for i in range(5):
                last = s.put(f"data-{i}", f"value-{i}".encode()).wait()
            c.wait_settled(last)

            compactor_kp = self._grant_compactor(c)
            cs = self._compactor_session(c, compactor_kp)
            self._submit_pivot(c, cs)

            roots = {n.store.state_root() for n in c.nodes}
            accs = {n.store.accumulator() for n in c.nodes}
            self.assertEqual(len(roots), 1, "nodes disagree on state_root after pivot")
            self.assertEqual(len(accs), 1, "nodes disagree on accumulator after pivot")

            held = c.nodes[0].store.get(ops.STORE_MANAGEMENT, b"compact")
            self.assertIsNotNone(held, "compact/ key not set after pivot")
        finally:
            c.close()

    def test_gc_all_nodes_then_joiner_catches_up(self):
        c, s = self._boot()
        try:
            last = None
            for i in range(5):
                last = s.put(f"k{i}", f"v{i}".encode()).wait()
            c.wait_settled(last)

            compactor_kp = self._grant_compactor(c)
            cs = self._compactor_session(c, compactor_kp)

            for i in range(3):
                last = s.put(f"pre-pivot-{i}", f"p{i}".encode()).wait()
            c.wait_settled(last)

            self._submit_pivot(c, cs)

            source = c.nodes[0].store
            meta, chunks, pivot = self._checkpoint_from(source, c.anchor)

            for i in range(3):
                last = s.put(f"post-pivot-{i}", f"pp{i}".encode()).wait()
            c.wait_settled(last)
            c.close()

            for n in c.nodes:
                n.store.gc_below(pivot)

            dst = self._load_from_checkpoint(meta, chunks, c.anchor.public)
            self._replay_above(source, dst, pivot)

            self.assertEqual(dst.accumulator(), source.accumulator())
            self.assertEqual(dst.log_accumulator(), source.log_accumulator())
            self.assertEqual(dst.state_root(), source.state_root())
            self.assertEqual(dst.head(), source.head())
            self.assertEqual(dst.head_block_num(), source.head_block_num())
        except Exception:
            c.close()
            raise

    def test_all_nodes_converge_after_gc(self):
        c, s = self._boot()
        try:
            last = None
            for i in range(5):
                last = s.put(f"d{i}", f"v{i}".encode()).wait()
            c.wait_settled(last)

            compactor_kp = self._grant_compactor(c)
            cs = self._compactor_session(c, compactor_kp)
            self._submit_pivot(c, cs)

            pivot_block = c.nodes[0].store.head_block_num()
            for n in c.nodes:
                n.store.gc_below(pivot_block)

            roots = {n.store.state_root() for n in c.nodes}
            accs = {n.store.accumulator() for n in c.nodes}
            log_accs = {n.store.log_accumulator() for n in c.nodes}
            self.assertEqual(len(roots), 1, "state_roots diverge after GC")
            self.assertEqual(len(accs), 1, "accumulators diverge after GC")
            self.assertEqual(len(log_accs), 1, "log accumulators diverge after GC")

            for n in c.nodes:
                self.assertIsNone(n.store.settled_at(0), "block 0 should be GC'd")
                self.assertIsNotNone(
                    n.store.settled_at(pivot_block), "pivot block should survive"
                )
        finally:
            c.close()

    def test_consecutive_pivots(self):
        c, s = self._boot()
        try:
            last = None
            for i in range(3):
                last = s.put(f"wave1-{i}", f"a{i}".encode()).wait()
            c.wait_settled(last)

            compactor_kp = self._grant_compactor(c)
            cs = self._compactor_session(c, compactor_kp)
            self._submit_pivot(c, cs)

            for i in range(3):
                last = s.put(f"wave2-{i}", f"b{i}".encode()).wait()
            c.wait_settled(last)

            self._submit_pivot(c, cs)

            source = c.nodes[0].store
            meta, chunks, pivot = self._checkpoint_from(source, c.anchor)
            c.close()

            source.gc_below(pivot)
            dst = self._load_from_checkpoint(meta, chunks, c.anchor.public)

            self.assertEqual(dst.accumulator(), source.accumulator())
            self.assertEqual(dst.state_root(), source.state_root())
        except Exception:
            c.close()
            raise


if __name__ == "__main__":
    unittest.main()
