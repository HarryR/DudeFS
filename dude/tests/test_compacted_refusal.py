from __future__ import annotations

import unittest

from dude.sync.adapter import GetBlocks, SettledBlockReply, SyncMsg, SyncRefused
from dude.sync.follower import serve_getblocks
from dude.sync.refusal import SyncRefusedReason
from dude.tests.cluster import Cluster


class TestCompactedRefusalWire(unittest.TestCase):
    def test_compacted_with_payload_roundtrips(self):
        msg = SyncRefused(reason=SyncRefusedReason.COMPACTED, checkpoint_block_num=42)
        verb, body = msg.encode()
        decoded = SyncMsg.decode(verb, body)
        assert isinstance(decoded, SyncRefused)
        self.assertEqual(decoded.reason, SyncRefusedReason.COMPACTED)
        self.assertEqual(decoded.checkpoint_block_num, 42)

    def test_plain_refusal_still_roundtrips(self):
        msg = SyncRefused(reason=SyncRefusedReason.NOT_YET_SETTLED)
        verb, body = msg.encode()
        decoded = SyncMsg.decode(verb, body)
        assert isinstance(decoded, SyncRefused)
        self.assertEqual(decoded.reason, SyncRefusedReason.NOT_YET_SETTLED)
        self.assertIsNone(decoded.checkpoint_block_num)

    def test_compacted_without_payload_roundtrips(self):
        msg = SyncRefused(reason=SyncRefusedReason.COMPACTED)
        verb, body = msg.encode()
        decoded = SyncMsg.decode(verb, body)
        assert isinstance(decoded, SyncRefused)
        self.assertEqual(decoded.reason, SyncRefusedReason.COMPACTED)
        self.assertIsNone(decoded.checkpoint_block_num)


class TestServeGetblocksCompacted(unittest.TestCase):
    def test_gc_then_request_returns_compacted(self):
        c = Cluster(nodes=3, mgmt=1)
        try:
            s = c.replicas[0].session_rw()
            last = None
            for i in range(3):
                last = s.put(f"k{i}", f"v{i}".encode()).wait()
            c.wait_settled(last)

            store = c.nodes[0].store
            pivot = store.head_block_num()
            assert pivot is not None
            store.gc_below(pivot)

            response = serve_getblocks(store, GetBlocks(frm=0, count=5), cap=10)
            assert isinstance(response, SyncRefused)
            self.assertEqual(response.reason, SyncRefusedReason.COMPACTED)
            self.assertEqual(response.checkpoint_block_num, pivot)
        finally:
            c.close()

    def test_request_above_gc_returns_blocks(self):
        c = Cluster(nodes=3, mgmt=1)
        try:
            s = c.replicas[0].session_rw()
            c.wait_settled(s.put("x", b"y").wait())

            store = c.nodes[0].store
            head = store.head_block_num()
            assert head is not None
            store.gc_below(head)

            response = serve_getblocks(store, GetBlocks(frm=head, count=5), cap=10)
            self.assertIsInstance(response, SettledBlockReply)
        finally:
            c.close()

    def test_no_gc_unsettled_returns_not_yet_settled(self):
        c = Cluster(nodes=3, mgmt=1)
        try:
            c.wait_head(c.nodes[0].store.head())
            store = c.nodes[0].store
            future = (store.head_block_num() or 0) + 100
            response = serve_getblocks(store, GetBlocks(frm=future, count=5), cap=10)
            assert isinstance(response, SyncRefused)
            self.assertEqual(response.reason, SyncRefusedReason.NOT_YET_SETTLED)
        finally:
            c.close()
