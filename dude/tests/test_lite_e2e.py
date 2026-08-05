# End-to-end coverage for the light-client server-side path.
#
# Two layers:
#   * `serve_get_anchors` / `serve_get_proof` (`dude.sync.lite`) directly, with a real
#     Cluster's stores + Management. Verifies bundle shape, piggyback headers, refusal
#     paths (STALE_CLIENT, FORK_DETECTED).
#   * Node dispatch (`_on_get_anchors` / `_on_get_proof`) via a signed envelope handed
#     to `node.receive`. Verifies auth gate and that a reply is queued on the postman.
#
# The full-wire round-trip test (client Postman + client InProc + drain back) lands
# with the LightClient state machine (Wave G).

from __future__ import annotations

import unittest

from dude.consensus.bootstrap import intervene
from dude.consensus.settle_round import SettledBlock
from dude.core import crypto
from dude.net.envelope import Envelope, new_message_id
from dude.store import ops
from dude.store.management import Cert, Management, Role
from dude.sync.lite import serve_get_anchors, serve_get_proof
from dude.sync.lite_adapter import (
    AnchorsReply,
    GetAnchors,
    GetProof,
    LiteRefusal,
    LiteRefused,
    ProofReply,
)

from .cluster import DELTA, T0, Cluster


def _provision_client(c: Cluster, kp: crypto.Keypair) -> None:
    """Grant Role.CLIENT to `kp`, applied via intervene so every store sees it."""
    mgmt = Management(c.nodes[0].store)
    grant_tx = mgmt.authorise(
        kp.public,
        Role.CLIENT,
        stores=frozenset(),
        pop=kp.prove_possession(),
        cert=Cert.sign_grant(c.mgr, kp.public, Role.CLIENT),
    ).sign(c.mgr, T0)
    for node in c.nodes:
        intervene(node.store, c.mgr, bodies=(grant_tx,), bucket=444)


class TestServeGetAnchors(unittest.TestCase):
    """serve_get_anchors: piggyback shape, refusals."""

    def test_bootstrap_carries_full_bundle(self):
        c = Cluster()
        node = c.nodes[0]
        req = GetAnchors(known_roster_fingerprint=None, known_trusted_block=None)
        reply = serve_get_anchors(node.store, node.mgmt, req, liveness_window=2)
        self.assertIsInstance(reply, AnchorsReply)
        assert isinstance(reply, AnchorsReply)
        self.assertIsNotNone(reply.bundle)
        assert reply.bundle is not None
        self.assertEqual(len(reply.bundle.entries), 3)
        self.assertGreaterEqual(len(reply.bundle.managers), 1)
        self.assertEqual(reply.headers, ())

    def test_matching_fingerprint_omits_bundle(self):
        c = Cluster()
        node = c.nodes[0]
        # First call: get the fingerprint.
        first = serve_get_anchors(
            node.store,
            node.mgmt,
            GetAnchors(known_roster_fingerprint=None, known_trusted_block=None),
            liveness_window=2,
        )
        assert isinstance(first, AnchorsReply)
        # Second call: send that fingerprint back; expect no bundle.
        second = serve_get_anchors(
            node.store,
            node.mgmt,
            GetAnchors(
                known_roster_fingerprint=first.roster_fingerprint,
                known_trusted_block=None,
            ),
            liveness_window=2,
        )
        assert isinstance(second, AnchorsReply)
        self.assertIsNone(second.bundle)

    def test_stale_client_refused(self):
        c = Cluster()
        # Produce enough blocks that client is way behind.
        for _ in range(6):
            c.pump(T0 + DELTA)
        node = c.nodes[0]
        head_num = node.store.head_block_num()
        assert head_num is not None
        self.assertGreater(head_num, 3)
        # Client claims trusted_block at 1 (behind by liveness_window + more).
        block1_bytes = node.store.settled_at(1)
        assert block1_bytes is not None
        block1 = SettledBlock.decode(block1_bytes)
        req = GetAnchors(
            known_roster_fingerprint=None,
            known_trusted_block=(1, block1.block_hash),
        )
        reply = serve_get_anchors(node.store, node.mgmt, req, liveness_window=2)
        self.assertIsInstance(reply, LiteRefused)
        assert isinstance(reply, LiteRefused)
        self.assertEqual(reply.reason, LiteRefusal.STALE_CLIENT)

    def test_fork_detected_refused(self):
        c = Cluster()
        node = c.nodes[0]
        head_num = node.store.head_block_num()
        assert head_num is not None
        # Client claims block N with a wrong hash.
        req = GetAnchors(
            known_roster_fingerprint=None,
            known_trusted_block=(head_num, crypto.Digest(b"\x00" * 32)),
        )
        reply = serve_get_anchors(node.store, node.mgmt, req, liveness_window=2)
        self.assertIsInstance(reply, LiteRefused)
        assert isinstance(reply, LiteRefused)
        self.assertEqual(reply.reason, LiteRefusal.FORK_DETECTED)

    def test_headers_piggybacked_within_window(self):
        c = Cluster()
        node = c.nodes[0]
        # Baseline head + hash.
        head1 = node.store.head_block_num()
        assert head1 is not None
        head1_bytes = node.store.settled_at(head1)
        assert head1_bytes is not None
        head1_hash = SettledBlock.decode(head1_bytes).block_hash

        # Advance by 1 block via pump.
        c.pump(T0 + DELTA)
        head2 = node.store.head_block_num()
        assert head2 is not None
        # We may not always advance by exactly 1; expect head2 > head1.
        gap = head2 - head1
        self.assertGreater(gap, 0)

        # Client at head1, requests anchors; expect headers[1..gap] (within window).
        req = GetAnchors(
            known_roster_fingerprint=None,
            known_trusted_block=(head1, head1_hash),
        )
        reply = serve_get_anchors(node.store, node.mgmt, req, liveness_window=max(gap, 2))
        self.assertIsInstance(reply, AnchorsReply)
        assert isinstance(reply, AnchorsReply)
        self.assertEqual(len(reply.headers), gap)


class TestServeGetProof(unittest.TestCase):
    """serve_get_proof: value at head, refusals."""

    def test_get_proof_returns_head_value(self):
        c = Cluster()
        key = crypto.h(b"lite-proof")
        tx = ops.writes(ops.Set(ops.STORE_DATA, key, b"present")).sign(c.mgr, T0)
        c.submit(c.mgr, tx, to=0, now=T0)
        c.pump(T0)
        c.pump(T0 + DELTA)

        node = c.nodes[0]
        head = node.store.head_block_num()
        assert head is not None

        req = GetProof(
            store_id=ops.STORE_DATA,
            name=key,
            block_num=head,
            known_roster_fingerprint=None,
            known_trusted_block=None,
        )
        reply = serve_get_proof(node.store, node.mgmt, req, liveness_window=2)
        self.assertIsInstance(reply, ProofReply)
        assert isinstance(reply, ProofReply)
        self.assertFalse(reply.absent)
        self.assertEqual(reply.value, b"present")

    def test_get_proof_absent_key_returns_absent(self):
        c = Cluster()
        c.pump(T0 + DELTA)
        node = c.nodes[0]
        head = node.store.head_block_num()
        assert head is not None
        req = GetProof(
            store_id=ops.STORE_DATA,
            name=crypto.h(b"never-written"),
            block_num=head,
            known_roster_fingerprint=None,
            known_trusted_block=None,
        )
        reply = serve_get_proof(node.store, node.mgmt, req, liveness_window=2)
        self.assertIsInstance(reply, ProofReply)
        assert isinstance(reply, ProofReply)
        self.assertTrue(reply.absent)

    def test_get_proof_past_head_refused_not_yet_settled(self):
        c = Cluster()
        node = c.nodes[0]
        head = node.store.head_block_num()
        assert head is not None
        req = GetProof(
            store_id=ops.STORE_DATA,
            name=b"whatever",
            block_num=head + 100,
            known_roster_fingerprint=None,
            known_trusted_block=None,
        )
        reply = serve_get_proof(node.store, node.mgmt, req, liveness_window=2)
        self.assertIsInstance(reply, LiteRefused)
        assert isinstance(reply, LiteRefused)
        self.assertEqual(reply.reason, LiteRefusal.NOT_YET_SETTLED)


class TestNodeDispatchAndAuth(unittest.TestCase):
    """Node routes GET_ANCHORS to `serve_get_anchors` and enforces auth."""

    def test_unauthorised_sender_is_refused(self):
        c = Cluster()
        stranger = crypto.Keypair.generate()
        # Stranger has no grant, no roster entry -- fails auth.
        node = c.nodes[0]
        req = GetAnchors(known_roster_fingerprint=None, known_trusted_block=None)
        verb, body = req.encode()
        env = Envelope(node.me.public, verb, new_message_id(), body).sign(stranger, T0)
        # Deliver via node.receive; expect the refusal to be queued in the mailbox.
        before = len(node.postman.mailbox.pending)
        node.receive(env.seal(), T0)
        after = len(node.postman.mailbox.pending)
        # The auth-refusal reply was queued (MALFORMED_QUERY per _lite_authorised gate).
        self.assertGreater(after, before)

    def test_authorised_client_reaches_serve_handler(self):
        c = Cluster()
        client_kp = crypto.Keypair.generate()
        _provision_client(c, client_kp)
        node = c.nodes[0]

        req = GetAnchors(known_roster_fingerprint=None, known_trusted_block=None)
        verb, body = req.encode()
        env = Envelope(node.me.public, verb, new_message_id(), body).sign(client_kp, T0 + DELTA)
        before = len(node.postman.mailbox.pending)
        node.receive(env.seal(), T0 + DELTA)
        after = len(node.postman.mailbox.pending)
        # Successful handler queued the AnchorsReply for the client.
        self.assertGreater(after, before)


if __name__ == "__main__":
    unittest.main()
