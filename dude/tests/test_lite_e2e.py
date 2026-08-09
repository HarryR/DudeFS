# End-to-end coverage for the light-client server-side path.
#
# Two layers:
#   * `serve_get_anchors` / `serve_get_proof` (`dude.sync.lite`) directly, with a real
#     Cluster's stores + MgmtWriter. Verifies bundle shape, piggyback headers, and the
#     one refusal a responder can honestly make about a client's head: FORK_DETECTED.
#   * Node dispatch (`_on_get_anchors` / `_on_get_proof`) via a signed envelope handed
#     to `node.receive`. Verifies auth gate and that a reply is queued on the postman.
#
# The full-wire round-trip test (client Postman + client InProc + drain back) lands
# with the LightClient state machine (Wave G).

from __future__ import annotations

import contextlib
import sqlite3
import unittest
from unittest import mock

from dude.consensus.bootstrap import intervene
from dude.consensus.settle_round import SettledBlock
from dude.core import codec, crypto
from dude.net.envelope import Envelope, Verb, new_message_id
from dude.store import Store, ops
from dude.store.management import Cert, MgmtWriter, Role
from dude.sync.lite import serve_get_anchors, serve_get_proof
from dude.sync.lite_adapter import (
    AnchorsReply,
    GetAnchors,
    GetProof,
    LiteAdapterError,
    LiteMsg,
    LiteRefused,
    ProofReply,
    SyncRefusal,
    TrustedBlock,
)

from .cluster import DELTA, T0, TUNABLES, Cluster


def _provision_client(c: Cluster, kp: crypto.Keypair) -> None:
    """Grant Role.CLIENT_RW to `kp`, applied via intervene so every store sees it."""
    mgmt = MgmtWriter(c.nodes[0].store)
    grant_tx = mgmt.authorise(
        kp.public,
        Role.CLIENT_RW,
        stores=frozenset({ops.STORE_DATA}),  # scoped: reads are refused outside it
        pop=kp.prove_possession(),
        cert=Cert.sign_grant(c.mgr, kp.public, Role.CLIENT_RW),
    ).sign(c.mgr, T0)
    for node in c.nodes:
        intervene(node.store, c.mgr, bodies=(grant_tx,), bucket=TUNABLES.mempool.bucket(c.clock))


class TestServeGetAnchors(unittest.TestCase):
    """serve_get_anchors: piggyback shape, refusals."""

    def test_bootstrap_carries_full_bundle(self):
        c = Cluster()
        node = c.nodes[0]
        req = GetAnchors(known_roster_fingerprint=None, known_trusted_block=None)
        reply = serve_get_anchors(node.store, req, liveness_window=2)
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
            GetAnchors(known_roster_fingerprint=None, known_trusted_block=None),
            liveness_window=2,
        )
        assert isinstance(first, AnchorsReply)
        # Second call: send that fingerprint back; expect no bundle.
        second = serve_get_anchors(
            node.store,
            GetAnchors(
                known_roster_fingerprint=first.roster_fingerprint,
                known_trusted_block=None,
            ),
            liveness_window=2,
        )
        assert isinstance(second, AnchorsReply)
        self.assertIsNone(second.bundle)

    def test_a_far_behind_client_is_answered_with_capped_headers(self):
        """It used to be refused STALE_CLIENT. A responder cannot judge whether the client is
        current -- only the client's clock can -- and refusing withheld the very headers that
        would have caught it up. It answers, capped, and the client walks up over more trips."""
        c = Cluster()
        for _ in range(6):
            c.pump(T0 + DELTA)
        node = c.nodes[0]
        head_num = node.store.head_block_num()
        assert head_num is not None
        cap = 2
        self.assertGreater(head_num - 1, cap, "client is not actually far behind")
        block1_bytes = node.store.settled_at(1)
        assert block1_bytes is not None
        block1 = SettledBlock.decode(block1_bytes)
        req = GetAnchors(
            known_roster_fingerprint=None,
            known_trusted_block=TrustedBlock(1, block1.block_hash),
        )
        reply = serve_get_anchors(node.store, req, liveness_window=cap)
        assert isinstance(reply, AnchorsReply), reply
        self.assertEqual(len(reply.headers), cap)
        self.assertEqual(
            [b.anchors.block_num for b in reply.headers],
            [2, 3],
            "headers must be the contiguous run from the client's head, not a suffix",
        )
        self.assertEqual(reply.head.anchors.block_num, head_num)

    def test_fork_detected_refused(self):
        c = Cluster()
        node = c.nodes[0]
        head_num = node.store.head_block_num()
        assert head_num is not None
        # Client claims block N with a wrong hash.
        req = GetAnchors(
            known_roster_fingerprint=None,
            known_trusted_block=TrustedBlock(head_num, crypto.Digest(b"\x00" * 32)),
        )
        reply = serve_get_anchors(node.store, req, liveness_window=2)
        self.assertIsInstance(reply, LiteRefused)
        assert isinstance(reply, LiteRefused)
        self.assertEqual(reply.reason, SyncRefusal.FORK_DETECTED)

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
            known_trusted_block=TrustedBlock(head1, head1_hash),
        )
        reply = serve_get_anchors(node.store, req, liveness_window=max(gap, 2))
        self.assertIsInstance(reply, AnchorsReply)
        assert isinstance(reply, AnchorsReply)
        self.assertEqual(len(reply.headers), gap)


class TestTheReplyComesFromOneSnapshot(unittest.TestCase):
    """A light-client reply quotes a head, a value and a proof that MUST agree.

    They are four separate reads. Served off the live store, a commit landing between them
    yields a proof that does not verify against the state_root quoted beside it -- fails safe
    (the client drops the reply) but silently, and only under load.

    `Store.db` is the raw-handle escape hatch documented as tests-only, and it was the only
    way `serve_get_proof` could reach the tree. Making it raise is what pins the production
    path to `store.snapshot()`: nothing else about the reply would look wrong if this
    regressed, because a correct-looking proof is exactly what the race produces most of the
    time.
    """

    def _cluster_with_a_value(self):
        c = Cluster()
        key = crypto.h(b"one-snapshot")
        tx = ops.writes(ops.Set(ops.STORE_DATA, key, b"present")).sign(c.mgr, T0)
        c.submit(c.mgr, tx, to=0, now=T0)
        c.pump(T0)
        c.pump(T0 + DELTA)
        return c, key

    def test_serving_a_proof_never_reaches_the_raw_handle(self):
        c, key = self._cluster_with_a_value()
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
        with _raw_handle_is_poisoned():
            reply = serve_get_proof(node.store, req, liveness_window=2)
        self.assertIsInstance(reply, ProofReply)

    def test_serving_anchors_never_reaches_the_raw_handle(self):
        c, _key = self._cluster_with_a_value()
        node = c.nodes[0]
        req = GetAnchors(known_roster_fingerprint=None, known_trusted_block=None)
        with _raw_handle_is_poisoned():
            reply = serve_get_anchors(node.store, req, liveness_window=2)
        self.assertIsInstance(reply, AnchorsReply)


@contextlib.contextmanager
def _raw_handle_is_poisoned():
    """Make `Store.db` raise for the duration. Any production read outside a snapshot trips."""

    def boom(_self: Store) -> sqlite3.Connection:
        raise AssertionError("production read reached Store.db instead of Store.snapshot()")

    with mock.patch.object(Store, "db", property(boom)):
        yield


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
        reply = serve_get_proof(node.store, req, liveness_window=2)
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
        reply = serve_get_proof(node.store, req, liveness_window=2)
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
        reply = serve_get_proof(node.store, req, liveness_window=2)
        self.assertIsInstance(reply, LiteRefused)
        assert isinstance(reply, LiteRefused)
        self.assertEqual(reply.reason, SyncRefusal.NOT_YET_SETTLED)


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
        # SILENCE, not a refusal. A principal we recognise but have not scoped for the store it
        # asked about is told UNAUTHORISED, because it can act on that; an identity we do not
        # recognise at all is cut off at `receive` and told nothing. Counting the mailbox, as
        # this did, could not tell either outcome from being served.
        with mock.patch.object(node.lite_adapter, "reply") as replied:
            node.receive(env.seal(), T0)
        replied.assert_not_called()
        self.assertNotIn(stranger.public, node.postman.peers)

    def test_authorised_client_reaches_serve_handler(self):
        c = Cluster()
        client_kp = crypto.Keypair.generate()
        _provision_client(c, client_kp)
        node = c.nodes[0]

        req = GetAnchors(known_roster_fingerprint=None, known_trusted_block=None)
        verb, body = req.encode()
        env = Envelope(node.me.public, verb, new_message_id(), body).sign(client_kp, T0 + DELTA)
        with mock.patch.object(node.lite_adapter, "reply") as replied:
            node.receive(env.seal(), T0 + DELTA)
        replied.assert_called_once()
        self.assertIsInstance(replied.call_args.args[1], AnchorsReply)

    def test_a_client_is_refused_a_store_its_grant_does_not_name(self):
        """The grant names STORE_DATA. Store 0 holds grants, roster rows, possession proofs and
        wrapped keys, and the gate used to ask only whether a grant EXISTED -- so every granted
        identity read every store."""
        c = Cluster()
        client_kp = crypto.Keypair.generate()
        _provision_client(c, client_kp)
        node = c.nodes[0]
        self.assertTrue(node.mgmt.may_read(node.store, client_kp.public, ops.STORE_DATA))

        req = GetProof(
            store_id=ops.STORE_MANAGEMENT,
            name=b"node/",
            block_num=node.store.head_block_num() or 1,
            known_roster_fingerprint=None,
            known_trusted_block=None,
        )
        verb, body = req.encode()
        env = Envelope(node.me.public, verb, new_message_id(), body).sign(client_kp, T0 + DELTA)
        with mock.patch.object(node.lite_adapter, "reply") as replied:
            node.receive(env.seal(), T0 + DELTA)
        replied.assert_called_once()
        sent = replied.call_args.args[1]
        self.assertIsInstance(sent, LiteRefused, f"store 0 was served: {sent!r}")
        self.assertIs(sent.reason, SyncRefusal.UNAUTHORISED)


class TestTrustedBlockEncoding(unittest.TestCase):
    """Wire-form drift guard for `TrustedBlock` (CLAUDE.md trap #1). Two fields, nullable via
    `encode_optional`/`decode_optional` (empty bytes -> None). Round-trip proves
    consistency; field-count refusal proves neither half silently added a field."""

    def test_present_form_round_trips(self):
        tb = TrustedBlock(block_num=42, block_hash=crypto.Digest(b"\xaa" * 32))
        self.assertEqual(TrustedBlock.decode(tb.encode()), tb)

    def test_absent_form_round_trips(self):
        self.assertEqual(TrustedBlock.encode_optional(None), b"")
        self.assertIsNone(TrustedBlock.decode_optional(b""))

    def test_optional_carries_present_value_unchanged(self):
        tb = TrustedBlock(block_num=1, block_hash=crypto.Digest(b"\x01" * 32))
        self.assertEqual(TrustedBlock.decode_optional(TrustedBlock.encode_optional(tb)), tb)

    def test_present_form_wrong_field_count_raises(self):
        """Two fields is what `encode` emits. Anything else is a hard decode refusal --
        trap #1: a field added to encode without a matching `as_seq(..., N)` bump would
        silently drop otherwise."""
        from dude.core import codec  # noqa: PLC0415 -- local; only used here
        from dude.core.errors import DudeError  # noqa: PLC0415

        for wrong in (1, 3):
            malformed = codec.encode([b""] * wrong)
            with self.assertRaises(DudeError):
                TrustedBlock.decode(malformed)


class TestProofReplyPinsItsFieldCount(unittest.TestCase):
    """Encode and decode are two halves of one fact, and a field added to one and not the other
    drifts in silence -- both halves stay self-consistent alone, so a round-trip cannot see it.
    The epoch is the field that made this urgent: a decoder still reading eight fields would drop
    it and every value would read as unencrypted."""

    def _reply(self, head: SettledBlock) -> ProofReply:
        return ProofReply(
            value=b"v",
            credential=b"c",
            absent=False,
            proof=b"p",
            epoch=7,
            head=head,
            roster_fingerprint=crypto.Digest(bytes(32)),
            bundle=None,
            headers=(),
        )

    def test_round_trip_carries_the_epoch(self):
        c = Cluster()
        raw = c.nodes[0].store.settled_at(1)
        assert raw is not None
        reply = self._reply(SettledBlock.decode(raw))
        verb, body = reply.encode()
        back = LiteMsg.decode(verb, body)
        assert isinstance(back, ProofReply)
        self.assertEqual(back.epoch, 7)
        self.assertEqual(back, reply)

    def test_a_body_of_the_wrong_field_count_is_refused(self):
        c = Cluster()
        raw = c.nodes[0].store.settled_at(1)
        assert raw is not None
        _, body = self._reply(SettledBlock.decode(raw)).encode()
        fields = codec.as_seq(codec.decode(body), 9)
        self.assertEqual(len(fields), 9, "field count moved; both halves must move together")
        with self.assertRaises(LiteAdapterError):
            LiteMsg.decode(Verb.PROOF_REPLY, codec.encode(list(fields[:-1])))


if __name__ == "__main__":
    unittest.main()
