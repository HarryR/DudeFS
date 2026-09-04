import unittest
from dataclasses import replace
from unittest import mock

from ..consensus.settle_round import SettledBlock
from ..core import crypto
from ..core.errors import DudeError
from ..core.units import Millis
from ..net.address import Address, Endpoint, Scheme
from ..net.envelope import MessageId
from ..net.postman import Delivered, OutputQueue, Postman
from ..store import ops
from ..store.management import Cert, Grant, NodeRecord, Role, RosterCommitment
from ..sync import chain
from ..sync.lite import serve_get_anchors, serve_get_proof
from ..sync.lite_adapter import (
    AnchorsReply,
    GetAnchors,
    GetProof,
    LiteMsg,
    ProofReply,
    RosterBundle,
    TrustedBlock,
)
from ..sync.lite_client import (
    Failed,
    GetResult,
    LightClient,
    Read,
    State,
    TrustedState,
    _BootstrapReply,
    _BootstrapRequest,
)
from .cluster import Cluster


def _now_for_store(c: Cluster) -> Millis:
    store = c.nodes[0].store
    head_num = store.head_block_num()
    assert head_num is not None
    raw = store.settled_at(head_num)
    assert raw is not None
    bucket = SettledBlock.decode(raw).block.bucket
    return c.tunables.bucket_start(bucket + 1)


# ---------------------------------------------------------------------------
# Category 1 — happy-path through the real threaded cluster
# ---------------------------------------------------------------------------


class TestBootstrap(unittest.TestCase):
    def setUp(self) -> None:
        self.c = Cluster(nodes=3, mgmt=0, ro=0, rw=1)
        self.lc = self.c.rw_clients[0]
        self.lc.bootstrap()

    def tearDown(self) -> None:
        self.c.close()

    def test_bootstrap_reaches_ready(self) -> None:
        ts = self.lc.trusted_state
        self.assertIsNotNone(ts)
        assert ts is not None
        self.assertEqual(len(ts.roster), 3)
        self.assertGreater(ts.head.anchors.block_num, 0)

    def test_trusted_state_has_full_roster(self) -> None:
        ts = self.lc.trusted_state
        assert ts is not None
        self.assertEqual(len(ts.roster), 3)
        self.assertGreater(ts.head.anchors.block_num, 0)


class TestLightClientRead(unittest.TestCase):
    def setUp(self) -> None:
        self.c = Cluster(nodes=3, mgmt=1, ro=0, rw=1)
        self.lc = self.c.rw_clients[0]
        self.lc.bootstrap()

    def tearDown(self) -> None:
        self.c.close()

    def test_put_and_get_via_session(self) -> None:
        s = self.lc.session()
        self.c.wait_settled(s.put("hello", b"world").wait())
        rec = s.get("hello")
        self.assertFalse(rec.absent)
        self.assertEqual(rec.value, b"world")

    def test_value_is_encrypted_on_disk(self) -> None:
        s = self.lc.session()
        s.put("secret", b"plaintext").wait()
        rec = s.get("secret")
        self.assertNotEqual(rec.raw, b"plaintext")
        self.assertEqual(rec.value, b"plaintext")

    def test_handle_outlives_inflight(self) -> None:
        s = self.lc.session()
        s.put("outlive", b"value").wait()
        rec = s.get("outlive")
        self.assertFalse(rec.absent)
        first = rec.value
        second = s.get("outlive").value
        self.assertEqual(first, second)


# ---------------------------------------------------------------------------
# Category 2 — byzantine security via crafted Delivered objects
#
# Bootstrap a real LC against a real cluster to get a valid trusted_state,
# then feed crafted messages through _on_delivered — the same dispatch the
# run loop uses.  The verification pipeline (decode → resolve_read → proof
# check) runs identically; only the postman/transport layer is bypassed,
# and that layer is already covered by test_postman.py.
# ---------------------------------------------------------------------------


def _trusted_state_from_cluster(c: Cluster) -> TrustedState:
    store = c.nodes[0].store
    mgmt = store.mgmt_reader
    commitment = mgmt.roster_commitment()
    assert commitment is not None
    head_num = store.head_block_num()
    assert head_num is not None
    raw = store.settled_at(head_num)
    assert raw is not None
    head = SettledBlock.decode(raw)
    return TrustedState(
        roster=tuple(sorted(commitment.members)),
        managers=tuple(sorted(g.identity for g in mgmt.manager_grants())),
        node_endpoints={rec.identity: rec.endpoints for rec in mgmt.nodes().values()},
        roster_fingerprint=crypto.Digest(commitment.cert.subject),
        head=head,
    )


def _get_real_proof_reply(c: Cluster, store_id: int, name: bytes) -> ProofReply:
    store = c.nodes[0].store
    head_num = store.head_block_num()
    assert head_num is not None
    ts = _trusted_state_from_cluster(c)
    request = GetProof(
        store_id=store_id,
        name=name,
        block_num=head_num,
        known_roster_fingerprint=ts.roster_fingerprint,
        known_trusted_block=TrustedBlock(ts.head.anchors.block_num, ts.head.block_hash),
    )
    reply = serve_get_proof(store, request, c.tunables.liveness_window)
    assert isinstance(reply, ProofReply), (
        f"expected ProofReply, got {type(reply).__name__}: {reply}"
    )
    return reply


def _make_unstarted_lc(c: Cluster, head_behind: int = 0) -> LightClient:
    kp = crypto.Keypair.generate()
    postman = Postman(kp, c.tunables, on_output=OutputQueue())
    lc = LightClient(me=kp, anchor=c.anchor.public, postman=postman)
    ts = _trusted_state_from_cluster(c)
    if head_behind > 0:
        store = c.nodes[0].store
        target = ts.head.anchors.block_num - head_behind
        target = max(target, 1)
        raw = store.settled_at(target)
        assert raw is not None
        ts = replace(ts, head=SettledBlock.decode(raw))
    lc.trusted_state = ts
    lc.state = State.READY
    return lc


def _feed_reply(
    lc: LightClient,
    reply: LiteMsg,
    peer: crypto.PublicKey,
    store_id: int = ops.STORE_DATA,
    name: bytes = b"",
) -> Read:
    mid = MessageId.random()
    read = Read(mid=mid, peer=peer, client=lc, store_id=store_id, name=name)
    lc.inflight.register(mid, read)
    verb, body = reply.encode()
    delivered = Delivered(
        frm=peer,
        verb=verb,
        body=body,
        mid=MessageId.random(),
        in_reply_to=mid,
    )
    lc._on_delivered(delivered)
    return read


class TestByzantineProofReply(unittest.TestCase):
    def setUp(self) -> None:
        self.c = Cluster(nodes=3, mgmt=1, ro=0, rw=0)
        ms = self.c.replicas[0].session()
        self.c.wait_settled(ms.put("byz-target", b"real-value").wait())
        self.c.wait_settled(ms.put("byz-pad", b"x").wait())

    def tearDown(self) -> None:
        self.c.close()

    def _lc(self) -> LightClient:
        return _make_unstarted_lc(self.c)

    def _token(self) -> bytes:
        ms = self.c.replicas[0].session()
        return ms.get("byz-target").token

    def _real_reply(self) -> ProofReply:
        return _get_real_proof_reply(self.c, ops.STORE_DATA, self._token())

    def test_honest_reply_succeeds(self) -> None:
        lc = self._lc()
        reply = self._real_reply()
        read = _feed_reply(lc, reply, self.c.nodes[0].me.public, name=self._token())
        result = read.poll()
        self.assertIsInstance(result, GetResult, f"got {result!r}")

    def test_byzantine_value_swap_fails_proof(self) -> None:
        lc = self._lc()
        reply = self._real_reply()
        bad = replace(reply, value=b"NOT-THE-REAL-VALUE")
        read = _feed_reply(lc, bad, self.c.nodes[0].me.public, name=self._token())
        result = read.poll()
        self.assertIsInstance(result, Failed, f"got {result!r}")
        assert isinstance(result, Failed)
        self.assertEqual(result.reason, "proof-verify-failed")

    def test_byzantine_credential_swap_fails_proof(self) -> None:
        lc = self._lc()
        reply = self._real_reply()
        bad = replace(reply, credential=b"FAKE-CRED")
        read = _feed_reply(lc, bad, self.c.nodes[0].me.public, name=self._token())
        result = read.poll()
        self.assertIsInstance(result, Failed, f"got {result!r}")
        assert isinstance(result, Failed)
        self.assertEqual(result.reason, "proof-verify-failed")

    def test_wrong_width_signer_bitmap_fails_not_crashes(self) -> None:
        lc = _make_unstarted_lc(self.c, head_behind=1)
        reply = self._real_reply()
        ts = lc.trusted_state
        assert ts is not None
        head_num = ts.head.anchors.block_num
        store = self.c.nodes[0].store
        above_raw = store.settled_at(head_num + 1)
        assert above_raw is not None, "setUp should ensure head >= 2"
        above = SettledBlock.decode(above_raw)
        wrecked = replace(
            above,
            multisig=replace(above.multisig, bitmap=crypto.SignerBitmap(bytes(5))),
        )
        bad = replace(reply, head=wrecked, headers=())
        read = _feed_reply(lc, bad, self.c.nodes[0].me.public, name=self._token())
        result = read.poll()
        self.assertIsInstance(result, Failed, f"got {result!r}")
        assert isinstance(result, Failed)
        self.assertIn("verify failed", result.reason)
        self.assertIs(lc.state, State.READY)
        self.assertIsNotNone(lc.trusted_state)

    def test_dude_error_from_chain_advance_resolves_read(self) -> None:
        lc = _make_unstarted_lc(self.c, head_behind=1)
        reply = self._real_reply()
        ts = lc.trusted_state
        assert ts is not None
        head_num = ts.head.anchors.block_num
        store = self.c.nodes[0].store
        above_raw = store.settled_at(head_num + 1)
        assert above_raw is not None, "setUp should ensure head >= 2"
        above = SettledBlock.decode(above_raw)
        advanced = replace(reply, head=above, headers=())

        with mock.patch.object(
            chain,
            "advance",
            side_effect=DudeError("header check exploded"),
        ):
            read = _feed_reply(lc, advanced, self.c.nodes[0].me.public, name=self._token())

        result = read.poll()
        self.assertIsInstance(result, Failed, f"read left unresolved: {result!r}")
        assert isinstance(result, Failed)
        self.assertIn("header check exploded", result.reason)
        self.assertIs(lc.state, State.READY)


class TestByzantineBootstrapReply(unittest.TestCase):
    def setUp(self) -> None:
        self.c = Cluster(nodes=3, mgmt=1, ro=0, rw=0)
        self.c.wait_block(2)

    def tearDown(self) -> None:
        self.c.close()

    def test_forged_quorum_proof_does_not_reach_ready(self) -> None:
        store = self.c.nodes[0].store
        mgmt = store.mgmt_reader
        commitment = mgmt.roster_commitment()
        assert commitment is not None
        head_num = store.head_block_num()
        assert head_num is not None
        raw = store.settled_at(head_num)
        assert raw is not None
        request = GetAnchors(known_roster_fingerprint=None, known_trusted_block=None)
        reply = serve_get_anchors(store, request, self.c.tunables.liveness_window)
        assert isinstance(reply, AnchorsReply)

        forged_head = replace(
            reply.head,
            multisig=crypto.MultiSig(
                reply.head.multisig.bitmap,
                tuple(crypto.Signature(bytes(64)) for _ in reply.head.multisig.sigs),
            ),
        )
        forged = replace(reply, head=forged_head)

        kp = crypto.Keypair.generate()
        postman = Postman(kp, self.c.tunables, on_output=OutputQueue())
        lc = LightClient(me=kp, anchor=self.c.anchor.public, postman=postman)
        lc.state = State.BOOTSTRAPPING
        for node in self.c.nodes:
            lc.bootstrap_peers[node.me.public] = _BootstrapReply()

        for node in self.c.nodes:
            mid = MessageId.random()
            lc.inflight.register(mid, _BootstrapRequest(mid=mid, peer=node.me.public, client=lc))
            verb, body = forged.encode()
            delivered = Delivered(
                frm=node.me.public,
                verb=verb,
                body=body,
                mid=MessageId.random(),
                in_reply_to=mid,
            )
            lc._on_delivered(delivered)

        self.assertFalse(lc.bootstrapped(), "forged quorum proof was accepted")
        self.assertIsNone(lc.trusted_state)

    def test_forged_bundle_from_revoked_manager_not_adopted(self) -> None:
        store = self.c.nodes[0].store
        mgmt = store.mgmt_reader
        commitment = mgmt.roster_commitment()
        assert commitment is not None
        request = GetAnchors(known_roster_fingerprint=None, known_trusted_block=None)
        honest_reply = serve_get_anchors(store, request, self.c.tunables.liveness_window)
        assert isinstance(honest_reply, AnchorsReply)

        kp = crypto.Keypair.generate()
        postman = Postman(kp, self.c.tunables, on_output=OutputQueue())
        lc = LightClient(me=kp, anchor=self.c.anchor.public, postman=postman)
        lc.state = State.BOOTSTRAPPING
        for node in self.c.nodes:
            lc.bootstrap_peers[node.me.public] = _BootstrapReply()

        for node in self.c.nodes:
            mid = MessageId.random()
            lc.inflight.register(mid, _BootstrapRequest(mid=mid, peer=node.me.public, client=lc))
            verb, body = honest_reply.encode()
            delivered = Delivered(
                frm=node.me.public,
                verb=verb,
                body=body,
                mid=MessageId.random(),
                in_reply_to=mid,
            )
            lc._on_delivered(delivered)
        self.assertTrue(lc.bootstrapped(), "honest bootstrap failed")
        assert lc.trusted_state is not None
        honest_roster = lc.trusted_state.roster

        warm = crypto.Keypair.generate()
        warm_cert = Cert.sign_grant(self.c.anchor, warm.public, Role.MANAGER)

        attacker_nodes = [crypto.Keypair.generate() for _ in range(3)]
        entries = tuple(
            NodeRecord(
                ak.public,
                (Endpoint(Address(Scheme.INPROC, f"attacker{i}")),),
                Cert.sign_roster(warm, ak.public),
                frozenset(),
            )
            for i, ak in enumerate(attacker_nodes)
        )
        members = tuple(sorted(ak.public for ak in attacker_nodes))
        state_fingerprint = RosterCommitment.fingerprint(entries)
        content = RosterCommitment.content(99, members, state_fingerprint)
        forged_bundle = RosterBundle(
            commitment_serial=99,
            commitment_members=members,
            commitment_cert=Cert.sign_roster_commitment(warm, content),
            entries=entries,
            managers=(Grant(warm.public, Role.MANAGER, frozenset(), frozenset(), warm_cert),),
        )

        forged_fingerprint = crypto.Digest(forged_bundle.commitment_cert.subject)

        store = self.c.nodes[0].store
        head_num = store.head_block_num()
        assert head_num is not None

        token = crypto.h(b"anything")
        request = GetProof(
            store_id=ops.STORE_DATA,
            name=token,
            block_num=head_num,
            known_roster_fingerprint=lc.trusted_state.roster_fingerprint,
            known_trusted_block=TrustedBlock(
                lc.trusted_state.head.anchors.block_num,
                lc.trusted_state.head.block_hash,
            ),
        )
        real_proof_reply = serve_get_proof(store, request, self.c.tunables.liveness_window)
        assert isinstance(real_proof_reply, ProofReply)
        forged_proof = replace(
            real_proof_reply,
            bundle=forged_bundle,
            roster_fingerprint=forged_fingerprint,
        )
        read = _feed_reply(
            lc,
            forged_proof,
            self.c.nodes[0].me.public,
            name=token,
        )

        read.poll()
        after = lc.trusted_state
        if after is not None:
            attacker_roster = tuple(sorted(ak.public for ak in attacker_nodes))
            self.assertNotEqual(after.roster, attacker_roster, "forged roster was adopted")
            self.assertEqual(after.roster, honest_roster, "trusted roster changed")


if __name__ == "__main__":
    unittest.main()
