from __future__ import annotations

import unittest

from dude.consensus.round import Block
from dude.consensus.settle_round import Anchors, SettledBlock, _settle_payload
from dude.core import crypto
from dude.store.checkpoint import CheckpointMeta
from dude.store.management import Cert, Role


def _make_settled_block(
    signers: list[crypto.Keypair],
    _anchor: crypto.Keypair,
    block_num: int = 5,
    height: int = 10,
) -> SettledBlock:
    anchors = Anchors(
        block_num=block_num,
        height=height,
        prev_block=crypto.h(b"prev"),
        state_root=crypto.h(b"root"),
        acc_state=crypto.Accumulator(crypto.acc_element(b"state")),
        acc_log=crypto.Accumulator(crypto.acc_element(b"log")),
    )
    block = Block(bucket=1000, hashes=())
    payload = _settle_payload(block.slice_hash, anchors)
    roster = sorted(kp.public for kp in signers)
    kp_by_pub = {kp.public: kp for kp in signers}
    n = len(signers) + 1
    shares = {i: kp_by_pub[pub].sign(payload) for i, pub in enumerate(roster)}
    multisig = crypto.MultiSig.combine(shares, n)
    return SettledBlock(block=block, anchors=anchors, multisig=multisig)


def _test_fixture():
    anchor = crypto.Keypair.generate()
    nodes = [crypto.Keypair.generate() for _ in range(3)]
    compactor = crypto.Keypair.generate()
    grant_cert = Cert.sign_grant(anchor, compactor.public, Role.COMPACTOR)
    sb = _make_settled_block(nodes, anchor)
    roster = tuple(sorted(kp.public for kp in nodes))
    return anchor, nodes, compactor, grant_cert, sb, roster


class TestCheckpointMeta(unittest.TestCase):
    def test_create_and_verify_compactor(self):
        anchor, _, compactor, grant_cert, sb, _ = _test_fixture()
        meta = CheckpointMeta.create(sb.encode(), anchor.public, compactor, grant_cert)
        self.assertIsNone(meta.verify_compactor(anchor.public))

    def test_verify_quorum(self):
        anchor, _, compactor, grant_cert, sb, roster = _test_fixture()
        meta = CheckpointMeta.create(sb.encode(), anchor.public, compactor, grant_cert)
        self.assertIsNone(meta.verify_quorum(roster))

    def test_wrong_anchor_rejected(self):
        anchor, _, compactor, grant_cert, sb, _ = _test_fixture()
        meta = CheckpointMeta.create(sb.encode(), anchor.public, compactor, grant_cert)
        wrong_anchor = crypto.Keypair.generate()
        why = meta.verify_compactor(wrong_anchor.public)
        assert why is not None
        self.assertIn("anchor", why)

    def test_tampered_block_bytes_rejected(self):
        anchor, _, compactor, grant_cert, sb, _ = _test_fixture()
        meta = CheckpointMeta.create(sb.encode(), anchor.public, compactor, grant_cert)
        tampered = CheckpointMeta(
            settled_block_bytes=crypto.random_bytes(len(meta.settled_block_bytes)),
            anchor=meta.anchor,
            compactor=meta.compactor,
            grant_cert=meta.grant_cert,
            sig=meta.sig,
        )
        why = tampered.verify_compactor(anchor.public)
        assert why is not None
        self.assertIn("compactor signature invalid", why)

    def test_wrong_compactor_key_rejected(self):
        anchor, _, compactor, grant_cert, sb, _ = _test_fixture()
        meta = CheckpointMeta.create(sb.encode(), anchor.public, compactor, grant_cert)
        impostor = crypto.Keypair.generate()
        impostor_grant = Cert.sign_grant(anchor, impostor.public, Role.COMPACTOR)
        forged = CheckpointMeta(
            settled_block_bytes=meta.settled_block_bytes,
            anchor=meta.anchor,
            compactor=impostor.public,
            grant_cert=impostor_grant,
            sig=meta.sig,
        )
        why = forged.verify_compactor(anchor.public)
        assert why is not None
        self.assertIn("compactor signature invalid", why)

    def test_grant_not_signed_by_anchor_rejected(self):
        anchor, _, compactor, _, sb, _ = _test_fixture()
        rogue = crypto.Keypair.generate()
        bad_grant = Cert.sign_grant(rogue, compactor.public, Role.COMPACTOR)
        meta = CheckpointMeta.create(sb.encode(), anchor.public, compactor, bad_grant)
        why = meta.verify_compactor(anchor.public)
        assert why is not None
        self.assertIn("grant not signed by anchor", why)

    def test_grant_wrong_role_rejected(self):
        anchor, _, compactor, _, sb, _ = _test_fixture()
        wrong_role = Cert.sign_grant(anchor, compactor.public, Role.CLIENT_RO)
        meta = CheckpointMeta.create(sb.encode(), anchor.public, compactor, wrong_role)
        why = meta.verify_compactor(anchor.public)
        assert why is not None
        self.assertIn("COMPACTOR", why)

    def test_quorum_with_wrong_roster_rejected(self):
        anchor, _, compactor, grant_cert, sb, _ = _test_fixture()
        meta = CheckpointMeta.create(sb.encode(), anchor.public, compactor, grant_cert)
        wrong_roster = tuple(crypto.Keypair.generate().public for _ in range(3))
        why = meta.verify_quorum(wrong_roster)
        assert why is not None
        self.assertIn("quorum", why)

    def test_encode_decode_roundtrip(self):
        anchor, _, compactor, grant_cert, sb, roster = _test_fixture()
        meta = CheckpointMeta.create(sb.encode(), anchor.public, compactor, grant_cert)
        raw = meta.encode()
        restored = CheckpointMeta.decode(raw)
        self.assertIsNone(restored.verify_compactor(anchor.public))
        self.assertIsNone(restored.verify_quorum(roster))
        self.assertEqual(restored.settled_block_bytes, meta.settled_block_bytes)
        self.assertEqual(restored.anchor, meta.anchor)
        self.assertEqual(restored.compactor, meta.compactor)
        self.assertEqual(restored.sig, meta.sig)

    def test_anchors_accessible(self):
        anchor, _, compactor, grant_cert, sb, _ = _test_fixture()
        meta = CheckpointMeta.create(sb.encode(), anchor.public, compactor, grant_cert)
        self.assertEqual(meta.anchors.block_num, 5)
        self.assertEqual(meta.anchors.height, 10)
        self.assertEqual(meta.state_root, sb.anchors.state_root)
        self.assertEqual(meta.block_hash, sb.block_hash)


if __name__ == "__main__":
    unittest.main()
