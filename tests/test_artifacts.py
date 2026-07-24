# M0 — typed artifacts: identity-is-bytes, signatures, QC quorum math,
# watermarks, frontier bundles, golden wire vectors (freeze the wire).

import unittest

from dudefs import artifacts as A
from dudefs import codec
from dudefs import crypto as C


def _kp(seed):
    sk = bytes([seed] * 32)
    return sk, C.SIGNER.public(sk)


class TestOp(unittest.TestCase):
    def setUp(self):
        self.sk, self.pub = _kp(1)
        self.data_key = bytes([9] * 32)
        self.secret = bytes([8] * 32)

    def _op(self):
        txn = A.Txn(
            slot=(b"k", A.VERSION_ABSENT, 0),
            guards=[[A.Guard.ABSENT, b"k"]],
            mutations=[[A.Mutation.SET, b"k", b"v"]],
        )
        tag = A.compute_slot_tag(self.secret, b"k", A.VERSION_ABSENT, 0)
        return A.Op.build_data(
            author_sk=self.sk,
            author_pub=self.pub,
            seq=0,
            prev=A.GENESIS_PREV,
            hlc=A.HLC(1000, 0),
            keyepoch=0,
            data_key=self.data_key,
            txn_bytes=txn.encode(),
            slot_tag=tag,
        )

    def test_identity_is_received_bytes(self):
        op = self._op()
        op2 = A.Op.from_bytes(op.raw)
        self.assertEqual(op2.raw, op.raw)
        self.assertEqual(op2.op_hash, op.op_hash)
        self.assertEqual(op.op_hash, C.h(op.raw))

    def test_structure_and_signature(self):
        op = self._op()
        self.assertTrue(op.verify_structure())
        self.assertTrue(op.verify_sig(self.pub))
        self.assertFalse(op.verify_sig(_kp(2)[1]))

    def test_payload_open_and_aad_binding(self):
        op = self._op()
        pt = op.open_payload(self.data_key)
        self.assertIsNotNone(pt)
        assert pt is not None
        self.assertEqual(A.Txn.decode(pt).mutations, [[A.Mutation.SET, b"k", b"v"]])
        self.assertIsNone(op.open_payload(bytes(32)))  # wrong key -> auth fail

    def test_noncanonical_bytes_rejected(self):
        # a trailing byte makes it non-canonical -> codec rejects at ingest
        op = self._op()
        with self.assertRaises(codec.CodecError):
            A.Op.from_bytes(op.raw + b"x")

    def test_unknown_envelope_field_rejected(self):
        # from_bytes re-keys through Field(), raising the typed UnknownField
        # (which carries the offending key as data, not a string flavour).
        op = self._op()
        fields = codec.as_dict(codec.decode(op.raw))
        tampered = codec.encode({**fields, b"surprise": b"x"})
        with self.assertRaises(A.UnknownField) as cm:
            A.Op.from_bytes(tampered)
        self.assertEqual(cm.exception.key, b"surprise")

    def test_missing_required_field_is_typed(self):
        # a decoded artifact missing a required key raises the typed MissingField
        # (a DudeFSError), never a bare KeyError — the catch-all guarantee.
        from dudefs.errors import DudeFSError

        with self.assertRaises(A.MissingField) as cm:
            A.Receipt.decode(codec.encode({b"epoch": 0}))  # lacks op_hash, ...
        self.assertEqual(cm.exception.key, b"op_hash")
        self.assertIsInstance(cm.exception, DudeFSError)


class TestQuorumArtifacts(unittest.TestCase):
    def setUp(self):
        self.n = 5
        self.sks = [bytes([10 + i] * 32) for i in range(self.n)]
        self.pubs = [C.SIGNER.public(s) for s in self.sks]
        self.index = {p: i for i, p in enumerate(self.pubs)}

    def test_quorum_sizes(self):
        self.assertEqual([A.quorum_size(n) for n in (1, 3, 5, 7)], [1, 2, 3, 4])

    def test_qc_needs_majority(self):
        oph = bytes([7] * 32)
        rs = [A.Receipt.issue(self.sks[i], self.pubs[i], oph, 0, A.BLIND, 1) for i in (0, 1, 3)]
        for r in rs:
            self.assertTrue(r.verify())
        qc = A.QC.assemble(rs, self.n, self.index)
        self.assertTrue(qc.verify(self.pubs))
        self.assertTrue(A.QC.decode(qc.encode()).verify(self.pubs))
        # 2 of 5 < quorum 3 -> invalid
        small = A.QC.assemble(rs[:2], self.n, self.index)
        self.assertFalse(small.verify(self.pubs))

    def test_ballot_ordering_and_blind(self):
        self.assertTrue(A.BLIND.is_blind())
        self.assertFalse(A.Ballot(0, b"c").is_blind())
        self.assertLess(A.Ballot(0, b"a"), A.Ballot(1, b"a"))
        self.assertLess(A.Ballot(1, b"a"), A.Ballot(1, b"b"))

    def test_watermark_and_frontier(self):
        wm = A.Watermark.issue(self.sks[0], self.pubs[0], A.HLC(5000, 0), 0, 1)
        self.assertTrue(wm.verify())
        wm.floor = A.HLC(9999, 0)
        self.assertFalse(wm.verify())
        heads = {b"A": (3, bytes([1] * 32)), b"B": (0, bytes([2] * 32))}
        fb = A.FrontierBundle.issue(self.sks[0], self.pubs[0], heads, None, 0, A.HLC(5000, 0))
        self.assertTrue(fb.verify())


class TestGoldenVectors(unittest.TestCase):
    """Freeze the wire (M0). Deterministic keys/inputs -> fixed bytes. If these
    change, the wire format changed — bump on purpose, never by accident."""

    def test_op_golden(self):
        sk, pub = _kp(1)
        secret = bytes([8] * 32)
        data_key = bytes([9] * 32)
        txn = A.Txn(
            slot=(b"k", A.VERSION_ABSENT, 0),
            guards=[[A.Guard.ABSENT, b"k"]],
            mutations=[[A.Mutation.SET, b"k", b"v"]],
        )
        tag = A.compute_slot_tag(secret, b"k", A.VERSION_ABSENT, 0)
        op = A.Op.build_data(
            author_sk=sk,
            author_pub=pub,
            seq=0,
            prev=A.GENESIS_PREV,
            hlc=A.HLC(1000, 0),
            keyepoch=0,
            data_key=data_key,
            txn_bytes=txn.encode(),
            slot_tag=tag,
        )
        # golden: the op_hash is stable across runs (pure functions, fixed seeds)
        self.assertEqual(op.op_hash.hex(), GOLDEN_OP_HASH)
        self.assertEqual(tag.hex(), GOLDEN_SLOT_TAG)

    def test_receipt_message_golden(self):
        msg = A.receipt_message(bytes([7] * 32), 0, A.BLIND, 1)
        self.assertEqual(C.h(msg).hex(), GOLDEN_RECEIPT_MSG_HASH)


# Golden constants captured from the reference implementation (M0 freeze).
# GOLDEN_OP_HASH bumped at (1) the auth0→xcs1 crypto swap (payload became real
# XChaCha20-Poly1305 ciphertext), (2) removal of the vestigial `authz` field, and
# (3) removal of the `deps` field (the plaintext dependency mechanism — orphaned by
# the ZK invariant, will return transaction-integrated behind a protocol-version bump
# if ever). All deliberate wire changes. The slot-tag and receipt-message goldens are
# untouched (never involved the envelope's field set). Deterministic across runs.
GOLDEN_OP_HASH = "fe765b8a3da629d45f21877c0d8b81e51746d12e67f762cde3c96855fb3c5ce0"
GOLDEN_SLOT_TAG = "90f95fff86da601e863bff7a94a015ef6a55241da944541f4ee5ce26556a6c53"
GOLDEN_RECEIPT_MSG_HASH = "14b2178154576d6005816103e16b6f4fee08c09fedcbce7323fdfb9d3e593bac"


if __name__ == "__main__":
    unittest.main()
