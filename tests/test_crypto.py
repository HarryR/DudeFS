# M0 — L0 crypto: Ed25519 RFC 8032 vectors, PRF, AEAD auth0, MultiSig list.

import binascii
import random
import unittest

from dudefs import crypto as C
from dudefs.vendor import ed25519

# RFC 8032 §7.1 test vectors (authoritative).
RFC8032 = [
    (
        "9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60",
        "d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a",
        "",
        "e5564300c360ac729086e2cc806e828a84877f1eb8e5d974d873e065224901555fb8821590a33bacc61e39701cf9b46bd25bf5f0595bbe24655141438e7a100b",
    ),
    (
        "4ccd089b28ff96da9db6c346ec114e0f5b8a319f35aba624da8cf6ed4fb8a6fb",
        "3d4017c3e843895a92b70aa74d1b7ebc9c982ccf2ec4968cc0cd55f12af4660c",
        "72",
        "92a009a9f0d4cab8720e820b5f642540a2b27b5416503f8fb3762223ebdb69da085ac1e43e15996e458f3613d0f11d8c387b2eaeb4302aeeb00d291612bb0c00",
    ),
    (
        "c5aa8df43f9f837bedb7442f31dcb7b166d38535076f094b85ce3a2e0b4458f7",
        "fc51cd8e6218a1a38da47ed00230f0580816ed13ba3303ac5deb911548908025",
        "af82",
        "6291d657deec24024827e69c3abe01a30ce548a284743a445e3680d7db5ac3ac18ff9b538d16f290ae67f760984dc6594a7c15e9716ed28dc027beceea1ec40a",
    ),
]


class TestEd25519RFC(unittest.TestCase):
    def test_vectors(self):
        h = binascii.unhexlify
        for sk_h, pk_h, msg_h, sig_h in RFC8032:
            sk, pk, msg, sig = h(sk_h), h(pk_h), h(msg_h), h(sig_h)
            self.assertEqual(ed25519.publickey(sk), pk)
            self.assertEqual(ed25519.sign(sk, msg), sig)
            self.assertTrue(ed25519.verify(pk, msg, sig))

    def test_tamper_rejected(self):
        h = binascii.unhexlify
        sk_h, pk_h, msg_h, sig_h = RFC8032[1]
        pk, msg, sig = h(pk_h), h(msg_h), h(sig_h)
        self.assertFalse(ed25519.verify(pk, msg + b"x", sig))
        self.assertFalse(ed25519.verify(pk, msg, sig[:-1] + bytes([sig[-1] ^ 1])))
        self.assertFalse(ed25519.verify(bytes(32), msg, sig))


class TestPRF(unittest.TestCase):
    def test_determinism_and_secret_dependence(self):
        rng = random.Random(7)
        s1 = bytes(rng.getrandbits(8) for _ in range(32))
        s2 = bytes(rng.getrandbits(8) for _ in range(32))
        self.assertEqual(C.prf_tag(s1, b"k"), C.prf_tag(s1, b"k"))
        self.assertNotEqual(C.prf_tag(s1, b"k"), C.prf_tag(s2, b"k"))
        self.assertNotEqual(C.prf_tag(s1, b"k"), C.prf_tag(s1, b"k2"))
        self.assertEqual(len(C.prf_tag(s1, b"k")), 32)


class TestAeadAuth0(unittest.TestCase):
    def test_seal_open_and_auth(self):
        k = bytes(range(32))
        nonce = b"nonce-1234567890"
        aad = b"env"
        pt = b"the-secret-value"
        ct, tag = C.AeadAuth0.seal(k, nonce, aad, pt)
        self.assertEqual(ct, pt)  # UNENCRYPTED — zero-knowledge suspended, loudly
        self.assertEqual(C.AeadAuth0.open(k, nonce, aad, ct, tag), pt)
        self.assertIsNone(C.AeadAuth0.open(k, nonce, b"other-aad", ct, tag))
        self.assertIsNone(C.AeadAuth0.open(k, b"other-nonce-0000", aad, ct, tag))
        self.assertIsNone(C.AeadAuth0.open(k, nonce, aad, ct, bytes(32)))

    def test_zero_knowledge_suspended(self):
        self.assertFalse(C.zero_knowledge_active(b"auth0"))


class TestMultiSigList(unittest.TestCase):
    def test_combine_verify_and_tamper(self):
        rng = random.Random(3)
        n = 5
        sks = [bytes(rng.getrandbits(8) for _ in range(32)) for _ in range(n)]
        pks = [C.SIGNER.public(s) for s in sks]
        msg = b"op_hash||epoch||ballot"
        shares = {i: C.MULTISIG.sign_share(sks[i], msg) for i in (0, 2, 4)}
        bitmap, sigs = C.MULTISIG.combine(shares, n)
        self.assertEqual(C.bitmap_indices(bitmap, n), [0, 2, 4])
        self.assertEqual(C.bitmap_count(bitmap, n), 3)
        self.assertTrue(C.MULTISIG.verify(bitmap, sigs, msg, pks))
        self.assertFalse(C.MULTISIG.verify(bitmap, sigs, b"other", pks))
        bad = list(pks)
        bad[2] = C.SIGNER.public(bytes(32))
        self.assertFalse(C.MULTISIG.verify(bitmap, sigs, msg, bad))


if __name__ == "__main__":
    unittest.main()
