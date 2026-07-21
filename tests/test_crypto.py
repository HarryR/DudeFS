# M0 — L0 crypto: Ed25519 RFC 8032 KATs (SIGNER over PyNaCl), PRF, AEAD xcs1
# (XChaCha20-Poly1305-IETF, SIV nonce — CRYPTO.md §2), MultiSig list.

import binascii
import random
import unittest

from dudefs import crypto as C

# RFC 8032 §7.1 test vectors (authoritative). KATs for the SIGNER over PyNaCl —
# byte-identical to the vendored reference we replaced (the swap is wire-invisible).
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
            self.assertEqual(C.SIGNER.public(sk), pk)
            self.assertEqual(C.SIGNER.sign(sk, msg), sig)
            self.assertTrue(C.SIGNER.verify(pk, msg, sig))

    def test_tamper_rejected(self):
        h = binascii.unhexlify
        sk_h, pk_h, msg_h, sig_h = RFC8032[1]
        pk, msg, sig = h(pk_h), h(msg_h), h(sig_h)
        self.assertFalse(C.SIGNER.verify(pk, msg + b"x", sig))
        self.assertFalse(C.SIGNER.verify(pk, msg, sig[:-1] + bytes([sig[-1] ^ 1])))
        self.assertFalse(C.SIGNER.verify(bytes(32), msg, sig))


class TestPRF(unittest.TestCase):
    def test_determinism_and_secret_dependence(self):
        rng = random.Random(7)
        s1 = bytes(rng.getrandbits(8) for _ in range(32))
        s2 = bytes(rng.getrandbits(8) for _ in range(32))
        self.assertEqual(C.prf_tag(s1, b"k"), C.prf_tag(s1, b"k"))
        self.assertNotEqual(C.prf_tag(s1, b"k"), C.prf_tag(s2, b"k"))
        self.assertNotEqual(C.prf_tag(s1, b"k"), C.prf_tag(s1, b"k2"))
        self.assertEqual(len(C.prf_tag(s1, b"k")), 32)


class TestAeadXcs1(unittest.TestCase):
    # Canonical KAT for xcs1 (XChaCha20-Poly1305-IETF over the SIV nonce of
    # CRYPTO.md §2). SELF-GENERATED here, and thereby the construction's reference
    # vector — the Rust/Go ports MUST reproduce this exact blob for k = 00..1f,
    # aad = ab*32, pt = b"the-secret-value". Blob layout: nonce(24) ‖ ct ‖ tag(16).
    KAT_KEY = bytes(range(32))
    KAT_AAD = bytes([0xAB]) * 32
    KAT_PT = b"the-secret-value"
    KAT_BLOB = binascii.unhexlify(
        "f09f5a46316a9c0e08e0e4b4bb65a0b5be7b34126ec8f1dd"
        "b34a5a26f036fe43031c8ae051ecb2005df5a0e7391ccec7899155b047049b38"
    )

    def test_kat_blob_is_canonical(self):
        self.assertEqual(C.AeadXcs1.seal(self.KAT_KEY, self.KAT_AAD, self.KAT_PT), self.KAT_BLOB)
        self.assertEqual(C.AeadXcs1.open(self.KAT_KEY, self.KAT_AAD, self.KAT_BLOB), self.KAT_PT)

    def test_seal_open_roundtrip_and_auth(self):
        k, aad, pt = self.KAT_KEY, b"env", b"the-secret-value"
        blob = C.AeadXcs1.seal(k, aad, pt)
        self.assertNotIn(pt, blob)  # ENCRYPTED — zero-knowledge genuinely on
        self.assertEqual(C.AeadXcs1.open(k, aad, blob), pt)
        self.assertIsNone(C.AeadXcs1.open(bytes(32), aad, blob))  # wrong key -> ⊥
        self.assertIsNone(C.AeadXcs1.open(k, b"other-aad", blob))  # wrong AD -> ⊥
        self.assertIsNone(C.AeadXcs1.open(k, aad, blob[:-1] + bytes([blob[-1] ^ 1])))  # tamper
        self.assertIsNone(C.AeadXcs1.open(k, aad, b"\x00" * 39))  # too short -> ⊥

    def test_deterministic_and_misuse_resistant(self):
        # SIV: (key, aad, pt) -> identical blob (determinism, the MRAE bound), but
        # two plaintexts under ONE header get INDEPENDENT nonces — keystream reuse
        # is structurally impossible (CRYPTO.md §2, the equivocating-author case).
        k, aad = self.KAT_KEY, b"header"
        self.assertEqual(C.AeadXcs1.seal(k, aad, b"P1"), C.AeadXcs1.seal(k, aad, b"P1"))
        n1 = C.AeadXcs1.seal(k, aad, b"P1")[:24]
        n2 = C.AeadXcs1.seal(k, aad, b"P2")[:24]
        self.assertNotEqual(n1, n2)


class TestEpochKeyDerivation(unittest.TestCase):
    # K_epoch is THE epoch master (finding 21): the working keys DERIVE via person
    # domains, they are not distributed. Canonical KATs for master = 00..1f — the
    # Rust/Go ports MUST reproduce these exact subkeys.
    KAT_MASTER = bytes(range(32))
    KAT_DATA_KEY = binascii.unhexlify(
        "1522919474e9234bbcb572caa1937517d999a2cec896d0c936b4e7ce04bb4774"
    )
    KAT_SLOT_SECRET = binascii.unhexlify(
        "8bac258c8b84cc47efacb70a3d912955041ac2b3621938081ff19124ee94de6b"
    )

    def test_derivation_kat_is_canonical(self):
        self.assertEqual(C.derive_data_key(self.KAT_MASTER), self.KAT_DATA_KEY)
        self.assertEqual(C.derive_slot_secret(self.KAT_MASTER), self.KAT_SLOT_SECRET)

    def test_domain_separation_and_determinism(self):
        K = bytes([7] * 32)
        dk, ss = C.derive_data_key(K), C.derive_slot_secret(K)
        self.assertEqual(len(dk), 32)
        self.assertEqual(len(ss), 32)
        # each working key is distinct from the master and from every sibling
        self.assertNotEqual(dk, ss)
        self.assertNotEqual(dk, K)
        self.assertNotEqual(ss, K)
        # deterministic; a different master gives entirely different subkeys
        self.assertEqual(C.derive_data_key(K), dk)
        self.assertNotEqual(C.derive_data_key(bytes([8] * 32)), dk)


class TestSealedBoxSbx1(unittest.TestCase):
    # sbx1 seals to an Ed25519 identity via its X25519 agreement key. Ephemeral
    # sender keypair => non-deterministic ciphertext, so the KAT is FUNCTIONAL:
    # the addressed member opens it; nobody else can.
    def test_member_opens_wrong_recipient_fails(self):
        sk_a, sk_b = bytes([9] * 32), bytes([10] * 32)
        pub_a = C.SIGNER.public(sk_a)
        secret = b"K_epoch: a 32-byte group key!!!!"
        sealed = C.seal_to(pub_a, secret)
        self.assertNotIn(secret, sealed)  # actually sealed
        self.assertEqual(C.open_sealed(sk_a, sealed), secret)  # addressee opens
        self.assertIsNone(C.open_sealed(sk_b, sealed))  # wrong recipient -> None
        self.assertIsNone(C.open_sealed(sk_a, sealed[:-1] + bytes([sealed[-1] ^ 1])))  # tamper

    def test_ephemeral_sender_is_nondeterministic(self):
        pub = C.SIGNER.public(bytes([11] * 32))
        self.assertNotEqual(C.seal_to(pub, b"k"), C.seal_to(pub, b"k"))


class TestProofOfPossession(unittest.TestCase):
    # NOTES 58: the manager certifies a pubkey only after the subject proves it holds
    # the sk. Non-interactive self-attestation bound to THAT pubkey.
    def test_round_trip_and_forgery(self):
        sk = bytes([9] * 32)
        pub = C.SIGNER.public(sk)
        pop = C.prove_possession(sk)
        self.assertTrue(C.verify_possession(pub, pop))
        # a pop from a DIFFERENT key does not prove possession of `pub`
        self.assertFalse(C.verify_possession(pub, C.prove_possession(bytes([8] * 32))))
        # ...nor can THIS pop be transplanted onto another pubkey (bound to `pub`)
        other = C.SIGNER.public(bytes([8] * 32))
        self.assertFalse(C.verify_possession(other, pop))
        # tamper -> reject
        self.assertFalse(C.verify_possession(pub, pop[:-1] + bytes([pop[-1] ^ 1])))


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
