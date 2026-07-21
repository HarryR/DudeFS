# DudeFS L0 — cryptographic primitives + suite registry.
#
# ARCHITECTURE.md L0 / DESIGN.md §3, §8 / IMPLEMENTATION.md §1.
#
# Pure black boxes selected by suite ids carried in genesis / control ops
# (crypto agility — DESIGN §16). Nothing above L0 names a concrete algorithm;
# it names a suite id and asks the registry. The interfaces:
#
#   Hash      h(bytes) -> 32B                       content addressing everywhere
#   PRF       tag(secret, preimage) -> 32B          opaque, keyed slot tags (§7)
#   AEAD      seal(k,aad,pt)->blob / open(k,aad,blob)  data payloads (SIV, §5)
#   Signer    sign(sk,msg) / verify(pk,msg,sig)      authors (Ed25519)
#   MultiSig  sign_share / combine / verify          node receipts -> QC (§8)
#
# v1 concrete choices (IMPLEMENTATION §1 / CRYPTO.md): BLAKE2b-256, keyed-BLAKE2
# PRF, Ed25519 (authors) + Ed25519 signature list & signer bitmap (node MultiSig),
# and the `xcs1` AEAD suite — XChaCha20-Poly1305-IETF with an SIV-derived
# (misuse-resistant) nonce over libsodium. Zero-knowledge is genuinely on.

from __future__ import annotations

import hashlib
from collections.abc import Iterable

import nacl.exceptions
import nacl.public
import nacl.secret
import nacl.signing

from .errors import DudeFSError


def _ed25519_sign(sk: bytes, msg: bytes) -> bytes:
    return nacl.signing.SigningKey(sk).sign(msg).signature


def _ed25519_public(sk: bytes) -> bytes:
    return bytes(nacl.signing.SigningKey(sk).verify_key)


def _ed25519_verify(pk: bytes, msg: bytes, sig: bytes) -> bool:
    try:
        nacl.signing.VerifyKey(pk).verify(msg, sig)
        return True
    except (nacl.exceptions.BadSignatureError, ValueError):
        return False


class CryptoError(DudeFSError):
    """The crypto module's base error: suite/parameter misuse (unknown suite id,
    out-of-range signer index)."""


# --------------------------------------------------------------------------- #
# Default suite ids (genesis picks these; control ops may bump them — §16)     #
# --------------------------------------------------------------------------- #

HASH_SUITE = b"blake2b-256"
SIGNER_SUITE = b"ed25519"
MULTISIG_SUITE = b"ed25519-list"
PRF_SUITE = b"blake2b-tag"
AEAD_SUITE = b"xcs1"


# --------------------------------------------------------------------------- #
# Hash (content addressing)                                                    #
# --------------------------------------------------------------------------- #

DIGEST_SIZE = 32


def h(data: bytes) -> bytes:
    """Content-address hash. `op_hash = h(bytes-as-received)` (IMPLEMENTATION §2)."""
    return hashlib.blake2b(data, digest_size=DIGEST_SIZE).digest()


# --------------------------------------------------------------------------- #
# PRF (slot tags — DESIGN §7)                                                  #
# --------------------------------------------------------------------------- #


def prf_tag(slot_secret: bytes, preimage: bytes) -> bytes:
    """Keyed-BLAKE2 PRF over the slot preimage. All clients holding the
    per-keyepoch slot secret compute identical tags; nodes cannot invert or
    brute-force them (closes the low-entropy leak, DESIGN §7)."""
    return hashlib.blake2b(
        preimage, key=slot_secret, person=b"dude.tag", digest_size=DIGEST_SIZE
    ).digest()


# --------------------------------------------------------------------------- #
# Signer — authors (Ed25519)                                                   #
# --------------------------------------------------------------------------- #


class Ed25519Signer:
    """L0 Signer over libsodium (PyNaCl). `sk` is the 32-byte seed; the public key
    is derived. RFC 8032 deterministic — byte-identical signatures to any
    conforming implementation (the Rust/Go ports and the KAT vectors)."""

    suite_id = SIGNER_SUITE

    @staticmethod
    def public(sk: bytes) -> bytes:
        return _ed25519_public(sk)

    @staticmethod
    def sign(sk: bytes, msg: bytes) -> bytes:
        return _ed25519_sign(sk, msg)

    @staticmethod
    def verify(pk: bytes, msg: bytes, sig: bytes) -> bool:
        return _ed25519_verify(pk, msg, sig)


SIGNER = Ed25519Signer


# --------------------------------------------------------------------------- #
# Proof-of-possession (NOTES 58): the manager signs pubkeys only and never       #
# certifies an unheld key — the subject proves it holds the sk by signing a      #
# domain-separated self-attestation over its own pubkey. Non-interactive (no     #
# challenge round trip); replay-safe because the pop is bound to THAT pubkey and #
# cannot be transplanted to another. The `dude.pop:` prefix keeps it disjoint    #
# from every real signed artifact (ops sign an envelope, never this message).    #
# --------------------------------------------------------------------------- #

_POP_PREFIX = b"dude.pop:"


def prove_possession(sk: bytes) -> bytes:
    """The subject's self-attestation that it holds `sk` (keys generate where they
    live; only pubkey + pop travel to the manager)."""
    pub = SIGNER.public(sk)
    return SIGNER.sign(sk, _POP_PREFIX + pub)


def verify_possession(pub: bytes, pop: bytes) -> bool:
    """The manager's check before certifying `pub` — never certify an unheld key."""
    return SIGNER.verify(pub, _POP_PREFIX + pub, pop)


# --------------------------------------------------------------------------- #
# Signer-set bitmap (which nodes signed — DESIGN §8)                           #
# --------------------------------------------------------------------------- #


def bitmap_set(indices: Iterable[int], n: int) -> bytes:
    """Pack signer indices into a big-endian bit set over an n-node roster.
    Bit i (MSB-first within each byte) set <=> node i signed."""
    nbytes = (n + 7) // 8
    buf = bytearray(nbytes)
    for i in indices:
        if not (0 <= i < n):
            raise CryptoError(f"signer index {i} out of range for n={n}")
        buf[i >> 3] |= 0x80 >> (i & 7)
    return bytes(buf)


def bitmap_indices(bitmap: bytes, n: int) -> list[int]:
    """Iterate the set signer indices in ascending order."""
    out: list[int] = []
    for i in range(n):
        if bitmap[i >> 3] & (0x80 >> (i & 7)):
            out.append(i)
    return out


def bitmap_count(bitmap: bytes, n: int) -> int:
    return len(bitmap_indices(bitmap, n))


# --------------------------------------------------------------------------- #
# MultiSig — node receipts -> QC (DESIGN §8)                                   #
# --------------------------------------------------------------------------- #


class Ed25519ListMultiSig:
    """The concatenated-signature-list instantiation (DESIGN §8, decided for
    v1): a signer bitmap plus one Ed25519 signature per signer, all over the
    identical message. A drop-in for a future BLS aggregate behind this same
    interface (ARCHITECTURE L0). No proof-of-possession needed (lists don't
    aggregate)."""

    suite_id = MULTISIG_SUITE

    @staticmethod
    def sign_share(sk: bytes, msg: bytes) -> bytes:
        return _ed25519_sign(sk, msg)

    @staticmethod
    def combine(shares_by_index: dict[int, bytes], n: int) -> tuple[bytes, list[bytes]]:
        """shares_by_index: {roster_index: signature}. Returns (bitmap, sigs)
        with sigs ordered by ascending index to match bitmap iteration."""
        indices = sorted(shares_by_index)
        bitmap = bitmap_set(indices, n)
        sigs = [shares_by_index[i] for i in indices]
        return bitmap, sigs

    @staticmethod
    def verify(bitmap: bytes, sigs: list[bytes], msg: bytes, roster_pubkeys: list[bytes]) -> bool:
        """Verify every listed signature against its named roster member over
        the identical `msg`. Quorum/majority sizing is the QC layer's job
        (artifacts.py); here we only check that the claimed signers really
        signed."""
        n = len(roster_pubkeys)
        indices = bitmap_indices(bitmap, n)
        if len(indices) != len(sigs):
            return False
        for idx, sig in zip(indices, sigs, strict=False):
            if not _ed25519_verify(roster_pubkeys[idx], msg, sig):
                return False
        return True

    @staticmethod
    def verify_each(
        bitmap: bytes, sigs: list[bytes], msgs: list[bytes], roster_pubkeys: list[bytes]
    ) -> bool:
        """Verify each listed signature against ITS OWN message (finding-17): the
        shares no longer sign an identical message — each carries the signer's own
        `issue_seq` — so `msgs[i]` is the message for the i-th named signer (index
        order). Bitmap-count / quorum sizing stays the QC layer's job."""
        n = len(roster_pubkeys)
        indices = bitmap_indices(bitmap, n)
        if len(indices) != len(sigs) or len(indices) != len(msgs):
            return False
        for idx, sig, msg in zip(indices, sigs, msgs, strict=False):
            if not _ed25519_verify(roster_pubkeys[idx], msg, sig):
                return False
        return True


MULTISIG = Ed25519ListMultiSig


# --------------------------------------------------------------------------- #
# Epoch key derivation — K_epoch master -> working keys (CRYPTO.md §2 / NOTES  #
# 48, finding 21). The wrap-set seals ONE 32-byte master per epoch; every      #
# working key is a keyed-BLAKE2b subkey under a fixed person domain. One wrap  #
# distributes all; rotation/escrow hold one secret. Never wrap the pair.       #
# --------------------------------------------------------------------------- #

PERSON_ENC = b"dude.enc"  # data_key — the xcs1 AEAD key (payload confidentiality)
PERSON_SLOT = b"dude.slot"  # slot_secret — the PRF key for slot tags (§7)
PERSON_NONCE = b"dude.nonce"  # nk — the xcs1 SIV nonce subkey (derived under data_key)


def _epoch_subkey(master: bytes, person: bytes) -> bytes:
    """A 32-byte keyed-BLAKE2b subkey of `master` under a person domain. The
    person separates the working keys so no two are ever equal, and knowledge of
    one never yields another (domain separation)."""
    return hashlib.blake2b(b"", key=master, person=person, digest_size=DIGEST_SIZE).digest()


def derive_data_key(master: bytes) -> bytes:
    """The xcs1 AEAD key for `master` (K_epoch), `person=b"dude.enc"`."""
    return _epoch_subkey(master, PERSON_ENC)


def derive_slot_secret(master: bytes) -> bytes:
    """The slot-tag PRF secret for `master` (K_epoch), `person=b"dude.slot"`."""
    return _epoch_subkey(master, PERSON_SLOT)


# --------------------------------------------------------------------------- #
# AEAD — data payloads (DESIGN §5, staged per IMPLEMENTATION §1)               #
# --------------------------------------------------------------------------- #


NONCE_SIZE = 24  # XChaCha20 (192-bit) nonce
AEAD_TAG_SIZE = 16  # Poly1305 tag


class AeadXcs1:
    """Suite `xcs1`: XChaCha20-Poly1305-IETF (libsodium) with an SIV-derived,
    misuse-resistant nonce. The kernel is deterministic, so nonces are *derived*,
    not random; folding the plaintext into the nonce (SIV) makes keystream reuse
    structurally impossible even for an equivocating/crash-retrying author who
    emits two payloads under one header (CRYPTO.md §2). Zero-knowledge is on.

    Sealed blob layout: `nonce(24) ‖ ciphertext ‖ tag(16)` — the derived nonce
    travels with the ciphertext because `open` cannot re-derive it (it lacks the
    plaintext). AD binds the envelope-minus-payload and is NOT stored (the caller
    recomputes it from the envelope)."""

    suite_id = b"xcs1"

    @staticmethod
    def _nonce(k: bytes, aad: bytes, pt: bytes) -> bytes:
        # SIV nonce (CRYPTO.md §2). nk: the `dude.nonce` subkey of the AEAD key `k`
        # (which is itself K_epoch's `dude.enc` subkey, finding 21); nonce: 24-byte
        # keyed digest over AD ‖ H(plaintext), so two plaintexts under one header get
        # independent nonces. These vectors are the construction's canonical
        # reference (KATs; the Rust/Go ports match).
        nk = _epoch_subkey(k, PERSON_NONCE)
        return hashlib.blake2b(aad + h(pt), key=nk, digest_size=NONCE_SIZE).digest()

    @classmethod
    def seal(cls, k: bytes, aad: bytes, pt: bytes) -> bytes:
        nonce = cls._nonce(k, aad, pt)
        enc = nacl.secret.Aead(k).encrypt(pt, aad, nonce)  # nonce ‖ ct ‖ tag
        return bytes(enc)

    @classmethod
    def open(cls, k: bytes, aad: bytes, sealed: bytes) -> bytes | None:
        if len(sealed) < NONCE_SIZE + AEAD_TAG_SIZE:
            return None
        try:
            return nacl.secret.Aead(k).decrypt(sealed, aad)
        except (nacl.exceptions.CryptoError, ValueError):
            return None  # authentication failure — decrypt fails loudly (⊥)


# ONE payload scheme, no suite menu (NOTES 42 — agility is a downgrade surface).
# The AEAD is the constant `AEAD`, not a registry lookup: a scheme change is a
# lane-2 pver fence + keyepoch rotation, never a per-op suite id (NOTES 48 nit).
# Recorded fallbacks if a standards-stamped MRAE is ever demanded (CRYPTO.md §2):
# `dxy2` (Deoxys-II), `AES-SIV`/`AES-GCM-SIV` — each one keyepoch bump away.
AEAD = AeadXcs1


# --------------------------------------------------------------------------- #
# Sealed box — group-key distribution (wrap-sets, DESIGN §3 / §15)             #
# --------------------------------------------------------------------------- #

WRAPSET_SUITE = b"sbx1"


def seal_to(recipient_pub: bytes, msg: bytes) -> bytes:
    """Suite `sbx1`: an anonymous libsodium sealed box (crypto_box_seal) to a
    member's *Ed25519 identity*, converted to its X25519 agreement key. Used to
    wrap the per-keyepoch group key K_epoch to each roster/client member (the
    WRAP_SET control op, DESIGN §3). An ephemeral sender keypair per seal means
    there is no sender authentication (the enclosing control op's signature
    provides provenance) and the ciphertext is NON-deterministic — so `sbx1` has
    no byte-pinned KAT, only a functional one (member opens; others cannot)."""
    xpk = nacl.signing.VerifyKey(recipient_pub).to_curve25519_public_key()
    return bytes(nacl.public.SealedBox(xpk).encrypt(msg))


def open_sealed(recipient_sk: bytes, sealed: bytes) -> bytes | None:
    """Open an `sbx1` sealed box addressed to this member's Ed25519 seed (via its
    X25519 agreement key), or None if it was sealed to someone else / tampered."""
    try:
        xsk = nacl.signing.SigningKey(recipient_sk).to_curve25519_private_key()
        return bytes(nacl.public.SealedBox(xsk).decrypt(sealed))
    except (nacl.exceptions.CryptoError, ValueError):
        return None
