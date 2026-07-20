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
#   AEAD      seal(k,nonce,aad,pt) / open(...)       data payloads (staged, §16)
#   Signer    sign(sk,msg) / verify(pk,msg,sig)      authors (Ed25519)
#   MultiSig  sign_share / combine / verify          node receipts -> QC (§8)
#
# v1 concrete choices (IMPLEMENTATION §1): BLAKE2b-256, keyed-BLAKE2 PRF,
# Ed25519 (authors) + Ed25519 signature list & signer bitmap (node MultiSig),
# and the `auth0` AEAD suite — authenticated-UNENCRYPTED. auth0 suspends
# zero-knowledge *loudly*: callers must surface `zero_knowledge_active()`.

from __future__ import annotations

import hashlib
import hmac
from collections.abc import Iterable

from .errors import DudeFSError
from .vendor import ed25519


class CryptoError(DudeFSError):
    """The crypto module's base error: suite/parameter misuse (unknown suite id,
    out-of-range signer index). (The vendored Ed25519 raises stdlib ValueError
    on a malformed key — a programmer error, left as-is to keep it standalone.)"""


# --------------------------------------------------------------------------- #
# Default suite ids (genesis picks these; control ops may bump them — §16)     #
# --------------------------------------------------------------------------- #

HASH_SUITE = b"blake2b-256"
SIGNER_SUITE = b"ed25519"
MULTISIG_SUITE = b"ed25519-list"
PRF_SUITE = b"blake2b-tag"
AEAD_SUITE = b"auth0"


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
    """L0 Signer over the vendored RFC 8032 implementation. `sk` is the 32-byte
    seed; the public key is derived. POC-only (not constant-time)."""

    suite_id = SIGNER_SUITE

    @staticmethod
    def public(sk: bytes) -> bytes:
        return ed25519.publickey(sk)

    @staticmethod
    def sign(sk: bytes, msg: bytes) -> bytes:
        return ed25519.sign(sk, msg)

    @staticmethod
    def verify(pk: bytes, msg: bytes, sig: bytes) -> bool:
        return ed25519.verify(pk, msg, sig)


SIGNER = Ed25519Signer


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
        return ed25519.sign(sk, msg)

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
            if not ed25519.verify(roster_pubkeys[idx], msg, sig):
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
            if not ed25519.verify(roster_pubkeys[idx], msg, sig):
                return False
        return True


MULTISIG = Ed25519ListMultiSig


# --------------------------------------------------------------------------- #
# AEAD — data payloads (DESIGN §5, staged per IMPLEMENTATION §1)               #
# --------------------------------------------------------------------------- #


def _mac(subkey: bytes, aad: bytes, ct: bytes) -> bytes:
    # Injective framing: le64(len(aad)) ‖ aad ‖ le64(len(ct)) ‖ ct, then keyed
    # BLAKE2 (IMPLEMENTATION §1). Length prefixes stop aad/ct boundary confusion.
    msg = len(aad).to_bytes(8, "little") + aad + len(ct).to_bytes(8, "little") + ct
    return hashlib.blake2b(msg, key=subkey, digest_size=DIGEST_SIZE).digest()


class AeadAuth0:
    """Suite `auth0` (launch): authenticated-UNENCRYPTED. `ct = pt`; a keyed
    BLAKE2 MAC binds (nonce, aad, ct). **Zero-knowledge is suspended — this
    suite does not conceal payloads.** Every other property (provenance,
    durability, CAS, finality, detect-and-punish) is exercised for real.
    Migration to a real cipher (`b2s1`/`xcp1`) is a keyepoch rotation (§16)."""

    suite_id = b"auth0"
    confidential = False

    @staticmethod
    def _subkey(k: bytes, nonce: bytes) -> bytes:
        return hashlib.blake2b(nonce, key=k, person=b"dude.mac").digest()[:32]

    @classmethod
    def seal(cls, k: bytes, nonce: bytes, aad: bytes, pt: bytes) -> tuple[bytes, bytes]:
        ct = pt
        tag = _mac(cls._subkey(k, nonce), aad, ct)
        return ct, tag

    @classmethod
    def open(cls, k: bytes, nonce: bytes, aad: bytes, ct: bytes, tag: bytes) -> bytes | None:
        expected = _mac(cls._subkey(k, nonce), aad, ct)
        if not hmac.compare_digest(expected, tag):
            return None  # authentication failure — decrypt fails loudly (⊥)
        return ct  # pt == ct under auth0


AEAD_SUITES = {
    b"auth0": AeadAuth0,
    # b"b2s1": AeadB2s1,   # BLAKE2 stream+MAC — later (IMPLEMENTATION §1, M8)
    # b"xcp1": AeadXcp1,   # vendored ChaCha20-Poly1305 — alternative
}


def get_aead(suite_id: bytes = AEAD_SUITE) -> type[AeadAuth0]:
    try:
        return AEAD_SUITES[suite_id]
    except KeyError:
        raise CryptoError(f"unknown AEAD suite {suite_id!r}") from None


def zero_knowledge_active(aead_suite_id: bytes = AEAD_SUITE) -> bool:
    """False under `auth0` — the README banner and `dude status` MUST say so
    (IMPLEMENTATION §1). True once a confidential suite is active."""
    return bool(get_aead(aead_suite_id).confidential)
