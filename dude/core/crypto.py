# dude — cryptographic primitives. See ../../SPEC.md.
#
# Salvaged from the previous package, trimmed to what SPEC needs, with three changes marked
# in place: the slot-tag PRF is GONE (slots are deleted — SPEC "do not reintroduce"), key
# derivation is split into permanent-name / rotating-value (#two-secrets), and the AEAD uses a
# random nonce so a key's value cardinality is not observable (#random-nonce; see AeadXcs1).
#
# What is here, and the SPEC clause each one serves:
#
#   h(bytes) -> 32B                    content addressing (BLAKE2b-256)
#   Ed25519 sign / verify              every operation is signed by its author (1.2)
#   Ed25519 list multisig + bitmap     N-of-M over a slice = the quorum proof (2.2)
#   ECMH accumulator (acc_*)           order-independent set fingerprint (5.8c, gossip §3.2)
#   AEAD seal/open (random nonce)      no cardinality leak (4.4, 4.5, 11.4d)
#   PublicKey.seal / Keypair.open_sealed  wrapping a master to each client (9.5)
#   derive_name_key / derive_value_key two secrets, never one (9.7)
#   possession proof (on the key types) binds a key to its holder at issuance
#
# Every key operation hangs off `PublicKey` or `Keypair` — there is no function here that
# takes a raw seed. That is deliberate: a free `open_sealed(sk, ...)` / `prove_possession(sk)`
# is an invitation to pass secret bytes around, which defeats `Keypair._seed` being private.
#
# No suite registry and no agility: one scheme per job. A scheme change is a keyepoch
# rotation, never a per-operation suite id — agility is a downgrade surface.

from __future__ import annotations

import hashlib
from collections.abc import Iterable
from enum import Enum
from typing import NamedTuple, Self

import nacl.bindings
import nacl.exceptions
import nacl.public
import nacl.secret
import nacl.signing
import nacl.utils

from .errors import DudeError


def _ed25519_sign(sk: Seed, msg: bytes) -> Signature:
    return Signature(nacl.signing.SigningKey(sk).sign(msg).signature)


def _ed25519_public(sk: Seed) -> PublicKey:
    return PublicKey(bytes(nacl.signing.SigningKey(sk).verify_key))


def _ed25519_verify(pk: PublicKey, msg: bytes, sig: Signature) -> VerifyFailure | None:
    """`None` if it verifies, otherwise WHY — returned, not raised.

    The two reasons are different facts and must not be flattened into one bool: a non-matching
    signature is about the message, a non-point key is about the key."""
    if not nacl.bindings.crypto_core_ed25519_is_valid_point(pk):
        # Explicit, because PyNaCl will not tell us: it defers point decompression to verify time
        # and reports a non-point key as a bad signature.
        return VerifyFailure.MALFORMED_KEY
    try:
        nacl.signing.VerifyKey(pk).verify(msg, sig)
    except (nacl.exceptions.BadSignatureError, nacl.exceptions.CryptoError, ValueError):
        return VerifyFailure.BAD_SIGNATURE
    return None


class CryptoError(DudeError):
    """The crypto module's base error: parameter misuse (bad bitmap width, out-of-range
    signer index, malformed key material)."""


class VerifyFailure(Enum):
    """Why a signature did not verify. A RETURNED VALUE, never an exception.

    A signature that does not match is the most routine answer this package gives — it is the normal
    result of receiving a message from someone who did not author it. Raising for it would be using
    exceptions for control flow, and it is not hypothetical: `_ed25519_verify` briefly RAISED
    instead
    of returning, which made `if not _ed25519_verify(...)` vacuously true and silently broke EVERY
    multisig verification in the system. Nothing caught it because nothing exercised the path.

    Closed, and `INVALID` is reserved at ordinal 0 so a Go port's zero value lands on a named
    invalid
    rather than on a real outcome."""

    INVALID = "invalid"
    BAD_SIGNATURE = "bad-signature"
    """The signature does not match this key and message. A fact about a MESSAGE."""
    MALFORMED_KEY = "malformed-key"
    """The key is the right width but not a point on the curve. A fact about a KEY — the same
    signature might verify perfectly against a real one, so blaming the payload is wrong."""


class AeadError(CryptoError):
    """Base for an AEAD open failure. Catch this to treat every flavour alike; catch a leaf
    when the flavours mean different things — and they do, see below."""


class AeadMalformedError(AeadError):
    """Structurally impossible: shorter than nonce ‖ tag. Nothing was attempted."""


class AeadAuthFailedError(AeadError):
    """Authentication failed: wrong key, wrong AAD, or tampered ciphertext. Which of those it
    was is deliberately not knowable — that indistinguishability is the AEAD's job."""


class SealedBoxError(CryptoError):
    """An `sbx1` sealed box would not open: sealed to someone else, or tampered. One error, not
    two, because an anonymous sealed box genuinely cannot distinguish them — that is the
    anonymity property, not missing detail. Expected when scanning a wrap-set for one's own
    entry, so callers scanning SHOULD catch it."""


# --------------------------------------------------------------------------- #
# Scheme identifiers — a RECORD of what is in use, not a selector.             #
# Nothing looks a scheme up by id: there is one scheme per job, and changing    #
# one is a keyepoch rotation. These exist so a stored artifact can say what     #
# produced it. (`PRF_SUITE` is gone with the slot-tag PRF.)                     #
# --------------------------------------------------------------------------- #

HASH_SUITE = b"blake2b-256"
SIGNER_SUITE = b"ed25519"
MULTISIG_SUITE = b"ed25519-list"
AEAD_SUITE = b"xcs1"
WRAPSET_SUITE = b"sbx1"  # PublicKey.seal / Keypair.open_sealed


# --------------------------------------------------------------------------- #
# Widths, in one place — the typed byte strings below are built from them.       #
# --------------------------------------------------------------------------- #

DIGEST_SIZE = 32
NONCE_SIZE = 24  # XChaCha20 (192-bit)
AEAD_TAG_SIZE = 16  # Poly1305
ACC_SIZE = nacl.bindings.crypto_core_ed25519_BYTES  # 32 — the curve point width
SIG_SIZE = 64
SCREEN_TAG_SIZE = 16


# --------------------------------------------------------------------------- #
# Typed byte strings — every 32-byte blob is NOT the same 32-byte blob.        #
# --------------------------------------------------------------------------- #
# All of these are `bytes` subclasses, so on the wire they are free: `codec` encodes by
# `isinstance(v, bytes)`, and a subclass encodes byte-identically to the raw value. The
# whole cost is one explicit wrap on DECODE — `Digest(codec.as_bytes(p[0]))` — and that wrap
# is where the width check fires, so it is doing work rather than ceremony.
#
# What this buys: `Digest`, `NameToken` and `Accumulator` are all 32 bytes out of hash-shaped
# functions and are the most confusable values in the system; `NameKey` and `ValueKey` are the
# two halves #two-secrets says must never be one, so swapping them becomes a TYPE ERROR rather
# than a silent O(state) re-encryption discovered in production.
#
# What it does NOT buy, stated so nobody expects it: equality is still `bytes` equality, so
# `Digest(x) == NameToken(x)` is True at runtime. The discrimination is static. Overriding
# __eq__ would break dict/set behaviour and hashing, which costs more than it saves.
# Slicing or concatenating also degrades to plain `bytes`, which is intended.


class _Fixed(bytes):
    """Base for a fixed-width typed byte string. Subclasses set `WIDTH`."""

    __slots__ = ()
    WIDTH = 0

    def __new__(cls, raw: bytes):
        if len(raw) != cls.WIDTH:
            raise CryptoError(f"{cls.__name__} must be {cls.WIDTH} bytes, got {len(raw)}")
        return super().__new__(cls, raw)


class Digest(_Fixed):
    """A BLAKE2b-256 content address — `h()`'s output, an operation's identity."""

    WIDTH = DIGEST_SIZE
    __slots__ = ()


class NameToken(_Fixed):
    """The opaque key identifier a node sees. Derived under the PERMANENT name key, so it is
    stable across every keyepoch rotation (#two-secrets)."""

    WIDTH = DIGEST_SIZE
    __slots__ = ()


class Accumulator(_Fixed):
    """An ECMH accumulator value — a curve point, not a hash. Same width as `Digest` and
    routinely confused with one; that confusion is what this type exists to prevent."""

    WIDTH = ACC_SIZE
    __slots__ = ()


class Signature(_Fixed):
    """An Ed25519 signature."""

    WIDTH = SIG_SIZE
    __slots__ = ()


class Master(_Fixed):
    """An unwrapped 32-byte master secret — either the permanent one or a keyepoch's. What
    `PublicKey.seal` distributes and `Keypair.open_sealed` recovers (#wrapped-masters)."""

    WIDTH = 32
    __slots__ = ()


class NameKey(_Fixed):
    """Derived from the PERMANENT master. Never rotates (#two-secrets)."""

    WIDTH = DIGEST_SIZE
    __slots__ = ()


class ValueKey(_Fixed):
    """Derived from a KEYEPOCH master. Rotates — the half forward secrecy applies to."""

    WIDTH = DIGEST_SIZE
    __slots__ = ()


class ItemKey(_Fixed):
    """The per-`(name, version)` AEAD key derived from a `ValueKey` (#per-item-key)."""

    WIDTH = DIGEST_SIZE
    __slots__ = ()


class Seed(_Fixed):
    """An Ed25519 private seed. Deliberately distinct from `Master`: both are 32-byte secrets,
    so `Keypair.from_seed(master)` is an easy and catastrophic mistake — one that produces a
    working keypair nobody else knows about."""

    WIDTH = 32
    __slots__ = ()


class Nonce(_Fixed):
    """An `xcs1` SIV nonce, derived — never chosen. See `AeadXcs1.open` for why choosing one
    is a soundness break rather than a style question."""

    WIDTH = NONCE_SIZE
    __slots__ = ()


class ScreenTag(_Fixed):
    """The transport screening tag for oblivious filtering (#screen-tag)."""

    WIDTH = SCREEN_TAG_SIZE
    __slots__ = ()


class SignerBitmap(bytes):
    """Which roster positions signed, MSB-first. Variable width — `(n + 7) // 8` for the
    roster size it was built against, which is why it carries no fixed WIDTH."""

    __slots__ = ()


class SealedBlob(bytes):
    """An `sbx1` anonymous sealed box — the output of `PublicKey.seal`."""

    __slots__ = ()


class AeadBlob(bytes):
    """An `xcs1` sealed payload: `nonce ‖ ciphertext ‖ tag`. Distinct from `SealedBlob`
    because handing one to the other's open path is an easy and silent mistake."""

    __slots__ = ()


# --------------------------------------------------------------------------- #
# Hash (content addressing)                                                    #
# --------------------------------------------------------------------------- #


def h(data: bytes) -> Digest:
    """Content-address hash. `op_hash = h(bytes-as-received)` (IMPLEMENTATION §2)."""
    return Digest(hashlib.blake2b(data, digest_size=DIGEST_SIZE).digest())


def random_bytes(n: int) -> bytes:
    """Cryptographic randomness, funnelled through one function on purpose.

    Everything unpredictable in the protocol — nonces, message ids, seeds — comes from here, so
    "where does randomness enter?" has one answer and a test can find every caller. `random` is
    never acceptable for any of them, which ruff's `S311` enforces at the other end."""
    return nacl.utils.random(n)


# --------------------------------------------------------------------------- #
# State accumulator — ECMH over the ed25519 prime-order subgroup (ACCUMULATOR) #
# --------------------------------------------------------------------------- #
# A commutative, incremental digest of a SET of elements (the live-key state).
# `acc_element` maps a canonical element encoding to a curve point via libsodium's
# Elligator2 map WITH the cofactor cleared (`from_uniform` lands on the prime-order
# subgroup), so the sum is MuHash-on-a-curve: collision-resistant under discrete log,
# a fixed 32-byte digest independent of set size, add/sub the group op + inverse.
# XHASH was rejected (silent key-drop via GF(2) subset-cancellation); Ristretto255 is
# not exposed by PyNaCl, but ed25519+from_uniform gives the same prime-order + canonical
# encoding we need (ACCUMULATOR §6).

PERSON_ACC = b"dude.acc:v1"  # element-hash domain separation (frozen: goldens depend on it)
# The neutral element (identity point (0,1)) = the digest of the EMPTY set.
ACC_IDENTITY = Accumulator(b"\x01" + b"\x00" * (ACC_SIZE - 1))


def acc_element(enc: bytes) -> Accumulator:
    """φ(e): map a canonical element encoding to its prime-order curve point — a
    domain-separated 32-byte hash through Elligator2 + cofactor clear. `enc` MUST be a
    canonical, injective serialization of the element (ACCUMULATOR §3.1)."""
    return Accumulator(nacl.bindings.crypto_core_ed25519_from_uniform(h(PERSON_ACC + enc)))


def acc_add(a: Accumulator, b: Accumulator) -> Accumulator:
    """Add element/point `b` into accumulator `a` (the group op ⊕)."""
    return Accumulator(nacl.bindings.crypto_core_ed25519_add(a, b))


def acc_sub(a: Accumulator, b: Accumulator) -> Accumulator:
    """Remove element/point `b` from accumulator `a` (the inverse ⊖) — self-consistent
    with `acc_add`, so an update is `acc_sub(acc_add(A, new), old)`."""
    return Accumulator(nacl.bindings.crypto_core_ed25519_sub(a, b))


PERSON_SCREEN = b"dude.screen"  # L_msg to_hint — the screening tag domain (TRANSPORT §3)


def screen_tag(node_identity: PublicKey, sealed: bytes) -> ScreenTag:
    """The frame discriminator of #screen-tag, for a channel WITHOUT link-level confidentiality:
    keyed-BLAKE2 over the sealed bytes, keyed by the TARGET's identity pubkey (never an
    epoch-scoped key — that deadlocks a from-scratch sync), domain-separated `dude.screen`.

    The sender keys on the target's identity; the receiver keys on its OWN and compares. One
    symmetric hash, and only on a match is the far more expensive ECDH against the ephemeral
    key worth doing.

    TWO properties, both load-bearing (#sign-then-seal):

    * a non-member knows no identity, so it cannot forge a tag — garbage costs one hash;
    * `sealed` is an input, so the tag DIFFERS PER MESSAGE. Drop that input and the tag
      degrades to a static per-node fingerprint: a passive linkability handle, forgeable
      forever by anyone who ever saw one. A test for this must fail when `sealed` stops
      being used — the previous package's did not, which is how the hazard stayed invisible."""
    return ScreenTag(
        hashlib.blake2b(
            sealed, key=node_identity, person=PERSON_SCREEN, digest_size=SCREEN_TAG_SIZE
        ).digest()
    )


# --------------------------------------------------------------------------- #
# Signer — authors (Ed25519)                                                   #
# --------------------------------------------------------------------------- #


# (No `Signer` facade class. It wrapped the three `_ed25519_*` functions for a suite registry
# that no longer exists, and its only callers were the two functions immediately below.
# Ed25519 signing is RFC 8032 deterministic, so these are byte-identical to any conforming
# implementation — worth knowing when a port needs to match.)


# --------------------------------------------------------------------------- #
# Proof-of-possession (NOTES 58): the manager signs pubkeys only and never       #
# certifies an unheld key — the subject proves it holds the sk by signing a      #
# domain-separated self-attestation over its own pubkey. Non-interactive (no     #
# challenge round trip); replay-safe because the pop is bound to THAT pubkey and #
# cannot be transplanted to another. The `dude.pop:` prefix keeps it disjoint    #
# from every real signed artifact (ops sign an envelope, never this message).    #
# --------------------------------------------------------------------------- #

_POP_PREFIX = b"dude.pop:"


# --------------------------------------------------------------------------- #
# PublicKey / Keypair — the typed key face (no raw blobs above L0)             #
# --------------------------------------------------------------------------- #


class PublicKey(_Fixed):
    """An Ed25519 verify key — 32 bytes WITH identity. A `bytes` subclass, so it is
    still a dict key, encodes as itself on the wire, and compares equal to the raw
    pubkey already stored in envelopes (decode just wraps it — zero wire change). It
    carries the public-key operations so nothing above L0 hands a raw blob to the
    suite."""

    WIDTH = 32
    __slots__ = ()

    def verify(self, msg: bytes, sig: Signature) -> bool:
        """Does this signature match? The convenience form, when the reason does not matter."""
        return _ed25519_verify(self, msg, sig) is None

    def why_not(self, msg: bytes, sig: Signature) -> VerifyFailure | None:
        """`None` if it verifies, else the reason — for a caller that distinguishes a bad signature
        from a key that is not a key."""
        return _ed25519_verify(self, msg, sig)

    def seal(self, msg: bytes) -> SealedBlob:
        """Wrap `msg` TO this key — suite `sbx1`, an anonymous libsodium sealed box to this
        Ed25519 identity via its X25519 agreement key. This is how a master is distributed to
        each authorised client (#wrapped-masters).

        An ephemeral sender keypair per seal means there is no sender authentication (the
        enclosing operation's signature carries provenance) and the ciphertext is
        NON-deterministic — so `sbx1` admits no byte-pinned KAT, only a functional one:
        the holder opens it, nobody else does."""
        xpk = nacl.signing.VerifyKey(self).to_curve25519_public_key()
        return SealedBlob(nacl.public.SealedBox(xpk).encrypt(msg))

    def verify_possession(self, pop: Signature) -> bool:
        """Check the subject's self-attestation that it holds the matching secret — what the
        manager checks before authorising a key it never generated."""
        return self.verify(_POP_PREFIX + self, pop)

    def fingerprint(self) -> Digest:
        return h(self)


class Keypair:
    """A signing identity: an Ed25519 seed held in this process.

    One concrete class, no abstract base — if a hardware-backed variant is ever needed, the
    interface gets built then, against a real second implementation. The seed stays private
    (`_seed`, never a property) so that remains a possible change rather than a wide one.

    Signing and decryption share the one Ed25519 identity: `open_sealed` uses its X25519
    conversion, which is where a hardware backend would most likely want to split them."""

    __slots__ = ("_public", "_seed")

    def __init__(self, seed: Seed):
        self._seed = Seed(seed)  # re-wrap: enforces the width at runtime too, not just statically
        self._public = PublicKey(_ed25519_public(seed))

    @classmethod
    def generate(cls) -> Self:
        return cls(Seed(bytes(nacl.signing.SigningKey.generate())))

    @classmethod
    def from_seed(cls, seed: Seed) -> Self:
        return cls(seed)

    @property
    def public(self) -> PublicKey:
        return self._public

    def sign(self, msg: bytes) -> Signature:
        return Signature(_ed25519_sign(self._seed, msg))

    def open_sealed_raw(self, blob: SealedBlob) -> bytes:
        """Open an `sbx1` sealed box addressed to this identity, returning plain bytes.

        Exists because `open_sealed` coerces to `Master` — right for key distribution
        (#wrapped-masters),
        wrong for the transport-confidentiality layer, where the plaintext is a signed p2p envelope
        and not a secret at all. Same primitive, two callers, no lying about the type."""
        try:
            xsk = nacl.signing.SigningKey(self._seed).to_curve25519_private_key()
            return nacl.public.SealedBox(xsk).decrypt(blob)
        except (nacl.exceptions.CryptoError, ValueError) as e:
            raise SealedBoxError("sealed box would not open (not ours, or tampered)") from e

    def open_sealed(self, blob: SealedBlob) -> Master:
        """Open an `sbx1` sealed box addressed to this identity — recovering a wrapped master
        (#wrapped-masters) — via this key's X25519 agreement conversion.

        Raises `SealedBoxError` if the box was sealed to someone else or was tampered with:
        one error, because an anonymous sealed box cannot distinguish those by design. A
        client scanning the management store for its own wrapped entry will hit this on every
        entry that is not its own, so scan with `except SealedBoxError: continue`."""
        try:
            xsk = nacl.signing.SigningKey(self._seed).to_curve25519_private_key()
            return Master(nacl.public.SealedBox(xsk).decrypt(blob))
        except (nacl.exceptions.CryptoError, ValueError) as e:
            raise SealedBoxError("sealed box would not open (not ours, or tampered)") from e

    def prove_possession(self) -> Signature:
        """Self-attest holding this identity. Keys generate where they live; only the public
        half and this proof ever travel."""
        return self.sign(_POP_PREFIX + self.public)


# --------------------------------------------------------------------------- #
# Signer-set bitmap (which nodes signed — DESIGN §8)                           #
# --------------------------------------------------------------------------- #


NO_SIGNERS = SignerBitmap(b"")
"""An empty bitmap: nobody has signed. A named value rather than a bare `b""`, so that
"unsigned" reads as a state rather than as a forgotten field."""


def bitmap_size(n: int) -> int:
    """Bytes needed for an `n`-member bitmap. Exposed so a caller can reject a bitmap of the
    wrong width up front — a cheaper and clearer complaint than a signature that fails to match."""
    return (n + 7) // 8


def bitmap_set(indices: Iterable[int], n: int) -> SignerBitmap:
    """Pack signer indices into a big-endian bit set over an n-node roster.
    Bit i (MSB-first within each byte) set <=> node i signed."""
    nbytes = (n + 7) // 8
    buf = bytearray(nbytes)
    for i in indices:
        if not (0 <= i < n):
            raise CryptoError(f"signer index {i} out of range for n={n}")
        buf[i >> 3] |= 0x80 >> (i & 7)
    return SignerBitmap(buf)


def bitmap_indices(bitmap: SignerBitmap, n: int) -> list[int]:
    """Iterate the set signer indices in ascending order.

    The length check is not optional here: `bitmap` arrives off the wire inside a quorum
    proof, and indexing `bitmap[i >> 3]` on a short one raises IndexError — outside the
    DudeError tree, therefore a process kill under crash-only. Typed rejection instead."""
    if len(bitmap) != (n + 7) // 8:
        want = (n + 7) // 8
        raise CryptoError(f"signer bitmap is {len(bitmap)}B, expected {want}B for n={n}")
    return [i for i in range(n) if bitmap[i >> 3] & (0x80 >> (i & 7))]


def bitmap_count(bitmap: SignerBitmap, n: int) -> int:
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
    def sign_share(sk: Seed, msg: bytes) -> Signature:
        return _ed25519_sign(sk, msg)

    @staticmethod
    def combine(
        shares_by_index: dict[int, Signature], n: int
    ) -> tuple[SignerBitmap, list[Signature]]:
        """shares_by_index: {roster_index: signature}. Returns (bitmap, sigs)
        with sigs ordered by ascending index to match bitmap iteration."""
        indices = sorted(shares_by_index)
        bitmap = bitmap_set(indices, n)
        sigs = [shares_by_index[i] for i in indices]
        return bitmap, sigs

    @staticmethod
    def verify(
        bitmap: SignerBitmap, sigs: list[Signature], msg: bytes, roster_pubkeys: list[PublicKey]
    ) -> bool:
        """Verify every listed signature against its named roster member over
        the identical `msg`. Quorum/majority sizing is the QC layer's job
        (artifacts.py); here we only check that the claimed signers really
        signed."""
        n = len(roster_pubkeys)
        indices = bitmap_indices(bitmap, n)
        if len(indices) != len(sigs):
            return False
        for idx, sig in zip(indices, sigs, strict=False):
            # `PublicKey.verify`, NOT `_ed25519_verify`: the latter RAISES the specific reason and
            # returns None, so `if not ...` was vacuously true and EVERY multisig verification
            # returned False. Introduced when verification split into typed errors, and invisible
            # because nothing exercised this path.
            if not roster_pubkeys[idx].verify(msg, sig):
                return False
        return True

    @staticmethod
    def verify_each(
        bitmap: SignerBitmap,
        sigs: list[Signature],
        msgs: list[bytes],
        roster_pubkeys: list[PublicKey],
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
            if not roster_pubkeys[idx].verify(msg, sig):  # bool wrapper, see `verify` above
                return False
        return True


MULTISIG = Ed25519ListMultiSig


# --------------------------------------------------------------------------- #
# Key derivation — one master -> working keys. Every working key is a keyed-    #
# BLAKE2b subkey under a fixed person domain, so no two are ever equal and      #
# knowledge of one never yields another. A holder unwraps ONE secret and derives #
# the rest locally (#wrapped-masters: the manager distributes masters, not key sets).    #
# --------------------------------------------------------------------------- #

PERSON_ENC = b"dude.enc"  # value_key — the AEAD key (payload confidentiality)
PERSON_NONCE = b"dude.nonce"  # nk — the SIV nonce subkey (derived under the item key)


# Any 32-byte SECRET may be domain-separated into a subkey. Named as a union rather than
# `bytes` so that a PUBLIC 32-byte value — a Digest, a PublicKey, an Accumulator — is refused:
# using one as key material is the mistake worth catching here.
type Secret = Master | Seed | NameKey | ValueKey | ItemKey


def _subkey(master: Secret, person: bytes) -> bytes:
    """A 32-byte keyed-BLAKE2b subkey of `master` under a person domain. Not epoch-specific:
    the same helper derives from the rotating keyepoch master and from the permanent one."""
    return hashlib.blake2b(b"", key=master, person=person, digest_size=DIGEST_SIZE).digest()


def derive_value_key(epoch_master: Master) -> ValueKey:
    """The value-encryption key for one keyepoch master, `person=b"dude.enc"`. Rotating —
    this is the half forward secrecy applies to (#possession-proof)."""
    return ValueKey(_subkey(epoch_master, PERSON_ENC))


# --------------------------------------------------------------------------- #
# #two-secrets — TWO secrets, and they must not be one.                            #
#                                                                              #
# NAME derivation is essentially permanent; VALUE derivation lives under the    #
# rotating keyepoch master, so forward secrecy applies to values only. If names #
# rotated too, the same logical key would take a different token every epoch —  #
# fracturing the key->provenance index, the refcounts, and any predicate naming #
# that key, and turning an O(1) manager write into an O(state) re-encryption.   #
# --------------------------------------------------------------------------- #

PERSON_NAME = b"dude.name"  # name_key — derived from the PERMANENT master (never rotated)


def derive_name_key(permanent_master: Master) -> NameKey:
    """The key-name derivation secret. Derived from the permanent master, NOT from a
    keyepoch master — #two-secrets. Stable across every rotation, by construction."""
    return NameKey(_subkey(permanent_master, PERSON_NAME))


def derive_item_key(value_key: ValueKey, name_token: NameToken) -> ItemKey:
    """The per-item AEAD key, #per-item-key: derived from the value key and the NAME only — there is
    deliberately no per-write component.

    Per-write uniqueness comes from the RANDOM NONCE (#random-nonce), not from the key. An earlier
    revision took a `version` here, meaning the settled index, which is unbuildable: the author
    encrypts before submitting, and a settled index does not exist until the batch settles. If
    anything ever reaches for the settled index at encryption time it has re-created that bug
    (#position-is-not-authored)."""
    return ItemKey(
        hashlib.blake2b(
            name_token, key=value_key, person=PERSON_ENC, digest_size=DIGEST_SIZE
        ).digest()
    )


class EpochKeys(NamedTuple):
    """One keyepoch's working keys, derived from its 32-byte master. Only ONE entry now: the
    value key. Names deliberately do not appear here — they come from the permanent master
    (#two-secrets), and putting them in an epoch-scoped record is exactly the mistake that would
    make rotation O(state)."""

    value_key: ValueKey

    @classmethod
    def derive(cls, master: Master) -> EpochKeys:
        return cls(derive_value_key(master))


# keyepoch -> that epoch's derived working keys.
type Keyring = dict[int, EpochKeys]


# --------------------------------------------------------------------------- #
# AEAD — data payloads (DESIGN §5, staged per IMPLEMENTATION §1)               #
# --------------------------------------------------------------------------- #


class AeadXcs1:
    """Suite `xcs1`: XChaCha20-Poly1305-IETF (libsodium) with a **random** 24-byte nonce.

    Sealed blob layout: `nonce(24) ‖ ciphertext ‖ tag(16)`.

    WHY RANDOM, and not the SIV-derived nonce this used to have (#random-nonce) — the reasoning is
    worth keeping, because the deterministic version looks like the more rigorous choice:

    A deterministic AEAD makes ciphertext equality imply plaintext equality, which also means an
    observer holding every ciphertext for one key can **count that key's distinct values** — its
    cardinality. A boolean toggled a thousand times shows two ciphertexts. That is a real leak to
    a storage node, which sees every write.

    It buys nothing, because **a predicate QUOTES the ciphertext rather than recomputing it**: a
    client reads the current value and puts those exact bytes (or a digest of them) into its
    predicate, so the node compares bytes it was handed. Nothing ever needs to derive what a
    ciphertext *should* be. Random therefore leaks nothing and costs nothing — SIV had to transmit
    the nonce regardless, since `open` cannot derive one without the plaintext.

    Consequently there is also no committing check in `open`: with a random nonce there is nothing
    to recompute. An earlier revision verified the nonce was the derived one, justified by
    ciphertext-equality soundness; that justification came from the deterministic construction and
    left with it."""

    suite_id = AEAD_SUITE

    @classmethod
    def seal(cls, k: ItemKey, aad: bytes, pt: bytes) -> AeadBlob:
        nonce = Nonce(nacl.utils.random(NONCE_SIZE))
        return AeadBlob(nacl.secret.Aead(k).encrypt(pt, aad, nonce))  # nonce ‖ ct ‖ tag

    @classmethod
    def open(cls, k: ItemKey, aad: bytes, sealed: AeadBlob) -> bytes:
        """Return the plaintext, or raise which of the two failures it was."""
        if len(sealed) < NONCE_SIZE + AEAD_TAG_SIZE:
            floor = NONCE_SIZE + AEAD_TAG_SIZE
            raise AeadMalformedError(f"sealed blob is {len(sealed)}B, under the {floor}B floor")
        try:
            return bytes(nacl.secret.Aead(k).decrypt(sealed, aad))
        except (nacl.exceptions.CryptoError, ValueError) as e:
            raise AeadAuthFailedError("AEAD authentication failed") from e


AEAD = AeadXcs1
