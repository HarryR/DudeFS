from __future__ import annotations

import hashlib
from collections.abc import Iterable, Sequence
from dataclasses import dataclass
from enum import Enum
from typing import ClassVar, NamedTuple, Self

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
    if not nacl.bindings.crypto_core_ed25519_is_valid_point(pk):
        return VerifyFailure.MALFORMED_KEY
    try:
        nacl.signing.VerifyKey(pk).verify(msg, sig)
    except (nacl.exceptions.BadSignatureError, nacl.exceptions.CryptoError, ValueError):
        return VerifyFailure.BAD_SIGNATURE
    return None


class CryptoError(DudeError): ...


class VerifyFailure(Enum):
    BAD_SIGNATURE = "bad-signature"
    MALFORMED_KEY = "malformed-key"


class AeadError(CryptoError): ...


class AeadMalformedError(AeadError): ...


class AeadAuthFailedError(AeadError): ...


class SealedBoxError(CryptoError): ...


HASH_SUITE = b"blake2b-256"
SIGNER_SUITE = b"ed25519"
MULTISIG_SUITE = b"ed25519-list"
AEAD_SUITE = b"xcs1"
WRAPSET_SUITE = b"sbx1"


DIGEST_SIZE = 32
NONCE_SIZE = 24
AEAD_TAG_SIZE = 16
ACC_SIZE = nacl.bindings.crypto_core_ed25519_BYTES
SIG_SIZE = 64
SCREEN_TAG_SIZE = 16


class _Fixed(bytes):
    __slots__ = ()
    WIDTH = 0

    def __new__(cls, raw: bytes):
        if len(raw) != cls.WIDTH:
            raise CryptoError(f"{cls.__name__} must be {cls.WIDTH} bytes, got {len(raw)}")
        return super().__new__(cls, raw)


class Digest(_Fixed):
    WIDTH = DIGEST_SIZE
    __slots__ = ()


class NameToken(_Fixed):
    WIDTH = DIGEST_SIZE
    __slots__ = ()


class Accumulator(_Fixed):
    WIDTH = ACC_SIZE
    __slots__ = ()


class Signature(_Fixed):
    WIDTH = SIG_SIZE
    __slots__ = ()


class Master(_Fixed):
    WIDTH = 32
    __slots__ = ()


class NameKey(_Fixed):
    WIDTH = DIGEST_SIZE
    __slots__ = ()


class ValueKey(_Fixed):
    WIDTH = DIGEST_SIZE
    __slots__ = ()


class ItemKey(_Fixed):
    WIDTH = DIGEST_SIZE
    __slots__ = ()


class Seed(_Fixed):
    WIDTH = 32
    __slots__ = ()


class Nonce(_Fixed):
    WIDTH = NONCE_SIZE
    __slots__ = ()


class ScreenTag(_Fixed):
    WIDTH = SCREEN_TAG_SIZE
    __slots__ = ()


class SignerBitmap(bytes):
    __slots__ = ()


class SealedBlob(bytes):
    __slots__ = ()


class AeadBlob(bytes):
    __slots__ = ()


def h(data: bytes) -> Digest:
    return Digest(hashlib.blake2b(data, digest_size=DIGEST_SIZE).digest())


def h_domain(person: bytes, data: bytes) -> Digest:
    return Digest(hashlib.blake2b(data, person=person, digest_size=DIGEST_SIZE).digest())


PERSON_SIZE = hashlib.blake2b.PERSON_SIZE


def random_bytes(n: int) -> bytes:
    return nacl.utils.random(n)


PERSON_ACC = b"dude.acc:v1"
ACC_IDENTITY = Accumulator(b"\x01" + b"\x00" * (ACC_SIZE - 1))


def acc_element(enc: bytes) -> Accumulator:
    return Accumulator(nacl.bindings.crypto_core_ed25519_from_uniform(h(PERSON_ACC + enc)))


def acc_add(a: Accumulator, b: Accumulator) -> Accumulator:
    return Accumulator(nacl.bindings.crypto_core_ed25519_add(a, b))


def acc_sub(a: Accumulator, b: Accumulator) -> Accumulator:
    return Accumulator(nacl.bindings.crypto_core_ed25519_sub(a, b))


PERSON_SCREEN = b"dude.screen"


def screen_tag(node_identity: PublicKey, sealed: bytes) -> ScreenTag:
    return ScreenTag(
        hashlib.blake2b(
            sealed, key=node_identity, person=PERSON_SCREEN, digest_size=SCREEN_TAG_SIZE
        ).digest()
    )


_POP_PREFIX = b"dude.pop:"


class PublicKey(_Fixed):
    WIDTH = 32
    __slots__ = ()

    def verify(self, msg: bytes, sig: Signature) -> bool:
        return _ed25519_verify(self, msg, sig) is None

    def why_not(self, msg: bytes, sig: Signature) -> VerifyFailure | None:
        return _ed25519_verify(self, msg, sig)

    def seal(self, msg: bytes) -> SealedBlob:
        xpk = nacl.signing.VerifyKey(self).to_curve25519_public_key()
        return SealedBlob(nacl.public.SealedBox(xpk).encrypt(msg))

    def verify_possession(self, pop: Signature) -> bool:
        return self.verify(_POP_PREFIX + self, pop)

    def fingerprint(self) -> Digest:
        return h(self)


class Keypair:
    __slots__ = ("_public", "_seed")

    def __init__(self, seed: Seed):
        self._seed = Seed(seed)
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

    @property
    def seed(self) -> Seed:
        return self._seed

    def sign(self, msg: bytes) -> Signature:
        return Signature(_ed25519_sign(self._seed, msg))

    def open_sealed_raw(self, blob: SealedBlob) -> bytes:
        try:
            xsk = nacl.signing.SigningKey(self._seed).to_curve25519_private_key()
            return nacl.public.SealedBox(xsk).decrypt(blob)
        except (nacl.exceptions.CryptoError, ValueError) as e:
            raise SealedBoxError("sealed box would not open (not ours, or tampered)") from e

    def open_sealed(self, blob: SealedBlob) -> Master:
        try:
            xsk = nacl.signing.SigningKey(self._seed).to_curve25519_private_key()
            return Master(nacl.public.SealedBox(xsk).decrypt(blob))
        except (nacl.exceptions.CryptoError, ValueError) as e:
            raise SealedBoxError("sealed box would not open (not ours, or tampered)") from e

    def prove_possession(self) -> Signature:
        return self.sign(_POP_PREFIX + self.public)


NO_SIGNERS = SignerBitmap(b"")


def bitmap_size(n: int) -> int:
    return (n + 7) // 8


def bitmap_set(indices: Iterable[int], n: int) -> SignerBitmap:
    nbytes = (n + 7) // 8
    buf = bytearray(nbytes)
    for i in indices:
        if not (0 <= i < n):
            raise CryptoError(f"signer index {i} out of range for n={n}")
        buf[i >> 3] |= 0x80 >> (i & 7)
    return SignerBitmap(buf)


def bitmap_indices(bitmap: SignerBitmap, n: int) -> list[int]:
    if len(bitmap) != (n + 7) // 8:
        want = (n + 7) // 8
        raise CryptoError(f"signer bitmap is {len(bitmap)}B, expected {want}B for n={n}")
    return [i for i in range(n) if bitmap[i >> 3] & (0x80 >> (i & 7))]


def bitmap_count(bitmap: SignerBitmap, n: int) -> int:
    return len(bitmap_indices(bitmap, n))


@dataclass(frozen=True, slots=True)
class MultiSig:
    bitmap: SignerBitmap
    sigs: tuple[Signature, ...]

    suite_id: ClassVar[bytes] = MULTISIG_SUITE

    @classmethod
    def combine(cls, shares_by_index: dict[int, Signature], n: int) -> Self:
        indices = sorted(shares_by_index)
        return cls(bitmap_set(indices, n), tuple(shares_by_index[i] for i in indices))

    def indices(self, n: int) -> list[int]:
        return bitmap_indices(self.bitmap, n)

    def count(self, n: int) -> int:
        return len(self.indices(n))

    def verify(self, msg: bytes, signers: Sequence[PublicKey]) -> bool:
        # A REFUSAL, NEVER A RAISE. The bitmap arrives from a peer, so a width that does not match
        # the roster is that peer's claim being wrong, not our invariant being broken. Raising
        # `CryptoError` here reached a light client through `Authorization.verify` and killed its
        # run thread, because nothing on the lite read path catches. `bitmap_indices` stays strict
        # for callers building a bitmap of their own, where a bad width IS a local bug.
        if len(self.bitmap) != bitmap_size(len(signers)):
            return False
        indices = self.indices(len(signers))
        if len(indices) != len(self.sigs):
            return False
        for idx, sig in zip(indices, self.sigs, strict=True):
            if not signers[idx].verify(msg, sig):
                return False
        return True


UNSIGNED = MultiSig(NO_SIGNERS, ())


def sign_share(sk: Seed, msg: bytes) -> Signature:
    return _ed25519_sign(sk, msg)


PERSON_ENC = b"dude.enc"


type Secret = Master | Seed | NameKey | ValueKey | ItemKey


def _subkey(master: Secret, person: bytes) -> bytes:
    return hashlib.blake2b(b"", key=master, person=person, digest_size=DIGEST_SIZE).digest()


def derive_value_key(epoch_master: Master) -> ValueKey:
    return ValueKey(_subkey(epoch_master, PERSON_ENC))


PERSON_NAME = b"dude.name"
PERSON_NAME_TOKEN = b"dude.nametok"


def derive_name_key(permanent_master: Master) -> NameKey:
    return NameKey(_subkey(permanent_master, PERSON_NAME))


def derive_name_token(name_key: NameKey, name: bytes) -> NameToken:
    """The opaque name a storage node indexes by. Its own personalisation, not `PERSON_NAME`:
    that one already derives the key this is keyed WITH, and these are two functions rather than
    one function over two tagged messages.

    Takes bytes. Whether a caller's string becomes these bytes -- encoding, and Unicode
    normalisation above all -- is a decision `crypto` is not positioned to make, and is fixed once
    at the client boundary instead."""
    return NameToken(
        hashlib.blake2b(
            name, key=name_key, person=PERSON_NAME_TOKEN, digest_size=DIGEST_SIZE
        ).digest()
    )


def derive_item_key(value_key: ValueKey, name_token: NameToken) -> ItemKey:
    return ItemKey(
        hashlib.blake2b(
            name_token, key=value_key, person=PERSON_ENC, digest_size=DIGEST_SIZE
        ).digest()
    )


class EpochKeys(NamedTuple):
    value_key: ValueKey

    @classmethod
    def derive(cls, master: Master) -> EpochKeys:
        return cls(derive_value_key(master))


class AeadXcs1:
    suite_id = AEAD_SUITE

    @classmethod
    def seal(cls, k: ItemKey, aad: bytes, pt: bytes) -> AeadBlob:
        nonce = Nonce(nacl.utils.random(NONCE_SIZE))
        return AeadBlob(nacl.secret.Aead(k).encrypt(pt, aad, nonce))

    @classmethod
    def open(cls, k: ItemKey, aad: bytes, sealed: AeadBlob) -> bytes:
        if len(sealed) < NONCE_SIZE + AEAD_TAG_SIZE:
            floor = NONCE_SIZE + AEAD_TAG_SIZE
            raise AeadMalformedError(f"sealed blob is {len(sealed)}B, under the {floor}B floor")
        try:
            return bytes(nacl.secret.Aead(k).decrypt(sealed, aad))
        except (nacl.exceptions.CryptoError, ValueError) as e:
            raise AeadAuthFailedError("AEAD authentication failed") from e


AEAD = AeadXcs1
