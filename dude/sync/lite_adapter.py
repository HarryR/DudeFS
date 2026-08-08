from __future__ import annotations

from abc import ABC, abstractmethod
from collections.abc import Callable
from dataclasses import dataclass
from enum import Enum
from typing import ClassVar

from ..consensus.settle_round import SettledBlock
from ..core import codec, crypto
from ..core.errors import DudeError
from ..net.envelope import Verb
from ..store.management import Cert, Grant, NodeRecord


class LiteAdapterError(DudeError): ...


class LiteRefusal(Enum):
    INVALID = "invalid"

    NO_STATE = "no-state"

    NOT_YET_SETTLED = "not-yet-settled"

    TOO_OLD = "too-old"

    UNKNOWN_STORE = "unknown-store"

    MALFORMED_QUERY = "malformed-query"

    STALE_CLIENT = "stale-client"

    FORK_DETECTED = "fork-detected"

    INTERNAL = "internal"


@dataclass(frozen=True, slots=True)
class RosterBundle:
    commitment_serial: int
    commitment_members: tuple[crypto.PublicKey, ...]
    commitment_cert: Cert
    entries: tuple[NodeRecord, ...]
    managers: tuple[Grant, ...]

    def _encode(self) -> bytes:
        return codec.encode(
            [
                self.commitment_serial,
                sorted(bytes(m) for m in self.commitment_members),
                self.commitment_cert.encode(),
                [rec.encode() for rec in self.entries],
                [g.encode() for g in self.managers],
            ]
        )

    @classmethod
    def _decode(cls, raw: bytes) -> RosterBundle:
        try:
            p = codec.as_seq(codec.decode(raw), 5)
            serial = codec.as_int(p[0])
            members = tuple(crypto.PublicKey(codec.as_bytes(m)) for m in codec.as_seq(p[1]))
            commitment_cert = Cert.decode(codec.as_bytes(p[2]))
            entries = tuple(NodeRecord.decode(codec.as_bytes(e)) for e in codec.as_seq(p[3]))
            managers = tuple(Grant.decode(codec.as_bytes(g)) for g in codec.as_seq(p[4]))
        except DudeError as e:
            raise LiteAdapterError(f"malformed RosterBundle: {e}") from e
        return cls(serial, members, commitment_cert, entries, managers)


class LiteMsg(ABC):
    verb: ClassVar[Verb]

    @abstractmethod
    def _encode(self) -> bytes: ...

    def encode(self) -> tuple[Verb, bytes]:
        return self.verb, self._encode()

    @classmethod
    def decode(cls, verb: Verb, body: bytes) -> LiteMsg:
        try:
            handler = _DECODERS[verb]
        except KeyError as e:
            raise LiteAdapterError(f"not a lite-client verb: {verb.name}") from e
        return handler(body)


@dataclass(frozen=True, slots=True)
class TrustedBlock:
    block_num: int
    block_hash: crypto.Digest

    def encode(self) -> bytes:
        return codec.encode([self.block_num, self.block_hash])

    @classmethod
    def decode(cls, raw: bytes) -> TrustedBlock:
        p = codec.as_seq(codec.decode(raw), 2)
        return cls(codec.as_int(p[0]), crypto.Digest(codec.as_bytes(p[1])))

    @classmethod
    def encode_optional(cls, tb: TrustedBlock | None) -> bytes:
        return b"" if tb is None else tb.encode()

    @classmethod
    def decode_optional(cls, raw: bytes) -> TrustedBlock | None:
        return None if not raw else cls.decode(raw)


@dataclass(frozen=True, slots=True)
class GetAnchors(LiteMsg):
    verb: ClassVar[Verb] = Verb.GET_ANCHORS

    known_roster_fingerprint: crypto.Digest | None
    known_trusted_block: TrustedBlock | None

    def _encode(self) -> bytes:
        return codec.encode(
            [
                self.known_roster_fingerprint or b"",
                TrustedBlock.encode_optional(self.known_trusted_block),
            ]
        )

    @classmethod
    def _decode(cls, body: bytes) -> GetAnchors:
        try:
            p = codec.as_seq(codec.decode(body), 2)
            fp_raw = codec.as_bytes(p[0])
            trusted = TrustedBlock.decode_optional(codec.as_bytes(p[1]))
        except DudeError as e:
            raise LiteAdapterError(f"malformed GET_ANCHORS body: {e}") from e
        return cls(
            known_roster_fingerprint=crypto.Digest(fp_raw) if fp_raw else None,
            known_trusted_block=trusted,
        )


@dataclass(frozen=True, slots=True)
class AnchorsReply(LiteMsg):
    verb: ClassVar[Verb] = Verb.ANCHORS_REPLY

    head: SettledBlock
    roster_fingerprint: crypto.Digest
    bundle: RosterBundle | None
    headers: tuple[SettledBlock, ...]

    def _encode(self) -> bytes:
        return codec.encode(
            [
                self.head.encode(),
                self.roster_fingerprint,
                self.bundle._encode() if self.bundle is not None else b"",  # noqa: SLF001
                [h.encode() for h in self.headers],
            ]
        )

    @classmethod
    def _decode(cls, body: bytes) -> AnchorsReply:
        try:
            p = codec.as_seq(codec.decode(body), 4)
            head = SettledBlock.decode(codec.as_bytes(p[0]))
            roster_fingerprint = crypto.Digest(codec.as_bytes(p[1]))
            bundle_bytes = codec.as_bytes(p[2])
            bundle = RosterBundle._decode(bundle_bytes) if bundle_bytes else None  # noqa: SLF001
            headers = tuple(SettledBlock.decode(codec.as_bytes(h)) for h in codec.as_seq(p[3]))
        except DudeError as e:
            raise LiteAdapterError(f"malformed ANCHORS_REPLY body: {e}") from e
        return cls(head, roster_fingerprint, bundle, headers)


@dataclass(frozen=True, slots=True)
class GetProof(LiteMsg):
    verb: ClassVar[Verb] = Verb.GET_PROOF

    store_id: int
    name: bytes
    block_num: int
    known_roster_fingerprint: crypto.Digest | None
    known_trusted_block: TrustedBlock | None

    def _encode(self) -> bytes:
        return codec.encode(
            [
                self.store_id,
                self.name,
                self.block_num,
                self.known_roster_fingerprint or b"",
                TrustedBlock.encode_optional(self.known_trusted_block),
            ]
        )

    @classmethod
    def _decode(cls, body: bytes) -> GetProof:
        try:
            p = codec.as_seq(codec.decode(body), 5)
            fp_raw = codec.as_bytes(p[3])
            trusted = TrustedBlock.decode_optional(codec.as_bytes(p[4]))
            return cls(
                store_id=codec.as_int(p[0]),
                name=codec.as_bytes(p[1]),
                block_num=codec.as_int(p[2]),
                known_roster_fingerprint=crypto.Digest(fp_raw) if fp_raw else None,
                known_trusted_block=trusted,
            )
        except DudeError as e:
            raise LiteAdapterError(f"malformed GET_PROOF body: {e}") from e


ABSENT_MARKER = b""


@dataclass(frozen=True, slots=True)
class ProofReply(LiteMsg):
    verb: ClassVar[Verb] = Verb.PROOF_REPLY

    value: bytes
    credential: bytes
    absent: bool
    proof: bytes
    head: SettledBlock
    roster_fingerprint: crypto.Digest
    bundle: RosterBundle | None
    headers: tuple[SettledBlock, ...]

    def _encode(self) -> bytes:
        return codec.encode(
            [
                self.value,
                self.credential,
                1 if self.absent else 0,
                self.proof,
                self.head.encode(),
                self.roster_fingerprint,
                self.bundle._encode() if self.bundle is not None else b"",  # noqa: SLF001
                [h.encode() for h in self.headers],
            ]
        )

    @classmethod
    def _decode(cls, body: bytes) -> ProofReply:
        try:
            p = codec.as_seq(codec.decode(body), 8)
            head = SettledBlock.decode(codec.as_bytes(p[4]))
            roster_fingerprint = crypto.Digest(codec.as_bytes(p[5]))
            bundle_bytes = codec.as_bytes(p[6])
            bundle = RosterBundle._decode(bundle_bytes) if bundle_bytes else None  # noqa: SLF001
            headers = tuple(SettledBlock.decode(codec.as_bytes(h)) for h in codec.as_seq(p[7]))
            return cls(
                value=codec.as_bytes(p[0]),
                credential=codec.as_bytes(p[1]),
                absent=codec.as_int(p[2]) == 1,
                proof=codec.as_bytes(p[3]),
                head=head,
                roster_fingerprint=roster_fingerprint,
                bundle=bundle,
                headers=headers,
            )
        except DudeError as e:
            raise LiteAdapterError(f"malformed PROOF_REPLY body: {e}") from e


@dataclass(frozen=True, slots=True)
class LiteRefused(LiteMsg):
    verb: ClassVar[Verb] = Verb.LITE_REFUSED

    reason: LiteRefusal

    def _encode(self) -> bytes:
        return self.reason.value.encode()

    @classmethod
    def _decode(cls, body: bytes) -> LiteRefused:
        try:
            reason = LiteRefusal(body.decode("utf-8"))
        except (ValueError, UnicodeDecodeError) as e:
            raise LiteAdapterError(f"unknown LITE_REFUSED reason: {body!r}") from e
        return cls(reason=reason)


_LITE_MSG_CLASSES: tuple[type[LiteMsg], ...] = (
    GetAnchors,
    AnchorsReply,
    GetProof,
    ProofReply,
    LiteRefused,
)


_DECODERS: dict[Verb, Callable[[bytes], LiteMsg]] = {
    c.verb: c._decode  # noqa: SLF001 -- same-module dispatch table
    for c in _LITE_MSG_CLASSES
}


class LiteAdapter:
    def __init__(self, me: crypto.Keypair, postman, ttl):
        self.me = me
        self.postman = postman
        self.ttl = ttl

    def send(self, to: crypto.PublicKey, msg: LiteMsg, now) -> bytes:
        from ..net.envelope import Envelope, new_message_id  # noqa: PLC0415

        verb, body = msg.encode()
        mid = new_message_id()
        env = Envelope(to, verb, mid, body).sign(self.me, now)
        self.postman.mailbox.post(env, now, self.ttl, await_reply=True)
        return mid

    def reply(self, to, msg: LiteMsg, now):
        verb, body = msg.encode()
        self.postman.mailbox.post(
            to.answer(verb, body).sign(self.me, now), now, self.ttl, await_reply=False
        )


__all__ = [
    "ABSENT_MARKER",
    "AnchorsReply",
    "GetAnchors",
    "GetProof",
    "LiteAdapter",
    "LiteAdapterError",
    "LiteMsg",
    "LiteRefusal",
    "LiteRefused",
    "ProofReply",
    "RosterBundle",
]
