from __future__ import annotations

from abc import ABC, abstractmethod
from collections.abc import Callable
from dataclasses import dataclass
from typing import ClassVar

from ..consensus.settle_round import SettledBlockWithBodies
from ..core import codec, crypto
from ..core.errors import DudeError
from ..net.envelope import Verb
from ..net.postman import Encodable
from .refusal import SyncRefusal


class SyncAdapterError(DudeError): ...


class SyncMsg(Encodable):
    verb: ClassVar[Verb]

    @abstractmethod
    def _encode(self) -> bytes: ...

    def encode(self) -> tuple[Verb, bytes]:
        return self.verb, self._encode()

    @classmethod
    def decode(cls, verb: Verb, body: bytes) -> SyncMsg:
        try:
            handler = _DECODERS[verb]
        except KeyError as e:
            raise SyncAdapterError(f"not a sync verb: {verb.name}") from e
        return handler(body)


@dataclass(frozen=True, slots=True)
class HeightAsk(SyncMsg):
    verb: ClassVar[Verb] = Verb.HEIGHT

    def _encode(self) -> bytes:
        return b""

    @classmethod
    def _decode(cls, body: bytes) -> HeightAsk:
        if body != b"":
            raise SyncAdapterError(f"HEIGHT body must be empty, got {body!r}")
        return cls()


@dataclass(frozen=True, slots=True)
class HeightReply(SyncMsg):
    verb: ClassVar[Verb] = Verb.HEIGHT_REPLY

    block_num: int
    tip_hash: crypto.Digest

    def _encode(self) -> bytes:
        return codec.encode([self.block_num, self.tip_hash])

    @classmethod
    def _decode(cls, body: bytes) -> HeightReply:
        try:
            p = codec.as_seq(codec.decode(body), 2)
            return cls(
                block_num=codec.as_int(p[0]),
                tip_hash=crypto.Digest(codec.as_bytes(p[1])),
            )
        except DudeError as e:
            raise SyncAdapterError(f"malformed HEIGHT_REPLY body: {e}") from e


@dataclass(frozen=True, slots=True)
class GetBlocks(SyncMsg):
    verb: ClassVar[Verb] = Verb.GETBLOCK

    frm: int
    count: int

    def _encode(self) -> bytes:
        return codec.encode([self.frm, self.count])

    @classmethod
    def _decode(cls, body: bytes) -> GetBlocks:
        try:
            p = codec.as_seq(codec.decode(body), 2)
            return cls(frm=codec.as_int(p[0]), count=codec.as_int(p[1]))
        except DudeError as e:
            raise SyncAdapterError(f"malformed GETBLOCK body: {e}") from e


@dataclass(frozen=True, slots=True)
class SettledBlockReply(SyncMsg):
    verb: ClassVar[Verb] = Verb.SETTLED_BLOCK

    payload: tuple[SettledBlockWithBodies, ...]

    def _encode(self) -> bytes:
        return codec.encode([b.encode() for b in self.payload])

    @classmethod
    def _decode(cls, body: bytes) -> SettledBlockReply:
        try:
            raw = codec.as_seq(codec.decode(body))
        except DudeError as e:
            raise SyncAdapterError(f"malformed SETTLED_BLOCK body: {e}") from e
        return cls(payload=tuple(SettledBlockWithBodies.decode(codec.as_bytes(b)) for b in raw))


@dataclass(frozen=True, slots=True)
class Refused(SyncMsg):
    verb: ClassVar[Verb] = Verb.SYNC_REFUSED

    reason: SyncRefusal
    checkpoint_block_num: int | None = None

    def _encode(self) -> bytes:
        if self.checkpoint_block_num is not None:
            return codec.encode([self.reason.value.encode(), self.checkpoint_block_num])
        return self.reason.value.encode()

    @classmethod
    def _decode(cls, body: bytes) -> Refused:
        try:
            parts = codec.as_seq(codec.decode(body))
            reason = SyncRefusal(codec.as_bytes(parts[0]).decode("utf-8"))
            block_num = codec.as_int(parts[1]) if len(parts) > 1 else None
            return cls(reason=reason, checkpoint_block_num=block_num)
        except (DudeError, ValueError, UnicodeDecodeError):
            pass
        try:
            reason = SyncRefusal(body.decode("utf-8"))
        except (ValueError, UnicodeDecodeError) as e:
            raise SyncAdapterError(f"unknown SYNC_REFUSED reason: {body!r}") from e
        return cls(reason=reason)


_SYNC_MSG_CLASSES: tuple[type[SyncMsg], ...] = (
    HeightAsk,
    HeightReply,
    GetBlocks,
    SettledBlockReply,
    Refused,
)


_DECODERS: dict[Verb, Callable[[bytes], SyncMsg]] = {
    c.verb: c._decode  # noqa: SLF001 -- same-module dispatch table
    for c in _SYNC_MSG_CLASSES
}


__all__ = [
    "GetBlocks",
    "HeightAsk",
    "HeightReply",
    "Refused",
    "SettledBlockReply",
    "SyncAdapterError",
    "SyncMsg",
]
