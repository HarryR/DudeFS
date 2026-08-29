from __future__ import annotations

from dataclasses import dataclass
from typing import ClassVar

from ..core import codec, crypto
from ..core.errors import DudeError
from ..net.envelope import Verb
from ..net.postman import Encodable
from ..store.layer import PathRow
from ..store.smt_sync import Chunk


class CheckpointAdapterError(DudeError): ...


@dataclass(frozen=True, slots=True)
class GetCheckpoint(Encodable):
    verb: ClassVar[Verb] = Verb.GET_CHECKPOINT

    def encode(self) -> tuple[Verb, bytes]:
        return self.verb, b""

    @classmethod
    def decode(cls, _body: bytes) -> GetCheckpoint:
        return cls()


@dataclass(frozen=True, slots=True)
class CheckpointMetaReply(Encodable):
    verb: ClassVar[Verb] = Verb.CHECKPOINT_META

    meta_bytes: bytes

    def encode(self) -> tuple[Verb, bytes]:
        return self.verb, self.meta_bytes

    @classmethod
    def decode(cls, body: bytes) -> CheckpointMetaReply:
        return cls(meta_bytes=body)


@dataclass(frozen=True, slots=True)
class GetChunks(Encodable):
    verb: ClassVar[Verb] = Verb.GET_CHUNKS

    checkpoint_id: crypto.Digest
    offset: int

    def encode(self) -> tuple[Verb, bytes]:
        return self.verb, codec.encode([self.checkpoint_id, self.offset])

    @classmethod
    def decode(cls, body: bytes) -> GetChunks:
        try:
            p = codec.as_seq(codec.decode(body), 2)
            return cls(
                checkpoint_id=crypto.Digest(codec.as_bytes(p[0])),
                offset=codec.as_int(p[1]),
            )
        except DudeError as e:
            raise CheckpointAdapterError(f"malformed GET_CHUNKS: {e}") from e


def _encode_chunk(chunk: Chunk) -> bytes:
    return codec.encode(
        [
            chunk.depth,
            chunk.prefix,
            chunk.subtree_hash,
            [[r.store, r.name, r.value, r.credential, r.epoch] for r in chunk.rows],
        ]
    )


def _decode_chunk(raw: bytes) -> Chunk:
    p = codec.as_seq(codec.decode(raw), 4)
    depth = codec.as_int(p[0])
    prefix = codec.as_bytes(p[1])
    subtree_hash = crypto.Digest(codec.as_bytes(p[2]))
    rows = tuple(
        PathRow(
            codec.as_int(r[0]),
            codec.as_bytes(r[1]),
            codec.as_bytes(r[2]),
            codec.as_bytes(r[3]),
            codec.as_int(r[4]),
        )
        for r in (codec.as_seq(item, 5) for item in codec.as_seq(p[3]))
    )
    return Chunk(depth=depth, prefix=prefix, subtree_hash=subtree_hash, rows=rows)


@dataclass(frozen=True, slots=True)
class ChunksReply(Encodable):
    verb: ClassVar[Verb] = Verb.CHUNKS_REPLY

    chunks: tuple[Chunk, ...]
    more: bool

    def encode(self) -> tuple[Verb, bytes]:
        return self.verb, codec.encode(
            [
                [_encode_chunk(c) for c in self.chunks],
                1 if self.more else 0,
            ]
        )

    @classmethod
    def decode(cls, body: bytes) -> ChunksReply:
        try:
            p = codec.as_seq(codec.decode(body), 2)
            chunks = tuple(_decode_chunk(codec.as_bytes(c)) for c in codec.as_seq(p[0]))
            more = codec.as_int(p[1]) != 0
            return cls(chunks=chunks, more=more)
        except DudeError as e:
            raise CheckpointAdapterError(f"malformed CHUNKS_REPLY: {e}") from e
