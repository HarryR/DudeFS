from __future__ import annotations

from ..core import crypto
from ..store import Store
from ..store.checkpoint import CheckpointMeta
from ..store.smt_sync import TreeExporter
from .checkpoint_adapter import (
    CheckpointMetaReply,
    ChunksReply,
    GetChunks,
    _decode_chunk,
    _encode_chunk,
)


class CheckpointServer:
    def __init__(self, store: Store, batch_size: int = 10):
        self._store = store
        self._batch_size = batch_size
        raw = store.checkpoint_meta_bytes()
        self._checkpoint_id: crypto.Digest | None = crypto.h(raw) if raw is not None else None

    @classmethod
    def create_and_persist(
        cls,
        store: Store,
        meta: CheckpointMeta,
        max_chunk_bytes: int = 50_000,
        batch_size: int = 10,
    ) -> CheckpointServer:
        with store.snapshot() as reader:
            chunks = tuple(TreeExporter(reader, max_chunk_bytes=max_chunk_bytes).chunks())
        chunk_blobs = tuple(_encode_chunk(c) for c in chunks)
        with store.write() as w:
            w.persist_checkpoint(meta.encode(), chunk_blobs)
        return cls(store, batch_size)

    def has_checkpoint(self) -> bool:
        return self._checkpoint_id is not None

    @property
    def checkpoint_id(self) -> crypto.Digest | None:
        return self._checkpoint_id

    def serve_meta(self) -> CheckpointMetaReply:
        raw = self._store.checkpoint_meta_bytes()
        if raw is None:
            return CheckpointMetaReply(meta_bytes=b"")
        return CheckpointMetaReply(meta_bytes=raw)

    def serve_chunks(self, req: GetChunks) -> ChunksReply | None:
        if self._checkpoint_id is None or req.checkpoint_id != self._checkpoint_id:
            return None
        blobs = self._store.checkpoint_chunks(req.offset, self._batch_size)
        chunks = tuple(_decode_chunk(b) for b in blobs)
        total = self._store.checkpoint_chunk_count()
        served_up_to = req.offset + len(chunks)
        return ChunksReply(chunks=chunks, more=served_up_to < total)
