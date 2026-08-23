from __future__ import annotations

from ..store import Store
from ..store.checkpoint import CheckpointMeta
from ..store.smt_sync import Chunk, TreeExporter
from .checkpoint_adapter import CheckpointMetaReply, ChunksReply, GetChunks


class CheckpointServer:
    def __init__(
        self, meta: CheckpointMeta, chunks: tuple[Chunk, ...], batch_size: int = 10
    ):
        self._meta = meta
        self._chunks = chunks
        self._batch_size = batch_size

    @classmethod
    def from_store(
        cls,
        store: Store,
        meta: CheckpointMeta,
        max_chunk_bytes: int = 50_000,
        batch_size: int = 10,
    ) -> CheckpointServer:
        with store.snapshot() as reader:
            chunks = tuple(TreeExporter(reader, max_chunk_bytes=max_chunk_bytes).chunks())
        return cls(meta, chunks, batch_size)

    def serve_meta(self) -> CheckpointMetaReply:
        return CheckpointMetaReply(meta_bytes=self._meta.encode())

    def serve_chunks(self, req: GetChunks) -> ChunksReply:
        start = req.offset
        end = min(start + self._batch_size, len(self._chunks))
        batch = self._chunks[start:end]
        return ChunksReply(chunks=batch, more=end < len(self._chunks))
