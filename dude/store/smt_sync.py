from __future__ import annotations

from collections.abc import Iterator
from dataclasses import dataclass
from typing import Protocol

from ..core import crypto
from . import smt
from .errors import StoreError
from .layer import PathRow


class TreeSyncError(StoreError): ...


@dataclass(frozen=True, slots=True)
class Chunk:
    depth: int
    prefix: bytes
    subtree_hash: crypto.Digest
    rows: tuple[PathRow, ...]


class _ExportSource(Protocol):
    def subtree_data_size(self, prefix: bytes, depth: int) -> int: ...
    def subtree_rows(self, prefix: bytes, depth: int) -> tuple[PathRow, ...]: ...
    def hash_under(self, prefix: bytes, depth: int) -> crypto.Digest: ...


class TreeExporter:
    def __init__(self, source: _ExportSource, max_chunk_bytes: int):
        self._source = source
        self._budget = max_chunk_bytes

    def chunks(self) -> Iterator[Chunk]:
        yield from self._walk(bytes(crypto.DIGEST_SIZE), 0)

    def _walk(self, prefix: bytes, depth: int) -> Iterator[Chunk]:
        if self._source.subtree_data_size(prefix, depth) == 0:
            return
        if self._source.subtree_data_size(prefix, depth) <= self._budget or depth >= smt.MAX_DEPTH:
            rows = self._source.subtree_rows(prefix, depth)
            yield Chunk(depth, prefix, self._source.hash_under(prefix, depth), rows)
            return
        left = prefix
        right = smt.with_bit(prefix, depth, 1)
        if smt.bit(prefix, depth) == 1:
            left, right = right, left
        yield from self._walk(left, depth + 1)
        yield from self._walk(right, depth + 1)


class _ImportTarget(Protocol):
    def insert_live_row(self, row: PathRow) -> None: ...
    def hash_under(self, prefix: bytes, depth: int) -> crypto.Digest: ...
    def state_root(self) -> crypto.Digest: ...


class TreeImporter:
    def __init__(self, target: _ImportTarget, expected_root: crypto.Digest):
        self._target = target
        self._expected_root = expected_root

    def load(self, chunk: Chunk) -> None:
        for row in chunk.rows:
            self._target.insert_live_row(row)
        computed = self._target.hash_under(chunk.prefix, chunk.depth)
        if computed != chunk.subtree_hash:
            raise TreeSyncError(
                f"chunk at depth={chunk.depth}: "
                f"expected {chunk.subtree_hash.hex()[:16]}, "
                f"got {computed.hex()[:16]}"
            )

    def verify(self) -> crypto.Digest:
        root = self._target.state_root()
        if root != self._expected_root:
            raise TreeSyncError(
                f"final root mismatch: "
                f"expected {self._expected_root.hex()[:16]}, "
                f"got {root.hex()[:16]}"
            )
        return root
