from __future__ import annotations

import sqlite3
from collections.abc import Iterator
from dataclasses import dataclass

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


class TreeExporter:
    def __init__(self, db: sqlite3.Connection, max_chunk_bytes: int):
        self._db = db
        self._tree = smt.Tree(db, memoize=False)
        self._budget = max_chunk_bytes

    def chunks(self) -> Iterator[Chunk]:
        yield from self._walk(bytes(crypto.DIGEST_SIZE), 0)

    def _walk(self, prefix: bytes, depth: int) -> Iterator[Chunk]:
        lo, hi = smt.bounds(prefix, depth)
        if self._subtree_size(lo, hi) == 0:
            return
        if self._subtree_size(lo, hi) <= self._budget or depth >= smt.MAX_DEPTH:
            rows = self._subtree_rows(lo, hi)
            yield Chunk(depth, lo, self._tree.hash_under(prefix, depth), rows)
            return
        left = prefix
        right = smt.with_bit(prefix, depth, 1)
        if smt.bit(prefix, depth) == 1:
            left, right = right, left
        yield from self._walk(left, depth + 1)
        yield from self._walk(right, depth + 1)

    def _subtree_size(self, lo: bytes, hi: bytes) -> int:
        row = self._db.execute(
            "SELECT COALESCE(SUM(LENGTH(value) + LENGTH(cred)), 0)"
            " FROM live WHERE path BETWEEN ? AND ?",
            (lo, hi),
        ).fetchone()
        return row[0]

    def _subtree_rows(self, lo: bytes, hi: bytes) -> tuple[PathRow, ...]:
        rows = self._db.execute(
            "SELECT store, name, value, cred, epoch FROM live"
            " WHERE path BETWEEN ? AND ? ORDER BY path",
            (lo, hi),
        ).fetchall()
        return tuple(PathRow(int(r[0]), r[1], r[2], r[3], int(r[4])) for r in rows)


class TreeImporter:
    def __init__(self, db: sqlite3.Connection, expected_root: crypto.Digest):
        self._db = db
        self._tree = smt.Tree(db, memoize=True)
        self._expected_root = expected_root
        self._received: list[Chunk] = []

    def load(self, chunk: Chunk) -> None:
        for row in chunk.rows:
            path = smt.path_of(row.store, row.name)
            self._db.execute(
                "INSERT OR REPLACE INTO live (store, name, value, epoch, path, cred)"
                " VALUES (?,?,?,?,?,?)",
                (row.store, row.name, row.value, row.epoch, path, row.credential),
            )
        computed = self._tree.hash_under(chunk.prefix, chunk.depth)
        if computed != chunk.subtree_hash:
            raise TreeSyncError(
                f"chunk at depth={chunk.depth}: "
                f"expected {chunk.subtree_hash.hex()[:16]}, "
                f"got {computed.hex()[:16]}"
            )
        self._received.append(chunk)

    def verify(self) -> crypto.Digest:
        root = self._tree.root()
        if root != self._expected_root:
            raise TreeSyncError(
                f"final root mismatch: "
                f"expected {self._expected_root.hex()[:16]}, "
                f"got {root.hex()[:16]}"
            )
        return root
