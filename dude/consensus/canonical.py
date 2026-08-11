from __future__ import annotations

from collections.abc import Iterable, Iterator

from ..core import crypto
from ..store.ops import SignedTransaction


class CanonicalBatch:
    """Signed transactions in ascending `op_hash` order -- the one order every producer,
    replayer, and settler assumes. Sorted BY THE CONSTRUCTOR, not by convention: `__init__`
    taking pre-sorted input on faith would let `CanonicalBatch(unsorted)` typecheck.

    `filter` is order-preserving, so a screen returning `frozenset[Digest]` cannot widen the
    slice or shuffle it."""

    __slots__ = ("_txs",)

    def __init__(self, txs: Iterable[SignedTransaction]) -> None:
        self._txs = tuple(sorted(txs, key=lambda tx: tx.op_hash))

    def __iter__(self) -> Iterator[SignedTransaction]:
        return iter(self._txs)

    def __len__(self) -> int:
        return len(self._txs)

    def __eq__(self, other: object) -> bool:
        return isinstance(other, CanonicalBatch) and self._txs == other._txs

    def __hash__(self) -> int:
        return hash(self._txs)

    @property
    def txs(self) -> tuple[SignedTransaction, ...]:
        return self._txs

    @property
    def op_hashes(self) -> frozenset[crypto.Digest]:
        return frozenset(tx.op_hash for tx in self._txs)

    def filter(self, keep: frozenset[crypto.Digest]) -> CanonicalBatch:
        return CanonicalBatch(tx for tx in self._txs if tx.op_hash in keep)


def bodies_canonical(bodies: Iterable[SignedTransaction]) -> CanonicalBatch:
    """Named alias for `CanonicalBatch(...)`; reads better at call sites."""
    return CanonicalBatch(bodies)


def hashes_canonical(hashes: Iterable[crypto.Digest]) -> tuple[crypto.Digest, ...]:
    return tuple(sorted(hashes))
