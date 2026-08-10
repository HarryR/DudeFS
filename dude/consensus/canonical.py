from __future__ import annotations

from collections.abc import Iterable, Iterator

from ..core import crypto
from ..store.ops import SignedTransaction


class CanonicalBatch:
    """Signed transactions in the one order every producer, replayer and settler assumes:
    ascending `op_hash` as bytes. Sorted BY THE CONSTRUCTOR, not by convention: a public
    `__init__` that trusted its input to already be sorted would let a fourth caller write
    `CanonicalBatch(some_tuple)`, pass every typecheck, and silently reintroduce the drift
    this file exists to kill -- wearing a name that asserts the opposite. Sorting inside
    `__init__` makes the wrong thing unsayable, and the O(n log n) is nothing beside the
    signature verification happening either side of every batch.

    Filter, don't rebuild. `filter` narrows by op_hash and is order-preserving, so a screen
    that returns membership (a `frozenset[Digest]`) cannot widen the slice or shuffle it --
    the structural guarantee replaces the assertion that would otherwise sit at every
    consumer."""

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
    """Named entry point for `CanonicalBatch(...)`. The constructor sorts either way; this
    exists so call sites read as "canonicalise these bodies" rather than "construct a
    CanonicalBatch out of these bodies", which is the same operation described from two
    sides."""
    return CanonicalBatch(bodies)


def hashes_canonical(hashes: Iterable[crypto.Digest]) -> tuple[crypto.Digest, ...]:
    return tuple(sorted(hashes))
