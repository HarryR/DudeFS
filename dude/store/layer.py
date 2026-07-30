# dude.store.layer — the read surface, and the writable delta over it. See SPEC.md (#settlement).
#
# WHY THIS IS ITS OWN MODULE. Evaluating a transaction — guards, authority — must be possible
# WITHOUT a store: the mempool screens candidates speculatively, thousands of times, and none
# of that work may be durable or reach SQLite. So evaluation is written against `Reader`, and
# `Layer` is a `Reader` you can write to. Neither knows anything about persistence, which lets
# `dude.store.settle` be pure and replay bypasses evaluation (#replay-does-not-readjudicate).

from __future__ import annotations

from collections.abc import Iterator
from typing import NamedTuple, Protocol

from . import ops

# A settled index (#settlement). Compactly encoded — a few bytes, never a digest.
type Index = int


# The provenance reported for a value written into a layer but not yet settled. Negative, so it can
# never collide with a settled index (those start at 1) and so a caller that mistakes one for the
# other gets an obviously-wrong number rather than a plausible one.
PENDING: Index = -1


class Held(NamedTuple):
    """A live value and the settled index that last wrote it.

    Named for the same reason `Row` is: `got[1]` says nothing, and a bare `(Index, bytes)` is the
    pair a port transposes — one is a number, one a blob, and swapping them still type-checks in a
    language with weaker aliases than these."""

    provenance: Index
    value: bytes
    epoch: int = ops.EPOCH_NONE
    """Which keyepoch `value` is under. A reader needs it to pick a key, and the conveyor needs it
    to count (#conveyor)."""


class Row(NamedTuple):
    """One enumerated entry: its key, the settled index that last wrote it, and its value.

    Named because `for name, prov, value in ...` is only self-documenting while the reader remembers
    the order — and `prov` between two byte strings is exactly the position a port transposes."""

    name: bytes
    provenance: Index
    value: bytes
    epoch: int = ops.EPOCH_NONE


class Reader(Protocol):
    """The read surface. `Store` implements it over SQLite; `Layer` implements it over another
    Reader. Anything that only READS state takes this — including `Management`, which is how a
    transaction's own uncommitted grants become visible to its own authority checks."""

    def get(self, store: int, name: bytes) -> Held | None: ...

    def prefix(self, store: int, pre: bytes) -> Iterator[Row]: ...

    def epoch_live(self, epoch: int) -> int: ...


class Layer:
    """A read-through, writable delta over any `Reader`. Writes land in this layer; reads fall
    through to the base when this layer has nothing to say.

    This is the evaluation substrate, and it exists because **the mempool evaluates speculatively**.
    A candidate transaction must be checkable — guards, authority, conflicts — thousands of times
    without touching the store, so the mechanism cannot be a database transaction: SQLite
    savepoints would mean thousands of write transactions for work that must never be durable.

    It also nests: a `Layer` over a `Layer` gives per-transaction isolation inside a batch, and
    `absorb` merges a survivor down. That is the same construct as the compaction layers of SPEC
    11.1a — a stack where reads consult the top first — so one primitive serves both.

    Mutations are recorded IN ORDER, so several transactions can be thrown at one layer and the
    resulting sequence is exactly what would be applied."""

    def __init__(self, base: Reader):
        self._base = base
        # None == tombstone; a key absent from the dict falls through to the base
        self._delta: dict[tuple[int, bytes], Held | None] = {}
        self._log: list[ops.Mutation] = []

    # -- Reader ------------------------------------------------------------- #

    def get(self, store: int, name: bytes) -> Held | None:
        key = (store, name)
        if key not in self._delta:
            return self._base.get(store, name)
        return self._delta[key]

    def prefix(self, store: int, pre: bytes) -> Iterator[Row]:
        """Merged view. A tombstone in this layer HIDES a base row — without that, a deleted key
        would reappear in an enumeration, which is how `Management.nodes()` would resurrect a node
        removed earlier in the same transaction."""
        rows: dict[bytes, Held] = {
            name: Held(prov, val, ep) for name, prov, val, ep in self._base.prefix(store, pre)
        }
        for (st, name), held in self._delta.items():
            if st != store or not name.startswith(pre):
                continue
            if held is None:
                rows.pop(name, None)
            else:
                rows[name] = held
        for name in sorted(rows):
            yield Row(name, rows[name].provenance, rows[name].value, rows[name].epoch)

    def epoch_live(self, epoch: int) -> int:
        """The base count, corrected for what this layer has done to it.

        A layer that only delegated would let a transaction retire an epoch it is itself writing
        under, in the same batch — the count has to see uncommitted work for the same reason a
        guard does."""
        n = self._base.epoch_live(epoch)
        for (st, name), held in self._delta.items():
            was = self._base.get(st, name)
            if was is not None and was.epoch == epoch:
                n -= 1
            if held is not None and held.epoch == epoch:
                n += 1
        return n

    # -- writes ------------------------------------------------------------- #

    def apply(self, m: ops.Mutation) -> None:
        """Record one mutation. Nothing reaches the underlying store."""
        if isinstance(m, ops.Move):
            # Carries no value: it moves whatever is already there, so the layer copies the current
            # row forward rather than inventing one. A move of a key that is absent records
            # nothing — settlement refuses it separately, with a reason.
            held = self.get(m.store, m.name)
            if held is not None:
                self._delta[(m.store, m.name)] = Held(PENDING, held.value, held.epoch)
        else:
            self._delta[(m.store, m.name)] = (
                Held(PENDING, m.value, m.epoch) if isinstance(m, ops.Set) else None
            )
        self._log.append(m)

    @property
    def mutations(self) -> tuple[ops.Mutation, ...]:
        """Everything written here, in order."""
        return tuple(self._log)

    def absorb(self, child: Layer) -> None:
        """Merge a nested layer down into this one — used when a transaction survives evaluation.
        Discarding a child is simply not calling this."""
        self._delta.update(child._delta)
        self._log.extend(child._log)


def holds(reader: Reader, pred: ops.Predicate) -> bool:
    """Evaluate one predicate against any Reader — with **no key at all** (#predicates).

    `absent` is a presence test; `holds` compares the digest the author QUOTED against the stored
    ciphertext (11.4d), never a value the node derived. Taking a `Reader` rather than a `Store` is
    what lets a guard see mutations from earlier steps of its own transaction."""
    if isinstance(pred, ops.Drained):
        return reader.epoch_live(pred.epoch) == 0
    cur = reader.get(pred.store, pred.name)
    if isinstance(pred, ops.Absent):
        return cur is None
    return cur is not None and ops.value_digest(cur[1]) == pred.digest


def _prefix_upper(pre: bytes) -> bytes | None:
    """The exclusive upper bound for a bytewise prefix scan, or None when the prefix is all 0xFF
    (nothing sorts above it). Increment the last byte that can be incremented and truncate."""
    for i in range(len(pre) - 1, -1, -1):
        if pre[i] != 0xFF:
            return pre[:i] + bytes([pre[i] + 1])
    return None
