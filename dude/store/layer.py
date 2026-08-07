# dude.store.layer — the read surface, and the writable delta over it. See SPECv2 anchors
# settlement, view-abstraction, and frozen-base-for-layer.
#
# WHY THIS IS ITS OWN MODULE. Evaluating a transaction -- guards, authority -- must be possible
# WITHOUT a store: the mempool screens candidates speculatively, thousands of times, and none
# of that work may be durable or reach SQLite. So evaluation is written against `Reader`, and
# `Layer` is a `Reader` you can write to. Neither knows anything about persistence, which lets
# `dude.store.settle` be pure and replay bypasses evaluation (#replay-does-not-readjudicate).
#
# TWO PROTOCOLS. `Reader` is the minimal read surface (get, prefix); enough for settle.evaluate,
# MgmtReader, admission. `View(Reader)` extends it with the root-computing surface a Layer's
# base must provide (accumulator, state_root, hash_under, is_frozen) -- because a Layer computes
# its projected roots by composing over its base's roots. Store implements View; Layer
# implements View. That common shape is the "View abstraction" (SPECv2 #view-abstraction) --
# Store and Layer will eventually collapse to one type distinguished only by backing store.

from __future__ import annotations

from collections.abc import Iterator
from typing import NamedTuple, Protocol, cast

from ..core import crypto
from . import ops, smt


class LayerError(Exception):
    """A Layer used out of contract: base not frozen, apply on a frozen Layer, and so on."""


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
    epoch: int
    """Which keyepoch `value` is under. A reader needs it to pick a key, and the conveyor needs it
    to count (#conveyor)."""

    cred: bytes
    """The signed transaction that authorised `value`, and part of what the root commits to
    (`smt.leaf_hash`).

    ON THE READ SURFACE because settlement must compare a relocation against the credential the row
    ALREADY holds, and settlement reads through a `Layer` — so asking the store directly would miss
    a row written earlier in the same batch.

    NO DEFAULT, and neither has `epoch` any more `[H]`. There is no live row without a credential:
    the one write path is `_commit`, which records the transaction doing the write. An empty one
    is not a state the system has -- so it must not be a value this type can be given by
    omission. A default here would make an unauthenticated leaf constructible by forgetting an
    argument, which is the shape of every bug this codebase keeps finding."""


class Row(NamedTuple):
    """One enumerated entry: its key, the settled index that last wrote it, and its value.

    Named because `for name, prov, value in ...` is only self-documenting while the reader remembers
    the order — and `prov` between two byte strings is exactly the position a port transposes."""

    name: bytes
    provenance: Index
    value: bytes
    epoch: int = ops.EPOCH_NONE


class Reader(Protocol):
    """The minimal read surface. `Store` implements it over SQLite; `Layer` implements it over
    another `View`. Anything that only READS state takes this -- including `MgmtReader`, which
    is how a transaction's own uncommitted grants become visible to its own authority checks
    (and admission, and settle.evaluate, and every guard predicate)."""

    def get(self, store: int, name: bytes) -> Held | None: ...

    def prefix(self, store: int, pre: bytes) -> Iterator[Row]: ...


class View(Reader, Protocol):
    """The root-computing surface a Layer's base must expose (SPECv2 #view-protocol).

    Adds three commitments over live state (`accumulator`, `state_root`, `hash_under`) plus the
    frozen-lifecycle bit (`is_frozen`). Store implements View. Layer implements View. `Layer
    (base=X)` requires `X.is_frozen` at construction (SPECv2 #frozen-base-for-layer): once you
    stack over something, that something must not move under your feet."""

    def accumulator(self) -> crypto.Accumulator: ...

    def state_root(self) -> crypto.Digest: ...

    def hash_under(self, prefix: bytes, depth: int) -> crypto.Digest: ...

    @property
    def is_frozen(self) -> bool: ...


class Layer:
    """A read-through, writable delta over any `View`. Writes land in this layer; reads fall
    through to the base when this layer has nothing to say.

    Two states (SPECv2 #frozen-base-for-layer):
      OPEN    -- accepts `apply(mutation, credential)`.
      FROZEN  -- refuses `apply`. Eligible as another Layer's base.
    Transition OPEN -> FROZEN via `freeze()`, one-way. There is no thaw.

    `Layer(base=X)` REFUSES construction if `not X.is_frozen`. That single check is what makes
    the stack safe: nothing under a Layer can change while the Layer is alive, so every subtree
    hash the Layer memoises is valid for its lifetime. No cross-layer invalidation protocol.

    This is the evaluation substrate, and it exists because **the mempool evaluates
    speculatively**. A candidate transaction must be checkable -- guards, authority, conflicts
    -- thousands of times without touching the store, so the mechanism cannot be a database
    transaction: SQLite savepoints would mean thousands of write transactions for work that
    must never be durable.

    It also nests: a `Layer` over a `Layer` gives per-transaction isolation inside a batch, and
    `absorb` merges a survivor down. The same construct is what L5 settlement will use to
    project post-apply anchors before committing.

    Mutations are recorded IN ORDER, so several transactions can be thrown at one layer and the
    resulting sequence is exactly what would be applied."""

    def __init__(self, base: View):
        """The safe constructor: base MUST be frozen so this Layer can freeze itself and be a
        base for another Layer. For settle's speculative nested evaluation (where the base
        Layer stays OPEN across a batch and absorbs survivors), use `Layer.speculative` --
        that path does not compute or memoise subtree hashes, so the base moving under it is
        harmless."""
        if not base.is_frozen:
            raise LayerError(
                "Layer base must be frozen (SPECv2 #frozen-base-for-layer); "
                "call base.freeze() first, or use Layer.speculative for evaluation overlays"
            )
        self._init(base)

    @classmethod
    def speculative(cls, base: Reader) -> Layer:
        """A Layer for guard/authority evaluation only -- no root computation, no memoisation.
        Used by settle.evaluate/would_apply, where the base is another open Layer that absorbs
        survivors as the batch is walked. Calling `accumulator` / `state_root` / `hash_under`
        on a speculative Layer (or its ancestors) is a caller bug -- the base is not required
        to implement the root-computing surface. `freeze()` is a no-op signal but does not make
        the Layer safe as another Layer's frozen base."""
        layer = cls.__new__(cls)
        layer._init(cast(View, base))  # noqa: SLF001 — factory constructing its own type
        return layer

    def _init(self, base: View) -> None:
        self._base = base
        # None == tombstone; a key absent from the dict falls through to the base
        self._delta: dict[tuple[int, bytes], Held | None] = {}
        self._log: list[ops.Mutation] = []
        self._frozen = False
        # A per-layer memo of subtree hashes for the state root. Only populated after freeze --
        # while OPEN the delta can change, so cached hashes might be stale. Once FROZEN the memo
        # is valid forever (base cannot change either, per the constructor check).
        self._smt_memo: dict[tuple[int, bytes], crypto.Digest] = {}

    # -- Reader ------------------------------------------------------------- #

    def get(self, store: int, name: bytes) -> Held | None:
        key = (store, name)
        if key not in self._delta:
            return self._base.get(store, name)
        return self._delta[key]

    def prefix(self, store: int, pre: bytes) -> Iterator[Row]:
        """Merged view. A tombstone in this layer HIDES a base row -- without that, a deleted
        key would reappear in an enumeration, which is how `MgmtReader.nodes`()` would resurrect
        a node removed earlier in the same transaction."""
        rows: dict[bytes, Row] = {r.name: r for r in self._base.prefix(store, pre)}
        for (st, name), held in self._delta.items():
            if st != store or not name.startswith(pre):
                continue
            if held is None:
                rows.pop(name, None)
            else:
                rows[name] = Row(name, held.provenance, held.value, held.epoch)
        for name in sorted(rows):
            yield rows[name]

    # -- View (root-computing surface) -------------------------------------- #

    @property
    def is_frozen(self) -> bool:
        return self._frozen

    def freeze(self) -> None:
        """OPEN -> FROZEN. Idempotent -- freezing an already-frozen Layer is a no-op, not an
        error, so a caller need not track the transition."""
        self._frozen = True

    def accumulator(self) -> crypto.Accumulator:
        """`A_state` projected: base's accumulator, minus what the delta removed, plus what the
        delta added. Cheap arithmetic: O(|delta|), no walk of live state.

        `epoch` and `cred` are deliberately absent from the element (SPECv2 #accumulators): the
        accumulator fingerprints `(store, name, value)` and nothing else, so it is stable across
        credential-rewrites or epoch-conveyance that leave the value unchanged."""
        from .store import element  # noqa: PLC0415 — store imports layer, so this is deferred

        acc = self._base.accumulator()
        for (st, name), held in self._delta.items():
            was = self._base.get(st, name)
            if was is not None:
                acc = crypto.acc_sub(acc, element(st, name, was.value))
            if held is not None:
                acc = crypto.acc_add(acc, element(st, name, held.value))
        return acc

    def state_root(self) -> crypto.Digest:
        """The projected SMT root. Recurses into `hash_under` at (empty prefix, depth 0)."""
        return self.hash_under(bytes(crypto.DIGEST_SIZE), 0)

    def hash_under(self, prefix: bytes, depth: int) -> crypto.Digest:
        """The projected hash of the subtree under `prefix` at `depth`, considering base + delta.

        Two fast paths: no delta touches under this prefix -> `base.hash_under` is the answer;
        the memo already knows -> return it. Otherwise recurse via effective leaf counting to
        handle the compression rule (a subtree with exactly one leaf hashes as that leaf)."""
        lo, hi = smt.bounds(prefix, depth)
        if not self._delta_touches_range(lo, hi):
            return self._base.hash_under(prefix, depth)
        memo_key = (depth, lo)
        if memo_key in self._smt_memo:
            return self._smt_memo[memo_key]
        # Effective leaves under this prefix, capped at 2 (all we need to know for the shape).
        effective = self._effective_leaves(lo, hi, at_most=2)
        if not effective:
            result = smt.EMPTY
        elif len(effective) == 1:
            result = effective[0][1]
        else:
            # 2+ leaves: recurse into children and combine
            left, right = (
                smt.bounds(prefix, depth + 1)[0],
                smt.bounds(smt.with_bit(prefix, depth, 1), depth + 1)[0],
            )
            left_hash = self.hash_under(left, depth + 1)
            right_hash = self.hash_under(right, depth + 1)
            result = smt.branch_hash(depth, lo, left_hash, right_hash)
        if self._frozen:
            self._smt_memo[memo_key] = result
        return result

    def _delta_touches_range(self, lo: bytes, hi: bytes) -> bool:
        """Does this Layer's delta modify any row whose SMT path falls inside `[lo, hi]`?"""
        return any(lo <= smt.path_of(st, name) <= hi for st, name in self._delta)

    def _effective_leaves(
        self, lo: bytes, hi: bytes, at_most: int
    ) -> list[tuple[bytes, crypto.Digest]]:
        """Up to `at_most` effective leaves in [lo, hi], with their leaf hashes -- base rows
        minus delta tombstones, plus delta additions. Sorted by path for determinism."""
        delta_paths = {
            smt.path_of(st, name): (st, name, held)
            for (st, name), held in self._delta.items()
            if lo <= smt.path_of(st, name) <= hi
        }
        # Base rows in range, excluding those the delta touches (add or remove).
        base_leaves: list[tuple[bytes, crypto.Digest]] = []
        for st, name, value, cred in self._base_rows_in_range(lo, hi):
            path = smt.path_of(st, name)
            if path in delta_paths:
                continue  # delta will decide
            base_leaves.append((path, smt.leaf_hash(path, crypto.h(value), crypto.h(cred))))
        # Delta additions (Set) contribute leaf hashes; deletions (None) contribute nothing.
        delta_leaves: list[tuple[bytes, crypto.Digest]] = []
        for path, entry in delta_paths.items():
            held = entry[2]
            if held is not None:
                delta_leaves.append(
                    (path, smt.leaf_hash(path, crypto.h(held.value), crypto.h(held.cred)))
                )
        merged = sorted(base_leaves + delta_leaves, key=lambda pl: pl[0])
        return merged[:at_most]

    def _base_rows_in_range(
        self, lo: bytes, hi: bytes
    ) -> Iterator[tuple[int, bytes, bytes, bytes]]:
        """Base rows whose paths fall inside `[lo, hi]`. Requires `_rows_in_path_range` on the
        base -- both `Store` and `Layer` expose it, so the stack composes."""
        rows_fn = getattr(self._base, "_rows_in_path_range", None)
        if rows_fn is None:
            raise LayerError(
                "base does not expose _rows_in_path_range; every View in a Layer stack must "
                "provide a path-range scan"
            )
        yield from rows_fn(lo, hi)

    def _rows_in_path_range(
        self, lo: bytes, hi: bytes
    ) -> Iterator[tuple[int, bytes, bytes, bytes]]:
        """Effective rows in `[lo, hi]` -- base rows minus delta tombstones, plus delta additions.
        Sorted by path for determinism. Enables another Layer to stack above this one and walk
        its projected SMT (SPECv2 #view-protocol)."""
        delta_by_path = {
            smt.path_of(st, name): (st, name, held)
            for (st, name), held in self._delta.items()
            if lo <= smt.path_of(st, name) <= hi
        }
        merged: dict[bytes, tuple[int, bytes, bytes, bytes]] = {}
        for st, name, value, cred in self._base_rows_in_range(lo, hi):
            path = smt.path_of(st, name)
            if path in delta_by_path:
                continue  # delta will decide
            merged[path] = (st, name, value, cred)
        for path, (st, name, held) in delta_by_path.items():
            if held is not None:
                merged[path] = (st, name, held.value, held.cred)
        for path in sorted(merged):
            yield merged[path]

    # -- writes ------------------------------------------------------------- #

    def apply(self, m: ops.Mutation, cred: bytes) -> None:
        """Record one mutation. Nothing reaches the underlying store.

        `cred` is the credential a `Set` will leave behind -- the transaction doing it. REQUIRED,
        for the reason `Held.cred` has no default: the layer cannot know it and the caller
        settling the transaction can, so an omitted one would silently record a row that could
        not exist.

        Refuses on a FROZEN Layer (SPECv2 #frozen-base-for-layer)."""
        if self._frozen:
            raise LayerError("Layer is frozen; no more mutations")
        self._delta[(m.store, m.name)] = (
            Held(PENDING, m.value, m.epoch, cred) if isinstance(m, ops.Set) else None
        )
        self._log.append(m)

    @property
    def mutations(self) -> tuple[ops.Mutation, ...]:
        """Everything written here, in order."""
        return tuple(self._log)

    def absorb(self, child: Layer) -> None:
        """Merge a nested layer down into this one -- used when a transaction survives
        evaluation. Discarding a child is simply not calling this."""
        if self._frozen:
            raise LayerError("Layer is frozen; cannot absorb")
        self._delta.update(child._delta)
        self._log.extend(child._log)


def holds(reader: Reader, pred: ops.Predicate) -> bool:
    """Evaluate one predicate against any Reader — with **no key at all** (#predicates).

    `absent` is a presence test; `holds` compares the digest the author QUOTED against the stored
    ciphertext (11.4d), never a value the node derived. Taking a `Reader` rather than a `Store` is
    what lets a guard see mutations from earlier steps of its own transaction."""
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
