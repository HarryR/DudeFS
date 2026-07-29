# dude.store.store — the log and the derived view, on SQLite. See ../../SPEC.md §11.
#
# TWO COMPONENTS, ONE DATABASE (#one-write-vocabulary, 11.0a). They are separate in interface — the
# log is a
# sequence, the store is derived state — and share one SQLite file because a settlement must
# append entries, update chain pointers, update the live view and update the accumulator
# ATOMICALLY. That single transaction is what makes 11.1's "only the log is authoritative"
# survivable across a crash mid-settlement; hand-rolling it would mean re-earning transactionality
# SQLite already has.
#
# THE INVARIANT EVERYTHING RESTS ON, and the one worth testing hardest:
#
#     applying entries incrementally == replaying the log from scratch
#
# The live view and the accumulator are caches of a fold (#one-write-vocabulary — state is tacit).
# If they can
# disagree with the log there are two truths, and `rebuild()` exists so that claim is checkable
# rather than asserted.
#
# WHY `live` HOLDS THE VALUE rather than pointing at its entry: compaction deletes entries while
# preserving state (#collect-whole-segment), so the current value has to survive its log entry being
# collected.
# It is also why the accumulated element is over `(name, value)` and computable from `live` alone.

from __future__ import annotations

import sqlite3
from collections.abc import Iterable, Iterator
from dataclasses import dataclass
from typing import NamedTuple

from ..core import codec, crypto
from ..core.errors import DudeError
from . import attest, ops, settle, smt
from .layer import Held, Index, Row, _prefix_upper, holds

_SCHEMA = """
CREATE TABLE IF NOT EXISTS entry (
    idx      INTEGER PRIMARY KEY,      -- the settled index; assigned by settlement, never authored
    kind     INTEGER NOT NULL,         -- 0 = transaction, 1 = collection
    op_hash  BLOB NOT NULL UNIQUE,     -- h(raw): content address (#content-address)
    raw      BLOB NOT NULL,            -- the bytes exactly as received
    author   BLOB,                     -- transactions only; a compaction has no single author
    ts       INTEGER,                  -- transactions only. The author's own clock (#buckets)
    segment  INTEGER NOT NULL          -- the SETTLEMENT bucket, not the author's clock. See below.
);
CREATE INDEX IF NOT EXISTS entry_by_segment ON entry(segment, idx);

-- Segments are PHYSICAL SLICES of the one logical log, and they are the unit of collection.
--
-- Not stores, and not ACL domains: conflating those breaks predicates and grants -- a store id
-- is stable and named by a grant, while a segment is ephemeral and named by nobody.
--
-- The id is the SETTLEMENT bucket. Deriving it from the author's `ts` would be wrong: the mempool
-- carries late transactions forward, so an author-stamped entry could land in a segment that has
-- already been collected — recreating exactly the scattering segments exist to prevent.
--
-- A segment is collected WHOLE. That is the entire mechanism: no scattered drop set, no chain
-- repair, no run-length problem, because a segment IS a run by construction.
CREATE TABLE IF NOT EXISTS segment (
    id     INTEGER PRIMARY KEY,
    acc    BLOB NOT NULL,              -- ECMH over this segment; collection subtracts it whole
    sealed INTEGER NOT NULL DEFAULT 0  -- no further entries may be assigned to it
);

-- The live view: the store proper. An absent key is simply no row (#predicates's `absent`, which is
-- deliberately different from holding empty bytes).
-- Keyed by (store, name), not name alone. A key's IDENTITY includes its store, so the same name
-- token in the management store and in a data store are different keys. Keying by name alone let a
-- data write silently clobber a management value — an ACL bypass by name collision.
CREATE TABLE IF NOT EXISTS live (
    store  INTEGER NOT NULL,
    name   BLOB NOT NULL,
    head   INTEGER NOT NULL,           -- the settled index of the last write (#provenance)
    value  BLOB NOT NULL,              -- ciphertext; held here so it outlives its log entry
    epoch  INTEGER NOT NULL DEFAULT 0, -- which keyepoch `value` is under (#conveyor)
    path   BLOB NOT NULL,              -- H(store||name): where this key sits in the state root
    PRIMARY KEY (store, name)
);
-- UNIQUE deliberately: `path` is a hash of the primary key, so a duplicate is a collision, and a
-- collision must be an error rather than two keys silently sharing one leaf (#state-root).
CREATE UNIQUE INDEX IF NOT EXISTS live_by_path ON live(path);
-- The conveyor's whole question -- "is this epoch drained yet" -- is one indexed count.
CREATE INDEX IF NOT EXISTS live_by_epoch ON live(epoch);

-- Internal nodes of the state root. A MEMO OF A PURE FUNCTION and nothing more: every row is
-- recomputable from `live` alone, so truncating this table costs time and cannot cost correctness.
CREATE TABLE IF NOT EXISTS smt_memo (
    depth  INTEGER NOT NULL,
    prefix BLOB NOT NULL,
    hash   BLOB NOT NULL,
    PRIMARY KEY (depth, prefix)
);

CREATE TABLE IF NOT EXISTS meta (k TEXT PRIMARY KEY, v BLOB NOT NULL);

-- NODE-LOCAL, NOT LOG STATE. What this node has heard other nodes say about themselves, and what
-- it has proved about them. Deliberately outside the log: an accusation is not consensus, it is a
-- pair of signatures that speaks for itself wherever it is carried (#cross-attestation).
CREATE TABLE IF NOT EXISTS sighting (peer BLOB PRIMARY KEY, att BLOB NOT NULL);
CREATE TABLE IF NOT EXISTS conviction (
    peer    BLOB PRIMARY KEY,
    fault   INTEGER NOT NULL,
    earlier BLOB NOT NULL,
    later   BLOB NOT NULL
);
"""


class StoreError(DudeError):
    """The store's base error."""


@dataclass(frozen=True, slots=True)
class Entry:
    """A settled log item: the transaction, plus what settlement attached to it."""

    idx: Index
    item: ops.LogEntry


class Dropped(NamedTuple):
    """A transaction that did not settle, and the reason. Named so a caller reads `d.why` rather
    than `d[1]`, and so a port cannot reverse the pair."""

    op_hash: crypto.Digest
    why: settle.Reason


@dataclass(frozen=True, slots=True)
class Applied:
    """The outcome of settling one ordered batch. `settled` and `dropped` partition the input, so a
    caller can tell a client which of its transactions took effect and which failed a predicate."""

    settled: tuple[tuple[Index, crypto.Digest], ...]
    dropped: tuple[Dropped, ...]


def _write_set(mutations: tuple[ops.Mutation, ...]) -> tuple[tuple[int, bytes], ...]:
    """The distinct `(store, key)` pairs a mutation sequence touches, in first-touch order — one
    entry per key, however many times the sequence writes it."""
    seen: dict[tuple[int, bytes], None] = {}
    for m in mutations:
        seen.setdefault((m.store, m.name), None)
    return tuple(seen)


def log_element(idx: int, op_hash: crypto.Digest) -> crypto.Accumulator:
    """The accumulated element for one LOG entry: `HashToPoint(bencode(["log", idx, op_hash]))`.

    A second, independent measure (#replay-does-not-readjudicate). `A_state` answers *do we hold
    the same state*;
    `A_log` answers *do we hold the same history*, which `A_state` cannot — two nodes agreeing on
    every value can differ by any number of superseded entries. It binds the INDEX, so an entry at
    the wrong position is a mismatch rather than a match.

    ECMH rather than a hash chain or MMR for one reason: this log DELETES (compaction), and a chain
    cannot be maintained incrementally under deletion. Here it is one subtraction."""
    return crypto.acc_element(codec.encode([b"log", idx, op_hash]))


def element(store: int, name: bytes, value: bytes) -> crypto.Accumulator:
    """The accumulated element for one live key: `HashToPoint(bencode([store, name, value]))`
    (#provenance). The STORE is part of it because a key's identity includes its store — without it,
    two states differing only in *which* store held a value would fingerprint identically.

    Provenance is deliberately NOT in here. If it were, re-pointing a live key's provenance would
    change the ECMH — and that is exactly what the useful compaction does, so accumulating it would
    forbid the compaction worth doing (#provenance)."""
    return crypto.acc_element(codec.encode([store, name, value]))


class Store:
    """The log plus its derived view, over one SQLite connection."""

    def __init__(self, path: str = ":memory:"):
        self.db = sqlite3.connect(path, isolation_level=None)
        self.db.execute("PRAGMA journal_mode=WAL")
        self.db.execute("PRAGMA foreign_keys=ON")
        self.db.executescript(_SCHEMA)
        self.tree = smt.Tree(self.db)

    def close(self) -> None:
        self.db.close()

    # -- meta ---------------------------------------------------------------- #

    def _get_meta(self, k: str, default: bytes) -> bytes:
        row = self.db.execute("SELECT v FROM meta WHERE k=?", (k,)).fetchone()
        return row[0] if row else default

    def _set_meta(self, k: str, v: bytes) -> None:
        self.db.execute("INSERT OR REPLACE INTO meta VALUES (?,?)", (k, v))

    def accumulator(self) -> crypto.Accumulator:
        """`A_state`: the ECMH fingerprint of the whole live state (#accumulators). O(1) to
        read, O(Δ)
        to maintain, and the thing a compaction must leave unchanged (#accumulators)."""
        return crypto.Accumulator(self._get_meta("acc", crypto.ACC_IDENTITY))

    def log_accumulator(self) -> crypto.Accumulator:
        """`A_log`: the ECMH fingerprint of the log itself (#replay-does-not-readjudicate).
        Equal `A_state` with unequal
        `A_log` means *same state, different history* — legitimate across compaction generations.
        Unequal at the same head means a fork or corruption, not lag."""
        return crypto.Accumulator(self._get_meta("acc_log", crypto.ACC_IDENTITY))

    def _log_add(self, idx: Index, op_hash: crypto.Digest) -> None:
        self._set_meta("acc_log", crypto.acc_add(self.log_accumulator(), log_element(idx, op_hash)))

    def _log_sub(self, idx: Index, op_hash: crypto.Digest) -> None:
        self._set_meta("acc_log", crypto.acc_sub(self.log_accumulator(), log_element(idx, op_hash)))

    # -- LOG ----------------------------------------------------------------- #

    def head(self) -> Index:
        """The highest settled index, or 0 for an empty log (indices start at 1)."""
        row = self.db.execute("SELECT MAX(idx) FROM entry").fetchone()
        return row[0] or 0

    def entries(self, frm: Index = 1, to: Index | None = None) -> Iterator[Entry]:
        """Replay range, inclusive. The only way anyone derives state (SPEC §8)."""
        hi = self.head() if to is None else to
        for idx, kind, raw in self.db.execute(
            "SELECT idx, kind, raw FROM entry WHERE idx BETWEEN ? AND ? ORDER BY idx", (frm, hi)
        ):
            yield Entry(
                idx,
                ops.SignedTransaction.decode(raw)
                if kind == ops.KIND_TRANSACTION
                else ops.Compaction.decode(raw),
            )

    # -- STORE --------------------------------------------------------------- #

    def get(self, store: int, name: bytes) -> Held | None:
        """`(provenance, value)`, or None if absent. `provenance` is the CURRENT head only — the
        chain behind it is a traversal (`history`), and compaction may have collapsed it
        (#provenance)."""
        row = self.db.execute(
            "SELECT head, value, epoch FROM live WHERE store=? AND name=?", (store, name)
        ).fetchone()
        return Held(row[0], row[1], row[2]) if row else None

    def prefix(self, store: int, pre: bytes) -> Iterator[Row]:
        """Every live `(name, provenance, value)` in `store` whose name starts with `pre`, in name
        order. A range scan on the `(store, name)` primary key, not a table walk.

        Enumeration is what the management store needs and a data store cannot offer: control keys
        are cleartext paths (#management-is-cleartext), so `b"node/"` is a meaningful
        prefix, whereas data keys are
        opaque derived tokens whose structure lives only in the client that derived them."""
        hi = _prefix_upper(pre)
        # `Row(*r)` at the boundary, not a bare yield of the driver's tuples: the SELECT's column
        # order is the only thing that made `(name, head, value)` mean anything, and naming it here
        # is what stops a reordered SELECT silently transposing provenance and value.
        if hi is None:  # the prefix is all 0xFF; nothing sorts above it
            rows = self.db.execute(
                "SELECT name, head, value, epoch FROM live WHERE store=? AND name>=? ORDER BY name",
                (store, pre),
            )
        else:
            rows = self.db.execute(
                "SELECT name, head, value, epoch FROM live"
                " WHERE store=? AND name>=? AND name<? ORDER BY name",
                (store, pre, hi),
            )
        for name, head, value, epoch in rows:
            yield Row(name, head, value, epoch)

    def holds(self, pred: ops.Predicate) -> bool:
        """Evaluate one predicate against committed state. See the free `holds`, which is the one
        implementation and works against any `Reader`."""
        return holds(self, pred)

    # -- SETTLEMENT ---------------------------------------------------------- #

    def apply(
        self, batch: tuple[ops.SignedTransaction, ...], auth: settle.Authoriser | None = None
    ) -> Applied:
        """Settle an **already-ordered** batch: evaluate each transaction, commit the survivors
        (#settlement).

        Policy lives in `dude.store.settle` and persistence lives here. This method decides nothing
        about guards or authority — it drives the evaluator, commits what survives, and owns the one
        SQL transaction that makes a crash mid-settlement leave the store at the previous batch
        boundary rather than half-applied.

        Ordering is NOT decided here either: that is the discriminator's job one layer up (2.13)."""
        settled: list[tuple[Index, crypto.Digest]] = []
        dropped: list[Dropped] = []
        self.db.execute("BEGIN IMMEDIATE")
        try:
            acc = self.accumulator()
            idx = self.head()
            for tx in batch:
                verdict, layer = settle.evaluate(self, tx, auth)
                # Walrus on `why` rather than `if not verdict`, because a verdict is exactly "no
                # reason or a reason" — testing the reason IS testing success, and it narrows the
                # type so the reason needs no `or "rejected"` fallback for a case that cannot occur.
                if (why := verdict.why) is not None:
                    dropped.append(Dropped(tx.op_hash, why))
                    continue
                idx += 1
                acc = self._commit(idx, tx, layer.mutations, acc)
                settled.append((idx, tx.op_hash))
            self._set_meta("acc", acc)
            self.db.execute("COMMIT")
        except Exception:
            self.db.execute("ROLLBACK")
            raise
        return Applied(tuple(settled), tuple(dropped))

    def replay(self, items: Iterable[Entry]) -> None:
        """Apply already-settled entries **at their recorded indices**, without re-adjudicating.

        This is #replay-does-not-readjudicate, and it differs from `apply` in two ways that
        both matter:

        * **Positions are preserved, never re-assigned.** A settled index is part of the log's
          identity — chain pointers and compaction drop sets reference entries BY index — so
          renumbering on replay silently invalidates every one of them.
        * **Predicates are not evaluated.** In a compacted log the state a predicate referenced has
          been collected, so re-evaluation would fail every retained entry and produce nothing
          (#replay-does-not-readjudicate). Predicate evaluation belongs to settlement and
          happened once; a replayer's
          check is the accumulator against a quorum attestation (#collection-is-ratified),
          not a re-decision.

        Signatures ARE verified: self-contained, always possible, and there is never an excuse."""
        self.db.execute("BEGIN IMMEDIATE")
        try:
            acc = self.accumulator()
            for e in items:
                if isinstance(e.item, ops.Compaction):
                    # A collection replays as itself: drop the segment's entries and subtract its
                    # accumulator. There is no splice and no chain to repair, because a segment is
                    # collected WHOLE — which is the entire reason the segment model replaces the
                    # entry-level one.
                    self._set_meta("acc", acc)
                    self._collect(e.item.segment, at=e.idx)
                    acc = self.accumulator()
                    continue
                self._require_verified(e)
                acc = self._commit(e.idx, e.item, e.item.txn.mutations, acc)
            self._set_meta("acc", acc)
            self.db.execute("COMMIT")
        except Exception:
            self.db.execute("ROLLBACK")
            raise

    @staticmethod
    def _require_verified(e: Entry) -> None:
        """A replayed entry must carry a good signature. Self-contained, always checkable, so there
        is never an excuse to skip it — unlike its predicates (#replay-does-not-readjudicate)."""
        if isinstance(e.item, ops.SignedTransaction) and not e.item.verify():
            raise StoreError(f"entry {e.idx} does not verify")

    def _commit(
        self,
        idx: Index,
        tx: ops.SignedTransaction,
        mutations: tuple[ops.Mutation, ...],
        acc: crypto.Accumulator,
    ) -> crypto.Accumulator:
        """Append one transaction at `idx` and fold `mutations` into the live view and `acc`.

        Takes the mutation sequence rather than re-deriving it from `tx`, because the evaluator has
        already produced it in order — and because replay hands over the same shape without any
        evaluation having happened (#replay-does-not-readjudicate)."""
        seg = self.segment_of(idx)
        self.db.execute(
            "INSERT INTO entry (idx, kind, op_hash, raw, author, ts, segment)"
            " VALUES (?,?,?,?,?,?,?)",
            (idx, ops.KIND_TRANSACTION, tx.op_hash, tx.raw, tx.author, tx.ts, seg),
        )
        self._log_add(idx, tx.op_hash)
        self._segment_add(seg, idx, tx.op_hash)
        # Effects, in order — the last write to a key wins (#last-write-wins).
        #    The accumulator is maintained HERE and only here: each step removes whatever the key
        #    currently holds and adds what it will hold. Doing any of it in the loop above would
        #    subtract the prior element twice, which is exactly the bug the set-then-del identity
        #    test caught.
        for m in mutations:
            cur = self.get(m.store, m.name)
            if cur:
                acc = crypto.acc_sub(acc, element(m.store, m.name, cur[1]))
            path = smt.path_of(m.store, m.name)
            # Both commitments move together, in this transaction, for the same reason the live
            # view does: two truths about one state is the failure the store exists to prevent.
            self.tree.invalidate(path)
            if isinstance(m, ops.Set):
                self.db.execute(
                    "INSERT OR REPLACE INTO live (store, name, head, value, path, epoch)"
                    " VALUES (?,?,?,?,?,?)",
                    (m.store, m.name, idx, m.value, path, m.epoch),
                )
                acc = crypto.acc_add(acc, element(m.store, m.name, m.value))
            else:
                self.db.execute("DELETE FROM live WHERE store=? AND name=?", (m.store, m.name))
        return acc

    # -- the invariant, made checkable --------------------------------------- #

    def rebuild(self) -> Store:
        """A fresh store holding the same log, replayed from scratch into a new database.

        This exists so "the derived view equals a replay of the log" is a TEST rather than a claim
        (#content-address), and it is the same operation as total-loss recovery: given the log,
        everything else is reconstructible.

        It re-evaluates predicates and RAISES if one fails, which is
        #replay-does-not-readjudicate — in an uncompacted
        region a predicate that fails on replay means the log and the view disagree, i.e. corruption
        rather than a decision. **Once compaction exists this is no longer the whole story**: a
        compacted log cannot re-evaluate predicates whose referenced state was collected, so replay
        there APPLIES without re-adjudicating and correctness comes from comparing the accumulator
        against a quorum attestation (#collection-is-ratified). This method is the
        uncompacted case."""
        fresh = Store(":memory:")
        fresh.replay(list(self.entries()))
        return fresh

    # -- COMPACTION (#collection-is-a-log-entry, 11.2a-i, 11.4b) ------------------------------ #

    # -- segments ------------------------------------------------------------- #

    SEGMENT_WIDTH = 1024
    """Entries per segment. A COUNT, not a duration, because the settlement bucket is what must not
    move — see the `segment` table comment. It must exceed the mempool's dedup window, since
    `entry.op_hash UNIQUE` is the dedup substrate and collection forgets hashes: collect a segment
    narrower than that window and a transaction still inside it becomes replayable."""

    def segment_of(self, idx: Index) -> int:
        """Which segment an index belongs to. Pure arithmetic — computed, never negotiated."""
        return idx // self.SEGMENT_WIDTH

    def _segment_add(self, seg: int, idx: Index, op_hash: crypto.Digest) -> None:
        row = self.db.execute("SELECT acc FROM segment WHERE id=?", (seg,)).fetchone()
        acc = crypto.Accumulator(row[0]) if row else crypto.ACC_IDENTITY
        acc = crypto.acc_add(acc, log_element(idx, op_hash))
        self.db.execute(
            "INSERT OR REPLACE INTO segment (id, acc, sealed) VALUES (?,?,0)", (seg, acc)
        )

    def segments(self) -> tuple[int, ...]:
        """Sorted — never mapping or rowid order, which is a portability rule, not a style one."""
        return tuple(r[0] for r in self.db.execute("SELECT id FROM segment ORDER BY id"))

    def segment_live(self, seg: int) -> int:
        """How many of this segment's entries still provide a LIVE value.

        This is the collection trigger: a segment is worth collecting when it is mostly dead, which
        is the classic generational rule and the explicit signal entry-level compaction
        never had."""
        q = "SELECT COUNT(*) FROM live WHERE head IN (SELECT idx FROM entry WHERE segment=?)"
        return int(self.db.execute(q, (seg,)).fetchone()[0])

    def roster(self) -> tuple[crypto.PublicKey, ...]:
        """Who may ratify a collection. Read from the management prefix rather than configured, so
        the set that signs is the set the log itself says exists.

        Imported lazily because `management` reads through `Store` — the cycle is real, and breaking
        it by hoisting would mean the store knowing the management schema, which is the coupling the
        prefixed keyspace exists to avoid."""
        from .management import Management  # noqa: PLC0415

        return Management(self).node_set()

    def migrate(
        self, seg: int, author: crypto.Keypair, now: int
    ) -> tuple[ops.SignedTransaction, ...]:
        """Rewrite this segment's stragglers at the head, SAME VALUE, so the segment can collect.

        `A_state`-invariant by construction: re-setting a key to the value it already holds changes
        no state element, so the accumulator is untouched while provenance moves forward. That is
        the cheap half of the conveyor — the forward-secrecy half re-encrypts under the current
        epoch and belongs with the worker bees.

        Without this, collection has a permanent floor: genesis grants and roster rows are live for
        the life of the log, so segment 0 could never be collected at all."""
        moves = []
        for st, name in self.stragglers(seg):
            held = self.get(st, name)
            if held is None:  # raced with a writer; it has already moved on
                continue
            moves.append(ops.writes(ops.Set(st, name, held.value)).sign(author, now))
        if moves:
            self.apply(tuple(moves))
        return tuple(moves)

    def collect(
        self,
        seg: int,
        attest: ops.Compaction | None = None,
        now: int | None = None,
        dedup_window: int = 0,
    ) -> Index:
        """Collect a segment WHOLE. Returns the index of the collection entry.

        Refuses while the segment still holds live values: those stragglers must be migrated forward
        first, which is what keeps `A_state` invariant across a collection. The refusal is the point
        — a segment that silently collected live data would lose committed state, which is the one
        failure this system exists to prevent."""
        # The dedup floor. `entry.op_hash UNIQUE` is what makes a settled transaction unrepeatable,
        # and collection FORGETS those hashes -- so collecting a segment while the mempool would
        # still admit one of its transactions makes that transaction replayable.
        #
        # Expressed as an AGE, not as a segment width. The plan said "width > w_admit + w_valid",
        # but a width is a COUNT of entries and the window is a DURATION: comparing them needs an
        # assumed arrival rate, which nobody has. The newest entry's own timestamp answers it
        # directly and needs no rate at all.
        if dedup_window and now is not None:
            row = self.db.execute(
                "SELECT MAX(ts) FROM entry WHERE segment=? AND ts IS NOT NULL", (seg,)
            ).fetchone()
            newest = row[0] if row and row[0] is not None else None
            if newest is not None and now - newest < dedup_window:
                raise StoreError(
                    f"segment {seg} is younger than the dedup window "
                    f"({now - newest}ms < {dedup_window}ms); collecting it would make its "
                    f"transactions replayable"
                )
        current = self.segment_of(self.head() + 1)
        if seg >= current:
            # Migration writes at the HEAD, so draining a segment into ITSELF is a no-op — the
            # straggler simply reappears at a later index in the same segment. A segment is only
            # drainable once the log has moved past it. Found by writing the test.
            raise StoreError(f"segment {seg} is still current (head is in segment {current})")
        roster = self.roster()
        marker = attest or ops.Compaction(seg, self.head(), self.accumulator(), self.state_root())
        if roster:
            # Enforced here, not left to a caller: collection deletes the joiner's only other way
            # to check this log, so an unratified collection is one nobody can ever verify. The
            # complaint is plain -- "no signature" -- because a vague failure at this boundary is
            # how an unverifiable log gets shipped.
            why = marker.attested(list(roster))
            if why is not None:
                raise StoreError(f"collection of segment {seg} is not ratified: {why}")
        if marker.segment != seg:
            raise StoreError("attestation names a different segment")
        left = self.stragglers(seg)
        if left:
            raise StoreError(
                f"segment {seg} still holds {len(left)} live value(s); migrate them forward first"
            )
        self.db.execute("BEGIN IMMEDIATE")
        try:
            idx = self._collect(seg, at=self.head() + 1, marker=marker)
            self.db.execute("COMMIT")
        except Exception:
            self.db.execute("ROLLBACK")
            raise
        return idx

    def _collect(self, seg: int, at: Index, marker: ops.Compaction | None = None) -> Index:
        """`collect`'s body, assuming an open transaction and no stragglers."""
        before = self.accumulator()
        if marker is None:
            marker = ops.Compaction(seg, at - 1, before, self.state_root())
        self.db.execute(
            "INSERT INTO entry (idx, kind, op_hash, raw, author, ts, segment)"
            " VALUES (?,?,?,?,NULL,NULL,?)",
            (at, ops.KIND_COMPACTION, marker.op_hash, marker.raw, self.segment_of(at)),
        )
        self._log_add(at, marker.op_hash)
        self._segment_add(self.segment_of(at), at, marker.op_hash)

        # The checkpoint is RETAINED here rather than derived from the log later, because this
        # marker is itself an entry and a later collection will delete it -- and a node that
        # forgot its own floor would attest zero and look like it had regressed. Monotone by
        # policy at exactly one place: a node never adopts a checkpoint older than its floor.
        if marker.height > self.floor():
            self._set_meta("checkpoint", marker.raw)

        row = self.db.execute("SELECT acc FROM segment WHERE id=?", (seg,)).fetchone()
        if row is not None:
            # ONE subtraction, not a per-entry fold. This is what a segment buys.
            self._set_meta(
                "acc_log", crypto.acc_sub(self.log_accumulator(), crypto.Accumulator(row[0]))
            )
        self.db.execute("DELETE FROM entry WHERE segment=?", (seg,))
        self.db.execute("DELETE FROM segment WHERE id=?", (seg,))

        if self.accumulator() != before:
            raise StoreError("collection changed the state accumulator")
        return at

    # -- THE CONVEYOR (#conveyor) ---------------------------------------------- #

    def epoch_live(self, epoch: int) -> int:
        """How many live values are still encrypted under `epoch`.

        A pure function of live state, so every node computes the same number at the same log
        position and nobody has to be trusted about it. Zero is the ONLY condition under which that
        epoch's key may die — retire one value too early and that value is unreadable by everyone,
        forever, which is the failure this whole system exists to prevent."""
        row = self.db.execute("SELECT COUNT(*) FROM live WHERE epoch=?", (epoch,)).fetchone()
        return row[0] or 0

    def epochs(self) -> dict[int, int]:
        """Live values per epoch, `EPOCH_NONE` excluded — the conveyor's backlog, by age.

        Sorted, since a caller wants the oldest first: that is the epoch closest to dying."""
        return {
            r[0]: r[1]
            for r in self.db.execute(
                "SELECT epoch, COUNT(*) FROM live WHERE epoch<>? GROUP BY epoch ORDER BY epoch",
                (ops.EPOCH_NONE,),
            )
        }

    # -- THE STATE ROOT (#state-root) ------------------------------------------ #

    def state_root(self) -> crypto.Digest:
        """One commitment to all live state, against which a single key can be PROVED.

        Kept alongside `A_state` rather than replacing it: the accumulator answers "do we agree" in
        O(1) and nodes ask that constantly, while this is paid when a proof is served or a
        checkpoint is cut."""
        return self.tree.root()

    def prove(self, store: int, name: bytes) -> smt.Proof:
        """Presence or absence, by the same walk. Absence is the valuable half — it is what makes
        a revocation checkable rather than asserted (#absence-is-revocation)."""
        return self.tree.prove(store, name)

    # -- ATTESTATION (#monotonicity) ------------------------------------------ #

    def checkpoint(self) -> ops.Compaction | None:
        """The highest quorum-ratified checkpoint this node holds, or None before the first."""
        raw = self._get_meta("checkpoint", b"")
        return ops.Compaction.decode(raw) if raw else None

    def floor(self) -> Index:
        """That checkpoint's height. Zero until one exists — a young cluster has no floor."""
        ck = self.checkpoint()
        return ck.height if ck is not None else 0

    def attestation(self, now: int) -> attest.Attestation:
        """Bump the counter and read one coherent snapshot to attest.

        THE INTERLOCK, and the highest-risk line in the design: the counter is bumped and
        COMMITTED here, and the caller signs only what this returns. Signing over uncommitted
        state is therefore not expressible rather than merely discouraged.

        It matters because the consequence is asymmetric (#cross-attestation): peers keep the
        evidence and conviction is terminal, so a node that signed a height it had not yet made
        durable would destroy itself on an honest crash. A crash here SKIPS a counter value
        instead, and a gap means nothing to anyone.

        One transaction for the same reason: five separate reads could interleave with a
        settlement and attest a head whose accumulator belongs to a different moment.

        `now` is passed IN. The store keeps no clock — a timestamp is the node's assertion about
        its own clock (#freshness-is-gathered), and nothing here can check it."""
        self.db.execute("BEGIN IMMEDIATE")
        try:
            seq = int.from_bytes(self._get_meta("attest_seq", b"")) + 1
            self._set_meta("attest_seq", seq.to_bytes(8))
            claim = attest.Attestation(
                seq,
                self.head(),
                self.accumulator(),
                self.log_accumulator(),
                now,
                self.state_root(),
                self.checkpoint(),
            )
            self.db.execute("COMMIT")
        except Exception:
            self.db.execute("ROLLBACK")
            raise
        return claim

    # -- WHAT PEERS HAVE SAID (#cross-attestation) ----------------------------- #

    def witness(self, signed: attest.SignedAttestation) -> attest.Evidence | None:
        """Take a peer's statement. Returns the conviction it completes, if it completes one.

        THE RETENTION RULE, and the trap it avoids: the obvious "latest wins by seq" is WRONG,
        because a regression arrives with the highest counter and would therefore overwrite the
        very statement that proves it. So the contradiction is tested first and both halves are
        kept forever when it convicts.

        Unsigned bytes are dropped rather than stored: anyone can write an incriminating claim,
        and only the key can make it evidence."""
        if not signed.verify():
            return None
        held = self.sighting(signed.by)
        if held is not None:
            found = attest.contradiction(held, signed)
            if found is not None:
                self.db.execute(
                    "INSERT OR IGNORE INTO conviction (peer, fault, earlier, later)"
                    " VALUES (?,?,?,?)",
                    (
                        found.culprit,
                        found.fault.value,
                        found.earlier.encode(),
                        found.later.encode(),
                    ),
                )
                return found
            if signed.claim.seq <= held.claim.seq:
                return None  # stale relay; we already hold this or better
        self.db.execute(
            "INSERT OR REPLACE INTO sighting (peer, att) VALUES (?,?)",
            (signed.by, signed.encode()),
        )
        return None

    def judge(self, claimed: attest.Evidence) -> attest.Evidence | None:
        """Take evidence someone else assembled, and RECOMPUTE the verdict rather than believe it.

        The same principle as ratifying a collection: a relay's word is worth nothing and its
        signatures are worth everything. Recomputing costs two signature checks and means a peer
        cannot get an honest node shunned by asserting a fault that is not there."""
        found = attest.contradiction(claimed.earlier, claimed.later)
        if found is None:
            return None
        self.db.execute(
            "INSERT OR IGNORE INTO conviction (peer, fault, earlier, later) VALUES (?,?,?,?)",
            (found.culprit, found.fault.value, found.earlier.encode(), found.later.encode()),
        )
        return found

    def sighting(self, peer: crypto.PublicKey) -> attest.SignedAttestation | None:
        row = self.db.execute("SELECT att FROM sighting WHERE peer=?", (peer,)).fetchone()
        return attest.SignedAttestation.decode(row[0]) if row else None

    def sightings(self) -> tuple[attest.SignedAttestation, ...]:
        """Sorted by peer — never rowid order, which is a portability rule, not a style one."""
        return tuple(
            attest.SignedAttestation.decode(r[0])
            for r in self.db.execute("SELECT att FROM sighting ORDER BY peer")
        )

    def convictions(self) -> dict[crypto.PublicKey, attest.Evidence]:
        """Proven self-contradictions, kept forever. The evidence a manager acts on, and meanwhile
        the shun list — which is a local READ policy and changes no roster and no quorum."""
        out: dict[crypto.PublicKey, attest.Evidence] = {}
        for peer, fault, earlier, later in self.db.execute(
            "SELECT peer, fault, earlier, later FROM conviction ORDER BY peer"
        ):
            out[crypto.PublicKey(peer)] = attest.Evidence(
                attest.Fault(fault),
                attest.SignedAttestation.decode(earlier),
                attest.SignedAttestation.decode(later),
            )
        return out

    def stragglers(self, seg: int) -> tuple[tuple[int, bytes], ...]:
        """The `(store, name)` pairs this segment still holds live.

        These are what stops a segment collecting, and there is ALWAYS at least one class of them:
        genesis grants and roster rows are live for the lifetime of the log, so segment 0 would be
        permanently uncollectable without migration."""
        q = (
            "SELECT store, name FROM live WHERE head IN (SELECT idx FROM entry WHERE segment=?)"
            " ORDER BY store, name"
        )
        return tuple((int(s), n) for s, n in self.db.execute(q, (seg,)).fetchall())
