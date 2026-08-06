# dude.store.store — the log and the derived view, on SQLite. See SPEC.md (#settlement).
#
# TWO COMPONENTS, ONE DATABASE (#one-write-vocabulary). They are separate in interface — the
# log is a sequence, the store is derived state — and share one SQLite file because a
# settlement must append entries, update chain pointers, update the live view and update the
# accumulator ATOMICALLY. That single transaction is what makes "only the log is authoritative"
# survivable across a crash mid-settlement; hand-rolling it would mean re-earning
# transactionality SQLite already has.
#
# READER / WRITER SPLIT. Store owns TWO sqlite connections to one DB:
#   * `_writer_conn` -- protected by `_writer_lock`. All mutations go here, inside a
#     `BEGIN IMMEDIATE ... COMMIT` block. `store.write() as w:` scope hands the writer to
#     the caller.
#   * fresh reader connection per `store.snapshot() as r:` scope -- opened, BEGIN pins a
#     snapshot for the scope's lifetime, closed on exit. Different threads calling
#     `snapshot()` simultaneously each get their own independent snapshot via SQLite's
#     WAL isolation.
# Convenience one-shot methods on Store (`store.get(...)`, `store.head_block_num()`,
# `store.commit_block(...)`, `store.apply(...)`, `store.provision(...)`) open a scope
# internally so every existing caller keeps working.
#
# StoreReader implements the `Reader` and `View` protocols in dude.store.layer. StoreWriter
# inherits StoreReader and adds mutation methods -- because a Writer's reads MUST use the
# writer connection so `_apply_within`'s mid-batch reads (direct or via Layer) see the
# transaction's own state.
#
# THE INVARIANT EVERYTHING RESTS ON, and the one worth testing hardest:
#
#     applying entries incrementally == replaying the log from scratch
#
# The live view and the accumulator are caches of a fold (#one-write-vocabulary — state is
# tacit). If they can disagree with the log there are two truths, and `rebuild()` exists so
# that claim is checkable rather than asserted.
#
# WHY `live` HOLDS THE VALUE rather than pointing at its entry: compaction deletes entries
# while preserving state (#collect-whole-segment), so the current value has to survive its
# log entry being collected. It is also why the accumulated element is over `(name, value)`
# and computable from `live` alone.

from __future__ import annotations

import contextlib
import os
import sqlite3
import tempfile
import threading
from collections.abc import Iterable, Iterator
from contextlib import contextmanager
from dataclasses import dataclass
from typing import NamedTuple

from ..core import codec, crypto
from ..core.errors import DudeError, InvariantError
from . import ops, settle, smt
from .layer import Held, Index, Row, _prefix_upper, holds
from .management import P_NODE, P_ROSTER, Management, Role

_SCHEMA = """
CREATE TABLE IF NOT EXISTS entry (
    idx      INTEGER PRIMARY KEY,      -- the settled index; assigned by settlement, never authored
    op_hash  BLOB NOT NULL UNIQUE,     -- h(raw): content address (#content-address)
    raw      BLOB NOT NULL,            -- the bytes exactly as received
    author   BLOB NOT NULL,            -- the transaction's author key
    ts       INTEGER NOT NULL          -- the author's own clock (#buckets)
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
    -- The signed transaction that authorised `value`, for EVERY row. NO DEFAULT: the state root
    -- commits to it (`smt.leaf_hash`), so a row without one is not a row this system has, and an
    -- INSERT that forgets it must fail rather than quietly produce an unauthenticated leaf.
    cred   BLOB NOT NULL,
    PRIMARY KEY (store, name)
);
-- UNIQUE deliberately: `path` is a hash of the primary key, so a duplicate is a collision, and a
-- collision must be an error rather than two keys silently sharing one leaf (#state-root).
CREATE UNIQUE INDEX IF NOT EXISTS live_by_path ON live(path);
-- Internal nodes of the state root. A MEMO OF A PURE FUNCTION and nothing more: every row is
-- recomputable from `live` alone, so truncating this table costs time and cannot cost correctness.
CREATE TABLE IF NOT EXISTS smt_memo (
    depth  INTEGER NOT NULL,
    prefix BLOB NOT NULL,
    hash   BLOB NOT NULL,
    PRIMARY KEY (depth, prefix)
);

CREATE TABLE IF NOT EXISTS meta (k TEXT PRIMARY KEY, v BLOB NOT NULL);

-- Settled blocks (SPECv2 #block-shape-settled), one row per SETTLED bucket.
--   `block_num`    -- MONOTONE per-block counter (increments per SETTLED block, whether empty
--                     or not). Primary key. `GETBLOCK n` names this. Chain-continuity holds
--                     even across empty ratifications (#empty-bucket-still-settles).
--   `first_height` -- log Index of the FIRST tx this block committed. For an empty block,
--                     `first_height == height + 1` (an empty range). Written so
--                     `bodies_of_block(n)` can fetch bodies from the entry table by range
--                     without inferring the base offset from prior blocks.
--   `height`       -- log Index of the LAST tx committed by this block. Non-unique across
--                     empty blocks. Kept for lookup by log-position.
--   `bytes`        -- `SettledBlock.encode()` (identity + quorum proof).
--   `hash`         -- `SettledBlock.block_hash` (sig-independent identity) for the chain link
--                     a successor's `prev_block` names.
-- Persisted so peers can serve `GETBLOCK n` to joiners (#sync-is-log-replay). Bodies live in
-- the entry table (already-persisted) and are fetched by range at serve-time -- no duplication.
-- Ratify sigs are NOT here; identity excludes them (see SettledBlock.encode docstring).
CREATE TABLE IF NOT EXISTS block (
    block_num    INTEGER PRIMARY KEY,
    first_height INTEGER NOT NULL,
    height       INTEGER NOT NULL,
    bytes        BLOB NOT NULL,
    hash         BLOB NOT NULL UNIQUE
);

"""


class StoreError(DudeError):
    """The store's base error."""


@dataclass(frozen=True, slots=True)
class Entry:
    """A settled log item: the transaction, plus what settlement attached to it."""

    idx: Index
    item: ops.LogEntry


class Commitment(NamedTuple):
    """What a node has SIGNED about its own state at one height (#monotonicity).

    Handed to `replay` so a bulk transfer is checked against something the sender put its identity
    behind, rather than believed because it arrived."""

    head: Index
    acc_state: crypto.Accumulator
    acc_log: crypto.Accumulator
    root: crypto.Digest


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


def _unverified(e: Entry) -> str | None:
    """`None` if this replayed entry carries a good signature, else why not.

    Self-contained and always checkable, so there is never an excuse to skip it — unlike its
    predicates (#replay-does-not-readjudicate). A bad signature in a transferred run is THEIR
    fault, so it is returned rather than raised, like every other refusal on that path."""
    if isinstance(e.item, ops.SignedTransaction) and not e.item.verify():
        return f"entry {e.idx} does not verify"
    return None


# ============================================================================= #
# StoreReader -- read-only view backed by ONE connection inside a BEGIN.        #
# ============================================================================= #


class StoreReader:
    """Read-only view of the store, backed by ONE sqlite connection. When constructed
    inside a `store.snapshot()` scope, the connection has a `BEGIN` open, pinning a
    snapshot for the scope's lifetime (SQLite WAL isolation). Implements the `Reader`
    AND `View` protocols in `dude.store.layer`, so anything that takes a `Reader` (e.g.
    `settle.evaluate`) works with a StoreReader.

    `_memoize = False`: this class's SMT operations don't write to `smt_memo` -- the
    writer maintains it. Reader recomputes on memo miss (correct, and usually a memo
    hit in practice because the writer keeps the tree warm)."""

    _memoize: bool = False

    def __init__(self, conn: sqlite3.Connection):
        self._conn = conn
        self._tree = smt.Tree(conn, memoize=self._memoize)

    # -- Reader protocol (get, prefix) ---------------------------------------- #

    def get(self, store: int, name: bytes) -> Held | None:
        """`(provenance, value)`, or None if absent. `provenance` is the CURRENT head only — the
        chain behind it is a traversal (`history`), and compaction may have collapsed it
        (#provenance)."""
        row = self._conn.execute(
            "SELECT head, value, epoch, cred FROM live WHERE store=? AND name=?", (store, name)
        ).fetchone()
        return Held(row[0], row[1], row[2], row[3]) if row else None

    def prefix(self, store: int, pre: bytes) -> Iterator[Row]:
        """Every live `(name, provenance, value)` in `store` whose name starts with `pre`, in name
        order. A range scan on the `(store, name)` primary key, not a table walk."""
        hi = _prefix_upper(pre)
        # MATERIALIZED via `fetchall()` inside the same call as `execute` -- streaming a cursor
        # across the yield boundary would race any concurrent execute on this connection.
        if hi is None:
            rows = self._conn.execute(
                "SELECT name, head, value, epoch FROM live WHERE store=? AND name>=? ORDER BY name",
                (store, pre),
            ).fetchall()
        else:
            rows = self._conn.execute(
                "SELECT name, head, value, epoch FROM live"
                " WHERE store=? AND name>=? AND name<? ORDER BY name",
                (store, pre, hi),
            ).fetchall()
        for name, head, value, epoch in rows:
            yield Row(name, head, value, epoch)

    # -- View protocol (accumulator, state_root, hash_under, is_frozen) ------- #

    def accumulator(self) -> crypto.Accumulator:
        """`A_state`: the ECMH fingerprint of the whole live state (#accumulators). O(1) to read."""
        return crypto.Accumulator(self._get_meta("acc", crypto.ACC_IDENTITY))

    def log_accumulator(self) -> crypto.Accumulator:
        """`A_log`: the ECMH fingerprint of the log itself (#replay-does-not-readjudicate)."""
        return crypto.Accumulator(self._get_meta("acc_log", crypto.ACC_IDENTITY))

    def state_root(self) -> crypto.Digest:
        """One commitment to all live state, against which a single key can be PROVED."""
        return self._tree.root()

    def hash_under(self, prefix: bytes, depth: int) -> crypto.Digest:
        """SMT subtree hash under `prefix` at `depth`."""
        return self._tree.hash_under(prefix, depth)

    def prove(self, store: int, name: bytes) -> smt.Proof:
        """Presence or absence, by the same walk. Absence is what makes revocation checkable
        (#absence-is-revocation)."""
        return self._tree.prove(store, name)

    @property
    def is_frozen(self) -> bool:
        """A Reader's snapshot never moves for its lifetime (WAL isolation)."""
        return True

    def holds(self, pred: ops.Predicate) -> bool:
        """Evaluate one predicate against committed state."""
        return holds(self, pred)

    # -- log / meta reads ----------------------------------------------------- #

    def head(self) -> Index:
        """The highest settled index. Zero on an empty log."""
        row = self._conn.execute("SELECT MAX(idx) FROM entry").fetchone()
        return row[0] or 0

    def entries(self, frm: Index = 1, to: Index | None = None) -> Iterator[Entry]:
        """Replay range, inclusive. The only way anyone derives state
        (#replay-does-not-readjudicate)."""
        hi = self.head() if to is None else to
        rows = self._conn.execute(
            "SELECT idx, raw FROM entry WHERE idx BETWEEN ? AND ? ORDER BY idx", (frm, hi)
        ).fetchall()
        for idx, raw in rows:
            yield Entry(idx, ops.SignedTransaction.decode(raw))

    def settled_at(self, block_num: Index) -> bytes | None:
        """The encoded SETTLED block bytes at `block_num`, or None if not held."""
        row = self._conn.execute(
            "SELECT bytes FROM block WHERE block_num=?", (block_num,)
        ).fetchone()
        return bytes(row[0]) if row else None

    def bodies_of_block(self, block_num: Index) -> tuple[ops.SignedTransaction, ...]:
        """The tx bodies this block committed, in log-idx order. Empty for empty blocks and
        for unknown blocks."""
        row = self._conn.execute(
            "SELECT first_height, height FROM block WHERE block_num=?", (block_num,)
        ).fetchone()
        if row is None:
            return ()
        first_height, height = row
        if first_height > height:
            return ()
        return tuple(e.item for e in self.entries(first_height, height))

    def head_block_hash(self) -> crypto.Digest | None:
        """`H(SettledBlock.encode())` at the current head, or None if no block is settled yet."""
        row = self._conn.execute(
            "SELECT hash FROM block ORDER BY block_num DESC LIMIT 1"
        ).fetchone()
        return crypto.Digest(bytes(row[0])) if row else None

    def head_block_num(self) -> Index | None:
        """The monotone block counter at the current head, or None if no block is settled yet."""
        row = self._conn.execute("SELECT MAX(block_num) FROM block").fetchone()
        return row[0] if row and row[0] is not None else None

    def credential(self, store: int, name: bytes) -> bytes:
        """The signed transaction that authorised this row's value, or empty if none is kept."""
        row = self._conn.execute(
            "SELECT cred FROM live WHERE store=? AND name=?", (store, name)
        ).fetchone()
        return row[0] if row else b""

    # -- provisioning reads --------------------------------------------------- #

    def anchor(self) -> crypto.PublicKey | None:
        """The manager public key this node was provisioned with, or None if it was not."""
        raw = self._get_meta("anchor", b"")
        return crypto.PublicKey(raw) if raw else None

    def seeds(self) -> tuple[bytes, ...]:
        """The addresses this node was provisioned with, to reach the cluster at all."""
        raw = self._get_meta("seeds", b"")
        return tuple(codec.as_bytes(a) for a in codec.as_seq(codec.decode(raw))) if raw else ()

    def roster_serial(self) -> int:
        """The highest roster revision this node has accepted."""
        return int.from_bytes(self._get_meta("roster_serial", b""))

    # -- composed reads: the acceptance-of-a-replayed-log checks -------------- #

    def wrong_cluster(self) -> str | None:
        """`None` if the log we hold is the one our anchor authorises, else why not."""
        held = self.anchor()
        if held is None:
            return "no anchor: this node was never provisioned with a manager key"
        grant = self._mgmt().grant_of(held)
        if grant is None:
            return "the log holds no grant for the manager we were provisioned with"
        if grant.role is not Role.MANAGER:
            return f"our anchor holds {grant.role.value} in this log, not manager"
        return None

    def unvouched_roster(self) -> str | None:
        """`None` if every roster row traces to our anchor, else the first one that does not."""
        held = self.anchor()
        if held is None:
            return "no anchor: this node was never provisioned with a manager key"
        for who in self._mgmt().roster():
            name = P_NODE + who
            author = settle.vouched(self, ops.STORE_MANAGEMENT, name, self.credential(0, name))
            if author is None:
                return (
                    f"roster row for {who.hex()[:8]} carries no credential vouching for its value"
                )
            if author != held:
                return f"roster row for {who.hex()[:8]} is vouched by {author.hex()[:8]}, not by us"
        return None

    def roster_incomplete(self) -> str | None:
        """`None` if the roster we hold is the whole roster the manager signed, else why not."""
        held = self.anchor()
        if held is None:
            return "no anchor: this node was never provisioned with a manager key"
        mgmt = self._mgmt()
        commitment = mgmt.roster_commitment()
        if commitment is None:
            return "the log states no roster commitment, so a subset could not be detected"
        author = settle.vouched(self, ops.STORE_MANAGEMENT, P_ROSTER, self.credential(0, P_ROSTER))
        if author != held:
            return f"the roster commitment is vouched by {author.hex()[:8] if author else 'nobody'}"
        serial, members = commitment
        if members != mgmt.roster():
            return (
                f"the roster commitment names {len(members)} members, the log holds a different set"
            )
        if serial < self.roster_serial():
            return f"roster serial {serial} is older than the {self.roster_serial()} already seen"
        return None

    # -- internals ------------------------------------------------------------ #

    def _get_meta(self, k: str, default: bytes) -> bytes:
        row = self._conn.execute("SELECT v FROM meta WHERE k=?", (k,)).fetchone()
        return row[0] if row else default

    def _rows_in_path_range(
        self, lo: bytes, hi: bytes
    ) -> Iterator[tuple[int, bytes, bytes, bytes]]:
        """Every live `(store, name, value, credential)` whose SMT path falls inside `[lo, hi]`.
        Used by `Layer` when computing projected root hashes."""
        rows = self._conn.execute(
            "SELECT store, name, value, cred FROM live WHERE path BETWEEN ? AND ? ORDER BY path",
            (lo, hi),
        ).fetchall()
        for st, name, value, cred in rows:
            yield int(st), name, value, cred

    def _settled_hashes(self, want: tuple[crypto.Digest, ...]) -> set[bytes]:
        """Which of these op hashes the log already holds. One query, not one per transaction."""
        if not want:
            return set()
        marks = ",".join("?" * len(want))
        rows = self._conn.execute(
            f"SELECT op_hash FROM entry WHERE op_hash IN ({marks})",  # noqa: S608
            want,
        ).fetchall()
        return {r[0] for r in rows}

    def _mgmt(self) -> Management:
        """A Management view over this Reader. Used by composed acceptance-checks; internal
        so callers don't couple to it. Note: `Management` still type-annotates its
        parameter as `Store`, but at runtime it uses only methods on StoreReader
        (get, prefix, anchor, credential). Wave 3 will split Management into
        MgmtReader/MgmtWriter and this cast disappears."""
        from typing import cast  # noqa: PLC0415 -- local; only used by this shim

        return Management(cast("Store", self))


# ============================================================================= #
# StoreWriter -- mutating view on the writer connection, inside BEGIN IMMEDIATE #
# ============================================================================= #


class StoreWriter(StoreReader):
    """Mutating view backed by the writer connection, inside a `BEGIN IMMEDIATE`
    transaction held under Store's writer lock. Inherits every read from StoreReader
    -- but the reads run on the WRITER connection, so `_apply_within`'s mid-batch
    reads (direct or via Layer) see the transaction's own state, not the last
    committed snapshot.

    `_memoize = True`: the writer maintains `smt_memo` via `tree.invalidate` and
    subsequent `tree.hash_under` calls that repopulate memo on the changed ancestors."""

    _memoize: bool = True

    # -- write-side helpers --------------------------------------------------- #

    def _set_meta(self, k: str, v: bytes) -> None:
        self._conn.execute("INSERT OR REPLACE INTO meta VALUES (?,?)", (k, v))

    def _log_add(self, idx: Index, op_hash: crypto.Digest) -> None:
        self._set_meta("acc_log", crypto.acc_add(self.log_accumulator(), log_element(idx, op_hash)))

    def _remember_roster_serial(self) -> None:
        """Advance the roster high-water mark, having accepted the run that carried it."""
        commitment = self._mgmt().roster_commitment()
        if commitment is not None and commitment[0] > self.roster_serial():
            self._set_meta("roster_serial", commitment[0].to_bytes(8))

    # -- provisioning --------------------------------------------------------- #

    def provision(self, manager: crypto.PublicKey, seeds: Iterable[bytes] = ()) -> None:
        """Record the anchor. Idempotent for the same key, and REFUSED for a different one."""
        held = self.anchor()
        if held is not None and held != manager:
            raise InvariantError(
                "this node is provisioned to a different manager; re-provisioning would move it "
                "between clusters while keeping its identity and its attested height"
            )
        self._set_meta("anchor", manager)
        if seeds:
            self._set_meta("seeds", codec.encode(sorted(seeds)))

    # -- SETTLEMENT ----------------------------------------------------------- #

    def apply(self, batch: tuple[ops.SignedTransaction, ...], auth: settle.Authoriser) -> Applied:
        """Settle an already-ordered batch inside the current writer transaction.

        `commit_block` is the same shape plus a block-bytes persist -- that is the entry
        point production settlement uses, so a crash cannot leave txs committed with no
        matching block record."""
        return self._apply_within(batch, auth)

    def commit_block(  # noqa: PLR0913
        self,
        block_num: Index,
        *,
        first_height: Index,
        block_bytes: bytes,
        block_hash: crypto.Digest,
        batch: tuple[ops.SignedTransaction, ...],
        auth: settle.Authoriser,
    ) -> Applied:
        """Apply the batch and persist the SETTLED block bytes atomically (#atomic-write).

        `block_num` is the monotone per-block counter (from `Anchors.block_num`); it
        uniquely indexes this block in the chain. `first_height` is the log-idx the FIRST
        tx would land at (whether or not there is one). `block_bytes` is opaque here.
        `block_hash` is the sig-independent chain identity (SettledBlock.block_hash).

        Runs inside the writer transaction already opened by `Store.write()` -- the
        caller's `with` scope commits or rolls back around this call.

        IDEMPOTENT ON REDUNDANT-COMMIT. Coordinator and Follower can both reach
        "commit block N" when their timings race. Both have the same block bytes and
        same hash (both saw the same consensus outcome), so committing twice is the
        safe no-op case. A DIFFERENT hash at the same block_num is a fork and raises."""
        existing = self._conn.execute(
            "SELECT hash FROM block WHERE block_num=?", (block_num,)
        ).fetchone()
        if existing is not None:
            if existing[0] == block_hash:
                return Applied(settled=(), dropped=())
            raise InvariantError(
                f"fork at block_num={block_num}: existing hash "
                f"{crypto.Digest(existing[0]).hex()[:8]} != new {block_hash.hex()[:8]}"
            )
        applied = self._apply_within(batch, auth)
        height = self.head()
        self._conn.execute(
            "INSERT INTO block (block_num, first_height, height, bytes, hash) VALUES (?,?,?,?,?)",
            (block_num, first_height, height, block_bytes, block_hash),
        )
        return applied

    def _apply_within(
        self, batch: tuple[ops.SignedTransaction, ...], auth: settle.Authoriser
    ) -> Applied:
        """Settle the batch inside the current writer transaction (caller owns BEGIN/COMMIT)."""
        settled: list[tuple[Index, crypto.Digest]] = []
        dropped: list[Dropped] = []
        already = self._settled_hashes(tuple(tx.op_hash for tx in batch))
        acc = self.accumulator()
        idx = self.head()
        for tx in batch:
            if tx.op_hash in already:
                dropped.append(Dropped(tx.op_hash, settle.Reason.SETTLED))
                continue
            verdict, layer = settle.evaluate(self, tx, auth)
            if (why := verdict.why) is not None:
                dropped.append(Dropped(tx.op_hash, why))
                continue
            idx += 1
            acc = self._commit(idx, tx, layer.mutations, acc)
            settled.append((idx, tx.op_hash))
        self._set_meta("acc", acc)
        return Applied(tuple(settled), tuple(dropped))

    def replay(self, items: Iterable[Entry], expect: Commitment | None = None) -> str | None:
        """Apply already-settled entries at their recorded indices, without re-adjudicating.
        See the pre-split docstring for the full rationale (#replay-does-not-readjudicate)."""
        acc = self.accumulator()
        for e in items:
            if (why := _unverified(e)) is not None:
                # Caller's `with store.write()` scope will re-raise our exception if we raise --
                # but a bad replay signature is THEIR fault (routine outcome), so we return the
                # reason and expect the caller to rollback by raising or by explicit contract.
                raise _ReplayRefusedError(why)
            acc = self._commit(e.idx, e.item, e.item.txn.mutations, acc)
        self._set_meta("acc", acc)
        if (why := self._unacceptable(expect)) is not None:
            raise _ReplayRefusedError(why)
        self._remember_roster_serial()
        return None

    def _unacceptable(self, expect: Commitment | None) -> str | None:
        """Everything judged AFTER a run is applied and BEFORE it is committed."""
        if (
            expect is not None
            and self.head() == expect.head
            and (why := self._disagrees(expect)) is not None
        ):
            return why
        if self.anchor() is None:
            return None
        for why in (self.wrong_cluster(), self.unvouched_roster(), self.roster_incomplete()):
            if why is not None:
                return f"refusing a log this node's anchor does not authorise: {why}"
        return None

    def _disagrees(self, expect: Commitment) -> str | None:
        """`None` if every commitment agrees, else which one did not."""
        for what, mine, theirs in (
            ("state", self.accumulator(), expect.acc_state),
            ("log", self.log_accumulator(), expect.acc_log),
            ("root", self.state_root(), expect.root),
        ):
            if mine != theirs:
                return (
                    f"transferred log disagrees with the sender's signed {what} "
                    f"at height {expect.head}"
                )
        return None

    def _commit(
        self,
        idx: Index,
        tx: ops.SignedTransaction,
        mutations: tuple[ops.Mutation, ...],
        acc: crypto.Accumulator,
    ) -> crypto.Accumulator:
        """Append one transaction at `idx` and fold `mutations` into the live view and `acc`."""
        cred = tx.raw
        self._conn.execute(
            "INSERT INTO entry (idx, op_hash, raw, author, ts) VALUES (?,?,?,?,?)",
            (idx, tx.op_hash, tx.raw, tx.author, tx.ts),
        )
        self._log_add(idx, tx.op_hash)
        for m in mutations:
            cur = self.get(m.store, m.name)
            if cur:
                acc = crypto.acc_sub(acc, element(m.store, m.name, cur[1]))
            path = smt.path_of(m.store, m.name)
            self._tree.invalidate(path)
            if isinstance(m, ops.Set):
                self._conn.execute(
                    "INSERT OR REPLACE INTO live (store, name, head, value, path, epoch, cred)"
                    " VALUES (?,?,?,?,?,?,?)",
                    (m.store, m.name, idx, m.value, path, m.epoch, cred),
                )
                acc = crypto.acc_add(acc, element(m.store, m.name, m.value))
            else:
                self._conn.execute("DELETE FROM live WHERE store=? AND name=?", (m.store, m.name))
        return acc


class _ReplayRefusedError(Exception):
    """Internal signal used inside `StoreWriter.replay` to short-circuit the transaction
    with a returnable reason. Caught in `Store.replay`'s convenience wrapper, converted
    back to a string return; the writer's `with` scope rolls back on the exception."""

    def __init__(self, why: str):
        super().__init__(why)
        self.why = why


# ============================================================================= #
# Store -- facade owning both connections and providing scopes + shortcuts.     #
# ============================================================================= #


class Store:
    """The log plus its derived view, on SQLite. Owns two connections to one DB:
    a writer (serialised via `_writer_lock`) and a per-snapshot fresh reader.

    Callers use scopes explicitly for anything that composes multiple reads or writes:
        with store.snapshot() as r:      # snapshot-consistent reads across the scope
            v1 = r.get(...); v2 = r.roster()
        with store.write() as w:         # exclusive write transaction
            w.commit_block(...)

    For one-shot calls, Store keeps convenience wrappers that internally open a scope --
    `store.get(...)`, `store.head_block_num()`, `store.commit_block(...)`, etc. Every
    existing caller keeps working."""

    def __init__(self, path: str = ":memory:"):
        # For `path == ":memory:"` we back the store with a temp file that gets deleted on
        # close. Two reasons the naive `sqlite3.connect(":memory:")` fails us:
        #   * Each `sqlite3.connect(":memory:")` opens a NEW empty DB -- the writer and
        #     each reader would see different DBs.
        #   * `PRAGMA journal_mode=WAL` is silently downgraded on `:memory:`, so there's
        #     no snapshot isolation across connections.
        # The obvious alternative -- `file:name?mode=memory&cache=shared` -- shares the DB
        # across connections but reverts to shared-cache locking semantics: a writer
        # holding BEGIN IMMEDIATE blocks any concurrent reader with `database table is
        # locked`. That's the opposite of what we need.
        # A tempfile gives real WAL, real snapshot isolation, real cross-connection
        # sharing, and cleans up on close(). Perf overhead is tiny for the test sizes we
        # care about (~1 ms per Store construction).
        self._tempfile_path: str | None = None
        if path == ":memory:":
            fd, self._tempfile_path = tempfile.mkstemp(prefix="dude-store-", suffix=".sqlite")
            os.close(fd)
            path = self._tempfile_path
        self._conn_uri = path
        self._writer_conn = sqlite3.connect(
            self._conn_uri,
            check_same_thread=False,
            isolation_level=None,
        )
        self._writer_lock = threading.RLock()
        self._writer_conn.execute("PRAGMA journal_mode=WAL")
        self._writer_conn.execute("PRAGMA foreign_keys=ON")
        self._writer_conn.executescript(_SCHEMA)

    @property
    def db(self) -> sqlite3.Connection:
        """Compat shim for tests that read raw SQLite state directly. Production callers
        should use `store.snapshot()` / `store.write()` scopes. Returns the writer
        connection -- tests using this outside a writer scope get the last-committed
        state (they only ever do SELECTs)."""
        return self._writer_conn

    def close(self) -> None:
        """Close the writer connection and delete the backing temp file if any. Reader
        connections are per-scope and close on scope exit, so nothing lingers there.
        Idempotent."""
        with contextlib.suppress(sqlite3.Error):
            self._writer_conn.close()
        if self._tempfile_path is not None:
            for suffix in ("", "-wal", "-shm"):
                with contextlib.suppress(OSError):
                    os.unlink(self._tempfile_path + suffix)
            self._tempfile_path = None

    def __del__(self) -> None:
        # Best-effort cleanup for callers that don't call close(). SQLite finalizers
        # will close the connection anyway; the tempfile removal is what this catches.
        with contextlib.suppress(Exception):
            self.close()

    # -- scopes -------------------------------------------------------------- #

    def _open_reader_conn(self) -> sqlite3.Connection:
        conn = sqlite3.connect(
            self._conn_uri,
            check_same_thread=False,
            isolation_level=None,
        )
        conn.execute("PRAGMA foreign_keys=ON")
        return conn

    @contextmanager
    def snapshot(self) -> Iterator[StoreReader]:
        """A snapshot-consistent read scope. Opens a FRESH reader connection, opens a
        transaction, and PINS the snapshot via a trivial SELECT before yielding --
        SQLite's default `BEGIN` is deferred, meaning the snapshot only starts at the
        first read. Doing that first read here means the caller's later reads inside the
        scope all see the state as of `snapshot()` entry, not as of "first caller read"
        (which is fragile: any commit in that window would move the snapshot).

        Different threads calling `snapshot()` simultaneously each get their own
        independent connection and their own snapshot via WAL isolation. Connection
        closes on scope exit."""
        conn = self._open_reader_conn()
        try:
            conn.execute("BEGIN")
            # Force snapshot acquisition NOW, not at first user read. A cheap read
            # against a table that always exists (meta) is enough -- SQLite pins the
            # WAL frame at this point.
            conn.execute("SELECT 1 FROM meta LIMIT 0").fetchone()
            try:
                yield StoreReader(conn)
                conn.execute("COMMIT")
            except Exception:
                conn.execute("ROLLBACK")
                raise
        finally:
            conn.close()

    @contextmanager
    def write(self) -> Iterator[StoreWriter]:
        """The exclusive write transaction. Acquires the writer lock, opens `BEGIN
        IMMEDIATE` on the writer connection, yields a StoreWriter, COMMITs on success or
        ROLLBACKs on exception. Only one writer at a time -- SQLite's own constraint,
        made explicit through the lock."""
        with self._writer_lock:
            self._writer_conn.execute("BEGIN IMMEDIATE")
            try:
                yield StoreWriter(self._writer_conn)
                self._writer_conn.execute("COMMIT")
            except Exception:
                self._writer_conn.execute("ROLLBACK")
                raise

    # -- convenience one-shot reads (preserve every existing call site) ------ #

    def get(self, store: int, name: bytes) -> Held | None:
        with self.snapshot() as r:
            return r.get(store, name)

    def prefix(self, store: int, pre: bytes) -> Iterator[Row]:
        # `prefix` yields; materialize inside the scope so results outlive it.
        with self.snapshot() as r:
            yield from list(r.prefix(store, pre))

    def head(self) -> Index:
        with self.snapshot() as r:
            return r.head()

    def entries(self, frm: Index = 1, to: Index | None = None) -> Iterator[Entry]:
        with self.snapshot() as r:
            yield from list(r.entries(frm, to))

    def settled_at(self, block_num: Index) -> bytes | None:
        with self.snapshot() as r:
            return r.settled_at(block_num)

    def bodies_of_block(self, block_num: Index) -> tuple[ops.SignedTransaction, ...]:
        with self.snapshot() as r:
            return r.bodies_of_block(block_num)

    def head_block_hash(self) -> crypto.Digest | None:
        with self.snapshot() as r:
            return r.head_block_hash()

    def head_block_num(self) -> Index | None:
        with self.snapshot() as r:
            return r.head_block_num()

    def credential(self, store: int, name: bytes) -> bytes:
        with self.snapshot() as r:
            return r.credential(store, name)

    def accumulator(self) -> crypto.Accumulator:
        with self.snapshot() as r:
            return r.accumulator()

    def log_accumulator(self) -> crypto.Accumulator:
        with self.snapshot() as r:
            return r.log_accumulator()

    def state_root(self) -> crypto.Digest:
        with self.snapshot() as r:
            return r.state_root()

    def hash_under(self, prefix: bytes, depth: int) -> crypto.Digest:
        with self.snapshot() as r:
            return r.hash_under(prefix, depth)

    def prove(self, store: int, name: bytes) -> smt.Proof:
        with self.snapshot() as r:
            return r.prove(store, name)

    def anchor(self) -> crypto.PublicKey | None:
        with self.snapshot() as r:
            return r.anchor()

    def seeds(self) -> tuple[bytes, ...]:
        with self.snapshot() as r:
            return r.seeds()

    def roster_serial(self) -> int:
        with self.snapshot() as r:
            return r.roster_serial()

    def wrong_cluster(self) -> str | None:
        with self.snapshot() as r:
            return r.wrong_cluster()

    def unvouched_roster(self) -> str | None:
        with self.snapshot() as r:
            return r.unvouched_roster()

    def roster_incomplete(self) -> str | None:
        with self.snapshot() as r:
            return r.roster_incomplete()

    def holds(self, pred: ops.Predicate) -> bool:
        with self.snapshot() as r:
            return r.holds(pred)

    def _rows_in_path_range(
        self, lo: bytes, hi: bytes
    ) -> Iterator[tuple[int, bytes, bytes, bytes]]:
        # Called by Layer over Store as base -- must yield real rows, so materialize.
        with self.snapshot() as r:
            yield from list(r._rows_in_path_range(lo, hi))  # noqa: SLF001

    def _settled_hashes(self, want: tuple[crypto.Digest, ...]) -> set[bytes]:
        # Called by Coordinator when previewing a slice.
        with self.snapshot() as r:
            return r._settled_hashes(want)  # noqa: SLF001

    @property
    def is_frozen(self) -> bool:
        """Store implements View for callers that construct `Layer(store)` -- a Store,
        by test discipline, is not mutated while a Layer over it is OPEN, so from the
        Layer's perspective it is de facto frozen. When real snapshotting arrives this
        becomes a version-handle check; today it is a constant."""
        return True

    @property
    def mgmt(self) -> Management:
        """A Management view over this store. Convenience for read-only mgmt calls
        (`store.mgmt.roster()`, `store.mgmt.grant_of(...)`). For tx composition
        (change_roster, authorise, etc.) with snapshot consistency, use
        `with store.snapshot() as r: MgmtWriter(r).X(...)` explicitly."""
        return Management(self)

    # -- convenience one-shot writes ----------------------------------------- #

    def apply(self, batch: tuple[ops.SignedTransaction, ...], auth: settle.Authoriser) -> Applied:
        with self.write() as w:
            return w.apply(batch, auth)

    def commit_block(  # noqa: PLR0913
        self,
        block_num: Index,
        *,
        first_height: Index,
        block_bytes: bytes,
        block_hash: crypto.Digest,
        batch: tuple[ops.SignedTransaction, ...],
        auth: settle.Authoriser,
    ) -> Applied:
        with self.write() as w:
            return w.commit_block(
                block_num,
                first_height=first_height,
                block_bytes=block_bytes,
                block_hash=block_hash,
                batch=batch,
                auth=auth,
            )

    def provision(self, manager: crypto.PublicKey, seeds: Iterable[bytes] = ()) -> None:
        with self.write() as w:
            w.provision(manager, seeds)

    def replay(self, items: Iterable[Entry], expect: Commitment | None = None) -> str | None:
        """See `StoreWriter.replay`. Returns the refusal reason or None on success."""
        try:
            with self.write() as w:
                w.replay(items, expect)
        except _ReplayRefusedError as e:
            return e.why
        return None

    def rebuild(self) -> Store:
        """A fresh store holding the same log, replayed from scratch into a new database.
        The invariant made checkable: `applying entries incrementally == replaying the log
        from scratch`."""
        fresh = Store(":memory:")
        fresh.replay(list(self.entries()))
        return fresh
