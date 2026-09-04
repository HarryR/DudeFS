from __future__ import annotations

import contextlib
import os
import sqlite3
import tempfile
import threading
from collections.abc import Generator, Iterable, Iterator
from contextlib import contextmanager
from dataclasses import dataclass
from typing import NamedTuple

from ..core import codec, crypto
from ..core.errors import InvariantError
from ..session import Session, Settled
from . import ops, settle, smt
from .layer import Held, Index, Ledger, PathRow, View, element, holds, log_element
from .management import MgmtReader, MgmtWriter
from .smt_sync import _ExportSource, _ImportTarget

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
    value  BLOB NOT NULL,
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

-- Persisted checkpoint artifact. Row 0 = CheckpointMeta.encode(). Rows 1..N = bencoded
-- chunks in TreeExporter walk order. Replaced atomically when a new checkpoint is created.
CREATE TABLE IF NOT EXISTS checkpoint (
    seq  INTEGER PRIMARY KEY,
    data BLOB NOT NULL
);

"""


@dataclass(frozen=True, slots=True)
class Entry:
    idx: Index
    item: ops.LogEntry


class Commitment(NamedTuple):
    head: Index
    acc_state: crypto.Accumulator
    acc_log: crypto.Accumulator
    root: crypto.Digest


class Dropped(NamedTuple):
    op_hash: crypto.Digest
    why: settle.Reason


@dataclass(frozen=True, slots=True)
class Applied:
    settled: tuple[tuple[Index, crypto.Digest], ...]
    dropped: tuple[Dropped, ...]


def _unverified(e: Entry) -> str | None:
    if isinstance(e.item, ops.SignedTransaction) and not e.item.verify():
        return f"entry {e.idx} does not verify"
    return None


class StoreReader(View, Ledger, _ExportSource):
    _memoize: bool = False

    def __init__(self, conn: sqlite3.Connection):
        self._conn = conn
        self._tree = smt.Tree(conn, memoize=self._memoize)

    def get(self, store: int, name: bytes) -> Held | None:
        row = self._conn.execute(
            "SELECT value, epoch, cred FROM live WHERE store=? AND name=?", (store, name)
        ).fetchone()
        return Held(row[0], row[1], row[2]) if row else None

    def accumulator(self) -> crypto.Accumulator:
        return crypto.Accumulator(self._get_meta("acc", crypto.ACC_IDENTITY))

    def log_accumulator(self) -> crypto.Accumulator:
        return crypto.Accumulator(self._get_meta("acc_log", crypto.ACC_IDENTITY))

    def state_root(self) -> crypto.Digest:
        return self._tree.root()

    def hash_under(self, prefix: bytes, depth: int) -> crypto.Digest:
        return self._tree.hash_under(prefix, depth)

    def prove(self, store: int, name: bytes) -> smt.Proof:
        return self._tree.prove(store, name)

    @property
    def is_frozen(self) -> bool:
        return True

    def holds(self, pred: ops.Predicate) -> bool:
        return holds(self, pred)

    def head(self) -> Index:
        row = self._conn.execute("SELECT MAX(idx) FROM entry").fetchone()
        if row[0] is not None:
            return row[0]
        floor = self._get_meta("head_floor", b"")
        return int.from_bytes(floor, "big") if floor else 0

    def entries(self, frm: Index = 1, to: Index | None = None) -> Iterator[Entry]:
        hi = self.head() if to is None else to
        rows = self._conn.execute(
            "SELECT idx, raw FROM entry WHERE idx BETWEEN ? AND ? ORDER BY idx", (frm, hi)
        ).fetchall()
        for idx, raw in rows:
            yield Entry(idx, ops.SignedTransaction.decode(raw))

    def settled_at(self, block_num: Index) -> bytes | None:
        row = self._conn.execute(
            "SELECT bytes FROM block WHERE block_num=?", (block_num,)
        ).fetchone()
        return bytes(row[0]) if row else None

    def bodies_of_block(self, block_num: Index) -> tuple[ops.SignedTransaction, ...]:
        row = self._conn.execute(
            "SELECT first_height, height FROM block WHERE block_num=?", (block_num,)
        ).fetchone()
        if row is None:
            return ()
        first_height, height = row
        if first_height > height:
            return ()
        return tuple(e.item for e in self.entries(first_height, height))

    def oldest_block_num(self) -> Index | None:
        row = self._conn.execute("SELECT MIN(block_num) FROM block").fetchone()
        return row[0] if row and row[0] is not None else None

    def head_block_hash(self) -> crypto.Digest | None:
        row = self._conn.execute(
            "SELECT hash FROM block ORDER BY block_num DESC LIMIT 1"
        ).fetchone()
        return crypto.Digest(bytes(row[0])) if row else None

    def head_block_num(self) -> Index | None:
        row = self._conn.execute("SELECT MAX(block_num) FROM block").fetchone()
        return row[0] if row and row[0] is not None else None

    def checkpoint_meta_bytes(self) -> bytes | None:
        row = self._conn.execute(
            "SELECT data FROM checkpoint WHERE seq = 0",
        ).fetchone()
        return bytes(row[0]) if row else None

    def checkpoint_chunk_count(self) -> int:
        row = self._conn.execute(
            "SELECT COUNT(*) FROM checkpoint WHERE seq > 0",
        ).fetchone()
        return row[0]

    def checkpoint_chunks(self, offset: int, limit: int) -> tuple[bytes, ...]:
        rows = self._conn.execute(
            "SELECT data FROM checkpoint WHERE seq > ? ORDER BY seq LIMIT ?",
            (offset, limit),
        ).fetchall()
        return tuple(bytes(r[0]) for r in rows)

    def credential(self, store: int, name: bytes) -> bytes:
        row = self._conn.execute(
            "SELECT cred FROM live WHERE store=? AND name=?", (store, name)
        ).fetchone()
        return row[0] if row else b""

    def anchor(self) -> crypto.PublicKey:
        raw = self._get_meta("anchor", b"")
        if not raw:
            raise InvariantError("store has no anchor")
        return crypto.PublicKey(raw)

    def seeds(self) -> tuple[bytes, ...]:
        raw = self._get_meta("seeds", b"")
        return tuple(codec.as_bytes(a) for a in codec.as_seq(codec.decode(raw))) if raw else ()

    def roster_serial(self) -> int:
        return int.from_bytes(self._get_meta("roster_serial", b""))

    def _get_meta(self, k: str, default: bytes) -> bytes:
        row = self._conn.execute("SELECT v FROM meta WHERE k=?", (k,)).fetchone()
        return row[0] if row else default

    def subtree_data_size(self, prefix: bytes, depth: int) -> int:
        lo, hi = smt.bounds(prefix, depth)
        row = self._conn.execute(
            "SELECT COALESCE(SUM(LENGTH(value) + LENGTH(cred)), 0)"
            " FROM live WHERE path BETWEEN ? AND ?",
            (lo, hi),
        ).fetchone()
        return row[0]

    def subtree_rows(self, prefix: bytes, depth: int) -> tuple[PathRow, ...]:
        lo, hi = smt.bounds(prefix, depth)
        return tuple(self.rows_in_path_range(lo, hi))

    def rows_in_path_range(self, lo: bytes, hi: bytes) -> Iterator[PathRow]:
        rows = self._conn.execute(
            "SELECT store, name, value, cred, epoch FROM live"
            " WHERE path BETWEEN ? AND ? ORDER BY path",
            (lo, hi),
        ).fetchall()
        for st, name, value, cred, epoch in rows:
            yield PathRow(int(st), name, value, cred, int(epoch))

    def has_settled(self, *op_hashes: crypto.Digest) -> frozenset[crypto.Digest]:
        if not op_hashes:
            return frozenset()
        marks = ",".join("?" * len(op_hashes))
        rows = self._conn.execute(
            f"SELECT op_hash FROM entry WHERE op_hash IN ({marks})",  # noqa: S608
            op_hashes,
        ).fetchall()
        return frozenset(r[0] for r in rows)

    def settlement_of(self, op_hash: crypto.Digest) -> Settled | None:
        row = self._conn.execute(
            "SELECT b.block_num, b.hash FROM entry e"
            " JOIN block b ON e.idx BETWEEN b.first_height AND b.height"
            " WHERE e.op_hash = ?",
            (op_hash,),
        ).fetchone()
        if row is None:
            return None
        return Settled(op_hash, row[0], crypto.Digest(bytes(row[1])))

    @property
    def mgmt_reader(self) -> MgmtReader:
        return MgmtReader(Session(self, ops.STORE_MANAGEMENT))


class StoreWriter(StoreReader, _ImportTarget):
    _memoize: bool = True

    def _set_meta(self, k: str, v: bytes) -> None:
        self._conn.execute("INSERT OR REPLACE INTO meta VALUES (?,?)", (k, v))

    def _log_add(self, idx: Index, op_hash: crypto.Digest) -> None:
        self._set_meta("acc_log", crypto.acc_add(self.log_accumulator(), log_element(idx, op_hash)))

    def _remember_roster_serial(self) -> None:
        if not self._get_meta("anchor", b""):
            return
        commitment = self.mgmt_reader.roster_commitment()
        if commitment is not None and commitment.serial > self.roster_serial():
            self._set_meta("roster_serial", commitment.serial.to_bytes(8))

    def provision(self, manager: crypto.PublicKey, seeds: Iterable[bytes] = ()) -> None:
        raw = self._get_meta("anchor", b"")
        if raw and crypto.PublicKey(raw) != manager:
            raise InvariantError(
                "this node is provisioned to a different manager; re-provisioning would move it "
                "between clusters while keeping its identity and its attested height"
            )
        self._set_meta("anchor", manager)
        if seeds:
            self._set_meta("seeds", codec.encode(sorted(seeds)))

    def persist_checkpoint(self, meta_bytes: bytes, chunk_blobs: tuple[bytes, ...]) -> None:
        self._conn.execute("DELETE FROM checkpoint")
        self._conn.execute(
            "INSERT INTO checkpoint (seq, data) VALUES (0, ?)",
            (meta_bytes,),
        )
        for i, blob in enumerate(chunk_blobs, 1):
            self._conn.execute(
                "INSERT INTO checkpoint (seq, data) VALUES (?, ?)",
                (i, blob),
            )
        self._set_meta("checkpoint_id", crypto.h(meta_bytes))

    def reset_for_checkpoint(self) -> None:
        self._conn.execute("DELETE FROM live")
        self._conn.execute("DELETE FROM entry")
        self._conn.execute("DELETE FROM block")
        self._conn.execute("DELETE FROM smt_memo")
        self._conn.execute("DELETE FROM meta")

    def bootstrap_checkpoint(self, anchor: crypto.PublicKey, settled_block_bytes: bytes) -> None:
        from ..consensus.settle_round import SettledBlock  # noqa: PLC0415

        sb = SettledBlock.decode(settled_block_bytes)
        a = sb.anchors
        self.provision(anchor)
        self._set_meta("acc", a.acc_state)
        self._set_meta("acc_log", a.acc_log)
        self._set_meta("head_floor", a.height.to_bytes(8, "big"))
        self._conn.execute(
            "INSERT INTO block (block_num, first_height, height, bytes, hash) VALUES (?,?,?,?,?)",
            (a.block_num, a.height + 1, a.height, settled_block_bytes, sb.block_hash),
        )

    def insert_live_row(self, row: PathRow) -> None:
        path = smt.path_of(row.store, row.name)
        self._tree.invalidate(path)
        self._conn.execute(
            "INSERT OR REPLACE INTO live (store, name, value, epoch, path, cred)"
            " VALUES (?,?,?,?,?,?)",
            (row.store, row.name, row.value, row.epoch, path, row.credential),
        )

    def gc_below(self, pivot_block_num: Index) -> int:
        row = self._conn.execute(
            "SELECT first_height FROM block WHERE block_num=?", (pivot_block_num,)
        ).fetchone()
        if row is None:
            return 0
        first_height = row[0]
        cur = self._conn.execute("DELETE FROM entry WHERE idx < ?", (first_height,))
        entries_deleted = cur.rowcount
        self._conn.execute("DELETE FROM block WHERE block_num < ?", (pivot_block_num,))
        return entries_deleted

    def apply(self, batch: tuple[ops.SignedTransaction, ...], auth: settle.Authoriser) -> Applied:
        return self._apply_within(batch, auth)

    def commit_block(
        self,
        block_num: Index,
        *,
        first_height: Index,
        block_bytes: bytes,
        block_hash: crypto.Digest,
        batch: tuple[ops.SignedTransaction, ...],
        auth: settle.Authoriser,
    ) -> Applied:
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
        settled: list[tuple[Index, crypto.Digest]] = []
        dropped: list[Dropped] = []
        already = set(self.has_settled(*(tx.op_hash for tx in batch)))
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
            # Into the dedup set NOW, not just the pre-loop snapshot: acceptors cannot screen
            # bodies, so a proposer duplicating a tx WITHIN one block otherwise reached
            # `entry.op_hash UNIQUE` and crashed every honest applier with the same
            # sqlite3.IntegrityError -- not a DudeError -- in a restart loop, since the block
            # re-arrives on sync.
            already.add(tx.op_hash)
        self._set_meta("acc", acc)
        return Applied(tuple(settled), tuple(dropped))

    def replay(self, items: Iterable[Entry]) -> None:
        acc = self.accumulator()
        for e in items:
            if (why := _unverified(e)) is not None:
                raise _ReplayRefusedError(why)
            acc = self._commit(e.idx, e.item, e.item.txn.mutations, acc)
        self._set_meta("acc", acc)
        self._remember_roster_serial()

    def _commit(
        self,
        idx: Index,
        tx: ops.SignedTransaction,
        mutations: tuple[ops.Mutation, ...],
        acc: crypto.Accumulator,
    ) -> crypto.Accumulator:
        cred = tx.raw
        self._conn.execute(
            "INSERT INTO entry (idx, op_hash, raw, author, ts) VALUES (?,?,?,?,?)",
            (idx, tx.op_hash, tx.raw, tx.author, tx.ts),
        )
        self._log_add(idx, tx.op_hash)
        for m in mutations:
            cur = self.get(m.store, m.name)
            if cur:
                acc = crypto.acc_sub(acc, element(m.store, m.name, cur.value, cur.epoch))
            path = smt.path_of(m.store, m.name)
            self._tree.invalidate(path)
            if isinstance(m, ops.Set):
                self._conn.execute(
                    "INSERT OR REPLACE INTO live (store, name, value, path, epoch, cred)"
                    " VALUES (?,?,?,?,?,?)",
                    (m.store, m.name, m.value, path, m.epoch, cred),
                )
                acc = crypto.acc_add(acc, element(m.store, m.name, m.value, m.epoch))
            else:
                self._conn.execute("DELETE FROM live WHERE store=? AND name=?", (m.store, m.name))
        return acc


class _ReplayRefusedError(Exception):
    def __init__(self, why: str):
        super().__init__(why)
        self.why = why


class Store(View, Ledger):
    def __init__(self, path: str | None = None):
        self._tempfile_path: str | None = None
        if path is None:
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
        """Raw handle, for tests only. A production read outside `snapshot()` is unpinned: four
        reads can straddle a commit and produce a proof that does not verify against the root
        quoted beside it."""
        return self._writer_conn

    def close(self) -> None:
        with contextlib.suppress(sqlite3.Error):
            self._writer_conn.close()
        if self._tempfile_path is not None:
            for suffix in ("", "-wal", "-shm"):
                with contextlib.suppress(OSError):
                    os.unlink(self._tempfile_path + suffix)
            self._tempfile_path = None

    def __del__(self) -> None:
        with contextlib.suppress(Exception):
            self.close()

    def _open_reader_conn(self) -> sqlite3.Connection:
        conn = sqlite3.connect(
            self._conn_uri,
            check_same_thread=False,
            isolation_level=None,
        )
        conn.execute("PRAGMA foreign_keys=ON")
        return conn

    @contextmanager
    def snapshot(self) -> Generator[StoreReader]:
        conn = self._open_reader_conn()
        try:
            conn.execute("BEGIN")
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
    def write(self) -> Generator[StoreWriter]:
        with self._writer_lock:
            self._writer_conn.execute("BEGIN IMMEDIATE")
            try:
                yield StoreWriter(self._writer_conn)
                self._writer_conn.execute("COMMIT")
            except Exception:
                self._writer_conn.execute("ROLLBACK")
                raise

    def get(self, store: int, name: bytes) -> Held | None:
        with self.snapshot() as r:
            return r.get(store, name)

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

    def oldest_block_num(self) -> Index | None:
        with self.snapshot() as r:
            return r.oldest_block_num()

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

    def anchor(self) -> crypto.PublicKey:
        with self.snapshot() as r:
            return r.anchor()

    def seeds(self) -> tuple[bytes, ...]:
        with self.snapshot() as r:
            return r.seeds()

    def roster_serial(self) -> int:
        with self.snapshot() as r:
            return r.roster_serial()

    def holds(self, pred: ops.Predicate) -> bool:
        with self.snapshot() as r:
            return r.holds(pred)

    def rows_in_path_range(self, lo: bytes, hi: bytes) -> Iterator[PathRow]:
        with self.snapshot() as r:
            yield from list(r.rows_in_path_range(lo, hi))

    def has_settled(self, *op_hashes: crypto.Digest) -> frozenset[crypto.Digest]:
        with self.snapshot() as r:
            return r.has_settled(*op_hashes)

    def settlement_of(self, op_hash: crypto.Digest) -> Settled | None:
        with self.snapshot() as r:
            return r.settlement_of(op_hash)

    def checkpoint_meta_bytes(self) -> bytes | None:
        with self.snapshot() as r:
            return r.checkpoint_meta_bytes()

    def checkpoint_chunk_count(self) -> int:
        with self.snapshot() as r:
            return r.checkpoint_chunk_count()

    def checkpoint_chunks(self, offset: int, limit: int) -> tuple[bytes, ...]:
        with self.snapshot() as r:
            return r.checkpoint_chunks(offset, limit)

    @property
    def is_frozen(self) -> bool:
        return True

    def mgmt_session(self) -> Session:
        return Session(self, ops.STORE_MANAGEMENT)

    @property
    def mgmt_reader(self) -> MgmtReader:
        return MgmtReader(self.mgmt_session())

    @property
    def mgmt_writer(self) -> MgmtWriter:
        return MgmtWriter(self.mgmt_session())

    def apply(self, batch: tuple[ops.SignedTransaction, ...], auth: settle.Authoriser) -> Applied:
        with self.write() as w:
            return w.apply(batch, auth)

    def commit_block(
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

    def gc_below(self, pivot_block_num: Index) -> int:
        with self.write() as w:
            return w.gc_below(pivot_block_num)

    def provision(self, manager: crypto.PublicKey, seeds: Iterable[bytes] = ()) -> None:
        with self.write() as w:
            w.provision(manager, seeds)

    def replay(self, items: Iterable[Entry]) -> str | None:
        try:
            with self.write() as w:
                w.replay(items)
        except _ReplayRefusedError as e:
            return e.why
        return None

    def rebuild(self) -> Store:
        fresh = Store()
        fresh.provision(self.anchor())
        fresh.replay(list(self.entries()))
        return fresh
