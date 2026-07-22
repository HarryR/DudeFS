# HANDOFF-R5 — Storage concurrency: per-connection WAL, transactions, delete the global lock

> **From:** reviewer/planner (Opus) · **To:** implementer · **Date:** 2026-07-22 ·
> **Baseline:** `530ad9a` (296 green). Companion to **DESIGN §8** (acceptor-state durability &
> GC — "persist commitments, derive views", sign-after-fsync) and **ARCHITECTURE L2** (the store
> as a swappable black box).
>
> **This is a work order, not documentation.** It comes **before** the compaction milestone
> ([HANDOFF-R6.md](HANDOFF-R6.md)) and the CLI daemons ([HANDOFF-RX.md](HANDOFF-RX.md)) — both run
> multi-threaded over the store and are unsafe until this lands.

## 1. The problem: we bought SQLite and then fought it

`ChainStore` opens **one** connection with `check_same_thread=False` and shares it across every
thread, guarded by a **single per-daemon Python lock** (store.py:328-337; daemon.py:92,115). The
whole reason to sit on SQLite is its **extremely well-known semantics** — WAL MVCC, ACID
transactions, and SQL. The shared-connection-plus-Python-lock design throws all three away and
re-implements a worse version by hand. Three symptoms, **one root cause**:

- **(a) Data race — live bug.** The maintenance thread (`sync_once` → `gossip_round`/`adopt`/`gc`,
  daemon.py:357-376) touches the shared connection **without** the `_lock` that `serve()` holds
  (daemon.py:115). A `threading.Lock` only serializes threads that *take* it; the maintenance path
  doesn't, so it and a serving thread issue concurrent statements on one connection → torn reads,
  `sqlite3.ProgrammingError`/"database is locked", or a `commit()` from one thread flushing the
  other's half-done transaction. Latent today (tests call `sync_once` manually, single-threaded);
  active the moment `run_periodic` runs alongside `serve_forever` — i.e. normal operation.
- **(b) Read-uncommitted — self-inflicted.** WAL **already** gives snapshot isolation: concurrent
  readers each see a consistent *committed* snapshot, never a writer's uncommitted rows. But that
  is **per connection**. By sharing one connection, all threads collapse onto one transaction
  context, so a reader can see another thread's uncommitted `INSERT`/`DELETE` (dirty read). WAL was
  handing us isolation for free; the shared connection switched it off.
- **(c) Convoy → indefinite stall.** The single global lock serializes the node to **one request at
  a time**. `serve()`→`_dispatch` is local-only so each hold is brief — tolerable alone. But the
  naive fix for (a) — putting `sync_once` under the same lock — would hold it across
  `gossip_round`'s `link.request(...)` **outbound peer dial** (daemon.py:214), which blocks up to
  the timeout. A slow/dead peer would then block **every** serving thread for the dial's duration,
  possibly indefinitely. (Not a deadlock — no cycle — a convoy that stalls when the holder blocks
  on I/O.)

All three are the same mistake: **isolation and mutual exclusion belong to the database, not to a
hand-rolled Python lock over a shared handle.**

## 2. The principle

Use SQLite the way its semantics intend:
- **WAL MVCC via a reader/writer split** — one reader connection + one writer connection, each behind
  its own lock. Separate connections mean the reader always sees a committed snapshot, never the
  writer's in-flight transaction. This *is* the isolation (kills (b)) and replaces the one global
  daemon lock with per-connection locks that don't block each other (kills (c)); each connection
  touched by one thread at a time (kills (a)). No pool — throughput is low and reads are near-instant.
- **ACID transactions** are the atomic-unit primitive — `BEGIN IMMEDIATE … COMMIT` around a set of
  mutations; `BEGIN … COMMIT` around a compound read for a consistent snapshot. Database-managed, not
  a process-lifetime Python mutex.
- **Never hold a lock across network I/O** — dial peers outside any transaction (kills the (c) stall
  and the (a) race together).

## 3. Work packages

- **WP-1 — Read/write connection split (no pool), always file-backed.** At this throughput a pool is
  machinery we don't need — reads are near-instant and traffic is low — but the split earns its keep:
  a slow write (a GC that takes a second) must not block reads, and we are multi-threaded. Two
  connections:
  - **one writer connection** guarded by a **writer lock** (WAL serializes writes anyway — all
    mutations + the maintenance adopt/GC transaction go through it);
  - **one reader connection** guarded by a **reader lock** (reads serialize against each other —
    fine at this throughput; the point is they don't block behind a long write).
  - Independent locks ⟹ a read and a write run concurrently; WAL gives the reader a committed
    snapshot, never the writer's in-flight transaction. Kills **dirty reads** (separate connections)
    and the **data race** (one thread per connection).
  - **Assume multiple processes** on the same file (e.g. `node status` reading a live node's store):
    an in-process lock does **not** stop another process committing between our statements — so
    correctness rests on SQL transactions (WP-2), not the lock. Pragmas: `journal_mode=WAL`,
    `synchronous=FULL`, `busy_timeout` (cross-process writer contention retries), `wal_autocheckpoint`.
  - **Path handling** (drops the `:memory:`-breaks-two-connections problem): a **file path** → two
    connections to the file + WAL (production, durable, cross-process). **`:memory:`** →
    a shared-cache memory DB (`file:<uniq>?mode=memory&cache=shared`) so reader+writer share one
    in-memory database — keeps the existing unit tests fast and exercising the split; the concurrency
    and durable-restart tests (WP-5) use real temp files for true WAL/cross-process behavior.
  - Files: `dudefs/store.py`, `dudefs/daemon.py`, `dudefs/client.py`.
- **WP-2 — Transaction hygiene (writes atomic, compound reads snapshotted, never across I/O).**
  Three rules:
  - **Writes** → their own explicit `BEGIN IMMEDIATE … COMMIT` (IMMEDIATE takes the write lock up
    front, avoiding a mid-transaction upgrade dueling writers can't resolve); compound writes
    (adopt+GC) are **one** transaction (WP-3).
  - **Compound reads** (several SELECTs forming one logical answer) → wrap in a `BEGIN … COMMIT`
    **read transaction** so a writer committing mid-read can't tear the composite. WAL pins a
    consistent snapshot at the transaction's start. Applies to: building a gossip `Summary`
    (heads+receipts+qcs+floor+**cut+retained** must agree), `baseline_commitment`/`baseline_digest`
    over `all_ops()`, `delta()`/`_baseline_ops_for`, and the client's quorum read.
  - **Point reads** (`get_op`, `get_qc`, a single lookup) → autocommit (read-committed).
  - **Never across I/O:** `gossip_round` dials the peer **outside** any transaction/lock, gets the
    delta bytes, *then* takes the writer lock to `apply_delta`. Files: `dudefs/daemon.py`,
    `dudefs/store.py`, `dudefs/client.py`.
- **WP-3 — Atomic units as transactions.** `adopt_checkpoint` + `gc_checkpoint` become **one**
  transaction (adopt-before-GC, made atomic). Manager log+view update (the crash-consistency WP-0
  of R6 needs) is one transaction — so R6-WP-0 gets its atomicity **for free** from SQLite here.
  Files: `dudefs/store.py`, `dudefs/daemon.py`.
- **WP-4 — Move locking into the store; delete the global daemon lock.** The reader/writer locks
  live **inside** `ChainStore` (one per connection), so the store owns its own serialization and
  every caller is safe by construction. Remove `NodeDaemon._lock`/`ClientDaemon._lock` as the *store*
  serializer and the misleading store.py:331-332 comment. Keep a **narrow** lock only for
  genuinely-in-process non-store state that isn't in SQLite (e.g. the client's chain-head counter),
  scoped to that. Files: `dudefs/store.py`, `dudefs/daemon.py`, `dudefs/client.py`,
  `dudefs/workerapi.py`.
- **WP-5 — Reproduce-then-fix concurrency tests** (the gate). Tests that, on the current code,
  trigger: (a) the maintenance/serve race (a torn/`ProgrammingError` under a tick overlapping a
  request), (b) a dirty read (a reader observing an uncommitted write), (c) the stall (a serve
  blocked behind a maintenance dial to a dead peer). Green after WP-1-4. These use **real temp
  files** (true WAL). The regression gate and the reproductions R6 finding #3 asks for.
- **WP-6 — Persistence, wired and proven.** Today every daemon defaults to `:memory:`, so a restart
  re-syncs from genesis — persistence is *supported by the store but unwired*. Give the daemons a
  **file-backed** store (a `--dir/store.sqlite` path; the CLI serve verbs pass it, but the durability
  itself belongs here), and add a **durable-restart test**: write, kill, reopen the *same* path,
  assert the node resumes from disk and only catches up the delta it missed — never re-folds from
  day 0. This is what makes "ultra-durable" real. Files: `dudefs/daemon.py`, `dudefs/client.py`,
  tests.

**Store API (implementation shape) — EXPLICIT transactions, no magic.** The read/write operations
live on a transaction object the caller opens and passes; no decorators, no thread-locals, no
implicit routing. This is the idiomatic data-layer shape and maps 1:1 to Rust (`rusqlite::Transaction`)
and Go (`*sql.Tx`).

- `with store.write_txn() as tx: …` — writer lock + `BEGIN IMMEDIATE`; `COMMIT` on exit (`ROLLBACK` on
  exception). `tx` is a `_WriteTxn` exposing reads **and** writes on the writer connection, so an
  acceptor RMW —`tx.get_slot()`→decide→`tx.write_slot()`, and for a receipt `sign` + `tx.put_receipt()`—
  is one atomic, cross-process-isolated transaction. The signed artifact is returned **after** the
  block commits (sign-after-fsync). Replaces the acceptor's `store.commit()`.
- `with store.read_txn() as tx: …` — reader lock + `BEGIN` snapshot; `tx` is a `_Txn` exposing reads on
  the reader connection, for a compound read (`build_summary(tx)`, `baseline_digest`, `delta`).
- Read vs write is **structural** — reads on `_Txn`, writes on `_WriteTxn(_Txn)` — decided once by
  placement, never re-judged per call (the bug the earlier decorator approach kept hitting).
- Every store call site wraps in one of the two; the repetition is deliberate and visible. A later
  DAO / data-layer consolidation of recurring patterns is a *secondary* win, not part of R5.

## 4. Scope / affected components

`dudefs/store.py` (connection model, transaction helpers), `dudefs/daemon.py` (`NodeDaemon`:
lock/threads, the `gossip_round` I/O-vs-transaction split, the adopt+GC transaction), `dudefs/client.py`
(`ClientDaemon`: same shared-connection + background-refresh-thread pattern), `dudefs/workerapi.py`
(worker threads over the client store), and — via R6-WP-0 — the manager once it moves onto `ChainStore`.

## 5. Relationship to the other milestones

- **R5 is the storage foundation.** Land it first.
- **R6 (compaction)** keeps only the compaction-**logic** concurrency in its WP-F — cut-dominance
  guard (#4), checkpoint-QC verification (#5), compactor serialization (#6), dead-delta ordering
  (#10). The connection/lock/transaction model — finding #3 and the dirty-read/stall — lives **here**.
- **RX (CLI daemons)** run `run_periodic` alongside serving; they are only safe on top of R5.

## 6. Design note

The obvious minimal alternative — keep one shared connection but make **every** access take the one
lock and never hold it across I/O — would fix (a) and (c) and, by strict serialization, avoid (b)
too. It is rejected: it keeps zero read-concurrency and re-implements, in Python, the isolation WAL
already provides in C. The point of choosing SQLite was its semantics; WP-1-3 use them.

## 7. Portability (Rust / Go)

The design is deliberately portable — a hard requirement, since the fold/protocol are heading toward
Rust/Go reimplementations. The **semantics** live in libsqlite3 (WAL MVCC, single-writer,
read-committed via short transactions), identical across every binding; the **structure** (a
reader connection + a writer connection, each behind its own lock, never held across I/O) is trivial
in all three:

- **Go** — two `*sql.DB` handles (or two `*sql.Conn`), a write handle at `SetMaxOpenConns(1)` and a
  read-only handle; `database/sql` serializes each. `busy_timeout`/WAL via DSN; works with
  `mattn/go-sqlite3` or pure-Go `modernc.org/sqlite`.
- **Rust** — two `Mutex<rusqlite::Connection>` (reader, writer); `Connection` is `Send`; the borrow
  checker makes "never hold the guard across I/O/await" a **compile-time** property, not a review rule.
- **Portability rule for the Python implementation:** drive transactions **explicitly**
  (`BEGIN IMMEDIATE` / `COMMIT`, `BEGIN` for compound reads), never leaning on Python `sqlite3`'s
  implicit-BEGIN `isolation_level` magic — explicit control maps 1:1 onto `rusqlite`/`database/sql`.
  (Aside: Python's GIL means serialized reads don't cost us true parallelism we'd otherwise have —
  SQLite releases the GIL during C calls so I/O concurrency still works — whereas Rust/Go get real
  parallelism. The design is *conservative* in Python and scales strictly better under reimplementation.)
