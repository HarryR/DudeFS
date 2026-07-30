# dude.store.store — the log and the derived view, on SQLite. See SPEC.md (#settlement).
#
# TWO COMPONENTS, ONE DATABASE (#one-write-vocabulary). They are separate in interface — the
# log is a
# sequence, the store is derived state — and share one SQLite file because a settlement must
# append entries, update chain pointers, update the live view and update the accumulator
# ATOMICALLY. That single transaction is what makes "only the log is authoritative"
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
from ..core.errors import DudeError, InvariantError
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
    -- The signed transaction that authorised `value`, for EVERY row. NO DEFAULT: the state root
    -- commits to it (`smt.leaf_hash`), so a row without one is not a row this system has, and an
    -- INSERT that forgets it must fail rather than quietly produce an unauthenticated leaf.
    cred   BLOB NOT NULL,
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


def _unverified(e: Entry) -> str | None:
    """`None` if this replayed entry carries a good signature, else why not.

    Self-contained and always checkable, so there is never an excuse to skip it — unlike its
    predicates (#replay-does-not-readjudicate). A bad signature in a transferred run is THEIR
    fault, so it is returned rather than raised, like every other refusal on that path."""
    if isinstance(e.item, ops.SignedTransaction) and not e.item.verify():
        return f"entry {e.idx} does not verify"
    return None


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
        """The highest settled index, or the adopted height if state was taken without the log.

        `MAX(idx)` ALONE IS WRONG AFTER A BOOTSTRAP. A node that took state against a checkpoint's
        root holds no entries at all, so the log's maximum is zero while the state it holds is the
        state at the checkpoint's height. Reporting zero would say it is behind the frontier for
        ever, and it would bootstrap again on every round — the walk would succeed and change
        nothing.

        The adopted height is durable and monotone, and it is only ever set once the walk has been
        CORROBORATED against the same checkpoint's fold (`Store.adopted_at`)."""
        row = self.db.execute("SELECT MAX(idx) FROM entry").fetchone()
        return max(row[0] or 0, self.adopted_height())

    def adopted_height(self) -> Index:
        """The height this node's state was taken AT, if it was taken rather than replayed."""
        return int.from_bytes(self._get_meta("adopted_height", b""))

    def adopted_at(self, ck: ops.Compaction) -> str | None:
        """Declare this node to be at `ck`, having verified it holds exactly what `ck` commits to.

        THE CORROBORATION IS THE WHOLE POINT, and it is cheap: the fold is O(1) and already signed,
        so "the walk's queue emptied" becomes "the state I hold is the state that was committed".
        Without it, a walk that lost replies — or was steered into asking for nothing — finishes
        looking exactly like one that succeeded.

        `A_log` is ADOPTED here rather than computed, because a joiner cannot compute it: it is a
        fold over every entry ever, minus what has been collected, and this node held none of them.
        That is why the ratified marker carries it (#accumulators)."""
        if self.accumulator() != ck.acc_state:
            return "the state walked does not match the fold the quorum signed"
        if self.state_root() != ck.root:
            return "the state walked does not match the root the quorum signed"
        if ck.height <= self.adopted_height():
            return None  # already at or past it; adoption is monotone, never a step back
        self._set_meta("adopted_height", ck.height.to_bytes(8))
        self._set_meta("acc_log", ck.acc_log)
        return None

    def entries(self, frm: Index = 1, to: Index | None = None) -> Iterator[Entry]:
        """Replay range, inclusive. The only way anyone derives state
        (#replay-does-not-readjudicate)."""
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
            "SELECT head, value, epoch, cred FROM live WHERE store=? AND name=?", (store, name)
        ).fetchone()
        return Held(row[0], row[1], row[2], row[3]) if row else None

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
        already = self._settled_hashes(tuple(tx.op_hash for tx in batch))
        self.db.execute("BEGIN IMMEDIATE")
        try:
            acc = self.accumulator()
            idx = self.head()
            for tx in batch:
                if tx.op_hash in already:
                    # Already in the log — it arrived by TRANSFER while this bucket was settling.
                    # A duplicate is a routine outcome and is reported rather than raised: the
                    # alternative was `entry.op_hash UNIQUE` throwing out of a frame handler, i.e.
                    # a race reported as corruption (#no-exceptions-for-control-flow).
                    dropped.append(Dropped(tx.op_hash, settle.Reason.SETTLED))
                    continue
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

    def replay(self, items: Iterable[Entry], expect: Commitment | None = None) -> str | None:
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

        Signatures ARE verified: self-contained, always possible, and there is never an excuse.

        **A collection in the run is RATIFIED OR REFUSED.** This used to apply any `Compaction` a
        peer put in a run, with no signature check anywhere — so bulk transfer was a data-loss
        primitive: hand a catching-up node an unsigned marker and it forgot the segment, permanently
        and on one peer's word. `Store.collect` was the only place that ever verified a marker
        (#collection-is-ratified). The marker is also passed THROUGH to `_collect` now, so the
        quorum's signatures survive into this node's own checkpoint instead of being replaced by a
        locally fabricated one nobody signed.

        `expect` is the sender's own signed commitment, and it is the WEAKER of the two anchors: it
        says only that the sender is internally consistent, which a liar can arrange. The stronger
        one is this node's ratified checkpoint, and both are checked wherever the run reaches their
        height — every commitment must agree or the whole batch is ROLLED BACK, before it is
        committed rather than detected afterwards.

        RETURNS THE REFUSAL, and raises nothing for it `[H]`. A run that does not reconcile is
        THEIR fault and a routine outcome — a bounded `PULL` races the sender's own progress, a
        sighting goes stale, a peer lies — so it comes back as a reason a log line can carry, in
        the house idiom of `Compaction.attested` (#no-exceptions-for-control-flow). It used to be a
        `StoreError` out of a frame handler, i.e. one peer's ordinary message taking a node's
        process down. `None` means the run was applied; anything else means nothing was."""
        self.db.execute("BEGIN IMMEDIATE")
        try:
            acc = self.accumulator()
            for e in items:
                if isinstance(e.item, ops.Compaction):
                    # The roster is read HERE, at the marker, not once before the run. A replay
                    # starting from genesis begins with no roster at all, so hoisting this would
                    # check nothing on exactly the path that most needs it — and the roster that
                    # matters is the one the log had reached when the collection happened, which is
                    # what reading it mid-replay gives.
                    roster = list(self.roster())
                    # A collection replays as itself: drop the segment's entries and subtract its
                    # accumulator. There is no splice and no chain to repair, because a segment is
                    # collected WHOLE — which is the entire reason the segment model replaces the
                    # entry-level one.
                    if roster and (why := e.item.attested(roster)) is not None:
                        self.db.execute("ROLLBACK")
                        seg = e.item.segment
                        return f"collection of segment {seg} in the run is not ratified: {why}"
                    self._set_meta("acc", acc)
                    self._collect(e.item.segment, at=e.idx, marker=e.item)
                    acc = self.accumulator()
                    continue
                if (why := _unverified(e)) is not None:
                    self.db.execute("ROLLBACK")
                    return why
                acc = self._commit(e.idx, e.item, e.item.txn.mutations, acc)
            self._set_meta("acc", acc)
            if (why := self._unacceptable(expect)) is not None:
                self.db.execute("ROLLBACK")
                return why
            self._remember_roster_serial()
            self.db.execute("COMMIT")
        except Exception:
            # Still here, and still re-raising: a bug of OURS mid-replay must not be reported as a
            # refusal of THEIRS. `InvariantError` travels this path (see core/errors.py).
            self.db.execute("ROLLBACK")
            raise
        return None

    def _unacceptable(self, expect: Commitment | None) -> str | None:
        """Everything judged AFTER a run is applied and BEFORE it is committed. `None` to commit.

        AFTERWARDS IS THE POINT, not laziness: a from-scratch replay begins with genesis, so neither
        the manager grant nor the roster exists until the run lands. Checking first would refuse the
        only run that could ever establish them. Checking after refuses a STRANGER'S log, which is
        the case that matters — a log introducing its own manager and its own roster checks out
        against itself, and only the anchor can say no.

        Two kinds of question, in order. Does this agree with something SIGNED (the ratified
        checkpoint, then the sender's own claim), and is this the log our anchor authorises (its
        manager grant, then every roster row's credential)."""
        for at in self._anchors(expect):
            if self.head() == at.head and (why := self._disagrees(at)) is not None:
                return why
        if self.anchor() is None:
            return None  # unprovisioned: it cannot answer, and `adopt` already refuses it a floor
        for why in (self.wrong_cluster(), self.unvouched_roster(), self.roster_incomplete()):
            if why is not None:
                return f"refusing a log this node's anchor does not authorise: {why}"
        return None

    def _remember_roster_serial(self) -> None:
        """Advance the roster high-water mark, having accepted the run that carried it.

        Separate from the check that reads it: a verifier that also recorded would decide and commit
        in one act, and could not be run twice safely."""
        from .management import Management  # noqa: PLC0415 -- reads through Store

        commitment = Management(self).roster_commitment()
        if commitment is not None and commitment[0] > self.roster_serial():
            self._set_meta("roster_serial", commitment[0].to_bytes(8))

    def _anchors(self, expect: Commitment | None) -> tuple[Commitment, ...]:
        """Every signed position this run can be checked against, strongest first.

        THE RATIFIED CHECKPOINT IS THE STRONG ONE, and until now it was never used for this at all:
        a transfer was checked only against `expect`, which is the SENDER'S OWN attestation — so a
        roster member could serve any history it liked provided it signed a statement matching it.
        Self-consistency is not authenticity. The checkpoint carries the quorum, so a run crossing
        its height is checked against what everybody agreed rather than against one peer's story.

        Both are returned rather than one: they answer at different heights, and a run reaching
        neither is unverified — which is #4's missing anchor, not something this can invent."""
        ck = self.checkpoint()
        return tuple(
            c
            for c in (
                Commitment(ck.height, ck.acc_state, ck.acc_log, ck.root) if ck else None,
                expect,
            )
            if c is not None
        )

    def _disagrees(self, expect: Commitment) -> str | None:
        """`None` if every commitment agrees, else which one did not — in words a log line can
        carry, the same shape as `Compaction.attested`.

        Every commitment, not just one. `A_state` alone would pass a log that differs by any
        number of superseded entries — exactly the divergence this system has already been bitten
        by once."""
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
        """Append one transaction at `idx` and fold `mutations` into the live view and `acc`.

        Takes the mutation sequence rather than re-deriving it from `tx`, because the evaluator has
        already produced it in order — and because replay hands over the same shape without any
        evaluation having happened (#replay-does-not-readjudicate)."""
        seg = self.segment_of(idx)
        # The credential a `Set` leaves behind is the transaction doing it, FOR EVERY STORE `[H]`.
        # It was management-only while the leaf hashed the value alone, on the reasoning that data
        # rows derive their authority from management state — true of the authority, and no use to
        # a reader holding a row: the chain existed and nothing carried it. Now the leaf commits to
        # it (`smt.leaf_hash`), so every row answers "who was permitted to write this" without a
        # second lookup, and the log's own history is not the only thing that can say.
        #
        # Storage: a transaction writing 100 keys stores 100 copies. Deduplicating by `op_hash`
        # with live rows referencing it is the natural fix and the same refcount shape as epochs;
        # inline until the numbers say otherwise (#credential-in-every-leaf).
        cred = tx.raw
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
            if isinstance(m, ops.Move):
                # BEFORE the accumulator arithmetic, and that placement is the whole correctness of
                # it: the loop below subtracts the current element for every mutation and only a
                # `Set` adds one back, so falling through here would have deleted the moved row
                # from `A_state` while leaving it in the live view. Provenance moves; NOTHING ELSE
                # DOES — the value, its epoch, its credential and both commitments are untouched.
                #
                # `m.credential` is deliberately not written. Settlement has already refused any
                # move whose credential is not byte-for-byte what the row holds, so writing it
                # would be a no-op — and not writing it makes relocation-invariance STRUCTURAL:
                # since the root commits to the credential, there is now no path through this
                # function by which relocating a row can move the state root. A guard that could be
                # bypassed is weaker than an operation that cannot express the mistake. The
                # credential still travels on the wire, because that is what lets a validator check
                # the move without holding the row.
                self.db.execute(
                    "UPDATE live SET head=? WHERE store=? AND name=?", (idx, m.store, m.name)
                )
                continue
            cur = self.get(m.store, m.name)
            if cur:
                acc = crypto.acc_sub(acc, element(m.store, m.name, cur[1]))
            path = smt.path_of(m.store, m.name)
            # Both commitments move together, in this transaction, for the same reason the live
            # view does: two truths about one state is the failure the store exists to prevent.
            self.tree.invalidate(path)
            if isinstance(m, ops.Set):
                self.db.execute(
                    "INSERT OR REPLACE INTO live (store, name, head, value, path, epoch, cred)"
                    " VALUES (?,?,?,?,?,?,?)",
                    (m.store, m.name, idx, m.value, path, m.epoch, cred),
                )
                acc = crypto.acc_add(acc, element(m.store, m.name, m.value))
            else:
                self.db.execute("DELETE FROM live WHERE store=? AND name=?", (m.store, m.name))
        return acc

    def _settled_hashes(self, want: tuple[crypto.Digest, ...]) -> set[bytes]:
        """Which of these op hashes the log already holds. One query, not one per transaction."""
        if not want:
            return set()
        # The only interpolation is a run of `?`, one per parameter; every value is still bound.
        marks = ",".join("?" * len(want))
        rows = self.db.execute(
            f"SELECT op_hash FROM entry WHERE op_hash IN ({marks})",  # noqa: S608
            want,
        )
        return {r[0] for r in rows}

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

    def credential(self, store: int, name: bytes) -> bytes:
        """The signed transaction that authorised this row's value, or empty if none is kept."""
        row = self.db.execute(
            "SELECT cred FROM live WHERE store=? AND name=?", (store, name)
        ).fetchone()
        return row[0] if row else b""

    def migration(
        self, seg: int, author: crypto.Keypair, now: int, at_most: int
    ) -> ops.SignedTransaction | None:
        """AUTHOR the transaction that moves this segment's stragglers forward. Settles nothing.

        Two things this deliberately does NOT do, both of which it used to.

        It does not `Set` the same value back: that is indistinguishable from setting a different
        one, so it needed write authority the author does not have, and migration acquired it by
        applying with authority checking off — which put node-signed writes into the management
        store and displaced the manager's signature over the roster. `ops.Move` asserts nothing and
        so needs nothing (#conveyor).

        CLAMPED, and the clamp is required rather than defaulted. A segment may hold up to
        `SEGMENT_WIDTH` live rows, and a management row carries a signed transaction as its
        credential, so relocating every straggler at once builds a transaction no frame can carry.
        Taking `at_most` per call makes draining a segment converge over rounds rather than fail in
        one.

        It does not APPLY. Migration entries are log entries like any other and must be agreed by
        the quorum, or every node authors its own and three honest nodes end up holding
        byte-different logs at identical indices — `A_state` agreeing throughout, which is exactly
        why it went unnoticed."""
        moves = [
            ops.Move(st, name, self.credential(st, name))
            for st, name in self.stragglers(seg)[:at_most]
            if self.get(st, name) is not None  # raced with a writer; it has already moved on
        ]
        if not moves:
            return None
        return ops.writes(*moves).sign(author, now)

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
        marker = attest or ops.Compaction(
            seg, self.head(), self.accumulator(), self.log_accumulator(), self.state_root()
        )
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
        before, before_root = self.accumulator(), self.state_root()
        if marker is None:
            marker = ops.Compaction(seg, at - 1, before, self.log_accumulator(), self.state_root())
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

        # A HARD INVARIANT `[H]`, and therefore not a `DudeError`: collection is defined as
        # state-preserving, so either of these firing means our own fold is wrong, not that
        # somebody sent us something bad. Nothing may catch it (core/errors.py).
        #
        # BOTH COMMITMENTS, because there are two and preserving one says nothing about the other.
        # The accumulator is over `(store, name, value)` and cannot see a credential at all, so
        # while the root commits to credentials, an accumulator check alone would sleep through a
        # relocation that rewrote one. The two disagreeing is precisely the "two truths about one
        # state" failure the store exists to prevent, and the root is the half a joiner checks
        # against.
        if self.accumulator() != before:
            raise InvariantError("collection changed the state accumulator")
        if self.state_root() != before_root:
            raise InvariantError("collection changed the state root")
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

    def subtree(self, prefix: bytes, depth: int) -> tuple[crypto.Digest, crypto.Digest]:
        """The two child hashes one bit below `prefix`. The walk's comparison step.

        A subtree hash IS a chunk hash (#state-root), so a joiner descends only where its own hash
        differs from the server's and never transfers a region it agrees about. Cost degrades
        smoothly with absence, which is what `[H]` "re-join as if new" asked for."""
        return (
            self.tree.hash_under(smt.with_bit(prefix, depth, 0), depth + 1),
            self.tree.hash_under(smt.with_bit(prefix, depth, 1), depth + 1),
        )

    def rows_under(self, prefix: bytes, depth: int) -> tuple[tuple[int, bytes, bytes, bytes], ...]:
        """Every live `(store, name, value, credential)` whose path falls under `prefix`'s first
        `depth` bits.

        THE CREDENTIAL IS NOT OPTIONAL HERE. The root commits to it, so a row served without one
        cannot be folded to the root a quorum signed — the transfer would refuse every row it was
        given. It is also the thing the receiver actually wants: a row arriving from a stranger is
        worth having because it carries the signature that authorised it, not because the stranger
        said so.

        A subtree is a contiguous range in path order, so this is an index scan, not a walk."""
        lo, hi = smt.bounds(prefix, depth)
        return tuple(
            (int(s), n, val, cred)
            for s, n, val, cred in self.db.execute(
                "SELECT store, name, value, cred FROM live"
                " WHERE path BETWEEN ? AND ? ORDER BY path",
                (lo, hi),
            )
        )

    def adopt_state(
        self, rows: Iterable[tuple[int, bytes, bytes, bytes, smt.Proof]], root: crypto.Digest
    ) -> str | None:
        """Apply state this node never held, each row checked against a root the quorum signed.

        THE FIRST WRITE PATH THAT IS NOT THE LOG, and it has to be: a joiner past the frontier
        cannot replay the entries that built the state, because collection deleted them. What it can
        do is take the state and check every piece against `root` — which is why the root rides in
        the ratified checkpoint (#state-root) and not only in an attestation.

        EVERY ROW, SEPARATELY, ON ARRIVAL. `smt.verify` folds the row's own siblings to the root, so
        a chunk that does not belong is refused where it arrives instead of poisoning a whole
        transfer that is only checked at the end. That per-chunk property is what lets the walk be
        optimistic — pull, verify, discard the bad — rather than all-or-nothing.

        AND EACH ROW ARRIVES WITH THE CREDENTIAL THAT AUTHORISED IT, which `smt.verify` folds into
        the leaf. So a transferred row is not merely "committed by a quorum" — it carries the
        signature of the client who was permitted to write it, and a peer cannot substitute one it
        prefers without failing the fold. It is also simply required for the arithmetic: storing a
        row without its credential would give this node a different root from the one it just
        checked against, and every subsequent walk would disagree with the cluster for ever.

        It does NOT touch `A_log` or the head: history is not what is being transferred. Those come
        from the checkpoint the root belongs to, and from replaying forward afterwards."""
        checked: list[tuple[int, bytes, bytes, bytes]] = []
        for store, name, value, cred, proof in rows:
            if not smt.verify(root, store, name, (value, cred), proof):
                return f"a row for store {store} does not verify against the signed root"
            checked.append((store, name, value, cred))
        self.db.execute("BEGIN IMMEDIATE")
        try:
            acc = self.accumulator()
            for store, name, value, cred in checked:
                if (cur := self.get(store, name)) is not None:
                    acc = crypto.acc_sub(acc, element(store, name, cur[1]))
                path = smt.path_of(store, name)
                self.tree.invalidate(path)
                self.db.execute(
                    "INSERT OR REPLACE INTO live (store, name, head, value, path, epoch, cred)"
                    " VALUES (?,?,?,?,?,?,?)",
                    (store, name, 0, value, path, ops.EPOCH_NONE, cred),
                )
                acc = crypto.acc_add(acc, element(store, name, value))
            self._set_meta("acc", acc)
            self.db.execute("COMMIT")
        except Exception:
            self.db.execute("ROLLBACK")
            raise
        return None

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

    def horizon(self) -> int:
        """The lowest segment this log still retains. Zero until anything is collected.

        THE FRONTIER, NOT A SET, and that is the whole of why nothing here grows without bound.
        Collection is oldest-first (`Node.maybe_collect`), so the retained log is a contiguous
        suffix and one ratified marker describes where it starts: the marker names the segment it
        collected, so the next one up is the frontier. A per-collection ledger would explain the
        same holes and would be the only structure in the system that grows for ever — the log is
        bounded by collection, sightings and convictions by the roster, and that would be bounded
        by nothing.

        Distinct from `floor`, the HEIGHT that checkpoint attests, being the head at the moment of
        collecting. A client relies on the floor; the horizon is what explains an absence."""
        ck = self.checkpoint()
        return ck.segment + 1 if ck is not None else 0

    def retained_from(self) -> Index:
        """The lowest index this log is obliged to hold. Below it, absence is authorised.

        THE COMPLETENESS RULE in one expression: an index at or above this MUST be present, and one
        below it is accounted for by the ratified collection that removed it. It replaces the
        `(floor, head]` phrasing, which used the wrong quantity: the floor is the head at collection
        time, while the frontier says which indices were forgotten.

        Floored at 1 because indices start there: with nothing collected the horizon is segment 0
        and the arithmetic would name index 0, which no log holds — so a completeness check would
        report a gap that cannot exist."""
        return self.frontier(self.checkpoint())

    def frontier(self, ck: ops.Compaction | None) -> Index:
        """The lowest index a log holding THIS checkpoint is obliged to retain.

        Split out from `retained_from` so a node can ask the question about SOMEBODY ELSE'S marker.
        A node that was absent while the cluster collected holds no newer checkpoint, so its own
        answer is stale by exactly the amount that matters — it would believe the log could still
        reach it while every `PULL` was refused. `Node.bootstrap` asks this about the marker f+1
        fresh peers vouch for instead.

        One expression, two callers, deliberately: the frontier arithmetic being written twice is
        how the two answers would come to disagree."""
        return max(1, ((ck.segment + 1) if ck is not None else 0) * self.SEGMENT_WIDTH)

    def anchor(self) -> crypto.PublicKey | None:
        """The manager public key this node was provisioned with, or None if it was not.

        THE ONE VALUE NOT DERIVED FROM ANYTHING `[H]`: *"the manager public key is provided to the
        new node when it bootstraps and would be retained through a new bootstrap."* Everything else
        a node believes is reached from here — the roster by the credentials the manager signed, the
        quorum by that roster, the state by the quorum's root — so it is the axiom of the bootstrap
        chain (#bootstrap-anchor).

        IN `meta` AND NOT IN THE LOG, deliberately. It is what VALIDATES the log, so taking it from
        the log would be circular: a forged genesis would introduce its own manager and check out
        against itself. Durable because it must survive the wipe that makes a node re-bootstrap; if
        it does not survive, the node is unprovisioned and cannot verify anything."""
        raw = self._get_meta("anchor", b"")
        return crypto.PublicKey(raw) if raw else None

    def seeds(self) -> tuple[bytes, ...]:
        """The addresses this node was provisioned with, to reach the cluster at all.

        THE SECOND THING THAT CANNOT BE DERIVED `[H]`: *"we need to know the manager key, we need
        f+1 nodes to determine freshness"* — and reaching `f+1` nodes needs `f+1` addresses, which
        cannot be obtained by asking, because asking requires an address. So they are provisioning
        input alongside the anchor, and retained for the same reason.

        Addresses only. WHO answers is established by their signatures and by the anchor chain; a
        seed that turns out to be a stranger costs a wasted connection and nothing else."""
        raw = self._get_meta("seeds", b"")
        return tuple(codec.as_bytes(a) for a in codec.as_seq(codec.decode(raw))) if raw else ()

    def provision(self, manager: crypto.PublicKey, seeds: Iterable[bytes] = ()) -> None:
        """Record the anchor. Idempotent for the same key, and REFUSED for a different one.

        Re-provisioning to a different manager would move a node between clusters silently, taking
        its identity and its attestation history with it — and its monotone height, which is the one
        thing #monotonicity says cannot be forged. An operator who genuinely means it deletes the
        store, which is the same act as retiring the identity."""
        held = self.anchor()
        if held is not None and held != manager:
            raise InvariantError(
                "this node is provisioned to a different manager; re-provisioning would move it "
                "between clusters while keeping its identity and its attested height"
            )
        self._set_meta("anchor", manager)
        if seeds:
            self._set_meta("seeds", codec.encode(sorted(seeds)))

    def wrong_cluster(self) -> str | None:
        """`None` if the log we hold is the one our anchor authorises, else why not.

        The second step of the chain: the log's own manager grant MUST name the key we were given.
        A log that does not is a different cluster's, and adopting anything from it — a roster, a
        checkpoint, a state root — would be believing a stranger's whole world.

        An unprovisioned node cannot answer this and says so rather than passing: it holds no
        axiom, so nothing it could check would mean anything."""
        from .management import Management, Role  # noqa: PLC0415 -- management reads through Store

        held = self.anchor()
        if held is None:
            return "no anchor: this node was never provisioned with a manager key"
        grant = Management(self).grant_of(held)
        if grant is None:
            return "the log holds no grant for the manager we were provisioned with"
        if grant.role is not Role.MANAGER:
            return f"our anchor holds {grant.role.value} in this log, not manager"
        return None

    def unvouched_roster(self) -> str | None:
        """`None` if every roster row traces to our anchor, else the first one that does not.

        STEP 6 OF THE CHAIN (#bootstrap-anchor), and the reason the credential travels with the row:
        collection eventually forgets the entry that first set a roster row, so without the carried
        credential a joiner could only take the roster on the word of the quorum — and the roster is
        what defines that quorum. Circular, and this is the way out.

        VOUCHED BY THE ANCHOR ITSELF, not by "a manager". `replay` does not re-adjudicate authority,
        so a forged log can hold a `grant` row naming a manager nobody authorised, and a check that
        accepted "signed by some manager in this log" would accept a roster that manager wrote.
        The anchor is the only key not taken from the log, so it is the only one worth checking
        against.

        MANAGER ROTATION IS THEREFORE NOT YET SUPPORTED HERE: a row vouched by a successor key would
        need the chain of grants from the anchor forward, walked and verified. `[H]` the manager is
        cold and is not revoked, so nothing needs it today — but a rotation would break this check,
        which is the correct direction to fail in.

        Unprovisioned nodes get "no anchor": holding no axiom, they cannot answer the question."""
        from .management import P_NODE, Management  # noqa: PLC0415 -- reads through Store

        held = self.anchor()
        if held is None:
            return "no anchor: this node was never provisioned with a manager key"
        for who in Management(self).node_set():
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
        """`None` if the roster we hold is the whole roster the manager signed, else why not.

        STEP 7 OF THE CHAIN (#bootstrap-anchor). Step 6 proves every member was authorised by the
        anchor; it cannot prove NO MEMBER IS MISSING, and a subset is a smaller roster, hence a
        smaller quorum — a party handed three of eleven rows would compute a quorum of two.

        THREE THINGS, and each is a different attack:

        * the commitment traces to the anchor, or a forged log states its own membership;
        * it equals the rows we hold, or a subset passes while claiming to be the whole;
        * its serial never goes backwards, or a genuine-but-superseded roster — members since
          removed, whose keys an adversary may still hold — verifies perfectly for ever.

        The high-water mark is node-local and durable, like the anchor and the checkpoint, and is
        advanced by `replay` once the run it came in is accepted. A checker that moved it would
        decide and record in one act, so the two are kept apart."""
        from .management import P_ROSTER, Management  # noqa: PLC0415 -- reads through Store

        held = self.anchor()
        if held is None:
            return "no anchor: this node was never provisioned with a manager key"
        mgmt = Management(self)
        commitment = mgmt.roster_commitment()
        if commitment is None:
            return "the log states no roster commitment, so a subset could not be detected"
        author = settle.vouched(self, ops.STORE_MANAGEMENT, P_ROSTER, self.credential(0, P_ROSTER))
        if author != held:
            return f"the roster commitment is vouched by {author.hex()[:8] if author else 'nobody'}"
        serial, members = commitment
        if members != mgmt.node_set():
            return (
                f"the roster commitment names {len(members)} members, the log holds a different set"
            )
        if serial < self.roster_serial():
            return f"roster serial {serial} is older than the {self.roster_serial()} already seen"
        return None

    def roster_serial(self) -> int:
        """The highest roster revision this node has accepted. Monotone, and durable so it survives
        the restart that would otherwise let an old roster back in."""
        return int.from_bytes(self._get_meta("roster_serial", b""))

    def adopt(self, ck: ops.Compaction) -> str | None:
        """Take a checkpoint somebody else holds, if the quorum signed it. `None` if adopted, else
        why not.

        THE ONLY WAY A WIPED NODE GETS AN ANCHOR. Before this, `checkpoint` meta was written by
        exactly one code path — a collection this node performed itself — so a node that had never
        collected had floor 0 for ever and nothing to check any transfer against. Meanwhile the
        checkpoint it needed was already arriving on every attestation it heard (`Attestation
        .ratified`) and being dropped on the floor.

        MAX WINS, and that is safe only because the signatures are checked here `[H]`. A floor
        carries the quorum, so it can be WITHHELD but not forged upward — which is what makes
        "believe the highest" the correct rule rather than a credulous one (`attest.attested_floor`
        reasons the same way about the same object). Verify first, then take the higher.

        A floor ABOVE our own head is not an error and must not be refused: it is the true, signed,
        locally-checkable statement *"the cluster has ratified state I do not hold"* — which is
        precisely the bootstrap trigger, and refusing it would discard the one fact that says so."""
        if (why := self.wrong_cluster()) is not None:
            # The chain has an ORDER (#bootstrap-anchor): a checkpoint is verified against the
            # roster, and the roster is worth something only if the log holding it is the one our
            # anchor authorises. Adopting first and verifying later would take a floor — and so a
            # monotone height — from a cluster we were never provisioned into.
            return why
        roster = list(self.roster())
        if not roster:
            return "no roster to check a checkpoint against"
        if (why := ck.attested(roster)) is not None:
            return why
        if ck.height <= self.floor():
            return None  # not better than what we hold; monotone by policy, and not a failure
        self._set_meta("checkpoint", ck.raw)
        return None

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
        and only the key can make it evidence.

        ALSO WHERE A CHECKPOINT IS ADOPTED, because this is the one funnel every peer attestation
        passes through, and a claim carries the quorum-signed floor it stands on. `adopt` verifies
        those signatures itself, so hearing from a liar costs nothing."""
        if not signed.verify():
            return None
        if signed.claim.ratified is not None:
            self.adopt(signed.claim.ratified)
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
