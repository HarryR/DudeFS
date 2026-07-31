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

    # -- LOG ----------------------------------------------------------------- #

    def head(self) -> Index:
        """The highest settled index. Zero on an empty log."""
        row = self.db.execute("SELECT MAX(idx) FROM entry").fetchone()
        return row[0] or 0

    def entries(self, frm: Index = 1, to: Index | None = None) -> Iterator[Entry]:
        """Replay range, inclusive. The only way anyone derives state
        (#replay-does-not-readjudicate)."""
        hi = self.head() if to is None else to
        for idx, raw in self.db.execute(
            "SELECT idx, raw FROM entry WHERE idx BETWEEN ? AND ? ORDER BY idx", (frm, hi)
        ):
            yield Entry(idx, ops.SignedTransaction.decode(raw))

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

        Two kinds of question, in order. Does this agree with the sender's own signed claim (if
        the run reached its height), and is this the log our anchor authorises (its manager grant,
        then every roster row's credential)."""
        if (
            expect is not None
            and self.head() == expect.head
            and (why := self._disagrees(expect)) is not None
        ):
            return why
        if self.anchor() is None:
            return None  # unprovisioned: it cannot answer
        for why in (self.wrong_cluster(), self.unvouched_roster(), self.roster_incomplete()):
            if why is not None:
                return f"refusing a log this node's anchor does not authorise: {why}"
        return None

    def _remember_roster_serial(self) -> None:
        """Advance the roster high-water mark, having accepted the run that carried it.

        Separate from the check that reads it: a verifier that also recorded would decide and commit
        in one act, and could not be run twice safely."""

        commitment = Management(self).roster_commitment()
        if commitment is not None and commitment[0] > self.roster_serial():
            self._set_meta("roster_serial", commitment[0].to_bytes(8))

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
            "INSERT INTO entry (idx, op_hash, raw, author, ts) VALUES (?,?,?,?,?)",
            (idx, tx.op_hash, tx.raw, tx.author, tx.ts),
        )
        self._log_add(idx, tx.op_hash)
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

    def roster(self) -> tuple[crypto.PublicKey, ...]:
        """The set of authorised nodes. Read from the management prefix rather than configured,
        so the set that signs is the set the log itself says exists.

        `management` reads through `layer.Reader`, NOT through `Store`, so importing it here is a
        plain one-way edge and there is no cycle to avoid."""

        return Management(self).node_set()

    def credential(self, store: int, name: bytes) -> bytes:
        """The signed transaction that authorised this row's value, or empty if none is kept."""
        row = self.db.execute(
            "SELECT cred FROM live WHERE store=? AND name=?", (store, name)
        ).fetchone()
        return row[0] if row else b""

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
            )
            self.db.execute("COMMIT")
        except Exception:
            self.db.execute("ROLLBACK")
            raise
        return claim
