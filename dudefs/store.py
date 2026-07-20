# DudeFS L2 — durable store & the finality floor (node replication substrate).
#
# ARCHITECTURE L2 / DESIGN §8, §9 / PROTOCOL §2.1 / RESILIENCE §0.
#
# One sqlite database per storage node = one durability domain (DESIGN §8): the
# node's acceptor state, its floor, and (in a real deployment) its signing key
# all live or die together. **Sign-after-fsync = sign after COMMIT**
# (RESILIENCE §0): the store's mutating methods COMMIT before the acceptor
# (L3) signs anything, so no receipt/promise/watermark ever outlives the state
# that justified it. sqlite runs in WAL + `synchronous=FULL`, so COMMIT fsyncs.

from __future__ import annotations

import sqlite3
from enum import StrEnum

from . import artifacts as A
from . import codec
from .artifacts import BLIND, HLC, QC, Ballot, Heads, Op, Receipt


class AppendStatus(StrEnum):
    """append() outcomes (ARCHITECTURE L2: ok | dup | gap | fork-evidence).
    INVALID (bad structure/signature — drop) is distinct from GAP (missing
    predecessor — retry after the gap fills): gossip must treat them
    differently (NOTES item 17)."""

    OK = "ok"
    DUP = "dup"
    GAP = "gap"
    FORK = "fork"
    INVALID = "invalid"


class EvidenceKind(StrEnum):
    """Kind of misbehavior proof (DESIGN §4). StrEnum: persisted to the evidence
    table, so its stable string value round-trips through sqlite."""

    FORK = "fork"  # two signed ops at one (author, seq)
    # DOUBLE_VOTE, FLOOR_PERJURY: later (RESILIENCE §3.1)


class AppendResult:
    __slots__ = ("status", "evidence")

    def __init__(self, status: AppendStatus, evidence: ForkEvidence | None = None):
        self.status = status
        self.evidence = evidence  # ForkEvidence on AppendStatus.FORK

    def __bool__(self) -> bool:
        return self.status in (AppendStatus.OK, AppendStatus.DUP)


class ForkEvidence:
    """Two validly-signed ops at one (author, seq) = a portable equivocation
    proof (DESIGN §4). Self-verifying: both signatures check, hashes differ."""

    __slots__ = ("author", "seq", "raw_a", "raw_b")

    def __init__(self, author: bytes, seq: int, raw_a: bytes, raw_b: bytes):
        self.author = author
        self.seq = seq
        self.raw_a, self.raw_b = raw_a, raw_b

    def verify(self) -> bool:
        try:
            a = A.Op.from_bytes(self.raw_a)
            b = A.Op.from_bytes(self.raw_b)
        except Exception:
            return False
        return (
            a.author == b.author == self.author
            and a.seq == b.seq == self.seq
            and a.op_hash != b.op_hash
            and a.verify_sig(a.author)
            and b.verify_sig(b.author)
        )


_SCHEMA = """
CREATE TABLE IF NOT EXISTS ops (
    op_hash BLOB PRIMARY KEY, author BLOB NOT NULL, seq INTEGER NOT NULL,
    is_control INTEGER NOT NULL, hlc_wall INTEGER NOT NULL, hlc_ctr INTEGER NOT NULL,
    raw BLOB NOT NULL);
CREATE INDEX IF NOT EXISTS ops_author_seq ON ops(author, seq);
CREATE TABLE IF NOT EXISTS receipts (
    op_hash BLOB, epoch INTEGER, ballot BLOB, signer BLOB, sig BLOB,
    PRIMARY KEY (op_hash, epoch, ballot, signer));
CREATE TABLE IF NOT EXISTS qcs (
    op_hash BLOB, epoch INTEGER, ballot BLOB, bitmap BLOB, sigs BLOB,
    PRIMARY KEY (op_hash, epoch, ballot));
CREATE TABLE IF NOT EXISTS slot_state (
    tag BLOB PRIMARY KEY, promised BLOB NOT NULL,
    accepted_ballot BLOB, accepted_op BLOB);
CREATE TABLE IF NOT EXISTS floor (
    id INTEGER PRIMARY KEY CHECK (id = 0),
    hw_wall INTEGER, hw_ctr INTEGER, att_wall INTEGER, att_ctr INTEGER);
CREATE TABLE IF NOT EXISTS evidence (
    id INTEGER PRIMARY KEY AUTOINCREMENT, kind TEXT, data BLOB);
CREATE TABLE IF NOT EXISTS meta (k TEXT PRIMARY KEY, v BLOB);
"""


class ChainStore:
    """Durable store. Knows nothing of slots-as-predicates or payloads: a
    `slot_tag` is opaque bytes, a data payload is opaque ciphertext (zero-
    knowledge is structural — the node build has no keyring)."""

    def __init__(self, path: str = ":memory:"):
        self.db = sqlite3.connect(path)
        self.db.execute("PRAGMA journal_mode=WAL")
        self.db.execute("PRAGMA synchronous=FULL")  # COMMIT fsyncs (sign-after-fsync)
        self.db.executescript(_SCHEMA)
        if self.db.execute("SELECT 1 FROM floor WHERE id=0").fetchone() is None:
            self.db.execute("INSERT INTO floor VALUES (0,0,0,0,0)")
            self.db.commit()

    def close(self) -> None:
        self.db.close()

    # ---- meta ------------------------------------------------------------- #
    def set_meta(self, key: str, value: bytes) -> None:
        self.db.execute("INSERT OR REPLACE INTO meta VALUES (?,?)", (key, value))
        self.db.commit()

    def get_meta(self, key: str) -> bytes | None:
        row = self.db.execute("SELECT v FROM meta WHERE k=?", (key,)).fetchone()
        return row[0] if row else None

    # ---- ops: append with contiguity + fork detection (PROTOCOL §2.1) ----- #
    def append(self, op: Op) -> AppendResult:
        if not (op.verify_structure() and op.verify_sig(op.author)):
            return AppendResult(AppendStatus.INVALID)  # caller drops (not stored)
        existing = self.db.execute(
            "SELECT op_hash, raw FROM ops WHERE author=? AND seq=?", (op.author, op.seq)
        ).fetchall()
        for oh, raw in existing:
            if oh == op.op_hash:
                return AppendResult(AppendStatus.DUP)  # idempotent
            # different hash at same (author, seq) -> fork
            ev = ForkEvidence(op.author, op.seq, raw, op.raw)
            self._store_evidence(EvidenceKind.FORK, ev)
            return AppendResult(AppendStatus.FORK, ev)
        # contiguity: need seq-1 (or seq 0). Gaps are deferred (PROTOCOL §2.1).
        if op.seq > 0:
            has_prev = self.db.execute(
                "SELECT 1 FROM ops WHERE author=? AND seq=?", (op.author, op.seq - 1)
            ).fetchone()
            if has_prev is None:
                return AppendResult(AppendStatus.GAP)
        self.db.execute(
            "INSERT INTO ops VALUES (?,?,?,?,?,?,?)",
            (
                op.op_hash,
                op.author,
                op.seq,
                1 if op.is_control else 0,
                op.hlc.wall_ms,
                op.hlc.counter,
                op.raw,
            ),
        )
        self.db.commit()
        return AppendResult(AppendStatus.OK)

    def put_op_raw(self, op: Op) -> None:
        """Store an op referenced by a ballot ACCEPT even if it opens no
        contiguous chain locally (the envelope is self-contained and
        re-proposable — DESIGN §8). Bypasses the contiguity gate."""
        if self.get_op(op.op_hash) is not None:
            return
        self.db.execute(
            "INSERT OR IGNORE INTO ops VALUES (?,?,?,?,?,?,?)",
            (
                op.op_hash,
                op.author,
                op.seq,
                1 if op.is_control else 0,
                op.hlc.wall_ms,
                op.hlc.counter,
                op.raw,
            ),
        )

    def get_op(self, op_hash: bytes) -> Op | None:
        row = self.db.execute("SELECT raw FROM ops WHERE op_hash=?", (op_hash,)).fetchone()
        return A.Op.from_bytes(row[0]) if row else None

    def get(self, author: bytes, seq: int) -> list[Op]:
        row = self.db.execute(
            "SELECT raw FROM ops WHERE author=? AND seq=?", (author, seq)
        ).fetchall()
        return [A.Op.from_bytes(r[0]) for r in row]

    def heads(self) -> Heads:
        """{author: (head_seq, head_op_hash)} — the per-author frontier,
        computed over each author's CONTIGUOUS prefix only. Orphan islands
        (ops stored contiguity-free by a ballot ACCEPT, DESIGN §8) are never
        reported: a signed frontier bundle must not claim a head the node
        cannot serve as a contiguous run (PROTOCOL §2.1 / NOTES item 16)."""
        out: Heads = {}
        for author, seq, oh in self.db.execute(
            "SELECT author, seq, op_hash FROM ops ORDER BY author, seq"
        ):
            cur = out.get(author)
            if cur is None:
                if seq == 0:  # a run must start at the chain root (M6: at the cut)
                    out[author] = (seq, oh)
            elif seq == cur[0] + 1:
                out[author] = (seq, oh)  # contiguous extension
            # seq == cur[0]: an equivocation sibling — keep the first
            # seq > cur[0] + 1: beyond a gap — not part of the frontier
        return out

    def all_ops(self) -> list[Op]:
        return [A.Op.from_bytes(r[0]) for r in self.db.execute("SELECT raw FROM ops")]

    # ---- receipts & QCs --------------------------------------------------- #
    def put_receipt(self, r: Receipt) -> None:
        self.db.execute(
            "INSERT OR IGNORE INTO receipts VALUES (?,?,?,?,?)",
            (r.op_hash, r.config_epoch, codec.encode(r.ballot.encode()), r.signer, r.sig),
        )
        self.db.commit()

    def receipts_for(self, op_hash: bytes) -> list[Receipt]:
        out: list[Receipt] = []
        for oh, ep, ballot, signer, sig in self.db.execute(
            "SELECT * FROM receipts WHERE op_hash=?", (op_hash,)
        ):
            out.append(A.Receipt(oh, ep, Ballot.decode(codec.decode(ballot)), signer, sig))
        return out

    def all_receipts(self) -> list[Receipt]:
        """Every receipt held, for gossip coverage/diff (M4)."""
        return [
            A.Receipt(oh, ep, Ballot.decode(codec.decode(ballot)), signer, sig)
            for oh, ep, ballot, signer, sig in self.db.execute("SELECT * FROM receipts")
        ]

    def put_qc(self, qc: QC) -> None:
        self.db.execute(
            "INSERT OR REPLACE INTO qcs VALUES (?,?,?,?,?)",
            (
                qc.op_hash,
                qc.config_epoch,
                codec.encode(qc.ballot.encode()),
                qc.signer_bitmap,
                codec.encode(qc.sigs),
            ),
        )
        self.db.commit()

    def get_qc(self, op_hash: bytes) -> QC | None:
        # deterministic pick when one op holds QCs under several epochs/ballots
        row = self.db.execute(
            "SELECT * FROM qcs WHERE op_hash=? ORDER BY epoch DESC, ballot DESC LIMIT 1",
            (op_hash,),
        ).fetchone()
        if not row:
            return None
        oh, ep, ballot, bitmap, sigs = row
        sig_list = [codec.as_bytes(x) for x in codec.as_seq(codec.decode(sigs))]
        return A.QC(oh, ep, Ballot.decode(codec.decode(ballot)), bitmap, sig_list)

    def all_qcs(self) -> list[QC]:
        """Every QC held, for gossip coverage/diff (M4)."""
        out: list[QC] = []
        for oh, ep, ballot, bitmap, sigs in self.db.execute("SELECT * FROM qcs"):
            sig_list = [codec.as_bytes(x) for x in codec.as_seq(codec.decode(sigs))]
            out.append(A.QC(oh, ep, Ballot.decode(codec.decode(ballot)), bitmap, sig_list))
        return out

    def gc_checkpoint(self, dead: list[bytes]) -> None:
        """Log-compaction GC (DESIGN §12 rev 6): on observing a quorum-committed
        checkpoint, drop the ops named in its `dead` delta and every receipt/QC for
        them — the checkpoint's retained commitment vouches for below-cut commitment
        (NOTES 29d), so provenance survives in the retained envelopes. Retained
        winners, control-plane liveness, and pinned heads stay. Lazy, local,
        uncoordinated: each node runs it independently."""
        for oh in dead:
            self.db.execute("DELETE FROM ops WHERE op_hash=?", (oh,))
            self.db.execute("DELETE FROM receipts WHERE op_hash=?", (oh,))
            self.db.execute("DELETE FROM qcs WHERE op_hash=?", (oh,))
        self.db.commit()

    # ---- slot acceptor state (DESIGN §8) ---------------------------------- #
    def get_slot(self, tag: bytes) -> SlotState:
        row = self.db.execute(
            "SELECT promised, accepted_ballot, accepted_op FROM slot_state WHERE tag=?", (tag,)
        ).fetchone()
        if row is None:
            return SlotState(BLIND, None, None)
        promised = Ballot.decode(codec.decode(row[0]))
        ab = Ballot.decode(codec.decode(row[1])) if row[1] is not None else None
        return SlotState(promised, ab, row[2])

    def _write_slot(self, tag: bytes, s: SlotState) -> None:
        self.db.execute(
            "INSERT OR REPLACE INTO slot_state VALUES (?,?,?,?)",
            (
                tag,
                codec.encode(s.promised.encode()),
                codec.encode(s.accepted_ballot.encode()) if s.accepted_ballot else None,
                s.accepted_op,
            ),
        )

    # ---- floor / high-water (DESIGN §9) ----------------------------------- #
    def get_hw(self) -> HLC:
        r = self.db.execute("SELECT hw_wall, hw_ctr FROM floor WHERE id=0").fetchone()
        return HLC(r[0], r[1])

    def get_attested(self) -> HLC:
        r = self.db.execute("SELECT att_wall, att_ctr FROM floor WHERE id=0").fetchone()
        return HLC(r[0], r[1])

    def _write_hw(self, hw: HLC) -> None:
        self.db.execute("UPDATE floor SET hw_wall=?, hw_ctr=? WHERE id=0", (hw.wall_ms, hw.counter))

    def _write_attested(self, att: HLC) -> None:
        self.db.execute(
            "UPDATE floor SET att_wall=?, att_ctr=? WHERE id=0", (att.wall_ms, att.counter)
        )

    # ---- evidence --------------------------------------------------------- #
    def _store_evidence(self, kind: EvidenceKind, ev: ForkEvidence) -> None:
        self.db.execute(
            "INSERT INTO evidence (kind, data) VALUES (?,?)",
            (kind.value, codec.encode([ev.author, ev.seq, ev.raw_a, ev.raw_b])),
        )
        self.db.commit()

    def evidence(self) -> list[tuple[EvidenceKind, ForkEvidence]]:
        out: list[tuple[EvidenceKind, ForkEvidence]] = []
        for kind, data in self.db.execute("SELECT kind, data FROM evidence"):
            p = codec.as_seq(codec.decode(data))
            out.append(
                (
                    EvidenceKind(kind),
                    ForkEvidence(
                        codec.as_bytes(p[0]),
                        codec.as_int(p[1]),
                        codec.as_bytes(p[2]),
                        codec.as_bytes(p[3]),
                    ),
                )
            )
        return out

    # ---- transactional commit boundary (sign-after-fsync) ----------------- #
    def commit(self) -> None:
        self.db.commit()


class SlotState:
    __slots__ = ("promised", "accepted_ballot", "accepted_op")

    def __init__(self, promised: Ballot, accepted_ballot: Ballot | None, accepted_op: bytes | None):
        self.promised = promised  # Ballot
        self.accepted_ballot = accepted_ballot  # Ballot | None
        self.accepted_op = accepted_op  # op_hash bytes | None
