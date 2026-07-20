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


def covered(op: Op, cut: Heads) -> bool:
    """At-or-below the pinned cut, per-author by seq (DESIGN §12) — the boundary
    between the sparse baseline and the dense tail. The canonical predicate;
    gossip (L2) imports it so store and anti-entropy agree on the boundary."""
    entry = cut.get(op.author)
    return entry is not None and op.seq <= entry[0]


def baseline_digest(
    ops: list[Op], cut: Heads, dead: frozenset[bytes]
) -> dict[bytes, tuple[int, bytes]]:
    """The per-author commitment over the RETAINED below-cut projection —
    `covered ∖ dead` (DESIGN §12 / NOTES 34, Q2). Excluding `dead` is what makes
    a lazy-GC node (still holding superseded ops) agree with a GC'd node and with
    the checkpoint's winners-only `retained`: both project to the same winners, so
    completeness compares equal and neither re-pulls the other's dead envelopes."""
    return A.retained_commitment([o for o in ops if covered(o, cut) and o.op_hash not in dead])


def _encode_pairs(d: dict[bytes, tuple[int, bytes]]) -> bytes:
    """Serialize a {key: (n, hash)} map (a cut or a retained commitment) for the
    durable `meta` table."""
    return codec.encode({a: [n, h] for a, (n, h) in d.items()})


def _decode_pairs(raw: bytes) -> dict[bytes, tuple[int, bytes]]:
    out: dict[bytes, tuple[int, bytes]] = {}
    for a, entry in codec.as_dict(codec.decode(raw)).items():
        pair = codec.as_seq(entry, 2)
        out[a] = (codec.as_int(pair[0]), codec.as_bytes(pair[1]))
    return out


def _wm_fields(wm: A.Watermark) -> list:
    """Pack a Watermark for the evidence blob (it has no wire codec of its own)."""
    return [wm.floor.wall_ms, wm.floor.counter, wm.config_epoch, wm.issue_seq, wm.signer, wm.sig]


def _wm_from(p) -> A.Watermark:
    return A.Watermark(
        HLC(codec.as_int(p[0]), codec.as_int(p[1])),
        codec.as_int(p[2]),
        codec.as_int(p[3]),
        codec.as_bytes(p[4]),
        codec.as_bytes(p[5]),
    )


# --- issuance-chain artifacts (receipts + watermarks share the seq space) ------ #
# A SEQ_REUSE proof (finding 18a) can pair ANY two: receipt/receipt, receipt/
# watermark, watermark/watermark. These helpers give a uniform pack/unpack and the
# reissue-key that distinguishes a genuine collision from a legitimate re-issue.


def _art_pack(art) -> tuple[bytes, bytes]:
    """(kind_tag, raw-blob) for a Receipt or Watermark — its on-wire evidence form."""
    if isinstance(art, Receipt):
        return (b"r", art.encode())
    return (b"w", codec.encode(_wm_fields(art)))


def _art_unpack(kind: bytes, raw: bytes):
    return A.Receipt.decode(raw) if kind == b"r" else _wm_from(codec.as_seq(codec.decode(raw)))


def _art_reissue_key(art) -> tuple:
    """The identity two artifacts at one (signer, issue_seq) may LEGITIMATELY share:
    two receipts for the same (op_hash, ballot) — a cross-epoch RERECEIPT (different
    epochs are different messages at one seq). Anything else at one seq is a
    collision; watermarks key on their content, so two distinct WMs (or a
    receipt-vs-WM back-stamp) always collide."""
    if isinstance(art, Receipt):
        return (b"r", art.op_hash, art.ballot.encode())
    return (b"w", art.floor.as_tuple(), art.config_epoch)


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
    DOUBLE_VOTE = "double_vote"  # one signer's two receipts for one slot at one ballot
    FLOOR_PERJURY = "floor_perjury"  # a watermark + a LATER receipt beneath its floor
    SEQ_REUSE = "seq_reuse"  # two receipts at one signer/issue_seq (issuance-chain fork)
    LOST_COMMIT = "lost_commit"  # a QC below a recovery fence, absent from its manifest


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


class DoubleVoteEvidence:
    """One signer's two receipts for DIFFERENT ops on the SAME slot at one ballot —
    a B1 (slot-safety) violation, portable and self-verifying (DESIGN §4 / §8). The
    receipt signs only (op_hash, epoch, ballot), so the two op envelopes ride along
    to prove the shared slot_tag; the accuser cannot forge either receipt (both are
    the signer's own signatures)."""

    __slots__ = ("signer", "raw_a", "raw_b", "rcpt_a", "rcpt_b")

    def __init__(self, signer: bytes, raw_a: bytes, raw_b: bytes, rcpt_a: Receipt, rcpt_b: Receipt):
        self.signer = signer
        self.raw_a, self.raw_b = raw_a, raw_b
        self.rcpt_a, self.rcpt_b = rcpt_a, rcpt_b

    def verify(self) -> bool:
        try:
            a = A.Op.from_bytes(self.raw_a)
            b = A.Op.from_bytes(self.raw_b)
        except Exception:
            return False
        return (
            a.slot_tag is not None
            and a.slot_tag == b.slot_tag  # same slot
            and a.op_hash != b.op_hash  # different ops
            and self.rcpt_a.op_hash == a.op_hash
            and self.rcpt_b.op_hash == b.op_hash
            and self.rcpt_a.signer == self.rcpt_b.signer == self.signer
            and self.rcpt_a.ballot == self.rcpt_b.ballot  # same ballot
            and self.rcpt_a.verify()
            and self.rcpt_b.verify()  # genuine signer signatures
        )


class FloorPerjuryEvidence:
    """A signer's watermark attesting floor F at issuance-chain position `s`, plus
    its own receipt at position `s' > s` for an op with `hlc < F` — receipting
    beneath a floor it swore was final, AFTER swearing it (a B3 violation).

    The ORDERING is the whole proof (finding-17): the naive pair (any WM above any
    below-floor receipt) convicts honest nodes, because receipting X while the floor
    is low and letting the floor rise later is legal. Only `rcpt.issue_seq >
    wm.issue_seq` — issued AFTER the attestation — is the crime, and an honest node
    structurally cannot produce it (after attesting F the past gate refuses below-F
    acceptances, and re-issues preserve their original lower seq). Self-verifying;
    the op envelope rides along for its hlc (the receipt omits it)."""

    __slots__ = ("signer", "wm", "rcpt", "op_raw")

    def __init__(self, signer: bytes, wm: A.Watermark, rcpt: Receipt, op_raw: bytes):
        self.signer = signer
        self.wm = wm
        self.rcpt = rcpt
        self.op_raw = op_raw

    def verify(self) -> bool:
        try:
            op = A.Op.from_bytes(self.op_raw)
        except Exception:
            return False
        return (
            self.wm.signer == self.rcpt.signer == self.signer
            and self.rcpt.op_hash == op.op_hash
            and op.hlc < self.wm.floor  # the receipted op is beneath the sworn floor
            and self.rcpt.issue_seq > self.wm.issue_seq  # ...and issued AFTER swearing it
            and self.wm.verify()
            and self.rcpt.verify()
        )


class SeqReuseEvidence:
    """One signer's TWO distinct signed artifacts — receipt/receipt, receipt/
    watermark, or watermark/watermark — at a single issuance-chain position
    (`signer, issue_seq`). The issuance-chain FORK (finding 17/18a): the monotone
    counter must place at most one artifact per seq. Generalizing beyond
    receipt/receipt closes the back-stamp evasion where a perjurer stamps its
    below-floor receipt with the WATERMARK's own seq. Carve-out: two receipts for
    the same (op_hash, ballot) is a legitimate cross-epoch RERECEIPT; identical
    artifacts are not a contradiction. Self-verifying (both signatures + a real
    collision)."""

    __slots__ = ("signer", "issue_seq", "kind_a", "raw_a", "kind_b", "raw_b")

    def __init__(
        self,
        signer: bytes,
        issue_seq: int,
        kind_a: bytes,
        raw_a: bytes,
        kind_b: bytes,
        raw_b: bytes,
    ):
        self.signer = signer
        self.issue_seq = int(issue_seq)
        self.kind_a, self.raw_a = kind_a, raw_a
        self.kind_b, self.raw_b = kind_b, raw_b

    def verify(self) -> bool:
        if (self.kind_a, self.raw_a) == (self.kind_b, self.raw_b):
            return False  # identical bytes are not a contradiction
        try:
            a = _art_unpack(self.kind_a, self.raw_a)
            b = _art_unpack(self.kind_b, self.raw_b)
        except Exception:
            return False
        return (
            a.signer == b.signer == self.signer
            and a.issue_seq == b.issue_seq == self.issue_seq
            and _art_reissue_key(a) != _art_reissue_key(b)  # a genuine collision
            and a.verify()
            and b.verify()
        )


class LostCommitEvidence:
    """A QC that a recovery fence ORPHANED: an op committed at an epoch BELOW the
    fence's new epoch, yet ABSENT from the recovery checkpoint's `retained` manifest
    (RESILIENCE §2.2 step 4 — the QC is a cryptographic receipt of the broken
    durability promise). Not signer misbehavior — an honest-but-mistaken recovery's
    disclosure, attributable to the recovery op. `verify` needs external context the
    store does not hold as artifacts: the old-epoch `roster` (to check the QC) and
    the recovery checkpoint's `retained_hashes` (to prove absence)."""

    __slots__ = ("qc", "recovery_epoch", "recovery_ckpt_hash")

    def __init__(self, qc: QC, recovery_epoch: int, recovery_ckpt_hash: bytes):
        self.qc = qc
        self.recovery_epoch = int(recovery_epoch)
        self.recovery_ckpt_hash = recovery_ckpt_hash

    def verify(self, roster: list[bytes], retained_hashes: frozenset[bytes]) -> bool:
        return (
            self.qc.config_epoch < self.recovery_epoch  # below the fence
            and self.qc.op_hash not in retained_hashes  # absent from the manifest
            and self.qc.verify(roster)  # a genuine commitment
        )


_SCHEMA = """
CREATE TABLE IF NOT EXISTS ops (
    op_hash BLOB PRIMARY KEY, author BLOB NOT NULL, seq INTEGER NOT NULL,
    is_control INTEGER NOT NULL, hlc_wall INTEGER NOT NULL, hlc_ctr INTEGER NOT NULL,
    raw BLOB NOT NULL);
CREATE INDEX IF NOT EXISTS ops_author_seq ON ops(author, seq);
CREATE TABLE IF NOT EXISTS receipts (
    op_hash BLOB, epoch INTEGER, ballot BLOB, signer BLOB, sig BLOB, issue_seq INTEGER,
    PRIMARY KEY (op_hash, epoch, ballot, signer));
CREATE TABLE IF NOT EXISTS qcs (
    op_hash BLOB, epoch INTEGER, ballot BLOB, bitmap BLOB, sigs BLOB, issue_seqs BLOB,
    PRIMARY KEY (op_hash, epoch, ballot));
CREATE TABLE IF NOT EXISTS slot_state (
    tag BLOB PRIMARY KEY, promised BLOB NOT NULL,
    accepted_ballot BLOB, accepted_op BLOB);
CREATE TABLE IF NOT EXISTS floor (
    id INTEGER PRIMARY KEY CHECK (id = 0),
    hw_wall INTEGER, hw_ctr INTEGER, att_wall INTEGER, att_ctr INTEGER);
CREATE TABLE IF NOT EXISTS evidence (
    id INTEGER PRIMARY KEY AUTOINCREMENT, kind TEXT, data BLOB);
CREATE TABLE IF NOT EXISTS issuance (
    seq INTEGER PRIMARY KEY, kind TEXT, ident BLOB);
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
            self._store_evidence(EvidenceKind.FORK, [ev.author, ev.seq, ev.raw_a, ev.raw_b])
            return AppendResult(AppendStatus.FORK, ev)
        # contiguity: need seq-1 (or seq 0). Gaps are deferred (PROTOCOL §2.1).
        if op.seq > 0:
            has_prev = self.db.execute(
                "SELECT 1 FROM ops WHERE author=? AND seq=?", (op.author, op.seq - 1)
            ).fetchone()
            if has_prev is None:
                # cut exemption (WP1.2 / finding 2, PROTOCOL §2.1): an op whose
                # predecessor is at-or-below the cut (seq-1 <= cut_seq, i.e.
                # seq <= cut_seq+1) is contiguous-by-fiat — that predecessor was
                # legitimately GC'd and the checkpoint's retained commitment
                # certifies the below-cut prefix. Only a genuine tail gap defers.
                entry = self.cut().get(op.author)
                cut_seq = entry[0] if entry else -1
                if op.seq > cut_seq + 1:
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
        cannot serve as a contiguous run (PROTOCOL §2.1 / NOTES item 16).

        Cut-aware (WP1.2 / finding 1): below the cut the log is sparse (below-cut
        ops may be GC'd), so a cut author's dense-tail run is anchored at its
        PINNED head (cut_seq, cut_hash) and resumes at cut_seq+1 — never at
        seq 0, which may be gone. A cut author with no tail reports the pin
        itself. Authors absent from the cut anchor at the chain root (seq 0), as
        before — an empty cut is exactly the pre-compaction behavior."""
        cut = self.cut()
        # seed each cut author with its pinned head: that IS its frontier below
        # the cut, and the boundary the tail extends from.
        out: Heads = dict(cut)
        for author, seq, oh in self.db.execute(
            "SELECT author, seq, op_hash FROM ops ORDER BY author, seq"
        ):
            cur = out.get(author)
            if cur is None:
                if seq == 0:  # no cut for this author: a run starts at the root
                    out[author] = (seq, oh)
            elif seq == cur[0] + 1:
                out[author] = (seq, oh)  # contiguous extension (from pin or root)
            # seq <= cur[0]: below/at the pin, or an equivocation sibling — skip
            # seq > cur[0] + 1: beyond a gap — not part of the frontier
        return out

    def all_ops(self) -> list[Op]:
        return [A.Op.from_bytes(r[0]) for r in self.db.execute("SELECT raw FROM ops")]

    # ---- receipts & QCs --------------------------------------------------- #
    def put_receipt(self, r: Receipt) -> None:
        self.db.execute(
            "INSERT OR IGNORE INTO receipts VALUES (?,?,?,?,?,?)",
            (
                r.op_hash,
                r.config_epoch,
                codec.encode(r.ballot.encode()),
                r.signer,
                r.sig,
                r.issue_seq,
            ),
        )
        self.db.commit()

    def _row_to_receipt(self, oh, ep, ballot, signer, sig, seq) -> Receipt:
        return A.Receipt(oh, ep, Ballot.decode(codec.decode(ballot)), int(seq), signer, sig)

    def receipts_for(self, op_hash: bytes) -> list[Receipt]:
        return [
            self._row_to_receipt(*row)
            for row in self.db.execute("SELECT * FROM receipts WHERE op_hash=?", (op_hash,))
        ]

    def all_receipts(self) -> list[Receipt]:
        """Every receipt held, for gossip coverage/diff (M4)."""
        return [self._row_to_receipt(*row) for row in self.db.execute("SELECT * FROM receipts")]

    def get_receipt(
        self, op_hash: bytes, epoch: int, ballot: Ballot, signer: bytes
    ) -> Receipt | None:
        """The exact stored receipt for one (op, epoch, ballot, signer), or None —
        the serve-from-store lookup (finding-17): an idempotent re-issue returns THIS
        instead of re-signing with a fresh issue_seq."""
        row = self.db.execute(
            "SELECT * FROM receipts WHERE op_hash=? AND epoch=? AND ballot=? AND signer=?",
            (op_hash, epoch, codec.encode(ballot.encode()), signer),
        ).fetchone()
        return self._row_to_receipt(*row) if row else None

    def reserve_issue_seq(self, kind: bytes, ident: bytes) -> int:
        """Reserve this signer's issuance-chain position for one artifact and record
        its justification `ident` in ONE COMMIT (finding 18b: gap-free issuance).

        `ident` is the deterministic justification the artifact re-derives from — a
        receipt's `(op_hash, ballot)` (epoch-independent, so a cross-epoch RERECEIPT
        reuses the SAME seq), a watermark's `(floor, epoch)`. If `ident` is already
        reserved, its seq is returned (idempotent — the deterministic re-sign yields
        the identical artifact after a crash); otherwise the next seq is MAX+1 and
        the reservation is written atomically. Because the counter IS the ledger, a
        crash between reserving and signing burns nothing: the seq stays occupied by
        its justification, re-derivable, so an honest chain has no gaps and every
        back-stamp collides with a genuine occupant (which detect_seq_reuse proves)."""
        row = self.db.execute(
            "SELECT seq FROM issuance WHERE kind=? AND ident=?", (kind, ident)
        ).fetchone()
        if row is not None:
            return int(row[0])
        mx = self.db.execute("SELECT MAX(seq) FROM issuance").fetchone()[0]
        seq = (mx or 0) + 1
        self.db.execute("INSERT INTO issuance VALUES (?,?,?)", (seq, kind, ident))
        self.db.commit()
        return seq

    def reserve_receipt_seq(self, op_hash: bytes, ballot: Ballot) -> int:
        """The acceptance-bound issue_seq for a receipt on (op_hash, ballot) — the
        same across epochs (RERECEIPT), a fresh seq for a new acceptance."""
        return self.reserve_issue_seq(b"r", codec.encode([op_hash, ballot.encode()]))

    def reserve_watermark_seq(self, floor: HLC, epoch: int) -> int:
        """The issue_seq for a watermark attesting `floor` at `epoch`."""
        return self.reserve_issue_seq(
            b"w", codec.encode([floor.wall_ms, floor.counter, int(epoch)])
        )

    def issuance_chain(self) -> list[tuple[int, bytes, bytes]]:
        """The signer's issuance ledger `(seq, kind, ident)` in order — the audit
        surface a chain-checking third party (or the node itself) runs. Gapless by
        construction post-18b."""
        return [
            (int(s), k, i)
            for s, k, i in self.db.execute("SELECT seq, kind, ident FROM issuance ORDER BY seq")
        ]

    def issuance_gapless(self) -> bool:
        """The gapless self-check (finding 18b): a well-formed chain is exactly
        seqs 1..N. A gap is a burned seq — a back-stampable hole — impossible under
        the single-transaction reserve flow."""
        seqs = [s for s, _, _ in self.issuance_chain()]
        return seqs == list(range(1, len(seqs) + 1))

    def put_qc(self, qc: QC) -> None:
        self.db.execute(
            "INSERT OR REPLACE INTO qcs VALUES (?,?,?,?,?,?)",
            (
                qc.op_hash,
                qc.config_epoch,
                codec.encode(qc.ballot.encode()),
                qc.signer_bitmap,
                codec.encode(qc.sigs),
                codec.encode(list(qc.issue_seqs)),
            ),
        )
        self.db.commit()

    def _row_to_qc(self, oh, ep, ballot, bitmap, sigs, seqs) -> QC:
        return A.QC(
            oh,
            ep,
            Ballot.decode(codec.decode(ballot)),
            bitmap,
            [codec.as_bytes(x) for x in codec.as_seq(codec.decode(sigs))],
            [codec.as_int(x) for x in codec.as_seq(codec.decode(seqs))],
        )

    def get_qc(self, op_hash: bytes) -> QC | None:
        # deterministic pick when one op holds QCs under several epochs/ballots
        row = self.db.execute(
            "SELECT * FROM qcs WHERE op_hash=? ORDER BY epoch DESC, ballot DESC LIMIT 1",
            (op_hash,),
        ).fetchone()
        return self._row_to_qc(*row) if row else None

    def all_qcs(self) -> list[QC]:
        """Every QC held, for gossip coverage/diff (M4)."""
        return [self._row_to_qc(*row) for row in self.db.execute("SELECT * FROM qcs")]

    # ---- checkpoint cut (the log-compaction boundary; DESIGN §12) ---------- #
    def adopt_checkpoint(
        self,
        cut: Heads,
        retained: dict[bytes, tuple[int, bytes]],
        dead: list[bytes] = [],  # noqa: B006 (read-only default; never mutated)
    ) -> None:
        """Persist the active compaction cut, its `retained` commitment, and the
        `dead` set on observing a quorum-committed checkpoint (WP1.2/1.3). DURABLE
        — the cut re-parametrizes heads()/append()/possession below it, and `dead`
        is the RETAINED-projection mask (covered ∖ dead) the possession and
        completeness checks run against while GC is still lazy; all must survive
        crash-restart like the floor (`set_meta` COMMIT-fsyncs). Physical GC of
        `dead` is a separate step (gc_checkpoint); adoption must precede it so the
        gates never see dropped ops without the cut. Atomic (finding 16): the
        three writes are ONE transaction/COMMIT, so a crash can never leave the cut
        adopted without its retained/dead companions (nothing re-runs adoption)."""
        self.db.execute("INSERT OR REPLACE INTO meta VALUES (?,?)", ("cut", _encode_pairs(cut)))
        self.db.execute(
            "INSERT OR REPLACE INTO meta VALUES (?,?)", ("cut_retained", _encode_pairs(retained))
        )
        self.db.execute(
            "INSERT OR REPLACE INTO meta VALUES (?,?)", ("cut_dead", codec.encode(list(dead)))
        )
        self.db.commit()  # one atomic COMMIT for all three

    def cut(self) -> Heads:
        """The active compaction cut, or {} when uncompacted (pre-M6 behavior)."""
        raw = self.get_meta("cut")
        return _decode_pairs(raw) if raw else {}

    def cut_retained(self) -> dict[bytes, tuple[int, bytes]]:
        """The checkpoint's signed per-author below-cut commitment (the target a
        node's own baseline_commitment() must match to prove completeness)."""
        raw = self.get_meta("cut_retained")
        return _decode_pairs(raw) if raw else {}

    def cut_dead(self) -> frozenset[bytes]:
        """The active checkpoint's `dead` set — masked out of the retained
        projection while GC is lazy (post-GC these ops are gone, so the mask is a
        no-op). Empty when uncompacted."""
        raw = self.get_meta("cut_dead")
        if not raw:
            return frozenset()
        return frozenset(codec.as_bytes(h) for h in codec.as_seq(codec.decode(raw)))

    def baseline_commitment(self) -> dict[bytes, tuple[int, bytes]]:
        """This node's ACTUAL commitment over the RETAINED below-cut projection
        (covered ∖ dead) — compared per author against cut_retained() to prove
        baseline completeness (WP1.2 possession, WP1.3 gossip). Excluding `dead`
        lets a lazy-GC node prove completeness before it has physically dropped
        the superseded ops."""
        return baseline_digest(self.all_ops(), self.cut(), self.cut_dead())

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
    def _store_evidence(self, kind: EvidenceKind, payload: list) -> None:
        self.db.execute(
            "INSERT INTO evidence (kind, data) VALUES (?,?)",
            (kind.value, codec.encode(payload)),
        )
        self.db.commit()

    def evidence(
        self,
    ) -> list[
        tuple[
            EvidenceKind,
            ForkEvidence
            | DoubleVoteEvidence
            | FloorPerjuryEvidence
            | SeqReuseEvidence
            | LostCommitEvidence,
        ]
    ]:
        out: list[
            tuple[
                EvidenceKind,
                ForkEvidence
                | DoubleVoteEvidence
                | FloorPerjuryEvidence
                | SeqReuseEvidence
                | LostCommitEvidence,
            ]
        ] = []
        for kind, data in self.db.execute("SELECT kind, data FROM evidence"):
            k = EvidenceKind(kind)
            p = codec.as_seq(codec.decode(data))
            if k == EvidenceKind.FORK:
                out.append(
                    (
                        k,
                        ForkEvidence(
                            *(
                                codec.as_bytes(p[0]),
                                codec.as_int(p[1]),
                                codec.as_bytes(p[2]),
                                codec.as_bytes(p[3]),
                            )
                        ),
                    )
                )
            elif k == EvidenceKind.DOUBLE_VOTE:
                out.append(
                    (
                        k,
                        DoubleVoteEvidence(
                            codec.as_bytes(p[0]),
                            codec.as_bytes(p[1]),
                            codec.as_bytes(p[2]),
                            A.Receipt.decode(codec.as_bytes(p[3])),
                            A.Receipt.decode(codec.as_bytes(p[4])),
                        ),
                    )
                )
            elif k == EvidenceKind.FLOOR_PERJURY:
                out.append(
                    (
                        k,
                        FloorPerjuryEvidence(
                            codec.as_bytes(p[0]),
                            _wm_from(codec.as_seq(p[1])),
                            A.Receipt.decode(codec.as_bytes(p[2])),
                            codec.as_bytes(p[3]),
                        ),
                    )
                )
            elif k == EvidenceKind.SEQ_REUSE:
                out.append(
                    (
                        k,
                        SeqReuseEvidence(
                            codec.as_bytes(p[0]),
                            codec.as_int(p[1]),
                            codec.as_bytes(p[2]),
                            codec.as_bytes(p[3]),
                            codec.as_bytes(p[4]),
                            codec.as_bytes(p[5]),
                        ),
                    )
                )
            elif k == EvidenceKind.LOST_COMMIT:
                out.append(
                    (
                        k,
                        LostCommitEvidence(
                            A.QC.decode(codec.as_bytes(p[0])),
                            codec.as_int(p[1]),
                            codec.as_bytes(p[2]),
                        ),
                    )
                )
        return out

    def detect_seq_reuse(
        self, watermarks: list[A.Watermark] | None = None
    ) -> list[SeqReuseEvidence]:
        """Scan held receipts + observed `watermarks` for a signer that placed two
        DISTINCT artifacts at one issuance-chain position (signer, issue_seq) — the
        generalized issuance fork (finding 18a): receipt/receipt, receipt/watermark
        (the WM's-own-seq back-stamp), or watermark/watermark. A legitimate
        cross-epoch RERECEIPT (same op_hash+ballot) is exempt. Watermarks ride the
        finality path (not stored artifacts), so the caller supplies the observed
        ones. Mints + persists; idempotent."""
        seen = {
            (ev.signer, ev.issue_seq, frozenset({(ev.kind_a, ev.raw_a), (ev.kind_b, ev.raw_b)}))
            for k, ev in self.evidence()
            if k == EvidenceKind.SEQ_REUSE and isinstance(ev, SeqReuseEvidence)
        }
        by_key: dict[tuple[bytes, int], list] = {}
        for art in [*self.all_receipts(), *(watermarks or [])]:
            by_key.setdefault((art.signer, art.issue_seq), []).append(art)
        found: list[SeqReuseEvidence] = []
        for (signer, seq), group in by_key.items():
            for i in range(len(group)):
                for j in range(i + 1, len(group)):
                    a, b = group[i], group[j]
                    if _art_reissue_key(a) == _art_reissue_key(b):
                        continue  # legitimate re-issue (or identical artifact)
                    ka, ra = _art_pack(a)
                    kb, rb = _art_pack(b)
                    if (signer, seq, frozenset({(ka, ra), (kb, rb)})) in seen:
                        continue
                    found.append(SeqReuseEvidence(signer, seq, ka, ra, kb, rb))
        for ev in found:
            self._store_evidence(
                EvidenceKind.SEQ_REUSE,
                [ev.signer, ev.issue_seq, ev.kind_a, ev.raw_a, ev.kind_b, ev.raw_b],
            )
        return found

    def detect_lost_commits(
        self, recovery_epoch: int, recovery_ckpt_hash: bytes, retained_hashes: frozenset[bytes]
    ) -> list[LostCommitEvidence]:
        """Against a recovery fence (its `recovery_epoch` and the recovery
        checkpoint's `retained_hashes` manifest), scan held QCs for a commitment
        that the fence orphaned — below the fence's epoch AND absent from the
        manifest — and mint + persist a portable LOST_COMMIT record (RESILIENCE §2.2
        step 4). Idempotent."""
        seen = {
            ev.qc.op_hash
            for k, ev in self.evidence()
            if k == EvidenceKind.LOST_COMMIT and isinstance(ev, LostCommitEvidence)
        }
        found: list[LostCommitEvidence] = []
        for qc in self.all_qcs():
            if (
                qc.config_epoch < recovery_epoch
                and qc.op_hash not in retained_hashes
                and qc.op_hash not in seen
            ):
                found.append(LostCommitEvidence(qc, recovery_epoch, recovery_ckpt_hash))
        for ev in found:
            self._store_evidence(
                EvidenceKind.LOST_COMMIT,
                [ev.qc.encode(), ev.recovery_epoch, ev.recovery_ckpt_hash],
            )
        return found

    def detect_floor_perjury(self, watermarks: list[A.Watermark]) -> list[FloorPerjuryEvidence]:
        """Against a set of observed `watermarks`, scan held receipts + ops for a
        signer that receipted an op BENEATH a floor it attested (a B3 violation) and
        mint + persist a portable FLOOR_PERJURY proof. Watermarks are not stored
        artifacts (they ride the finality path), so the caller supplies the ones it
        observed; ops + receipts come from the store. Idempotent."""
        ops = {o.op_hash: o for o in self.all_ops()}
        rc_by_signer: dict[bytes, list[Receipt]] = {}
        for r in self.all_receipts():
            rc_by_signer.setdefault(r.signer, []).append(r)
        seen = {
            (ev.signer, ev.rcpt.op_hash, ev.wm.floor.as_tuple())
            for k, ev in self.evidence()
            if k == EvidenceKind.FLOOR_PERJURY and isinstance(ev, FloorPerjuryEvidence)
        }
        found: list[FloorPerjuryEvidence] = []
        for wm in watermarks:
            for r in rc_by_signer.get(wm.signer, []):
                op = ops.get(r.op_hash)
                if op is None or not (op.hlc < wm.floor):
                    continue
                if r.issue_seq <= wm.issue_seq:
                    continue  # NOT issued after the attestation -> honest, not perjury
                if (wm.signer, r.op_hash, wm.floor.as_tuple()) in seen:
                    continue
                found.append(FloorPerjuryEvidence(wm.signer, wm, r, op.raw))
        for ev in found:
            self._store_evidence(
                EvidenceKind.FLOOR_PERJURY,
                [ev.signer, _wm_fields(ev.wm), ev.rcpt.encode(), ev.op_raw],
            )
        return found

    def detect_double_votes(self) -> list[DoubleVoteEvidence]:
        """Scan held receipts + ops for a signer that receipted two DIFFERENT ops
        on one slot at one ballot (a B1 violation), and mint + persist a portable
        DOUBLE_VOTE proof for each. This is the "assemble both" step (B6): any party
        that gossips in an equivocator's receipts + ops can run it. Idempotent — a
        proof already stored (same signer/ballot/op pair) is not re-minted."""
        ops = {o.op_hash: o for o in self.all_ops()}
        by_key: dict[tuple[bytes, bytes], list[Receipt]] = {}
        for r in self.all_receipts():
            by_key.setdefault((r.signer, codec.encode(r.ballot.encode())), []).append(r)
        seen = {
            (ev.signer, ev.rcpt_a.op_hash, ev.rcpt_b.op_hash)
            for k, ev in self.evidence()
            if k == EvidenceKind.DOUBLE_VOTE and isinstance(ev, DoubleVoteEvidence)
        }
        found: list[DoubleVoteEvidence] = []
        for (signer, _b), rcpts in by_key.items():
            for i in range(len(rcpts)):
                for j in range(i + 1, len(rcpts)):
                    a, b = rcpts[i], rcpts[j]
                    oa, ob = ops.get(a.op_hash), ops.get(b.op_hash)
                    if oa is None or ob is None or oa.slot_tag is None:
                        continue
                    if oa.op_hash != ob.op_hash and oa.slot_tag == ob.slot_tag:
                        if (signer, a.op_hash, b.op_hash) in seen or (
                            signer,
                            b.op_hash,
                            a.op_hash,
                        ) in seen:
                            continue
                        found.append(DoubleVoteEvidence(signer, oa.raw, ob.raw, a, b))
        for ev in found:
            self._store_evidence(
                EvidenceKind.DOUBLE_VOTE,
                [ev.signer, ev.raw_a, ev.raw_b, ev.rcpt_a.encode(), ev.rcpt_b.encode()],
            )
        return found

    # ---- transactional commit boundary (sign-after-fsync) ----------------- #
    def commit(self) -> None:
        self.db.commit()


class SlotState:
    __slots__ = ("promised", "accepted_ballot", "accepted_op")

    def __init__(self, promised: Ballot, accepted_ballot: Ballot | None, accepted_op: bytes | None):
        self.promised = promised  # Ballot
        self.accepted_ballot = accepted_ballot  # Ballot | None
        self.accepted_op = accepted_op  # op_hash bytes | None
