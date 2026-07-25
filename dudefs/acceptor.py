# DudeFS L3 — the acceptor (per-slot single-decree agreement, node-side).
#
# ARCHITECTURE L3 / DESIGN §8 (ballots, receipts), §9 (floor/finality).
#
#   on_submit(op)              -> Receipt | Rejected   # blind writes only (rev 5)
#   on_prepare(tag, ballot)    -> Promise | Nack
#   on_accept(tag, ballot, op) -> Receipt | Nack | Rejected
#
# rev 5 (NOTES item 21): the ballot-0 fast path is gone. A slotted op is decided
# only through two-phase Paxos (PREPARE/ACCEPT); SUBMIT carries blind writes.
#
# Tags are opaque; the only operation is equality (zero-knowledge — the node
# never reads a payload). Agreement lives in what the acceptor **refuses to
# sign**; the QC is merely the receipt of it (DESIGN §8). Everything is
# **sign-after-fsync**: the store COMMITs the state change before we sign, so no
# receipt/promise/watermark ever outlives its justification (RESILIENCE §0).
#
# The kernel injects time (`now_ms`) — no clocks inside (IMPLEMENTATION §0).

from __future__ import annotations

from collections.abc import Callable
from enum import Enum, auto

from . import artifacts as A
from . import crypto, tunables
from .artifacts import (
    BLIND,
    HLC,
    Ballot,
    FrontierBundle,
    Op,
    Promise,
    Receipt,
    Watermark,
)
from .store import AppendStatus, ChainStore, ReadTxn, SlotState, WriteTxn

# Any node-side response to a coordination verb (DESIGN §8 / PROTOCOL §1.1).
type SubmitResult = Receipt | Rejected  # blind writes only (rev 5); slotted -> NEEDS_BALLOT
type AcceptResult = Receipt | Nack | Rejected
type PrepareResult = Promise | Nack


class RejectReason(Enum):
    """Why an acceptor refused an op (PROTOCOL §1.1). A typed variant carried in
    Rejected — never a string. Local-only (plain Enum); the wire encoding of a
    REJECTED response is the protocol layer's concern (M3)."""

    BAD_STRUCTURE = auto()  # signature, chain gap, fork mismatch, malformed
    BAD_AUTHZ = auto()
    FUTURE_HLC = auto()  # op.hlc > local_now + δ
    BELOW_FLOOR = auto()  # op.hlc < floor
    UNKNOWN_PREV = auto()  # node lacks the author's prior op
    WRONG_EPOCH = auto()
    EQUIVOCATION_GUARD = auto()  # would double-vote a (tag, ballot); refused
    BELOW_HORIZON = auto()  # op.hlc < checkpoint horizon — §12 receipt-floor backstop
    NEEDS_BALLOT = auto()  # slotted op sent via SUBMIT — propose via PREPARE/ACCEPT (rev 5)
    # L_msg peer-gate refusals (PROTOCOL §7.5) — the requester, not the op. Specific
    # so the refusal says WHY: not "bad authz" but which door check the caller failed.
    NOT_A_MEMBER = auto()  # `from` ∉ current roster / revoked cert — get re-certed, or you're out
    STALE_ENVELOPE = auto()  # envelope ts outside δ — resync your clock, or it was a replay


# ---- non-receipt outcomes ------------------------------------------------- #


class Nack:
    __slots__ = ("promised",)

    def __init__(self, promised: Ballot):
        self.promised = promised


class Rejected:
    __slots__ = ("reason",)

    def __init__(self, reason: RejectReason):
        self.reason = reason


class Acceptor:
    """A storage node's coordination surface + its finality floor. One instance
    per node, over one ChainStore (one durability domain)."""

    def __init__(
        self,
        node: crypto.Keypair,
        store: ChainStore,
        config_epoch: int = 0,
        delta_ms: int = tunables.DELTA_MS,
        authz: Callable[[bytes], bool] | None = None,
    ):
        self.node = node
        self.store = store
        # the request gate (NOTES 58): `authz(author)` is the node's best-effort view
        # of whether an author may WRITE. None = ungated (the L4 sim + unit tests);
        # the daemon injects a live view so a revoked client's SUBMIT is refused AT
        # THE DOOR, not stored-then-fold-invalid (the resource/DoS hole). The acceptor
        # stays L6-free — it holds a bool callback, not the control vocabulary.
        self.authz = authz
        # config epoch (finding 20): the DB is the single source of truth. `get_epoch()`
        # is None only on a VIRGIN store, so we MATERIALIZE the genesis `config_epoch`
        # into the store at construction — after this, every authoritative read (receipt
        # /watermark/frontier stamping, the §8 guards) uses `tx.get_epoch()` and can
        # never regress to a constructor seed. `self.epoch` remains ONLY as the advisory
        # wire cache (NOTES 59: the envelope epoch is diagnostic-never-gate), refreshed
        # after each activation commit; it never justifies a signature or a reject.
        # The checkpoint horizon (finding 19) is likewise read durably at each use
        # (`tx.get_horizon()`), so there is no in-memory horizon to lag a committed
        # adoption.
        with self.store.read_txn() as tx:
            persisted_epoch = tx.get_epoch()
        if persisted_epoch is None:
            persisted_epoch = config_epoch
            with self.store.write_txn() as tx:
                tx.set_epoch(persisted_epoch)  # virgin store: seat the genesis epoch
        self.epoch = persisted_epoch
        self.delta_ms = delta_ms

    def _epoch(self, tx: ReadTxn) -> int:
        """The authoritative config epoch, read from the txn's snapshot. Never None:
        the constructor materializes it on a virgin store and it is monotone thereafter
        (finding 20). Used for every signature-justifying / gating read."""
        e = tx.get_epoch()
        assert e is not None, "epoch is materialized at construction (finding 20)"
        return e

    # ------------------------------------------------------------------ #
    # Finality floor (DESIGN §9): floor = max(hw, now) − δ, monotone.     #
    # ------------------------------------------------------------------ #
    def floor(self, tx: ReadTxn, now_ms: int) -> HLC:
        hw = tx.get_hw()
        computed = HLC(max(hw.wall_ms, now_ms) - self.delta_ms, 0)
        attested = tx.get_attested()  # never below what we attested
        return computed if attested <= computed else attested

    def _skew_reason(self, tx: ReadTxn, op: Op, now_ms: int) -> RejectReason | None:
        # future gate and past gate on NEW receipts (DESIGN §9)
        if op.hlc.wall_ms > now_ms + self.delta_ms:
            return RejectReason.FUTURE_HLC
        if op.hlc < self.floor(tx, now_ms):
            return RejectReason.BELOW_FLOOR
        return None

    def issue_watermark(self, now_ms: int) -> Watermark:
        """Advance and attest the floor (monotone & durable): a node never signs
        a floor below one it has signed before (DESIGN §9)."""
        with self.store.write_txn() as tx:
            fl = self.floor(tx, now_ms)
            att = tx.get_attested()
            new_att = fl if att <= fl else att
            tx.write_attested(new_att)
            # reserve the attestation's issuance-chain position + justification
            # (finding 18b) inside the txn; the deterministic sign after COMMIT
            # re-derives the identical watermark on a crash (it is not stored). Capture
            # the epoch IN the txn so the seq's justification and the signed epoch are
            # the same value — a concurrent activation cannot slip between them.
            ep = self._epoch(tx)
            seq = tx.reserve_watermark_seq(new_att, ep)
        return A.Watermark.issue(self.node, new_att, ep, seq)

    def issue_frontier(self, now_ms: int) -> FrontierBundle:
        """The signed read primitive (PROTOCOL §1): per-author heads + floor +
        epoch, all signed at one instant (relay-safe, PROTOCOL §7.3)."""
        with self.store.read_txn() as tx:
            heads, fl, ep = tx.heads(), self.floor(tx, now_ms), self._epoch(tx)
        return A.FrontierBundle.issue(self.node, heads, None, ep, fl)

    def _advance_hw(self, tx: WriteTxn, op: Op) -> None:
        hw = tx.get_hw()
        if hw < op.hlc:
            tx.write_hw(op.hlc)

    # ------------------------------------------------------------------ #
    # SUBMIT — blind-write accept at the BLIND ballot (DESIGN §8, rev 5)  #
    # ------------------------------------------------------------------ #
    def on_submit(self, op: Op, now_ms: int) -> SubmitResult:
        # rev 5 (NOTES item 21): the ballot-0 fast path is gone — a slotted op is
        # proposed via PREPARE/ACCEPT, never SUBMIT. SUBMIT serves blind writes.
        if isinstance(op, A.Slotted):
            return Rejected(RejectReason.NEEDS_BALLOT)
        if not (op.verify_structure() and op.verify_sig()):
            return Rejected(RejectReason.BAD_STRUCTURE)
        # the request gate (NOTES 58/60): refuse a non-authorized REQUESTER at the
        # door — best-effort, fail-closed until the cert propagates (NOTES 59), the
        # fold is authoritative. For SUBMIT the requester IS the author, so gating on
        # the author is exact here. PREPARE/ACCEPT stay ungated: the gate authorizes
        # the requester, never an artifact's author, so it must not block a proposer
        # carrying a (possibly since-revoked) author's op through recovery (PROTOCOL
        # §2.1; RESILIENCE §3.4 makes the same trade at the fold). L_msg (step 6)
        # makes every verb requester-gated on the envelope `from` — wedge-free.
        if self.authz is not None and not self.authz(op.author):
            return Rejected(RejectReason.BAD_AUTHZ)
        # skew check, dep resolution, the contiguity-checked store, and the receipt
        # are ONE write transaction — the COMMIT fsyncs before the receipt is returned
        # (sign-after-fsync), and the receipt lands atomically with the op it attests.
        with self.store.write_txn() as tx:
            skew = self._skew_reason(tx, op, now_ms)
            if skew:
                return Rejected(skew)
            # contiguity-checked store for blind writes (PROTOCOL §1.1 `unknown_prev`
            # / §2.1; NOTES item 16) — only a ballot ACCEPT may store an envelope
            # contiguity-free (re-proposal, on_accept below).
            res = tx.append(op)
            if res.status == AppendStatus.GAP:
                return Rejected(RejectReason.UNKNOWN_PREV)
            if res.status in (AppendStatus.FORK, AppendStatus.INVALID):
                return Rejected(RejectReason.BAD_STRUCTURE)  # fork evidence stored by append
            # blind write: always receipted at the BLIND ballot (DESIGN §8).
            self._advance_hw(tx, op)
            receipt = self._issue_receipt(tx, op.op_hash, BLIND)
        return receipt

    # ------------------------------------------------------------------ #
    # PREPARE — classic Paxos phase 1 (DESIGN §8 recovery)               #
    # ------------------------------------------------------------------ #
    def on_prepare(self, tag: bytes, ballot: Ballot) -> PrepareResult:
        with self.store.write_txn() as tx:
            s = tx.get_slot(tag)
            # void rule (NOTES 27, DESIGN §8): a slot whose accepted op is BELOW THE
            # CHECKPOINT HORIZON is dead — a reborn creation tag must not make PREPARE
            # report an ancient decided op that §1.3 would re-propose but can never
            # re-commit (its hlc is below the floor), a livelock until every node GCs.
            # Discard the accept; the promise reports a fresh slot and the new op wins.
            #
            # The horizon is the SOLE void authority (review C-1), and the test is TOTAL
            # (FIX-1): the accepted op's hlc lives in the slot state, so this never consults
            # the envelope. That matters because the envelope legitimately disappears — the
            # adopt path raises the horizon and GCs the `dead` band in ONE txn, and a slot's
            # accepted op can be in `dead` (it won its slot but folded STALE). Deciding from
            # the envelope made this predicate PARTIAL, and BOTH answers to the undefined case
            # are unsafe: voiding on absence is slot amnesia (two QCs for one slot, no
            # evidence), refusing to void re-opens the NOTES 27 livelock — permanently, since
            # GC would then be what CAUSES it. With the hlc held here there is no undefined
            # case, and `accepted_hlc` is always reportable for the client's own guard.
            if s.accepted_hlc is not None and s.accepted_hlc < tx.get_horizon():
                s.accepted_ballot = s.accepted_op = s.accepted_hlc = None
            if ballot <= s.promised:
                return Nack(s.promised)  # no write; the txn commits empty
            s.promised = ballot
            tx.write_slot(tag, s)
            accepted_ballot, accepted_op = s.accepted_ballot, s.accepted_op
            accepted_hlc = s.accepted_hlc
        # promised ballot is now durable; sign the promise (re-derivable, not stored)
        return A.Promise.issue(self.node, tag, ballot, accepted_ballot, accepted_op, accepted_hlc)

    def advance_horizon(self, hlc: HLC) -> None:
        """Raise the DURABLE checkpoint horizon on observing a quorum-committed
        checkpoint (DESIGN §12): ops below it are GC'd and slot state accepting a
        below-horizon op is void on prepare (the void rule above). Monotone, and
        persisted so the guards (which read `tx.get_horizon()`) never lag it."""
        with self.store.write_txn() as tx:
            tx.advance_horizon(hlc)

    # ------------------------------------------------------------------ #
    # ACCEPT — classic Paxos phase 2 (DESIGN §8 recovery)               #
    # ------------------------------------------------------------------ #
    # ---- the named ACCEPT guards (DIRECTIONS D-B) -------------------------- #
    # Pure predicates over `(slot state, ballot, op)`. Each names the ONE thing it stops, so a
    # test can exercise it directly and a subclass can replace exactly one.

    @staticmethod
    def _verbatim_reaccept(s: SlotState, ballot: Ballot, op: Op) -> bool:
        """Is this the SAME op at the SAME ballot we already accepted — a dropped/retried
        transmit rather than a new proposal? Such a request cannot mint a new artifact:
        `_issue_receipt` serves the stored receipt for `(op, epoch, ballot)` at its ORIGINAL
        `issue_seq`, so it re-yields the receipt the caller lost (PROTOCOL §0 idempotence) and
        creates no new decree. Only then may the future/floor gate be skipped.

        The op alone is NOT enough (review FIX-6). `reserve_receipt_seq` idents on
        `(op_hash, ballot)`, so a re-ACCEPT at a DIFFERENT ballot mints a receipt at a FRESH
        `issue_seq`; past δ that receipt sits below a floor this node has already attested, with
        a higher seq than the watermark — precisely `FloorPerjuryEvidence`. Exempting it makes an
        honest node convict ITSELF and reopens finding 17: the past gate is exactly what makes
        that pair structurally unproducible."""
        return s.accepted_op == op.op_hash and s.accepted_ballot == ballot

    @staticmethod
    def _equivocates(s: SlotState, ballot: Ballot, op: Op) -> bool:
        """Would accepting sign a SECOND, different op at one `(tag, ballot)` — the one thing an
        honest acceptor must never do (DESIGN §8)? Its own two receipts would be a portable
        DOUBLE_VOTE proof against it. This is the single predicate `_personas`' equivocator
        overrides; everything else it does is inherited, so it cannot drift from the honest path."""
        return (
            s.accepted_ballot == ballot
            and s.accepted_op is not None
            and s.accepted_op != op.op_hash
        )

    @staticmethod
    def _below_horizon(tx: WriteTxn, s: SlotState, op: Op) -> bool:
        """§12 receipt-floor-at-horizon backstop (NOTES 34/Q5, third layer): after GC forgets
        below-horizon slot state, a late contender must NOT win a fresh receipt for a spent slot.
        Logically implied by the floor (attested ≥ the sealed F), restated as an explicit guard.
        STRICT: `hlc == horizon` is still committable (`== floor` passes the past gate). Skipped
        for an idempotent re-accept of the SAME op, so a RERECEIPT is never blocked."""
        return s.accepted_op != op.op_hash and op.hlc < tx.get_horizon()

    def on_accept(
        self, tag: bytes, ballot: Ballot, op: Op, now_ms: int, *, receipt_epoch: int | None = None
    ) -> AcceptResult:
        if not (op.verify_structure() and op.verify_sig()):
            return Rejected(RejectReason.BAD_STRUCTURE)
        if not isinstance(op, A.Slotted) or op.slot_tag != tag:
            return Rejected(RejectReason.BAD_STRUCTURE)
        with self.store.write_txn() as tx:
            s = tx.get_slot(tag)
            # The guards are NAMED PREDICATES (DIRECTIONS D-B), mirroring checkpoint.py's
            # `_RULES` decomposition: each states the one attack it stops, each is testable in
            # isolation, and an adversarial persona overrides exactly ONE instead of hand-copying
            # this whole body (which is how `accepted_hlc` nearly got missed in _personas).
            if not self._verbatim_reaccept(s, ballot, op):
                skew = self._skew_reason(tx, op, now_ms)
                if skew:
                    return Rejected(skew)
            if ballot < s.promised:
                return Nack(s.promised)
            if self._equivocates(s, ballot, op):
                return Rejected(RejectReason.EQUIVOCATION_GUARD)
            if self._below_horizon(tx, s, op):
                return Rejected(RejectReason.BELOW_HORIZON)
            tx.put_op_raw(op)  # self-contained, re-proposable
            s.promised = ballot
            s.accepted_ballot = ballot
            s.accepted_op = op.op_hash
            s.accepted_hlc = op.hlc  # denormalized WITH the accept, so the void rule is total
            tx.write_slot(tag, s)
            self._advance_hw(tx, op)
            receipt = self._issue_receipt(tx, op.op_hash, ballot, receipt_epoch)
        return receipt

    def _issue_receipt(
        self, tx: WriteTxn, op_hash: bytes, ballot: Ballot, epoch: int | None = None
    ) -> Receipt:
        """Sign a receipt AND persist it inside the caller's write transaction — the
        receipt lands atomically with the slot state that justifies it, and the
        COMMIT (when the caller's `write_txn` exits) fsyncs before it is returned, so
        it never outlives its justification (RESILIENCE §0). A node holds every
        receipt it issues so gossip can spread it and any node can assemble the QC
        from a quorum (PROTOCOL §2.2, §1.4). `epoch` overrides the node's current
        epoch — a new-roster node receipts a roster op under e+1 (DESIGN §13).

        Serve-from-store (finding-17): a receipt already stored for exactly this
        (op, epoch, ballot) is returned UNCHANGED — re-issuing is idempotent and
        must preserve the original `issue_seq`; re-signing with a fresh seq is the
        crime the perjury proof relies on. A cross-epoch re-issue (RERECEIPT) reuses
        the ACCEPTANCE seq (bound when the op was first accepted, any epoch); only a
        genuinely new acceptance consumes the next monotone issue_seq."""
        ep = self._epoch(tx) if epoch is None else epoch
        existing = tx.get_receipt(op_hash, ep, ballot, self.node.public)
        if existing is not None:
            return existing
        # reserve the acceptance-bound seq + justification (finding 18b), sign
        # deterministically, and store — all in the caller's txn. A crash before the
        # COMMIT rolls it all back; the retry re-derives the identical receipt.
        seq = tx.reserve_receipt_seq(op_hash, ballot)
        r = A.Receipt.issue(self.node, op_hash, ep, ballot, seq)
        tx.put_receipt(r)
        return r

    # ------------------------------------------------------------------ #
    # Membership / epoch bridge (DESIGN §13, PROTOCOL §3.1)               #
    # ------------------------------------------------------------------ #
    def activate_epoch(self, new_epoch: int) -> None:
        """Switch config epochs on holding a roster op's joint certificate. Slot
        acceptor state `(promised, accepted_ballot, accepted_op)` is UNTOUCHED — it
        carries across epochs unchanged; the node simply issues receipts, promises,
        and watermarks under `new_epoch` from now on (DESIGN §13). Monotone, and
        DURABLE (finding 20): the new epoch is persisted BEFORE `self.epoch` is
        advanced, so a rollback (or crash) can never leave the advisory cache ahead of
        the store — every receipt/watermark reads `tx.get_epoch()`, so it is stamped
        under e+1 only once e+1 is durable, and a restart resumes e+1 rather than
        regressing and wedging."""
        with self.store.write_txn() as tx:
            if new_epoch <= self._epoch(tx):
                return  # monotone: never regress the durable epoch
            tx.set_epoch(new_epoch)  # single-writer materialization, durable FIRST
        self.epoch = new_epoch  # advisory wire cache, refreshed only AFTER commit

    def on_recovery_fence(
        self,
        roster_op: Op,
        recovery_ckpt: Op,
        new_epoch: int,
        recovery_hash: bytes,
        manager_pub: bytes,
    ) -> bool:
        """The recovery trigger / activation-is-the-park (DESIGN §13 recovery
        exception, NOTES 36a). A ROOT-signed pair — a recovery checkpoint and a
        ROSTER op naming it via its `recovery` field — SUBSTITUTES for the joint
        certificate to activate `new_epoch`. There is deliberately no joint QC (a
        quorum may be gone — that is what recovery is for), so the acceptor trusts
        the root signature on the pair; fiat is root-only, so a delegate's recovery
        op never reaches a valid fence (it also folds invalid). The park is
        EMERGENT, not a separate rule: once activated the node stamps every
        receipt/watermark at e+1 and old-epoch coordination dies wherever the fence
        propagates. Distinct from the possession barrier (`on_roster_accept`, which
        gates JOINING the new roster); this fence parks everyone who sees it.
        Monotone (`activate_epoch`): replaying a fence for a passed epoch is a
        no-op. Returns whether the pair is a valid fence."""
        if roster_op.author != manager_pub or recovery_ckpt.author != manager_pub:
            return False  # fiat is root-only
        if not (roster_op.verify_sig() and recovery_ckpt.verify_sig()):
            return False
        if recovery_hash != recovery_ckpt.op_hash:
            return False  # the roster must name THIS checkpoint (the pairing)
        self.activate_epoch(new_epoch)  # monotone; a passed epoch is a no-op
        return True

    def on_rereceipt(self, target: bytes) -> Receipt | None:
        """RERECEIPT (PROTOCOL §1.1): re-issue a receipt under the node's CURRENT
        epoch for an op/slot it already holds, so a client can assemble a fresh
        single-epoch QC for an op that was in-flight across a roster change (DESIGN
        §13). Idempotent — the slot state is untouched. `target` is a slot_tag
        (re-receipt its accepted op at its accepted ballot) or a blind op_hash."""
        with self.store.write_txn() as tx:
            s = tx.get_slot(target)
            if s.accepted_op is not None and s.accepted_ballot is not None:
                receipt = self._issue_receipt(tx, s.accepted_op, s.accepted_ballot)
            elif tx.get_op(target) is not None:
                receipt = self._issue_receipt(tx, target, BLIND)  # blind op held directly
            else:
                return None
        return receipt

    def holds_frontier(self, sync_frontier: A.Heads) -> bool:
        """The data-possession barrier (DESIGN §13): does this node hold every
        committed op at or below `sync_frontier`? A new-roster node's receipt
        must prove possession, not just agreement; a node that fails this PULLs
        to baseline and retries.

        Cut-aware (WP1.2 / finding 11): a frontier entry AT-OR-BELOW the active
        cut may name an envelope that was legitimately GC'd, so requiring the
        exact op there would wedge a roster change forever (an idle author whose
        whole chain sits below the cut). Below/at the cut, possession = the node
        holds the COMPLETE below-cut baseline for that author (its retained
        digest matches the checkpoint commitment); ABOVE the cut, the per-op
        check stands (contiguous head reaches the seq AND holds the exact op)."""
        with self.store.read_txn() as tx:
            heads = tx.heads()
            cut = tx.cut()
            committed = tx.cut_retained()
            have_baseline: dict[bytes, A.RetainedEntry] | None = None  # computed once, lazily
            for author, (seq, head_hash) in sync_frontier.items():
                centry = cut.get(author)
                if centry is not None and seq <= centry.seq:
                    if have_baseline is None:
                        have_baseline = tx.baseline_commitment()
                    if have_baseline.get(author) != committed.get(author):
                        return False  # incomplete below-cut baseline for this author
                else:
                    cur = heads.get(author)
                    if cur is None or cur.seq < seq or tx.get_op(head_hash) is None:
                        return False
            return True

    def on_roster_accept(
        self,
        tag: bytes,
        ballot: Ballot,
        op: Op,
        _sync_frontier: A.Heads,
        _new_epoch: int,
        now_ms: int,
    ) -> AcceptResult:
        """A NEW-roster node accepting a roster op (DESIGN §13 step 4): gate on the possession
        barrier, then accept via the ordinary slot machinery but stamp the receipt e+1. That
        receipt is simultaneously the agreement proof and the data-possession proof — the joint
        certificate's new half.

        The acceptor trusts ONLY the signed op body (review K-2): the possession frontier and
        the new epoch are read from `op`, NEVER the requester's wire values (`_sync_frontier`/
        `_new_epoch`) — an empty wire frontier would otherwise make the barrier vacuous. In the
        legit flow the manager authors the same frontier it sends, so this is transparent; it
        only refuses a requester whose wire values disagree with the op it carries. Only a
        RosterOp at the node's CURRENT epoch activates a new one (DESIGN §13)."""
        if not isinstance(op, A.RosterOp):
            return Rejected(RejectReason.BAD_STRUCTURE)  # only a roster op activates a new epoch
        if op.from_epoch != self.epoch:
            return Rejected(RejectReason.BAD_STRUCTURE)  # §13: receipt only when from_epoch == e
        if not self.holds_frontier(op.sync_frontier):
            return Rejected(RejectReason.UNKNOWN_PREV)  # not caught up — PULL, then retry
        return self.on_accept(tag, ballot, op, now_ms, receipt_epoch=op.from_epoch + 1)
