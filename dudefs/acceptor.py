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
from . import tunables
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
from .store import AppendStatus, ChainStore

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
    UNKNOWN_DEP = auto()  # node lacks a deps-referenced op (SUBMIT only — PROTOCOL §2.1)
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
        node_sk: bytes,
        node_pub: bytes,
        store: ChainStore,
        config_epoch: int = 0,
        delta_ms: int = tunables.DELTA_MS,
        authz: Callable[[bytes], bool] | None = None,
    ):
        self.sk = node_sk
        self.pub = node_pub
        self.store = store
        # the request gate (NOTES 58): `authz(author)` is the node's best-effort view
        # of whether an author may WRITE. None = ungated (the L4 sim + unit tests);
        # the daemon injects a live view so a revoked client's SUBMIT is refused AT
        # THE DOOR, not stored-then-fold-invalid (the resource/DoS hole). The acceptor
        # stays L6-free — it holds a bool callback, not the control vocabulary.
        self.authz = authz
        # config epoch restored from the store (finding 20): epoch stamps every
        # receipt/watermark, so a restart must NOT regress it to the constructor
        # seed. `config_epoch` seeds a VIRGIN store only (get_epoch() is None there).
        persisted_epoch = self.store.get_epoch()
        self.epoch = config_epoch if persisted_epoch is None else persisted_epoch
        self.delta_ms = delta_ms
        # checkpoint horizon (DESIGN §12) restored from the store (finding 19): a
        # crash-restart must NOT reset it to 0, or the void rule + receipt-floor
        # backstop go inert against a below-horizon reborn op. HLC(0,0) pre-adoption.
        self.horizon = self.store.get_horizon()

    # ------------------------------------------------------------------ #
    # Finality floor (DESIGN §9): floor = max(hw, now) − δ, monotone.     #
    # ------------------------------------------------------------------ #
    def floor(self, now_ms: int) -> HLC:
        hw = self.store.get_hw()
        computed = HLC(max(hw.wall_ms, now_ms) - self.delta_ms, 0)
        attested = self.store.get_attested()  # never below what we attested
        return computed if attested <= computed else attested

    def _skew_reason(self, op: Op, now_ms: int) -> RejectReason | None:
        # future gate and past gate on NEW receipts (DESIGN §9)
        if op.hlc.wall_ms > now_ms + self.delta_ms:
            return RejectReason.FUTURE_HLC
        if op.hlc < self.floor(now_ms):
            return RejectReason.BELOW_FLOOR
        return None

    def issue_watermark(self, now_ms: int) -> Watermark:
        """Advance and attest the floor (monotone & durable): a node never signs
        a floor below one it has signed before (DESIGN §9)."""
        fl = self.floor(now_ms)
        att = self.store.get_attested()
        new_att = fl if att <= fl else att
        self.store._write_attested(new_att)
        # reserve the attestation's issuance-chain position + justification (finding
        # 18b) before signing; the deterministic sign re-derives it after a crash.
        seq = self.store.reserve_watermark_seq(new_att, self.epoch)
        self.store.commit()  # fsync before signing
        return A.Watermark.issue(self.sk, self.pub, new_att, self.epoch, seq)

    def issue_frontier(self, now_ms: int) -> FrontierBundle:
        """The signed read primitive (PROTOCOL §1): per-author heads + floor +
        epoch, all signed at one instant (relay-safe, PROTOCOL §7.3)."""
        return A.FrontierBundle.issue(
            self.sk, self.pub, self.store.heads(), None, self.epoch, self.floor(now_ms)
        )

    def _advance_hw(self, op: Op) -> None:
        hw = self.store.get_hw()
        if hw < op.hlc:
            self.store._write_hw(op.hlc)

    # ------------------------------------------------------------------ #
    # SUBMIT — blind-write accept at the BLIND ballot (DESIGN §8, rev 5)  #
    # ------------------------------------------------------------------ #
    def on_submit(self, op: Op, now_ms: int) -> SubmitResult:
        # rev 5 (NOTES item 21): the ballot-0 fast path is gone — a slotted op is
        # proposed via PREPARE/ACCEPT, never SUBMIT. SUBMIT serves blind writes.
        if op.slot_tag is not None:
            return Rejected(RejectReason.NEEDS_BALLOT)
        if not (op.verify_structure() and op.verify_sig(op.author)):
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
        skew = self._skew_reason(op, now_ms)
        if skew:
            return Rejected(skew)

        # deps resolve before acceptance (DESIGN §4 / PROTOCOL §2.1): every
        # referenced op must be present locally — committed or merely stored.
        # M2 rejects; M4 upgrades this to PULL-then-accept. Ballot ACCEPT is
        # exempt (recovery must complete; NOTES item 20).
        for dep in op.deps:
            if self.store.get_op(A.codec.as_bytes(dep)) is None:
                return Rejected(RejectReason.UNKNOWN_DEP)

        # contiguity-checked store for blind writes (PROTOCOL §1.1 `unknown_prev`
        # / §2.1; NOTES item 16) — only a ballot ACCEPT may store an envelope
        # contiguity-free (re-proposal, on_accept below).
        res = self.store.append(op)
        if res.status == AppendStatus.GAP:
            return Rejected(RejectReason.UNKNOWN_PREV)
        if res.status in (AppendStatus.FORK, AppendStatus.INVALID):
            return Rejected(RejectReason.BAD_STRUCTURE)  # fork evidence stored by append

        # blind write: always receipted at the BLIND ballot (DESIGN §8).
        self._advance_hw(op)
        self.store.commit()  # fsync before signing
        return self._issue_receipt(op.op_hash, BLIND)

    # ------------------------------------------------------------------ #
    # PREPARE — classic Paxos phase 1 (DESIGN §8 recovery)               #
    # ------------------------------------------------------------------ #
    def on_prepare(self, tag: bytes, ballot: Ballot) -> PrepareResult:
        s = self.store.get_slot(tag)
        # void rule (NOTES 27, DESIGN §8): a slot whose accepted op is below the
        # checkpoint horizon is dead — a reborn creation tag must not make PREPARE
        # report an ancient decided op that §1.3 would re-propose but that can never
        # re-commit (its hlc is below the floor), a livelock until every node GCs.
        # Discard the accept; the promise reports a fresh slot and the new op wins.
        accepted_hlc: HLC | None = None
        if s.accepted_op is not None:
            acc = self.store.get_op(s.accepted_op)
            if acc is None or acc.hlc < self.horizon:
                s.accepted_ballot = None
                s.accepted_op = None
            else:
                accepted_hlc = acc.hlc  # reported so the client can apply its own guard
        if ballot > s.promised:
            s.promised = ballot
            self.store._write_slot(tag, s)
            self.store.commit()  # fsync before signing the promise
            return A.Promise.issue(
                self.sk, self.pub, tag, ballot, s.accepted_ballot, s.accepted_op, accepted_hlc
            )
        return Nack(s.promised)

    def advance_horizon(self, hlc: HLC) -> None:
        """Raise the checkpoint horizon on observing a quorum-committed checkpoint
        (DESIGN §12): ops below it are GC'd and slot state accepting a below-horizon
        op is void on prepare (the void rule above). Monotone."""
        if hlc > self.horizon:
            self.horizon = hlc

    # ------------------------------------------------------------------ #
    # ACCEPT — classic Paxos phase 2 (DESIGN §8 recovery)               #
    # ------------------------------------------------------------------ #
    def on_accept(
        self, tag: bytes, ballot: Ballot, op: Op, now_ms: int, *, receipt_epoch: int | None = None
    ) -> AcceptResult:
        if not (op.verify_structure() and op.verify_sig(op.author)):
            return Rejected(RejectReason.BAD_STRUCTURE)
        if op.slot_tag != tag:
            return Rejected(RejectReason.BAD_STRUCTURE)
        skew = self._skew_reason(op, now_ms)
        if skew:
            return Rejected(skew)
        s = self.store.get_slot(tag)
        if ballot < s.promised:
            return Nack(s.promised)
        if (
            s.accepted_ballot == ballot
            and s.accepted_op is not None
            and s.accepted_op != op.op_hash
        ):
            # would sign two ops at one (tag, ballot) — the one thing an honest
            # acceptor must never do (DESIGN §8).
            return Rejected(RejectReason.EQUIVOCATION_GUARD)
        # §12 receipt-floor-at-horizon backstop (NOTES 34/Q5 third layer): after GC
        # forgets below-horizon slot state, a late contender must NOT win a fresh
        # receipt for a spent slot. Logically implied by the floor (attested ≥ the
        # sealed F), but restated as an independent, explicit guard. Strict: hlc ==
        # horizon is still committable (== floor passes the past gate). Skipped for
        # an idempotent re-accept of the SAME op (serve-from-store re-issue), so a
        # RERECEIPT across a bridge is never blocked.
        if s.accepted_op != op.op_hash and op.hlc < self.horizon:
            return Rejected(RejectReason.BELOW_HORIZON)
        self.store.put_op_raw(op)  # self-contained, re-proposable
        s.promised = ballot
        s.accepted_ballot = ballot
        s.accepted_op = op.op_hash
        self.store._write_slot(tag, s)
        self._advance_hw(op)
        self.store.commit()  # fsync before signing
        return self._issue_receipt(op.op_hash, ballot, receipt_epoch)

    def _issue_receipt(self, op_hash: bytes, ballot: Ballot, epoch: int | None = None) -> Receipt:
        """Sign a receipt AND persist it. A node holds every receipt it issues so
        gossip can spread it and any node can assemble the QC from a quorum
        (PROTOCOL §2.2, §1.4). Storage is derived from the already-fsynced slot
        state, so it never outlives its justification (RESILIENCE §0). `epoch`
        overrides the node's current epoch — a new-roster node receipts a roster
        op under e+1 before activating (DESIGN §13).

        Serve-from-store (finding-17): a receipt already stored for exactly this
        (op, epoch, ballot) is returned UNCHANGED — re-issuing is idempotent and
        must preserve the original `issue_seq`; re-signing with a fresh seq is the
        crime the perjury proof relies on. A cross-epoch re-issue (RERECEIPT) reuses
        the ACCEPTANCE seq (bound when the op was first accepted, any epoch); only a
        genuinely new acceptance consumes the next monotone issue_seq."""
        ep = self.epoch if epoch is None else epoch
        existing = self.store.get_receipt(op_hash, ep, ballot, self.pub)
        if existing is not None:
            return existing
        # reserve the acceptance-bound seq + justification atomically (finding 18b),
        # THEN sign deterministically — a crash before the receipt is stored
        # re-derives the identical receipt on restart, never a burned seq.
        seq = self.store.reserve_receipt_seq(op_hash, ballot)
        r = A.Receipt.issue(self.sk, self.pub, op_hash, ep, ballot, seq)
        self.store.put_receipt(r)
        return r

    # ------------------------------------------------------------------ #
    # Membership / epoch bridge (DESIGN §13, PROTOCOL §3.1)               #
    # ------------------------------------------------------------------ #
    def activate_epoch(self, new_epoch: int) -> None:
        """Switch config epochs on holding a roster op's joint certificate. Slot
        acceptor state `(promised, accepted_ballot, accepted_op)` is UNTOUCHED — it
        carries across epochs unchanged; the node simply issues receipts, promises,
        and watermarks under `new_epoch` from now on (DESIGN §13). Monotone, and
        DURABLE (finding 20): the new epoch is persisted before any receipt is
        stamped under it, so a restart resumes e+1 instead of regressing to the
        constructor seed and wedging."""
        if new_epoch > self.epoch:
            self.epoch = new_epoch
            self.store.set_epoch(new_epoch)  # single-writer materialization

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
        if not (roster_op.verify_sig(manager_pub) and recovery_ckpt.verify_sig(manager_pub)):
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
        s = self.store.get_slot(target)
        if s.accepted_op is not None and s.accepted_ballot is not None:
            return self._issue_receipt(s.accepted_op, s.accepted_ballot)
        if self.store.get_op(target) is not None:
            return self._issue_receipt(target, BLIND)  # blind op held directly
        return None

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
        heads = self.store.heads()
        cut = self.store.cut()
        committed = self.store.cut_retained()
        have_baseline: dict[bytes, A.RetainedEntry] | None = None  # computed once, lazily
        for author, (seq, head_hash) in sync_frontier.items():
            centry = cut.get(author)
            if centry is not None and seq <= centry[0]:
                if have_baseline is None:
                    have_baseline = self.store.baseline_commitment()
                if have_baseline.get(author) != committed.get(author):
                    return False  # incomplete below-cut baseline for this author
            else:
                cur = heads.get(author)
                if cur is None or cur[0] < seq or self.store.get_op(head_hash) is None:
                    return False
        return True

    def on_roster_accept(
        self,
        tag: bytes,
        ballot: Ballot,
        op: Op,
        sync_frontier: A.Heads,
        new_epoch: int,
        now_ms: int,
    ) -> AcceptResult:
        """A NEW-roster node accepting a roster op (DESIGN §13 step 4): gate on the
        possession barrier, then accept via the ordinary slot machinery but stamp
        the receipt `new_epoch` (e+1). That receipt is simultaneously the agreement
        proof and the data-possession proof — the joint certificate's new half. The
        caller (a manager, L4+) supplies `sync_frontier`/`new_epoch` decoded from the
        op body, so the acceptor stays free of the L6 control vocabulary."""
        if not self.holds_frontier(sync_frontier):
            return Rejected(RejectReason.UNKNOWN_PREV)  # not caught up — PULL, then retry
        return self.on_accept(tag, ballot, op, now_ms, receipt_epoch=new_epoch)
