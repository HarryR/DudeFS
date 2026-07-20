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
    NEEDS_BALLOT = auto()  # slotted op sent via SUBMIT — propose via PREPARE/ACCEPT (rev 5)


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
    ):
        self.sk = node_sk
        self.pub = node_pub
        self.store = store
        self.epoch = config_epoch
        self.delta_ms = delta_ms

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
        self.store.commit()  # fsync before signing
        return A.Watermark.issue(self.sk, self.pub, new_att, self.epoch)

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
        if ballot > s.promised:
            s.promised = ballot
            self.store._write_slot(tag, s)
            self.store.commit()  # fsync before signing the promise
            return A.Promise.issue(self.sk, self.pub, tag, ballot, s.accepted_ballot, s.accepted_op)
        return Nack(s.promised)

    # ------------------------------------------------------------------ #
    # ACCEPT — classic Paxos phase 2 (DESIGN §8 recovery)               #
    # ------------------------------------------------------------------ #
    def on_accept(self, tag: bytes, ballot: Ballot, op: Op, now_ms: int) -> AcceptResult:
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
        self.store.put_op_raw(op)  # self-contained, re-proposable
        s.promised = ballot
        s.accepted_ballot = ballot
        s.accepted_op = op.op_hash
        self.store._write_slot(tag, s)
        self._advance_hw(op)
        self.store.commit()  # fsync before signing
        return self._issue_receipt(op.op_hash, ballot)

    def _issue_receipt(self, op_hash: bytes, ballot: Ballot) -> Receipt:
        """Sign a receipt AND persist it. A node holds every receipt it issues so
        gossip can spread it and any node can assemble the QC from a quorum
        (PROTOCOL §2.2, §1.4). Storage is derived from the already-fsynced slot
        state, so it never outlives its justification (RESILIENCE §0)."""
        r = A.Receipt.issue(self.sk, self.pub, op_hash, self.epoch, ballot)
        self.store.put_receipt(r)
        return r
