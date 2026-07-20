# DudeFS — adversarial sim-node personas (IMPLEMENTATION §6.4 / RESILIENCE §3).
#
# First-class Acceptor subclasses that MISBEHAVE in one specific way each, wired
# into the Sim as ordinary nodes (Sim(personas={i: Cls})). Every persona asserts
# BOTH containment (honest nodes' state is unaffected) AND evidence (the violation
# mints a portable proof — B6 becomes an assertion, not a claim). The TEE
# deployment profile (NOTES 35) makes these node-side personas the priority
# threat, outranking client-side ones.

from __future__ import annotations

from ..acceptor import Acceptor, AcceptResult, Nack, Rejected, RejectReason
from ..artifacts import Ballot, Op


class EquivocatingAcceptor(Acceptor):
    """WP3.1 — signs TWO different ops at one (tag, ballot), the one thing an honest
    acceptor must never do (DESIGN §8). Identical to Acceptor except the
    equivocation guard is dropped, so the node's own two receipts are a portable
    DOUBLE_VOTE proof against it. Containment: a single equivocator never reaches a
    quorum for two ops, so B1 at the quorum level is untouched and the fold
    collapses the duplicates to one winner per slot; only the node is incriminated.
    """

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
        # THE misbehavior: no equivocation guard — it re-signs at the same ballot
        # for a different op, overwriting its accepted slot state.
        self.store.put_op_raw(op)
        s.promised = ballot
        s.accepted_ballot = ballot
        s.accepted_op = op.op_hash
        self.store._write_slot(tag, s)
        self._advance_hw(op)
        self.store.commit()  # fsync before signing
        return self._issue_receipt(op.op_hash, ballot, receipt_epoch)
