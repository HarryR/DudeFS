# Adversarial Acceptor personas — test doubles (IMPLEMENTATION §6.4 / RESILIENCE §3).
#
# First-class Acceptor subclasses that MISBEHAVE in one specific way each. Every persona
# asserts BOTH containment (honest nodes' state is unaffected) AND evidence (the violation
# mints a portable proof — B6 becomes an assertion, not a claim). The TEE deployment profile
# (NOTES 35) makes these node-side personas the priority threat, outranking client-side ones.
#
# These subclass the REAL Acceptor (not a sim double), so they drive the production evidence
# path directly (test_daemon's detector tests wire them into a live NodeDaemon).

from __future__ import annotations

from dudefs import store
from dudefs.acceptor import Acceptor, RejectReason
from dudefs.artifacts import Ballot, Op


class EquivocatingAcceptor(Acceptor):
    """WP3.1 — signs TWO different ops at one (tag, ballot), the one thing an honest
    acceptor must never do (DESIGN §8). Identical to Acceptor except the
    equivocation guard is dropped, so the node's own two receipts are a portable
    DOUBLE_VOTE proof against it. Containment: a single equivocator never reaches a
    quorum for two ops, so B1 at the quorum level is untouched and the fold
    collapses the duplicates to one winner per slot; only the node is incriminated.
    """

    @staticmethod
    def _equivocates(s: store.SlotState, ballot: Ballot, op: Op) -> bool:
        """THE misbehavior, and the WHOLE of it (DIRECTIONS D-B): the honest predicate refuses
        to sign a second, different op at one (tag, ballot); this one never refuses.

        Everything else — the skew gate, the ballot check, the below-horizon backstop, the slot
        write, the receipt issuance — is INHERITED, so the persona cannot drift from the honest
        path. It previously hand-copied the entire `on_accept` body to drop this one line, which
        meant every field the honest path denormalized into SlotState had to be mirrored by hand
        (`accepted_hlc`, FIX-1, nearly was not)."""
        return False


class FloorPerjurer(Acceptor):
    """WP3.2 — attests a finality floor, then receipts an op BENEATH it, breaking
    the finality promise (B3 / DESIGN §9). It drops the PAST half of the skew gate
    (keeping the future gate), so it signs below-floor ops; its own watermark plus
    that receipt are a portable FLOOR_PERJURY proof. Containment: an honest quorum
    never finalizes below its own floor, so honest finality still converges — only
    the perjurer is incriminated."""

    def _skew_reason(self, tx: store.ReadTxn, op: Op, now_ms: int) -> RejectReason | None:
        # only the future gate; the past gate (op.hlc < floor) is what it perjures.
        if op.hlc.wall_ms > now_ms + self.delta_ms:
            return RejectReason.FUTURE_HLC
        return None
