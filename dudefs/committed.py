# dudefs/committed.py — the committed-set boundary (review RC-1 / DIRECTIONS D-A).
#
# ONE question, asked once, in a type: "did a QUORUM decide this op, or do I merely HOLD it?"
#
# The store's write path is deliberately unverified — `put_op_raw`, `put_receipt`, `put_qc`
# store whatever arrives, on the theory that CONSUMPTION verifies. That theory is sound, and
# most consumers honour it. RC-1 is the cluster of consumers that did not: they read held
# artifacts as TRUSTED INPUT and inherited "an op I hold is an op the quorum committed".
#
# The fix is deliberately a TYPE and not a helper predicate. A predicate is still one call site
# per consumer and one chance each to forget; a type makes "I forgot to verify" a type error,
# because a consumer that wants committed state cannot be handed held state by accident.
#
# The trap this exists to avoid: `tx.get_qc(op_hash) is not None` is PRESENCE, not verification,
# and `put_qc` is an unverified INSERT OR REPLACE reachable as a first-class wire verb (K-5).
# A presence-based predicate closes F-1/F-2 against an ORPHANED checkpoint and reopens them
# against an active peer who plants a forged QC. Verification is the whole point.

from __future__ import annotations

from collections.abc import Callable
from dataclasses import dataclass

from .artifacts import QC, CheckpointOp, Op

# author-fingerprint -> the roster that was in force at that config epoch.
type Rosters = dict[int, list[bytes]]


def qc_verifies(qc: QC | None, rosters: Rosters) -> bool:
    """Committed proof = a majority of the QC's OWN epoch roster actually signed it (issue #3).

    Verified against the QC's own epoch, NOT the reader's current epoch: an op committed under
    epoch 1 stays committed at epoch 2, so a current-epoch match would silently discard real
    history. (The adopt path layers a STRICTER rule on top — `checkpoint.qc_final` additionally
    requires `qc.config_epoch == view.epoch`, because a checkpoint may only drive GC in the epoch
    that decided it. This is the floor, not the ceiling.)"""
    if qc is None:
        return False
    roster = rosters.get(qc.config_epoch)
    return roster is not None and qc.verify(roster)


@dataclass(frozen=True)
class CommittedSet:
    """Ops a quorum DECIDED — the input every RC-1 consumer actually wants.

    Construct it only via `.of`, which verifies. Consumers take a `CommittedSet` rather than a
    `list[Op]`, so the checker refuses a raw held list at the boundary."""

    ops: list[Op]

    @classmethod
    def of(
        cls, ops: list[Op], qc_for: Callable[[bytes], QC | None], rosters: Rosters
    ) -> CommittedSet:
        """Filter held `ops` down to the committed ones. `qc_for` is a lookup (a `ReadTxn.get_qc`
        or a dict's `.get`) so this stays sans-io and unit-testable.

        TWO ARMS, and the distinction is the point — F-1 exists precisely because it was
        implicit at a call site instead of visible here:

        * **Quorum authority** — data ops AND `CheckpointOp`. A checkpoint's authority to place a
          fold barrier / drive GC comes from its commit QC, never from its author's signature. An
          orphan (authored and stored locally before the drive, then never committed) must NOT be
          admitted; that is F-1.
        * **Chain authority** — every other control op (cert, roster, rotate, wrap-set, endpoint,
          pver). These are root-signed and self-authorizing: the manager chain IS their authority,
          and they are validated positionally by the fold's `ControlReducer`, not by a quorum.
          Requiring a QC here would discard the authorization chain itself."""
        return cls(
            [o for o in ops if not _needs_quorum(o) or qc_verifies(qc_for(o.op_hash), rosters)]
        )

    def __iter__(self):
        return iter(self.ops)

    def __len__(self) -> int:
        return len(self.ops)


def _needs_quorum(op: Op) -> bool:
    """Does this op's authority come from a quorum decision rather than the manager chain?"""
    return not op.is_control or isinstance(op, CheckpointOp)
