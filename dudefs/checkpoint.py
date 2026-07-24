# DudeFS — checkpoint RULES (the WP-F invariants), shared by the node (adopt-side) and the
# compactor (author-side). This module answers "is this checkpoint valid / adoptable / forward?";
# how to BUILD a checkpoint's compacted baseline lives in compactor.py. The node imports this,
# never compactor (it only adopts). Every rule is a PURE function over a CheckpointView whose
# `.of(tx, …)` classmethod is the ONLY store read — so the adoptability invariants (findings
# #4/#5/#8/#10, WP-F(a)) unit-test against a crafted view — no daemon, no sim (HANDOFF-R9 §0).

from __future__ import annotations

from dataclasses import dataclass

from .artifacts import (
    HLC,
    QC,
    Baseline,
    CheckpointOp,
    ControlKind,
    Heads,
    Op,
    checkpoint_slot_tag,
    covered,
)
from .fold import ControlReducer, ControlState
from .store import ReadTxn


def cut_dominates(new: Heads, cur: Heads) -> bool:
    """Does `new` per-author advance-or-hold every author of `cur`? (A checkpoint's cut may add
    authors / higher seqs, but must never take one BACKWARDS — GC past a cut is irreversible,
    WP-F(a)/#4.) Vacuously true against the empty (pre-first-checkpoint) cut."""
    return all((e := new.get(a)) is not None and e[0] >= seq for a, (seq, _h) in cur.items())


# --------------------------------------------------------------------------- #
# The adopt-side decision — a CheckpointView (like Baseline: frozen struct + `.of()` builder +   #
# behaviour) whose `.of(tx)` is the ONLY store read, so `.adoptable` / `.select` / `.overfull_drop`#
# are pure and unit-test with a crafted view (HANDOFF-R9 §0.3).                                    #
# --------------------------------------------------------------------------- #


@dataclass(frozen=True)
class CheckpointView:
    """Everything the node reads to decide which committed checkpoint to adopt: the held ops,
    my adopted cut/horizon, the next seq to look for, the QCs, and the authorization state at
    this position (control ops replayed in `.of`). Behaviour is pure over these fields."""

    ops: list[Op]
    cut: Heads  # my adopted cut (empty before the first checkpoint)
    horizon: HLC  # my adopted horizon
    adopted_seq: int  # the next checkpoint seq to look for (adopted body seq + 1)
    qcs: dict[bytes, QC]  # op_hash -> its commit QC
    epoch: int
    roster: list[bytes]  # this epoch's roster pubkeys (QC verification)
    authz: ControlState  # authorization state at this position (control ops replayed)

    @classmethod
    def of(
        cls, tx: ReadTxn, *, epoch: int, roster: list[bytes], manager_pub: bytes
    ) -> CheckpointView:
        """The ONE store read. Also replays control ops in total order into the authz reducer, so
        `.authorized` needs no further I/O."""
        all_ops = tx.all_ops()
        adopted = tx.get_meta("checkpoint")
        adopted_seq = 0
        if adopted is not None:  # chain from the seq I last adopted
            cur = tx.get_op(adopted)
            adopted_seq = cur.checkpoint_seq + 1 if isinstance(cur, CheckpointOp) else 0
        reducer = ControlReducer(manager_pub, epoch)
        for op in sorted(all_ops, key=lambda o: (o.hlc.as_tuple(), o.op_hash)):
            if op.is_control:
                reducer.observe(op)  # authorization state up to here
        return cls(
            ops=all_ops,
            cut=tx.cut(),
            horizon=tx.get_horizon(),
            adopted_seq=adopted_seq,
            qcs={qc.op_hash: qc for qc in tx.all_qcs()},
            epoch=epoch,
            roster=roster,
            authz=reducer.control,
        )

    def authorized(self, author: bytes, kind: ControlKind) -> bool:
        return self.authz.can_author_control(author, kind)

    def adoptable(self, op: CheckpointOp) -> bool:
        """The full WP-F adoptability predicate — every rule must hold (composed from the named
        predicates below, so a test sees exactly which one rejects)."""
        return all(rule(self, op) for rule in _RULES)

    def candidates(self) -> dict[int, CheckpointOp]:
        """The forward-valid committed checkpoints, one per seq (the slot decrees one per seq)."""
        out: dict[int, CheckpointOp] = {}
        for op in self.ops:
            if isinstance(op, CheckpointOp) and self.adoptable(op):
                out.setdefault(op.checkpoint_seq, op)
        return out

    def select(self) -> CheckpointOp | None:
        """Which adoptable checkpoint to take: the HOT next link if I hold its baseline
        (incremental, applying its `dead` band); else the HIGHEST seq whose signed `retained`
        baseline I hold in FULL — a bootstrap JUMP over links GC'd while I was away. None = defer.
        The verify gate keeps the jump safe: I only leap to a checkpoint I demonstrably satisfy."""
        cands = self.candidates()

        def holds(op: CheckpointOp) -> bool:  # I hold the full below-cut baseline it pins
            return not op.baseline.mismatched(self.ops)

        hot = cands.get(self.adopted_seq)
        if hot is not None and holds(hot):
            return hot
        for seq in sorted(cands, reverse=True):  # jump as far as a held baseline allows
            if seq != self.adopted_seq and holds(cands[seq]):
                return cands[seq]
        return None

    def overfull_drop(self) -> list[bytes]:
        """When `select` defers, the below-cut ops to DROP: for the furthest target I can't verify,
        any author where I hold MORE retained-projection ops than its signed `retained` count is
        carrying stale superseded extras a PULL can never fix (pull only adds). Reload beats
        reconcile: drop that author's whole below-cut set, gossip refetches exactly the winners.
        [] = nothing over-full: a plain lag a later round fills, never destructive."""
        cands = self.candidates()
        if not cands:
            return []
        bl = cands[max(cands)].baseline  # the furthest target I'm trying to reach
        have = Baseline.of(self.ops, bl.cut, bl.dead).retained
        overfull = {a for a, e in have.items() if e.size > bl.retained.get(a, (0, b""))[0]}
        if not overfull:
            return []
        return [o.op_hash for o in self.ops if o.author in overfull and covered(o, bl.cut)]


# ---- the named adoptability rules (pure `(view, op) -> bool`, composed by `.adoptable`) ---- #


def forward(view: CheckpointView, op: CheckpointOp) -> bool:
    """Forward-only (WP-F(a)/#4): seq only advances, horizon is monotone, and the cut per-author
    dominates my adopted cut — GC past a cut and the horizon are both irreversible."""
    return (
        op.checkpoint_seq >= view.adopted_seq
        and op.horizon.as_tuple() >= view.horizon.as_tuple()
        and cut_dominates(op.baseline.cut, view.cut)
    )


def slot_bound(view: CheckpointView, op: CheckpointOp) -> bool:
    """The declared seq must bind the slot the op actually won (WP-F(c)) — else an adversary wins
    slot 0 yet claims seq=5 in the body, jumping the chain."""
    return op.slot_tag == checkpoint_slot_tag(op.checkpoint_seq)


def qc_final(view: CheckpointView, op: CheckpointOp) -> bool:
    """Quorum-committed AND verified (finding #5): a MAJORITY of THIS epoch's roster signed it.
    put_qc stores whatever is gossiped in, so a forged / sub-quorum / wrong-epoch QC must never
    drive a GC on a lie."""
    qc = view.qcs.get(op.op_hash)
    return qc is not None and qc.config_epoch == view.epoch and qc.verify(view.roster)


def minter_authorized(view: CheckpointView, op: CheckpointOp) -> bool:
    """The author held the COMPACT capability at this position (DESIGN §15) — never adopt an
    unauthorized minter's checkpoint."""
    return view.authorized(op.author, ControlKind.CHECKPOINT)


def horizon_covers_cut(view: CheckpointView, op: CheckpointOp) -> bool:
    """The horizon (F, the finality frontier the cut was sealed at) covers EVERY op the checkpoint
    compacts (≤ cut, finding #8): a cut reaching above its horizon would seal a not-yet-final op."""
    return not any(covered(o, op.baseline.cut) and o.hlc > op.horizon for o in view.ops)


_RULES = (forward, slot_bound, qc_final, minter_authorized, horizon_covers_cut)
