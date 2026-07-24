# The compactor DRIVER (R6 WP-G / DESIGN §12). A compactor is a key-holding node-adjacent
# party — a gossip-synced replica that authors real checkpoints. It reuses the ClientDaemon
# machinery it shares (quorum sync, keyring-from-wraps, its own authored chain) and adds the
# compaction pass on top:
#
#   sync the committed log -> pick a FINAL cut (F = the quorum-attested floor) -> compact()
#   -> author a Cap.COMPACT checkpoint op on its own chain at the next SEQUENCE -> commit it
#   to a node quorum on the checkpoint slot -> gossip op + QC; the nodes adopt in sequence via
#   adopt_committed_checkpoints (horizon advances, `dead` GC'd).
#
# A checkpoint is SLOTTED by a monotone sequence (`checkpoint_slot_tag(seq)`, WP-F(c)): the
# quorum decrees at most ONE checkpoint per seq, so concurrent compactors cannot commit
# diverging cuts — divergence is impossible by construction, not a one-honest-compactor
# assumption. Cap.COMPACT authorizes ONLY the checkpoint kind, so a rogue compactor can
# propose junk a quorum won't adopt and censor — never alter the control hierarchy (#2/#3).

from __future__ import annotations

import threading

from . import artifacts as A
from . import compactor
from .artifacts import HLC, Op
from .client import ClientDaemon, _drive
from .quorum import Commit, Committed
from .store import ReadTxn


class CompactorDaemon(ClientDaemon):
    """A ClientDaemon that also authors checkpoints. Constructed identically (it is
    provisioned the same way — its Cap.COMPACT cert + back-wrapped keys arrive in the
    control chain); `compact_once` / `run` are the compaction surface. It carries the last
    checkpoint's state forward — reconstructed from its OWN adopted store each pass — so each
    pass is INCREMENTAL and a RESTART resumes incremental rather than re-folding history
    (cost ∝ churn since the last cut, never ∝ history; DESIGN §12 rev 6)."""

    def _committed_frontier(self, tx: ReadTxn) -> tuple[int, A.Heads]:
        """The checkpoint-chain head the QUORUM has decided: (next seq to contend, the latest
        committed checkpoint's cut). Reading committed checkpoints from the synced log — not
        just my own adopted meta — means a compactor that LOST a slot or is a concurrent/
        failover peer contends the next UNCONTENDED seq instead of wedging forever on one a
        rival already decided, and extends the decided CUT rather than a stale local one. Only
        slot-BOUND checkpoints count (slot_tag == the seq's tag), exactly as adoption enforces,
        so a mismatched seq claim can neither force a skip nor move the frontier."""
        best_seq = -1
        best_cut: A.Heads = {}
        h = tx.get_meta("checkpoint")
        own = tx.get_op(h) if h else None
        if isinstance(own, A.CheckpointOp):  # my adopted head (its QC may be GC'd)
            best_seq, best_cut = own.checkpoint_seq, own.baseline.cut
        for op in tx.all_ops():
            if not isinstance(op, A.CheckpointOp):
                continue
            if tx.get_qc(op.op_hash) is None:  # only a COMMITTED checkpoint decides a seq
                continue
            if op.slot_tag != A.checkpoint_slot_tag(op.checkpoint_seq):  # seq must bind its slot
                continue
            if op.checkpoint_seq > best_seq:
                best_seq, best_cut = op.checkpoint_seq, op.baseline.cut
        return best_seq + 1, best_cut

    def _author_checkpoint(
        self, cr: compactor.CompactResult, cut: A.Heads, horizon: HLC, seq: int
    ) -> Op:
        """Author the Cap.COMPACT checkpoint op on the compactor's OWN chain (its cert
        authorizes the CHECKPOINT kind), carrying `seq` and sitting on the PUBLIC slot
        `checkpoint_slot_tag(seq)` so the quorum serializes it (WP-F(c)). The `attempts`
        sidecar is sealed under the group key; everything else is the plaintext manifest."""
        dk = self.keyring[self.keyepoch]["data_key"]
        with self._lock:
            op = A.CheckpointOp.build(
                author=self.key,
                seq=self._seq,
                prev=self._prev,
                hlc=self._next_hlc(),
                baseline=A.Baseline(cut, A.retained_commitment(cr.retained), frozenset(cr.dead)),
                state_acc=cr.state_acc,
                attempts=compactor.seal_attempts(cr.attempts, dk),
                keyepoch=self.keyepoch,
                horizon=horizon,
                checkpoint_seq=seq,
            )
            with self.store.write_txn() as tx:
                tx.put_op_raw(op)
            self._seq += 1
            self._prev = op.op_hash
        return op

    def compact_once(self) -> bytes | None:
        """One INCREMENTAL compaction pass: sync -> decide (`compactor.plan_compaction`) -> seal ->
        commit+adopt. Returns the committed checkpoint's op_hash, or None when there is nothing
        new+final to seal or the quorum didn't commit. The DECISION is pure (testable without a
        daemon); the store I/O is `_seal` / `_commit_and_adopt`. Cost ∝ churn since the last cut,
        never ∝ history; `prev` reads from the durable store, so a restart resumes."""
        self.sync()  # pull the committed log + set the finalized floor F
        with self._lock:
            f = self._final_frontier
        if f == HLC(0, 0):
            return None  # nothing is final yet — no cut to pin
        with self.store.read_txn() as tx:
            committed = [
                o for o in tx.all_ops() if o.is_control or tx.get_qc(o.op_hash) is not None
            ]
            prev = compactor.PrevState.of(tx, self.keyring)
            next_seq, committed_cut = self._committed_frontier(tx)
        plan = compactor.plan_compaction(
            committed, prev, horizon=f, next_seq=next_seq, committed_cut=committed_cut
        )
        if plan is None:
            return None
        ckpt, cr = self._seal(plan)
        return self._commit_and_adopt(ckpt, cr, plan)

    def _seal(self, plan: compactor.CompactionPlan) -> tuple[Op, compactor.CompactResult]:
        """Fold the prev retained set + only the newly-committed band `(prev_cut, cut]` into a
        CompactResult, and author the Cap.COMPACT checkpoint op on my own chain (WP-F(c) slot)."""
        cr = compactor.compact(
            plan.prev.retained,
            plan.prev.attempts,
            plan.prev.cut,
            plan.committed,
            self.keyring,
            self.genesis,
            plan.cut,
        )
        return self._author_checkpoint(cr, plan.cut, plan.horizon, plan.seq), cr

    def _commit_and_adopt(
        self, ckpt: Op, cr: compactor.CompactResult, plan: compactor.CompactionPlan
    ) -> bytes | None:
        """SLOTTED-commit the checkpoint to a node quorum (WP-F(c): the quorum decrees at most ONE
        per seq, so concurrent compactors cannot diverge), then adopt into my OWN store — GC `dead`,
        persist cut/horizon so a restart resumes incremental. None if I lost the slot
        (retry next pass)."""
        outcome = _drive(Commit(self.cfg, ckpt), self._rpc, stop=self._closing)
        if not isinstance(outcome, Committed):
            return None  # lost the slot / unreachable — retry next pass
        self._store_qc(outcome.qc)  # persist + gossip the commit proof; nodes then adopt
        with self.store.write_txn() as tx:
            manifest = A.Baseline(plan.cut, A.retained_commitment(cr.retained), frozenset(cr.dead))
            tx.adopt_checkpoint(manifest, plan.horizon)
            tx.gc_checkpoint(cr.dead)
            tx.set_meta("checkpoint", ckpt.op_hash)
        return ckpt.op_hash

    def run(self, interval_s: float, stop: threading.Event | None = None) -> None:
        """Compact every `interval_s` seconds until `stop` (continuous `compactor run`)."""
        stop = stop or threading.Event()
        while not stop.wait(interval_s):
            try:
                self.compact_once()
            except OSError:
                continue  # transient unreachability; the next tick retries
            if self._closing.is_set():
                return
