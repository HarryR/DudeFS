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


class CompactorDaemon(ClientDaemon):
    """A ClientDaemon that also authors checkpoints. Constructed identically (it is
    provisioned the same way — its Cap.COMPACT cert + back-wrapped keys arrive in the
    control chain); `compact_once` / `run` are the compaction surface. It carries the last
    checkpoint's state forward — reconstructed from its OWN adopted store each pass — so each
    pass is INCREMENTAL and a RESTART resumes incremental rather than re-folding history
    (cost ∝ churn since the last cut, never ∝ history; DESIGN §12 rev 6)."""

    def _author_checkpoint(self, cr: compactor.CompactResult, plan: compactor.CompactionPlan) -> Op:
        """Author the Cap.COMPACT checkpoint op on the compactor's OWN chain (its cert
        authorizes the CHECKPOINT kind), carrying `plan.seq` and sitting on the PUBLIC slot
        `checkpoint_slot_tag(seq)` so the quorum serializes it (WP-F(c)). The `attempts`
        sidecar is sealed under the group key; everything else is the plaintext manifest.
        `cr.cut` IS `plan.cut` (compact echoes the cut it was given), so read it off the result."""
        dk = self.keyring[self.keyepoch]["data_key"]
        with self._lock:
            op = A.CheckpointOp.build(
                author=self.key,
                seq=self._seq,
                prev=self._prev,
                hlc=self._next_hlc(),
                baseline=A.Baseline(cr.cut, A.retained_commitment(cr.retained), frozenset(cr.dead)),
                state_acc=cr.state_acc,
                attempts=compactor.seal_attempts(cr.attempts, dk),
                keyepoch=self.keyepoch,
                horizon=plan.horizon,
                checkpoint_seq=plan.seq,
            )
            with self.store.write_txn() as tx:
                tx.put_op_raw(op)
            self._seq += 1
            self._prev = op.op_hash
        return op

    def compact_once(self) -> bytes | None:
        """One INCREMENTAL compaction pass: sync -> decide (`CompactorView.of(tx).plan(F)`) -> seal
        -> commit+adopt. Returns the committed checkpoint's op_hash, or None when there is nothing
        new+final to seal or the quorum didn't commit. The read is ONE `.of(tx)` boundary and the
        DECISION is pure (testable without a daemon); the store I/O is `_seal`/`_commit_and_adopt`.
        Cost ∝ churn since the last cut, never ∝ history; `prev` reads from the durable store, so a
        restart resumes."""
        self.sync()  # pull the committed log + set the finalized floor F
        with self._lock:
            f = self._final_frontier
        if f == HLC(0, 0):
            return None  # nothing is final yet — no cut to pin
        with self.store.read_txn() as tx:
            view = compactor.CompactorView.of(tx, self.keyring)
        plan = view.plan(f)
        if plan is None:
            return None
        ckpt, cr = self._seal(plan)
        return self._commit_and_adopt(ckpt, cr, plan)

    def _seal(self, plan: compactor.CompactionPlan) -> tuple[Op, compactor.CompactResult]:
        """Fold the prev retained set + only the newly-committed band `(prev_cut, cut]` into a
        CompactResult, and author the Cap.COMPACT checkpoint op on my own chain (WP-F(c) slot)."""
        cr = compactor.compact(plan.prev, plan.committed, plan.cut, self.keyring, self.genesis)
        return self._author_checkpoint(cr, plan), cr

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
            manifest = A.Baseline(cr.cut, A.retained_commitment(cr.retained), frozenset(cr.dead))
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
