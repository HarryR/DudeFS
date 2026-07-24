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
from .artifacts import HLC, Op, covered
from .client import ClientDaemon, _drive
from .daemon import _cut_dominates
from .quorum import Commit, Committed
from .store import ReadTxn


class CompactorDaemon(ClientDaemon):
    """A ClientDaemon that also authors checkpoints. Constructed identically (it is
    provisioned the same way — its Cap.COMPACT cert + back-wrapped keys arrive in the
    control chain); `compact_once` / `run` are the compaction surface. It carries the last
    checkpoint's state forward — reconstructed from its OWN adopted store each pass — so each
    pass is INCREMENTAL and a RESTART resumes incremental rather than re-folding history
    (cost ∝ churn since the last cut, never ∝ history; DESIGN §12 rev 6)."""

    @staticmethod
    def _advances(cut: A.Heads, prev_cut: A.Heads) -> bool:
        """Does `cut` move at least one author's frontier past `prev_cut`? (Finality is
        monotone, so no author ever regresses — so this is exactly 'is there new sealed
        work'.) No advance => nothing to compact this pass."""
        return any(seq > prev_cut.get(a, (-1, b""))[0] for a, (seq, _h) in cut.items())

    def _cut_at(self, ops: list[Op], f: HLC) -> A.Heads:
        """The per-author frontier at the finalized floor `f`: the highest-seq op each
        author has authored with `hlc <= f`. Per-author HLC monotonicity (DESIGN §4) makes
        this a contiguous, final cut — everything it covers has `hlc <= f = horizon`."""
        ft = f.as_tuple()
        cut: dict[bytes, tuple[int, bytes]] = {}
        for o in ops:
            if o.hlc.as_tuple() <= ft:
                cur = cut.get(o.author)
                if cur is None or o.seq > cur[0]:
                    cut[o.author] = (o.seq, o.op_hash)
        return cut

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

    def _prev_state(self, tx: ReadTxn) -> tuple[A.Heads, list[Op], dict[bytes, int]]:
        """Reconstruct the previous checkpoint's (cut, retained ops, attempts) from the
        compactor's OWN adopted store — the SINGLE source of truth, so a cold restart resumes
        incremental instead of re-folding history. After adopt+GC the ops still held below the
        cut ARE the retained set (winners + masks + control; dead physically gone). Empty when
        no checkpoint is adopted yet (the genesis pass)."""
        prev_cut = tx.cut()
        if not prev_cut:
            return {}, [], {}
        retained = [o for o in tx.all_ops() if covered(o, prev_cut)]
        attempts: dict[bytes, int] = {}
        h = tx.get_meta("checkpoint")
        op = tx.get_op(h) if h else None
        if isinstance(op, A.CheckpointOp):
            attempts = compactor.open_attempts(op.attempts, self.keyring[op.keyepoch]["data_key"])
        return prev_cut, retained, attempts

    def compact_once(self) -> bytes | None:
        """One INCREMENTAL compaction pass. Returns the committed checkpoint's op_hash, or
        None when there is nothing new+final to seal (no quorum floor / no advance since the
        last cut) or the quorum didn't commit. The band `(prev_cut, cut]` is the only work:
        cost ∝ churn since the last checkpoint, never ∝ history — and `prev_*` is read from the
        durable store, so a restart mid-sequence resumes exactly where it left off."""
        self.sync()  # pull the committed log + set the finalized floor F
        with self._lock:
            f = self._final_frontier
        if f == HLC(0, 0):
            return None  # nothing is final yet — no cut to pin
        with self.store.read_txn() as tx:
            committed = [
                o for o in tx.all_ops() if o.is_control or tx.get_qc(o.op_hash) is not None
            ]
            prev_cut, prev_retained, prev_attempts = self._prev_state(tx)
            seq, committed_cut = self._committed_frontier(tx)
        cut = self._cut_at(committed, f)
        if not cut or not self._advances(cut, prev_cut):
            return None  # no new sealed work since the last checkpoint
        # never author a link that REGRESSES the decided chain head: if my finality F lags the
        # latest committed checkpoint's cut, my cut would not dominate it and the nodes would
        # reject it (WP-F(a) gate) — decided-but-unadoptable = a WEDGE. Skip and retry once my
        # floor catches up, so a lagging concurrent compactor waits rather than wedges.
        if not _cut_dominates(cut, committed_cut):
            return None
        # incremental: fold the previous retained set + only the newly-committed band. The
        # first pass is the degenerate prev = ∅ (compact filters the tail to `(prev_cut, cut]`).
        cr = compactor.compact(
            prev_retained, prev_attempts, prev_cut, committed, self.keyring, self.genesis, cut
        )
        ckpt = self._author_checkpoint(cr, cut, f, seq)
        # SLOTTED commit (WP-F(c)): PREPARE/ACCEPT on checkpoint_slot_tag(seq) — the quorum
        # decrees at most ONE checkpoint per seq, so concurrent compactors cannot diverge. A
        # rival that won the slot -> LostSlot; the next pass retries at the tip. Divergence is
        # impossible by construction, no longer a one-honest-compactor assumption.
        outcome = _drive(Commit(self.cfg, ckpt), self._rpc, stop=self._closing)
        if not isinstance(outcome, Committed):
            return None  # lost the slot / unreachable — retry next pass
        self._store_qc(outcome.qc)  # persist + gossip the commit proof; nodes then adopt
        # adopt into the compactor's OWN store — GC `dead`, persist cut/horizon — so the store
        # below the cut becomes exactly the retained set and a restart resumes incremental.
        with self.store.write_txn() as tx:
            manifest = A.Baseline(cut, A.retained_commitment(cr.retained), frozenset(cr.dead))
            tx.adopt_checkpoint(manifest, f)
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
