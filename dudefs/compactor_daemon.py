# The compactor DRIVER (R6 WP-G / DESIGN §12). A compactor is a key-holding node-adjacent
# party — a gossip-synced replica that authors real checkpoints. It reuses the ClientDaemon
# machinery it shares (quorum sync, keyring-from-wraps, blind-commit of a slotless op, its
# own authored chain) and adds the compaction pass on top:
#
#   sync the committed log -> pick a FINAL cut (F = the quorum-attested floor) -> compact()
#   -> author a Cap.COMPACT checkpoint op on its own chain -> blind-commit it to a node
#   quorum -> gossip op + QC; the nodes adopt via adopt_committed_checkpoints (horizon
#   advances, `dead` GC'd).
#
# A checkpoint carries no slot, so it commits on the same slotless path a blind PUT uses.
# Cap.COMPACT authorizes ONLY the checkpoint kind, so a rogue compactor can propose junk a
# quorum won't commit and censor — never alter the control hierarchy (issues #2/#3).

from __future__ import annotations

import threading

from . import artifacts as A
from . import compactor
from .artifacts import HLC, Op
from .client import ClientDaemon
from .handlers import control as ctl
from .store import covered


class CompactorDaemon(ClientDaemon):
    """A ClientDaemon that also authors checkpoints. Constructed identically (it is
    provisioned the same way — its Cap.COMPACT cert + back-wrapped keys arrive in the
    control chain); `compact_once` / `run` are the compaction surface."""

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

    def _author_checkpoint(self, cr: compactor.CompactResult, cut: A.Heads, horizon: HLC) -> Op:
        """Author the Cap.COMPACT checkpoint op on the compactor's OWN chain (its cert
        authorizes the CHECKPOINT kind). The `attempts` sidecar is sealed under the group
        key; everything else is the plaintext structural manifest ZK nodes read."""
        dk = self.keyring[self.keyepoch]["data_key"]
        body = ctl.checkpoint_body(
            cut,
            cr.state_acc,
            cr.dead,
            A.retained_commitment(cr.retained),
            compactor.seal_attempts(cr.attempts, dk),
            self.keyepoch,
            horizon,
        )
        with self._lock:
            op = A.Op.build(
                author_sk=self.sk,
                author_pub=self.pub,
                cls_=A.OpClass.CONTROL,
                seq=self._seq,
                prev=self._prev,
                hlc=self._next_hlc(),
                deps=[],
                authz=b"cert",
                keyepoch=self.keyepoch,
                payload=body,
            )
            with self.store.write_txn() as tx:
                tx.put_op_raw(op)
            self._seq += 1
            self._prev = op.op_hash
        return op

    def compact_once(self) -> bytes | None:
        """One compaction pass. Returns the committed checkpoint's op_hash, or None when
        there is nothing final to seal (no quorum floor yet) or the quorum didn't commit."""
        self.sync()  # pull the full committed log + set the finalized floor F
        with self._lock:
            f = self._final_frontier
        if f == HLC(0, 0):
            return None  # nothing is final yet — no cut to pin
        with self.store.read_txn() as tx:
            committed = [
                o for o in tx.all_ops() if o.is_control or tx.get_qc(o.op_hash) is not None
            ]
        cut = self._cut_at(committed, f)
        if not cut:
            return None
        below = [o for o in committed if covered(o, cut)]
        # genesis-first: the whole committed set below the cut. (Incremental compaction
        # from a prior checkpoint is the next step — DESIGN §12 rev 6.)
        cr = compactor.compact_genesis(below, self.keyring, self.genesis, cut)
        ckpt = self._author_checkpoint(cr, cut, f)
        qc = self._commit_blind(ckpt)  # SUBMIT to the roster; assemble a QC of blind receipts
        if qc is None:
            return None  # couldn't reach a quorum this pass — retry next
        self._store_qc(qc)  # persist + gossip the commit proof; nodes then adopt
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
