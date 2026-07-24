# DudeFS L2 — gossip / anti-entropy (PROTOCOL §2), as PURE functions over stores.
#
# ARCHITECTURE L2 / PROTOCOL §2 / DESIGN §8.
#
# Convergence is a *fixpoint of pairwise merges* (IMPLEMENTATION §6): there is no
# network here, only `summary(store)` (what I hold) and `delta(store, peer)`
# (what I hold that the peer, per its summary, lacks). A gossip round is
# `merge(dst, src)` — apply the delta `src` owes `dst`. Repeat over any connected
# mesh and every store reaches the union; the transport (memory/tcp) merely moves
# the Summary/Delta bags around.
#
# Invariants honored (PROTOCOL §2.1):
#   * Contiguity — ops ship as per-author runs from the peer's head; apply via
#     `store.append`, which refuses a gap and mints fork evidence. No orphan
#     islands cross the wire as heads.
#   * Floors never gate gossip — receipts/QCs replicate regardless of floor
#     (floors gate *issuing* receipts, not storing them).
#   * Receipt coverage is per-(op, signer), not per-op: a node needs a *quorum*
#     of distinct signers to assemble a QC, so a boolean-per-op summary would
#     stall QC assembly. (Bitmap encoding is wire-adjacent, deferred — DESIGN §17.)

from __future__ import annotations

from dataclasses import dataclass, field

from . import artifacts as A
from . import codec
from .artifacts import HLC, QC, Heads, Op, Receipt
from .store import ReadTxn, WriteTxn, baseline_digest

# --------------------------------------------------------------------------- #
# Summary — the compact "what I hold" advertisement (PROTOCOL §2.2)            #
# --------------------------------------------------------------------------- #


@dataclass(frozen=True)
class Summary:
    """What a node advertises in an epidemic round. `heads` is the per-author
    contiguous frontier of the DENSE TAIL (author pubkey -> head seq); `receipts`
    is per-(op, signer) coverage; `qcs` names the ops a QC is held for. Post-M6:
    `checkpoint` names the active cut, and `retained` is the per-author
    (count, digest) of the SPARSE BASELINE below it — the diff key for below-cut
    sync (DESIGN §12, NOTES 29c). `floor`/`epoch` ride along for health (§2.3)."""

    heads: dict[bytes, int]  # author_pub -> highest contiguous seq held (dense tail)
    receipts: frozenset[tuple[bytes, bytes]]  # (op_hash, signer) coverage
    qcs: frozenset[bytes]  # op_hashes a QC is held for
    floor: HLC
    epoch: int
    checkpoint: bytes = b""  # the active checkpoint op_hash (b"" = no compaction)
    retained: dict[bytes, A.RetainedEntry] = field(default_factory=dict)  # baseline digest

    @classmethod
    def of(
        cls,
        tx: ReadTxn,
        epoch: int = 0,
        cut: Heads | None = None,
        checkpoint: bytes = b"",
        dead: frozenset[bytes] = frozenset(),
    ) -> Summary:
        """What a store advertises, from a read snapshot. The baseline commits to the
        RETAINED projection (covered ∖ dead), so a lazy-GC node and a GC'd node advertise
        the SAME digest (WP1.3). Runs in `tx` so heads/receipts/qcs/cut are one instant."""
        baseline = baseline_digest(tx.all_ops(), cut, dead) if cut else {}
        return cls(
            heads={author: seq for author, (seq, _hh) in tx.heads().items()},
            receipts=frozenset((r.op_hash, r.signer) for r in tx.all_receipts()),
            qcs=frozenset(qc.op_hash for qc in tx.all_qcs()),
            floor=tx.get_attested(),
            epoch=epoch,
            checkpoint=checkpoint,
            retained=baseline,
        )

    def encode(self) -> bytes:
        return codec.encode(
            [
                dict(self.heads),
                [[oh, sig] for oh, sig in sorted(self.receipts)],
                sorted(self.qcs),
                list(self.floor.encode()),
                int(self.epoch),
                self.checkpoint,
                {a: [c, d] for a, (c, d) in self.retained.items()},
            ]
        )

    @classmethod
    def decode(cls, data: bytes) -> Summary:
        p = codec.as_seq(codec.decode(data))
        heads = {codec.as_bytes(a): codec.as_int(v) for a, v in codec.as_dict(p[0]).items()}
        receipts = frozenset(
            (codec.as_bytes(pair[0]), codec.as_bytes(pair[1]))
            for pair in (codec.as_seq(x, 2) for x in codec.as_seq(p[1]))
        )
        qcs = frozenset(codec.as_bytes(x) for x in codec.as_seq(p[2]))
        retained: dict[bytes, A.RetainedEntry] = {}
        for a, entry in codec.as_dict(p[6]).items():
            c, dig = codec.as_seq(entry, 2)
            retained[codec.as_bytes(a)] = A.RetainedEntry(codec.as_int(c), codec.as_bytes(dig))
        return cls(
            heads,
            receipts,
            qcs,
            HLC.decode(p[3]),
            codec.as_int(p[4]),
            codec.as_bytes(p[5]),
            retained,
        )


# --------------------------------------------------------------------------- #
# Delta — exactly the diff a Summary exposes (PROTOCOL §2.2)                   #
# --------------------------------------------------------------------------- #


@dataclass(frozen=True)
class Delta:
    ops: tuple[Op, ...]  # contiguous per-author runs the peer lacks (append, contiguity-gated)
    receipts: tuple[Receipt, ...]  # receipts the peer's coverage lacks
    qcs: tuple[QC, ...]  # QCs the peer lacks
    baseline: tuple[Op, ...] = ()  # sparse below-cut RETAINED ops — intake CONTIGUITY-FREE

    @classmethod
    def owed(cls, tx: ReadTxn, peer: Summary) -> Delta:
        """What a store (via read snapshot `tx`) holds that `peer` (per its Summary) lacks.
        Ops honor contiguity: only the run from the peer's head up to ours, per author."""
        ops: list[Op] = []
        for author, (my_head, _hh) in tx.heads().items():
            peer_head = peer.heads.get(author, -1)
            for seq in range(peer_head + 1, my_head + 1):
                ops.extend(tx.get(author, seq))  # fork siblings included — peer mints evidence
        ops.sort(key=lambda o: (o.author, o.seq))  # apply prev-before-successor
        receipts = tuple(r for r in tx.all_receipts() if (r.op_hash, r.signer) not in peer.receipts)
        qcs = tuple(qc for qc in tx.all_qcs() if qc.op_hash not in peer.qcs)
        return cls(tuple(ops), receipts, qcs)

    def apply(self, tx: WriteTxn) -> None:
        """Merge this Delta into `tx` in ONE write transaction. `baseline` ops (sparse
        below-cut retained winners, whose predecessors are legitimately GC'd) intake
        CONTIGUITY-FREE via `put_op_raw` — and FIRST, so the tail's `append` can find its
        predecessors and a fresh node's adoption sees a complete baseline (WP-E / Finding 1:
        breaks the bootstrap-vs-cut deadlock; the checkpoint's `retained` commitment vouches
        for them, and completeness is re-checked at adopt). Tail `ops` go through `append`
        (contiguity gate + fork evidence); a gap/fork op is simply not stored, retried next."""
        for op in self.baseline:
            tx.put_op_raw(op)  # author-signed envelope; no contiguity gate below the cut
        for op in sorted(self.ops, key=lambda o: (o.author, o.seq)):
            tx.append(op)
        for r in self.receipts:
            tx.put_receipt(r)
        for qc in self.qcs:
            tx.put_qc(qc)

    def encode(self) -> bytes:
        return codec.encode(
            [
                [o.raw for o in self.ops],
                [r.encode() for r in self.receipts],
                [qc.encode() for qc in self.qcs],
                [o.raw for o in self.baseline],
            ]
        )

    @classmethod
    def decode(cls, data: bytes) -> Delta:
        p = codec.as_seq(codec.decode(data))
        ops = tuple(A.Op.from_bytes(codec.as_bytes(x)) for x in codec.as_seq(p[0]))
        receipts = tuple(A.Receipt.decode(codec.as_bytes(x)) for x in codec.as_seq(p[1]))
        qcs = tuple(A.QC.decode(codec.as_bytes(x)) for x in codec.as_seq(p[2]))
        baseline = tuple(A.Op.from_bytes(codec.as_bytes(x)) for x in codec.as_seq(p[3]))
        return cls(ops, receipts, qcs, baseline)


# --------------------------------------------------------------------------- #
# Sparse below-cut baseline sync (DESIGN §12 rev 6, PROTOCOL §2)               #
# --------------------------------------------------------------------------- #
# Below the cut the log is SPARSE (retained winners/masks only, gaps where the
# `dead` delta was GC'd), and carries NO receipts/QCs — commitment there is
# certified by the manager-signed checkpoint, not per-op quorum proofs (NOTES
# 29d). So this path is digest-diff + pull-by-hash of author-signed envelopes,
# not the contiguous-run DELTA the dense tail uses.


# --------------------------------------------------------------------------- #
# Wire codec for the epidemic exchange (M7 WP1.2)                              #
# --------------------------------------------------------------------------- #
# A gossip round is one request/response: the initiator sends its Summary, the
# peer replies with the Delta it owes. Serialization is the objects' own encode/decode
# (Summary.encode / Delta.decode), a thin dispatch over the artifacts' own encoders.
