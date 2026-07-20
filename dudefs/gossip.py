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

from dataclasses import dataclass

from .artifacts import HLC, QC, Op, Receipt
from .store import ChainStore

# --------------------------------------------------------------------------- #
# Summary — the compact "what I hold" advertisement (PROTOCOL §2.2)            #
# --------------------------------------------------------------------------- #


@dataclass(frozen=True)
class Summary:
    """What a node advertises in an epidemic round. `heads` is the per-author
    contiguous frontier (author pubkey -> head seq); `receipts` is per-(op,
    signer) coverage; `qcs` names the ops a QC is held for. `floor`/`epoch` ride
    along for health (§2.3) and roster awareness — not used by convergence."""

    heads: dict[bytes, int]  # author_pub -> highest contiguous seq held
    receipts: frozenset[tuple[bytes, bytes]]  # (op_hash, signer) coverage
    qcs: frozenset[bytes]  # op_hashes a QC is held for
    floor: HLC
    epoch: int


def summary(store: ChainStore, epoch: int = 0) -> Summary:
    return Summary(
        heads={author: seq for author, (seq, _hh) in store.heads().items()},
        receipts=frozenset((r.op_hash, r.signer) for r in store.all_receipts()),
        qcs=frozenset(qc.op_hash for qc in store.all_qcs()),
        floor=store.get_attested(),
        epoch=epoch,
    )


# --------------------------------------------------------------------------- #
# Delta — exactly the diff a Summary exposes (PROTOCOL §2.2)                   #
# --------------------------------------------------------------------------- #


@dataclass(frozen=True)
class Delta:
    ops: tuple[Op, ...]  # contiguous per-author runs the peer lacks
    receipts: tuple[Receipt, ...]  # receipts the peer's coverage lacks
    qcs: tuple[QC, ...]  # QCs the peer lacks


def delta(store: ChainStore, peer: Summary) -> Delta:
    """What `store` holds that `peer` (per its Summary) lacks. Ops honor
    contiguity: only the run from the peer's head up to ours, per author."""
    ops: list[Op] = []
    for author, (my_head, _hh) in store.heads().items():
        peer_head = peer.heads.get(author, -1)
        for seq in range(peer_head + 1, my_head + 1):
            ops.extend(store.get(author, seq))  # fork siblings included — peer mints evidence
    ops.sort(key=lambda o: (o.author, o.seq))  # apply prev-before-successor
    receipts = tuple(r for r in store.all_receipts() if (r.op_hash, r.signer) not in peer.receipts)
    qcs = tuple(qc for qc in store.all_qcs() if qc.op_hash not in peer.qcs)
    return Delta(tuple(ops), receipts, qcs)


def apply_delta(store: ChainStore, d: Delta) -> None:
    """Merge a received Delta. Ops go through `append` (contiguity gate + fork
    evidence); a gap/fork op is simply not stored and the next round retries."""
    for op in sorted(d.ops, key=lambda o: (o.author, o.seq)):
        store.append(op)
    for r in d.receipts:
        store.put_receipt(r)
    for qc in d.qcs:
        store.put_qc(qc)


def merge(dst: ChainStore, src: ChainStore, dst_epoch: int = 0) -> None:
    """One-directional pull: apply everything `src` holds that `dst` lacks. A
    full epidemic round is `merge` both ways; convergence needs only that every
    pair eventually merges (PROTOCOL §2)."""
    apply_delta(dst, delta(src, summary(dst, dst_epoch)))


def pull_op(dst: ChainStore, src: ChainStore, op_hash: bytes) -> bool:
    """PULL a single op by hash from a peer (the PROTOCOL §1.1 `PULL` essence,
    used for dep resolution — §2.1). Stored contiguity-free: a dep may be
    referenced ahead of its own chain, and the envelope is self-validating.
    Returns whether the op was found at the peer."""
    op = src.get_op(op_hash)
    if op is None:
        return False
    dst.put_op_raw(op)
    return True
