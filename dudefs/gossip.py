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

from .artifacts import HLC, QC, Heads, Op, Receipt
from .store import ChainStore, baseline_digest
from .store import covered as _covered  # the canonical cut boundary (store L2)

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
    retained: dict[bytes, tuple[int, bytes]] = field(default_factory=dict)  # baseline digest


def summary(
    store: ChainStore,
    epoch: int = 0,
    cut: Heads | None = None,
    checkpoint: bytes = b"",
    dead: frozenset[bytes] = frozenset(),
) -> Summary:
    # the advertised baseline commits to the RETAINED projection (covered ∖ dead),
    # so a lazy-GC node and a GC'd node advertise the SAME digest (WP1.3).
    baseline = baseline_digest(store.all_ops(), cut, dead) if cut else {}
    return Summary(
        heads={author: seq for author, (seq, _hh) in store.heads().items()},
        receipts=frozenset((r.op_hash, r.signer) for r in store.all_receipts()),
        qcs=frozenset(qc.op_hash for qc in store.all_qcs()),
        floor=store.get_attested(),
        epoch=epoch,
        checkpoint=checkpoint,
        retained=baseline,
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


# --------------------------------------------------------------------------- #
# Sparse below-cut baseline sync (DESIGN §12 rev 6, PROTOCOL §2)               #
# --------------------------------------------------------------------------- #
# Below the cut the log is SPARSE (retained winners/masks only, gaps where the
# `dead` delta was GC'd), and carries NO receipts/QCs — commitment there is
# certified by the manager-signed checkpoint, not per-op quorum proofs (NOTES
# 29d). So this path is digest-diff + pull-by-hash of author-signed envelopes,
# not the contiguous-run DELTA the dense tail uses.


def pull_baseline(
    dst: ChainStore, src: ChainStore, cut: Heads, dead: frozenset[bytes] = frozenset()
) -> int:
    """Sync the sparse below-cut baseline from `src` into `dst`: compare per-author
    RETAINED projections (covered ∖ dead) and, for each author whose digest differs,
    pull `src`'s retained below-cut ops (envelopes ONLY — no receipts/QCs below the
    cut). Returns how many envelopes were pulled. The digest localizes the diff to
    an author, so a lagging node never refetches the whole 5–10 GB baseline.

    Excluding `dead` is load-bearing (WP1.3): without it a GC'd node and a lazy-GC
    peer disagree every round and re-pull each other's superseded envelopes forever
    (the oscillation bug). Only winners cross the wire, and only on a real diff."""
    dst_digest = baseline_digest(dst.all_ops(), cut, dead)
    src_digest = baseline_digest(src.all_ops(), cut, dead)
    src_below: dict[bytes, list[Op]] = {}
    for o in src.all_ops():
        if _covered(o, cut) and o.op_hash not in dead:
            src_below.setdefault(o.author, []).append(o)
    pulled = 0
    for author, ops in src_below.items():
        if dst_digest.get(author) != src_digest.get(author):
            for o in ops:
                if dst.get_op(o.op_hash) is None:
                    dst.put_op_raw(o)  # author-signed envelope; checkpoint certifies commitment
                    pulled += 1
    return pulled


def verify_baseline(
    store: ChainStore,
    cut: Heads,
    committed: dict[bytes, tuple[int, bytes]],
    dead: frozenset[bytes] = frozenset(),
) -> set[bytes]:
    """Verify a node/client holds the FULL below-cut baseline against the
    checkpoint's signed `retained` commitment (DESIGN §12 intake, NOTES 29c/29d).
    Returns the set of authors whose held baseline doesn't match — empty means
    complete. Compared over the RETAINED projection (covered ∖ dead, NOTES 34 Q2)
    so a node that has adopted the checkpoint but not yet GC'd its `dead` ops still
    verifies complete. A tampered or genuinely partial baseline fails here,
    localized to the author; the checkpoint signature is verified separately."""
    have = baseline_digest(store.all_ops(), cut, dead)
    return {a for a in set(have) | set(committed) if have.get(a) != committed.get(a)}
