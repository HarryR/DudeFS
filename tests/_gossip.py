# Two-store gossip helpers — TEST UTILITIES (not production).
#
# These sync two ChainStores DIRECTLY, composing the real gossip logic (Summary.of /
# Delta.owed / apply, pull-by-hash) but bypassing the wire (no L_msg envelope, no gate,
# no transport). Production gossip goes through the daemon serve path; these are the
# convenience drivers the property/chaos suites use to converge stores by hand. They have
# ZERO production callers, so they live here rather than in dudefs/gossip.py.

from __future__ import annotations

from dudefs.artifacts import Heads, Op
from dudefs.gossip import Delta, Summary
from dudefs.store import ChainStore, baseline_digest, covered


def merge(dst: ChainStore, src: ChainStore, dst_epoch: int = 0) -> None:
    """One-directional pull: apply everything `src` holds that `dst` lacks. A full
    epidemic round is `merge` both ways; convergence needs only that every pair eventually
    merges (PROTOCOL §2). Each store access is its own transaction — the peer read is not
    held across the local write."""
    with dst.read_txn() as dtx:
        summ = Summary.of(dtx, dst_epoch)
    with src.read_txn() as stx:
        d = Delta.owed(stx, summ)
    with dst.write_txn() as dtx:
        d.apply(dtx)


def pull_op(dst: ChainStore, src: ChainStore, op_hash: bytes) -> bool:
    """PULL a single op by hash from a peer (the PROTOCOL §1.1 `PULL` essence, used for dep
    resolution — §2.1). Stored contiguity-free: a dep may be referenced ahead of its own
    chain, and the envelope is self-validating. Returns whether the op was found at the peer."""
    with src.read_txn() as stx:
        op = stx.get_op(op_hash)
    if op is None:
        return False
    with dst.write_txn() as dtx:
        dtx.put_op_raw(op)
    return True


def pull_baseline(
    dst: ChainStore, src: ChainStore, cut: Heads, dead: frozenset[bytes] = frozenset()
) -> int:
    """Sync the sparse below-cut baseline from `src` into `dst`: compare per-author RETAINED
    projections (covered ∖ dead) and, for each author whose digest differs, pull `src`'s
    retained below-cut ops (envelopes ONLY — no receipts/QCs below the cut). Returns how many
    envelopes were pulled. The digest localizes the diff to an author, so a lagging node never
    refetches the whole 5–10 GB baseline.

    Excluding `dead` is load-bearing (WP1.3): without it a GC'd node and a lazy-GC peer
    disagree every round and re-pull each other's superseded envelopes forever (the
    oscillation bug). Only winners cross the wire, and only on a real diff."""
    with dst.read_txn() as dtx:
        dst_digest = baseline_digest(dtx.all_ops(), cut, dead)
    with src.read_txn() as stx:
        src_all = stx.all_ops()
    src_digest = baseline_digest(src_all, cut, dead)
    src_below: dict[bytes, list[Op]] = {}
    for o in src_all:
        if covered(o, cut) and o.op_hash not in dead:
            src_below.setdefault(o.author, []).append(o)
    pulled = 0
    with dst.write_txn() as dtx:
        for author, ops in src_below.items():
            if dst_digest.get(author) != src_digest.get(author):
                for o in ops:
                    if dtx.get_op(o.op_hash) is None:
                        dtx.put_op_raw(o)  # author-signed envelope; checkpoint certifies it
                        pulled += 1
    return pulled
