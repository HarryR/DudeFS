from __future__ import annotations

from collections.abc import Sequence
from dataclasses import dataclass
from enum import Enum

from ..consensus.settle_round import SettledBlock, _settle_payload, genesis_stamp
from ..core import crypto
from ..core.units import Millis
from ..store import smt
from ..store.layer import Index
from ..store.management import Authorization
from ..tunables import Tunables

_NO_BUCKET = -1
"""Before block 1 there is no bucket, and a node holding no blocks IS stale."""


class ChainRefusal(Enum):
    INVALID = "invalid"

    NOTHING_TO_WALK = "nothing-to-walk"

    BROKEN_LINK = "broken-link"

    UNAUTHORISED = "unauthorised"


@dataclass(frozen=True, slots=True)
class TrustedHead:
    """Where a chain walker has got to. A node keeps it in its Store and a light client in
    memory, but it is the same three facts and the same rule for moving it."""

    block_num: Index
    block_hash: crypto.Digest
    state_root: crypto.Digest
    bucket: int

    @classmethod
    def genesis(cls, anchor: crypto.PublicKey) -> TrustedHead:
        """Before block 1. ONE spelling of "no block yet": `serve_height` answered
        `Digest(bytes(32))` while `caught_up` used the genesis stamp, so two fresh nodes never
        matched tips and read each other as forked."""
        return cls(0, genesis_stamp(anchor), smt.EMPTY, _NO_BUCKET)


def advance(
    from_hash: crypto.Digest,
    blocks: Sequence[SettledBlock],
    roster: Sequence[crypto.PublicKey],
    anchor: crypto.PublicKey,
) -> TrustedHead | ChainRefusal:
    """Walk `blocks` from `from_hash`, one link at a time, and return where that leaves us.

    Takes only the hash to chain from, not a whole head: a node's state root costs an SMT walk
    over SQLite to produce and the link check never reads it.

    ONE ROSTER for the whole walk. A node therefore passes one block at a time -- it MUST check
    each against the roster at that block's height, which it only has by committing the one
    before. A light client passes a range, its roster fixed by construction: a moved fingerprint
    means re-bootstrap, not an adopted roster."""
    if not blocks:
        return ChainRefusal.NOTHING_TO_WALK
    prev = from_hash
    head: TrustedHead | None = None
    for b in blocks:
        if b.anchors.prev_block != prev:
            return ChainRefusal.BROKEN_LINK
        payload = _settle_payload(b.block.slice_hash, b.anchors)
        if not Authorization(b.multisig, payload, tuple(roster), anchor).verify():
            return ChainRefusal.UNAUTHORISED
        head = TrustedHead(b.anchors.block_num, b.block_hash, b.anchors.state_root, b.block.bucket)
        prev = b.block_hash
    assert head is not None  # noqa: S101 -- `blocks` is non-empty above
    return head


def buckets_behind(head_bucket: int, now: Millis, t: Tunables) -> int:
    """Zero when the head is the block for the bucket that just closed, which is as fresh as a
    head gets."""
    return t.mempool.bucket(now) - 1 - head_bucket


def is_stale(head_bucket: int, now: Millis, t: Tunables) -> bool:
    """THE freshness rule, for nodes and light clients alike. An old block verifies perfectly --
    signatures, chain link and quorum proof all pass -- so the clock is the only thing that
    separates current from merely valid. `bucket` sits inside the block identity and inside the
    settle signature, so it is quorum-attested; the only local input is NTP."""
    return buckets_behind(head_bucket, now, t) > t.timing.skew_buckets(t.mempool.delta)
