from __future__ import annotations

from collections.abc import Sequence
from enum import Enum

from ..consensus.settle_round import SettledBlock, _settle_payload
from ..core import crypto
from ..core.errors import InvariantError
from ..core.units import Millis
from ..store.management import Authorization
from ..tunables import Tunables

NO_BUCKET = -1


class ChainRefusal(Enum):
    INVALID = "invalid"

    NOTHING_TO_WALK = "nothing-to-walk"

    BROKEN_LINK = "broken-link"

    UNAUTHORISED = "unauthorised"


def advance(
    from_hash: crypto.Digest,
    blocks: Sequence[SettledBlock],
    roster: Sequence[crypto.PublicKey],
    anchor: crypto.PublicKey,
) -> SettledBlock | ChainRefusal:
    if not blocks:
        return ChainRefusal.NOTHING_TO_WALK
    prev = from_hash
    head: SettledBlock | None = None
    for b in blocks:
        if b.anchors.prev_block != prev:
            return ChainRefusal.BROKEN_LINK
        payload = _settle_payload(b.block.slice_hash, b.anchors)
        if not Authorization(b.multisig, payload, tuple(roster), anchor).verify():
            return ChainRefusal.UNAUTHORISED
        head = b
        prev = b.block_hash
    if head is None:
        raise InvariantError("non-empty blocks produced no head")
    return head


def buckets_behind(head_bucket: int, now: Millis, t: Tunables) -> int:
    return t.bucket(now) - t.windows_to_settle - head_bucket


def is_stale(head_bucket: int, now: Millis, t: Tunables) -> bool:
    return buckets_behind(head_bucket, now, t) > t.skew_buckets()
