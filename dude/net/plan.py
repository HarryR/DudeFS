from __future__ import annotations

from dataclasses import dataclass
from enum import Enum

from ..core import crypto
from ..core.units import Millis
from ..tunables import Tunables
from .link import Link, Peer


class Stalled(Enum):
    NO_USABLE_LINK = "no-usable-link"
    DEADLINE = "deadline"
    ATTEMPTS = "attempts"


@dataclass(frozen=True, slots=True)
class Send:
    link: Link
    again_at: Millis | None = None


@dataclass(frozen=True, slots=True)
class Wait:
    until: Millis
    why: Stalled


@dataclass(frozen=True, slots=True)
class GiveUp:
    why: Stalled


type Decision = Send | Wait | GiveUp


def plan_next(t: Tunables, peer: Peer, attempts: int, now: Millis, deadline: Millis) -> Decision:
    if now >= deadline:
        return GiveUp(Stalled.DEADLINE)
    if attempts >= t.max_attempts:
        return GiveUp(Stalled.ATTEMPTS)

    usable = peer.usable(now)
    if not usable:
        return Wait(min(deadline, now + backoff(t, attempts)), Stalled.NO_USABLE_LINK)

    best = usable[0]
    again = now + min(t.stagger_cap, best.rto(t.rtt_max)) if len(usable) > 1 else None
    return Send(best, again)


def backoff(t: Tunables, attempts: int) -> Millis:
    hi = min(t.backoff_cap, t.backoff_base * 3 ** max(1, attempts))
    return t.backoff_base + (hi - t.backoff_base) // 2


def retry_at(t: Tunables, attempts: int, now: Millis) -> Millis:
    return now + backoff(t, attempts)


def decorrelated(lo: int, hi: int) -> int:
    if hi <= lo:
        return lo
    span = hi - lo + 1
    return lo + int.from_bytes(crypto.random_bytes(8), "big") % span
