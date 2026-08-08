from __future__ import annotations

from collections.abc import Callable
from dataclasses import dataclass, field
from enum import Enum

from ..core import crypto
from ..core.units import Millis
from .link import Estimator, Link, Peer, SessionLink

type AnyLink = Link | SessionLink


class Stalled(Enum):
    INVALID = "invalid"

    NO_USABLE_LINK = "no-usable-link"
    DEADLINE = "deadline"
    ATTEMPTS = "attempts"


@dataclass(frozen=True, slots=True)
class Send:
    links: tuple[AnyLink, ...]
    again_at: Millis | None = None


@dataclass(frozen=True, slots=True)
class Wait:
    until: Millis
    why: Stalled


@dataclass(frozen=True, slots=True)
class GiveUp:
    why: Stalled


type Decision = Send | Wait | GiveUp


@dataclass(frozen=True, slots=True)
class PlanTunables:
    backoff_base: Millis = 100

    backoff_cap: Millis = 5_000

    stagger_cap: Millis = 250

    max_parallel: int = 2
    max_attempts: int = 8


@dataclass(frozen=True, slots=True)
class Plan:
    t: PlanTunables = field(default_factory=PlanTunables)
    jitter: Callable[[int, int], int] = field(default=lambda lo, hi: lo + (hi - lo) // 2)

    def next(self, peer: Peer, attempts: int, now: Millis, deadline: Millis) -> Decision:
        if now >= deadline:
            return GiveUp(Stalled.DEADLINE)
        if attempts >= self.t.max_attempts:
            return GiveUp(Stalled.ATTEMPTS)
        if not peer.deliverable(now):
            return Wait(min(deadline, now + self.backoff(attempts)), Stalled.NO_USABLE_LINK)

        usable = peer.usable(now)
        if not usable:
            return Wait(min(deadline, now + self.backoff(attempts)), Stalled.NO_USABLE_LINK)
        picked = [usable[0]]
        for link in usable[1:]:
            if len(picked) >= self.t.max_parallel or not peer.budget.spend():
                break
            picked.append(link)
        more = len(usable) > len(picked)
        return Send(tuple(picked), self.stagger(picked) if more else None)

    def backoff(self, attempts: int) -> Millis:
        hi = min(self.t.backoff_cap, self.t.backoff_base * 3 ** max(1, attempts))
        return max(self.t.backoff_base, self.jitter(self.t.backoff_base, hi))

    def stagger(self, picked: list[AnyLink]) -> Millis:
        rtos = [e.rto() for e in (ln.find(Estimator) for ln in picked) if e is not None]
        return min(self.t.stagger_cap, *rtos) if rtos else self.t.stagger_cap

    def retry_at(self, attempts: int, now: Millis) -> Millis:
        return now + self.backoff(attempts)


def decorrelated(lo: int, hi: int) -> int:
    if hi <= lo:
        return lo
    span = hi - lo + 1
    return lo + int.from_bytes(crypto.random_bytes(8), "big") % span
