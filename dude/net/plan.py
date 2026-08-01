# dude.net.plan — retry, stagger and give-up policy. Pure. See SPEC.md (#retry-budget).
#
# THE INVARIANT THIS FILE EXISTS TO KEEP [H]: **no object both holds state and decides policy.**
#
# Retry is a decision about a MESSAGE informed by PATH state, so it belongs to neither the mailbox
# nor the peer — put it in either and that object starts attracting the other's data, which is how
# the selection logic ended up duplicated in `Mailbox` and `Peer`. Policy in a state-holding object
# is magnetic.
#
# So: this module holds NOTHING. It is handed the facts and returns a decision. Backoff-with-jitter
# (R5), the budget interaction (R6) and stagger timing (R7) are therefore testable as plain values,
# with no mailbox, no clock and no sockets anywhere near them.

from __future__ import annotations

from collections.abc import Callable
from dataclasses import dataclass, field
from enum import Enum

from ..core import crypto
from ..core.units import Millis
from .link import Estimator, Link, Peer


class Stalled(Enum):
    """Why a message is not going out right now — closed, so the executor's `match` stays
    exhaustive and a metric counting these cannot drift on a typo.
    Plain `Enum`, deliberately NOT `StrEnum`: these never go on the wire, so the string would be a
    value nobody marshals, and `StrEnum` members ARE `str`s — which is how a comparison across two
    unrelated reason enums that happen to share a spelling came out True. Plain members compare
    False against each other and against bare strings, so a stray `== "guard"` fails loudly instead
    of silently passing. `StrEnum` is for values that are their own serialised form; `Scheme` and
    `Role` earn it, this does not.
    """

    INVALID = "invalid"
    """RESERVED, and never returned by this package. Declared FIRST so that a port to Go — where
    these become integers and a struct field's zero value is whatever member happens to be 0 —
    lands its zero value on a named invalid rather than on a real one. Without it, a zero-valued
    field silently means the first member: a bug that does not exist in Python and is very hard to
    see in review.

    Not dead code: it is load-bearing in the target, and Python's own `Enum(0)` has no meaning to
    guard. Treat receiving it as a decode fault."""

    NO_USABLE_LINK = "no-usable-link"
    """Every link refused: a breaker is open, or nothing is configured."""
    DEADLINE = "deadline"
    ATTEMPTS = "attempts"
    """The backstop limit, not the real one — the deadline and the budget are (see PlanTunables)."""


@dataclass(frozen=True, slots=True)
class Send:
    """Transmit on these links now. `again_at` is set when another link remains to try — a STAGGER,
    which adds an attempt to a live one, as opposed to a retry which replaces a failed one."""

    links: tuple[Link, ...]
    again_at: Millis | None = None


@dataclass(frozen=True, slots=True)
class Wait:
    """Nothing to do until then. Covers backoff, an open circuit, and a spent budget alike — the
    caller does not need to know which, and collapsing them keeps the executor free of policy."""

    until: Millis
    why: Stalled


@dataclass(frozen=True, slots=True)
class GiveUp:
    why: Stalled


type Decision = Send | Wait | GiveUp


@dataclass(frozen=True, slots=True)
class PlanTunables:
    """Destined for the one consolidated tunables surface (#timing) — no literal below."""

    backoff_base: Millis = 100
    """First retry delay, and the FLOOR of every delay: `backoff` never returns less. A third of a
    tolerable round trip, so a first retry is cheap on a fast link."""

    backoff_cap: Millis = 5_000
    """Ceiling on one delay, before jitter. MUST NOT exceed `net.ttl`, the deadline it is spent
    against: `Plan.next` clamps every wait to the deadline anyway, so a cap above it is incoherent
    rather than wrong — it states a limit the deadline has already imposed. It was 30 s against a
    10 s TTL, and `Tunables.__post_init__` refuses that combination now."""

    stagger_cap: Millis = 250
    """R7's Connection Attempt Delay, as a CAP rather than the value.

    RFC 8305 specifies a flat 250 ms because a browser has no RTT history for a freshly resolved
    address. We have history, per link, so the real delay is `min(cap, best_link.rto())` — waiting
    the full cap before trying a second address when the first is a unix socket with a 20 ms RTO
    would throw away most of what the estimator is for. One `RTT_MAX`: closer and the second dial is
    duplicate load, further and it is a serial retry wearing a parallel name."""

    max_parallel: int = 2
    """How many links one message may be in flight on at once. Two is the Happy Eyeballs shape;
    every attempt beyond the first also costs a budget token, so this is an upper bound rather than
    a target."""
    max_attempts: int = 8
    """A backstop, not the real limit — the deadline and the budget are. It exists so a pathological
    peer cannot be attempted thousands of times inside one long TTL.

    NOT DERIVED FROM THE DEADLINE, and an earlier commit wrongly said it must be. `backoff` is
    decorrelated jitter — `max(base, random(base, min(cap, base·3^attempts)))` — so a run's spend is
    not a fixed sum: its minimum is `attempts · base`, 800 ms here, and `Plan.next` checks the
    deadline explicitly and distinguishes `Stalled.ATTEMPTS` from
    `Stalled.DEADLINE`. Nothing is silently unreachable. The claim came from re-implementing this
    schedule in a checker with the wrong growth base."""


@dataclass(frozen=True, slots=True)
class Plan:
    """Decides what to do with one outstanding message. Stateless by construction."""

    t: PlanTunables = field(default_factory=PlanTunables)
    jitter: Callable[[int, int], int] = field(default=lambda lo, hi: lo + (hi - lo) // 2)
    """Injected so a test gets determinism and production gets randomness. The default is the
    MIDPOINT rather than a random draw: a module that silently randomised would make every test
    above it flaky, so the unpredictable behaviour must be asked for. `dude.net.plan.decorrelated`
    is the real one."""

    def next(self, peer: Peer, attempts: int, now: Millis, deadline: Millis) -> Decision:
        """The whole policy, in one place.

        Order is deliberate: exhaustion before deliverability before selection. A message that is
        out of time or attempts is over however healthy the paths are, and asking a peer to select
        links for a message already finished would waste budget tokens on it."""
        if now >= deadline:
            return GiveUp(Stalled.DEADLINE)
        if attempts >= self.t.max_attempts:
            return GiveUp(Stalled.ATTEMPTS)
        if not peer.deliverable(now):
            # Every link is refusing — breaker open, or nothing configured. Waiting is right rather
            # than giving up: a breaker's cooldown expires, and a roster update may add a link.
            return Wait(min(deadline, now + self.backoff(attempts)), Stalled.NO_USABLE_LINK)

        usable = peer.usable(now)
        if not usable:
            # `deliverable` said yes but `usable` returned empty. That can happen when a policy's
            # `before_send` reads state that other policies mutate between the two calls (e.g., a
            # per-check budget). Treat the same as "not deliverable" and wait.
            return Wait(min(deadline, now + self.backoff(attempts)), Stalled.NO_USABLE_LINK)
        picked = [usable[0]]  # the first attempt is always free; the budget bounds PARALLELISM only
        for link in usable[1:]:
            if len(picked) >= self.t.max_parallel or not peer.budget.spend():
                break
            picked.append(link)
        more = len(usable) > len(picked)
        return Send(tuple(picked), self.stagger(picked) if more else None)

    def backoff(self, attempts: int) -> Millis:
        """Decorrelated jitter (R5): `min(cap, random(base, base·3^attempts))`.

        Stateless — the previous delay is recovered from the attempt count rather than stored, which
        is what lets this object hold nothing. The randomisation is the point, not the growth: a
        fixed delay re-synchronises every client that failed together, so a recovering peer meets a
        thundering herd of perfectly aligned retries."""
        hi = min(self.t.backoff_cap, self.t.backoff_base * 3 ** max(1, attempts))
        return max(self.t.backoff_base, self.jitter(self.t.backoff_base, hi))

    def stagger(self, picked: list[Link]) -> Millis:
        """R7's Connection Attempt Delay: `min(cap, best picked link's RTO)`.

        RFC 8305 uses a flat 250 ms because a browser has no RTT history for a freshly resolved
        address. We have history, per link, so waiting 250 ms before trying a second address when
        the first is a unix socket with a 20 ms RTO would discard what the estimator is for."""
        rtos = [e.rto() for e in (ln.find(Estimator) for ln in picked) if e is not None]
        return min(self.t.stagger_cap, *rtos) if rtos else self.t.stagger_cap

    def retry_at(self, attempts: int, now: Millis) -> Millis:
        """When a failed attempt should be reconsidered. Separate from `next` because a failure is
        reported at a different moment than a scheduling decision is taken."""
        return now + self.backoff(attempts)


def decorrelated(lo: int, hi: int) -> int:
    """The production jitter source: uniform over `[lo, hi]`, from `crypto.random_bytes` so every
    unpredictable value in the system comes from one place (`random` is never acceptable, which
    ruff's S311 enforces at the other end)."""
    if hi <= lo:
        return lo
    span = hi - lo + 1
    return lo + int.from_bytes(crypto.random_bytes(8), "big") % span
