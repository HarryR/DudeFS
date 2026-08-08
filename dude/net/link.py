from __future__ import annotations

import contextlib
import queue
from collections.abc import Callable
from dataclasses import dataclass, field
from enum import Enum
from typing import NamedTuple, Protocol, runtime_checkable

from ..core import crypto
from ..core.errors import DudeError
from ..core.units import Millis
from .address import Address, Endpoint
from .envelope import Frame
from .session import Inbound, Session


class LinkError(DudeError): ...


class Transport(Protocol):
    def send(self, address: Address, frame: Frame) -> None: ...


@runtime_checkable
class Listener(Protocol):
    def start(self, inbox: queue.SimpleQueue[Inbound]) -> None: ...
    def stop(self) -> None: ...
    def drain(self) -> tuple[Inbound, ...]: ...


@dataclass(frozen=True, slots=True)
class LinkTunables:
    rto_floor: Millis = 200
    """RFC 6298 floors this at 1s for the internet. A unix socket is not the internet."""
    rto_initial: Millis = 1_000
    granularity: Millis = 1

    breaker_threshold: int = 5
    breaker_cooldown: Millis = 5_000

    keepalive_interval: Millis | None = None

    budget_max_tokens: int = 10_000
    budget_token_ratio: int = 100
    """MILLI-tokens, and they MUST NOT become floats: ten additions of 0.1 sum to
    0.9999999999999999, so a bucket refilled by exactly its ratio never reaches a whole token
    and every retry is refused for ever."""


class Refused(Enum):
    INVALID = "invalid"
    """Unused in Python and MUST stay: a Go port's zero value lands here, not on a real one."""

    CIRCUIT_OPEN = "circuit-open"
    CIRCUIT_PROBING = "circuit-probing"
    TRANSPORT = "transport"


class Policy(Protocol):
    def before_send(self, now: Millis, /) -> Refused | None: ...

    def on_sent(self, now: Millis, /) -> None: ...
    def on_failed(self, now: Millis, /) -> None: ...
    def on_reply(self, now: Millis, rtt: Millis | None, /) -> None: ...


class _Inert:
    def before_send(self, _now: Millis, /) -> Refused | None:
        return None

    def on_sent(self, _now: Millis, /) -> None: ...
    def on_failed(self, _now: Millis, /) -> None: ...
    def on_reply(self, _now: Millis, _rtt: Millis | None, /) -> None: ...


@dataclass(slots=True)
class Estimator(_Inert):
    t: LinkTunables = field(default_factory=LinkTunables)
    srtt: float | None = None
    rttvar: float = 0.0
    samples: int = 0
    ignored: int = 0
    last_activity: Millis = 0

    def on_sent(self, now: Millis, /) -> None:
        self.last_activity = now

    def on_reply(self, now: Millis, rtt: Millis | None, /) -> None:
        self.last_activity = now
        if rtt is None:
            # NOT a zero. Under multi-homing most replies are unattributable, so folding them
            # in as 0 builds the estimate from un-retried traffic alone (#rtt-attribution).
            self.ignored += 1
            return
        r = float(rtt)
        if self.srtt is None:  # RFC 6298 (2.2): first sample seeds both
            self.srtt, self.rttvar = r, r / 2
        else:
            self.rttvar = 0.75 * self.rttvar + 0.25 * abs(self.srtt - r)
            self.srtt = 0.875 * self.srtt + 0.125 * r
        self.samples += 1

    def rto(self) -> Millis:
        if self.srtt is None:
            return self.t.rto_initial
        return max(self.t.rto_floor, int(self.srtt + max(self.t.granularity, 4 * self.rttvar)))

    def needs_keepalive(self, now: Millis) -> bool:
        if self.t.keepalive_interval is None:
            return False
        if self.last_activity == 0:
            return False  # never active: keepalive would fire against nothing
        return (now - self.last_activity) >= self.t.keepalive_interval


class Breaker(Enum):
    CLOSED = "closed"
    OPEN = "open"
    HALF_OPEN = "half-open"


@dataclass(slots=True)
class CircuitBreaker(_Inert):
    t: LinkTunables = field(default_factory=LinkTunables)
    state: Breaker = Breaker.CLOSED
    consecutive: int = 0
    opened_at: Millis = 0
    probing: bool = False

    def before_send(self, now: Millis, /) -> Refused | None:
        if self.state is Breaker.CLOSED:
            return None
        if self.state is Breaker.OPEN:
            if now - self.opened_at < self.t.breaker_cooldown:
                return Refused.CIRCUIT_OPEN
            self.state, self.probing = Breaker.HALF_OPEN, False
        if self.probing:
            return Refused.CIRCUIT_PROBING
        self.probing = True
        return None

    def on_failed(self, now: Millis, /) -> None:
        self.consecutive += 1
        if self.state is Breaker.HALF_OPEN or self.consecutive >= self.t.breaker_threshold:
            self.state, self.opened_at, self.probing = Breaker.OPEN, now, False

    def on_reply(self, _now: Millis, _rtt: Millis | None, /) -> None:
        self.state, self.consecutive, self.probing = Breaker.CLOSED, 0, False


@dataclass(slots=True)
class RetryBudget(_Inert):
    t: LinkTunables = field(default_factory=LinkTunables)
    tokens: int = -1

    _FULL = 1_000

    def __post_init__(self) -> None:
        if self.tokens < 0:
            self.tokens = self.t.budget_max_tokens

    def spend(self) -> bool:
        if self.tokens < self._FULL:
            return False
        self.tokens -= self._FULL
        return True

    def on_sent(self, _now: Millis, /) -> None:
        self.tokens = min(self.t.budget_max_tokens, self.tokens + self.t.budget_token_ratio)


@dataclass(slots=True)
class Link:
    address: Address
    transport: Transport
    policies: tuple[Policy, ...] = ()

    def send(self, frame: Frame, now: Millis) -> Refused | None:
        for p in self.policies:
            refusal = p.before_send(now)
            if refusal is not None:
                return refusal
        try:
            self.transport.send(self.address, frame)
        except LinkError:
            self._each("on_failed", now)
            return Refused.TRANSPORT
        self._each("on_sent", now)
        return None

    def reply(self, now: Millis, rtt: Millis | None) -> None:
        for p in self.policies:
            p.on_reply(now, rtt)

    def expired(self, now: Millis) -> None:
        self._each("on_failed", now)

    def available(self, now: Millis) -> bool:
        return all(p.before_send(now) is None for p in self.policies)

    def find[T](self, kind: type[T]) -> T | None:
        for p in self.policies:
            if isinstance(p, kind):
                return p
        return None

    def _each(self, hook: str, now: Millis) -> None:
        for p in self.policies:
            getattr(p, hook)(now)


@dataclass(slots=True)
class SessionLink:
    address: Address

    session: Session
    policies: tuple[Policy, ...] = ()
    on_close: Callable[[SessionLink], None] | None = None

    _closed: bool = field(default=False, init=False)

    def send(self, frame: Frame, now: Millis) -> Refused | None:
        if self._closed:
            return Refused.TRANSPORT
        for p in self.policies:
            refusal = p.before_send(now)
            if refusal is not None:
                return refusal
        try:
            self.session.send(frame)
        except LinkError:
            self._each("on_failed", now)
            self._close()
            return Refused.TRANSPORT
        self._each("on_sent", now)
        return None

    def reply(self, now: Millis, rtt: Millis | None) -> None:
        for p in self.policies:
            p.on_reply(now, rtt)

    def expired(self, now: Millis) -> None:
        self._each("on_failed", now)

    def available(self, now: Millis) -> bool:
        if self._closed:
            return False
        return all(p.before_send(now) is None for p in self.policies)

    def find[T](self, kind: type[T]) -> T | None:
        for p in self.policies:
            if isinstance(p, kind):
                return p
        return None

    @property
    def last_activity(self) -> Millis:
        return self.session.last_activity

    def _close(self) -> None:
        if self._closed:
            return
        self._closed = True
        with contextlib.suppress(Exception):
            self.session.close()
        if self.on_close is not None:
            self.on_close(self)

    def _each(self, hook: str, now: Millis) -> None:
        for p in self.policies:
            getattr(p, hook)(now)


def standard(
    address: Address,
    transport: Transport,
    budget: RetryBudget,
    tunables: LinkTunables | None = None,
) -> Link:
    t = tunables or LinkTunables()
    return Link(address, transport, (Estimator(t), CircuitBreaker(t), budget))


class Diff(NamedTuple):
    added: tuple[Address, ...]
    removed: tuple[Address, ...]


@dataclass(slots=True)
class Peer:
    identity: crypto.PublicKey
    dial: Callable[[Endpoint], Transport]

    t: LinkTunables = field(default_factory=LinkTunables)
    links: dict[Address, Link] = field(default_factory=dict)
    sessions: list[SessionLink] = field(default_factory=list)
    endpoints: dict[Address, Endpoint] = field(default_factory=dict)
    budget: RetryBudget = field(default_factory=RetryBudget)

    def reconfigure(self, wanted_eps: tuple[Endpoint, ...]) -> Diff:
        by_address = {e.address: e for e in wanted_eps}
        wanted = set(by_address)
        added = tuple(sorted((a for a in wanted if a not in self.links), key=lambda a: a.sort_key))
        removed = tuple(
            sorted((a for a in self.links if a not in wanted), key=lambda a: a.sort_key)
        )
        for a in removed:
            del self.links[a]
            self.endpoints.pop(a, None)
        for a in added:
            self.links[a] = standard(a, self.dial(by_address[a]), self.budget, self.t)
        self.endpoints.update(by_address)
        return Diff(added, removed)

    def usable(self, now: Millis) -> tuple[Link | SessionLink, ...]:
        session_out = [sl for sl in self.sessions if sl.available(now)]
        session_out.sort(key=lambda sl: -sl.last_activity)
        dial_out = [ln for ln in self.links.values() if ln.available(now)]
        dial_out.sort(key=lambda ln: (self._rto(ln), ln.address.sort_key))
        return (*session_out, *dial_out)

    def deliverable(self, now: Millis) -> bool:
        return any(ln.available(now) for ln in self.links.values()) or any(
            sl.available(now) for sl in self.sessions
        )

    def _rto(self, link: Link) -> Millis:
        est = link.find(Estimator)
        return est.rto() if est else self.t.rto_initial
