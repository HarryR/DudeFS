from __future__ import annotations

import contextlib
from abc import ABC, abstractmethod
from collections.abc import Callable
from dataclasses import dataclass, field
from enum import Enum

from ..core import crypto
from ..core.errors import DudeError
from ..core.units import Millis
from ..tunables import Tunables
from .address import Address, Endpoint
from .envelope import Frame

type OnFrame = Callable[[Frame, "Link"], None]
type OnLink = Callable[["Link"], None]


class LinkError(DudeError): ...


class Acceptor(ABC):
    @abstractmethod
    def start(self, on_frame: OnFrame, on_link: OnLink) -> None: ...
    @abstractmethod
    def stop(self) -> None: ...


class Dialer(ABC):
    @abstractmethod
    def start(self, on_frame: OnFrame, on_link: OnLink) -> None: ...
    @abstractmethod
    def dial(self, address: Address) -> bool: ...
    @abstractmethod
    def stop(self) -> None: ...


class Refused(Enum):
    CIRCUIT_OPEN = "circuit-open"
    TRANSPORT = "transport"


@dataclass(slots=True)
class Link:
    address: Address
    identity: crypto.PublicKey | None

    _send_frame: Callable[[Frame], None]
    _close_transport: Callable[[], None]

    last_activity: Millis = Millis(0)

    # Estimator (RFC 6298 EWMA)
    srtt: float | None = field(default=None, repr=False)
    rttvar: float = field(default=0.0, repr=False)

    # CircuitBreaker
    breaker_failures: int = field(default=0, repr=False)
    breaker_opened_at: Millis = field(default=Millis(0), repr=False)
    breaker_open: bool = field(default=False, repr=False)

    _closed: bool = field(default=False, init=False)
    _close_notified: bool = field(default=False, init=False)
    on_close: Callable[[Link], None] | None = None

    def send(self, frame: Frame, now: Millis) -> Refused | None:
        if self._closed:
            return Refused.TRANSPORT
        if self.breaker_open:
            if now - self.breaker_opened_at < self._breaker_cooldown():
                return Refused.CIRCUIT_OPEN
            self.breaker_open = False
        try:
            self._send_frame(frame)
        except LinkError:
            self._on_failed(now)
            self.close()
            return Refused.TRANSPORT
        self.last_activity = now
        return None

    def on_reply(self, now: Millis, rtt: Millis | None) -> None:
        self.last_activity = now
        self.breaker_failures = 0
        self.breaker_open = False
        if rtt is None:
            return
        r = float(rtt)
        if self.srtt is None:
            self.srtt, self.rttvar = r, r / 2
        else:
            self.rttvar = 0.75 * self.rttvar + 0.25 * abs(self.srtt - r)
            self.srtt = 0.875 * self.srtt + 0.125 * r

    def on_expired(self, now: Millis) -> None:
        self._on_failed(now)

    def _on_failed(self, now: Millis) -> None:
        self.breaker_failures += 1
        if self.breaker_failures >= 5:
            self.breaker_open = True
            self.breaker_opened_at = now

    def rto(self, initial: Millis) -> Millis:
        if self.srtt is None:
            return initial
        return Millis(max(2, int(self.srtt + max(1, 4 * self.rttvar))))

    def available(self, now: Millis) -> bool:
        if self._closed:
            return False
        if self.breaker_open and now - self.breaker_opened_at < self._breaker_cooldown():
            return False
        return True

    def bind(self, identity: crypto.PublicKey) -> None:
        if self.identity is not None:
            if self.identity != identity:
                raise LinkError(
                    f"link already bound to {self.identity.hex()[:8]}, "
                    f"refuses rebind to {identity.hex()[:8]}"
                )
            return
        self.identity = identity

    def close(self) -> None:
        if self._closed:
            return
        self._closed = True
        with contextlib.suppress(Exception):
            self._close_transport()
        self.notify_closed()

    def notify_closed(self) -> None:
        if self._close_notified:
            return
        self._close_notified = True
        if self.on_close is not None:
            self.on_close(self)

    def _breaker_cooldown(self) -> Millis:
        return Millis(10_000)


# ---------------------------------------------------------------------------
# Peer
# ---------------------------------------------------------------------------


@dataclass(slots=True)
class Peer:
    identity: crypto.PublicKey
    t: Tunables
    dial_targets: dict[Address, Endpoint] = field(default_factory=dict)
    links: list[Link] = field(default_factory=list)

    def reconfigure(self, wanted_eps: tuple[Endpoint, ...]) -> None:
        wanted = {e.address: e for e in wanted_eps}
        for link in tuple(self.links):
            if link.address not in wanted:
                link.close()
        self.dial_targets = wanted

    def disconnect(self) -> None:
        for link in tuple(self.links):
            link.close()
        self.links.clear()

    def usable(self, now: Millis) -> tuple[Link, ...]:
        out = [ln for ln in self.links if ln.available(now)]
        out.sort(key=lambda ln: ln.rto(self.t.rtt_max))
        return tuple(out)

    def deliverable(self, now: Millis) -> bool:
        return any(ln.available(now) for ln in self.links)
