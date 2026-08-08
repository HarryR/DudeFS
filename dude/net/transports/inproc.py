from __future__ import annotations

import queue
from collections import deque
from dataclasses import dataclass, field

from ...core import crypto
from ...core.units import Millis, now_ms
from ..address import Address, Scheme
from ..envelope import Frame
from ..link import LinkError, Listener, Transport
from ..session import Inbound, Session

_INBOXES: dict[str, InProcListener] = {}


class InProcSession(Session):
    __slots__ = ("_me", "_reply_to")

    def __init__(self, reply_to: str, me: str) -> None:
        super().__init__(identity=None, address=Address(Scheme.INPROC, reply_to))
        self._reply_to = reply_to
        self._me = me

    def send(self, frame: Frame) -> None:
        target = _INBOXES.get(self._reply_to)
        if target is None:
            raise LinkError(f"in-process reply target no longer registered: {self._reply_to!r}")
        target._deliver(frame, sender_name=self._me)  # noqa: SLF001 -- same-module cooperative access
        self.last_activity = now_ms()

    def close(self) -> None:
        if self.on_close is not None:
            self.on_close()
            self.on_close = None

    def _notify_frame_in(self, now: Millis) -> None:
        self.last_activity = now


@dataclass(slots=True)
class InProcDialer(Transport):
    me: str

    def send(self, address: Address, frame: Frame) -> None:
        if address.scheme is not Scheme.INPROC:
            raise LinkError(f"inproc cannot dial {address.scheme.value.decode()}")
        target = _INBOXES.get(address.value)
        if target is None:
            raise LinkError(f"no such in-process endpoint: {address.value}")
        target._deliver(frame, sender_name=self.me)  # noqa: SLF001 -- same-module cooperative access


@dataclass(slots=True)
class InProcListener(Listener):
    me: str
    _inbox_queue: queue.SimpleQueue[Inbound] | None = field(init=False, default=None)
    _buffered: deque[Inbound] = field(init=False, default_factory=deque)
    _sessions: dict[str, InProcSession] = field(init=False, default_factory=dict)
    _stopped: bool = field(init=False, default=False)

    def __post_init__(self) -> None:
        if self.me in _INBOXES:
            raise LinkError(f"in-process name already registered: {self.me!r}")
        _INBOXES[self.me] = self

    def _deliver(self, frame: Frame, sender_name: str | None) -> None:
        if self._stopped:
            return
        if sender_name is None:
            session: InProcSession = InProcSession(reply_to="", me=self.me)
        else:
            session = self._sessions.setdefault(
                sender_name, InProcSession(reply_to=sender_name, me=self.me)
            )
        session._notify_frame_in(now_ms())  # noqa: SLF001 -- same-module cooperative access
        item = Inbound(frame, session)
        self._buffered.append(item)
        if self._inbox_queue is not None:
            self._inbox_queue.put(item)
            self._buffered.clear()

    def start(self, inbox: queue.SimpleQueue[Inbound]) -> None:
        if self._inbox_queue is inbox:
            return
        if self._inbox_queue is not None:
            raise RuntimeError("InProcListener already started with a different inbox")
        self._inbox_queue = inbox
        for item in self._buffered:
            inbox.put(item)
        self._buffered.clear()

    def stop(self) -> None:
        self._stopped = True
        self._inbox_queue = None
        _INBOXES.pop(self.me, None)
        for session in self._sessions.values():
            session.close()
        self._sessions.clear()

    def drain(self) -> tuple[Inbound, ...]:
        out = tuple(self._buffered)
        self._buffered.clear()
        return out


def _reset_for_tests() -> None:
    _INBOXES.clear()


def name_of(identity: crypto.PublicKey) -> str:
    return identity.hex()[:12]


def address_of(identity: crypto.PublicKey) -> Address:
    return Address(Scheme.INPROC, name_of(identity))
