from __future__ import annotations

from dataclasses import dataclass, field

from ...core import crypto
from ...core.units import now_ms
from ..address import Address, Endpoint, Scheme
from ..envelope import Frame
from ..link import Link, LinkError, Listener, OnFrame, OnLink


_INBOXES: dict[bytes, InProcListener] = {}


class _InProcConn:
    __slots__ = ("_me", "_reply_to", "link")

    def __init__(self, reply_to: bytes, me: bytes, address: Address) -> None:
        self._reply_to = reply_to
        self._me = me
        self.link = Link(
            address=address,
            identity=None,
            _send_frame=self.send_frame,
            _close_transport=self.close,
        )

    def send_frame(self, frame: Frame) -> None:
        target = _INBOXES.get(self._reply_to)
        if target is None:
            raise LinkError(f"in-process reply target no longer registered: {self._reply_to!r}")
        target._deliver(frame, sender=self._me)  # noqa: SLF001

    def close(self) -> None:
        pass


@dataclass(slots=True)
class InProcListener(Listener):
    identity: crypto.PublicKey
    _on_frame: OnFrame | None = field(init=False, default=None)
    _on_link: OnLink | None = field(init=False, default=None)
    _buffered: list[tuple[Frame, Link]] = field(init=False, default_factory=list)
    _conns: dict[bytes, _InProcConn] = field(init=False, default_factory=dict)
    _stopped: bool = field(init=False, default=False)

    def __post_init__(self) -> None:
        key = bytes(self.identity)
        if key in _INBOXES:
            raise LinkError(f"in-process identity already registered: {self.identity.hex()[:8]}")
        _INBOXES[key] = self

    @property
    def endpoint(self) -> Endpoint:
        return Endpoint(Address(Scheme.INPROC, self.identity.hex()))

    def _deliver(self, frame: Frame, sender: bytes) -> None:
        if self._stopped:
            return
        conn = self._conns.get(sender)
        if conn is None:
            conn = _InProcConn(
                reply_to=sender,
                me=bytes(self.identity),
                address=Address(Scheme.INPROC, sender.hex()),
            )
            self._conns[sender] = conn
            if self._on_link is not None:
                self._on_link(conn.link)
        conn.link.last_activity = now_ms()
        if self._on_frame is not None:
            self._on_frame(frame, conn.link)
        else:
            self._buffered.append((frame, conn.link))

    def start(self, on_frame: OnFrame, on_link: OnLink) -> None:
        if self._on_frame is not None:
            raise RuntimeError("InProcListener already started")
        self._on_frame = on_frame
        self._on_link = on_link
        for conn in self._conns.values():
            on_link(conn.link)
        for frame, link in self._buffered:
            on_frame(frame, link)
        self._buffered.clear()

    def dial(self, address: Address) -> None:
        if address.scheme is not Scheme.INPROC or self._on_link is None:
            return
        target_key = bytes.fromhex(address.value)
        if target_key not in _INBOXES or target_key in self._conns:
            return
        conn = _InProcConn(
            reply_to=target_key,
            me=bytes(self.identity),
            address=address,
        )
        self._conns[target_key] = conn
        self._on_link(conn.link)

    def stop(self) -> None:
        self._stopped = True
        self._on_frame = None
        self._on_link = None
        _INBOXES.pop(bytes(self.identity), None)
        for conn in self._conns.values():
            conn.link.close()
        self._conns.clear()


def _reset_for_tests() -> None:
    _INBOXES.clear()
