from __future__ import annotations

from dataclasses import dataclass, field
from typing import TYPE_CHECKING

from ...core import crypto
from ...core.units import Millis
from ..address import Address, Endpoint, Scheme
from ..envelope import Frame
from ..link import Acceptor, Dialer, Link, LinkError, OnFrame, OnLink

if TYPE_CHECKING:
    from ...node import _BaseNode
    from ..postman import Postman


class _InProcConn:
    __slots__ = ("_me", "_nexus", "_reply_to", "link")

    def __init__(self, reply_to: bytes, me: bytes, address: Address, nexus: InProcNexus) -> None:
        self._reply_to = reply_to
        self._me = me
        self._nexus = nexus
        self.link = Link(
            address=address,
            identity=None,
            _send_frame=self.send_frame,
            _close_transport=self.close,
        )

    def send_frame(self, frame: Frame) -> None:
        target = self._nexus._listeners.get(self._reply_to)
        if target is None:
            raise LinkError(f"in-process reply target no longer registered: {self._reply_to!r}")
        target._deliver(frame, sender=self._me)

    def close(self) -> None:
        pass


@dataclass(slots=True)
class InProcListener(Acceptor, Dialer):
    identity: crypto.PublicKey
    nexus: InProcNexus
    _on_frame: OnFrame | None = field(init=False, default=None)
    _on_link: OnLink | None = field(init=False, default=None)
    _buffered: list[tuple[Frame, Link]] = field(init=False, default_factory=list)
    _conns: dict[bytes, _InProcConn] = field(init=False, default_factory=dict)
    _stopped: bool = field(init=False, default=False)

    def __post_init__(self) -> None:
        key = bytes(self.identity)
        if key in self.nexus._listeners:
            raise LinkError(f"in-process identity already registered: {self.identity.hex()[:8]}")
        self.nexus._listeners[key] = self

    @property
    def endpoint(self) -> Endpoint:
        return self.endpoint_for(self.identity)

    @staticmethod
    def endpoint_for(identity: crypto.PublicKey) -> Endpoint:
        return Endpoint(Address(Scheme.INPROC, identity.hex()))

    def _deliver(self, frame: Frame, sender: bytes) -> None:
        if self._stopped:
            return
        conn = self._conns.get(sender)
        if conn is None:
            conn = _InProcConn(
                reply_to=sender,
                me=bytes(self.identity),
                address=Address(Scheme.INPROC, sender.hex()),
                nexus=self.nexus,
            )
            self._conns[sender] = conn
            if self._on_link is not None:
                self._on_link(conn.link)
        conn.link.last_activity = Millis.now()
        if self._on_frame is not None:
            self._on_frame(frame, conn.link)
        else:
            self._buffered.append((frame, conn.link))

    def start(self, on_frame: OnFrame, on_link: OnLink) -> None:
        self._stopped = False
        me = bytes(self.identity)
        if me not in self.nexus._listeners:
            self.nexus._listeners[me] = self
        self._on_frame = on_frame
        self._on_link = on_link
        for conn in self._conns.values():
            on_link(conn.link)
        for frame, link in self._buffered:
            on_frame(frame, link)
        self._buffered.clear()

    def dial(self, address: Address) -> bool:
        if address.scheme is not Scheme.INPROC or self._on_link is None:
            return False
        target_key = bytes.fromhex(address.value)
        if target_key not in self.nexus._listeners or target_key in self._conns:
            return False
        conn = _InProcConn(
            reply_to=target_key,
            me=bytes(self.identity),
            address=address,
            nexus=self.nexus,
        )
        self._conns[target_key] = conn
        self._on_link(conn.link)
        return True

    def stop(self) -> None:
        self._stopped = True
        self._on_frame = None
        self._on_link = None
        me = bytes(self.identity)
        self.nexus._listeners.pop(me, None)
        for conn in self._conns.values():
            conn.link.close()
        self._conns.clear()
        for listener in list(self.nexus._listeners.values()):
            remote_conn = listener._conns.pop(me, None)
            if remote_conn is not None:
                remote_conn.link.notify_closed()


class InProcNexus:
    __slots__ = ("_listeners",)

    def __init__(self) -> None:
        self._listeners: dict[bytes, InProcListener] = {}

    def attach(self, target: Postman | _BaseNode) -> InProcListener:
        pub = target.me.public
        inproc = InProcListener(pub, self)
        target.add_acceptor(inproc)
        target.add_dialer(inproc)
        return inproc

    def endpoint_for(self, identity: crypto.PublicKey) -> Endpoint:
        return InProcListener.endpoint_for(identity)
