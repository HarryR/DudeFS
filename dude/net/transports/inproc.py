# dude.net.transports.inproc — a paired loopback with the same shape as TCP.
# See SPEC.md (#inproc-is-a-loopback, #partitions-are-test-only).
#
# THE POINT OF InProc is that everything above the carrier gets exercised for real. A
# `Switchboard` with its own routing table and partition list used to sit here, which meant
# Postman's routing -- the thing under test -- was the thing being bypassed.
#
# TWO CONCRETE TYPES, mirroring the TCP shape:
#
#   InProcDialer   outbound only. Constructed by Postman via `transports.dial`, never by a caller.
#                  `send(address, frame)` looks the target up in the module-scope
#                  `_INBOXES` registry and appends to that listener's internal buffer.
#                  No state; construct one per Postman.
#   InProcListener receive-only. Registers itself in `_INBOXES` at construction under
#                  `name_of(identity)`; owns the internal buffer. Same `Listener`
#                  protocol as `TCPListener`: `start(inbox)` forwards to a queue in the
#                  simplest possible way (no threads needed -- appends happen on the
#                  send-side call), `stop()` unregisters, `drain()` returns buffered.
#
# Module-scope registry keyed by name -- the way TCP delegates to the kernel's socket table.
#
# SESSIONS. There is no persistent socket to wrap, so a session is synthesised per sender on
# the listener side and cached there. Reply-on-session works symmetrically: the session's
# `send()` looks the sender up in the registry and delivers back.
#
# NO PARTITION LOGIC (#partitions-are-test-only). A test partitions by `remove_peer` on both
# sides, which IS what a partition looks like to the protocol: no live path in the routing
# table.

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
"""Live `InProcListener` instances by name; one entry per identity answering in this process.

Module-scope deliberately. Making it an object created the illusion that several "networks"
could coexist, and forced every construction path to plumb it through -- plumbing that ended
up nowhere near the transport, which defeats #inproc-is-a-loopback."""


# --------------------------------------------------------------------------------------------- #
# InProcSession -- one delivered frame's-worth of session for the loopback carrier.             #
# --------------------------------------------------------------------------------------------- #


class InProcSession(Session):
    """A per-peer-pair reply channel over the loopback. The reply path is the forward path
    with the sender-name flipped: same registry lookup, opposite direction."""

    __slots__ = ("_me", "_reply_to")

    def __init__(self, reply_to: str, me: str) -> None:
        super().__init__(identity=None, address=Address(Scheme.INPROC, reply_to))
        self._reply_to = reply_to
        self._me = me

    def send(self, frame: Frame) -> None:
        """Deliver `frame` back to `_reply_to`'s InProcListener via the registry, tagged
        with `_me` so the receiver's Postman can establish a reverse session-Link."""
        target = _INBOXES.get(self._reply_to)
        if target is None:
            raise LinkError(f"in-process reply target no longer registered: {self._reply_to!r}")
        target._deliver(frame, sender_name=self._me)  # noqa: SLF001 -- same-module cooperative access
        self.last_activity = now_ms()

    def close(self) -> None:
        """Nothing to tear down, but `on_close` still fires so the unregister path runs the
        same way it does for a real socket."""
        if self.on_close is not None:
            self.on_close()
            self.on_close = None  # idempotent

    def _notify_frame_in(self, now: Millis) -> None:
        self.last_activity = now


# --------------------------------------------------------------------------------------------- #
# Dialer -- outbound only, held by Postman                                                      #
# --------------------------------------------------------------------------------------------- #


@dataclass(slots=True)
class InProcDialer(Transport):
    """InProc's send side. Stateless: look the target listener up in `_INBOXES` and append.
    No thread, no socket, no delay. A `LinkError` means the target is not registered --
    connection-refused, and the breaker treats it as such. `me` is our own in-process address,
    carried so a reply on the resulting session knows where to go."""

    me: str

    def send(self, address: Address, frame: Frame) -> None:
        if address.scheme is not Scheme.INPROC:
            raise LinkError(f"inproc cannot dial {address.scheme.value.decode()}")
        target = _INBOXES.get(address.value)
        if target is None:
            raise LinkError(f"no such in-process endpoint: {address.value}")
        target._deliver(frame, sender_name=self.me)  # noqa: SLF001 -- same-module cooperative access


# --------------------------------------------------------------------------------------------- #
# Listener -- inbound only, held by Node                                                        #
# --------------------------------------------------------------------------------------------- #


@dataclass(slots=True)
class InProcListener(Listener):
    """InProc's receive side, registered in `_INBOXES` at construction. Two identities
    colliding raises `LinkError`, the way TCP refuses two servers on one port.

    Two driver paths, one implementation: `start(inbox)` for production, `drain()` for tests.
    No background thread either way -- delivery happens on the SENDER's call, in the sender's
    thread. `start` exists so `Node.start(*listeners)` treats every carrier uniformly."""

    me: str
    _inbox_queue: queue.SimpleQueue[Inbound] | None = field(init=False, default=None)
    _buffered: deque[Inbound] = field(init=False, default_factory=deque)
    _sessions: dict[str, InProcSession] = field(init=False, default_factory=dict)
    """Cached session per sender-name. Same shape as TCP's per-socket session table: one
    session per (sender, us) pair, reused across frames. Cleared on `stop()`."""
    _stopped: bool = field(init=False, default=False)

    def __post_init__(self) -> None:
        if self.me in _INBOXES:
            raise LinkError(f"in-process name already registered: {self.me!r}")
        _INBOXES[self.me] = self

    def _deliver(self, frame: Frame, sender_name: str | None) -> None:
        """Called by `InProcDialer.send` when a peer sends TO us, and by `InProcSession.send`
        when a reply comes back. Wraps in `Inbound(frame, session)` where `session` is a
        cached `InProcSession` keyed by sender (so replies route symmetrically and Peer.sessions
        doesn't accumulate one entry per frame).

        `sender_name=None` when this is itself a reply (the reply's return path is already
        established elsewhere); in that case the session is a fresh stub with no reply target,
        used only to satisfy the `Inbound(frame, session)` type contract."""
        if self._stopped:
            return  # stopped: silently drop, same as a closed TCP socket does
        if sender_name is None:
            # A reply frame delivered via someone else's InProcSession -- no sender-name
            # from THIS transport hop. Stub session; send() would fail, and we don't
            # register it. `me=self.me` for the identity-carrying end so `session.address`
            # names something.
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
            self._buffered.clear()  # already forwarded; keep buffer empty

    def start(self, inbox: queue.SimpleQueue[Inbound]) -> None:
        """Attach an inbox. Any items already buffered flush into it immediately, and
        subsequent `_deliver` calls push straight through. Idempotent for the same
        inbox instance; a different one raises."""
        if self._inbox_queue is inbox:
            return
        if self._inbox_queue is not None:
            raise RuntimeError("InProcListener already started with a different inbox")
        self._inbox_queue = inbox
        for item in self._buffered:
            inbox.put(item)
        self._buffered.clear()

    def stop(self) -> None:
        """Unregister from `_INBOXES`, mark stopped, close every cached session. Idempotent.
        A closed listener that subsequently receives a send silently drops -- same as a
        stopped TCP listener would refuse the accept."""
        self._stopped = True
        self._inbox_queue = None
        _INBOXES.pop(self.me, None)
        for session in self._sessions.values():
            session.close()
        self._sessions.clear()

    def drain(self) -> tuple[Inbound, ...]:
        """Non-blocking: return the internal buffer and clear it. Test-path driver
        (`start()` need not have been called). Same semantics as `TCPListener.drain()`."""
        out = tuple(self._buffered)
        self._buffered.clear()
        return out


# --------------------------------------------------------------------------------------------- #
# Helpers                                                                                       #
# --------------------------------------------------------------------------------------------- #


def _reset_for_tests() -> None:
    """Clear the module registry. Test-only hook; production has no reason to call it.

    Named with a leading underscore and the `_for_tests` suffix so a production caller
    that reaches for this raises the reviewer's eyebrow immediately."""
    _INBOXES.clear()


def name_of(identity: crypto.PublicKey) -> str:
    """A stable in-process address for an identity. Short prefix, because these end up in
    test output and a full key is unreadable there."""
    return identity.hex()[:12]


def address_of(identity: crypto.PublicKey) -> Address:
    return Address(Scheme.INPROC, name_of(identity))
