# dude.net.transports.tcp -- real sockets, client/listener split.
#
# TWO CONCRETE TYPES, BOTH BIDIRECTIONAL FROM WAVE 2:
#
#   TCPDialer    outbound-initiated sessions. Per-target socket cache; each cached socket
#                is wrapped in a `TCPSession` and read from by a background reader thread
#                (once `start(inbox)` is called). Replies flow back through the same
#                connection they went out on -- no separate listener needed for a
#                client-only node (LightClient's shape). Implements both `Transport`
#                (send side) AND `Listener` (start/stop/drain for the reader thread).
#
#   TCPListener  inbound-accepted sessions. Owns a listen socket + a background reader
#                thread; each accepted connection becomes a `TCPSession` and pushed as
#                `Inbound(frame, session)` into the caller's inbox. Constructed with the
#                local bind address (LOCAL config, never in the roster).
#
# SESSIONS. Both types produce `TCPSession` objects (from `dude.net.session`). The
# dispatch layer (`Node.receive`, `LightClient.receive`) calls `session.bind(env.frm)`
# on the first inbound frame, then `Postman.register_session(session)` to add a
# `SessionLink` to `Peer(env.frm).sessions`. From then on, that peer's replies flow
# back on the same connection -- multi-homing benefit: a node dialed by AND dialing to
# the same peer has two independent session-Links, either usable.
#
# THE ASYMMETRY WORTH NAMING. Dialer creates sessions when we chose to reach out;
# Listener creates them when someone reached out to us. Both are equally full-duplex
# afterwards. The two objects exist because construction is asymmetric (one takes a
# target address, the other a bind address); the runtime job is the same.
#
# FRAMING: 4-byte big-endian length prefix + `Frame.raw`. TCP is a stream, not a
# message carrier; without a length prefix a partial read is indistinguishable from a
# short message. Frame size ceiling is `dude.net.envelope.MAX_FRAME_BYTES`
# (cluster-wide invariant, not a per-carrier knob).
#
# ERRORS: any OS failure (ECONNREFUSED, EPIPE, ECONNRESET, ...) collapses to
# `LinkError` out of `send()`. `Postman`'s link/breaker turns that into
# `Refused.TRANSPORT` and the multi-home retry path picks another address. A dead
# session removes itself from `TCPDialer._sessions` so the next send re-dials.

from __future__ import annotations

import contextlib
import errno
import queue
import selectors
import socket
import struct
import threading
from dataclasses import dataclass, field

from ...core.errors import DudeError
from ...core.units import Millis, now_ms
from ..address import Address, Scheme
from ..envelope import MAX_FRAME_BYTES, Frame
from ..link import LinkError, Listener, Transport
from ..session import Inbound, Session

_LEN = struct.Struct(">I")
"""4-byte big-endian frame length prefix. Max frame ~4 GiB by the field itself, capped
in practice by `MAX_FRAME_BYTES` (from `dude.net.envelope`) -- any advertised size
beyond that is treated as a malformed sender and the connection is dropped."""

_SELECT_TIMEOUT_SEC = 0.5
"""How long the reader thread blocks in `selector.select()` before checking its stop
flag AND draining any pending new-socket registrations from the send-side thread.
Short enough that `stop()` returns promptly and newly-dialed sockets start being read
within one interval; long enough that an idle reader doesn't spin."""


# --------------------------------------------------------------------------------------------- #
# TCPSession -- one open TCP connection, bidirectional.                                          #
# --------------------------------------------------------------------------------------------- #


class TCPSession(Session):
    """One TCP connection, wrapped as a Session. Owns the socket, writes on it via
    `send()`, closes it via `close()`. Identity binds on the first inbound frame's
    decoded `env.frm` (via `Session.bind` from the dispatch layer).

    THREAD MODEL. Reads happen on the owning transport's reader thread (blocking
    `recv` inside its selector loop). Writes happen on Postman's tick thread. TCP is
    duplex-safe: kernel serialises independent read/write on the same socket, and
    `sendall` is atomic within a frame. On write failure, the socket is closed and
    `on_close` fires -- both threads converge on the closed state via the `_closed`
    guard.

    OWNED-BY-TRANSPORT. `TCPListener` and `TCPDialer` each construct one per
    accepted/dialed connection and hold the canonical reference; the reader loop
    invokes `_notify_frame_in()` on incoming frames (for `last_activity`) and
    `close()` on peer-close/EOF."""

    __slots__ = ("_closed", "_sock")

    def __init__(self, sock: socket.socket, address: Address) -> None:
        super().__init__(identity=None, address=address)
        self._sock = sock
        self._closed = False

    def send(self, frame: Frame) -> None:
        if self._closed:
            raise LinkError("tcp session is closed")
        payload = frame.raw
        if len(payload) > MAX_FRAME_BYTES:
            raise LinkError(f"frame too large: {len(payload)} > {MAX_FRAME_BYTES}")
        blob = _LEN.pack(len(payload)) + payload
        try:
            self._sock.sendall(blob)
        except OSError as e:
            self._mark_closed()
            raise LinkError(f"tcp session send failed: {e}") from e
        self.last_activity = now_ms()

    def close(self) -> None:
        self._mark_closed()

    def _notify_frame_in(self, now: Millis) -> None:
        """Called by the owning transport when a complete inbound frame is extracted on
        this session's socket. Updates `last_activity` so `Peer.usable()`'s
        freshest-first ordering reflects real recency."""
        self.last_activity = now

    def _mark_closed(self) -> None:
        if self._closed:
            return
        self._closed = True
        with contextlib.suppress(OSError):
            self._sock.shutdown(socket.SHUT_RDWR)
        with contextlib.suppress(OSError):
            self._sock.close()
        if self.on_close is not None:
            self.on_close()


# --------------------------------------------------------------------------------------------- #
# Reader-thread body -- shared between TCPDialer and TCPListener.                                #
# --------------------------------------------------------------------------------------------- #


def _extract_and_dispatch(
    buf: bytearray,
    session: TCPSession,
    buffered: list[Inbound],
    now: Millis,
) -> bool:
    """Extract complete frames from `buf` and dispatch as `Inbound(frame, session)` into
    `buffered`. Returns True iff the socket should be closed (frame length exceeded
    `MAX_FRAME_BYTES` -- misbehaving sender)."""
    while len(buf) >= _LEN.size:
        (length,) = _LEN.unpack_from(buf, 0)
        if length > MAX_FRAME_BYTES:
            return True
        if len(buf) < _LEN.size + length:
            return False
        payload = bytes(buf[_LEN.size : _LEN.size + length])
        del buf[: _LEN.size + length]
        try:
            frame = Frame.decode(payload)
        except DudeError:
            continue  # malformed frame -- drop, keep reading (peer might be misbehaving)
        session._notify_frame_in(now)  # noqa: SLF001 -- same-module cooperative access
        buffered.append(Inbound(frame, session))
    return False


# --------------------------------------------------------------------------------------------- #
# TCPDialer -- outbound sessions + read replies on their sockets.                                #
# --------------------------------------------------------------------------------------------- #


@dataclass(slots=True)
class TCPDialer(Transport, Listener):
    """TCP's outbound side. Per-target session cache; `send(address, frame)` dials on
    first use, wraps the socket in a `TCPSession`, sends via that session, and
    subsequently reuses the session for further sends to the same address.

    BIDIRECTIONAL FROM WAVE 2. Once `start(inbox)` is called, a background reader
    thread polls every open outbound socket and pushes complete inbound frames into
    the inbox as `Inbound(frame, session)`. This is what makes a client-only node
    (LightClient shape) reachable for replies without ever running a listener:
    replies flow back on the same TCP connection the client opened.

    Any OS-level failure on a given socket closes the session, removes it from the
    cache, and (for `send`) raises `LinkError`. `Postman`'s link/breaker layer decides
    what happens next; a subsequent send to the same address re-dials.

    THREAD SAFETY. `send()` runs on Postman's tick thread; the reader thread does
    `select()` in a loop. New sockets registered by `send()` are added to a pending
    queue that the reader thread drains at the top of each iteration -- avoids
    calling `selector.register()` while `select()` is blocking (undefined behaviour
    in some backends)."""

    _sessions: dict[Address, TCPSession] = field(init=False, default_factory=dict)
    _read_buf: dict[socket.socket, bytearray] = field(init=False, default_factory=dict)
    _sock_to_session: dict[socket.socket, TCPSession] = field(init=False, default_factory=dict)
    _pending_registrations: queue.SimpleQueue[socket.socket] = field(
        init=False, default_factory=queue.SimpleQueue
    )
    _pending_deregistrations: queue.SimpleQueue[socket.socket] = field(
        init=False, default_factory=queue.SimpleQueue
    )
    _selector: selectors.BaseSelector | None = field(init=False, default=None)
    _buffered: list[Inbound] = field(init=False, default_factory=list)
    _inbox: queue.SimpleQueue[Inbound] | None = field(init=False, default=None)
    _stopping: threading.Event = field(init=False, default_factory=threading.Event)
    _thread: threading.Thread | None = field(init=False, default=None)

    # -- Transport (send side) ---------------------------------------------------------- #

    def send(self, address: Address, frame: Frame) -> None:
        if address.scheme is not Scheme.TCP:
            raise LinkError(f"tcp cannot dial {address.scheme.value.decode()}")
        session = self._sessions.get(address)
        if session is None:
            sock = self._connect(address)
            session = TCPSession(sock, address)
            self._sessions[address] = session
            self._sock_to_session[sock] = session
            self._read_buf[sock] = bytearray()
            # Reader thread will pick this socket up on its next selector iteration.
            self._pending_registrations.put(sock)
        try:
            session.send(frame)
        except LinkError:
            self._drop_session(address, session)
            raise

    def close(self) -> None:
        """Close every outbound session. Idempotent. Called on process shutdown; also
        called from `stop()`. Between sends there is no reason to call this."""
        for address, session in list(self._sessions.items()):
            self._drop_session(address, session)

    # -- Listener (start/stop/drain -- for reading replies) ----------------------------- #

    def start(self, inbox: queue.SimpleQueue[Inbound]) -> None:
        """Spawn the reader thread. Every subsequent complete `Inbound(frame, session)`
        read on any outbound session goes into `inbox`. Idempotent for the same inbox
        instance; a different one raises. Sessions dialed BEFORE `start()` are picked
        up on the reader's first iteration (via the pending-registrations queue)."""
        if self._inbox is inbox:
            return
        if self._inbox is not None:
            raise RuntimeError("TCPDialer already started with a different inbox")
        self._inbox = inbox
        self._selector = selectors.DefaultSelector()
        # Any sockets already dialed pre-start need registering.
        for sock in list(self._sock_to_session):
            self._pending_registrations.put(sock)
        self._thread = threading.Thread(target=self._run, name="tcp-dialer-reader", daemon=True)
        self._thread.start()

    def stop(self) -> None:
        """Signal, close every session, join. Idempotent."""
        self._stopping.set()
        thread = self._thread
        self._thread = None
        if thread is not None and thread.is_alive():
            thread.join(timeout=2.0)
        self.close()
        if self._selector is not None:
            with contextlib.suppress(Exception):
                self._selector.close()
            self._selector = None

    def drain(self) -> tuple[Inbound, ...]:
        """Non-blocking: poll once, extract every ready `Inbound`, return them. Test
        driver (`start()` need not have been called). Same semantics as
        `TCPListener.drain()`; useful for `Cluster.pump()`-style deterministic pumps."""
        if self._stopping.is_set():
            return ()
        if self._selector is None:
            self._selector = selectors.DefaultSelector()
        self._poll_once(timeout=0, forward_to_inbox=False)
        out = tuple(self._buffered)
        self._buffered.clear()
        return out

    # -- internals ---------------------------------------------------------------------- #

    def _connect(self, address: Address) -> socket.socket:
        host, _, port_s = address.value.partition(":")
        if not port_s:
            raise LinkError(f"tcp address missing port: {address.value}")
        try:
            port = int(port_s)
        except ValueError as e:
            raise LinkError(f"tcp address has non-integer port: {address.value}") from e
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        try:
            sock.connect((host, port))
        except OSError as e:
            sock.close()
            raise LinkError(f"tcp connect to {address.value} failed: {e}") from e
        sock.setblocking(False)
        return sock

    def _drop_session(self, address: Address, session: TCPSession) -> None:
        self._sessions.pop(address, None)
        sock = session._sock  # noqa: SLF001 -- same-module cooperative access
        self._sock_to_session.pop(sock, None)
        self._read_buf.pop(sock, None)
        if self._selector is not None:
            self._pending_deregistrations.put(sock)
        session.close()  # fires on_close -> Postman.unregister_session

    def _run(self) -> None:
        while not self._stopping.is_set():
            self._poll_once(timeout=_SELECT_TIMEOUT_SEC, forward_to_inbox=True)

    def _poll_once(self, *, timeout: float, forward_to_inbox: bool) -> None:
        if self._selector is None:  # not started (drain-first path); make a temp one
            return
        # Drain pending (de)registrations first -- new sockets from send(), dead sockets
        # from _drop_session. Must happen BEFORE select() so select observes them.
        self._drain_pending()
        try:
            events = self._selector.select(timeout=timeout)
        except OSError:
            return
        for key, _events in events:
            sock = key.fileobj
            assert isinstance(sock, socket.socket)  # noqa: S101
            self._read_from(sock)
        if forward_to_inbox and self._buffered:
            inbox = self._inbox
            if inbox is not None:
                for item in self._buffered:
                    inbox.put(item)
                self._buffered.clear()

    def _drain_pending(self) -> None:
        assert self._selector is not None  # noqa: S101
        while True:
            try:
                sock = self._pending_registrations.get_nowait()
            except queue.Empty:
                break
            with contextlib.suppress(KeyError, ValueError):
                self._selector.register(sock, selectors.EVENT_READ, data="outbound")
        while True:
            try:
                sock = self._pending_deregistrations.get_nowait()
            except queue.Empty:
                break
            with contextlib.suppress(KeyError, ValueError):
                self._selector.unregister(sock)

    def _read_from(self, sock: socket.socket) -> None:
        session = self._sock_to_session.get(sock)
        buf = self._read_buf.get(sock)
        if session is None or buf is None:
            self._close_sock(sock)
            return
        try:
            chunk = sock.recv(65536)
        except BlockingIOError:
            return
        except OSError as e:
            if e.errno != errno.ECONNRESET:
                pass
            self._close_sock(sock)
            return
        if not chunk:  # clean EOF
            self._close_sock(sock)
            return
        buf.extend(chunk)
        if _extract_and_dispatch(buf, session, self._buffered, now_ms()):
            self._close_sock(sock)

    def _close_sock(self, sock: socket.socket) -> None:
        session = self._sock_to_session.pop(sock, None)
        self._read_buf.pop(sock, None)
        if self._selector is not None:
            with contextlib.suppress(KeyError, ValueError):
                self._selector.unregister(sock)
        if session is not None:
            # Remove address entry too.
            for addr, s in list(self._sessions.items()):
                if s is session:
                    del self._sessions[addr]
                    break
            session.close()
        else:
            with contextlib.suppress(OSError):
                sock.close()


# --------------------------------------------------------------------------------------------- #
# TCPListener -- inbound-accepted sessions.                                                     #
# --------------------------------------------------------------------------------------------- #


@dataclass(slots=True)
class TCPListener(Listener):
    """TCP's accept side. Binds a listen socket at construction (which is why bind
    failures surface early -- the caller gets `OSError` from `__init__`, not a
    delayed thread crash).

    Two driver paths, one implementation:

      * PRODUCTION -- `start(inbox)` spawns a reader thread that runs a selector
        loop: accept new connections, wrap each in a `TCPSession`, read complete
        frames, push each into `inbox` as `Inbound(frame, session)`. `stop()` signals
        the thread, closes the listener, joins with a bounded timeout.
      * TESTS -- `drain()` runs the same selector loop for one iteration
        (`select(0)`), then returns whatever complete `Inbound` items buffered in
        this call. No thread involved. `start()` need not have been called.

    Same internal buffer / same frame-extraction code either way. `drain()` after
    `start()` returns whatever `_run` hasn't yet pushed to the inbox; well-defined
    but unusual (mixing driver paths is a caller error, not a shape we support)."""

    listen_host: str = "127.0.0.1"
    listen_port: int = 0
    _selector: selectors.BaseSelector = field(init=False)
    _listener: socket.socket = field(init=False)
    _bound_port: int = field(init=False, default=0)
    _read_buf: dict[socket.socket, bytearray] = field(init=False, default_factory=dict)
    _sessions: dict[socket.socket, TCPSession] = field(init=False, default_factory=dict)
    _buffered: list[Inbound] = field(init=False, default_factory=list)
    _inbox: queue.SimpleQueue[Inbound] | None = field(init=False, default=None)
    _stopping: threading.Event = field(init=False, default_factory=threading.Event)
    _thread: threading.Thread | None = field(init=False, default=None)

    def __post_init__(self) -> None:
        self._selector = selectors.DefaultSelector()
        self._listener = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        try:
            self._listener.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            self._listener.bind((self.listen_host, self.listen_port))
            self._listener.setblocking(False)
            self._listener.listen(128)
        except OSError:
            with contextlib.suppress(OSError):
                self._listener.close()
            self._selector.close()
            raise
        self._bound_port = self._listener.getsockname()[1]
        self._selector.register(self._listener, selectors.EVENT_READ, data="listener")

    @property
    def bound_address(self) -> Address:
        return Address(Scheme.TCP, f"{self.listen_host}:{self._bound_port}")

    def start(self, inbox: queue.SimpleQueue[Inbound]) -> None:
        if self._inbox is inbox:
            return
        if self._inbox is not None:
            raise RuntimeError("TCPListener already started with a different inbox")
        self._inbox = inbox
        self._thread = threading.Thread(
            target=self._run, name=f"tcp-listener-{self._bound_port}", daemon=True
        )
        self._thread.start()

    def stop(self) -> None:
        self._stopping.set()
        with contextlib.suppress(OSError):
            self._listener.shutdown(socket.SHUT_RDWR)
        thread = self._thread
        self._thread = None
        if thread is not None and thread.is_alive():
            thread.join(timeout=2.0)
        self._close_all()

    def drain(self) -> tuple[Inbound, ...]:
        if self._stopping.is_set():
            return ()
        self._poll_once(timeout=0, forward_to_inbox=False)
        out = tuple(self._buffered)
        self._buffered.clear()
        return out

    def _run(self) -> None:
        while not self._stopping.is_set():
            self._poll_once(timeout=_SELECT_TIMEOUT_SEC, forward_to_inbox=True)

    def _poll_once(self, *, timeout: float, forward_to_inbox: bool) -> None:
        try:
            events = self._selector.select(timeout=timeout)
        except OSError:
            return
        for key, _events in events:
            sock = key.fileobj
            assert isinstance(sock, socket.socket)  # noqa: S101
            if key.data == "listener":
                self._accept()
            else:
                self._read_from(sock)
        if forward_to_inbox and self._buffered:
            inbox = self._inbox
            if inbox is not None:
                for item in self._buffered:
                    inbox.put(item)
                self._buffered.clear()

    def _accept(self) -> None:
        while True:
            try:
                conn, peer_addr = self._listener.accept()
            except (BlockingIOError, OSError):
                return
            conn.setblocking(False)
            self._read_buf[conn] = bytearray()
            host, port = peer_addr[:2]
            self._sessions[conn] = TCPSession(conn, Address(Scheme.TCP, f"{host}:{port}"))
            self._selector.register(conn, selectors.EVENT_READ, data="incoming")

    def _read_from(self, sock: socket.socket) -> None:
        buf = self._read_buf.get(sock)
        session = self._sessions.get(sock)
        if buf is None or session is None:
            self._closesock(sock)
            return
        try:
            chunk = sock.recv(65536)
        except BlockingIOError:
            return
        except OSError as e:
            if e.errno != errno.ECONNRESET:
                pass
            self._closesock(sock)
            return
        if not chunk:
            self._closesock(sock)
            return
        buf.extend(chunk)
        if _extract_and_dispatch(buf, session, self._buffered, now_ms()):
            self._closesock(sock)

    def _closesock(self, sock: socket.socket) -> None:
        self._read_buf.pop(sock, None)
        session = self._sessions.pop(sock, None)
        with contextlib.suppress(KeyError, ValueError):
            self._selector.unregister(sock)
        if session is not None:
            session.close()
        else:
            with contextlib.suppress(OSError):
                sock.close()

    def _close_all(self) -> None:
        for sock in list(self._read_buf):
            self._closesock(sock)
        if self._listener.fileno() != -1:
            with contextlib.suppress(KeyError, ValueError):
                self._selector.unregister(self._listener)
            self._listener.close()
        with contextlib.suppress(Exception):
            self._selector.close()


