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

_SELECT_TIMEOUT_SEC = 0.5


class TCPSession(Session):
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


def _extract_and_dispatch(
    buf: bytearray,
    session: TCPSession,
    buffered: list[Inbound],
    now: Millis,
) -> bool:
    while len(buf) >= _LEN.size:
        (length,) = _LEN.unpack_from(buf, 0)
        if length > MAX_FRAME_BYTES:  # refuse BEFORE allocating what the sender claims
            return True
        if len(buf) < _LEN.size + length:
            return False
        payload = bytes(buf[_LEN.size : _LEN.size + length])
        del buf[: _LEN.size + length]
        try:
            frame = Frame.decode(payload)
        except DudeError:
            continue
        session._notify_frame_in(now)  # noqa: SLF001 -- same-module cooperative access
        buffered.append(Inbound(frame, session))
    return False


@dataclass(slots=True)
class TCPDialer(Transport, Listener):
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
            self._pending_registrations.put(sock)
        try:
            session.send(frame)
        except LinkError:
            self._drop_session(address, session)
            raise

    def close(self) -> None:
        for address, session in list(self._sessions.items()):
            self._drop_session(address, session)

    def start(self, inbox: queue.SimpleQueue[Inbound]) -> None:
        if self._inbox is inbox:
            return
        if self._inbox is not None:
            raise RuntimeError("TCPDialer already started with a different inbox")
        self._inbox = inbox
        self._selector = selectors.DefaultSelector()
        for sock in list(self._sock_to_session):
            self._pending_registrations.put(sock)
        self._thread = threading.Thread(target=self._run, name="tcp-dialer-reader", daemon=True)
        self._thread.start()

    def stop(self) -> None:
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
        if self._stopping.is_set():
            return ()
        if self._selector is None:
            self._selector = selectors.DefaultSelector()
        self._poll_once(timeout=0, forward_to_inbox=False)
        out = tuple(self._buffered)
        self._buffered.clear()
        return out

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
        session.close()

    def _run(self) -> None:
        while not self._stopping.is_set():
            self._poll_once(timeout=_SELECT_TIMEOUT_SEC, forward_to_inbox=True)

    def _poll_once(self, *, timeout: float, forward_to_inbox: bool) -> None:
        if self._selector is None:
            return
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
        if not chunk:
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
            for addr, s in list(self._sessions.items()):
                if s is session:
                    del self._sessions[addr]
                    break
            session.close()
        else:
            with contextlib.suppress(OSError):
                sock.close()


@dataclass(slots=True)
class TCPListener(Listener):
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
