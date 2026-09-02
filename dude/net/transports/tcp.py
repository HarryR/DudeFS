from __future__ import annotations

import contextlib
import queue
import socket
import struct
import threading
import time
from dataclasses import dataclass, field

import socks

from ...core.errors import DudeError
from ...core.units import Millis
from ...tunables import Tunables
from ..address import Address, Scheme
from ..envelope import MAX_FRAME_BYTES, Frame
from ..link import Acceptor, Dialer, Link, LinkError, OnFrame, OnLink

_LEN = struct.Struct(">I")

_OUTBOX_DEPTH = 64


@dataclass(frozen=True, slots=True)
class _TCPTiming:
    connect_sec: float
    send_sec: float
    idle_wait_sec: float

    @classmethod
    def from_tunables(cls, t: Tunables) -> _TCPTiming:
        return cls(
            connect_sec=t.tcp_connect.as_seconds,
            send_sec=t.tcp_send.as_seconds,
            idle_wait_sec=t.tick_interval.as_seconds,
        )


class _TCPConn:
    __slots__ = ("_closed", "_out", "_reader", "_sock", "_writer", "link")

    def __init__(
        self,
        sock: socket.socket,
        address: Address,
        timing: _TCPTiming,
        on_frame: OnFrame,
        on_link: OnLink,
    ) -> None:
        sock.setblocking(True)
        _bound_sends(sock, timing.send_sec)
        self._sock = sock
        self._closed = False
        self._out: queue.Queue[bytes | None] = queue.Queue(maxsize=_OUTBOX_DEPTH)

        self.link = Link(
            address=address,
            identity=None,
            _send_frame=self._enqueue,
            _close_transport=self._shutdown,
        )
        on_link(self.link)

        self._reader = threading.Thread(
            target=self._read_loop, args=(on_frame,), name="tcp-rx", daemon=True
        )
        self._writer = threading.Thread(target=self._write_loop, name="tcp-tx", daemon=True)
        self._reader.start()
        self._writer.start()

    def _enqueue(self, frame: Frame) -> None:
        if self._closed:
            raise LinkError("tcp connection is closed")
        payload = frame.raw
        if len(payload) > MAX_FRAME_BYTES:
            raise LinkError(f"frame too large: {len(payload)} > {MAX_FRAME_BYTES}")
        try:
            self._out.put_nowait(_LEN.pack(len(payload)) + payload)
        except queue.Full as e:
            raise LinkError("tcp outbox is full; peer is not reading") from e
        self.link.last_activity = Millis.now()

    def _shutdown(self) -> None:
        if self._closed:
            return
        self._closed = True
        with contextlib.suppress(queue.Full):
            self._out.put_nowait(None)
        with contextlib.suppress(OSError):
            self._sock.shutdown(socket.SHUT_RDWR)
        with contextlib.suppress(OSError):
            self._sock.close()

    def join(self) -> None:
        self._shutdown()
        self._reader.join()
        self._writer.join()

    def _fail(self) -> None:
        self._shutdown()
        self.link.notify_closed()

    def _write_loop(self) -> None:
        while True:
            blob = self._out.get()
            if blob is None:
                return
            try:
                self._sock.sendall(blob)
            except OSError:
                self._fail()
                return

    def _read_loop(self, on_frame: OnFrame) -> None:
        buf = bytearray()
        while True:
            try:
                chunk = self._sock.recv(65536)
            except OSError:
                self._fail()
                return
            if not chunk:
                self._fail()
                return
            buf.extend(chunk)
            if self._extract(buf, on_frame):
                self._fail()
                return

    def _extract(self, buf: bytearray, on_frame: OnFrame) -> bool:
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
                continue
            self.link.last_activity = Millis.now()
            on_frame(frame, self.link)
        return False


def _bound_sends(sock: socket.socket, seconds: float) -> None:
    whole = int(seconds)
    with contextlib.suppress(OSError, struct.error):
        sock.setsockopt(
            socket.SOL_SOCKET,
            socket.SO_SNDTIMEO,
            struct.pack("ll", whole, int((seconds - whole) * 1_000_000)),
        )


class _DialWorker:
    __slots__ = (
        "_address",
        "_on_frame",
        "_on_link",
        "_pending_sock",
        "_sock_lock",
        "_socks5",
        "_stopping",
        "_thread",
        "_timing",
        "connected",
    )

    def __init__(
        self,
        address: Address,
        timing: _TCPTiming,
        on_frame: OnFrame,
        on_link: OnLink,
        socks5: tuple[str, int] | None = None,
    ) -> None:
        self._address = address
        self._timing = timing
        self._on_frame = on_frame
        self._on_link = on_link
        self._socks5 = socks5
        self._stopping = threading.Event()
        self._pending_sock: socket.socket | None = None
        self._sock_lock = threading.Lock()
        self.connected = False
        self._thread = threading.Thread(
            target=self._serve, name=f"tcp-dial-{address.value}", daemon=True
        )
        self._thread.start()

    def alive(self) -> bool:
        return self._thread.is_alive()

    def stop(self) -> None:
        self._stopping.set()
        with self._sock_lock:
            if self._pending_sock is not None:
                with contextlib.suppress(OSError):
                    self._pending_sock.close()

    def join(self) -> None:
        self._thread.join()

    def _serve(self) -> None:
        sock = self._try_connect()
        if sock is None:
            return
        self.connected = True
        conn = _TCPConn(sock, self._address, self._timing, self._on_frame, self._on_link)
        conn.link.on_close = lambda _ln: None
        while not conn._closed and not self._stopping.is_set():  # noqa: SLF001
            self._stopping.wait(timeout=self._timing.idle_wait_sec)
        conn.join()

    def _try_connect(self) -> socket.socket | None:
        host, _, port_s = self._address.value.partition(":")
        if not port_s:
            return None
        try:
            port = int(port_s)
        except ValueError:
            return None
        if self._socks5 is not None:
            sock = socks.socksocket(socket.AF_INET, socket.SOCK_STREAM)
            sock.set_proxy(socks.SOCKS5, self._socks5[0], self._socks5[1])
        else:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(self._timing.connect_sec)
        with self._sock_lock:
            if self._stopping.is_set():
                sock.close()
                return None
            self._pending_sock = sock
        try:
            sock.connect((host, port))
        except OSError:
            sock.close()
            return None
        finally:
            with self._sock_lock:
                self._pending_sock = None
        return sock


def _parse_socks5(addr: str | None) -> tuple[str, int] | None:
    if addr is None:
        return None
    host, _, port_s = addr.rpartition(":")
    if not host:
        return None
    return host, int(port_s)


@dataclass(slots=True)
class TCPDialer(Dialer):
    tunables: Tunables
    _timing: _TCPTiming = field(init=False)
    _socks5: tuple[str, int] | None = field(init=False)
    _workers: dict[Address, _DialWorker] = field(init=False, default_factory=dict)
    _failures: dict[Address, int] = field(init=False, default_factory=dict)
    _cooldown_until: dict[Address, float] = field(init=False, default_factory=dict)
    _on_frame: OnFrame | None = field(init=False, default=None)
    _on_link: OnLink | None = field(init=False, default=None)
    _stopping: threading.Event = field(init=False, default_factory=threading.Event)

    def __post_init__(self) -> None:
        self._timing = _TCPTiming.from_tunables(self.tunables)
        self._socks5 = _parse_socks5(self.tunables.transports.tcp.socks5)

    def _accepts(self, address: Address) -> Address | None:
        if address.scheme is not Scheme.TCP:
            return None
        if not self.tunables.transports.tcp.enabled:
            return None
        return address

    def start(self, on_frame: OnFrame, on_link: OnLink) -> None:
        self._on_frame = on_frame
        self._on_link = on_link

    def dial(self, address: Address) -> bool:
        if self._stopping.is_set() or self._on_frame is None or self._on_link is None:
            return False
        wire_addr = self._accepts(address)
        if wire_addr is None:
            return False
        now = time.monotonic()
        if wire_addr in self._cooldown_until:
            if now < self._cooldown_until[wire_addr]:
                return False
            del self._cooldown_until[wire_addr]
        if wire_addr in self._workers:
            worker = self._workers[wire_addr]
            if worker.alive():
                return True
            del self._workers[wire_addr]
            if worker.connected:
                self._failures.pop(wire_addr, None)
            else:
                n = self._failures.get(wire_addr, 0) + 1
                self._failures[wire_addr] = n
                cap = self._timing.connect_sec * 30
                backoff = min(self._timing.connect_sec * (2**n), cap)
                self._cooldown_until[wire_addr] = now + backoff
                return False
        self._workers[wire_addr] = _DialWorker(
            wire_addr,
            self._timing,
            self._on_frame,
            self._on_link,
            socks5=self._socks5,
        )
        return True

    def stop(self) -> None:
        self._stopping.set()
        for worker in self._workers.values():
            worker.stop()
        for worker in self._workers.values():
            worker.join()
        self._workers.clear()


@dataclass(slots=True)
class OnionDialer(TCPDialer):
    def __post_init__(self) -> None:
        self._timing = _TCPTiming.from_tunables(self.tunables)
        parsed = _parse_socks5(self.tunables.transports.onion.socks5)
        if parsed is None:
            raise ValueError("onion transport requires a socks5 proxy address")
        self._socks5 = parsed

    def _accepts(self, address: Address) -> Address | None:
        if address.scheme is not Scheme.ONION:
            return None
        if not self.tunables.transports.onion.enabled:
            return None
        host, _, _ = address.value.partition(":")
        if not host.endswith(".onion"):
            return None
        return address


@dataclass(slots=True)
class TCPListener(Acceptor):
    tunables: Tunables
    listen_host: str = "127.0.0.1"
    listen_port: int = 0
    _timing: _TCPTiming = field(init=False)
    _listener: socket.socket = field(init=False)
    _bound_port: int = field(init=False, default=0)
    _conns: list[_TCPConn] = field(init=False, default_factory=list)
    _on_frame: OnFrame | None = field(init=False, default=None)
    _on_link: OnLink | None = field(init=False, default=None)
    _stopping: threading.Event = field(init=False, default_factory=threading.Event)
    _thread: threading.Thread | None = field(init=False, default=None)

    def __post_init__(self) -> None:
        self._timing = _TCPTiming.from_tunables(self.tunables)
        self._listener = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        try:
            self._listener.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            self._listener.bind((self.listen_host, self.listen_port))
            self._listener.listen(128)
        except OSError:
            with contextlib.suppress(OSError):
                self._listener.close()
            raise
        self._bound_port = self._listener.getsockname()[1]
        self._thread = threading.Thread(
            target=self._accept_loop, name=f"tcp-accept-{self._bound_port}", daemon=True
        )
        self._thread.start()

    @property
    def bound_address(self) -> Address:
        return Address(Scheme.TCP, f"{self.listen_host}:{self._bound_port}")

    def start(self, on_frame: OnFrame, on_link: OnLink) -> None:
        if self._on_frame is not None:
            raise RuntimeError("TCPListener already started")
        self._on_frame = on_frame
        self._on_link = on_link

    def stop(self) -> None:
        self._stopping.set()
        with contextlib.suppress(OSError):
            self._listener.shutdown(socket.SHUT_RDWR)
        with contextlib.suppress(OSError):
            self._listener.close()
        thread = self._thread
        self._thread = None
        if thread is not None:
            thread.join()
        for conn in self._conns:
            conn.join()
        self._conns.clear()

    def _accept_loop(self) -> None:
        while not self._stopping.is_set():
            try:
                conn_sock, peer_addr = self._listener.accept()
            except OSError:
                return
            if self._on_frame is None or self._on_link is None:
                conn_sock.close()
                continue
            host, port = peer_addr[:2]
            conn = _TCPConn(
                conn_sock,
                Address(Scheme.TCP, f"{host}:{port}"),
                self._timing,
                self._on_frame,
                self._on_link,
            )
            self._conns.append(conn)
            self._conns = [c for c in self._conns if not c._closed]  # noqa: SLF001
