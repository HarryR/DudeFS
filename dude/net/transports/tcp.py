from __future__ import annotations

import contextlib
import queue
import socket
import struct
import threading
from dataclasses import dataclass, field

from ...core.errors import DudeError
from ...core.units import Millis, now_ms
from ...tunables import Tunables
from ..address import Address, Scheme
from ..envelope import MAX_FRAME_BYTES, Frame
from ..link import Link, LinkError, Listener, OnFrame, OnLink

_LEN = struct.Struct(">I")

_OUTBOX_DEPTH = 64


@dataclass(frozen=True, slots=True)
class TCPTiming:
    connect: Millis = 6_000
    send: Millis = 4_000
    idle_wait: Millis = 500
    stop_join: Millis = 2_000

    @classmethod
    def for_deployment(cls, t: Tunables) -> TCPTiming:
        return cls(connect=2 * t.rtt_max, send=2 * t.rtt_max)

    @property
    def connect_sec(self) -> float:
        return self.connect / 1000

    @property
    def send_sec(self) -> float:
        return self.send / 1000

    @property
    def idle_wait_sec(self) -> float:
        return self.idle_wait / 1000

    @property
    def stop_join_sec(self) -> float:
        return self.stop_join / 1000


class _TCPConn:
    __slots__ = ("_closed", "_out", "_reader", "_sock", "_writer", "link")

    def __init__(
        self,
        sock: socket.socket,
        address: Address,
        timing: TCPTiming,
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
        self.link.last_activity = now_ms()

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
            self.link.last_activity = now_ms()
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
        "_address", "_on_frame", "_on_link",
        "_stopping", "_thread", "_timing",
        "_pending_sock", "_sock_lock",
    )

    def __init__(
        self,
        address: Address,
        timing: TCPTiming,
        on_frame: OnFrame,
        on_link: OnLink,
    ) -> None:
        self._address = address
        self._timing = timing
        self._on_frame = on_frame
        self._on_link = on_link
        self._stopping = threading.Event()
        self._pending_sock: socket.socket | None = None
        self._sock_lock = threading.Lock()
        self._thread = threading.Thread(
            target=self._serve, name=f"tcp-dial-{address.value}", daemon=True
        )
        self._thread.start()

    def stop(self) -> None:
        self._stopping.set()
        with self._sock_lock:
            if self._pending_sock is not None:
                with contextlib.suppress(OSError):
                    self._pending_sock.close()

    def join(self) -> None:
        self._thread.join()

    def _serve(self) -> None:
        while not self._stopping.is_set():
            sock = self._try_connect()
            if sock is None:
                self._stopping.wait(timeout=self._timing.connect_sec)
                continue
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


@dataclass(slots=True)
class TCPDialer(Listener):
    timing: TCPTiming = TCPTiming()

    _workers: dict[Address, _DialWorker] = field(init=False, default_factory=dict)
    _on_frame: OnFrame | None = field(init=False, default=None)
    _on_link: OnLink | None = field(init=False, default=None)
    _stopping: threading.Event = field(init=False, default_factory=threading.Event)

    def start(self, on_frame: OnFrame, on_link: OnLink) -> None:
        if self._on_frame is not None:
            raise RuntimeError("TCPDialer already started")
        self._on_frame = on_frame
        self._on_link = on_link

    def dial(self, address: Address) -> None:
        if address.scheme is not Scheme.TCP or self._stopping.is_set():
            return
        if self._on_frame is None or self._on_link is None:
            return
        if address not in self._workers:
            self._workers[address] = _DialWorker(
                address, self.timing, self._on_frame, self._on_link,
            )

    def stop(self) -> None:
        self._stopping.set()
        for worker in self._workers.values():
            worker.stop()
        for worker in self._workers.values():
            worker.join()
        self._workers.clear()


@dataclass(slots=True)
class TCPListener(Listener):
    listen_host: str = "127.0.0.1"
    listen_port: int = 0
    timing: TCPTiming = TCPTiming()
    _listener: socket.socket = field(init=False)
    _bound_port: int = field(init=False, default=0)
    _conns: list[_TCPConn] = field(init=False, default_factory=list)
    _on_frame: OnFrame | None = field(init=False, default=None)
    _on_link: OnLink | None = field(init=False, default=None)
    _stopping: threading.Event = field(init=False, default_factory=threading.Event)
    _thread: threading.Thread | None = field(init=False, default=None)

    def __post_init__(self) -> None:
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

    def dial(self, address: Address) -> None:
        pass

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
                self.timing,
                self._on_frame,
                self._on_link,
            )
            self._conns.append(conn)
            self._conns = [c for c in self._conns if not c._closed]  # noqa: SLF001
