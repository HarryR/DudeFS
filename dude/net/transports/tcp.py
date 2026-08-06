# dude.net.transports.tcp -- real sockets, client/listener split.
#
# TWO CONCRETE TYPES, DELIBERATELY SEPARATE:
#
#   TCPClient    send-only. Per-target outbound socket cache. `Postman` holds one via
#                `attach_transport(Scheme.TCP, client)`. Constructed with no config
#                because outbound TCP needs nothing from the caller beyond what each
#                `send(address, frame)` names.
#
#   TCPListener  receive-only. Owns a listen socket + accepted-connection state + a
#                background reader thread (in `start(inbox)`) or an internal buffer
#                (drained by `drain()`). Constructed with the local bind address --
#                which is LOCAL config, never in the roster.
#
# WHY THE SPLIT: `TCP` used to weld the two roles into one class, which forced every
# construction to bind a listener even for client-only nodes (behind NAT), and made the
# `Dialler` contract in `postman.py` awkward (it fabricated a listener from a peer's
# endpoint, which is meaningless for TCP). The split matches the `Transport` / `Listener`
# distinction in `link.py`: one protocol per role, one object per role.
#
# CONNECTION MODEL: two independent TCP connections per peer-pair. A's outbound socket
# to B's listener is distinct from B's outbound socket to A's listener. The alternative
# (reuse the accepted socket for the reverse direction) would need transport-level
# identification of who accepted us, which breaks layering -- transports carry addresses,
# envelopes carry identities.
#
# FRAMING: 4-byte big-endian length prefix + `Frame.raw`. TCP is a stream, not a message
# carrier; without a length prefix a partial read is indistinguishable from a short
# message. Frame size ceiling is `dude.net.envelope.MAX_FRAME_BYTES` (cluster-wide
# invariant, not a per-carrier knob).
#
# ERRORS: any OS failure (ECONNREFUSED, EPIPE, ECONNRESET, ...) collapses to `LinkError`
# out of `send()`. `Postman`'s link/breaker turns that into `Refused.TRANSPORT` and the
# multi-home retry path picks another address.

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
from ..address import Address, Scheme
from ..envelope import MAX_FRAME_BYTES, Frame
from ..link import LinkError, Listener, Transport

_LEN = struct.Struct(">I")
"""4-byte big-endian frame length prefix. Max frame ~4 GiB by the field itself, capped
in practice by `MAX_FRAME_BYTES` (from `dude.net.envelope`) -- any advertised size
beyond that is treated as a malformed sender and the connection is dropped."""

_SELECT_TIMEOUT_SEC = 0.5
"""How long `TCPListener`'s reader thread blocks in `selector.select()` before checking
its stop flag. Short enough that `stop()` returns promptly, long enough that an idle
listener doesn't spin. Not a tunable: tests don't run the threaded path (they use
`drain()`), and production doesn't care what the exact idle latency of shutdown is."""


# --------------------------------------------------------------------------------------------- #
# Client -- outbound only, held by Postman                                                      #
# --------------------------------------------------------------------------------------------- #


@dataclass(slots=True)
class TCPClient(Transport):
    """TCP's send side. Owns a per-target outbound socket cache; `send(address, frame)`
    opens a socket on first use and reuses it across sends. Any OS-level failure on a
    given socket closes it, drops it from the cache, and raises `LinkError` -- the
    caller's Link/breaker layer decides what happens next.

    Blocking `sendall`, single-threaded call site (Postman's tick thread). Not a
    threadsafe transport -- concurrent sends from multiple Postmen would race the
    outbound dict."""

    _outbound: dict[Address, socket.socket] = field(init=False, default_factory=dict)

    def send(self, address: Address, frame: Frame) -> None:
        if address.scheme is not Scheme.TCP:
            raise LinkError(f"tcp cannot dial {address.scheme.value.decode()}")
        payload = frame.raw
        if len(payload) > MAX_FRAME_BYTES:
            raise LinkError(f"frame too large: {len(payload)} > {MAX_FRAME_BYTES}")
        blob = _LEN.pack(len(payload)) + payload
        sock = self._outbound.get(address)
        if sock is None:
            sock = self._connect(address)
            self._outbound[address] = sock
        try:
            sock.sendall(blob)
        except OSError as e:
            self._drop(address, sock)
            raise LinkError(f"tcp send to {address.value} failed: {e}") from e

    def close(self) -> None:
        """Close every outbound socket. Idempotent. Called on process shutdown; not
        needed between sends."""
        for address in list(self._outbound):
            self._drop(address, self._outbound[address])

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
        return sock

    def _drop(self, address: Address, sock: socket.socket) -> None:
        self._outbound.pop(address, None)
        with contextlib.suppress(OSError):
            sock.close()


# --------------------------------------------------------------------------------------------- #
# Listener -- inbound only, held by Node                                                        #
# --------------------------------------------------------------------------------------------- #


@dataclass(slots=True)
class TCPListener(Listener):
    """TCP's receive side. Binds a listen socket at construction (which is why bind
    failures surface early -- the caller gets `OSError` from `__init__`, not a delayed
    thread crash).

    Two driver paths, one implementation:

      * PRODUCTION -- `start(inbox)` spawns a reader thread that runs a selector loop:
        accept new connections, read complete frames, push each into `inbox`. `stop()`
        signals the thread, closes the listener, joins with a bounded timeout.
      * TESTS -- `drain()` runs the same selector loop for one iteration (`select(0)`),
        then returns whatever complete frames buffered in this call. No thread involved.
        `start()` need not have been called.

    Same internal buffer / same frame-extraction code either way. `drain()` after
    `start()` returns whatever `_run` hasn't yet pushed to the inbox; well-defined but
    unusual (mixing driver paths is a caller error, not a shape we support)."""

    listen_host: str = "127.0.0.1"
    listen_port: int = 0
    _selector: selectors.BaseSelector = field(init=False)
    _listener: socket.socket = field(init=False)
    _bound_port: int = field(init=False, default=0)
    _read_buf: dict[socket.socket, bytearray] = field(init=False, default_factory=dict)
    _buffered: list[Frame] = field(init=False, default_factory=list)
    _inbox: queue.SimpleQueue[Frame] | None = field(init=False, default=None)
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
            # Bind (or any earlier syscall) failed -- close the socket we already
            # created so the OS reclaims the fd immediately. The exception propagates
            # to the caller, which is the fail-loud property `Node.start(*listeners)`
            # relies on for atomic-start rollback.
            with contextlib.suppress(OSError):
                self._listener.close()
            self._selector.close()
            raise
        self._bound_port = self._listener.getsockname()[1]
        self._selector.register(self._listener, selectors.EVENT_READ, data="listener")

    @property
    def bound_address(self) -> Address:
        """Where inbound peers dial us -- host:port as an `Address`. Valid after
        construction; use to advertise this node's endpoint to peers."""
        return Address(Scheme.TCP, f"{self.listen_host}:{self._bound_port}")

    # -- production path ------------------------------------------------------------------- #

    def start(self, inbox: queue.SimpleQueue[Frame]) -> None:
        """Spawn the reader thread. Every subsequent complete frame goes into `inbox`.
        Idempotent for the same inbox instance; a different one raises."""
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
        """Signal, close listener, join. Idempotent."""
        self._stopping.set()
        with contextlib.suppress(OSError):
            self._listener.shutdown(socket.SHUT_RDWR)
        thread = self._thread
        self._thread = None
        if thread is not None and thread.is_alive():
            thread.join(timeout=2.0)
        self._close_all()

    def _run(self) -> None:
        """Reader-thread body. Runs until `_stopping` is set. Each frame extracted from
        an accepted socket gets pushed into `_inbox`."""
        while not self._stopping.is_set():
            self._poll_once(timeout=_SELECT_TIMEOUT_SEC, forward_to_inbox=True)

    # -- test / driver path --------------------------------------------------------------- #

    def drain(self) -> tuple[Frame, ...]:
        """Non-blocking: poll the selector once, extract every complete frame that's
        ready, return them. Used by test pumps that drive tick/receive from one thread.

        Does not touch `_inbox` -- meant for callers that HAVEN'T called `start()`.
        Calling `drain()` after `start()` returns whatever the reader thread has
        already extracted but not yet forwarded; well-defined but unusual."""
        if self._stopping.is_set():
            return ()
        self._poll_once(timeout=0, forward_to_inbox=False)
        out = tuple(self._buffered)
        self._buffered.clear()
        return out

    # -- internals ------------------------------------------------------------------------ #

    def _poll_once(self, *, timeout: float, forward_to_inbox: bool) -> None:
        try:
            events = self._selector.select(timeout=timeout)
        except OSError:
            return  # selector closed under us during shutdown
        for key, _events in events:
            sock = key.fileobj
            assert isinstance(sock, socket.socket)  # noqa: S101 -- selector registers only sockets
            if key.data == "listener":
                self._accept()
            else:
                self._read_from(sock)
        if forward_to_inbox and self._buffered:
            inbox = self._inbox
            if inbox is not None:
                for frame in self._buffered:
                    inbox.put(frame)
                self._buffered.clear()

    def _accept(self) -> None:
        while True:
            try:
                conn, _addr = self._listener.accept()
            except (BlockingIOError, OSError):
                return
            conn.setblocking(False)
            self._read_buf[conn] = bytearray()
            self._selector.register(conn, selectors.EVENT_READ, data="incoming")

    def _read_from(self, sock: socket.socket) -> None:
        buf = self._read_buf.get(sock)
        if buf is None:
            self._closesock(sock)
            return
        try:
            chunk = sock.recv(65536)
        except BlockingIOError:
            return
        except OSError as e:
            if e.errno != errno.ECONNRESET:
                pass  # any other OS error -- same handling: close, move on
            self._closesock(sock)
            return
        if not chunk:  # clean EOF
            self._closesock(sock)
            return
        buf.extend(chunk)
        self._extract_frames(sock, buf)

    def _extract_frames(self, sock: socket.socket, buf: bytearray) -> None:
        while len(buf) >= _LEN.size:
            (length,) = _LEN.unpack_from(buf, 0)
            if length > MAX_FRAME_BYTES:
                self._closesock(sock)
                return
            if len(buf) < _LEN.size + length:
                return
            payload = bytes(buf[_LEN.size : _LEN.size + length])
            del buf[: _LEN.size + length]
            with contextlib.suppress(DudeError):
                self._buffered.append(Frame.decode(payload))

    def _closesock(self, sock: socket.socket) -> None:
        self._read_buf.pop(sock, None)
        with contextlib.suppress(KeyError, ValueError):
            self._selector.unregister(sock)
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
