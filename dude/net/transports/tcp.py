# dude.net.transports.tcp -- real sockets, same shape as InProc.
#
# One `TCP` per identity: owns a listener + a per-target outbound socket cache + a
# per-inbound-connection read buffer. Everything is non-blocking; `receive()` polls a
# selector once (no-timeout `select(0)`), processes any ready sockets, and returns
# whatever complete frames arrived. That keeps the tick model intact -- no background
# threads, no `asyncio`, one syscall per drain.
#
# FRAMING is a 4-byte big-endian length prefix followed by exactly that many bytes of
# `Frame.raw`. TCP is a stream, not a message carrier; without a length prefix a partial
# read is indistinguishable from a short message.
#
# CONNECTION MODEL: two independent connections per peer-pair. A's outbound to B is
# distinct from B's outbound to A. The alternative (reuse the accepted socket for the
# reverse direction) would need transport-level identification of who accepted us, which
# breaks the layering -- transports know addresses, not identities. Envelopes carry
# `frm`, transports carry bytes; the two must not merge.
#
# ERRORS: any OS failure (ECONNREFUSED, EPIPE, ECONNRESET, ...) collapses to `LinkError`.
# The link/breaker layer above turns that into `Refused.TRANSPORT` and retry policy.

from __future__ import annotations

import contextlib
import errno
import selectors
import socket
import struct
from dataclasses import dataclass, field

from ...core.errors import DudeError
from ..address import Address, Scheme
from ..envelope import Frame
from ..link import LinkError, Transport

_LEN = struct.Struct(">I")
"""4-byte big-endian frame length prefix. Max frame ~4 GiB, capped in practice at
`_MAX_FRAME` -- any advertised size beyond that is treated as a malformed sender and the
connection is dropped."""

_MAX_FRAME = 1 << 24  # 16 MiB -- generous ceiling; a well-formed envelope is much smaller.
"""Cap on advertised frame length. A stream that says "the next frame is 4 GiB" is either
malformed or hostile; either way, cheaper to drop the connection than to allocate."""


@dataclass(slots=True)
class TCP(Transport):
    """One identity's TCP presence: a listener plus per-connection I/O state.

    Same interface as `InProc`:
      * `send(address, frame)` -- bytes to an outbound socket keyed by target address;
        opens the socket lazily, reuses across sends. Raises `LinkError` on OS failure.
      * `receive() -> tuple[Frame, ...]` -- non-blocking selector drain: accept any
        pending inbound connections, read any waiting bytes, extract any complete frames
        buffered per connection. Called externally (Postman / test pump) every tick.

    `listen_address` is what other peers dial to reach us. When bound to port 0 the OS
    picks; read the actual endpoint back via `bound_address` before advertising it.

    `close()` shuts everything down. Idempotent."""

    listen_host: str = "127.0.0.1"
    listen_port: int = 0
    _selector: selectors.BaseSelector = field(init=False)
    _listener: socket.socket = field(init=False)
    _bound_port: int = field(init=False, default=0)
    _outbound: dict[Address, socket.socket] = field(init=False, default_factory=dict)
    _read_buf: dict[socket.socket, bytearray] = field(init=False, default_factory=dict)
    _inbox: list[Frame] = field(init=False, default_factory=list)

    def __post_init__(self) -> None:
        self._selector = selectors.DefaultSelector()
        self._listener = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self._listener.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self._listener.bind((self.listen_host, self.listen_port))
        self._listener.setblocking(False)
        self._listener.listen(128)
        self._bound_port = self._listener.getsockname()[1]
        self._selector.register(self._listener, selectors.EVENT_READ, data="listener")

    @property
    def bound_address(self) -> Address:
        """Where inbound peers dial us -- host:port as an `Address`. Only valid after
        construction. Use this to build the `Endpoint` other peers store for us."""
        return Address(Scheme.TCP, f"{self.listen_host}:{self._bound_port}")

    def close(self) -> None:
        """Shut every socket, clear the selector. Idempotent."""
        for sock in list(self._outbound.values()):
            self._closesock(sock, out=True)
        for sock in list(self._read_buf):
            self._closesock(sock, out=False)
        if self._listener.fileno() != -1:
            with contextlib.suppress(KeyError, ValueError):
                self._selector.unregister(self._listener)
            self._listener.close()
        self._selector.close()

    def send(self, address: Address, frame: Frame) -> None:
        """Write `frame` to a socket connected to `address`. Opens it lazily; caches it
        so subsequent sends reuse. Any OS-level failure closes the socket, drops it
        from the cache, and raises `LinkError` -- the caller's retry policy decides
        what happens next."""
        if address.scheme is not Scheme.TCP:
            raise LinkError(f"tcp cannot dial {address.scheme.value.decode()}")
        payload = frame.raw
        if len(payload) > _MAX_FRAME:
            raise LinkError(f"frame too large: {len(payload)} > {_MAX_FRAME}")
        blob = _LEN.pack(len(payload)) + payload
        sock = self._outbound.get(address)
        if sock is None:
            sock = self._connect(address)
            self._outbound[address] = sock
        try:
            # sendall on a blocking socket. TCP transports treat send as blocking for
            # simplicity; write-side backpressure would need a per-conn outbound queue,
            # which is worth the code only when we have a workload that hits it.
            sock.sendall(blob)
        except OSError as e:
            self._closesock(sock, out=True)
            self._outbound.pop(address, None)
            raise LinkError(f"tcp send to {address.value} failed: {e}") from e

    def receive(self) -> tuple[Frame, ...]:
        """Non-blocking drain. Runs the selector once (`select(0)`), handles every
        ready socket, and returns whatever complete frames arrived since the last call.

        Idempotent when there's nothing pending: returns `()` and does no I/O."""
        for key, _events in self._selector.select(timeout=0):
            sock = key.fileobj
            assert isinstance(sock, socket.socket)  # noqa: S101 -- selector registers only sockets
            if key.data == "listener":
                self._accept()
            else:
                self._read_from(sock)
        out = tuple(self._inbox)
        self._inbox.clear()
        return out

    # -- internals -------------------------------------------------------------------- #

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
        # Outbound sockets stay blocking -- send is a blocking sendall (see `send()`).
        # They aren't in the selector: we never READ from them.
        return sock

    def _accept(self) -> None:
        """Drain everything the listener will hand us this poll -- multiple pending
        connects are common under load."""
        while True:
            try:
                conn, _addr = self._listener.accept()
            except BlockingIOError:
                return
            except OSError:
                return  # listener died; caller will notice on next send / next receive
            conn.setblocking(False)
            self._read_buf[conn] = bytearray()
            self._selector.register(conn, selectors.EVENT_READ, data="incoming")

    def _read_from(self, sock: socket.socket) -> None:
        """Read whatever's waiting, append to the connection's read buffer, and extract
        every complete frame the buffer now holds. On EOF (peer closed) or error, close
        the connection and drop its buffer."""
        buf = self._read_buf.get(sock)
        if buf is None:
            self._closesock(sock, out=False)
            return
        try:
            chunk = sock.recv(65536)
        except BlockingIOError:
            return
        except OSError as e:
            if e.errno != errno.ECONNRESET:
                pass  # any other OS error -- same handling: close, move on
            self._closesock(sock, out=False)
            return
        if not chunk:  # clean EOF
            self._closesock(sock, out=False)
            return
        buf.extend(chunk)
        self._extract_frames(sock, buf)

    def _extract_frames(self, sock: socket.socket, buf: bytearray) -> None:
        """Pull every complete frame out of `buf`, appending to `_inbox`. Malformed
        frames drop silently; a length-prefix past the cap closes the connection.

        Split from `_read_from` so each function has one job: recv + framing state, vs.
        pure buffer parsing."""
        while len(buf) >= _LEN.size:
            (length,) = _LEN.unpack_from(buf, 0)
            if length > _MAX_FRAME:
                self._closesock(sock, out=False)
                return
            if len(buf) < _LEN.size + length:
                return
            payload = bytes(buf[_LEN.size : _LEN.size + length])
            del buf[: _LEN.size + length]
            with contextlib.suppress(DudeError):
                self._inbox.append(Frame.decode(payload))

    def _closesock(self, sock: socket.socket, *, out: bool) -> None:
        """Close `sock`, remove it from every internal map. `out=True` means it's an
        outbound socket (never in the selector or read-buffer maps); `out=False` means
        it's an accepted inbound connection (registered with the selector, has a read
        buffer). Idempotent."""
        if not out:
            self._read_buf.pop(sock, None)
            with contextlib.suppress(KeyError, ValueError):
                self._selector.unregister(sock)
        with contextlib.suppress(OSError):
            sock.close()


def endpoint_of(host: str, port: int) -> Address:
    """Build a `tcp:host:port` `Address`. Convenience for tests and CLI wiring; the
    management store stores endpoints as bytes and parses via `Address.parse`."""
    return Address(Scheme.TCP, f"{host}:{port}")


def dial(_endpoint, _me) -> TCP:
    """Postman-shaped dialler for `Scheme.TCP`. NOTE the API surprise this shape
    surfaces: `dial(endpoint, me)` is called once per Postman per scheme, cached in
    `_transports_by_scheme`. That means a single TCP transport per Postman serves EVERY
    peer -- outbound is per-target-address, inbound is one listener. Constructing one
    listener per peer would be wrong.

    But the CURRENT contract calls `dial(endpoint, ...)` with the FIRST peer's endpoint,
    which for TCP tells us NOTHING about where WE listen. So this dialler ignores
    `_endpoint` and binds to `127.0.0.1:0` (OS-picked port). Production callers that need
    a specific listen address must construct `TCP(listen_host=..., listen_port=...)`
    directly and register it via `register_dialler(Scheme.TCP, lambda e, m: transport)`.

    This is API weirdness worth naming: the dialler-per-scheme model assumes the
    endpoint tells the transport how to construct itself, which is TRUE for InProc
    (identity-bound) and FALSE for TCP (identity is not a listen address)."""
    return TCP()
