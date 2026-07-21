# dudefs/transport.py — the L_txport seam (PROTOCOL §7). A carrier is a dumb pipe:
# "push a message, get a reply — maybe". It owns ALL the I/O (sockets, timeouts,
# accept loops) AND the wire framing, so the layers above hand it PAYLOADS (L_msg
# envelope bytes) and a pure handler, never a socket. Selecting a carrier is by
# SCHEME — the `transport` field of an ENDPOINT record (transport, uri, opts) — so a
# new carrier (HTTP, XMPP) is one registry entry, not a rewrite of the callers.
#
# Two directions: `dial` (send one payload, get the reply payload back — b"" means no
# reply came, however the carrier spells "nothing") and a `Server` (listen, hand each
# inbound payload to the handler, send its reply — or render carrier-native silence
# when the handler returns None). The encoding layer stays sans-io; this is the edge.
from __future__ import annotations

import socket
import threading
from collections.abc import Callable
from typing import Protocol

from . import wire

# A request handler: an inbound payload -> the reply payload, or None for "no reply"
# (the transport renders that as its carrier's silence — a closed frame / no stanza /
# a 404). Pure w.r.t. I/O; the daemon's `serve` is the one wired in.
type Handler = Callable[[bytes], bytes | None]

UNIX = b"unix"  # the scheme for a local unix-domain-socket endpoint


class Server(Protocol):
    """A listening carrier. `serve` blocks until `close` (from another thread) tears
    down the listen socket."""

    def serve(self, uri: str, handler: Handler, ready: threading.Event | None = None) -> None: ...
    def close(self) -> None: ...


# --------------------------------------------------------------------------- #
# unix domain sockets — the local POC carrier (4-byte length-prefix framing)      #
# --------------------------------------------------------------------------- #


def _unix_dial(uri: str, payload: bytes, *, timeout: float) -> bytes:
    """One request/reply over a fresh unix socket. Unreachable / dropped -> b"" (the
    caller reads that as 'no reply came back', never a crash)."""
    try:
        with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as s:
            s.settimeout(timeout)
            s.connect(uri)
            s.sendall(wire.frame(payload))
            return wire.read_frame(s.recv) or b""
    except OSError:
        return b""


class UnixServer:
    """A unix-socket accept loop. Each connection is a thread running a thin frame
    loop; the handler's None reply is rendered as closing the connection (this
    carrier's 'nothing'). Catches only its own I/O errors — the handler owns any
    store/logic error (it returns None on a vanished store)."""

    def __init__(self) -> None:
        self._srv: socket.socket | None = None

    def serve(self, uri: str, handler: Handler, ready: threading.Event | None = None) -> None:
        srv = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        srv.bind(uri)
        srv.listen(16)
        self._srv = srv
        if ready is not None:
            ready.set()
        while True:
            try:
                conn, _ = srv.accept()
            except OSError:
                return  # listen socket closed -> shutdown
            threading.Thread(target=self._handle, args=(conn, handler), daemon=True).start()

    def _handle(self, conn: socket.socket, handler: Handler) -> None:
        with conn:
            while True:
                try:
                    payload = wire.read_frame(conn.recv)
                    if payload is None:
                        return  # clean EOF
                    reply = handler(payload)
                    if reply is None:
                        return  # handler chose silence -> close the conn (carrier 'nothing')
                    conn.sendall(wire.frame(reply))
                except OSError:
                    return  # peer vanished

    def close(self) -> None:
        if self._srv is not None:
            self._srv.close()


# --------------------------------------------------------------------------- #
# The carrier registry — a scheme -> (dialer, server) map. One entry per carrier. #
# --------------------------------------------------------------------------- #

_DIALERS: dict[bytes, Callable[..., bytes]] = {UNIX: _unix_dial}
_SERVERS: dict[bytes, Callable[[], Server]] = {UNIX: UnixServer}


def dial(scheme: bytes, uri: str, payload: bytes, *, timeout: float = 5.0) -> bytes:
    """Send `payload` to `uri` over the carrier named by `scheme`; return the reply
    payload (b"" = no reply). Raises KeyError for an unknown scheme — a real
    configuration error, not a silent no-op."""
    return _DIALERS[scheme](uri, payload, timeout=timeout)


def open_server(scheme: bytes) -> Server:
    """A fresh listening carrier for `scheme` (the daemon owns it and calls close)."""
    return _SERVERS[scheme]()
