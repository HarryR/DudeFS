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

import http.client
import http.server
import socket
import threading
from collections.abc import Callable
from typing import Protocol
from urllib.parse import urlsplit

from . import wire

# A request handler: an inbound payload -> the reply payload, or None for "no reply"
# (the transport renders that as its carrier's silence — a closed frame / no stanza /
# a 404). Pure w.r.t. I/O; the daemon's `serve` is the one wired in.
type Handler = Callable[[bytes], bytes | None]

UNIX = b"unix"  # the scheme for a local unix-domain-socket endpoint
HTTP = b"http"  # a plain-HTTP endpoint (LAN / behind a trusted terminator or Tor)


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
# HTTP — an intermediated carrier (§0). One POST per request; HTTP's Content-      #
# Length IS the framing (no 4-byte prefix), so the payload is the raw body. A      #
# non-200 (our 404) is the carrier's 'nothing' -> b"". Plain HTTP here (LAN / a     #
# trusted terminator / Tor); a sealed L_msg profile is what protects an untrusted   #
# CDN, and that rides the SAME payload — the carrier neither knows nor cares.       #
# --------------------------------------------------------------------------- #


def _http_dial(uri: str, payload: bytes, *, timeout: float) -> bytes:
    parts = urlsplit(uri)
    try:
        conn = http.client.HTTPConnection(parts.hostname or "", parts.port or 80, timeout=timeout)
        try:
            conn.request(
                "POST",
                parts.path or "/",
                body=payload,
                headers={"Content-Type": "application/octet-stream"},
            )
            resp = conn.getresponse()
            body = resp.read()
            return body if resp.status == 200 else b""  # 404 = carrier silence
        finally:
            conn.close()
    except OSError:
        return b""


def _request_handler_class(handler: Handler) -> type[http.server.BaseHTTPRequestHandler]:
    """A BaseHTTPRequestHandler subclass that closes over `handler` — cleaner than
    hanging a dynamic attribute off the server (and it type-checks)."""

    class _H(http.server.BaseHTTPRequestHandler):
        def do_POST(self) -> None:  # noqa: N802 (the base's fixed verb-method name)
            length = int(self.headers.get("Content-Length", 0))
            reply = handler(self.rfile.read(length))
            if reply is None:
                self.send_response(404)  # the carrier's 'nothing' (silence)
                self.end_headers()
                return
            self.send_response(200)
            self.send_header("Content-Type", "application/octet-stream")
            self.send_header("Content-Length", str(len(reply)))
            self.end_headers()
            self.wfile.write(reply)

        def log_message(self, format: str, *args: object) -> None:  # keep the carrier quiet
            pass

    return _H


class HttpServer:
    """A threaded HTTP server; each POST body is a request payload handed to the pure
    handler. `close` (from another thread) stops `serve_forever` and frees the port."""

    def __init__(self) -> None:
        self._httpd: http.server.ThreadingHTTPServer | None = None

    def serve(self, uri: str, handler: Handler, ready: threading.Event | None = None) -> None:
        parts = urlsplit(uri)
        httpd = http.server.ThreadingHTTPServer(
            (parts.hostname or "127.0.0.1", parts.port or 0), _request_handler_class(handler)
        )
        self._httpd = httpd
        if ready is not None:
            ready.set()
        httpd.serve_forever()

    def close(self) -> None:
        if self._httpd is not None:
            self._httpd.shutdown()
            self._httpd.server_close()


# --------------------------------------------------------------------------- #
# The carrier registry — a scheme -> (dialer, server) map. One entry per carrier. #
# --------------------------------------------------------------------------- #

_DIALERS: dict[bytes, Callable[..., bytes]] = {UNIX: _unix_dial, HTTP: _http_dial}
_SERVERS: dict[bytes, Callable[[], Server]] = {UNIX: UnixServer, HTTP: HttpServer}


def dial(scheme: bytes, uri: str, payload: bytes, *, timeout: float = 5.0) -> bytes:
    """Send `payload` to `uri` over the carrier named by `scheme`; return the reply
    payload (b"" = no reply). Raises KeyError for an unknown scheme — a real
    configuration error, not a silent no-op."""
    return _DIALERS[scheme](uri, payload, timeout=timeout)


def open_server(scheme: bytes) -> Server:
    """A fresh listening carrier for `scheme` (the daemon owns it and calls close)."""
    return _SERVERS[scheme]()
