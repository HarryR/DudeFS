# dudefs/transports/http.py — a plain-HTTP carrier (§0). One POST per request; HTTP's
# Content-Length IS the framing (no 4-byte prefix), so the payload is the raw body. A
# non-200 (our 404) is the carrier's 'nothing' -> b"". Plain HTTP here (LAN / a trusted
# terminator / Tor); a sealed L_msg profile is what protects an untrusted CDN, and that
# rides the SAME payload — the carrier neither knows nor cares.
#
# (`import http.client` below is the STDLIB http — absolute imports, so this module
# named `http` never shadows it.)
from __future__ import annotations

import http.client
import http.server
import threading
from urllib.parse import urlsplit

from .base import Handler


def dial(uri: str, payload: bytes, *, timeout: float) -> bytes:
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
