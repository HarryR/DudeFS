# dudefs/transports/inproc.py — the in-process carrier (PROTOCOL §7). `dial()` delivers
# the payload to the target's Handler DIRECTLY and returns its reply — no sockets, no
# threads, fully synchronous. Its purpose (WP-I) is to drive the REAL serve/gossip/adopt
# production path of several NodeDaemons wired together in ONE thread, deterministically,
# so lifecycle tests validate production code instead of the sim's out-of-band helpers.
#
# It is a first-class registry carrier (scheme INPROC) like unix/http, so nothing in
# Link / daemon / gossip changes: a peer's Endpoint just names `inproc` + an id. The
# module-level `register`/`unregister` are the direct seam a test uses; `InprocServer`
# is the Server-protocol face so `serve_forever(scheme=INPROC)` composes too.
from __future__ import annotations

import threading

from .base import Handler

# id (Endpoint.uri) -> the serving Handler. Process-global (the carrier is a shared
# medium, like the OS socket namespace); tests register distinct ids and clean up.
_HANDLERS: dict[str, Handler] = {}
_lock = threading.Lock()


def register(uri: str, handler: Handler) -> None:
    """Publish `handler` at `uri` so `dial(uri, ...)` reaches it. Idempotent-overwrite."""
    with _lock:
        _HANDLERS[uri] = handler


def unregister(uri: str) -> None:
    with _lock:
        _HANDLERS.pop(uri, None)


def dial(uri: str, payload: bytes, *, timeout: float = 5.0) -> bytes:
    """Deliver `payload` to the handler at `uri` and return its reply (b"" = the
    carrier's native silence). An unregistered id is a down peer — b"", a missed round,
    exactly as a refused socket connection would be. Synchronous: the reply IS the
    handler's return, so a driving test needs no scheduler."""
    with _lock:
        handler = _HANDLERS.get(uri)
    if handler is None:
        return b""
    reply = handler(payload)
    return reply if reply is not None else b""


class InprocServer:
    """The Server-protocol face (via `open_server(INPROC)`), so a daemon's
    `serve_forever(uri, scheme=INPROC)` registers here and blocks until `close` — the
    same shape as the unix/http accept loops. Deterministic tests skip this and call
    `register` directly; this exists for symmetry with the socket carriers."""

    def __init__(self) -> None:
        self._uri: str | None = None
        self._stop = threading.Event()

    def serve(self, uri: str, handler: Handler, ready: threading.Event | None = None) -> None:
        register(uri, handler)
        self._uri = uri
        if ready is not None:
            ready.set()
        self._stop.wait()  # mirror the socket carriers: block until close()

    def close(self) -> None:
        if self._uri is not None:
            unregister(self._uri)
        self._stop.set()
