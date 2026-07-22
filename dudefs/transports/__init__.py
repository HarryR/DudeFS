# dudefs/transports — the L_txport carriers (PROTOCOL §7) and the scheme registry
# that dispatches to them. A carrier is a dumb pipe (see base.py); one file per
# carrier (unix.py, http.py, …), plus memory.py (the SIM fault-carrier used by the
# quorum property tests — a different API, not part of this registry).
#
# Selecting a carrier is by SCHEME — the `transport` field of an ENDPOINT record — so
# a new carrier is one registry entry, not a rewrite of the callers.
from __future__ import annotations

from collections.abc import Callable
from urllib.parse import urlsplit, urlunsplit

from . import http as _http
from . import inproc
from . import unix as _unix
from .base import HTTP, INPROC, SEALED, UNIX, Endpoint, Handler, Server, parse_scheme

__all__ = [
    "HTTP",
    "INPROC",
    "UNIX",
    "Endpoint",
    "Handler",
    "Server",
    "dial",
    "inproc",
    "open_server",
    "parse_endpoint",
    "parse_scheme",
]


def parse_endpoint(spec: str) -> tuple[bytes, bytes, dict[bytes, bytes]]:
    """Decompose an operator-supplied endpoint into the STORED struct
    `(transport, uri, opts)` — ONCE, at the edge (the CLI). Internally we carry the
    struct and never re-parse the URL. Accepts a custom composite scheme so an operator
    types one URL instead of a pile of flags; a bare path defaults to a local unix
    socket. Examples:

        /run/n.sock              -> (b"unix", b"/run/n.sock", {})
        unix:/run/n.sock         -> (b"unix", b"/run/n.sock", {})
        http://host:8080/dude    -> (b"http", b"http://host:8080/dude", {})
        sealed+http://host/dude  -> (b"http", b"http://host/dude", {b"lmsg": b"sealed"})
    """
    parts = urlsplit(spec)
    if not parts.scheme:  # a bare path -> a local unix socket
        return UNIX, spec.encode(), {}
    mods, carrier = parse_scheme(parts.scheme.encode())
    opts: dict[bytes, bytes] = {b"lmsg": b"sealed"} if SEALED in mods else {}
    if carrier == UNIX:
        uri = parts.path.encode()  # the unix carrier connects to the raw path
    else:  # a networked carrier keeps its base URL (its dial urlsplits it)
        uri = urlunsplit(
            (carrier.decode(), parts.netloc, parts.path, parts.query, parts.fragment)
        ).encode()
    return carrier, uri, opts


_DIALERS: dict[bytes, Callable[..., bytes]] = {
    UNIX: _unix.dial,
    HTTP: _http.dial,
    INPROC: inproc.dial,
}
_SERVERS: dict[bytes, Callable[[], Server]] = {
    UNIX: _unix.UnixServer,
    HTTP: _http.HttpServer,
    INPROC: inproc.InprocServer,
}


def dial(scheme: bytes, uri: str, payload: bytes, *, timeout: float = 5.0) -> bytes:
    """Send `payload` to `uri` over the carrier named by `scheme`; return the reply
    payload (b"" = no reply). Raises KeyError for an unknown scheme — a real
    configuration error, not a silent no-op."""
    return _DIALERS[scheme](uri, payload, timeout=timeout)


def open_server(scheme: bytes) -> Server:
    """A fresh listening carrier for `scheme` (the daemon owns it and calls close)."""
    return _SERVERS[scheme]()
