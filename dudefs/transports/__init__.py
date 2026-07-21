# dudefs/transports — the L_txport carriers (PROTOCOL §7) and the scheme registry
# that dispatches to them. A carrier is a dumb pipe (see base.py); one file per
# carrier (unix.py, http.py, …), plus memory.py (the SIM fault-carrier used by the
# quorum property tests — a different API, not part of this registry).
#
# Selecting a carrier is by SCHEME — the `transport` field of an ENDPOINT record — so
# a new carrier is one registry entry, not a rewrite of the callers.
from __future__ import annotations

from collections.abc import Callable

from . import http as _http
from . import unix as _unix
from .base import HTTP, UNIX, Handler, Server

__all__ = ["HTTP", "UNIX", "Handler", "Server", "dial", "open_server"]

_DIALERS: dict[bytes, Callable[..., bytes]] = {UNIX: _unix.dial, HTTP: _http.dial}
_SERVERS: dict[bytes, Callable[[], Server]] = {UNIX: _unix.UnixServer, HTTP: _http.HttpServer}


def dial(scheme: bytes, uri: str, payload: bytes, *, timeout: float = 5.0) -> bytes:
    """Send `payload` to `uri` over the carrier named by `scheme`; return the reply
    payload (b"" = no reply). Raises KeyError for an unknown scheme — a real
    configuration error, not a silent no-op."""
    return _DIALERS[scheme](uri, payload, timeout=timeout)


def open_server(scheme: bytes) -> Server:
    """A fresh listening carrier for `scheme` (the daemon owns it and calls close)."""
    return _SERVERS[scheme]()
