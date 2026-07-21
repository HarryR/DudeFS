# dudefs/transports/base.py — the L_txport contracts (PROTOCOL §7). A carrier is a
# dumb pipe: "push a message, get a reply — maybe". It owns ALL the I/O (sockets,
# timeouts, accept loops) AND the wire framing, so the layers above hand it PAYLOADS
# (L_msg envelope bytes) and a pure handler, never a socket. One file per carrier
# (unix.py, http.py, …); __init__.py is the scheme registry that dispatches to them.
from __future__ import annotations

import threading
from collections.abc import Callable
from typing import Protocol

# A request handler: an inbound payload -> the reply payload, or None for "no reply"
# (the carrier renders that as its native silence — a closed frame / no stanza / a
# 404). Pure w.r.t. I/O; the daemon's `serve` is the one wired in.
type Handler = Callable[[bytes], bytes | None]

# Carrier schemes — the `transport` field of an ENDPOINT record (transport, uri, opts).
UNIX = b"unix"  # a local unix-domain socket
HTTP = b"http"  # a plain-HTTP endpoint (LAN / behind a trusted terminator or Tor)


class Server(Protocol):
    """A listening carrier. `serve` blocks until `close` (from another thread) tears
    down the listen socket."""

    def serve(self, uri: str, handler: Handler, ready: threading.Event | None = None) -> None: ...
    def close(self) -> None: ...
