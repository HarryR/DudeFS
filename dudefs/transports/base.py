# dudefs/transports/base.py — the L_txport contracts (PROTOCOL §7). A carrier is a
# dumb pipe: "push a message, get a reply — maybe". It owns ALL the I/O (sockets,
# timeouts, accept loops) AND the wire framing, so the layers above hand it PAYLOADS
# (L_msg envelope bytes) and a pure handler, never a socket. One file per carrier
# (unix.py, http.py, …); __init__.py is the scheme registry that dispatches to them.
from __future__ import annotations

import threading
from collections.abc import Callable
from dataclasses import dataclass
from typing import Protocol

from ..artifacts import AddrRecord

# A request handler: an inbound payload -> the reply payload, or None for "no reply"
# (the carrier renders that as its native silence — a closed frame / no stanza / a
# 404). Pure w.r.t. I/O; the daemon's `serve` is the one wired in.
type Handler = Callable[[bytes], bytes | None]

# Carrier schemes — the `transport` field of an ENDPOINT record (transport, uri, opts).
UNIX = b"unix"  # a local unix-domain socket
HTTP = b"http"  # a plain-HTTP endpoint (LAN / behind a trusted terminator or Tor)
INPROC = b"inproc"  # an in-process carrier: dial() calls the target's Handler directly
# (no sockets) — drives the REAL serve/gossip path in one thread for deterministic tests

SEALED = b"sealed"  # the L_msg profile modifier (seal the envelope before dialing)


def parse_scheme(scheme: bytes) -> tuple[frozenset[bytes], bytes]:
    """A composite carrier scheme `modifier+…+carrier` -> (modifiers, carrier). The
    TRAILING token is the carrier (the pipe); the leading `+`-joined tokens are L_msg
    profile modifiers (e.g. `sealed`), applied to the PAYLOAD and orthogonal to the
    carrier. `http` -> (∅, `http`); `sealed+http` -> ({`sealed`}, `http`)."""
    *mods, carrier = scheme.split(b"+")
    return frozenset(mods), carrier


@dataclass(frozen=True)
class Endpoint:
    """A dial address, decomposed once (transports.parse_endpoint / from_record) and
    carried as a struct — no code re-parses a composite scheme string. `transport` is
    the carrier scheme, `uri` its carrier-specific address (a path for unix, a URL for
    http), `sealed` the stored L_msg profile flag (consumed once sealed-mode is wired
    into serve; the carrier itself never cares)."""

    transport: bytes
    uri: str
    sealed: bool = False

    @staticmethod
    def from_record(rec: AddrRecord) -> Endpoint:
        """Build the dial struct from a stored ENDPOINT `AddrRecord` — the record IS the
        decomposition, so this is a view, not a re-parse."""
        return Endpoint(rec.transport, rec.uri.decode(), rec.opts.get(b"lmsg") == b"sealed")

    def to_record(self) -> AddrRecord:
        """The inverse of `from_record`: the addr as an ENDPOINT `AddrRecord` stores it.
        Faithful because `opts` carries only the L_msg profile today, so a read-modify-write of
        a node's address list (endpoint add/remove) round-trips."""
        opts = {b"lmsg": b"sealed"} if self.sealed else {}
        return AddrRecord(self.transport, self.uri.encode(), opts)


class Server(Protocol):
    """A listening carrier. `serve` blocks until `close` (from another thread) tears
    down the listen socket."""

    def serve(self, uri: str, handler: Handler, ready: threading.Event | None = None) -> None: ...
    def close(self) -> None: ...
