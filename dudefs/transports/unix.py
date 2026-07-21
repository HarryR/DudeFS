# dudefs/transports/unix.py — the local unix-domain-socket carrier (4-byte
# length-prefix framing). The POC carrier; also the fast path for co-located nodes.
from __future__ import annotations

import socket
import threading

from .. import wire
from .base import Handler


def dial(uri: str, payload: bytes, *, timeout: float) -> bytes:
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
