from __future__ import annotations

import os
import socket
import threading

from ..core import codec, crypto
from ..core.errors import DudeError
from ..session import Dropped, Substrate, SubmitHandle
from ..store import ops
from .socket_framing import QUERY_PENDING, Request, Response, read_request, send_response


class SocketServer:

    def __init__(self, path: str, substrate: Substrate) -> None:
        self._path = path
        self._sub = substrate
        self._sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        if os.path.exists(path):
            os.unlink(path)
        self._sock.bind(path)
        os.chmod(path, 0o600)
        self._sock.listen(16)
        self._stopping = threading.Event()
        self._clients: list[_ClientHandler] = []
        self._accept_thread: threading.Thread | None = None
        self._notify_thread: threading.Thread | None = None

    def start(self) -> None:
        self._accept_thread = threading.Thread(target=self._accept_loop, daemon=True)
        self._accept_thread.start()
        self._notify_thread = threading.Thread(target=self._commit_notify_loop, daemon=True)
        self._notify_thread.start()

    def stop(self) -> None:
        self._stopping.set()
        try:
            self._sock.shutdown(socket.SHUT_RDWR)
        except OSError:
            pass
        self._sock.close()
        for c in list(self._clients):
            c.stop()
        if self._accept_thread is not None:
            self._accept_thread.join()
        if self._notify_thread is not None:
            self._notify_thread.join()
        if os.path.exists(self._path):
            os.unlink(self._path)

    def _accept_loop(self) -> None:
        self._sock.settimeout(1.0)
        while not self._stopping.is_set():
            try:
                conn, _ = self._sock.accept()
            except (OSError, socket.timeout):
                continue
            handler = _ClientHandler(conn, self._sub, self._clients)
            self._clients.append(handler)
            handler.start()

    def _commit_notify_loop(self) -> None:
        cond = self._sub.commit_cond
        last = self._sub.commit_generation()
        while not self._stopping.is_set():
            with cond:
                cond.wait(timeout=1.0)
            cur = self._sub.commit_generation()
            if cur > last:
                last = cur
                h = self._sub.head()
                payload = h.encode() if h is not None else b""
                for c in list(self._clients):
                    if c.alive:
                        c.push_commit_wake(payload)


class _ClientHandler:

    def __init__(self, conn: socket.socket, substrate: Substrate, siblings: list[_ClientHandler]) -> None:
        self._conn = conn
        self._sub = substrate
        self._siblings = siblings
        self._send_lock = threading.Lock()
        self._stopped = False
        self._inflight: dict[crypto.Digest, SubmitHandle] = {}
        self._reader_thread: threading.Thread | None = None
        self.alive = True

    def start(self) -> None:
        self._reader_thread = threading.Thread(target=self._read_loop, daemon=True)
        self._reader_thread.start()

    def stop(self) -> None:
        self._stopped = True
        try:
            self._conn.shutdown(socket.SHUT_RDWR)
        except OSError:
            pass
        if self._reader_thread is not None:
            self._reader_thread.join()

    def push_commit_wake(self, payload: bytes) -> None:
        try:
            self._respond(Response.COMMIT, b"", payload)
        except OSError:
            pass

    def _respond(self, tag: Response, corr_id: bytes, payload: bytes) -> None:
        with self._send_lock:
            send_response(self._conn, tag, corr_id, payload)

    def _read_loop(self) -> None:
        try:
            while not self._stopped:
                frame = read_request(self._conn)
                if frame is None:
                    break
                tag, corr_id, payload = frame
                try:
                    self._dispatch(tag, corr_id, payload)
                except DudeError:
                    break
                except OSError:
                    break
        finally:
            self.alive = False
            self._stopped = True
            try:
                self._siblings.remove(self)
            except ValueError:
                pass
            try:
                self._conn.close()
            except OSError:
                pass

    def _dispatch(self, tag: Request, corr_id: bytes, payload: bytes) -> None:
        match tag:
            case Request.GET:
                parts = codec.as_seq(codec.decode(payload), 2)
                store = codec.as_int(parts[0])
                name = codec.as_bytes(parts[1])
                held = self._sub.get(store, name)
                if held is None:
                    self._respond(Response.GET, corr_id, b"")
                else:
                    self._respond(Response.GET, corr_id, held.encode())
            case Request.ANCHOR:
                self._respond(Response.ANCHOR, corr_id, bytes(self._sub.anchor()))
            case Request.EVICT:
                ms = int(self._sub.evict_after_sec() * 1000)
                self._respond(Response.EVICT, corr_id, codec.encode(ms))
            case Request.TOKEN:
                parts = codec.as_seq(codec.decode(payload), 2)
                store_id = codec.as_int(parts[0])
                name = codec.as_bytes(parts[1]).decode()
                self._respond(Response.TOKEN, corr_id, self._sub.token(store_id, name))
            case Request.SEAL:
                parts = codec.as_seq(codec.decode(payload), 3)
                store_id = codec.as_int(parts[0])
                name = codec.as_bytes(parts[1]).decode()
                value = codec.as_bytes(parts[2])
                token, sealed, epoch = self._sub.seal(store_id, name, value)
                self._respond(Response.SEAL, corr_id, codec.encode([token, sealed, epoch]))
            case Request.DECRYPT:
                parts = codec.as_seq(codec.decode(payload), 4)
                store_id = codec.as_int(parts[0])
                name = codec.as_bytes(parts[1]).decode()
                ct = codec.as_bytes(parts[2])
                epoch = codec.as_int(parts[3])
                plaintext = self._sub.decrypt(store_id, name, ct, epoch)
                self._respond(Response.DECRYPT, corr_id, plaintext)
            case Request.SUBMIT:
                tx = ops.Transaction.decode(payload)
                handle = self._sub.submit(tx)
                self._inflight[handle.op_hash] = handle
                self._respond(Response.SUBMIT_ACK, corr_id, handle.op_hash)
            case Request.QUERY:
                op_hash = crypto.Digest(payload)
                handle = self._inflight.get(op_hash)
                if handle is None:
                    self._respond(Response.QUERY, corr_id, Dropped().encode())
                    return
                result = handle.poll()
                if result is not None:
                    self._inflight.pop(op_hash, None)
                    self._respond(Response.QUERY, corr_id, result.encode())
                else:
                    self._respond(Response.QUERY, corr_id, QUERY_PENDING)
