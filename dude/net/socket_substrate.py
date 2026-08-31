from __future__ import annotations

import contextlib
import os
import socket
import threading

from ..core import codec, crypto
from ..core.errors import DudeError
from ..core.units import Millis
from ..net.envelope import MessageId
from ..session import SubmitHandle, SubmitResult, Substrate
from ..store import ops
from ..store.layer import BlockHead, Held
from ..tunables import Tunables
from .socket_framing import (
    QUERY_PENDING,
    QUERY_UNKNOWN,
    Request,
    Response,
    read_response,
    send_request,
)


class SocketSubstrateError(DudeError): ...


class RequestTimedOutError(SocketSubstrateError): ...


class ConnectionLostError(SocketSubstrateError): ...


class _ReplySlot:
    __slots__ = ("_error", "_event", "_value")

    def __init__(self) -> None:
        self._event = threading.Event()
        self._value: bytes | None = None
        self._error: bool = False

    def set(self, value: bytes) -> None:
        self._value = value
        self._event.set()

    def abort(self) -> None:
        self._error = True
        self._event.set()

    def wait(self, timeout: float) -> bytes:
        if not self._event.wait(timeout):
            raise RequestTimedOutError
        if self._error:
            raise ConnectionLostError
        if self._value is None:
            raise SocketSubstrateError("slot signalled without a value")
        return self._value


class SocketSubstrate(Substrate):
    def __init__(self, path: str, tunables: Tunables) -> None:
        self._sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        self._sock.connect(path)
        self._request_timeout = tunables.ttl_exchange.as_seconds
        self._send_lock = threading.Lock()
        self._cond = threading.Condition()
        self._commit_seq = 0
        self._pending: dict[bytes, _ReplySlot] = {}
        self._head: BlockHead | None = None
        self._anchor_cache: crypto.PublicKey | None = None
        self._evict_cache: float | None = None
        self._closed = False
        self._reader_thread = threading.Thread(target=self._read_loop, daemon=True)
        self._reader_thread.start()

    def anchor(self) -> crypto.PublicKey:
        if self._anchor_cache is None:
            self._anchor_cache = crypto.PublicKey(self._request(Request.ANCHOR, b""))
        return self._anchor_cache

    def get(self, store: int, name: bytes) -> Held | None:
        reply = self._request(Request.GET, codec.encode([store, name]))
        if reply == b"":
            return None
        return Held.decode(reply)

    def token(self, store_id: int, name: str) -> bytes:
        return self._request(Request.TOKEN, codec.encode([store_id, name.encode()]))

    def seal(self, store_id: int, name: str, value: bytes) -> tuple[bytes, bytes, int]:
        reply = self._request(Request.SEAL, codec.encode([store_id, name.encode(), value]))
        parts = codec.as_seq(codec.decode(reply), 3)
        return codec.as_bytes(parts[0]), codec.as_bytes(parts[1]), codec.as_int(parts[2])

    def decrypt(self, store_id: int, name: str, ciphertext: bytes, epoch: int) -> bytes:
        return self._request(
            Request.DECRYPT, codec.encode([store_id, name.encode(), ciphertext, epoch])
        )

    def submit(self, tx: ops.Transaction) -> SubmitHandle:
        corr_id = os.urandom(16)
        tx_bytes = tx.encode()
        mid = MessageId.random()
        slot = _ReplySlot()
        self._pending[corr_id] = slot
        self._send(Request.SUBMIT, corr_id, tx_bytes)
        try:
            op_hash = crypto.Digest(slot.wait(self._request_timeout))
        finally:
            self._pending.pop(corr_id, None)
        return SubmitHandle(mid=mid, op_hash=op_hash, _sub=self)

    def settled(self, op_hash: crypto.Digest) -> SubmitResult | None:
        reply = self._request(Request.QUERY, bytes(op_hash))
        if reply == QUERY_PENDING:
            return None
        if reply == QUERY_UNKNOWN:
            raise SocketSubstrateError(f"server has no record of {op_hash.hex()[:16]}")
        return SubmitResult.decode(reply)

    def evict_after_sec(self) -> float:
        if self._evict_cache is None:
            reply = self._request(Request.EVICT, b"")
            self._evict_cache = Millis(codec.as_int(codec.decode(reply))).as_seconds
        return self._evict_cache

    def wait_for_commit(self, timeout: float) -> None:
        with self._cond:
            self._cond.wait(timeout)

    @property
    def commit_cond(self) -> threading.Condition:
        return self._cond

    def commit_generation(self) -> int:
        return self._commit_seq

    def head(self) -> BlockHead | None:
        return self._head

    def __enter__(self):
        return self

    def __exit__(self, *_: object) -> None:
        self.close()

    def close(self) -> None:
        self._closed = True
        with contextlib.suppress(OSError):
            self._sock.shutdown(socket.SHUT_RDWR)
        self._sock.close()
        self._reader_thread.join()

    def _request(self, tag: Request, payload: bytes) -> bytes:
        corr_id = os.urandom(16)
        slot = _ReplySlot()
        self._pending[corr_id] = slot
        self._send(tag, corr_id, payload)
        try:
            return slot.wait(self._request_timeout)
        finally:
            self._pending.pop(corr_id, None)

    def _send(self, tag: Request, corr_id: bytes, payload: bytes) -> None:
        with self._send_lock:
            send_request(self._sock, tag, corr_id, payload)

    def _read_loop(self) -> None:
        try:
            while not self._closed:
                frame = read_response(self._sock)
                if frame is None:
                    break
                tag, corr_id, payload = frame
                if tag is Response.COMMIT:
                    if payload:
                        self._head = BlockHead.decode(payload)
                    with self._cond:
                        self._commit_seq += 1
                        self._cond.notify_all()
                else:
                    slot = self._pending.get(corr_id)
                    if slot is not None:
                        slot.set(payload)
        finally:
            for slot in self._pending.values():
                slot.abort()
            with self._cond:
                self._commit_seq += 1
                self._cond.notify_all()
