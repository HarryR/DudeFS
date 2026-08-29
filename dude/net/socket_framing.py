from __future__ import annotations

import socket
import struct
from enum import Enum

from ..core import codec
from ..core.errors import DudeError


class FramingError(DudeError): ...


class FrameTooLargeError(FramingError): ...


class FrameTruncatedError(FramingError): ...


class UnknownTagError(FramingError): ...


class Request(bytes, Enum):
    GET = b"g"
    ANCHOR = b"a"
    EVICT = b"e"
    TOKEN = b"t"
    SEAL = b"l"
    DECRYPT = b"y"
    SUBMIT = b"s"
    QUERY = b"q"


class Response(bytes, Enum):
    GET = b"G"
    ANCHOR = b"A"
    EVICT = b"E"
    TOKEN = b"T"
    SEAL = b"L"
    DECRYPT = b"Y"
    SUBMIT_ACK = b"S"
    QUERY = b"Q"
    COMMIT = b"C"


QUERY_PENDING = b"P"

_REQ_BY_VALUE: dict[bytes, Request] = {t.value: t for t in Request}
_RESP_BY_VALUE: dict[bytes, Response] = {t.value: t for t in Response}

_HDR = struct.Struct(">I")
_MAX_FRAME = 1 << 24


def send_request(sock: socket.socket, tag: Request, corr_id: bytes, payload: bytes) -> None:
    _send(sock, tag.value, corr_id, payload)


def send_response(sock: socket.socket, tag: Response, corr_id: bytes, payload: bytes) -> None:
    _send(sock, tag.value, corr_id, payload)


def read_request(sock: socket.socket) -> tuple[Request, bytes, bytes] | None:
    return _read(sock, _REQ_BY_VALUE)


def read_response(sock: socket.socket) -> tuple[Response, bytes, bytes] | None:
    return _read(sock, _RESP_BY_VALUE)


def _send(sock: socket.socket, tag: bytes, corr_id: bytes, payload: bytes) -> None:
    body = codec.encode([tag, corr_id, payload])
    sock.sendall(_HDR.pack(len(body)) + body)


def _read[T](sock: socket.socket, lookup: dict[bytes, T]) -> tuple[T, bytes, bytes] | None:
    raw_len = _recv_exact(sock, _HDR.size)
    if raw_len is None:
        return None
    length = _HDR.unpack(raw_len)[0]
    if length > _MAX_FRAME:
        raise FrameTooLargeError(length)
    raw_body = _recv_exact(sock, length)
    if raw_body is None:
        raise FrameTruncatedError
    parts = codec.as_seq(codec.decode(raw_body), 3)
    raw_tag = codec.as_bytes(parts[0])
    tag = lookup.get(raw_tag)
    if tag is None:
        raise UnknownTagError(raw_tag)
    return tag, codec.as_bytes(parts[1]), codec.as_bytes(parts[2])


def _recv_exact(sock: socket.socket, n: int) -> bytes | None:
    buf = bytearray()
    while len(buf) < n:
        chunk = sock.recv(n - len(buf))
        if not chunk:
            if buf:
                raise FrameTruncatedError
            return None
        buf.extend(chunk)
    return bytes(buf)
