# DudeFS — the cluster wire (node<->node + client<->node framing, IMPLEMENTATION §2).
#
# M7 WP1: the daemon speaks 4-byte big-endian length prefix + bencode. This module
# owns ONLY serialization — no sockets, no state (the M3 discipline: I/O lives in
# the daemon shell). Every request/response variant is a tag-led bencode list; the
# artifacts carry their own encode/decode, so this is a thin dispatch over them.

from __future__ import annotations

import struct
from collections.abc import Callable

from . import codec
from .acceptor import Nack, Rejected, RejectReason
from .artifacts import QC, Ballot, FrontierBundle, Op, Promise, Receipt, Watermark
from .node import (
    AcceptReq,
    FetchOpReq,
    FrontierReq,
    GetQCReq,
    PrepareReq,
    PutQCReq,
    Request,
    Response,
    SubmitReq,
    WatermarkReq,
)

# --------------------------------------------------------------------------- #
# Length-prefix framing                                                       #
# --------------------------------------------------------------------------- #


def frame(payload: bytes) -> bytes:
    """A wire frame: 4-byte big-endian length + payload (IMPLEMENTATION §2)."""
    return struct.pack(">I", len(payload)) + payload


def read_frame(recv: Callable[[int], bytes]) -> bytes | None:
    """Read one framed message via `recv(n)` (a socket's recv or any byte source).
    Returns the payload, or None on a clean EOF at a frame boundary."""
    hdr = _recv_exact(recv, 4)
    if hdr is None:
        return None
    (n,) = struct.unpack(">I", hdr)
    return _recv_exact(recv, n)


def _recv_exact(recv: Callable[[int], bytes], n: int) -> bytes | None:
    buf = b""
    while len(buf) < n:
        chunk = recv(n - len(buf))
        if not chunk:
            return None  # EOF mid-frame (clean only if buf is empty, caller's concern)
        buf += chunk
    return buf


# --------------------------------------------------------------------------- #
# Request codec — the client's PROTOCOL §1.1 verbs                            #
# --------------------------------------------------------------------------- #


def encode_request(req: Request) -> bytes:
    match req:
        case SubmitReq(op):
            body: list = [b"submit", op.raw]
        case PrepareReq(tag, ballot):
            body = [b"prepare", tag, ballot.encode()]
        case AcceptReq(tag, ballot, op):
            body = [b"accept", tag, ballot.encode(), op.raw]
        case FrontierReq():
            body = [b"frontier"]
        case WatermarkReq():
            body = [b"watermark"]
        case FetchOpReq(op_hash):
            body = [b"fetch", op_hash]
        case GetQCReq(op_hash):
            body = [b"getqc", op_hash]
        case PutQCReq(qc):
            body = [b"putqc", qc.encode()]
    return codec.encode(body)


def decode_request(data: bytes) -> Request:
    p = codec.as_seq(codec.decode(data))
    tag = codec.as_bytes(p[0])
    if tag == b"submit":
        return SubmitReq(Op.from_bytes(codec.as_bytes(p[1])))
    if tag == b"prepare":
        return PrepareReq(codec.as_bytes(p[1]), Ballot.decode(p[2]))
    if tag == b"accept":
        op = Op.from_bytes(codec.as_bytes(p[3]))
        return AcceptReq(codec.as_bytes(p[1]), Ballot.decode(p[2]), op)
    if tag == b"frontier":
        return FrontierReq()
    if tag == b"watermark":
        return WatermarkReq()
    if tag == b"fetch":
        return FetchOpReq(codec.as_bytes(p[1]))
    if tag == b"getqc":
        return GetQCReq(codec.as_bytes(p[1]))
    if tag == b"putqc":
        return PutQCReq(QC.decode(codec.as_bytes(p[1])))
    raise codec.CodecError(f"unknown request tag {tag!r}")


# --------------------------------------------------------------------------- #
# Response codec — the union every verb can return                            #
# --------------------------------------------------------------------------- #


def encode_response(resp: Response) -> bytes:
    match resp:
        case Receipt():
            body: list = [b"receipt", resp.encode()]
        case Nack():
            body = [b"nack", resp.promised.encode()]
        case Rejected():
            body = [b"rejected", resp.reason.name.encode()]  # enum NAME is the stable wire form
        case Promise():
            body = [b"promise", resp.encode()]
        case Watermark():
            body = [b"watermark", resp.encode()]
        case FrontierBundle():
            body = [b"frontier", resp.encode()]
        case QC():
            body = [b"qc", resp.encode()]
        case Op():
            body = [b"op", resp.raw]
        case None:
            body = [b"none"]
    return codec.encode(body)


def decode_response(data: bytes) -> Response:
    p = codec.as_seq(codec.decode(data))
    tag = codec.as_bytes(p[0])
    if tag == b"receipt":
        return Receipt.decode(codec.as_bytes(p[1]))
    if tag == b"nack":
        return Nack(Ballot.decode(p[1]))
    if tag == b"rejected":
        return Rejected(RejectReason[codec.as_bytes(p[1]).decode()])
    if tag == b"promise":
        return Promise.decode(codec.as_bytes(p[1]))
    if tag == b"watermark":
        return Watermark.decode(codec.as_bytes(p[1]))
    if tag == b"frontier":
        return FrontierBundle.decode(codec.as_bytes(p[1]))
    if tag == b"qc":
        return QC.decode(codec.as_bytes(p[1]))
    if tag == b"op":
        return Op.from_bytes(codec.as_bytes(p[1]))
    if tag == b"none":
        return None
    raise codec.CodecError(f"unknown response tag {tag!r}")
