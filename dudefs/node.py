# DudeFS — storage-node assembly + the client<->node protocol seam (PROTOCOL §1).
#
# This module owns the *verb surface* of a storage node: the `NodeAPI` Protocol
# (the PROTOCOL §1 verbs as typed methods), the typed `Request` vocabulary the
# quorum client builds, a `dispatch` that runs one request against a node, and
# `LocalNode` — the in-process adapter over an `Acceptor` + its `ChainStore`
# with an injected clock (no I/O, no wall-clock; IMPLEMENTATION §0).
#
# It is the ONE new Protocol seam M3 adds (IMPLEMENTATION §5): the sans-io
# quorum client (quorum.py) never touches a node directly — it emits Sends that
# a transport executes here.

from __future__ import annotations

from collections.abc import Callable
from dataclasses import dataclass
from typing import Protocol

from .acceptor import Acceptor, AcceptResult, PrepareResult, SubmitResult
from .artifacts import QC, Ballot, FrontierBundle, Heads, Op, Watermark

# --------------------------------------------------------------------------- #
# Request vocabulary — the PROTOCOL §1.1 verbs, as data the client sends.      #
# --------------------------------------------------------------------------- #


@dataclass(frozen=True)
class SubmitReq:
    op: Op


@dataclass(frozen=True)
class PrepareReq:
    tag: bytes
    ballot: Ballot


@dataclass(frozen=True)
class AcceptReq:
    tag: bytes
    ballot: Ballot
    op: Op


@dataclass(frozen=True)
class RosterAcceptReq:
    """A new-roster node accepting a roster op under the data-possession barrier
    (DESIGN §13 step 4): `sync_frontier` + `new_epoch` ride the wire so the acceptor
    stays free of the L6 control vocabulary. The manager drives this to gather the
    joint certificate's new-roster half."""

    tag: bytes
    ballot: Ballot
    op: Op
    sync_frontier: Heads
    new_epoch: int


@dataclass(frozen=True)
class FrontierReq:
    pass


@dataclass(frozen=True)
class WatermarkReq:
    pass


@dataclass(frozen=True)
class FetchOpReq:
    op_hash: bytes


@dataclass(frozen=True)
class GetQCReq:
    op_hash: bytes


@dataclass(frozen=True)
class PutQCReq:
    qc: QC


type Request = (
    SubmitReq
    | PrepareReq
    | AcceptReq
    | RosterAcceptReq
    | FrontierReq
    | WatermarkReq
    | FetchOpReq
    | GetQCReq
    | PutQCReq
)

# The result of serving a request — the union of every verb's return type.
type Response = (
    SubmitResult | AcceptResult | PrepareResult | FrontierBundle | Watermark | Op | QC | None
)


# --------------------------------------------------------------------------- #
# NodeAPI — the seam. A storage node answers these; every response is served   #
# from local state (nodes never fan out — PROTOCOL §0).                        #
# --------------------------------------------------------------------------- #


class NodeAPI(Protocol):
    def submit(self, op: Op) -> SubmitResult: ...
    def prepare(self, tag: bytes, ballot: Ballot) -> PrepareResult: ...
    def accept(self, tag: bytes, ballot: Ballot, op: Op) -> AcceptResult: ...
    def roster_accept(
        self, tag: bytes, ballot: Ballot, op: Op, sync_frontier: Heads, new_epoch: int
    ) -> AcceptResult: ...
    def frontier(self) -> FrontierBundle: ...
    def watermark(self) -> Watermark: ...
    def fetch_op(self, op_hash: bytes) -> Op | None: ...
    def get_qc(self, op_hash: bytes) -> QC | None: ...
    def put_qc(self, qc: QC) -> None: ...


def dispatch(node: NodeAPI, req: Request) -> Response:
    """Run one request against a node (server side). Every verb is idempotent
    and served from local state (PROTOCOL §0)."""
    match req:
        case SubmitReq(op):
            return node.submit(op)
        case PrepareReq(tag, ballot):
            return node.prepare(tag, ballot)
        case AcceptReq(tag, ballot, op):
            return node.accept(tag, ballot, op)
        case RosterAcceptReq(tag, ballot, op, sf, new_epoch):
            return node.roster_accept(tag, ballot, op, sf, new_epoch)
        case FrontierReq():
            return node.frontier()
        case WatermarkReq():
            return node.watermark()
        case FetchOpReq(op_hash):
            return node.fetch_op(op_hash)
        case GetQCReq(op_hash):
            return node.get_qc(op_hash)
        case PutQCReq(qc):
            node.put_qc(qc)
            return None


# --------------------------------------------------------------------------- #
# LocalNode — an Acceptor + store behind the NodeAPI, with an injected clock.  #
# --------------------------------------------------------------------------- #


class LocalNode:
    """In-process NodeAPI over one Acceptor. `clock` returns the node's local
    `now_ms` (the node uses its own clock — PROTOCOL §0; the sim drives it)."""

    def __init__(self, acceptor: Acceptor, clock: Callable[[], int]):
        self.acc = acceptor
        self.clock = clock

    def submit(self, op: Op) -> SubmitResult:
        return self.acc.on_submit(op, self.clock())

    def prepare(self, tag: bytes, ballot: Ballot) -> PrepareResult:
        return self.acc.on_prepare(tag, ballot)

    def accept(self, tag: bytes, ballot: Ballot, op: Op) -> AcceptResult:
        return self.acc.on_accept(tag, ballot, op, self.clock())

    def roster_accept(
        self, tag: bytes, ballot: Ballot, op: Op, sync_frontier: Heads, new_epoch: int
    ) -> AcceptResult:
        return self.acc.on_roster_accept(tag, ballot, op, sync_frontier, new_epoch, self.clock())

    def frontier(self) -> FrontierBundle:
        return self.acc.issue_frontier(self.clock())

    def watermark(self) -> Watermark:
        return self.acc.issue_watermark(self.clock())

    def fetch_op(self, op_hash: bytes) -> Op | None:
        with self.acc.store.read_txn() as tx:
            return tx.get_op(op_hash)

    def get_qc(self, op_hash: bytes) -> QC | None:
        with self.acc.store.read_txn() as tx:
            return tx.get_qc(op_hash)

    def put_qc(self, qc: QC) -> None:
        with self.acc.store.write_txn() as tx:
            tx.put_qc(qc)
