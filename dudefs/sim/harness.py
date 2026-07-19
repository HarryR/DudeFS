# DudeFS — the deterministic simulation harness (IMPLEMENTATION §6).
#
# COMPOSITION ONLY. Every rule the chaos monkey could catch has a smaller home
# where it is caught first (test_acceptor, test_quorum, test_transport); this
# harness just wires ≥3 layers together — many quorum clients + a roster of
# nodes + the fault-injecting transport, all on one seeded clock — and checks
# the end-to-end B-hypotheses *continuously* while chaos runs:
#
#   * B1 (slot safety) — at most one op per `slot_tag` ever gathers a same-ballot
#     quorum of receipts, and one winner per slot across all ballots. Checked at
#     the point receipts are *issued* (node-side), so a lost receipt still counts
#     — this is the rev-1 equivocation/deadlock guard.
#   * B2 (durability)  — a committed op is stored on ≥ quorum nodes (its receipts,
#     hence the op, sit in every quorum's intersection).
#   * B3 (finality)    — each node's attested watermark floor is monotone; a
#     regression is two signed statements in contradiction (DESIGN §9).
#
# Every node transition is appended to a structured trace from day one (the
# FORMAL §5 trace-validation seam). A violation raises immediately, and because
# the run is a pure function of the seed, the failure replays exactly.

from __future__ import annotations

import random
from dataclasses import dataclass, field

from ..acceptor import Acceptor, AcceptResult, PrepareResult, SubmitResult
from ..artifacts import (
    HLC,
    QC,
    Ballot,
    FrontierBundle,
    Op,
    Receipt,
    Watermark,
    fingerprint,
    quorum_size,
)
from ..crypto import SIGNER
from ..node import LocalNode
from ..quorum import Commit, Finalize, QuorumConfig
from ..store import ChainStore
from ..transports.memory import ClientRunner, Faults, MemoryTransport, Scheduler

NO_FAULTS = Faults()


@dataclass(frozen=True)
class Transition:
    """One node-side state transition — the trace record (FORMAL §5)."""

    t: int
    node: int
    verb: str
    result: str


def _tag(x: object) -> str:
    return type(x).__name__


# --------------------------------------------------------------------------- #
# LoggingNode — a NodeAPI that traces every verb and feeds the invariant checks #
# --------------------------------------------------------------------------- #


class LoggingNode:
    """Wraps a LocalNode: delegates every verb, appends a Transition, and routes
    issued receipts / floors into the Sim's continuous B1/B3 checks."""

    def __init__(self, inner: LocalNode, idx: int, sim: Sim):
        self.inner = inner
        self.idx = idx
        self.sim = sim

    def submit(self, op: Op) -> SubmitResult:
        r = self.inner.submit(op)
        self.sim._trace(self.idx, "submit", r)
        if isinstance(r, Receipt) and op.slot_tag is not None:
            self.sim._on_receipt(op.slot_tag, r.ballot, op.op_hash, self.idx)
        return r

    def prepare(self, tag: bytes, ballot: Ballot) -> PrepareResult:
        r = self.inner.prepare(tag, ballot)
        self.sim._trace(self.idx, "prepare", r)
        return r

    def accept(self, tag: bytes, ballot: Ballot, op: Op) -> AcceptResult:
        r = self.inner.accept(tag, ballot, op)
        self.sim._trace(self.idx, "accept", r)
        if isinstance(r, Receipt) and op.slot_tag is not None:
            self.sim._on_receipt(op.slot_tag, r.ballot, op.op_hash, self.idx)
        return r

    def frontier(self) -> FrontierBundle:
        r = self.inner.frontier()
        self.sim._trace(self.idx, "frontier", r)
        return r

    def watermark(self) -> Watermark:
        r = self.inner.watermark()
        self.sim._trace(self.idx, "watermark", r)
        self.sim._on_floor(self.idx, r.floor)
        return r

    def fetch_op(self, op_hash: bytes) -> Op | None:
        return self.inner.fetch_op(op_hash)

    def get_qc(self, op_hash: bytes) -> QC | None:
        return self.inner.get_qc(op_hash)

    def put_qc(self, qc: QC) -> None:
        self.inner.put_qc(qc)


# --------------------------------------------------------------------------- #
# Sim — the composition                                                        #
# --------------------------------------------------------------------------- #


@dataclass
class _B1State:
    # (slot_tag, ballot) -> {op_hash: set(node) that receipted it}
    receipts: dict[tuple[bytes, Ballot], dict[bytes, set[int]]] = field(default_factory=dict)
    # slot_tag -> every op that reached a same-ballot quorum (a QC). rev 5: the
    # fast path is gone, so this is single-decree — at most ONE op per slot ever
    # decides, across all ballots (cross-ballot B1, asserted below).
    decided: dict[bytes, set[bytes]] = field(default_factory=dict)


class Sim:
    """A seeded world: `n` honest nodes behind the fault-injecting transport, and
    a shared clock. Launch quorum clients with `commit`/`finalize`, then `run`."""

    def __init__(
        self,
        seed: int = 0,
        *,
        n: int = 3,
        faults: Faults = NO_FAULTS,
        delta: int = 10_000,
    ):
        self.sched = Scheduler()
        self.n = n
        self.quorum = quorum_size(n)
        self._raw = self._build_nodes(n, delta)
        self.roster = [nd.acc.pub for nd in self._raw]
        self.nodes = [LoggingNode(nd, i, self) for i, nd in enumerate(self._raw)]
        self.transport = MemoryTransport(
            self.sched, self.nodes, faults, random.Random(seed ^ 0x5DEECE66)
        )
        self.trace: list[Transition] = []
        self._b1 = _B1State()
        self._floors: dict[int, HLC] = {}
        self.runners: list[ClientRunner] = []

    def _build_nodes(self, n: int, delta: int) -> list[LocalNode]:
        out = []
        for i in range(n):
            sk = bytes([200 + i] * 32)
            pub = SIGNER.public(sk)
            acc = Acceptor(sk, pub, ChainStore(), config_epoch=0, delta_ms=delta)
            out.append(LocalNode(acc, lambda: self.sched.now))
        return out

    # ---- launching clients ------------------------------------------------- #
    def cfg(self, client_pub: bytes, **kw) -> QuorumConfig:
        return QuorumConfig(roster=self.roster, epoch=0, client_fp=fingerprint(client_pub), **kw)

    def commit(self, op: Op, **cfg_kw) -> ClientRunner:
        r = ClientRunner(Commit(self.cfg(op.author, **cfg_kw), op), self.transport, self.sched)
        r.launch()
        self.runners.append(r)
        return r

    def finalize(self, target: HLC, client_pub: bytes = b"reader", **cfg_kw) -> ClientRunner:
        r = ClientRunner(
            Finalize(self.cfg(client_pub, **cfg_kw), target), self.transport, self.sched
        )
        r.launch()
        self.runners.append(r)
        return r

    def run(self, deadline_ms: int = 100_000) -> None:
        """Interleave all launched runners on the one clock until they finish (or
        the deadline). B1/B3 are checked as transitions happen; B2 at the end."""
        while any(not r.done for r in self.runners) and self.sched.step():
            if self.sched.now > deadline_ms:
                break
        self._check_durability()

    # ---- trace + invariant hooks ------------------------------------------ #
    def _trace(self, node: int, verb: str, result: object) -> None:
        self.trace.append(Transition(self.sched.now, node, verb, _tag(result)))

    def _on_receipt(self, slot: bytes, ballot: Ballot, op_hash: bytes, node: int) -> None:
        by_op = self._b1.receipts.setdefault((slot, ballot), {})
        by_op.setdefault(op_hash, set()).add(node)
        quorumed = [h for h, nodes in by_op.items() if len(nodes) >= self.quorum]
        # B1 (FORMAL, rev 5 — the strengthened invariant): at most one op ever
        # obtains a quorum, both at a single ballot AND across all ballots. The
        # two-phase-only slot layer makes this unconditional (no fast-path
        # collision), so the sim asserts full single-decree.
        assert len(quorumed) <= 1, (
            f"B1 violated: {len(quorumed)} ops reached a same-ballot quorum "
            f"for one slot at {ballot}"
        )
        if quorumed:
            decided = self._b1.decided.setdefault(slot, set())
            decided.add(quorumed[0])
            assert len(decided) == 1, (
                f"B1 violated: {len(decided)} distinct ops decided for one slot "
                f"(cross-ballot) — {[h.hex()[:8] for h in decided]}"
            )

    def _on_floor(self, node: int, floor: HLC) -> None:
        prev = self._floors.get(node)
        assert prev is None or prev <= floor, f"B3 violated: node {node} floor regressed"
        self._floors[node] = floor

    def _check_durability(self) -> None:
        for slot, op_hashes in self._b1.decided.items():
            for op_hash in op_hashes:
                holders = sum(1 for nd in self._raw if nd.fetch_op(op_hash) is not None)
                assert holders >= self.quorum, (
                    f"B2 violated: committed op for slot {slot!r} on "
                    f"{holders} < {self.quorum} nodes"
                )

    # ---- read helpers for tests ------------------------------------------- #
    def decided_ops(self, slot_tag: bytes) -> set[bytes]:
        """Every op that obtained a QC for this slot. rev 5: exactly one (or zero
        if nothing committed) — the two-phase slot layer is single-decree."""
        return set(self._b1.decided.get(slot_tag, set()))

    def get_op(self, op_hash: bytes) -> Op | None:
        for nd in self._raw:
            op = nd.fetch_op(op_hash)
            if op is not None:
                return op
        return None
