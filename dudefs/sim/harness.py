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

from .. import gossip, tunables
from ..acceptor import Acceptor, AcceptResult, PrepareResult, SubmitResult
from ..artifacts import (
    HLC,
    QC,
    Ballot,
    FrontierBundle,
    Heads,
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
from ..transports.memory import (
    CLIENT,
    ClientRunner,
    Faults,
    MemoryTransport,
    NetworkLinks,
    Scheduler,
)

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

    def roster_accept(
        self, tag: bytes, ballot: Ballot, op: Op, sync_frontier: Heads, new_epoch: int
    ) -> AcceptResult:
        r = self.inner.roster_accept(tag, ballot, op, sync_frontier, new_epoch)
        self.sim._trace(self.idx, "roster_accept", r)
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
        delta: int = tunables.SIM_DELTA_MS,
        net: NetworkLinks | None = None,
        skew: dict[int, int] | None = None,
        drift: dict[int, float] | None = None,
        personas: dict[int, type[Acceptor]] | None = None,
    ):
        self.sched = Scheduler()
        self.n = n
        self.quorum = quorum_size(n)
        self._personas = personas or {}  # node idx -> adversarial Acceptor subclass (WP3)
        # per-node clock skew (WP2.3): each node acts at `now + offset + drift·now`.
        # A step jump is a scheduled reassignment of self._skew[i] mid-run; the
        # acceptor's floor = max(computed, attested) makes B3 survive a backward
        # jump by construction (the durable attested floor never regresses).
        self._skew = dict(skew or {})
        self._drift = dict(drift or {})
        self._raw = self._build_nodes(n, delta)
        self.roster = [nd.acc.pub for nd in self._raw]
        self.nodes = [LoggingNode(nd, i, self) for i, nd in enumerate(self._raw)]
        # `net` (a NetworkLinks) enables per-link faults + partitions + gossip heal
        # (WP2.2); without it the transport is the uniform per-hop Faults, unchanged.
        self.net = net
        self.transport = MemoryTransport(
            self.sched, self.nodes, faults, random.Random(seed ^ 0x5DEECE66), links=net
        )
        self.trace: list[Transition] = []
        self._b1 = _B1State()
        self._floors: dict[int, HLC] = {}
        self.runners: list[ClientRunner] = []
        self._cut: dict[bytes, tuple[int, bytes]] = {}  # active compaction cut (WP2 infra)
        self._dead: frozenset[bytes] = frozenset()

    def _build_nodes(self, n: int, delta: int) -> list[LocalNode]:
        out = []
        for i in range(n):
            sk = bytes([200 + i] * 32)
            pub = SIGNER.public(sk)
            cls = self._personas.get(i, Acceptor)  # an adversarial subclass, or honest
            acc = cls(sk, pub, ChainStore(), config_epoch=0, delta_ms=delta)
            out.append(LocalNode(acc, self._node_clock(i)))
        return out

    def _node_clock(self, i: int):
        """Node i's skewed clock: `now + offset + drift·now`, floored at 0."""

        def clk() -> int:
            off = self._skew.get(i, 0) + int(self._drift.get(i, 0) * self.sched.now)
            return max(0, self.sched.now + off)

        return clk

    def set_skew(self, i: int, offset: int) -> None:
        """Jump node i's clock offset (a scheduled call is an NTP-style step)."""
        self._skew[i] = offset

    # ---- launching clients ------------------------------------------------- #
    def cfg(self, client_pub: bytes, **kw) -> QuorumConfig:
        return QuorumConfig(roster=self.roster, epoch=0, client_fp=fingerprint(client_pub), **kw)

    def commit(self, op: Op, *, src_id: int = CLIENT, **cfg_kw) -> ClientRunner:
        r = ClientRunner(
            Commit(self.cfg(op.author, **cfg_kw), op), self.transport, self.sched, src_id=src_id
        )
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

    def run(self, deadline_ms: int = tunables.SIM_RUN_DEADLINE_MS) -> None:
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
        # B1 (FORMAL, rev 5): at most one op ever obtains a quorum for a slot, both
        # at a single ballot AND across all ballots — STRICT single-decree for
        # all-honest quorums. With adversarial personas present it relaxes to
        # exactly FORMAL B6 (NOTES 41 ruling a): an equivocator CAN mint duplicate
        # same-slot QCs (RESILIENCE §3.1), but only via its own equivocation, so
        # every such duplicate must trace to a persona node — never an honest one.
        if len(quorumed) > 1:
            self._b1_relaxed(quorumed, by_op, "same-ballot", ballot)
        if quorumed:
            decided = self._b1.decided.setdefault(slot, set())
            decided.update(quorumed)
            if len(decided) > 1:
                self._b1_relaxed(list(decided), None, "cross-ballot", ballot)

    def _b1_relaxed(self, ops, by_op, kind: str, ballot: Ballot) -> None:
        """A slot got >1 QC. Legal ONLY under personas (NOTES 41 a): assert a
        persona is responsible. For same-ballot, the equivocator is the node in the
        intersection of the quorums (it receipted two ops at one ballot); it must be
        a known persona. The one-winner fold and the assemblable DOUBLE_VOTE proof
        (B6's other two clauses) are asserted by the persona tests."""
        personas = set(self._personas)
        assert personas, (
            f"B1 violated ({kind}): {len(ops)} ops decided one slot at {ballot}; no persona"
        )
        if by_op is not None:
            doubles = {n for h in ops for n in by_op[h] if sum(n in by_op[g] for g in ops) >= 2}
            assert doubles and doubles <= personas, (
                f"B1 violated ({kind}): duplicate same-slot QCs but the intersection is HONEST"
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

    # ---- partitions + gossip heal (WP2.2) --------------------------------- #
    def partition(self, group_a: list[int], group_b: list[int]) -> None:
        """Cut every node↔node link between the two groups (both directions). A
        client is pinned to a side by cutting its src_id↔node links separately."""
        assert self.net is not None, "partitions require a NetworkLinks (pass net=...)"
        for a in group_a:
            for b in group_b:
                self.net.cut(a, b)

    def gossip_round(self) -> None:
        """One anti-entropy sweep: each node merges every peer whose DIRECTED link
        to it is up (partition-respecting) — node i learns from j iff j→i is up.
        Cut-aware once a checkpoint is adopted (NOTES 40 infra): the dense tail
        via merge, the sparse below-cut baseline via pull_baseline over the retained
        projection (covered ∖ dead), so a compacted mesh still converges."""
        for i in range(self.n):
            for j in range(self.n):
                if i != j and (self.net is None or (j, i) not in self.net.down):
                    dst, src = self._raw[i].acc.store, self._raw[j].acc.store
                    gossip.merge(dst, src)
                    if self._cut:
                        gossip.pull_baseline(dst, src, self._cut, self._dead)

    def adopt_checkpoint(self, cut, retained, dead, nodes=None) -> None:
        """Adopt a quorum-committed checkpoint on `nodes` (all by default) — the
        sim-side of checkpoint adoption (NOTES 40 infra). GC is a SEPARATE step
        (`gc`), so mixed-laziness (nodes GC'ing at different times) is testable."""
        for i in range(self.n) if nodes is None else nodes:
            self._raw[i].acc.store.adopt_checkpoint(cut, retained, list(dead))
        self._cut, self._dead = cut, frozenset(dead)

    def gc(self, dead, nodes=None) -> None:
        """Run the checkpoint's GC delta on `nodes` (all by default). Lazy + local:
        nodes may call this at wildly different times (the mixed-laziness persona)."""
        for i in range(self.n) if nodes is None else nodes:
            self._raw[i].acc.store.gc_checkpoint(list(dead))

    def start_gossip(self, period_ms: int) -> None:
        """Schedule periodic anti-entropy for the duration of the run."""

        def tick() -> None:
            self.gossip_round()
            self.sched.after(period_ms, tick)

        self.sched.after(period_ms, tick)

    def converged(self) -> bool:
        """The gossip fixpoint after heal: every node holds the same ops AND the
        same receipt coverage AND the same QCs (NOTES 40 infra — receipt/QC
        coverage is what lets any node assemble third-party evidence, e.g. a
        DOUBLE_VOTE from an equivocator's spread receipts)."""

        def triple(nd) -> tuple:
            st = nd.acc.store
            return (
                frozenset(o.op_hash for o in st.all_ops()),
                frozenset((r.op_hash, r.signer) for r in st.all_receipts()),
                frozenset(q.op_hash for q in st.all_qcs()),
            )

        views = [triple(nd) for nd in self._raw]
        return all(v == views[0] for v in views)

    def evidence(self) -> list:
        """Every portable misbehavior proof any node has minted (B6). Honest nodes
        never violate, so this stays empty across chaos runs; the persona builds
        (WP3) that equivocate are what exercise the minting side of B6. FORK
        (two signed ops at one author/seq) is the one kind wired today."""
        return [ev for nd in self._raw for ev in nd.acc.store.evidence()]

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
