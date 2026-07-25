# DudeFS — the deterministic STEP DRIVER (HANDOFF-R9 §1-3), the sim's successor.
#
# The old `_harness.Sim` drove the real quorum machines over the fault-injecting
# carrier, but its `ClientRunner` added a transport-level RETRANSMIT that production
# does NOT have (client._drive re-emits Sends only via the machine's own round-timeout
# escalation, quorum.py:279). That extra resend was the one place the sim diverged
# from the product — it could paper over a wedge the real system would hit. `StepDriver`
# removes it: a lost Send is recovered ONLY by the machine escalating on its deadline,
# exactly as production does. If a scenario now wedges, that is a real finding (§6.3),
# surfaced not masked.
#
# COMPOSITION ONLY (as before): every rule has a smaller home (test_acceptor,
# test_quorum, test_checkpoint); this driver wires many quorum clients + a roster of
# real Acceptors + the seeded carrier onto one clock and checks the end-to-end
# B-hypotheses CONTINUOUSLY while chaos runs:
#
#   * B1 (slot safety) — at most one op per `slot_tag` ever gathers a same-ballot
#     quorum of receipts, and one winner per slot across all ballots (checked where
#     receipts are ISSUED, so a lost receipt still counts).
#   * B2 (durability)  — a committed op is stored on >= quorum nodes.
#   * B3 (finality)    — each node's attested watermark floor is monotone.
#
# The carrier/clock/fault-models live in `tests/_carrier.py` (lifted out of the retired
# `dudefs/transports/memory.py`); this module owns the driver — `_Pump` + `StepDriver`.

from __future__ import annotations

import random
from dataclasses import dataclass, field

from dudefs import artifacts as A
from dudefs import tunables
from dudefs.acceptor import Acceptor, AcceptResult, PrepareResult, SubmitResult
from dudefs.artifacts import (
    HLC,
    QC,
    Ballot,
    Baseline,
    FrontierBundle,
    Heads,
    Op,
    Receipt,
    Watermark,
    fingerprint,
    quorum_size,
)
from dudefs.crypto import SoftwareKeypair
from dudefs.node import LocalNode, Request, Response
from dudefs.quorum import (
    Command,
    Commit,
    Done,
    Finalize,
    QuorumConfig,
    Reply,
    Send,
    Tick,
    Wake,
)
from dudefs.store import ChainStore
from tests._carrier import CLIENT, Faults, MemoryTransport, NetworkLinks, Scheduler
from tests._gossip import merge, pull_baseline

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
# _Pump — drive ONE sans-io machine over the carrier, NO retransmit             #
# --------------------------------------------------------------------------- #


class _Pump:
    """Pumps one sans-io machine (Commit/Finalize) over the carrier, registering its
    callbacks on the shared scheduler — but NOT owning the run loop, so many pumps
    interleave on one clock. Unlike the retired `ClientRunner`, there is NO retransmit:
    a Send that draws no Reply is recovered solely by the machine's round-timeout
    escalation (`feed(Tick)` past its deadline re-fans-out, quorum.py:279). This is a
    faithful twin of production `client._drive`, whose Sends are threads and Wakes are
    timers over the SAME machine. `done`/`outcome` report the terminal verdict."""

    def __init__(
        self, machine, transport: MemoryTransport, sched: Scheduler, *, src_id: int = CLIENT
    ):
        self.machine = machine
        self.transport = transport
        self.sched = sched
        self.src_id = src_id
        self.done = False
        self.outcome: object = None

    def launch(self) -> None:
        self._run(self.machine.start(self.sched.now))

    def _run(self, cmds: list[Command]) -> None:
        for c in cmds:
            match c:
                case Done(outcome):
                    self.done, self.outcome = True, outcome
                case Wake(at_ms):
                    self.sched.at(at_ms, self._on_tick)
                case Send(node, req):
                    self.transport.send(node, req, self._on_reply, self.src_id)

    def _on_reply(self, node: int, req: Request, result: Response) -> None:
        if self.done:
            return
        self._run(self.machine.feed(Reply(node, req, result, self.sched.now)))

    def _on_tick(self) -> None:
        if self.done:
            return
        self._run(self.machine.feed(Tick(self.sched.now)))


# --------------------------------------------------------------------------- #
# LoggingNode — a NodeAPI that traces every verb and feeds the invariant checks #
# --------------------------------------------------------------------------- #


class LoggingNode:
    """Wraps a LocalNode: delegates every verb, appends a Transition, and routes
    issued receipts / floors into the driver's continuous B1/B3 checks."""

    def __init__(self, inner: LocalNode, idx: int, drv: StepDriver):
        self.inner = inner
        self.idx = idx
        self.drv = drv

    def submit(self, op: Op) -> SubmitResult:
        r = self.inner.submit(op)
        self.drv._trace(self.idx, "submit", r)
        if isinstance(r, Receipt) and isinstance(op, A.Slotted):
            self.drv._on_receipt(op.slot_tag, r.ballot, op.op_hash, self.idx)
        return r

    def prepare(self, tag: bytes, ballot: Ballot) -> PrepareResult:
        r = self.inner.prepare(tag, ballot)
        self.drv._trace(self.idx, "prepare", r)
        return r

    def accept(self, tag: bytes, ballot: Ballot, op: Op) -> AcceptResult:
        r = self.inner.accept(tag, ballot, op)
        self.drv._trace(self.idx, "accept", r)
        if isinstance(r, Receipt) and isinstance(op, A.Slotted):
            self.drv._on_receipt(op.slot_tag, r.ballot, op.op_hash, self.idx)
        return r

    def roster_accept(
        self, tag: bytes, ballot: Ballot, op: Op, sync_frontier: Heads, new_epoch: int
    ) -> AcceptResult:
        r = self.inner.roster_accept(tag, ballot, op, sync_frontier, new_epoch)
        self.drv._trace(self.idx, "roster_accept", r)
        if isinstance(r, Receipt) and isinstance(op, A.Slotted):
            self.drv._on_receipt(op.slot_tag, r.ballot, op.op_hash, self.idx)
        return r

    def frontier(self) -> FrontierBundle:
        r = self.inner.frontier()
        self.drv._trace(self.idx, "frontier", r)
        return r

    def watermark(self) -> Watermark:
        r = self.inner.watermark()
        self.drv._trace(self.idx, "watermark", r)
        self.drv._on_floor(self.idx, r.floor)
        return r

    def fetch_op(self, op_hash: bytes) -> Op | None:
        return self.inner.fetch_op(op_hash)

    def get_qc(self, op_hash: bytes) -> QC | None:
        return self.inner.get_qc(op_hash)

    def put_qc(self, qc: QC) -> None:
        self.inner.put_qc(qc)

    def rereceipt(self, target: bytes) -> Receipt | None:
        return self.inner.rereceipt(target)


# --------------------------------------------------------------------------- #
# StepDriver — the composition (Sim's successor, retransmit-free)              #
# --------------------------------------------------------------------------- #


@dataclass
class _B1State:
    # (slot_tag, ballot) -> {op_hash: set(node) that receipted it}
    receipts: dict[tuple[bytes, Ballot], dict[bytes, set[int]]] = field(default_factory=dict)
    # slot_tag -> every op that reached a same-ballot quorum (a QC). Single-decree:
    # at most ONE op per slot ever decides, across all ballots (cross-ballot B1).
    decided: dict[bytes, set[bytes]] = field(default_factory=dict)


class StepDriver:
    """A seeded world: `n` honest (or persona) real Acceptors behind the seeded
    carrier, on a shared clock. Launch quorum clients with `commit`/`finalize`, then
    `run`. Drives the REAL Commit/Finalize machines over REAL Acceptors; the ONLY
    simulated thing is the network (loss/dup/delay/partition). No retransmit — the
    machine's escalation is the sole recovery from loss (production-faithful)."""

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
        self._skew = dict(skew or {})
        self._drift = dict(drift or {})
        self.raw = self._build_nodes(n, delta)
        self.roster: list[bytes] = [nd.acc.node.public for nd in self.raw]
        self.nodes = [LoggingNode(nd, i, self) for i, nd in enumerate(self.raw)]
        # `net` (a NetworkLinks) enables per-link faults + partitions + gossip heal;
        # without it the carrier is the uniform per-hop Faults, unchanged.
        self.net = net
        self.transport = MemoryTransport(
            self.sched, self.nodes, faults, random.Random(seed ^ 0x5DEECE66), links=net
        )
        self.trace: list[Transition] = []
        self._b1 = _B1State()
        self._floors: dict[int, HLC] = {}
        self.pumps: list[_Pump] = []
        self._cut: A.Heads = {}  # active compaction cut (WP2 infra)
        self._dead: frozenset[bytes] = frozenset()

    def _build_nodes(self, n: int, delta: int) -> list[LocalNode]:
        out = []
        for i in range(n):
            sk = bytes([200 + i] * 32)
            cls = self._personas.get(i, Acceptor)  # an adversarial subclass, or honest
            acc = cls(SoftwareKeypair.from_seed(sk), ChainStore(), config_epoch=0, delta_ms=delta)
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

    def commit(self, op: Op, *, src_id: int = CLIENT, **cfg_kw) -> _Pump:
        machine = Commit(self.cfg(op.author, **cfg_kw), op)
        p = _Pump(machine, self.transport, self.sched, src_id=src_id)
        p.launch()
        self.pumps.append(p)
        return p

    def finalize(self, target: HLC, client_pub: bytes = b"reader", **cfg_kw) -> _Pump:
        p = _Pump(Finalize(self.cfg(client_pub, **cfg_kw), target), self.transport, self.sched)
        p.launch()
        self.pumps.append(p)
        return p

    def run(self, deadline_ms: int = tunables.SIM_RUN_DEADLINE_MS) -> None:
        """Interleave all launched pumps on the one clock until they finish (or the
        deadline). B1/B3 are checked as transitions happen; B2 at the end."""
        while any(not p.done for p in self.pumps) and self.sched.step():
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
        # B1 (rev 5): at most one op ever obtains a quorum for a slot, both at a single
        # ballot AND across all ballots — STRICT single-decree for all-honest quorums.
        # With adversarial personas it relaxes to FORMAL B6: an equivocator CAN mint
        # duplicate same-slot QCs, but only via its own equivocation, so every such
        # duplicate must trace to a persona node — never an honest one.
        if len(quorumed) > 1:
            self._b1_relaxed(quorumed, by_op, "same-ballot", ballot)
        if quorumed:
            decided = self._b1.decided.setdefault(slot, set())
            decided.update(quorumed)
            if len(decided) > 1:
                self._b1_relaxed(list(decided), None, "cross-ballot", ballot)

    def _b1_relaxed(self, ops, by_op, kind: str, ballot: Ballot) -> None:
        """A slot got >1 QC. Legal ONLY under personas (NOTES 41 a): assert a persona
        is responsible. For same-ballot, the equivocator is the node in the intersection
        of the quorums (it receipted two ops at one ballot); it must be a known persona."""
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
                holders = sum(1 for nd in self.raw if nd.fetch_op(op_hash) is not None)
                assert holders >= self.quorum, (
                    f"B2 violated: committed op for slot {slot!r} on "
                    f"{holders} < {self.quorum} nodes"
                )

    # ---- partitions + gossip heal (WP2.2) --------------------------------- #
    def partition(self, group_a: list[int], group_b: list[int]) -> None:
        """Cut every node<->node link between the two groups (both directions)."""
        assert self.net is not None, "partitions require a NetworkLinks (pass net=...)"
        for a in group_a:
            for b in group_b:
                self.net.cut(a, b)

    def gossip_round(self) -> None:
        """One anti-entropy sweep: node i learns from j iff j->i is up (partition-
        respecting). Cut-aware once a checkpoint is adopted: the dense tail via merge,
        the sparse below-cut baseline via pull_baseline over the retained projection."""
        for i in range(self.n):
            for j in range(self.n):
                if i != j and (self.net is None or (j, i) not in self.net.down):
                    dst, src = self.raw[i].acc.store, self.raw[j].acc.store
                    merge(dst, src)
                    if self._cut:
                        pull_baseline(dst, src, self._cut, self._dead)

    def adopt_checkpoint(self, cut, retained, dead, nodes=None) -> None:
        """Adopt a quorum-committed checkpoint on `nodes` (all by default). GC is a
        SEPARATE step (`gc`), so mixed-laziness is testable."""
        for i in range(self.n) if nodes is None else nodes:
            with self.raw[i].acc.store.write_txn() as tx:
                tx.adopt_checkpoint(Baseline(cut, retained, frozenset(dead)))
        self._cut, self._dead = cut, frozenset(dead)

    def gc(self, dead, nodes=None) -> None:
        """Run the checkpoint's GC delta on `nodes` (all by default). Lazy + local."""
        for i in range(self.n) if nodes is None else nodes:
            with self.raw[i].acc.store.write_txn() as tx:
                tx.gc_checkpoint(list(dead))

    def start_gossip(self, period_ms: int) -> None:
        """Schedule periodic anti-entropy for the duration of the run."""

        def tick() -> None:
            self.gossip_round()
            self.sched.after(period_ms, tick)

        self.sched.after(period_ms, tick)

    def converged(self) -> bool:
        """The gossip fixpoint after heal: every node holds the same ops AND the same
        receipt coverage AND the same QCs."""

        def triple(nd) -> tuple:
            with nd.acc.store.read_txn() as tx:
                return (
                    frozenset(o.op_hash for o in tx.all_ops()),
                    frozenset((r.op_hash, r.signer) for r in tx.all_receipts()),
                    frozenset(q.op_hash for q in tx.all_qcs()),
                )

        views = [triple(nd) for nd in self.raw]
        return all(v == views[0] for v in views)

    def evidence(self) -> list:
        """Every portable misbehavior proof any node has minted (B6). Honest nodes
        never violate, so this stays empty across chaos runs."""
        out: list = []
        for nd in self.raw:
            with nd.acc.store.read_txn() as tx:
                out.extend(tx.evidence())
        return out

    # ---- read helpers for tests ------------------------------------------- #
    def decided_ops(self, slot_tag: bytes) -> set[bytes]:
        """Every op that obtained a QC for this slot. rev 5: exactly one (or zero if
        nothing committed) — the two-phase slot layer is single-decree."""
        return set(self._b1.decided.get(slot_tag, set()))

    def get_op(self, op_hash: bytes) -> Op | None:
        for nd in self.raw:
            op = nd.fetch_op(op_hash)
            if op is not None:
                return op
        return None
