# DudeFS L4 — the quorum client (commitment & finality), written SANS-I/O.
#
# ARCHITECTURE L4 / PROTOCOL §1.2-§1.3, §4 / DESIGN §8-§9.
#
# A pure `(event in) -> (commands out)` state machine: it never touches a socket
# or a clock. It emits `Send`/`Wake`/`Done` commands; a driver (a transport, or
# the sim harness) executes Sends against a NodeAPI (node.dispatch), delivers
# `Reply` events back, and fires `Wake` times as `Tick` events. Every event
# carries the current `now_ms` (the driver always knows the time); hedging
# schedules are computed from it and `delta_hedge_ms` (PROTOCOL §4: fire the
# preferred quorum, stagger the rest, cancel stragglers on quorum — QuePaxa).
#
# This makes the §1.3 rules unit-testable against scripted node replies with no
# network in sight (IMPLEMENTATION §5).

from __future__ import annotations

from dataclasses import dataclass
from enum import Enum, auto
from typing import TypeGuard

from .acceptor import Nack
from .artifacts import HLC, QC, Ballot, Op, Promise, Receipt, Watermark, quorum_size
from .node import AcceptReq, FetchOpReq, PrepareReq, Request, Response, WatermarkReq

# --------------------------------------------------------------------------- #
# Config                                                                       #
# --------------------------------------------------------------------------- #


@dataclass(frozen=True)
class QuorumConfig:
    """The client's view of the roster it fans out to. `roster[i]` is node i's
    public key; node ids are roster indices. `client_fp` identifies this client
    in recovery ballots (round, client_fp)."""

    roster: list[bytes]
    epoch: int
    client_fp: bytes
    delta_hedge_ms: int = 50
    max_rounds: int = 8
    finality_poll_ms: int = 20
    max_polls: int = 1000

    @property
    def n(self) -> int:
        return len(self.roster)

    @property
    def quorum(self) -> int:
        return quorum_size(self.n)

    @property
    def roster_index(self) -> dict[bytes, int]:
        return {pub: i for i, pub in enumerate(self.roster)}


# --------------------------------------------------------------------------- #
# Commands (out) / Events (in) — every event carries now_ms                    #
# --------------------------------------------------------------------------- #


@dataclass(frozen=True)
class Send:
    node: int
    req: Request


@dataclass(frozen=True)
class Wake:
    at_ms: int


@dataclass(frozen=True)
class Done:
    outcome: object


type Command = Send | Wake | Done


@dataclass(frozen=True)
class Reply:
    node: int
    req: Request
    result: Response
    now_ms: int


@dataclass(frozen=True)
class Tick:
    now_ms: int


type Event = Reply | Tick


# --------------------------------------------------------------------------- #
# Outcomes                                                                     #
# --------------------------------------------------------------------------- #


class CommitFailure(Enum):
    UNREACHABLE = auto()  # a quorum of nodes can never accept (too many blocked)
    EXHAUSTED = auto()  # recovery ran out of ballot rounds without deciding


@dataclass(frozen=True)
class Committed:
    """This client's op is committed for the slot (a QC over its op)."""

    qc: QC


@dataclass(frozen=True)
class LostSlot:
    """A *rival* op was decided for the slot: recovery re-proposed the highest
    accepted op (DESIGN §8). The client re-reads and retries above it."""

    winner: bytes
    qc: QC


@dataclass(frozen=True)
class Failed:
    reason: CommitFailure


type CommitOutcome = Committed | LostSlot | Failed


@dataclass(frozen=True)
class Final:
    """The target hlc is final: a quorum attests floors ≥ it, so the committed
    set below it — and every fold verdict in it — is frozen (DESIGN §9). The
    frontier is the highest hlc a quorum currently attests (≥ target); the
    watermarks are the portable proof."""

    frontier: HLC
    watermarks: tuple[Watermark, ...]


type FinalizeOutcome = Final | Failed


# --------------------------------------------------------------------------- #
# Hedged fan-out (PROTOCOL §4)                                                 #
# --------------------------------------------------------------------------- #


class _Fanout:
    """Send `req` to a preferred quorum immediately, then stagger the remaining
    nodes one per `delta_hedge` (cancelled once the caller is satisfied). Pure:
    emits Send/Wake commands; collects replies keyed by node id."""

    def __init__(self, order: list[int], req: Request, delta_hedge: int, preferred: int):
        self.order = order
        self.req = req
        self.delta = delta_hedge
        self.preferred = preferred
        self.replies: dict[int, Response] = {}
        self._sent: set[int] = set()
        self._stopped = False

    def start(self, now: int) -> list[Command]:
        cmds: list[Command] = [Send(nid, self.req) for nid in self.order[: self.preferred]]
        self._sent.update(self.order[: self.preferred])
        if len(self._sent) < len(self.order):
            cmds.append(Wake(now + self.delta))
        return cmds

    def on_tick(self, now: int) -> list[Command]:
        if self._stopped:
            return []
        remaining = [n for n in self.order if n not in self._sent]
        if not remaining:
            return []
        self._sent.add(remaining[0])
        cmds: list[Command] = [Send(remaining[0], self.req)]
        if len(remaining) > 1:
            cmds.append(Wake(now + self.delta))
        return cmds

    def record(self, node: int, result: Response) -> None:
        self.replies[node] = result

    def stop(self) -> None:
        self._stopped = True


# --------------------------------------------------------------------------- #
# Commit — classic two-phase per-slot Paxos (PROTOCOL §1.3, rev 5)             #
# --------------------------------------------------------------------------- #


class _Phase(Enum):
    PREPARE = auto()
    FETCH = auto()
    ACCEPT = auto()
    DONE = auto()


class Commit:
    """Drives one slotted op to a QC. rev 5 (NOTES item 21): no fast path — every
    slotted decision is two-phase Paxos, so exactly one op is ever decided per
    slot (cross-ballot B1, unconditional). PREPARE at ballot (round≥1, client_fp);
    from a quorum of promises MUST re-propose the highest accepted op reported —
    even a rival's (PROTOCOL §1.3 step 5) — fetch it if unheld, ACCEPT, assemble
    the QC. Terminates in Committed (own op), LostSlot (rival decided), or
    Failed. Two round trips is the accepted price of ultra-durability."""

    def __init__(self, cfg: QuorumConfig, op: Op):
        assert op.slot_tag is not None, "Commit is for slotted ops (blind writes race no slot)"
        self.cfg = cfg
        self.op = op
        self.tag: bytes = op.slot_tag
        self.phase = _Phase.PREPARE
        self.round = 0  # _begin_prepare bumps to 1 on start
        self.ballot = Ballot(1, cfg.client_fp)  # replaced on every _begin_prepare
        self.chosen: Op = op  # op to (re-)propose in ACCEPT
        self.fetch_hash: bytes = b""
        self._fan: _Fanout | None = None
        self._receipts: dict[int, Receipt] = {}  # for the current ballot/op
        self._blocked: set[int] = set()  # nodes that can't receipt this ballot
        self._promises: dict[int, Promise] = {}
        self._nacked: set[int] = set()

    # ---- driver interface ------------------------------------------------- #
    def start(self, now: int) -> list[Command]:
        return self._begin_prepare(now)

    def feed(self, ev: Event) -> list[Command]:
        if self.phase is _Phase.DONE:
            return []
        match ev:
            case Tick(now):
                return self._fan.on_tick(now) if self._fan else []
            case Reply(node, _, result, now):
                if self._fan is not None:
                    self._fan.record(node, result)
                return self._on_reply(node, result, now)

    # ---- phase transitions ------------------------------------------------ #
    def _begin_prepare(self, now: int) -> list[Command]:
        self.phase = _Phase.PREPARE
        self._promises.clear()
        self._nacked.clear()
        self.round += 1
        self.ballot = Ballot(self.round, self.cfg.client_fp)
        self._fan = _Fanout(
            list(range(self.cfg.n)),
            PrepareReq(self.tag, self.ballot),
            self.cfg.delta_hedge_ms,
            self.cfg.quorum,
        )
        return self._fan.start(now)

    def _begin_accept(self, now: int) -> list[Command]:
        self.phase = _Phase.ACCEPT
        self._receipts.clear()
        self._blocked.clear()
        self._fan = _Fanout(
            list(range(self.cfg.n)),
            AcceptReq(self.tag, self.ballot, self.chosen),
            self.cfg.delta_hedge_ms,
            self.cfg.quorum,
        )
        return self._fan.start(now)

    def _finish(self, outcome: CommitOutcome) -> list[Command]:
        self.phase = _Phase.DONE
        if self._fan:
            self._fan.stop()
        return [Done(outcome)]

    # ---- reply handling per phase ----------------------------------------- #
    def _on_reply(self, node: int, result: Response, now: int) -> list[Command]:
        match self.phase:
            case _Phase.PREPARE:
                return self._on_prepare_reply(node, result, now)
            case _Phase.FETCH:
                return self._on_fetch_reply(result, now)
            case _Phase.ACCEPT:
                return self._on_accept_reply(node, result, now)
            case _:
                return []

    def _on_prepare_reply(self, node: int, result: Response, now: int) -> list[Command]:
        if isinstance(result, Promise):
            if result.verify() and result.signer == self.cfg.roster[node]:
                self._promises[node] = result
                if len(self._promises) >= self.cfg.quorum:
                    return self._choose_and_accept(now)
        elif isinstance(result, Nack):
            self._nacked.add(node)
            return self._maybe_reprepare(result.promised, now)
        return []

    def _choose_and_accept(self, now: int) -> list[Command]:
        # MUST re-propose the accepted op with the highest ballot, if any
        # (PROTOCOL §1.3 step 5) — even a rival's.
        best: tuple[Ballot, bytes] | None = None
        for p in self._promises.values():
            if p.accepted_op_hash is not None and p.accepted_ballot is not None:
                if best is None or p.accepted_ballot > best[0]:
                    best = (p.accepted_ballot, p.accepted_op_hash)
        if best is None or best[1] == self.op.op_hash:
            self.chosen = self.op
            return self._begin_accept(now)
        # a rival's op is highest — fetch its envelope from a promiser, then ACCEPT it
        self.phase = _Phase.FETCH
        self.fetch_hash = best[1]
        self._fan = None
        holder = next(n for n, p in self._promises.items() if p.accepted_op_hash == best[1])
        return [Send(holder, FetchOpReq(best[1]))]

    def _on_fetch_reply(self, result: Response, now: int) -> list[Command]:
        if (
            isinstance(result, Op)
            and result.op_hash == self.fetch_hash
            and result.slot_tag == self.tag
            and result.verify_sig(result.author)
        ):
            self.chosen = result
            return self._begin_accept(now)
        return self._finish(Failed(CommitFailure.EXHAUSTED))

    def _on_accept_reply(self, node: int, result: Response, now: int) -> list[Command]:
        if self._is_receipt(result, node, self.chosen.op_hash, self.ballot):
            self._receipts[node] = result
            if len(self._receipts) >= self.cfg.quorum:
                qc = self._assemble()
                if self.chosen.op_hash == self.op.op_hash:
                    return self._finish(Committed(qc))
                return self._finish(LostSlot(self.chosen.op_hash, qc))
        elif isinstance(result, Nack):
            self._blocked.add(node)
            return self._maybe_reprepare(result.promised, now)
        return []

    def _maybe_reprepare(self, promised: Ballot, now: int) -> list[Command]:
        """A Nack means a higher ballot was promised; jump above it and re-prepare
        — unless a quorum is already unreachable this round or rounds are spent."""
        blocked = self._nacked if self.phase is _Phase.PREPARE else self._blocked
        if self.cfg.n - len(blocked) >= self.cfg.quorum:
            return []  # can still reach quorum at the current ballot
        if self.round >= self.cfg.max_rounds:
            return self._finish(Failed(CommitFailure.EXHAUSTED))
        if promised.round >= self.round:
            self.round = promised.round  # _begin_prepare bumps to promised.round + 1
        return self._begin_prepare(now)

    # ---- helpers ---------------------------------------------------------- #
    def _is_receipt(
        self, r: Response, node: int, op_hash: bytes, ballot: Ballot
    ) -> TypeGuard[Receipt]:
        return (
            isinstance(r, Receipt)
            and r.op_hash == op_hash
            and r.ballot == ballot
            and r.config_epoch == self.cfg.epoch
            and r.signer == self.cfg.roster[node]
            and r.verify()
        )

    def _assemble(self) -> QC:
        return QC.assemble(list(self._receipts.values()), self.cfg.n, self.cfg.roster_index)


# --------------------------------------------------------------------------- #
# Finalize — poll WATERMARK until a quorum attests floors ≥ target (§9)        #
# --------------------------------------------------------------------------- #


class Finalize:
    """Drives an hlc to finality. Commitment (a QC) means *durable*; finality
    means *its verdict can never change* — reached when a quorum of nodes attest
    a monotone floor ≥ the target (DESIGN §9, PROTOCOL §1.4 step 4). Floors rise
    in real time (`floor = max(hw, now) − δ`), so this re-polls the nodes still
    below target every `finality_poll_ms` until the quorum forms or polls run
    out. Terminates in Final (the proof) or Failed(EXHAUSTED)."""

    def __init__(self, cfg: QuorumConfig, target: HLC):
        self.cfg = cfg
        self.target = target
        self._wms: dict[int, Watermark] = {}  # node -> its highest attested floor
        self.polls = 0
        self._done = False

    def start(self, now: int) -> list[Command]:
        return self._poll(now, first=True)

    def feed(self, ev: Event) -> list[Command]:
        if self._done:
            return []
        match ev:
            case Reply(node, _, result, _):
                return self._on_watermark(node, result)
            case Tick(now):
                if self.polls >= self.cfg.max_polls:
                    return self._finish(Failed(CommitFailure.EXHAUSTED))
                return self._poll(now, first=False)

    def _poll(self, now: int, *, first: bool) -> list[Command]:
        self.polls += 1
        # (re-)ask every node not yet attesting ≥ target — floors only rise, so a
        # node already at/above target needs no further polling.
        targets = [
            n
            for n in range(self.cfg.n)
            if first or n not in self._wms or self._wms[n].floor < self.target
        ]
        cmds: list[Command] = [Send(n, WatermarkReq()) for n in targets]
        cmds.append(Wake(now + self.cfg.finality_poll_ms))
        return cmds

    def _on_watermark(self, node: int, result: Response) -> list[Command]:
        if (
            isinstance(result, Watermark)
            and result.config_epoch == self.cfg.epoch
            and result.signer == self.cfg.roster[node]
            and result.verify()
        ):
            prev = self._wms.get(node)
            if prev is None or prev.floor < result.floor:  # keep the highest (monotone)
                self._wms[node] = result
        frontier = self._quorum_frontier()
        if frontier is not None and self.target <= frontier:
            proof = tuple(wm for wm in self._wms.values() if frontier <= wm.floor)
            return self._finish(Final(frontier, proof))
        return []

    def _finish(self, outcome: FinalizeOutcome) -> list[Command]:
        self._done = True
        return [Done(outcome)]

    def _quorum_frontier(self) -> HLC | None:
        """The highest hlc a quorum currently attests: the q-th largest floor
        (None until a quorum of nodes have answered at all)."""
        if len(self._wms) < self.cfg.quorum:
            return None
        floors = sorted((wm.floor for wm in self._wms.values()), reverse=True)
        return floors[self.cfg.quorum - 1]
