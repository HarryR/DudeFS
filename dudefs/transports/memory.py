# DudeFS — the in-memory fault-injecting carrier + a single-machine driver.
#
# IMPLEMENTATION §4 (transports/memory.py, "first!") / §6 (sim seam).
#
# This is the FIRST thing that executes a sans-io quorum machine against real
# nodes over a *network* — a simulated one. Three pieces, all deterministic
# under a seeded `random.Random`:
#
#   * `Scheduler`  — a discrete-event clock: a time-ordered heap of callbacks.
#                    `now` only moves forward; ties break by insertion order, so
#                    a seed fully determines the run (failures replay, §6).
#   * `MemoryTransport` — carries a request to a node and its reply back, each
#                    hop independently subject to loss / duplication / delay.
#                    Reorder is emergent: per-message jitter reorders delivery.
#   * `drive`      — runs ONE machine (Commit/Finalize) to its outcome. The
#                    sans-io machine owns *protocol* (which node, when — hedging);
#                    the driver owns *reliability* (retransmit un-acked Sends
#                    until a reply or a deadline — sound because every node verb
#                    is idempotent, PROTOCOL §0).
#
# The node's own clock reads `Scheduler.now` (nodes act at message-arrival time),
# so floors advance in real simulated time and finality is reachable.

from __future__ import annotations

import heapq
import random
from collections.abc import Callable, Sequence
from dataclasses import dataclass
from typing import Protocol

from ..node import NodeAPI, Request, Response, dispatch
from ..quorum import Command, Done, Event, Reply, Send, Tick, Wake

# --------------------------------------------------------------------------- #
# Scheduler — a seeded discrete-event clock                                    #
# --------------------------------------------------------------------------- #


class Scheduler:
    """A time-ordered callback queue. `now` is simulated milliseconds; it jumps
    to each event's time as it fires and never goes backward. Deterministic:
    (time, insertion-seq) totally orders events, so one seed = one run."""

    def __init__(self):
        self.now = 0
        self._heap: list[tuple[int, int, Callable[[], None]]] = []
        self._seq = 0

    def at(self, when_ms: int, cb: Callable[[], None]) -> None:
        heapq.heappush(self._heap, (max(when_ms, self.now), self._seq, cb))
        self._seq += 1

    def after(self, delay_ms: int, cb: Callable[[], None]) -> None:
        self.at(self.now + delay_ms, cb)

    def step(self) -> bool:
        """Fire the earliest pending event. Returns False when the queue drains."""
        if not self._heap:
            return False
        when, _, cb = heapq.heappop(self._heap)
        self.now = when
        cb()
        return True

    def run(self, until_ms: int) -> None:
        while self._heap and self._heap[0][0] <= until_ms:
            self.step()


# --------------------------------------------------------------------------- #
# Fault model                                                                  #
# --------------------------------------------------------------------------- #


@dataclass(frozen=True)
class Faults:
    """Per-message-hop fault probabilities and a delay window. `reorder` is not
    a knob — it is the emergent consequence of `delay_hi > delay_lo` (two
    messages sent together arrive in jittered order)."""

    loss: float = 0.0  # P(drop this hop)
    dup: float = 0.0  # P(deliver a second copy)
    delay_lo: int = 1  # min hop latency (ms); ≥1 so time always advances
    delay_hi: int = 3  # max hop latency (ms)

    def __post_init__(self) -> None:
        assert self.delay_lo >= 1, "hop delay must be ≥1 so simulated time advances"
        assert self.delay_lo <= self.delay_hi


type OnReply = Callable[[int, Request, Response], None]


class MemoryTransport:
    """Carries requests to nodes and replies back, each hop independently faulted.
    A node processes a request at its *arrival* time (its clock is the shared
    scheduler), then the reply is carried back under the same fault model."""

    def __init__(
        self, sched: Scheduler, nodes: Sequence[NodeAPI], faults: Faults, rng: random.Random
    ):
        self.sched = sched
        self.nodes = nodes
        self.faults = faults
        self.rng = rng
        self.sent = 0  # messages handed to the carrier (incl. retransmits)
        self.dropped = 0

    def send(self, node: int, req: Request, on_reply: OnReply) -> None:
        self.sent += 1
        self._hop(lambda: self._deliver(node, req, on_reply))

    def _hop(self, deliver: Callable[[], None]) -> None:
        """Schedule one network hop: maybe drop, maybe duplicate, always delayed."""
        if self.rng.random() < self.faults.loss:
            self.dropped += 1
            return
        self.sched.after(self.rng.randint(self.faults.delay_lo, self.faults.delay_hi), deliver)
        if self.rng.random() < self.faults.dup:
            self.sched.after(self.rng.randint(self.faults.delay_lo, self.faults.delay_hi), deliver)

    def _deliver(self, node: int, req: Request, on_reply: OnReply) -> None:
        result = dispatch(self.nodes[node], req)  # node acts at arrival time
        self._hop(lambda: on_reply(node, req, result))  # carry the reply back


# --------------------------------------------------------------------------- #
# drive — run one sans-io machine to its outcome over a transport              #
# --------------------------------------------------------------------------- #


class Machine(Protocol):
    def start(self, now: int) -> list[Command]: ...
    def feed(self, ev: Event) -> list[Command]: ...


type Observer = Callable[[str, int, Request, Response], None]


class ClientRunner:
    """Pumps ONE sans-io machine over the transport, registering its callbacks on
    the shared scheduler — but NOT owning the run loop, so many runners interleave
    on one clock (the sim composition, IMPLEMENTATION §6). Sends are retransmitted
    to still-unanswered nodes every `retransmit_ms`: the reliability layer that
    lets a Commit survive message loss without the pure machine knowing there is
    a network (node verbs are idempotent, PROTOCOL §0). An optional `observer`
    sees every reply (the trace seam)."""

    def __init__(
        self,
        machine: Machine,
        transport: MemoryTransport,
        sched: Scheduler,
        *,
        retransmit_ms: int = 40,
        deadline_ms: int = 100_000,
        observer: Observer | None = None,
    ):
        self.machine = machine
        self.transport = transport
        self.sched = sched
        self.retransmit_ms = retransmit_ms
        self.deadline_ms = deadline_ms
        self.observer = observer
        self.done = False
        self.outcome: object = None
        self._outstanding: dict[int, Request] = {}  # node -> latest un-acked req

    def launch(self) -> None:
        self._run(self.machine.start(self.sched.now))
        self.sched.after(self.retransmit_ms, self._retransmit)

    def _run(self, cmds: list[Command]) -> None:
        for c in cmds:
            match c:
                case Done(outcome):
                    self.done, self.outcome = True, outcome
                case Wake(at_ms):
                    self.sched.at(at_ms, self._on_tick)
                case Send(node, req):
                    self._outstanding[node] = req
                    self.transport.send(node, req, self._on_reply)

    def _on_reply(self, node: int, req: Request, result: Response) -> None:
        if self.done:
            return
        if self.observer is not None:
            self.observer("reply", node, req, result)
        self._outstanding.pop(node, None)
        self._run(self.machine.feed(Reply(node, req, result, self.sched.now)))

    def _on_tick(self) -> None:
        if self.done:
            return
        self._run(self.machine.feed(Tick(self.sched.now)))

    def _retransmit(self) -> None:
        if self.done or self.sched.now >= self.deadline_ms:
            return
        for node, req in list(self._outstanding.items()):
            self.transport.send(node, req, self._on_reply)
        self.sched.after(self.retransmit_ms, self._retransmit)


def drive(
    machine: Machine,
    transport: MemoryTransport,
    sched: Scheduler,
    *,
    retransmit_ms: int = 40,
    deadline_ms: int = 100_000,
) -> object:
    """Run a single machine to its outcome (or None on deadline) — a ClientRunner
    plus the run loop. The sim launches many runners and owns the loop itself."""
    runner = ClientRunner(
        machine, transport, sched, retransmit_ms=retransmit_ms, deadline_ms=deadline_ms
    )
    runner.launch()
    while not runner.done and sched.step():
        if sched.now > deadline_ms:
            break
    return runner.outcome
