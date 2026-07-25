# DudeFS tests — the in-memory fault-injecting CARRIER + a seeded clock (HANDOFF-R9 §6,
# lifted out of the retired `dudefs/transports/memory.py`). This is the ONLY simulated
# thing under `StepDriver`: it moves a request to a node and its reply back, each hop
# independently subject to loss / duplication / delay / partition, all deterministic
# under a seeded `random.Random` (failures replay). The machine (Commit/Finalize) and
# the nodes (Acceptor) it carries between are production; the driver that pumps them is
# `tests/_drive.py`. The old module also held a `ClientRunner`/`drive` that RETRANSMITTED
# un-acked Sends — a reliability layer production never had; that is gone, replaced by
# `_drive._Pump` (escalation-only, production-faithful).

from __future__ import annotations

import heapq
import random
from collections.abc import Callable, Sequence
from dataclasses import dataclass
from typing import Protocol

from dudefs import tunables
from dudefs.node import NodeAPI, Request, Response, dispatch

# --------------------------------------------------------------------------- #
# Scheduler — a seeded discrete-event clock                                    #
# --------------------------------------------------------------------------- #


class Scheduler:
    """A time-ordered callback queue. `now` is simulated milliseconds; it jumps to each
    event's time as it fires and never goes backward. Deterministic: (time, insertion-
    seq) totally orders events, so one seed = one run."""

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
    """Per-message-hop fault probabilities and a delay window. `reorder` is not a knob —
    it is the emergent consequence of `delay_hi > delay_lo` (two messages sent together
    arrive in jittered order)."""

    loss: float = 0.0  # P(drop this hop)
    dup: float = 0.0  # P(deliver a second copy)
    delay_lo: int = tunables.SIM_DELAY_LO_MS  # min hop latency; ≥1 so time always advances
    delay_hi: int = tunables.SIM_DELAY_HI_MS  # max hop latency (reorder from the spread)

    def __post_init__(self) -> None:
        assert self.delay_lo >= 1, "hop delay must be ≥1 so simulated time advances"
        assert self.delay_lo <= self.delay_hi


# The client endpoint id — the external source of a Commit/Finalize's Sends. Node
# endpoints are their roster indices (0..n-1); links are DIRECTED (src, dst).
CLIENT = -1


@dataclass
class Link:
    """Directed-link fault params (src → dst), the per-link generalization of Faults.
    Latency = `base_ms + U(0, jitter_ms)`, with a rare heavy-tail spike (×`spike_mult`
    at prob `spike_p`) — a slow-not-failed node the hedge must mask. Loss/dup are
    per-link; burst loss rides a two-state Gilbert-Elliott model (good↔bad), so drops
    cluster instead of being independent."""

    base_ms: int = tunables.SIM_ONE_WAY_LATENCY_MS
    jitter_ms: int = 1
    loss: float = 0.0
    dup: float = 0.0
    spike_p: float = 0.0
    spike_mult: int = 100
    # Gilbert-Elliott burst loss: while "bad", loss is `bad_loss`; transitions per hop
    # are P(good→bad)=`p_bad`, P(bad→good)=`p_good`. p_bad=0 ⇒ never bursts.
    bad_loss: float = 0.0
    p_bad: float = 0.0
    p_good: float = 0.0


@dataclass(frozen=True)
class HopPlan:
    """What the link model decided for one hop: deliver-or-drop, the delay, and an
    optional duplicate copy's delay (reorder is emergent from the delay spread)."""

    deliver: bool
    delay_ms: int
    dup_delay_ms: int | None = None


class LinkModel(Protocol):
    def plan(self, src: int, dst: int, rng: random.Random, now: int) -> HopPlan: ...


class UniformLinks:
    """The degenerate single-link model — one Faults for every directed hop."""

    def __init__(self, faults: Faults):
        self.f = faults

    def plan(self, src: int, dst: int, rng: random.Random, now: int) -> HopPlan:
        if rng.random() < self.f.loss:
            return HopPlan(False, 0)
        delay = rng.randint(self.f.delay_lo, self.f.delay_hi)
        dup = rng.randint(self.f.delay_lo, self.f.delay_hi) if rng.random() < self.f.dup else None
        return HopPlan(True, delay, dup)


class NetworkLinks:
    """A per-directed-link fault model with partitions. `default` covers any hop without
    an override; `overrides[(src, dst)]` asymmetrizes a directed link. `down` is the set
    of DIRECTED links currently cut — one-way links are a link down in a single
    direction; flapping is a test toggling this set on scheduler callbacks. Gilbert-
    Elliott burst state is per directed link."""

    def __init__(
        self,
        default: Link | None = None,
        overrides: dict[tuple[int, int], Link] | None = None,
        down: set[tuple[int, int]] | None = None,
    ):
        self.default = default or Link()
        self.overrides = overrides or {}
        self.down = down if down is not None else set()
        self._bad: dict[tuple[int, int], bool] = {}  # GE state per directed link

    def cut(self, src: int, dst: int, *, both: bool = True) -> None:
        self.down.add((src, dst))
        if both:
            self.down.add((dst, src))

    def heal(self, src: int, dst: int, *, both: bool = True) -> None:
        self.down.discard((src, dst))
        if both:
            self.down.discard((dst, src))

    def plan(self, src: int, dst: int, rng: random.Random, now: int) -> HopPlan:
        if (src, dst) in self.down:
            return HopPlan(False, 0)  # partitioned this direction
        link = self.overrides.get((src, dst), self.default)
        if self._lost(src, dst, link, rng):
            return HopPlan(False, 0)
        delay = link.base_ms + rng.randint(0, link.jitter_ms)
        if link.spike_p and rng.random() < link.spike_p:
            delay *= link.spike_mult  # heavy-tail spike: slow, not failed
        dup_delay = None
        if link.dup and rng.random() < link.dup:
            dup_delay = link.base_ms + rng.randint(0, link.jitter_ms)
        return HopPlan(True, max(1, delay), dup_delay)

    def _lost(self, src: int, dst: int, link: Link, rng: random.Random) -> bool:
        key = (src, dst)
        if link.p_bad or link.p_good:  # Gilbert-Elliott: advance the burst state
            bad = self._bad.get(key, False)
            bad = rng.random() >= link.p_good if bad else rng.random() < link.p_bad
            self._bad[key] = bad
            if bad:
                return rng.random() < link.bad_loss
        return rng.random() < link.loss


type OnReply = Callable[[int, Request, Response], None]


class MemoryTransport:
    """Carries requests to nodes and replies back, each hop independently faulted. A node
    processes a request at its *arrival* time (its clock is the shared scheduler), then
    the reply is carried back under the same fault model."""

    def __init__(
        self,
        sched: Scheduler,
        nodes: Sequence[NodeAPI],
        faults: Faults | None = None,
        rng: random.Random | None = None,
        *,
        links: LinkModel | None = None,
    ):
        self.sched = sched
        self.nodes = nodes
        # `links` is the per-link model; a bare Faults is the uniform degenerate case.
        self.links: LinkModel = links or UniformLinks(faults or Faults())
        self.rng = rng or random.Random(0)
        self.sent = 0  # messages handed to the carrier
        self.dropped = 0

    def send(self, node: int, req: Request, on_reply: OnReply, src: int = CLIENT) -> None:
        """Carry `req` from `src` to node `dst`, then its reply back. Each hop is an
        independent directed link (src→dst forward, dst→src return), so partitions and
        asymmetry apply per direction."""
        self.sent += 1
        self._hop(src, node, lambda: self._deliver(src, node, req, on_reply))

    def _hop(self, src: int, dst: int, deliver: Callable[[], None]) -> None:
        """Schedule one directed network hop per the link model: maybe drop, maybe
        duplicate, always delayed (reorder emerges from the delay spread)."""
        plan = self.links.plan(src, dst, self.rng, self.sched.now)
        if not plan.deliver:
            self.dropped += 1
            return
        self.sched.after(plan.delay_ms, deliver)
        if plan.dup_delay_ms is not None:
            self.sched.after(plan.dup_delay_ms, deliver)

    def _deliver(self, src: int, dst: int, req: Request, on_reply: OnReply) -> None:
        result = dispatch(self.nodes[dst], req)  # node acts at arrival time
        self._hop(dst, src, lambda: on_reply(dst, req, result))  # reply hop dst→src
