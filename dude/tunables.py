from __future__ import annotations

from dataclasses import dataclass, field

from .consensus.mempool import Tunables as MempoolTunables
from .core.errors import InvariantError
from .core.units import Millis
from .net.link import LinkTunables
from .net.plan import PlanTunables


@dataclass(frozen=True, slots=True)
class TimingTunables:
    """Adding a field here MUST be a decision: everything else is derived from these, and
    declaring an answer is how a derivation gets bypassed silently.
    `test_declared_quantities_and_nothing_else` is what forces the decision.

    THE GLOBAL CLOCK IS LOAD-BEARING. Every node and client runs NTP; `clock_skew` is the
    assumed bound. Buckets are `floor(t/delta)` so agreement needs no coordination, and freshness
    is a WALL-CLOCK bound -- an old quorum-signed block verifies perfectly, so the clock is the
    only local oracle for currency."""

    rtt_max: Millis = 300
    """One wave, PROCESSING INCLUDED: getting a message to every peer and handling what comes
    back. Measured per deployment, so roster size shows up here."""

    clock_skew: Millis = 250

    client_clock_tolerance: Millis = 25_000

    waves_per_round: int = 3
    """HELD, SIG, SETTLE_SIG -- all three inside the round's own window."""

    windows_to_settle: int = 2
    """Collect in W, agree and apply in W+1. Counts WINDOWS; `waves_per_round` counts round
    trips. Two counters, two units."""

    ticks_per_cadence: int = 10

    @property
    def dissemination(self) -> Millis:
        return self.waves_per_round * self.rtt_max + self.clock_skew

    @property
    def conversation_floor(self) -> Millis:
        return self.clock_skew + self.rtt_max

    @property
    def cut_reserve(self) -> Millis:
        """What a window keeps back for the waves after phase 2: the SIG that cuts the slice and
        the SETTLE_SIG that agrees the anchors. Phase 2 gets the remainder."""
        return (self.waves_per_round - 1) * self.rtt_max

    @property
    def admission_floor(self) -> Millis:
        return self.client_clock_tolerance + 2 * self.rtt_max

    def skew_buckets(self, bucket_width: Millis) -> int:
        """Clock skew expressed in buckets: the tolerance on freshness, since a peer whose clock
        sits behind ours reports a head we would otherwise call stale."""
        return -(-self.clock_skew // bucket_width)

    def endorse_margin(self, bucket_width: Millis) -> Millis:
        return self.windows_to_settle * bucket_width + self.clock_skew


@dataclass(frozen=True, slots=True)
class NetTunables:
    window: Millis = 5_000

    ttl: Millis = 10_000


@dataclass(frozen=True, slots=True)
class SyncTunables:
    poll_interval: Millis = 1_000

    pull_timeout: Millis = 3_000

    freshness_window: Millis = 5_000

    pull_batch: int = 32
    """Blocks one GETBLOCK may carry. A message-size bound, not a rate: it trades reply size
    against round trips, and the server caps at its own value regardless of what is asked."""


@dataclass(frozen=True, slots=True)
class LightClientTunables:
    liveness_window: int = 2
    """How many headers a reply will carry. A MESSAGE-SIZE bound, not a trust one -- whether a
    head is current is `chain.is_stale`, judged by the client against its own clock, because a
    responder cannot be asked to certify its own freshness."""


@dataclass(frozen=True, slots=True)
class Tunables:
    timing: TimingTunables = field(default_factory=TimingTunables)
    net: NetTunables = field(default_factory=NetTunables)
    link: LinkTunables = field(default_factory=LinkTunables)
    plan: PlanTunables = field(default_factory=PlanTunables)
    mempool: MempoolTunables = field(default_factory=MempoolTunables)
    sync: SyncTunables = field(default_factory=SyncTunables)
    light_client: LightClientTunables = field(default_factory=LightClientTunables)

    def __post_init__(self) -> None:
        t = self.timing
        for what, value, floor in (
            ("mempool.delta", self.mempool.delta, t.dissemination),
            ("net.window", self.net.window, t.conversation_floor),
            ("mempool.w_admit", self.mempool.w_admit, t.admission_floor),
            (
                "mempool.w_valid_margin",
                self.mempool.w_valid_margin,
                t.endorse_margin(self.mempool.delta),
            ),
            ("sync.poll_interval", self.sync.poll_interval, t.conversation_floor),
            ("sync.pull_timeout", self.sync.pull_timeout, t.dissemination),
            ("sync.freshness_window", self.sync.freshness_window, self.sync.poll_interval),
        ):
            if value < floor:
                raise InvariantError(f"{what} is {value}ms, below its derived floor of {floor}ms")
        if self.plan.backoff_cap > self.net.ttl:
            raise InvariantError(
                f"plan.backoff_cap ({self.plan.backoff_cap}ms) exceeds the deadline it is spent "
                f"against, net.ttl ({self.net.ttl}ms), so it can never bind before the deadline"
            )
        if self.timing.ticks_per_cadence < 1:
            raise InvariantError(
                f"timing.ticks_per_cadence ({self.timing.ticks_per_cadence}) must be >= 1; "
                f"a driver loop that doesn't tick at all cannot advance consensus"
            )

    @property
    def tick_interval(self) -> Millis:
        smallest_cadence = min(
            self.plan.backoff_base,
            self.sync.poll_interval,
            self.mempool.delta,
        )
        return max(self.link.granularity, smallest_cadence // self.timing.ticks_per_cadence)


DEFAULT = Tunables()
