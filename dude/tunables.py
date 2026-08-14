"""Every deployment-global dial. Four physical measurements, three resilience counts, some
protocol counts -- everything else derives, `block_time` above all: raise a measurement or a
count and the block time moves in step.
"""

from __future__ import annotations

from dataclasses import dataclass

from .core.errors import InvariantError
from .core.units import Bucket, Millis


@dataclass(frozen=True, slots=True)
class LinkTunables:
    """One link's dials. Built by `Tunables.link_tunables`; never declared."""

    rto_floor: Millis
    rto_initial: Millis
    granularity: Millis
    breaker_threshold: int
    breaker_cooldown: Millis
    budget_max_tokens: int
    budget_token_ratio: int


@dataclass(frozen=True, slots=True)
class Tunables:
    # DECLARED. Every field here is a physical measurement, a product decision, or a count.
    # Arithmetic over them belongs below as a property.

    rtt_max: Millis = 2_000
    """Maximum physical link round-trip time this deployment tolerates. The wire, nothing else --
    not "one wave" or "reaching quorum", just one send and one reply on one link."""

    clock_skew: Millis = 2_000
    """Upper bound on NTP jitter between roster members. Every node runs NTP."""

    client_clock_tolerance: Millis = 25_000
    """Clients are not NTP-disciplined; nodes are. Collapsing the two would either refuse honest
    clients or widen the replay window for everyone."""

    granularity: Millis = 1

    retry_budget: int = 2
    """Attempts per sub-round before a peer is lost for that sub-round. Tied to link redundancy:
    2 links per peer -> 2 attempts."""

    held_convergence_max: int = 3
    """Maximum HELD/BODIES sub-rounds a wave accepts. Steady state converges in 1-2; partition
    or asymmetric client load can take more."""

    safety_margin: int = 2
    """`block_time = safety_margin * block_time_floor`. Slack above the coherent minimum."""

    windows_to_settle: int = 2
    """Collect in W, apply in W+1."""

    ticks_per_cadence: int = 10

    pull_batch: int = 32
    """Message-size bound, not a rate."""

    max_attempts: int = 8
    """Hard cap on total retransmit attempts for one message, across its whole lifetime. Distinct
    from `retry_budget` (per sub-round)."""

    desired_links_per_peer: int = 2
    """Concurrent connections the postman maintains to each peer. Dialing is continuous: when a
    link dies, the postman re-establishes it. All live links are available for sending."""

    breaker_threshold: int = 5
    budget_max_tokens: int = 10_000
    budget_token_ratio: int = 100
    """MILLI-tokens; MUST NOT become floats. Ten additions of 0.1 sum to 0.9999999999999999,
    so a bucket refilled by exactly its ratio never reaches a whole token."""

    # DERIVED. Nothing below may be set.

    @property
    def single_wave_budget(self) -> Millis:
        return self.retry_budget * self.rtt_max

    @property
    def held_wave_budget(self) -> Millis:
        return self.held_convergence_max * self.single_wave_budget

    @property
    def block_time_floor(self) -> Millis:
        return self.held_wave_budget + 2 * self.single_wave_budget + self.clock_skew

    @property
    def block_time(self) -> Millis:
        return self.safety_margin * self.block_time_floor

    @property
    def cut_reserve(self) -> Millis:
        """Time a bucket holds back for SIG and SETTLE_SIG after HELD closes."""
        return 2 * self.single_wave_budget

    @property
    def admission_floor(self) -> Millis:
        return self.client_clock_tolerance + 2 * self.rtt_max

    @property
    def w_admit(self) -> Millis:
        """How stale a client's own timestamp may be at the door."""
        return self.admission_floor

    @property
    def endorse_margin(self) -> Millis:
        return self.windows_to_settle * self.block_time + self.clock_skew

    @property
    def w_valid_margin(self) -> Millis:
        return self.endorse_margin

    @property
    def w_valid(self) -> Millis:
        return self.w_admit + self.w_valid_margin

    @property
    def evict_after(self) -> Millis:
        """Nothing held past the point it could still settle."""
        return self.w_valid

    @property
    def ttl_round(self) -> Millis:
        """HELD/SIG/SETTLE_SIG. Dies when its bucket settles."""
        return self.endorse_margin

    @property
    def ttl_exchange(self) -> Millis:
        """One request, one answer: height polls, block pulls, node replies."""
        return self.block_time_floor

    @property
    def ttl_lite(self) -> Millis:
        """A light client's answer carries a head; a late reply is a NEW question next block."""
        return self.block_time + self.clock_skew

    @property
    def ttl_longest(self) -> Millis:
        """Named once: two consumers, one answer, a second spelling would eventually disagree."""
        return max(self.ttl_round, self.ttl_exchange, self.ttl_lite)

    @property
    def window(self) -> Millis:
        """How old an envelope may be and still be accepted. Forced by the longest ttl: the
        mailbox retransmits the same envelope with its original timestamp until the deadline,
        so anything shorter refuses live retries at the receiver."""
        return self.ttl_longest + self.clock_skew

    @property
    def poll_interval(self) -> Millis:
        """Nothing polls faster than the thing it observes changes."""
        return self.block_time

    @property
    def freshness_window(self) -> Millis:
        """How long a height report is worth believing. A peer answering every poll is never
        mistaken for a silent one."""
        return self.poll_interval + self.rtt_max + self.clock_skew

    @property
    def pull_timeout(self) -> Millis:
        return self.block_time_floor

    @property
    def liveness_window(self) -> int:
        """Headers per reply -- a lagging client's catch-up horizon."""
        return self.windows_to_settle

    @property
    def backoff_base(self) -> Millis:
        """Retry no faster than one wave: sooner is a second copy in flight, not a retry."""
        return self.rtt_max

    @property
    def backoff_cap(self) -> Millis:
        return self.ttl_longest

    @property
    def stagger_cap(self) -> Millis:
        return self.rtt_max

    @property
    def tick_interval(self) -> Millis:
        """Sampled against `cut_reserve`, the tightest deadline the loop must not overshoot."""
        return max(1, self.cut_reserve // self.ticks_per_cadence)

    @property
    def breaker_cooldown(self) -> Millis:
        """A breaker cannot hold a link out across the bucket that needed it."""
        return self.block_time_floor

    @property
    def expected_rtt(self) -> Millis:
        """RTO prior for a link with no Estimator sample yet. Consumers: `Peer.usable` sort
        tiebreak, `Plan.stagger`."""
        return self.rtt_max

    @property
    def link_tunables(self) -> LinkTunables:
        return LinkTunables(
            rto_floor=2 * self.granularity,
            rto_initial=self.expected_rtt,
            granularity=self.granularity,
            breaker_threshold=self.breaker_threshold,
            breaker_cooldown=self.breaker_cooldown,
            budget_max_tokens=self.budget_max_tokens,
            budget_token_ratio=self.budget_token_ratio,
        )

    def skew_buckets(self) -> int:
        """Clock skew in buckets -- freshness tolerance against a peer whose clock lags."""
        return -(-self.clock_skew // self.block_time)

    def bucket(self, ts: Millis) -> Bucket:
        return ts // self.block_time

    def bucket_start(self, b: Bucket) -> Millis:
        return b * self.block_time

    def __post_init__(self) -> None:
        for what, count in (
            ("retry_budget", self.retry_budget),
            ("held_convergence_max", self.held_convergence_max),
            ("safety_margin", self.safety_margin),
            ("windows_to_settle", self.windows_to_settle),
            ("ticks_per_cadence", self.ticks_per_cadence),
            ("pull_batch", self.pull_batch),
            ("max_attempts", self.max_attempts),
            ("desired_links_per_peer", self.desired_links_per_peer),
        ):
            if count < 1:
                raise InvariantError(f"{what} is {count}; a count below 1 disables the mechanism")


DEFAULT = Tunables()
