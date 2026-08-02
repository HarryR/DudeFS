# dude.tunables — every dial, and the quantities they are derived from.
#
# THE RULING THIS FILE SERVES [H]: *"having any tunables deep within code is just going to linger."*
# And: *"they need to be derived from first principles values, not just set to arbitrary figures...
# specified in terms of multiples of maximum tolerable network round trip time versus the quorum
# size and things like tolerable NTP lag."*
#
# ONE FILE, and it briefly was two. The declared quantities started in `core/timing.py` so each
# group's field defaults could reference them — which put `RTT_MAX` in module scope, i.e. the exact
# "dial deep in code" this file exists to prevent, and split the single surface in two. The
# resolution is that a DERIVED value is not a field default at all:
#
#   declared    `TimingTunables`, below: two measurements of a deployment, one security policy whose
#               cost is stated, and two protocol counts. Everything else is arithmetic over these.
#   per group   a module declares the shape of its own dials — it alone knows what they mean — and
#               holds plain literals, each with a docstring naming the floor it must clear.
#   enforced    `Tunables.__post_init__` checks every floor, so a misconfigured deployment CANNOT BE
#               CONSTRUCTED rather than being caught by a test that runs somewhere else.
#
# Floors rather than exact values: several dials are tolerances where generosity costs only memory
# or latency, so sitting above the floor is a margin. Where a value MUST equal its derivation it is
# a property on the group and cannot be set at all — `MempoolTunables.evict_after`.
#
# AND NOTHING HERE RE-IMPLEMENTS A SCHEDULE. A first draft of this file modelled `Plan`'s retry
# backoff in order to check it against the deadline, got the growth base wrong, ignored the jitter,
# and "found" a defect that was not there. A check that reimplements the thing it checks is a second
# representation of one fact, which is the defect it was looking for.
#
# DELIBERATELY NOT IN THE MANAGEMENT STORE YET [H]: *"as long as they're somewhere together we can
# figure out how to make them either adjustable or tunable on a per-link basis or configurable by
# the manager."* Consolidation first, distribution second. When it lands there it becomes a
# consensus-agreed value at a log position, so every node uses the same delta at the same position
# rather than each holding a local file that can silently drift.
#
# THE PER-LINK CAVEAT: a mixnet hop and a unix socket want different numbers, so `link` and `plan`
# are the groups most likely to become per-endpoint overrides. `Endpoint.options` is where such an
# override would arrive from the manager, which is why options are opaque bytes.

from __future__ import annotations

from dataclasses import dataclass, field

from .consensus.mempool import Tunables as MempoolTunables
from .core.errors import InvariantError
from .core.units import Millis
from .net.link import LinkTunables
from .net.plan import PlanTunables


@dataclass(frozen=True, slots=True)
class TimingTunables:
    """The declared quantities. Every timing floor in the system is arithmetic over these five."""

    rtt_max: Millis = 300
    """The largest round trip between two cluster members this deployment tolerates.

    Not an average and not a measurement of the current network: a bound. Cross-region links run
    150-300 ms, so a member consistently slower is out of tolerance and its links are retired by the
    breaker rather than accommodated. A mixnet deployment declares a different number and every
    floor moves with it."""

    clock_skew: Millis = 250
    """The largest disagreement tolerated between two honest NODES' clocks.

    Nodes are operated and NTP-disciplined, typically inside 50 ms; this is generous by 5x. It
    bounds everything comparing one node's timestamp against another's, and a node outside it
    degrades its own contribution — a clock fault is never convictable (#freshness-is-gathered)."""

    client_clock_tolerance: Millis = 25_000
    """How far a CLIENT's clock may be from a node's before its transactions are refused at the
    door.

    A POLICY, and the one quantity whose cost is security rather than latency: a captured signed
    transaction stays admittable for roughly this long, because the admission window is what makes
    an old transaction un-admittable. Shrinking it tightens replay and refuses clients whose clocks
    are further out; a client is not assumed to run NTP at all, which is why it is far looser than
    `clock_skew`."""

    hops_to_quorum: int = 2
    """Delivery hops from one member to a quorum: direct, plus one relay for a member it cannot
    reach. Two rather than a function of `n`, because a message reaches a quorum by direct send,
    relay or epidemic spread and correctness is path-independent. Raise it for a deeper topology."""

    waves_to_settle: int = 3
    """Message waves between a closed bucket and a settled batch: propose, endorse, count. Protocol
    shape rather than a dial — it changes only if the round changes."""

    @property
    def dissemination(self) -> Millis:
        """How long a message needs to reach a quorum, worst case."""
        return self.hops_to_quorum * self.rtt_max + self.clock_skew

    @property
    def conversation_floor(self) -> Millis:
        """Below skew plus one trip, two honest nodes cannot hold a conversation at all."""
        return self.clock_skew + self.rtt_max

    @property
    def admission_floor(self) -> Millis:
        """The client's tolerated clock error, plus its transaction's trip and the reply's. Below
        this an honest client with a merely imprecise clock is refused for being slow."""
        return self.client_clock_tolerance + 2 * self.rtt_max

    def endorse_margin(self, bucket_width: Millis) -> Millis:
        """A transaction admitted at the very edge of the window must still survive the round it was
        admitted for, so the endorsement bound needs a round's worth of room plus skew."""
        return self.waves_to_settle * bucket_width + self.clock_skew


@dataclass(frozen=True, slots=True)
class NetTunables:
    """Dials that belong to the framing layer itself rather than to a link or a message."""

    window: Millis = 5_000
    """The conversation window (`SignedEnvelope.fresh`). A PARTICIPATION gate, not a DoS filter: a
    node outside it cannot hold a conversation, and because both ends check, it self-partitions.
    Measures "are we in sync right now", so it is tight — a transaction's admission window measures
    content age instead, and is looser.

    FLOOR: `timing.conversation_floor`."""

    ttl: Millis = 10_000
    """Default deadline for a posted message: how long the mailbox keeps trying. NEVER transmitted —
    the envelope carries no TTL, because a second expiry with no consumer on the wire is exactly the
    declared-but-unwired shape.

    THE DEADLINE IS THE REAL LIMIT on retrying: `Plan.next` checks it before attempts and before
    deliverability, and clamps every wait to it, so `plan.max_attempts` is a backstop and not the
    binding constraint."""

    pull_max: int = 256
    """Entries per `ENTRIES` reply — a bound on message size, never on how far behind a joiner is.

    Here rather than as a constant in `node.py`, because a dial deep in code lingers. A SIZE bound,
    so no timing quantity derives it: the requester asks again from where it got to, which costs
    round trips and never correctness."""


@dataclass(frozen=True, slots=True)
class SyncTunables:
    """Dials for L6 sync -- the Follower's height-poll cadence and pull-timeout.

    FLOORS: `poll_interval` >= `timing.conversation_floor` (a poll IS a conversation and cannot
    be faster than the window that carries it). `pull_timeout` >= `timing.dissemination`
    (fetching a block from one peer needs at least one hop). `freshness_window` >= `poll_interval`
    (a HeightReport must survive at least one poll cycle to count toward f+1, or an honest peer
    that answered once would evaporate before the next poll)."""

    poll_interval: Millis = 1_000
    """How often to send HEIGHT to each peer. One bucket-ish so a joiner notices progress
    within one settlement cycle but the wire is not spammed."""

    pull_timeout: Millis = 3_000
    """How long to wait for a SETTLED_BLOCK reply before dropping the peer as source for this
    block and trying another. Blocks are variable size; the timeout is a floor for the smallest
    honest response, not a bound on the largest."""

    freshness_window: Millis = 5_000
    """How old a HEIGHT_REPLY may be and still count toward `caught_up()`. Beyond this, the
    peer is assumed to have moved on (or gone away) and its report is stale. Wide enough that
    ordinary poll-and-reply variance doesn't cause an honest peer to flicker in-and-out of
    the fresh set."""


@dataclass(frozen=True, slots=True)
class Tunables:
    """The one surface. Pass this down; do not reach for a group's defaults directly."""

    timing: TimingTunables = field(default_factory=TimingTunables)
    net: NetTunables = field(default_factory=NetTunables)
    link: LinkTunables = field(default_factory=LinkTunables)
    plan: PlanTunables = field(default_factory=PlanTunables)
    mempool: MempoolTunables = field(default_factory=MempoolTunables)
    sync: SyncTunables = field(default_factory=SyncTunables)

    def __post_init__(self) -> None:
        """Refuse a configuration whose dials contradict their own derivation.

        HERE RATHER THAN IN A TEST, and that is the whole point: a test proves the DEFAULT set is
        coherent, while this proves that whatever a deployment overrides is coherent too. Otherwise
        the derivation is a claim about one tuple of numbers rather than a rule.

        `InvariantError`, because a process that cannot have a coherent configuration must not run.
        It is our fault, not a peer's, so no `except DudeError` may swallow it (core/errors.py)."""
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


DEFAULT = Tunables()
"""A well-connected deployment. Named rather than inlined so a reader can see that a default was
chosen, and so a deployment overrides ONE symbol."""
