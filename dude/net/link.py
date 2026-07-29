# dude.net.link — one path to one peer, and the policies layered over it. See ../../LINKS.md.
#
# SKETCH. Not wired into `Mailbox` yet — this is the shape, to see how it smells.
#
# THE COMPOSITION [H]: a transport adapter is DUMB (it moves bytes and raises), and everything
# interesting — measurement, breaking, throttling — is a stack of small policies layered over it.
# Nothing here needs a transport to exist, and no transport needs to know any of it.
#
# The interface that makes that work is four observations, because the useful information arrives at
# four different moments and a policy that cannot see one of them cannot do its job:
#
#   before_send()  veto — the only one that can refuse
#   on_sent()      the bytes left (which implies nothing about receipt)
#   on_failed()    the transport raised
#   on_reply(rtt)  a reply came back; `rtt` is None when it is UNATTRIBUTABLE (LINKS.md §3.3)
#
# `rtt=None` is the load-bearing case, not an edge case. Under multi-homing most replies cannot be
# attributed to a transmission at all (R2, Karn), and a policy that treats "no sample" as "sample of
# zero" or ignores the callback entirely will quietly build its estimate from the traffic that
# happens to be un-retried — i.e. from the easy cases only.

from __future__ import annotations

from collections.abc import Callable
from dataclasses import dataclass, field
from enum import Enum
from typing import NamedTuple, Protocol

from ..core import crypto
from ..core.errors import DudeError
from .address import Address, Endpoint
from .envelope import Frame

type Millis = int


class LinkError(DudeError):
    """The transport could not move the bytes. The only failure a transport may report — anything
    finer is this layer's business, not the carrier's."""


class Transport(Protocol):
    """A carrier. Deliberately tiny: no retries, no timeouts, no state, no opinions.

    Everything a transport knows is "did the bytes leave". It must not retry internally, because a
    hidden retry is a transmission this layer cannot count, and an uncounted transmission breaks R2
    (the sample looks single-attempt when it was not) and R6 (the budget never sees the load)."""

    def send(self, address: Address, frame: Frame) -> None: ...


# --------------------------------------------------------------------------------------------- #
# Tunables. ONE surface per LINKS.md §5 [H] — these belong in the consolidated management-store    #
# type, and live here only until that lands. No literal in this module appears anywhere but here.  #
# --------------------------------------------------------------------------------------------- #


@dataclass(frozen=True, slots=True)
class LinkTunables:
    rto_floor: Millis = 200
    """RFC 6298 floors RTO at 1s for the internet. A unix socket is not the internet, and a floor
    that large would make a local link's timeout three orders of magnitude too slow."""
    rto_initial: Millis = 1_000
    """Before any sample exists. RFC 6298 §2.1."""
    granularity: Millis = 1
    """`G` in `RTO = SRTT + max(G, 4·RTTVAR)`."""

    breaker_threshold: int = 5
    breaker_cooldown: Millis = 5_000

    stagger_cap: Millis = 250
    """R7's Connection Attempt Delay, as a CAP rather than the value.

    RFC 8305 specifies a flat 250 ms because a browser has no RTT history for a freshly resolved
    address. We do have history, per link, so the real delay is `min(cap, best_link.rto())` —
    waiting 250 ms before trying a second address when the first is a unix socket with a 20 ms RTO
    would throw away most of what the estimator is for."""

    max_parallel: int = 2
    """How many links one message may be in flight on at once. Two is the Happy Eyeballs shape;
    every attempt beyond the first also costs a budget token, so this is an upper bound and not a
    target."""

    budget_max_tokens: int = 10_000
    budget_token_ratio: int = 100
    """The bucket in MILLI-tokens: 10_000 = gRPC's 10 tokens, 100 = its 0.1 ratio.

    Integers, not floats, and the smoke test is why: ten additions of 0.1 sum to
    0.9999999999999999, so a bucket refilled by exactly its ratio never reaches a whole token and
    retries stay refused for ever. Scaling also removes an ordering dependency that would differ
    between this and a Rust or Go port — accumulated float error is not reproducible across
    languages, and a budget that diverges by implementation is a budget nobody can reason about."""


# --------------------------------------------------------------------------------------------- #
# Policies                                                                                       #
# --------------------------------------------------------------------------------------------- #


class Refused(Enum):
    """Why a policy would not let a send happen — a CLOSED set, not a free string.

    A refusal is a decision the layer above branches on, so its domain has to be enumerable: a
    stringly-typed reason cannot be matched exhaustively, cannot be counted into a metric without
    typos, and drifts the moment two modules spell the same condition differently. `StrEnum` so it
    still reads well in a log.
    Plain `Enum`, deliberately NOT `StrEnum`: these never go on the wire, so the string would be a
    value nobody marshals, and `StrEnum` members ARE `str`s — which is how a comparison across two
    unrelated reason enums that happen to share a spelling came out True. Plain members compare
    False against each other and against bare strings, so a stray `== "guard"` fails loudly instead
    of silently passing. `StrEnum` is for values that are their own serialised form; `Scheme` and
    `Role` earn it, this does not.
    """

    INVALID = "invalid"
    """RESERVED, and never returned by this package. Declared FIRST so that a port to Go — where
    these become integers and a struct field's zero value is whatever member happens to be 0 —
    lands its zero value on a named invalid rather than on a real one. Without it, a zero-valued
    field silently means the first member: a bug that does not exist in Python and is very hard to
    see in review.

    Not dead code: it is load-bearing in the target, and Python's own `Enum(0)` has no meaning to
    guard. Treat receiving it as a decode fault."""

    CIRCUIT_OPEN = "circuit-open"
    CIRCUIT_PROBING = "circuit-probing"
    """Half-open admits exactly ONE probe; this is every other caller in the same window."""
    TRANSPORT = "transport"
    """The carrier itself failed. The only refusal not decided by a policy."""


class Policy(Protocol):
    """One concern, layered over a link. All four callbacks have defaults in practice — a policy
    implements only what it cares about.

    Parameters are POSITIONAL-ONLY: they are invoked positionally, so their names are not part
    of the contract, and an implementation may underscore the ones it ignores without breaking
    override compatibility. Without `/` a renamed parameter is an invalid override."""

    def before_send(self, now: Millis, /) -> Refused | None:
        """`None` to allow, or the reason to refuse. The only veto in the stack."""
        ...

    def on_sent(self, now: Millis, /) -> None: ...
    def on_failed(self, now: Millis, /) -> None: ...
    def on_reply(self, now: Millis, rtt: Millis | None, /) -> None: ...


class _Inert:
    """Default no-op behaviour, so each policy below states only its own concern.

    Parameters are underscore-prefixed where a policy genuinely ignores them: the signature is fixed
    by `Policy`, so an unused argument here is protocol conformance rather than the
    declared-but-unwired shape ruff's ARG family exists to catch."""

    def before_send(self, _now: Millis, /) -> Refused | None:
        return None

    def on_sent(self, _now: Millis, /) -> None: ...
    def on_failed(self, _now: Millis, /) -> None: ...
    def on_reply(self, _now: Millis, _rtt: Millis | None, /) -> None: ...


@dataclass(slots=True)
class Estimator(_Inert):
    """R2 + R3. Per-link RTT, and the timeout derived from it.

    Refuses nothing — measurement is not a gate. It exists so `rto()` can be asked."""

    t: LinkTunables = field(default_factory=LinkTunables)
    srtt: float | None = None
    rttvar: float = 0.0
    samples: int = 0
    ignored: int = 0
    """Replies that carried no usable sample. Counted rather than discarded silently: a link with
    many ignored and few samples measures itself from a biased subset, which is worth seeing."""

    def on_reply(self, _now: Millis, rtt: Millis | None, /) -> None:
        if rtt is None:  # unattributable — R2. NOT a zero, and not nothing.
            self.ignored += 1
            return
        r = float(rtt)
        if self.srtt is None:  # RFC 6298 (2.2): first sample seeds both
            self.srtt, self.rttvar = r, r / 2
        else:
            # RTTVAR first, against the OLD srtt — reversing these silently biases the variance.
            self.rttvar = 0.75 * self.rttvar + 0.25 * abs(self.srtt - r)
            self.srtt = 0.875 * self.srtt + 0.125 * r
        self.samples += 1

    def rto(self) -> Millis:
        """`SRTT + max(G, 4·RTTVAR)`, floored. Variance is what the timeout is built from — a naive
        multiple of the average behaves badly on a link with occasional long tails."""
        if self.srtt is None:
            return self.t.rto_initial
        return max(self.t.rto_floor, int(self.srtt + max(self.t.granularity, 4 * self.rttvar)))


class Breaker(Enum):
    CLOSED = "closed"
    OPEN = "open"
    HALF_OPEN = "half-open"


@dataclass(slots=True)
class CircuitBreaker(_Inert):
    """R4. A timeout is a suspicion; this is the only thing that produces a verdict."""

    t: LinkTunables = field(default_factory=LinkTunables)
    state: Breaker = Breaker.CLOSED
    consecutive: int = 0
    opened_at: Millis = 0
    probing: bool = False

    def before_send(self, now: Millis, /) -> Refused | None:
        if self.state is Breaker.CLOSED:
            return None
        if self.state is Breaker.OPEN:
            if now - self.opened_at < self.t.breaker_cooldown:
                return Refused.CIRCUIT_OPEN
            self.state, self.probing = Breaker.HALF_OPEN, False
        if self.probing:  # half-open admits EXACTLY one probe, not a trickle
            return Refused.CIRCUIT_PROBING
        self.probing = True
        return None

    def on_failed(self, now: Millis, /) -> None:
        self.consecutive += 1
        if self.state is Breaker.HALF_OPEN or self.consecutive >= self.t.breaker_threshold:
            self.state, self.opened_at, self.probing = Breaker.OPEN, now, False

    def on_reply(self, _now: Millis, _rtt: Millis | None, /) -> None:
        """A reply closes the circuit even when the sample is unattributable: liveness and
        measurability are different questions, and only one of them is Karn's business."""
        self.state, self.consecutive, self.probing = Breaker.CLOSED, 0, False


@dataclass(slots=True)
class RetryBudget(_Inert):
    """R6. A token bucket, per PEER — shared by all of that peer's links, which is why it is
    constructed once and handed to each.

    Per peer and not per link because links fail independently by design (that is what
    multi-homing is for), so a per-link budget would fight R7; and not global, or one dead peer
    starves retries to healthy ones."""

    t: LinkTunables = field(default_factory=LinkTunables)
    tokens: int = -1
    """Milli-tokens. See `LinkTunables.budget_token_ratio`."""

    _FULL = 1_000

    def __post_init__(self) -> None:
        if self.tokens < 0:
            self.tokens = self.t.budget_max_tokens

    def spend(self) -> bool:
        """Charge one retry OR one staggered attempt. Charging both is what makes R6 and R7
        interlock instead of compete: a healthy peer has a full bucket and stagger is free, and as
        it degrades the bucket collapses stagger back to serial failover — Happy Eyeballs turning
        itself off exactly when parallel dialling would be harmful, with nothing else deciding."""
        if self.tokens < self._FULL:
            return False
        self.tokens -= self._FULL
        return True

    def on_sent(self, _now: Millis, /) -> None:
        """A first attempt is free and replenishes: the budget is a RATIO of traffic, which is the
        property per-request retry limits cannot express."""
        self.tokens = min(self.t.budget_max_tokens, self.tokens + self.t.budget_token_ratio)


# --------------------------------------------------------------------------------------------- #
# The link                                                                                       #
# --------------------------------------------------------------------------------------------- #


@dataclass(slots=True)
class Link:
    """One path to one peer: `(peer, address)` plus its stack of policies.

    Keyed per `(peer, address)` and not per address because the measured quantity is end-to-end to a
    specific peer, and an address may be shared by a relay fronting several nodes. Shared, keyed per
    address, one peer's slow backend is blamed on another — a wrong measurement made silently. Not
    shared, keyed per peer, we merely keep redundant state. Asymmetric, so the safe key wins."""

    address: Address
    transport: Transport
    policies: tuple[Policy, ...] = ()

    def send(self, frame: Frame, now: Millis) -> Refused | None:
        """Attempt one transmission. Returns `None` on success, or the reason it did not happen.

        RETURNS rather than raises for a refusal, because "the circuit is open" is an ordinary
        scheduling answer the mailbox acts on, not an exceptional condition. A transport failure is
        still a failure and is reported through `on_failed`."""
        for p in self.policies:
            refusal = p.before_send(now)
            if refusal is not None:
                return refusal
        try:
            self.transport.send(self.address, frame)
        except LinkError:
            self._each("on_failed", now)
            return Refused.TRANSPORT
        self._each("on_sent", now)
        return None

    def reply(self, now: Millis, rtt: Millis | None) -> None:
        """A reply arrived on this link. `rtt=None` when unattributable (LINKS.md §3.3) — pass it
        anyway: liveness still counts even when measurement does not."""
        for p in self.policies:
            p.on_reply(now, rtt)

    def expired(self, now: Millis) -> None:
        """A deadline passed with this link named as the sole attempt. Only then is it chargeable —
        an expiry on a staggered or retried message belongs to no link, and charging it would let a
        healthy link accumulate another's failures until the breaker opened on the wrong one."""
        self._each("on_failed", now)

    def available(self, now: Millis) -> bool:
        """Would this link accept a send right now? Asked by `Peer` so an unusable link is skipped
        during selection rather than attempted and refused — a refusal costs a scheduling round."""
        return all(p.before_send(now) is None for p in self.policies)

    def find[T](self, kind: type[T]) -> T | None:
        """Reach a policy by type, for the mailbox to ask `rto()` or `spend()`."""
        for p in self.policies:
            if isinstance(p, kind):
                return p
        return None

    def _each(self, hook: str, now: Millis) -> None:
        for p in self.policies:
            getattr(p, hook)(now)


def standard(
    address: Address,
    transport: Transport,
    budget: RetryBudget,
    tunables: LinkTunables | None = None,
) -> Link:
    """The default stack. `budget` is passed in rather than built, because it is per PEER and
    therefore shared across that peer's links — the one piece of state that is deliberately not
    per-link."""
    t = tunables or LinkTunables()
    return Link(address, transport, (Estimator(t), CircuitBreaker(t), budget))


# --------------------------------------------------------------------------------------------- #
# Peer — THE multi-homing object                                                                 #
# --------------------------------------------------------------------------------------------- #


class Diff(NamedTuple):
    """What `Peer.reconfigure` changed.

    A named record rather than a bare pair: the signature used to read
    `tuple[tuple[Address, ...], ...]`, which says nothing about which side is which and lets a
    caller unpack them backwards with no error. In Rust or Go a bare pair stays equally anonymous,
    so naming it here is what makes the translation self-documenting."""

    added: tuple[Address, ...]
    removed: tuple[Address, ...]


@dataclass(slots=True)
class Peer:
    """One participant, and every path currently known to reach it.

    This is where multi-homing lives, and it is a third object rather than a field on either
    neighbour: a `Link` must not know about its siblings, and a `Mailbox` must not know about paths.
    The tell that it was missing is that `RetryBudget` is peer-scoped while everything else in this
    module is link-scoped, so it had nowhere to live but the caller.

    Three jobs, none of which belongs to a link or to a message: CHOOSE which links to use, STAGGER
    attempts across them (R7), and decide whether an outcome is ATTRIBUTABLE to any one of them."""

    identity: crypto.PublicKey
    dial: Callable[[Endpoint], Transport]
    """How to obtain a carrier for an endpoint. Takes the whole `Endpoint`, not just its address, so
    a transport receives the manager's options for it — TLS material, a proxy, a mixnet profile —
    without any of that being crammed into the locator string. Injected, so `Peer` needs no
    transport registry and a test needs no transports at all."""

    t: LinkTunables = field(default_factory=LinkTunables)
    links: dict[Address, Link] = field(default_factory=dict)
    endpoints: dict[Address, Endpoint] = field(default_factory=dict)
    """The configuration each link was built from, kept so an options-only change can be applied
    without disturbing the link's measurements."""
    budget: RetryBudget = field(default_factory=RetryBudget)
    """Shared by every link to this peer — per PEER, so a failing peer's cost is confined to itself
    while its individual links keep failing independently, which is what multi-homing is for.

    Not optional: a `None` default would need widening to `RetryBudget | None` everywhere it is
    used, for no gain. Construct it with the same tunables this peer uses."""

    # -- reconfiguration ---------------------------------------------------------------------- #

    def reconfigure(self, wanted_eps: tuple[Endpoint, ...]) -> Diff:
        """Apply a new endpoint set as a DIFF. Returns `(added, removed)`.

        SURVIVING LINKS KEEP THEIR STATE, and that is the point rather than an optimisation.
        Rebuilding the set would reset every estimator and — far worse — every breaker, so a roster
        edit would become a way to silently un-break a broken link: an address whose circuit was
        open would come back CLOSED and be dialled at once, on no evidence. Endpoints change for
        reasons that have nothing to do with a path's health, so health must survive the change.

        A removed address stops being selectable at once. An attempt already in flight on it is
        not cancelled — it cannot be, the bytes have gone — so a late reply for a departed link is
        simply unattributable, a case the caller already handles (LINKS.md §3.3)."""
        by_address = {e.address: e for e in wanted_eps}
        wanted = set(by_address)
        added = tuple(sorted((a for a in wanted if a not in self.links), key=lambda a: a.sort_key))
        removed = tuple(
            sorted((a for a in self.links if a not in wanted), key=lambda a: a.sort_key)
        )
        for a in removed:
            del self.links[a]
        for a in removed:
            self.endpoints.pop(a, None)
        for a in added:
            self.links[a] = standard(a, self.dial(by_address[a]), self.budget, self.t)
        # Options-only changes are recorded WITHOUT rebuilding the link: the address names the path,
        # so a retuned option is the same path and its measurements still describe it. Rebuilding
        # would reset the breaker, which is the silent un-breaking this method exists to prevent.
        self.endpoints.update(by_address)
        return Diff(added, removed)

    # -- selection ---------------------------------------------------------------------------- #

    def usable(self, now: Millis) -> tuple[Link, ...]:
        """Links that would accept a send right now, best first.

        FACTS ABOUT PATHS, not a decision about a message: how MANY of these to use, and when to try
        again if none, is `dude.net.plan`'s business. This object holds state, so it must not hold
        policy — the two together are what made selection duplicate across `Mailbox` and here.

        Ordering: a refusing link is dropped rather than attempted and failed — that is what the
        breaker is for. The rest sort by measured `rto()`, with `Address.sort_key` as tiebreak so
        unmeasured links start in cost order (inproc, unix, tcp) rather than arbitrarily."""
        out = [ln for ln in self.links.values() if ln.available(now)]
        out.sort(key=lambda ln: (self._rto(ln), ln.address.sort_key))
        return tuple(out)

    def deliverable(self, now: Millis) -> bool:
        """Is there any path at all right now? A fact, so it lives here; what to do about `False` is
        policy, so it does not."""
        return any(ln.available(now) for ln in self.links.values())

    def _rto(self, link: Link) -> Millis:
        est = link.find(Estimator)
        return est.rto() if est else self.t.rto_initial

    def __len__(self) -> int:
        return len(self.links)
