# dude.net.link — one path to one peer, and the policies layered over it. See SPEC.md (#breaker).
#
# A carrier is DUMB (it moves bytes and raises); measurement, breaking and throttling are a stack
# of small policies over it. Four observations, because the useful information arrives at four
# moments and a policy that cannot see one of them cannot do its job:
#
#   before_send()  veto — the only one that can refuse
#   on_sent()      the bytes left (which implies nothing about receipt)
#   on_failed()    the transport raised
#   on_reply(rtt)  a reply came back; `rtt` is None when it is UNATTRIBUTABLE (#rtt-attribution)
#
# `rtt=None` is the load-bearing case, not an edge case: under multi-homing most replies cannot be
# attributed to a transmission at all (R2, Karn), so a policy that treats "no sample" as a sample
# of zero builds its estimate from the un-retried traffic alone — the easy cases only.

from __future__ import annotations

import contextlib
import queue
from collections.abc import Callable
from dataclasses import dataclass, field
from enum import Enum
from typing import NamedTuple, Protocol, runtime_checkable

from ..core import crypto
from ..core.errors import DudeError
from ..core.units import Millis
from .address import Address, Endpoint
from .envelope import Frame
from .session import Inbound, Session


class LinkError(DudeError):
    """The transport could not move the bytes. The only failure a transport may report — anything
    finer is this layer's business, not the carrier's."""


class Transport(Protocol):
    """A carrier's SEND side. Deliberately tiny: no retries, no timeouts, no state, no opinions.

    Everything a transport knows is "did the bytes leave". It must not retry internally, because a
    hidden retry is a transmission this layer cannot count, and an uncounted transmission breaks R2
    (the sample looks single-attempt when it was not) and R6 (the budget never sees the load).

    RECEIVE-SIDE IS `Listener` -- separate protocol, separate object, separate lifecycle. A carrier
    that both sends and receives (TCP, UNIX, InProc) ships two concrete types: `TCPDialer` and
    `TCPListener`, etc. Postman holds the `Transport` (send side) per scheme; Node holds the
    `Listener` (receive side). The split is what lets a node be dialler-only (behind a NAT, only
    outbound) or listener-only in some deployments; it also stops one class from having two roles
    with two constructors' worth of unrelated configuration."""

    def send(self, address: Address, frame: Frame) -> None: ...


@runtime_checkable
class Listener(Protocol):
    """A carrier's RECEIVE side. Owns inbound bytes: a listen socket (for TCP/UNIX), or the
    receiving half of a paired loopback (for InProc). Same discipline as `Transport` -- tiny
    contract, no policy.

    RUNTIME-CHECKABLE because one real question is asked of an instance: `Postman` constructs
    dial-side carriers and must know which of them ALSO read (`TCPDialer` does, on the sockets
    it opened; `InProcDialer` does not) so it can drive their lifecycle. That is a per-instance
    fact, not a per-scheme one, so a table would be a second place to keep it in step.

    THREE METHODS, two shapes of caller:

      * `start(inbox)` + `stop()` -- production. The listener spawns whatever thread it needs
        to accept + read, and pushes every complete inbound `Frame` into `inbox`. `stop()` is
        the bounded, idempotent shutdown that closes sockets and joins the thread.
      * `drain()` -- tests. Returns whatever the listener has already buffered internally,
        without starting a thread. Same underlying buffer either way; `start()` additionally
        forwards each new frame into the caller-supplied queue.

    The two paths coexist so tests drive `tick()`/`receive()` deterministically from one thread
    while production runs the same primitives from a Node-owned thread. Same public API for both;
    no test-only subclass, no private-state reach."""

    def start(self, inbox: queue.SimpleQueue[Inbound]) -> None: ...
    def stop(self) -> None: ...
    def drain(self) -> tuple[Inbound, ...]: ...


# Tunables. ONE surface per #timing -- these belong in the management store once that lands. No
# literal in this module appears outside this group.


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

    keepalive_interval: Millis | None = None
    """If set, the link PINGs itself after this long with no frame sent OR received. Two jobs:
    the reply's RTT feeds the Estimator, and the traffic holds a session-backed carrier open
    (a NAT-only node keeping outbound sessions alive -- kernel TCP keepalive is too coarse and
    often disabled). `None` = off, the default for stateless carriers."""

    # `stagger_cap` and `max_parallel` are NOT here -- they live in `PlanTunables`, which reads
    # them. Declared in both groups with no consumer for this copy, the two disagreed by 50 ms the
    # moment one was derived from `RTT_MAX`. The dial belongs to the object that decides with it.

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
    """Why a policy would not let a send happen — a CLOSED set the layer above branches on
    (#no-exceptions-for-control-flow), so it must be matchable exhaustively and countable
    without typos.

    Plain `Enum`, deliberately NOT `StrEnum`: these never go on the wire, and `StrEnum` members
    ARE `str`s -- which is how a comparison between two unrelated reason enums that happened to
    share a spelling came out True. Plain members compare False against bare strings, so a stray
    `== "guard"` fails loudly. Every closed reason set in this codebase follows suit."""

    INVALID = "invalid"
    """Reserved ordinal 0, never returned (#no-exceptions-for-control-flow). Load-bearing in a
    Go port, where the zero value would otherwise silently mean the first real member."""

    CIRCUIT_OPEN = "circuit-open"
    CIRCUIT_PROBING = "circuit-probing"
    """Half-open admits exactly ONE probe; this is every other caller in the same window."""
    TRANSPORT = "transport"
    """The carrier itself failed. The only refusal not decided by a policy."""


class Policy(Protocol):
    """One concern, layered over a link; an implementation states only what it cares about.

    Parameters are POSITIONAL-ONLY so an implementation may underscore the ones it ignores.
    Without `/`, a renamed parameter is an invalid override."""

    def before_send(self, now: Millis, /) -> Refused | None:
        """`None` to allow, or the reason to refuse. The only veto in the stack."""
        ...

    def on_sent(self, now: Millis, /) -> None: ...
    def on_failed(self, now: Millis, /) -> None: ...
    def on_reply(self, now: Millis, rtt: Millis | None, /) -> None: ...


class _Inert:
    """Default no-ops, so each policy states only its own concern. Underscored parameters are
    protocol conformance, not the declared-but-unwired shape ruff's ARG family catches."""

    def before_send(self, _now: Millis, /) -> Refused | None:
        return None

    def on_sent(self, _now: Millis, /) -> None: ...
    def on_failed(self, _now: Millis, /) -> None: ...
    def on_reply(self, _now: Millis, _rtt: Millis | None, /) -> None: ...


@dataclass(slots=True)
class Estimator(_Inert):
    """R2 + R3. Per-link RTT and the timeout derived from it. Refuses nothing -- measurement is
    not a gate. Also carries `last_activity`, which `needs_keepalive` reads: one clock serving
    liveness for the session and freshness for the estimate."""

    t: LinkTunables = field(default_factory=LinkTunables)
    srtt: float | None = None
    rttvar: float = 0.0
    samples: int = 0
    ignored: int = 0
    """Replies that carried no usable sample. Counted rather than discarded silently: a link with
    many ignored and few samples measures itself from a biased subset, which is worth seeing."""
    last_activity: Millis = 0
    """Most recent send or reply observed. `0` means never active; keepalive stays off until
    the first send goes out (there's nothing to keep alive on an untouched link)."""

    def on_sent(self, now: Millis, /) -> None:
        self.last_activity = now

    def on_reply(self, now: Millis, rtt: Millis | None, /) -> None:
        self.last_activity = now
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

    def needs_keepalive(self, now: Millis) -> bool:
        """Set, once-active, and idle longer than the interval. The `last_activity > 0` guard is
        what stops a fresh link firing a keepalive against nothing: keepalive is for links that
        WERE active and went quiet, not for cold ones."""
        if self.t.keepalive_interval is None:
            return False
        if self.last_activity == 0:
            return False
        return (now - self.last_activity) >= self.t.keepalive_interval


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

        Returns rather than raises (#no-exceptions-for-control-flow): "the circuit is open" is an
        ordinary scheduling answer. A transport failure is still reported through `on_failed`."""
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
        """A reply arrived on this link. `rtt=None` when unattributable (#rtt-attribution) — pass it
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


@dataclass(slots=True)
class SessionLink:
    """A Link backed by an OPEN Session (from either a dial or an accept), not by a
    dial-on-demand address. Same policy contract as `Link` (same `send`/`reply`/`expired`/
    `available`/`find` shape, same hook order), so `Peer.usable()` can return a mixed list and
    `Plan.next()` treats them uniformly.

    LIFETIME BOUND TO THE SESSION: a transport-level send failure presumes the session dead and
    runs `_close()`. The transport can signal death independently; both paths converge there.

    Not a `Link` subclass by choice -- the send line and the close lifecycle are the only real
    differences, and duplicating them reads better than a strategy callable threaded through
    `Link`."""

    address: Address
    """The peer's address through this session. Same field name as `Link.address` so
    `Peer.usable` sorting stays type-agnostic."""

    session: Session
    policies: tuple[Policy, ...] = ()
    on_close: Callable[[SessionLink], None] | None = None
    """Invoked exactly once when the SessionLink dies. Postman sets this at register-time to
    the removal-from-Peer.sessions routine; SessionLink calls it from `_close()`."""

    _closed: bool = field(default=False, init=False)

    def send(self, frame: Frame, now: Millis) -> Refused | None:
        """Same contract as `Link.send`. Extra: on transport failure, the session is closed
        and this SessionLink dies (its `on_close` fires). A dead SessionLink refuses further
        sends with `Refused.TRANSPORT`."""
        if self._closed:
            return Refused.TRANSPORT
        for p in self.policies:
            refusal = p.before_send(now)
            if refusal is not None:
                return refusal
        try:
            self.session.send(frame)
        except LinkError:
            self._each("on_failed", now)
            self._close()
            return Refused.TRANSPORT
        self._each("on_sent", now)
        return None

    def reply(self, now: Millis, rtt: Millis | None) -> None:
        for p in self.policies:
            p.on_reply(now, rtt)

    def expired(self, now: Millis) -> None:
        self._each("on_failed", now)

    def available(self, now: Millis) -> bool:
        if self._closed:
            return False
        return all(p.before_send(now) is None for p in self.policies)

    def find[T](self, kind: type[T]) -> T | None:
        for p in self.policies:
            if isinstance(p, kind):
                return p
        return None

    @property
    def last_activity(self) -> Millis:
        """Delegated to `Session.last_activity` so `Peer.usable()` can sort session-links
        freshest-first without knowing which policy holds the timestamp."""
        return self.session.last_activity

    def _close(self) -> None:
        """Idempotent -- transport-side death and send-side failure both reach here, and
        whichever fires first wins."""
        if self._closed:
            return
        self._closed = True
        with contextlib.suppress(Exception):
            self.session.close()  # best-effort teardown; nothing to escalate to
        if self.on_close is not None:
            self.on_close(self)

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
    """What `Peer.reconfigure` changed. Named rather than a bare
    `tuple[tuple[Address, ...], ...]`, which says nothing about which side is which and unpacks
    backwards with no error."""

    added: tuple[Address, ...]
    removed: tuple[Address, ...]


@dataclass(slots=True)
class Peer:
    """One participant, and every path currently known to reach it.

    Multi-homing lives here, in a third object: a `Link` must not know its siblings and a
    `Mailbox` must not know about paths. The tell that it was missing is that `RetryBudget` is
    peer-scoped while everything else in this module is link-scoped.

    Three jobs, none belonging to a link or a message: CHOOSE which links to use, STAGGER attempts
    across them (R7), and decide whether an outcome is ATTRIBUTABLE to any one of them."""

    identity: crypto.PublicKey
    dial: Callable[[Endpoint], Transport]
    """How to obtain a carrier. Takes the whole `Endpoint` so a transport receives the manager's
    options for it -- TLS material, a proxy, a mixnet profile -- rather than having them crammed
    into the locator string. Injected, so a test needs no transports at all."""

    t: LinkTunables = field(default_factory=LinkTunables)
    links: dict[Address, Link] = field(default_factory=dict)
    sessions: list[SessionLink] = field(default_factory=list)
    """Session-backed return paths -- one per open Session, whether we dialed out to this peer
    or they accepted us. Freshest-first (by `last_activity`) in `usable()`, ahead of dial-Links
    because a live session is a zero-cost reply. Populated by `Postman.register_session`,
    pruned by `Postman.unregister_session` / `SessionLink._close()`."""
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
        simply unattributable, a case the caller already handles (#rtt-attribution)."""
        by_address = {e.address: e for e in wanted_eps}
        wanted = set(by_address)
        added = tuple(sorted((a for a in wanted if a not in self.links), key=lambda a: a.sort_key))
        removed = tuple(
            sorted((a for a in self.links if a not in wanted), key=lambda a: a.sort_key)
        )
        for a in removed:
            del self.links[a]
            self.endpoints.pop(a, None)
        for a in added:
            self.links[a] = standard(a, self.dial(by_address[a]), self.budget, self.t)
        # Options-only changes are recorded WITHOUT rebuilding the link: the address names the path,
        # so a retuned option is the same path and its measurements still describe it. Rebuilding
        # would reset the breaker, which is the silent un-breaking this method exists to prevent.
        self.endpoints.update(by_address)
        return Diff(added, removed)

    # -- selection ---------------------------------------------------------------------------- #

    def usable(self, now: Millis) -> tuple[Link | SessionLink, ...]:
        """Links that would accept a send right now, best first.

        FACTS ABOUT PATHS, not a decision about a message: how MANY of these to use, and when to try
        again if none, is `dude.net.plan`'s business. This object holds state, so it must not hold
        policy — the two together are what made selection duplicate across `Mailbox` and here.

        Ordering: SESSION-LINKS FIRST, freshest-first by `last_activity` -- a live session is the
        cheapest reply path (already connected, one write) and the freshest is the most likely to
        still be alive. Then DIAL-LINKS, sorted by measured `rto()` with `Address.sort_key` as
        tiebreak so unmeasured links start in cost order (inproc, unix, tcp) rather than
        arbitrarily. Safe from Wave 2 onward: `TCPDialer` reads replies on its own outbound
        sockets, so a reply written on the accept-side session gets received on the dialer's
        side (or vice-versa) rather than sitting in an un-read socket buffer -- which was the
        blocker for this flip until Wave 2 landed. A refusing link is dropped rather than
        attempted and failed -- that is what the breaker is for."""
        session_out = [sl for sl in self.sessions if sl.available(now)]
        session_out.sort(key=lambda sl: -sl.last_activity)  # newest first
        dial_out = [ln for ln in self.links.values() if ln.available(now)]
        dial_out.sort(key=lambda ln: (self._rto(ln), ln.address.sort_key))
        return (*session_out, *dial_out)

    def deliverable(self, now: Millis) -> bool:
        """Is there any path at all right now? A fact, so it lives here; what to do about `False` is
        policy, so it does not."""
        return any(ln.available(now) for ln in self.links.values()) or any(
            sl.available(now) for sl in self.sessions
        )

    def _rto(self, link: Link) -> Millis:
        est = link.find(Estimator)
        return est.rto() if est else self.t.rto_initial
