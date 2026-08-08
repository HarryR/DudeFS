# dude.net.postman — the one impure object. See SPEC.md (#peer-not-path).
#
# WHY THIS EXISTS [H]: `Link`, `Peer` and `Mailbox` are each deliberately ignorant of the others'
# domain (#peer-not-path), so something composes them — and it cannot be one of them. A mailbox
# that drove peers would have to know about links and addresses, which is the exact separation the
# split was drawn to get. So the composer is a fourth object rather than a promotion of a third.
#
# IT OWNS THE TWO THINGS NOTHING ELSE MAY:
#
#   the keypair   Restamping a retransmission means re-signing it. Keeping the signer here is what
#                 lets `Mailbox` stay a pure data structure — it is TOLD which stamp was used
#                 (`sent(..., ts=)`) rather than being able to produce one.
#   the clock     Everything below takes `now` as a parameter. This is the only place a real clock
#                 is read, which is why the whole stack under it replays deterministically.
#   the carriers  Dial-side transports are CONSTRUCTED here (#postman-owns-dialling) from
#                 `dude.net.transports.dial`, and the ones that also read are started and stopped
#                 here. A caller never names a concrete carrier class.
#
# Sans-I/O core, one impure edge. Effects go out through transports; events come back in through
# `deliver`.

from __future__ import annotations

import contextlib
import queue
from dataclasses import dataclass, field
from enum import Enum, auto
from typing import NamedTuple

from ..core import crypto
from ..core.errors import DudeError
from ..core.units import Millis
from . import transports
from .address import Endpoint, Scheme
from .envelope import EnvelopeError, Frame, SignedEnvelope
from .link import (
    CircuitBreaker,
    Estimator,
    LinkError,
    LinkTunables,
    Listener,
    Peer,
    SessionLink,
    Transport,
)
from .mailbox import Expired, Mailbox, Reply, Transmit
from .plan import Decision, GiveUp, Plan, Send, Wait
from .session import Inbound, Session


def _no_dial(_endpoint: Endpoint) -> Transport:
    """Sentinel `dial` for Peer entries that were only ever reached via inbound sessions.
    A client with no roster row has no dialable endpoints; if code tries to add a dial-Link
    via `Peer.reconfigure`, we raise loudly rather than silently returning None. If the peer
    later becomes dialable (e.g. gets added to the roster), replace with a real dial by
    calling `add_peer` -- which constructs a fresh Peer, currently; this sentinel only
    protects the "session-only" invariant during that window."""
    raise LinkError("peer is session-only; no dial capability configured")


class PostmanError(DudeError):
    """A misconfiguration Postman cannot recover from: a lifecycle call that contradicts an
    earlier one. Not for peer-level failures (link down, breaker open) — those are policy
    outcomes below Postman — and not for "no carrier for this scheme", which is a `LinkError`
    from `transports.dial`, the same failure shape a caller already handles from `send`."""


class Recipient(Enum):
    """Where an outbound message goes. A `crypto.PublicKey` is a directed send; `ALL` is broadcast.

    An enum-plus-union rather than `PublicKey | None` because `None` is exactly the "did you forget
    a case" trap the codebase's closed enums exist to prevent (#no-exceptions-for-control-flow).

    Lives here because expansion (`ALL` -> every known peer) is `Postman.recipients` -- Postman
    owns the peer set and is the only object that can turn `ALL` into a concrete address list."""

    ALL = auto()


type Target = crypto.PublicKey | Recipient


class Received(NamedTuple):
    """An accepted inbound envelope, plus the correlation result if it answered something
    outstanding.

    `reply is None` means unsolicited — a request, or an answer to something already reaped. Named
    rather than a bare pair, because two same-shaped optionals side by side is exactly the signature
    a caller unpacks backwards."""

    envelope: SignedEnvelope
    reply: Reply | None


@dataclass(slots=True)
class Postman:
    """Drives the mailbox and the peers. Holds the keypair, reads the clock, performs the I/O.

    Owns peer AND dial-side carrier lifecycle (#postman-owns-dialling). Callers register
    endpoints via `add_peer(pubkey, endpoints)`; Postman asks `transports.dial` for the
    carrier and constructs it. Nothing outside Postman writes to `peers`, and nothing
    outside Postman names a concrete transport class.

    THE LIFECYCLE IS HERE BECAUSE THE CARRIER IS. `TCPDialer` reads replies on the sockets
    it opened, so it needs an inbox and a thread; whoever constructs it must therefore also
    start it. That used to be the caller, which is why it had to construct it — the whole
    reason `attach_transport` existed. Owning construction without owning the thread would
    just move the knot. `start` / `stop` / `drain` mirror the `Listener` protocol on
    purpose: `Node` starts its listeners and its Postman with the same inbox, in one call."""

    me: crypto.Keypair
    mailbox: Mailbox = field(default_factory=Mailbox)
    peers: dict[crypto.PublicKey, Peer] = field(default_factory=dict)
    window: Millis = 5_000
    """The conversation window a receiver will apply to us — see `SignedEnvelope.fresh`."""

    link_tunables: LinkTunables = field(default_factory=LinkTunables)
    """Per-Peer link-policy dials -- one set applied uniformly to every peer this Postman
    owns. Per-endpoint policy (TLS material, mixnet profile) lives in
    `Endpoint.options` instead (#peer-options-are-endpoint-options)."""

    plan: Plan = field(default_factory=Plan)
    """The policy. `Postman` decides NOTHING — it asks, executes, and reports. The stagger delay and
    the give-up-when-no-links case used to be inline here; both were policy smuggled into the
    executor, and both now live in `Plan` where they can be tested without a socket."""

    _transports_by_scheme: dict[Scheme, Transport] = field(default_factory=dict, init=False)
    """Cache of transports this Postman has already dialled, keyed by scheme. Some
    transports (InProc, and typically a single TCP client) are one-per-Postman; the cache
    reuses them across peers of the same scheme so `add_peer` for two peers on the same
    scheme doesn't duplicate carrier state."""

    _inbox: queue.SimpleQueue[Inbound] | None = field(default=None, init=False)
    """Where a reading carrier puts what arrives on a socket WE opened, set by `start`.
    `None` until then — the deterministic test path never calls `start` and uses `drain`.

    Held so that a carrier constructed AFTER `start` is started too. That ordering is the
    normal one, not an edge case: a node starts before its first tick, and the first tick
    is what reconciles the roster into peers, which is what dials anything at all."""

    def add_peer(self, pubkey: crypto.PublicKey, endpoints: tuple[Endpoint, ...]) -> None:
        """Register or reconfigure a peer with `endpoints` we should try to reach it at.
        Constructs any carrier not already cached, via `transports.dial`.
        See #postman-owns-dialling.

        Idempotent: adding a peer that already exists reconfigures its endpoints (which
        preserves the surviving links' estimator/breaker state via `Peer.reconfigure`)."""
        peer = self.peers.get(pubkey)
        if peer is None:
            peer = Peer(pubkey, self._dial, self.link_tunables)
            self.peers[pubkey] = peer
        peer.reconfigure(endpoints)

    def remove_peer(self, pubkey: crypto.PublicKey) -> None:
        """Drop a peer from the routing table. Idempotent. Outbound messages already
        queued for this peer will time out and reap normally — the Postman's tick loop
        sees `peer = self.peers.get(...) is None` and lets the deadline handle it.

        This is also the mechanism tests use to simulate a partition
        (#partitions-are-test-only): remove the target from both sides."""
        self.peers.pop(pubkey, None)

    def register_session(self, session: Session) -> None:
        """Wrap `session` in a `SessionLink` and add it to the appropriate peer's session list.
        Called by the dispatch layer immediately after `session.bind(env.frm)` succeeds on the
        first inbound frame from a fresh accepted session, OR after a `dial()` succeeds and
        the session's identity is known at construction time.

        `session.identity` MUST be set before calling. Creates a Peer entry for identities not
        already in `self.peers` (a client with no roster row still gets a Peer, populated only
        with session-links -- no dial-Links until it's a roster member).

        `session.on_close` is set to the SessionLink's `_close()`, so a transport-side close
        (peer disconnected, socket died) fires the same removal path a send-failure would.
        Idempotent-ish: if the session has already been registered for its current identity,
        this is a no-op; register-again with a different identity is a bug and raises."""
        if session.identity is None:
            raise PostmanError("register_session called before session.bind()")
        peer = self.peers.get(session.identity)
        if peer is None:
            # Client (or otherwise not-in-roster identity): fresh Peer with no dial capability.
            # If it later becomes a roster member, `add_peer` reconfigures endpoints and dial-Links
            # appear alongside the existing session-Links -- reconfigure preserves state.
            peer = Peer(session.identity, _no_dial, self.link_tunables)
            self.peers[session.identity] = peer
        # Check if already registered (idempotent path).
        for existing in peer.sessions:
            if existing.session is session:
                return
        # Session carries its own peer address (from accept-remote or dial-target); use it so
        # `Peer.usable()` sorting can name the link. Sort_key isn't the primary axis for
        # session-links (last_activity is), but consistency with dial-Link's address field
        # keeps the API uniform.
        link = SessionLink(
            address=session.address,
            session=session,
            policies=(
                Estimator(self.link_tunables),
                CircuitBreaker(self.link_tunables),
                peer.budget,
            ),
        )
        link.on_close = self._on_session_link_closed
        session.on_close = link._close  # noqa: SLF001 -- cooperative teardown wiring
        peer.sessions.append(link)

    def unregister_session(self, session: Session) -> None:
        """Explicit removal, called by test code or lifecycle wiring that wants to drop a
        session without waiting for `close()` to propagate. Idempotent."""
        identity = session.identity
        if identity is None:
            return
        peer = self.peers.get(identity)
        if peer is None:
            return
        peer.sessions = [sl for sl in peer.sessions if sl.session is not session]

    def can_reply(self, pubkey: crypto.PublicKey) -> bool:
        """True iff we have any usable link to `pubkey` -- session or dial. Replaces the old
        `pubkey in self.peers` check that assumed reply-by-dial was the only path. A client
        with a live session but no roster entry answers True here; a node that just went
        unreachable (all links refusing) answers False; a stranger who has never talked to us
        answers False."""
        peer = self.peers.get(pubkey)
        if peer is None:
            return False
        return peer.deliverable(now=0) or bool(peer.sessions) or bool(peer.links)

    def _on_session_link_closed(self, link: SessionLink) -> None:
        """SessionLink hook: called from `SessionLink._close()` (either transport-side death via
        `session.on_close` or send-side failure). Removes the link from its peer."""
        identity = link.session.identity
        if identity is None:
            return
        peer = self.peers.get(identity)
        if peer is None:
            return
        peer.sessions = [sl for sl in peer.sessions if sl is not link]

    # -- carrier lifecycle -------------------------------------------------------------------- #

    def start(self, inbox: queue.SimpleQueue[Inbound]) -> None:
        """Begin reading replies on the sockets we dial. Every carrier that also reads gets
        `start(inbox)` -- those already built now, those built later in `_dial`.

        Same idempotence rule as `Listener.start`: the same inbox twice is a no-op, a
        different one raises, because a Postman delivering into two inboxes is a node whose
        frames arrive on whichever thread got there first."""
        if self._inbox is inbox:
            return
        if self._inbox is not None:
            raise PostmanError("postman already started with a different inbox")
        self._inbox = inbox
        for transport in self._transports_by_scheme.values():
            if isinstance(transport, Listener):
                transport.start(inbox)

    def stop(self) -> None:
        """Shut every reading carrier down and forget the inbox. Idempotent, and
        best-effort per carrier: this runs during shutdown, where there is nothing left to
        escalate a failure to and stopping the rest still matters.

        The cache is NOT cleared -- links already built hold their transport directly, so
        dropping our reference would not un-wire them, it would only let a later `_dial`
        build a second carrier behind their backs."""
        self._inbox = None
        for transport in self._transports_by_scheme.values():
            if isinstance(transport, Listener):
                with contextlib.suppress(Exception):
                    transport.stop()

    def drain(self) -> tuple[Inbound, ...]:
        """Everything our reading carriers have buffered, non-blocking. The deterministic
        test path: `start` need not have been called, and this is the dial-side twin of
        pumping a `Listener`. A reply that came back on a socket we opened arrives here,
        not at any listener (#session-first-reply)."""
        out: list[Inbound] = []
        for transport in self._transports_by_scheme.values():
            if isinstance(transport, Listener):
                out.extend(transport.drain())
        return tuple(out)

    def _dial(self, endpoint: Endpoint) -> Transport:
        """The carrier for `endpoint`'s scheme, constructed on first use and cached per
        scheme. A carrier that also reads is started immediately if we are already started.
        Raises `LinkError` (from `transports.dial`) for a scheme this build cannot dial."""
        scheme = endpoint.address.scheme
        transport = self._transports_by_scheme.get(scheme)
        if transport is not None:
            return transport
        transport = transports.dial(endpoint, self.me)
        self._transports_by_scheme[scheme] = transport
        if self._inbox is not None and isinstance(transport, Listener):
            transport.start(self._inbox)
        return transport

    def tick(self, now: Millis) -> tuple[Expired, ...]:
        """One round: act on what is due, then reap what has expired.

        Order matters — acting first means a message whose deadline falls in this very round still
        gets its last attempt instead of being reaped a round early by its own scheduling."""
        for t in self.mailbox.due(now):
            peer = self.peers.get(t.to)
            if peer is None:  # not in the roster; let the deadline reap it
                self.mailbox.failed(t.mid, self.plan.retry_at(t.attempt, now))
                continue
            self._act(self.plan.next(peer, t.attempt, now, self.mailbox.deadline(t.mid)), t, now)
        return self._reap(now)

    def _act(self, decision: Decision, t: Transmit, now: Millis) -> None:
        """Execute a decision. The whole of this object's authority: no branch here chooses a link,
        a delay or a limit — those arrived already decided."""
        match decision:
            case GiveUp():
                self.mailbox.failed(t.mid, now)  # due immediately; the reaper takes it this round
            case Wait(until=until):
                self.mailbox.failed(t.mid, until)
            case Send(links=links, again_at=again_at):
                for link in links:
                    # RESTAMPED AND RE-SIGNED PER ATTEMPT. Not tidiness: a distinct `ts` per attempt
                    # is what lets a reply's `reply_ts` name one of them, which is what keeps a
                    # staggered message measurable rather than a blind spot (#rtt-attribution).
                    stamped = t.envelope.env.sign(self.me, now)
                    if link.send(stamped.seal(), now) is None:
                        self.mailbox.sent(t.mid, link.address, now, now, again_at=again_at)
                        return
                self.mailbox.failed(t.mid, self.plan.retry_at(t.attempt, now))

    def deliver(self, frame: Frame, now: Millis) -> Received:
        """An inbound frame: the envelope to act on, plus the correlation result if it answered
        something outstanding.

        The envelope is never `None` — the old signature said it might be, which was unreachable
        since a frame that will not unseal or verify RAISES rather than returning.

        Refuses by raising: strict in what we accept, and loudly (#be-strict).

        THE SCREEN TAG IS CHECKED HERE, and it was checked nowhere `[H]`. `crypto.screen_tag` states
        the intended flow — *"the sender keys on the target's identity; the receiver keys on its OWN
        and compares"* — and names what it buys: a non-member knows no identity, so it cannot
        forge a tag, and **garbage costs one hash** instead of an ECDH against an ephemeral key.
        No layer performed the comparison: the transports never touch the tag, so every junk frame
        paid for a full sealed-box attempt, and a frame tagged for somebody else was opened.

        It belongs HERE rather than in a transport, because this is the one door every carrier comes
        through — a check that lives in `InProc` is a check a socket transport would not have, and
        an obligation that differs per carrier is not an obligation.

        This is addressing, NOT authentication, and the two must not be confused: a matching tag
        proves nothing about who sent the frame or what they may ask for (see
        `test_the_tag_is_a_hint_and_authorises_nothing`), and everything that matters still happens
        in `accept` after unsealing. Acting on a mismatch costs nothing even though the field is
        unauthenticated: whoever can rewrite a tag in flight can drop the frame instead, so refusing
        one grants an attacker no capability it lacked."""
        if not frame.addressed_to(self.me.public):
            raise EnvelopeError("frame is not addressed to us (screen tag does not match)")
        env = frame.unseal(self.me)
        env.accept(self.me.public, now, self.window)
        reply = self.mailbox.arrived(env, now)
        if reply is not None:
            self._credit(env.frm, reply, now)
        return Received(env, reply)

    def _credit(self, frm: crypto.PublicKey, reply: Reply, now: Millis) -> None:
        """Report the outcome to the link it belongs to — or to none.

        An unattributable reply still closes a circuit and still counts as liveness; it simply
        carries no sample. A link is never charged for a reply not shown to be its own."""
        peer = self.peers.get(frm)
        if peer is None:
            return
        if reply.address is None:
            for link in peer.links.values():
                link.reply(now, None)
            return
        link = peer.links.get(reply.address)
        if link is not None:
            link.reply(now, reply.rtt)

    def recipients(self, target: Target) -> list[crypto.PublicKey]:
        """Expand a `Target` into concrete peer keys, excluding ourselves. `Recipient.ALL` fans
        out to every known peer; a specific key resolves to itself (empty if it happens to be
        our own key). The one place `ALL` is turned into a concrete address list, because peers
        live here."""
        if target is Recipient.ALL:
            return [p for p in self.peers if p != self.me.public]
        return [target] if target != self.me.public else []

    def _reap(self, now: Millis) -> tuple[Expired, ...]:
        """Expire deadlines, charging a link ONLY when it was the sole attempt.

        #breaker's discipline. `Expired.address` is populated only when one attempt was made,
        so the judgement is made where the attempt record lives and applied here."""
        done = self.mailbox.expired(now)
        for e in done:
            peer = self.peers.get(e.to)
            if peer is None or e.address is None:
                continue
            link = peer.links.get(e.address)
            if link is not None:
                link.expired(now)
        return done
