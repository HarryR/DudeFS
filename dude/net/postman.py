# dude.net.postman — the one impure object. See SPEC.md (#peer-not-path, #postman-owns-dialling).
#
# `Link`, `Peer` and `Mailbox` are each ignorant of the others' domain, so the composer has to be
# a fourth object rather than a promotion of a third. It owns the three things nothing else may:
#
#   the keypair   Restamping a retransmission means re-signing it. Keeping the signer here is what
#                 lets `Mailbox` stay pure — it is TOLD which stamp was used, not able to make one.
#   the clock     The only real clock read in the stack, which is why everything under it replays.
#   the carriers  Dial-side transports are constructed, started and stopped here; a caller never
#                 names a concrete carrier class.

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
    """`dial` for a peer only ever reached via an inbound session -- a client, which has no
    roster row and so no dialable endpoint. Raises rather than returning None, so building a
    dial-Link for one is loud instead of silently absent."""
    raise LinkError("peer is session-only; no dial capability configured")


class PostmanError(DudeError):
    """A lifecycle call that contradicts an earlier one. NOT peer-level failure (link down,
    breaker open — policy outcomes below Postman), and NOT "no carrier for this scheme", which
    is a `LinkError` from `transports.dial`: the shape a caller already handles from `send`."""


class Recipient(Enum):
    """Where an outbound message goes. A `crypto.PublicKey` is a directed send; `ALL` is broadcast.

    An enum-plus-union rather than `PublicKey | None`: `None` is exactly the "did you forget a
    case" trap the closed enums exist to prevent (#no-exceptions-for-control-flow)."""

    ALL = auto()


type Target = crypto.PublicKey | Recipient


class Received(NamedTuple):
    """An accepted inbound envelope, plus the correlation result if it answered something
    outstanding.

    `reply is None` means unsolicited — a request, or an answer to something already reaped.
    Named rather than a bare pair: two same-shaped optionals side by side is the signature a
    caller unpacks backwards."""

    envelope: SignedEnvelope
    reply: Reply | None


@dataclass(slots=True)
class Postman:
    """Drives the mailbox and the peers. Holds the keypair, reads the clock, performs the I/O.

    Owns peer AND dial-side carrier lifecycle (#postman-owns-dialling): nothing outside writes
    to `peers`, and nothing outside names a concrete transport class. `start` / `stop` / `drain`
    mirror `Listener`, so a `Node` starts its listeners and its Postman with one inbox."""

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
    """One carrier per scheme, reused across every peer on that scheme -- two peers over TCP
    share one dialer rather than duplicating its socket cache and reader thread."""

    _inbox: queue.SimpleQueue[Inbound] | None = field(default=None, init=False)
    """Where a reading carrier puts what arrives on a socket WE opened; `None` until `start`
    (the deterministic test path uses `drain` instead). HELD so a carrier built after `start`
    is started too -- the normal ordering, since a node starts before its first tick and the
    first tick is what reconciles the roster into peers, which is what dials anything."""

    def add_peer(self, pubkey: crypto.PublicKey, endpoints: tuple[Endpoint, ...]) -> None:
        """Register or reconfigure a peer, building any carrier not already cached
        (#postman-owns-dialling). Idempotent, and re-adding preserves surviving links'
        estimator and breaker state via `Peer.reconfigure`."""
        peer = self.peers.get(pubkey)
        if peer is None:
            peer = Peer(pubkey, self._dial, self.link_tunables)
            self.peers[pubkey] = peer
        peer.reconfigure(endpoints)

    def remove_peer(self, pubkey: crypto.PublicKey) -> None:
        """Drop a peer from the routing table. Idempotent; anything already queued for it
        reaps on its deadline. Removing on both sides is how a test simulates a partition
        (#partitions-are-test-only)."""
        self.peers.pop(pubkey, None)

    def register_session(self, session: Session) -> None:
        """Add `session` to its peer as a `SessionLink`. Called by dispatch once
        `session.bind(env.frm)` has succeeded, so `session.identity` MUST already be set.

        An identity with no Peer gets one -- a client with no roster row is reachable by
        session-link alone, and gains dial-Links only if it later joins the roster. Wiring
        `session.on_close` to the link's `_close` is what makes a transport-side death and a
        send-side failure converge on one removal path. Re-registering the same session is a
        no-op."""
        if session.identity is None:
            raise PostmanError("register_session called before session.bind()")
        peer = self.peers.get(session.identity)
        if peer is None:
            peer = Peer(session.identity, _no_dial, self.link_tunables)
            self.peers[session.identity] = peer
        for existing in peer.sessions:
            if existing.session is session:
                return
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
        """`SessionLink._close` hook -- transport-side death or send-side failure. Drops the
        link from its peer."""
        identity = link.session.identity
        if identity is None:
            return
        peer = self.peers.get(identity)
        if peer is None:
            return
        peer.sessions = [sl for sl in peer.sessions if sl is not link]

    # -- carrier lifecycle -------------------------------------------------------------------- #

    def start(self, inbox: queue.SimpleQueue[Inbound]) -> None:
        """Begin reading replies on the sockets we dial: every carrier that also reads gets
        `start(inbox)`, those already built and those `_dial` builds later.

        Same inbox twice is a no-op; a different one raises. A Postman delivering into two
        inboxes is a node whose frames arrive on whichever thread got there first."""
        if self._inbox is inbox:
            return
        if self._inbox is not None:
            raise PostmanError("postman already started with a different inbox")
        self._inbox = inbox
        for transport in self._transports_by_scheme.values():
            if isinstance(transport, Listener):
                transport.start(inbox)

    def stop(self) -> None:
        """Shut every reading carrier down and forget the inbox. Idempotent, best-effort per
        carrier (nothing left to escalate to during shutdown, and stopping the rest matters).

        The cache is NOT cleared: links already built hold their transport directly, so
        dropping our reference would not un-wire them -- it would only let a later `_dial`
        build a second carrier behind their backs."""
        self._inbox = None
        for transport in self._transports_by_scheme.values():
            if isinstance(transport, Listener):
                with contextlib.suppress(Exception):
                    transport.stop()

    def drain(self) -> tuple[Inbound, ...]:
        """Everything our reading carriers have buffered, non-blocking; the dial-side twin of
        pumping a `Listener`, and `start` need not have been called. A reply on a socket we
        opened arrives HERE, not at any listener (#session-first-reply)."""
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
        something outstanding. Refuses by raising (#be-strict).

        THE SCREEN TAG IS CHECKED HERE, and was checked nowhere: transports never touch it, so
        every junk frame paid for a full sealed-box attempt and a frame tagged for somebody else
        was opened. It belongs here rather than in a carrier because this is the one door every
        carrier comes through -- an obligation that differs per carrier is not an obligation.

        It is ADDRESSING, NOT AUTHENTICATION. A matching tag proves nothing about who sent the
        frame or what they may ask for (`test_the_tag_is_a_hint_and_authorises_nothing`);
        everything that matters happens in `accept`, after unsealing. Acting on a mismatch is
        still free despite the field being unauthenticated: whoever can rewrite a tag in flight
        can drop the frame instead, so refusing one grants no capability it lacked."""
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
        """Expand a `Target` into concrete peer keys, excluding ourselves. The one place `ALL`
        becomes a concrete address list, because the peer set lives here."""
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
