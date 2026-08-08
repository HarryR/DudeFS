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
    raise LinkError("peer is session-only; no dial capability configured")


class PostmanError(DudeError): ...


class Recipient(Enum):
    ALL = auto()


type Target = crypto.PublicKey | Recipient


class Received(NamedTuple):
    envelope: SignedEnvelope
    reply: Reply | None


@dataclass(slots=True)
class Postman:
    me: crypto.Keypair
    mailbox: Mailbox = field(default_factory=Mailbox)
    peers: dict[crypto.PublicKey, Peer] = field(default_factory=dict)
    window: Millis = 5_000

    link_tunables: LinkTunables = field(default_factory=LinkTunables)

    plan: Plan = field(default_factory=Plan)

    _transports_by_scheme: dict[Scheme, Transport] = field(default_factory=dict, init=False)

    _inbox: queue.SimpleQueue[Inbound] | None = field(default=None, init=False)

    def add_peer(self, pubkey: crypto.PublicKey, endpoints: tuple[Endpoint, ...]) -> None:
        peer = self.peers.get(pubkey)
        if peer is None:
            peer = Peer(pubkey, self._dial, self.link_tunables)
            self.peers[pubkey] = peer
        peer.reconfigure(endpoints)

    def remove_peer(self, pubkey: crypto.PublicKey) -> None:
        self.peers.pop(pubkey, None)

    def register_session(self, session: Session) -> None:
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
        identity = session.identity
        if identity is None:
            return
        peer = self.peers.get(identity)
        if peer is None:
            return
        peer.sessions = [sl for sl in peer.sessions if sl.session is not session]

    def can_reply(self, pubkey: crypto.PublicKey) -> bool:
        peer = self.peers.get(pubkey)
        if peer is None:
            return False
        return peer.deliverable(now=0) or bool(peer.sessions) or bool(peer.links)

    def _on_session_link_closed(self, link: SessionLink) -> None:
        identity = link.session.identity
        if identity is None:
            return
        peer = self.peers.get(identity)
        if peer is None:
            return
        peer.sessions = [sl for sl in peer.sessions if sl is not link]

    def start(self, inbox: queue.SimpleQueue[Inbound]) -> None:
        if self._inbox is inbox:
            return
        if self._inbox is not None:
            raise PostmanError("postman already started with a different inbox")
        self._inbox = inbox
        for transport in self._transports_by_scheme.values():
            if isinstance(transport, Listener):
                transport.start(inbox)

    def stop(self) -> None:
        # The carrier cache is NOT cleared: links already built hold their transport directly,
        # so dropping our reference lets a later `_dial` build a second one behind their backs.
        self._inbox = None
        for transport in self._transports_by_scheme.values():
            if isinstance(transport, Listener):
                with contextlib.suppress(Exception):
                    transport.stop()

    def drain(self) -> tuple[Inbound, ...]:
        out: list[Inbound] = []
        for transport in self._transports_by_scheme.values():
            if isinstance(transport, Listener):
                out.extend(transport.drain())
        return tuple(out)

    def _dial(self, endpoint: Endpoint) -> Transport:
        scheme = endpoint.address.scheme
        transport = self._transports_by_scheme.get(scheme)
        if transport is not None:
            return transport
        transport = transports.dial(endpoint, self.me)
        self._transports_by_scheme[scheme] = transport
        # A carrier built AFTER `start` must be started too -- the normal ordering, since the
        # first tick is what reconciles the roster into peers, which is what dials anything.
        if self._inbox is not None and isinstance(transport, Listener):
            transport.start(self._inbox)
        return transport

    def tick(self, now: Millis) -> tuple[Expired, ...]:
        for t in self.mailbox.due(now):
            peer = self.peers.get(t.to)
            if peer is None:
                self.mailbox.failed(t.mid, self.plan.retry_at(t.attempt, now))
                continue
            self._act(self.plan.next(peer, t.attempt, now, self.mailbox.deadline(t.mid)), t, now)
        return self._reap(now)

    def _act(self, decision: Decision, t: Transmit, now: Millis) -> None:
        match decision:
            case GiveUp():
                self.mailbox.failed(t.mid, now)
            case Wait(until=until):
                self.mailbox.failed(t.mid, until)
            case Send(links=links, again_at=again_at):
                for link in links:
                    stamped = t.envelope.env.sign(self.me, now)
                    if link.send(stamped.seal(), now) is None:
                        self.mailbox.sent(t.mid, link.address, now, now, again_at=again_at)
                        return
                self.mailbox.failed(t.mid, self.plan.retry_at(t.attempt, now))

    def deliver(self, frame: Frame, now: Millis) -> Received:
        # ADDRESSING, NOT AUTHENTICATION: a matching tag proves nothing about who sent this or
        # what they may ask for. Checked here because this is the one door every carrier comes
        # through -- an obligation that differs per carrier is not an obligation.
        if not frame.addressed_to(self.me.public):
            raise EnvelopeError("frame is not addressed to us (screen tag does not match)")
        env = frame.unseal(self.me)
        env.accept(self.me.public, now, self.window)
        reply = self.mailbox.arrived(env, now)
        if reply is not None:
            self._credit(env.frm, reply, now)
        return Received(env, reply)

    def _credit(self, frm: crypto.PublicKey, reply: Reply, now: Millis) -> None:
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
        if target is Recipient.ALL:
            return [p for p in self.peers if p != self.me.public]
        return [target] if target != self.me.public else []

    def _reap(self, now: Millis) -> tuple[Expired, ...]:
        done = self.mailbox.expired(now)
        for e in done:
            peer = self.peers.get(e.to)
            if peer is None or e.address is None:
                continue
            link = peer.links.get(e.address)
            if link is not None:
                link.expired(now)
        return done
