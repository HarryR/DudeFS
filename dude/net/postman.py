import contextlib
import queue
from abc import ABC, abstractmethod
from collections.abc import Callable, Iterable
from dataclasses import dataclass, field
from enum import Enum, auto
from typing import NamedTuple

from ..core import crypto
from ..core.errors import DudeError
from ..core.event_loop import Event, EventLoop, Scheduled
from ..core.units import Millis
from ..tunables import Tunables
from .address import Address, Endpoint
from .envelope import Envelope, EnvelopeError, Frame, MessageId, Verb
from .link import (
    Acceptor,
    Dialer,
    Link,
    Peer,
)
from .mailbox import Expired, Mailbox, Reply, Transmit
from .plan import Decision, GiveUp, Send, Wait, plan_next, retry_at
from .transports.tcp import OnionDialer, TCPDialer


class Recipient(Enum):
    ALL = auto()


type Target = crypto.PublicKey | Recipient


def recipients(
    target: Target, roster: Iterable[crypto.PublicKey], me: crypto.PublicKey
) -> list[crypto.PublicKey]:
    if target is Recipient.ALL:
        return [p for p in roster if p != me]
    return [target] if target != me else []


class Encodable(ABC):
    @abstractmethod
    def encode(self) -> tuple[Verb, bytes]: ...


# ---------------------------------------------------------------------------
# Postman events — everything the loop dispatches.
# ---------------------------------------------------------------------------


class _PostmanEvent(Event, ABC):
    __slots__ = ()


@dataclass(frozen=True, slots=True)
class _PostSend(_PostmanEvent):
    to: crypto.PublicKey
    verb: Verb
    body: bytes
    ttl: Millis
    await_reply: bool
    reply_to: bytes
    prefix: bytes


@dataclass(frozen=True, slots=True)
class _SyncPeers(_PostmanEvent):
    peers: dict[crypto.PublicKey, tuple[Endpoint, ...]]
    authorized: frozenset[crypto.PublicKey]


@dataclass(frozen=True, slots=True)
class _AddPeer(_PostmanEvent):
    pubkey: crypto.PublicKey
    endpoints: tuple[Endpoint, ...]


@dataclass(frozen=True, slots=True)
class _RemovePeer(_PostmanEvent):
    pubkey: crypto.PublicKey


@dataclass(frozen=True, slots=True)
class _FrameIn(_PostmanEvent):
    frame: Frame
    link: Link


@dataclass(frozen=True, slots=True)
class _LinkUp(_PostmanEvent):
    link: Link


@dataclass(frozen=True, slots=True)
class _LinkDown(_PostmanEvent):
    link: Link


@dataclass(frozen=True, slots=True)
class _LinkBroken(_PostmanEvent):
    address: Address


class _RetryDue(_PostmanEvent):
    __slots__ = ()


class _ReapCheck(_PostmanEvent):
    __slots__ = ()


class _MaintainLinks(_PostmanEvent):
    __slots__ = ()


@dataclass(frozen=True, slots=True)
class _Broadcast(_PostmanEvent):
    verb: Verb
    body: bytes
    ttl: Millis


# ---------------------------------------------------------------------------
# Output events — everything that comes OUT of the postman to the node.
# ---------------------------------------------------------------------------


class Delivered(NamedTuple):
    frm: crypto.PublicKey
    verb: Verb
    body: bytes
    mid: MessageId
    in_reply_to: MessageId | None


class Output(NamedTuple):
    delivered: tuple[Delivered, ...]
    expired: tuple[Expired, ...]


class OutputQueue:
    __slots__ = ("_q",)

    def __init__(self) -> None:
        self._q: queue.SimpleQueue[Output] = queue.SimpleQueue()

    def __call__(self, out: Output) -> None:
        self._q.put(out)

    def get(self, timeout: float | None = None) -> Output | None:
        try:
            return self._q.get(timeout=timeout)
        except queue.Empty:
            return None


# ---------------------------------------------------------------------------
# The actor.
# ---------------------------------------------------------------------------


@dataclass(slots=True)
class Postman:
    me: crypto.Keypair
    tunables: Tunables
    on_output: Callable[[Output], None]

    mailbox: Mailbox = field(default_factory=Mailbox)
    peers: dict[crypto.PublicKey, Peer] = field(default_factory=dict)

    _authorized: frozenset[crypto.PublicKey] = field(default_factory=frozenset, init=False)

    _loop: EventLoop[_PostmanEvent] = field(init=False)

    _retry_timer: Scheduled[_PostmanEvent] | None = field(default=None, init=False)
    _reap_timer: Scheduled[_PostmanEvent] | None = field(default=None, init=False)
    _link_timer: Scheduled[_PostmanEvent] | None = field(default=None, init=False)

    _acceptors: list[Acceptor] = field(default_factory=list, init=False)
    _dialers: list[Dialer] = field(default_factory=list, init=False)

    def __post_init__(self) -> None:
        self._dialers.append(TCPDialer(self.tunables))
        self._dialers.append(OnionDialer(self.tunables))
        self._loop = EventLoop()
        self._loop.register(_PostSend, self._on_post_send)
        self._loop.register(_SyncPeers, self._on_sync_peers)
        self._loop.register(_AddPeer, self._on_add_peer)
        self._loop.register(_RemovePeer, self._on_remove_peer)
        self._loop.register(_FrameIn, self._on_frame_in)
        self._loop.register(_LinkUp, self._on_link_up)
        self._loop.register(_LinkDown, self._on_link_down)
        self._loop.register(_LinkBroken, self._on_link_broken)
        self._loop.register(_RetryDue, self._on_retry_due)
        self._loop.register(_ReapCheck, self._on_reap_check)
        self._loop.register(_MaintainLinks, self._on_maintain_links)
        self._loop.register(_Broadcast, self._on_broadcast)

    # -- public interface: queue puts, never direct state mutation -----------

    def send(
        self,
        to: crypto.PublicKey,
        msg: Encodable,
        ttl: Millis,
        mid: MessageId | None = None,
    ) -> MessageId:
        verb, body = msg.encode()
        if mid is None:
            mid = MessageId.random()
        self._loop.post(_PostSend(to, verb, body, ttl, True, MessageId(b""), mid))
        return mid

    def reply(self, d: Delivered, msg: Encodable, ttl: Millis) -> MessageId:
        verb, body = msg.encode()
        new_mid = MessageId.random()
        self._loop.post(_PostSend(d.frm, verb, body, ttl, False, d.mid, new_mid))
        return new_mid

    def send_raw(
        self,
        to: crypto.PublicKey,
        verb: Verb,
        body: bytes,
        ttl: Millis,
        await_reply: bool = True,
        reply_to: MessageId | None = None,
        mid: MessageId | None = None,
    ) -> MessageId:
        if reply_to is None:
            reply_to = MessageId(b"")
        if mid is None:
            mid = MessageId.random()
        self._loop.post(_PostSend(to, verb, body, ttl, await_reply, reply_to, mid))
        return mid

    def sync(
        self,
        peers: dict[crypto.PublicKey, tuple[Endpoint, ...]],
        authorized: frozenset[crypto.PublicKey] = frozenset(),
    ) -> None:
        self._loop.post(_SyncPeers(peers, authorized))

    def add_peer(self, pubkey: crypto.PublicKey, endpoints: tuple[Endpoint, ...]) -> None:
        self._loop.post(_AddPeer(pubkey, endpoints))

    def remove_peer(self, pubkey: crypto.PublicKey) -> None:
        self._loop.post(_RemovePeer(pubkey))

    def broadcast(self, verb: Verb, body: bytes, ttl: Millis) -> None:
        self._loop.post(_Broadcast(verb, body, ttl))

    # -- lifecycle ----------------------------------------------------------

    def add_acceptor(self, acceptor: Acceptor) -> None:
        self._acceptors.append(acceptor)
        if self._loop.running:
            acceptor.start(self._on_frame, self._on_link_established)

    def add_dialer(self, dialer: Dialer) -> None:
        self._dialers.append(dialer)
        if self._loop.running:
            dialer.start(self._on_frame, self._on_link_established)

    def start(self) -> None:
        if self._loop.running:
            return
        for acceptor in self._acceptors:
            acceptor.start(self._on_frame, self._on_link_established)
        for dialer in self._dialers:
            dialer.start(self._on_frame, self._on_link_established)
        self._loop.start()
        self._schedule_link_maintenance()

    def stop(self) -> None:
        self._loop.stop()
        for acceptor in self._acceptors:
            with contextlib.suppress(Exception):
                acceptor.stop()
        for dialer in self._dialers:
            with contextlib.suppress(Exception):
                dialer.stop()

    # -- transport callbacks (called from transport threads, thread-safe) ----

    def _on_frame(self, frame: Frame, link: Link) -> None:
        self._loop.post(_FrameIn(frame, link))

    def _on_link_established(self, link: Link) -> None:
        link.on_close = lambda ln: self._loop.post(_LinkDown(ln))
        self._loop.post(_LinkUp(link))

    # -- event handlers (run on the postman's loop thread only) -------------

    def _on_post_send(self, event: _PostSend) -> None:
        now = Millis.now()
        env = Envelope(
            event.to,
            event.verb,
            MessageId(event.prefix + b"\x00"),
            event.body,
            reply_to=MessageId(event.reply_to),
        )
        self.mailbox.post(env, now, event.ttl, event.await_reply)
        self._schedule_retry()
        self._schedule_reap()

    def _on_sync_peers(self, event: _SyncPeers) -> None:
        self._do_sync(event.peers, event.authorized)
        for pk in event.peers:
            peer = self.peers.get(pk)
            if peer is not None:
                self._dial_peer(peer)

    def _on_add_peer(self, event: _AddPeer) -> None:
        self._do_add_peer(event.pubkey, event.endpoints)
        peer = self.peers.get(event.pubkey)
        if peer is not None:
            self._dial_peer(peer)

    def _on_remove_peer(self, event: _RemovePeer) -> None:
        self._do_remove_peer(event.pubkey)

    def _on_frame_in(self, event: _FrameIn) -> None:
        self._do_deliver(event.frame, event.link, Millis.now())

    def _on_link_up(self, event: _LinkUp) -> None:
        self._do_link_established(event.link)

    def _on_link_down(self, event: _LinkDown) -> None:
        self._do_link_died(event.link)
        if event.link.identity is not None:
            peer = self.peers.get(event.link.identity)
            if peer is not None:
                self._dial_peer(peer)

    def _on_link_broken(self, event: _LinkBroken) -> None:
        self._do_link_broken(event.address, Millis.now())

    def _on_retry_due(self, _event: _RetryDue) -> None:
        self._retry_timer = None
        now = Millis.now()
        for t in self.mailbox.due(now):
            peer = self.peers.get(t.to)
            if peer is None:
                self.mailbox.failed(t.prefix, retry_at(self.tunables, t.attempt, now))
                continue
            self._act(
                plan_next(self.tunables, peer, t.attempt, now, self.mailbox.deadline(t.prefix)),
                t,
                now,
            )
        self._schedule_retry()

    def _on_reap_check(self, _event: _ReapCheck) -> None:
        self._reap_timer = None
        now = Millis.now()
        expired = self._reap(now)
        if expired:
            self.on_output(Output(delivered=(), expired=expired))
        self._schedule_reap()

    def _on_maintain_links(self, _event: _MaintainLinks) -> None:
        self._link_timer = None
        self._maintain_links()
        self._schedule_link_maintenance()

    def _on_broadcast(self, event: _Broadcast) -> None:
        now = Millis.now()
        for pub in self.peers:
            mid = MessageId.random()
            env = Envelope(
                pub,
                event.verb,
                MessageId(mid + b"\x00"),
                event.body,
                reply_to=MessageId(b""),
            )
            self.mailbox.post(env, now, event.ttl, False)
        self._schedule_retry()
        self._schedule_reap()

    # -- timer scheduling (postman thread only) ----------------------------

    def _schedule_retry(self) -> None:
        if self._retry_timer is not None:
            self._retry_timer.cancel()
            self._retry_timer = None
        earliest: Millis | None = None
        for p in self.mailbox.pending.values():
            if (
                p.envelope is not None
                and not p.in_flight
                and p.next_at < p.deadline
                and (earliest is None or p.next_at < earliest)
            ):
                earliest = p.next_at
        if earliest is not None:
            self._retry_timer = self._loop.schedule(earliest, _RetryDue())

    def _schedule_reap(self) -> None:
        if self._reap_timer is not None:
            self._reap_timer.cancel()
            self._reap_timer = None
        earliest: Millis | None = None
        for p in self.mailbox.pending.values():
            if earliest is None or p.deadline < earliest:
                earliest = p.deadline
        if earliest is not None:
            self._reap_timer = self._loop.schedule(earliest, _ReapCheck())

    def _schedule_link_maintenance(self) -> None:
        if self._link_timer is not None:
            self._link_timer.cancel()
        interval = self.tunables.tick_interval * 10
        self._link_timer = self._loop.schedule(Millis.now() + interval, _MaintainLinks())

    # -- peer management (postman thread only) ------------------------------

    def _do_sync(
        self,
        wanted_peers: dict[crypto.PublicKey, tuple[Endpoint, ...]],
        authorized: frozenset[crypto.PublicKey],
    ) -> None:
        self._authorized = authorized
        gone = [pk for pk in self.peers if pk not in wanted_peers and pk not in authorized]
        for pk in gone:
            self._do_remove_peer(pk)
        for pk, endpoints in wanted_peers.items():
            self._do_add_peer(pk, endpoints)

    def _do_add_peer(self, pubkey: crypto.PublicKey, endpoints: tuple[Endpoint, ...]) -> None:
        peer = self.peers.get(pubkey)
        if peer is None:
            peer = Peer(pubkey, self.tunables)
            self.peers[pubkey] = peer
        peer.reconfigure(endpoints)

    def _do_remove_peer(self, pubkey: crypto.PublicKey) -> None:
        peer = self.peers.pop(pubkey, None)
        if peer is not None:
            peer.disconnect()

    def _do_link_established(self, link: Link) -> None:
        if link.identity is None:
            for peer in self.peers.values():
                if link.address in peer.dial_targets:
                    link.bind(peer.identity)
                    break
        if link.identity is None:
            return
        peer = self.peers.get(link.identity)
        if peer is None:
            if link.identity not in self._authorized:
                link.close()
                return
            peer = Peer(link.identity, self.tunables)
            self.peers[link.identity] = peer
        if link not in peer.links:
            peer.links.append(link)

    def _do_link_died(self, link: Link) -> None:
        if link.identity is None:
            return
        peer = self.peers.get(link.identity)
        if peer is None:
            return
        peer.links = [ln for ln in peer.links if ln is not link]

    # -- inbound frame processing (postman thread only) ---------------------

    def _do_deliver(self, frame: Frame, link: Link, now: Millis) -> None:
        if not frame.addressed_to(self.me.public):
            return
        try:
            env = frame.unseal(self.me)
            env.accept(self.me.public, now, self.tunables.window)
        except (EnvelopeError, DudeError):
            return

        reply = self.mailbox.arrived(env, now)
        solicited = reply is not None

        if solicited:
            self._credit(env.frm, reply, now)
        elif env.frm not in self.peers and env.frm not in self._authorized:
            link.close()
            return

        if link.identity is None:
            link.bind(env.frm)
            self._do_link_established(link)

        reply_to = env.env.reply_to
        out = Output(
            delivered=(
                Delivered(
                    frm=env.frm,
                    verb=env.env.verb,
                    body=env.env.body,
                    mid=env.env.mid,
                    in_reply_to=MessageId(reply_to) if reply_to else None,
                ),
            ),
            expired=(),
        )
        self.on_output(out)

    # -- link maintenance (postman thread only) ----------------------------

    def _dial_peer(self, peer: Peer) -> None:
        desired = self.tunables.desired_links_per_peer
        if len(peer.links) >= desired:
            return
        for address in peer.dial_targets:
            if any(ln.address == address for ln in peer.links):
                continue
            for dialer in self._dialers:
                if dialer.dial(address):
                    break

    def _maintain_links(self) -> None:
        for peer in self.peers.values():
            self._dial_peer(peer)

    def _do_link_broken(self, address: Address, now: Millis) -> None:
        for peer in self.peers.values():
            for link in peer.links:
                if link.address == address:
                    link.on_expired(now)
        self.mailbox.failed_on(address, retry_at(self.tunables, 0, now))
        self._schedule_retry()

    # -- send / retry machinery (postman thread only) ----------------------

    def _act(self, decision: Decision, t: Transmit, now: Millis) -> None:
        match decision:
            case GiveUp():
                self.mailbox.failed(t.prefix, now)
            case Wait(until=until):
                self.mailbox.failed(t.prefix, until)
            case Send(link=link, again_at=again_at):
                env = Envelope(
                    t.envelope.to,
                    t.envelope.verb,
                    MessageId(t.prefix).with_attempt(t.attempt),
                    t.envelope.body,
                    t.envelope.reply_to,
                )
                stamped = env.sign(self.me, now)
                if link.send(stamped.seal(), now) is None:
                    self.mailbox.sent(t.prefix, t.attempt, link.address, now, again_at=again_at)
                else:
                    self.mailbox.failed(t.prefix, retry_at(self.tunables, t.attempt, now))

    def _credit(self, frm: crypto.PublicKey, reply: Reply, now: Millis) -> None:
        peer = self.peers.get(frm)
        if peer is None:
            return
        if reply.address is None:
            for link in peer.links:
                link.on_reply(now, None)
            return
        for link in peer.links:
            if link.address == reply.address:
                link.on_reply(now, reply.rtt)
                return

    def _reap(self, now: Millis) -> tuple[Expired, ...]:
        done = self.mailbox.expired(now)
        for e in done:
            peer = self.peers.get(e.to)
            if peer is None or e.address is None:
                continue
            for link in peer.links:
                if link.address == e.address:
                    link.on_expired(now)
                    break
        return done
