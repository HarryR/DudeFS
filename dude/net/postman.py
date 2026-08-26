
import contextlib
from mailbox import Message
import queue
import threading
from collections.abc import Iterable, Iterator
from dataclasses import dataclass, field
from enum import Enum, auto
from typing import NamedTuple, Protocol

from ..core import crypto
from ..core.errors import DudeError
from ..core.units import Millis, now_ms
from ..tunables import Tunables
from .address import Address, Endpoint
from .envelope import Envelope, EnvelopeError, Frame, MessageId, Verb
from .link import (
    Link,
    Listener,
    Peer,
)
from .mailbox import Expired, Mailbox, Reply, Transmit
from .plan import Decision, GiveUp, Send, Wait, plan_next, retry_at




class Recipient(Enum):
    ALL = auto()


type Target = crypto.PublicKey | Recipient


def recipients(
    target: Target, roster: Iterable[crypto.PublicKey], me: crypto.PublicKey
) -> list[crypto.PublicKey]:
    if target is Recipient.ALL:
        return [p for p in roster if p != me]
    return [target] if target != me else []


class Encodable(Protocol):
    def encode(self) -> tuple[Verb, bytes]: ...


# ---------------------------------------------------------------------------
# Input events — everything that goes INTO the postman's single queue.
# ---------------------------------------------------------------------------


class _Cmd:
    __slots__ = ()


@dataclass(frozen=True, slots=True)
class _Send(_Cmd):
    to: crypto.PublicKey
    verb: Verb
    body: bytes
    ttl: Millis
    await_reply: bool
    reply_to: bytes
    prefix: bytes


@dataclass(frozen=True, slots=True)
class _Sync(_Cmd):
    peers: dict[crypto.PublicKey, tuple[Endpoint, ...]]
    authorized: frozenset[crypto.PublicKey]


@dataclass(frozen=True, slots=True)
class _AddPeer(_Cmd):
    pubkey: crypto.PublicKey
    endpoints: tuple[Endpoint, ...]


@dataclass(frozen=True, slots=True)
class _RemovePeer(_Cmd):
    pubkey: crypto.PublicKey


@dataclass(frozen=True, slots=True)
class _FrameIn(_Cmd):
    frame: Frame
    link: Link


@dataclass(frozen=True, slots=True)
class _LinkEstablished(_Cmd):
    link: Link


@dataclass(frozen=True, slots=True)
class _LinkDied(_Cmd):
    link: Link


@dataclass(frozen=True, slots=True)
class _LinkBroken(_Cmd):
    address: Address


class _Stop(_Cmd):
    __slots__ = ()


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


# ---------------------------------------------------------------------------
# The actor.
# ---------------------------------------------------------------------------


@dataclass(slots=True)
class Postman:
    me: crypto.Keypair
    tunables: Tunables

    mailbox: Mailbox = field(default_factory=Mailbox)
    peers: dict[crypto.PublicKey, Peer] = field(default_factory=dict)

    _authorized: frozenset[crypto.PublicKey] = field(default_factory=frozenset, init=False)

    _input: queue.SimpleQueue[_Cmd] = field(default_factory=queue.SimpleQueue, init=False)
    _output: queue.SimpleQueue[Output] = field(default_factory=queue.SimpleQueue, init=False)

    _thread: threading.Thread | None = field(default=None, init=False)
    _listeners: list[Listener] = field(default_factory=list, init=False)

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
        self._input.put(_Send(to, verb, body, ttl, True, MessageId(b""), mid))
        return mid

    def reply(self, d: Delivered, msg: Encodable, ttl: Millis) -> MessageId:
        verb, body = msg.encode()
        new_mid = MessageId.random()
        self._input.put(_Send(d.frm, verb, body, ttl, False, d.mid, new_mid))
        return new_mid

    def send_raw(
        self,
        to: crypto.PublicKey,
        verb: Verb,
        body: bytes,
        ttl: Millis,
        await_reply: bool = True,
        reply_to: MessageId = MessageId(b""),
        mid: MessageId | None = None,
    ) -> MessageId:
        if mid is None:
            mid = MessageId.random()
        self._input.put(_Send(to, verb, body, ttl, await_reply, reply_to, mid))
        return mid

    def sync(
        self,
        peers: dict[crypto.PublicKey, tuple[Endpoint, ...]],
        authorized: frozenset[crypto.PublicKey] = frozenset(),
    ) -> None:
        self._input.put(_Sync(peers, authorized))

    def add_peer(self, pubkey: crypto.PublicKey, endpoints: tuple[Endpoint, ...]) -> None:
        self._input.put(_AddPeer(pubkey, endpoints))

    def remove_peer(self, pubkey: crypto.PublicKey) -> None:
        self._input.put(_RemovePeer(pubkey))

    def drain_output(self, timeout: float | None = None) -> Iterator[Output]:
        if timeout is not None:
            try:
                yield self._output.get(timeout=timeout)
            except queue.Empty:
                return
        while True:
            try:
                yield self._output.get_nowait()
            except queue.Empty:
                return

    # -- lifecycle ----------------------------------------------------------

    def add_listener(self, listener: Listener) -> None:
        self._listeners.append(listener)
        if self._thread is not None:
            listener.start(self._on_frame, self._on_link_established)

    def start(self) -> None:
        if self._thread is not None:
            return
        for listener in self._listeners:
            listener.start(self._on_frame, self._on_link_established)
        self._thread = threading.Thread(
            target=self._run,
            name=f"postman-{self.me.public.hex()[:8]}",
            daemon=True,
        )
        self._thread.start()

    def stop(self) -> None:
        self._input.put(_Stop())
        thread = self._thread
        self._thread = None
        if thread is not None:
            thread.join()
        for listener in self._listeners:
            with contextlib.suppress(Exception):
                listener.stop()

    def _run(self) -> None:
        tick_interval = self.tunables.tick_interval / 1000
        while True:
            try:
                cmd = self._input.get(timeout=tick_interval)
            except queue.Empty:
                cmd = None
            if isinstance(cmd, _Stop):
                return
            now = now_ms()
            if cmd is not None:
                self._process(cmd, now)
            self._drain_input(now)
            self._tick(now)

    def _drain_input(self, now: Millis) -> None:
        while True:
            try:
                cmd = self._input.get_nowait()
            except queue.Empty:
                return
            if isinstance(cmd, _Stop):
                self._input.put(cmd)
                return
            self._process(cmd, now)

    # -- transport callbacks (called from transport threads, thread-safe) ----

    def _on_frame(self, frame: Frame, link: Link) -> None:
        self._input.put(_FrameIn(frame, link))

    def _on_link_established(self, link: Link) -> None:
        link.on_close = lambda ln: self._input.put(_LinkDied(ln))
        self._input.put(_LinkEstablished(link))

    # -- command dispatch (runs on the postman's own thread only) -----------

    def _process(self, cmd: _Cmd, now: Millis) -> None:
        match cmd:
            case _Send(to, verb, body, ttl, await_reply, reply_to, prefix):
                env = Envelope(to, verb, MessageId(prefix + b"\x00"), body, reply_to=MessageId(reply_to))
                self.mailbox.post(env, now, ttl, await_reply)
            case _Sync(peers, authorized):
                self._do_sync(peers, authorized)
            case _AddPeer(pubkey, endpoints):
                self._do_add_peer(pubkey, endpoints)
            case _RemovePeer(pubkey):
                self._do_remove_peer(pubkey)
            case _FrameIn(frame, link):
                self._do_deliver(frame, link, now)
            case _LinkEstablished(link):
                self._do_link_established(link)
            case _LinkDied(link):
                self._do_link_died(link)
            case _LinkBroken(address):
                self._do_link_broken(address, now)

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
        else:
            if env.frm not in self.peers and env.frm not in self._authorized:
                link.close()
                return

        if link.identity is None:
            link.bind(env.frm)
            self._do_link_established(link)

        reply_to = env.env.reply_to
        self._output.put(Output(
            delivered=(Delivered(
                frm=env.frm,
                verb=env.env.verb,
                body=env.env.body,
                mid=env.env.mid,
                in_reply_to=MessageId(reply_to) if reply_to else None,
            ),),
            expired=(),
        ))

    def _maintain_links(self) -> None:
        desired = self.tunables.desired_links_per_peer
        for peer in self.peers.values():
            if len(peer.links) >= desired:
                continue
            for address in peer.dial_targets:
                if any(ln.address == address for ln in peer.links):
                    continue
                for listener in self._listeners:
                    listener.dial(address)

    def _do_link_broken(self, address: Address, now: Millis) -> None:
        for peer in self.peers.values():
            for link in peer.links:
                if link.address == address:
                    link.on_expired(now)
        self.mailbox.failed_on(address, retry_at(self.tunables,0, now))

    # -- the tick (postman thread only) -------------------------------------

    def _tick(self, now: Millis) -> None:
        self._maintain_links()
        for t in self.mailbox.due(now):
            peer = self.peers.get(t.to)
            if peer is None:
                self.mailbox.failed(t.prefix, retry_at(self.tunables,t.attempt, now))
                continue
            self._act(plan_next(self.tunables,peer, t.attempt, now, self.mailbox.deadline(t.prefix)), t, now)
        expired = self._reap(now)
        if expired:
            self._output.put(Output(delivered=(), expired=expired))

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
                    self.mailbox.sent(
                        t.prefix, t.attempt, link.address, now, again_at=again_at
                    )
                else:
                    self.mailbox.failed(t.prefix, retry_at(self.tunables,t.attempt, now))

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
