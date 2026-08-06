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
#
# Sans-I/O core, one impure edge. Effects go out through transports; events come back in through
# `deliver`.

from __future__ import annotations

from collections.abc import Callable
from dataclasses import dataclass, field
from enum import Enum, auto
from typing import NamedTuple

from ..core import crypto
from ..core.errors import DudeError
from ..core.units import Millis
from .address import Endpoint, Scheme
from .envelope import EnvelopeError, Frame, SignedEnvelope
from .link import LinkTunables, Peer, Transport
from .mailbox import Expired, Mailbox, Reply, Transmit
from .plan import Decision, GiveUp, Plan, Send, Wait


class PostmanError(DudeError):
    """A misconfiguration Postman cannot recover from: an `add_peer` for a scheme with no
    registered dialler, or a transport constructor that itself raised. Not for peer-level
    failures (link down, breaker open) — those are policy outcomes below Postman."""


type Dialler = Callable[[Endpoint, crypto.Keypair], Transport]
"""How Postman obtains a `Transport` for an endpoint. Takes the whole `Endpoint` (so
the transport receives its options) plus the caller's identity (so identity-bound
transports like InProc know who is dialling). Registered per-scheme at module scope
via `register_dialler`, one entry per scheme this build can dial."""


_DIALLERS: dict[Scheme, Dialler] = {}
"""Module-scope scheme->dialler map (#postman-owns-dialling). A deployment fact, not
a per-Postman config. Test builds register INPROC; production builds register TCP/UNIX.
Populated at process startup (or, for tests, at cluster construction) via
`register_dialler(scheme, dialler)`."""


def register_dialler(scheme: Scheme, dialler: Dialler) -> None:
    """Register (or replace) the dialler for `scheme`. Idempotent — re-registering the
    same scheme with the same dialler at test setup is fine."""
    _DIALLERS[scheme] = dialler


def _reset_diallers_for_tests() -> None:
    """Clear the dialler registry. Test-only hook, called by cluster harness setup."""
    _DIALLERS.clear()


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

    Owns peer lifecycle (#postman-owns-dialling). Callers register endpoints via
    `add_peer(pubkey, endpoints)`; Postman looks up the scheme→dialler in the module-scope
    registry and constructs the transport. Nothing outside Postman writes to `peers`."""

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

    def add_peer(self, pubkey: crypto.PublicKey, endpoints: tuple[Endpoint, ...]) -> None:
        """Register or reconfigure a peer with `endpoints` we should try to reach it at.
        Uses the module-scope scheme→dialler map to construct any transports not already
        cached. See #postman-owns-dialling.

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

    def attach_transport(self, scheme: Scheme, transport: Transport) -> None:
        """Inject a pre-constructed transport for `scheme`, bypassing the module-scope
        dialler. Idempotent -- re-attaching the same instance is a no-op; replacing
        with a different instance is an error, because links already built against the
        first transport would silently keep using it.

        THE ASYMMETRY BETWEEN INPROC AND TCP LIVES HERE. The `Dialler` contract
        assumes the endpoint tells the transport how to construct itself: for InProc
        the endpoint's value IS a stable identity, so `dial(endpoint, me)` can
        construct a fresh loopback. For TCP the endpoint tells you where a PEER
        listens, which is unrelated to where WE should listen -- so the caller
        constructs the `TCP(listen_host=..., listen_port=...)` first, then attaches
        it here BEFORE any `add_peer`. Not a workaround; the two carrier shapes just
        genuinely differ."""
        existing = self._transports_by_scheme.get(scheme)
        if existing is transport:
            return
        if existing is not None:
            raise PostmanError(
                f"transport for scheme {scheme.name} already attached; "
                f"replacing it would orphan links already built against the old one"
            )
        self._transports_by_scheme[scheme] = transport

    def _dial(self, endpoint: Endpoint) -> Transport:
        """Look up (or lazily construct) the transport for `endpoint`'s scheme. Cached
        per scheme in `_transports_by_scheme`. Raises `PostmanError` if no dialler is
        registered for the scheme."""
        scheme = endpoint.address.scheme
        transport = self._transports_by_scheme.get(scheme)
        if transport is not None:
            return transport
        dialler = _DIALLERS.get(scheme)
        if dialler is None:
            raise PostmanError(
                f"no dialler registered for scheme {scheme.name}; "
                f"call postman.register_dialler(...) at startup"
            )
        transport = dialler(endpoint, self.me)
        self._transports_by_scheme[scheme] = transport
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
