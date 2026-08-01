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

from dataclasses import dataclass, field
from enum import Enum, auto
from typing import NamedTuple

from ..core import crypto
from ..core.units import Millis
from .envelope import EnvelopeError, Frame, SignedEnvelope, seal, unseal
from .link import Link, Peer
from .mailbox import Expired, Mailbox, Reply, Transmit
from .plan import Decision, GiveUp, Plan, Send, Wait


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


@dataclass(frozen=True, slots=True)
class Sample:
    """What a round produced for one link. Handed to the link's policies by `Postman`, which is the
    only object that can decide attribution — it alone sees both the message and the paths."""

    link: Link
    rtt: Millis | None


@dataclass(slots=True)
class Postman:
    """Drives the mailbox and the peers. Holds the keypair, reads the clock, performs the I/O."""

    me: crypto.Keypair
    mailbox: Mailbox = field(default_factory=Mailbox)
    peers: dict[crypto.PublicKey, Peer] = field(default_factory=dict)
    window: Millis = 5_000
    """The conversation window a receiver will apply to us — see `SignedEnvelope.fresh`."""

    plan: Plan = field(default_factory=Plan)
    """The policy. `Postman` decides NOTHING — it asks, executes, and reports. The stagger delay and
    the give-up-when-no-links case used to be inline here; both were policy smuggled into the
    executor, and both now live in `Plan` where they can be tested without a socket."""

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
                    if link.send(seal(stamped), now) is None:
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
        env = unseal(frame, self.me)
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
