# dude.net.mailbox — what to send, where to try next, when to give up. SPEC.md (#peer-not-path).
#
# SANS-I/O: it emits `Transmit` effects and consumes events (`sent`, `failed`, `arrived`, time).
# Two things fall out. Failure, partition, timeout and retry become values a test constructs
# rather than an environment it arranges; and MULTI-HOMING lives here rather than in any carrier —
# a link errors, the message goes back in the box, the next address is tried, and the failed one
# may be tried again later.
#
# TWO EXPIRIES, DELIBERATELY NOT ONE (and the second is never transmitted):
#
#   conversation window   on the envelope, checked by the RECEIVER: "are we in sync right now".
#                         Per ATTEMPT — a retransmit restamps, so this cannot expire a message the
#                         mailbox still wants to send.
#   deadline              here only: "how long do I keep trying". Per MESSAGE, across attempts.
#                         Putting it on the wire would be a second expiry with no consumer.
#
# NO REQUEST/REPLY TYPE, and this is the load-bearing decision. A sender cannot distinguish "it
# died", "it declined to answer" and "the reply was lost", so a type separating them would be
# fabricating information. Everything is one-way; `expect()` registers interest with a deadline and
# the absence of a reply is an ordinary `Expired`. An RPC type would hide the same case behind a
# timeout it still had to implement.

from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum

from ..core import crypto
from ..core.units import Millis
from .address import Address
from .envelope import MessageId, SignedEnvelope


class Expiry(Enum):
    """Why the mailbox stopped caring. Named, because "no answer" and "nowhere to send it" are
    different operational problems and a log line saying only "timeout" conflates them."""

    UNDELIVERED = "undelivered"
    """The deadline passed with every address having failed, or none to try."""
    UNANSWERED = "unanswered"
    """It went out, and no reply came before the deadline. Indistinguishable from a dead peer, a
    silent peer, and a lost reply — which is exactly why they share one outcome."""


@dataclass(frozen=True, slots=True)
class Transmit:
    """An effect: hand these bytes to this address. The mailbox never does this itself."""

    to: crypto.PublicKey
    envelope: SignedEnvelope
    mid: MessageId
    attempt: int
    """How many transmissions have already been made. Carried so the executor can hand it to
    `Plan` — the mailbox records it and draws no conclusion from it."""


@dataclass(frozen=True, slots=True)
class Attempt:
    """One transmission: which link it went out on, when, and under what stamp.

    `ts` is the stamp the DRIVER actually signed, reported back through `sent()` — not the stamp on
    the envelope the mailbox handed out. A retransmit restamps, so only the driver knows, and it is
    the value a reply's `reply_ts` will echo."""

    address: Address
    sent_at: Millis
    ts: int


@dataclass(frozen=True, slots=True)
class Reply:
    """A correlated reply, and what may be believed about it.

    `address is None` and `rtt is None` together mean UNATTRIBUTABLE (#rtt-attribution): the
    reply is real and proves liveness, but no link may be charged or credited for it. Both are
    `None` or neither — a link without a time, or a time without a link, would be meaningless."""

    mid: MessageId
    address: Address | None
    rtt: Millis | None


@dataclass(frozen=True, slots=True)
class Expired:
    """An outcome: this message is over."""

    mid: MessageId
    to: crypto.PublicKey
    why: Expiry
    attempts: int
    address: Address | None = None
    """The link this expiry may be CHARGED to, or `None` when it may be charged to nothing.

    Set only when exactly one attempt was made, so §3.3's rule is decided here — where the attempt
    record lives — rather than by a caller that would have to re-derive it. Charging an
    unattributable expiry would let a healthy link accumulate another's failures until the breaker
    opened on the wrong one."""


@dataclass(slots=True)
class _Pending:
    envelope: SignedEnvelope | None
    """`None` for an await-only entry (`expect`), which genuinely has nothing to send. Explicitly
    optional rather than a `type: ignore` over a lie — `due()` skips these by testing it."""

    to: crypto.PublicKey
    deadline: Millis
    next_at: Millis
    attempts: tuple[Attempt, ...] = ()
    """Every transmission of this message, in order. THE bookkeeping that makes attribution
    possible: a reply can only be matched to a link if there is a record of which link carried
    which stamp."""
    in_flight: bool = False
    awaiting_reply: bool = False


@dataclass(slots=True)
class Mailbox:
    """Outbound messages and the policy for getting them somewhere.

    One instance per node. Holds no lock and no socket; a driver polls `due()`, performs the
    transmits, and reports back with `sent` / `failed`."""

    pending: dict[MessageId, _Pending] = field(default_factory=dict)

    # -- posting ------------------------------------------------------------------------------- #

    def post(
        self,
        envelope: SignedEnvelope,
        now: Millis,
        ttl: Millis,
        await_reply: bool,
    ) -> None:
        """Queue a message.

        NO ADDRESSES. Which paths exist and which to use is `Peer`/`Plan`'s business — this object
        holds state and therefore holds no policy. It used to take them, and the duplication with
        `Peer` that produced is what the split exists to remove.

        `await_reply` says the caller cares about an answer — the ONLY place request/reply exists,
        and it is a sender-side intention rather than a property of the message. The receiver cannot
        tell, and nothing on the wire records it.

        NO DEFAULT `[H]`, and it had one. Every production caller took it, so every request's entry
        was deleted the moment the bytes left (`sent`), so every answer arrived uncorrelated and was
        dropped by `Node.SOLICITED` as unsolicited. `PULL`, `SUBTREE` and `LEAVES` were all posted
        that way: the questions went out, the answers were served correctly, and the asker threw
        every one of them away. Nothing errored, so a node simply never caught up and never walked —
        the exact signature of a quiet network.

        A default that is right for one caller and silently wrong for another is not a default. This
        is the same medicine as `Held.cred`: make the wrong thing unsayable rather than merely
        discouraged, so the next caller is asked the question at the point of writing it."""
        self.pending[envelope.env.mid] = _Pending(
            envelope=envelope,
            to=envelope.env.to,
            deadline=now + ttl,
            next_at=now,
            awaiting_reply=await_reply,
        )

    def expect(self, mid: MessageId, to: crypto.PublicKey, now: Millis, ttl: Millis) -> None:
        """Await a reply to a message sent by some other means — no transmits, just a deadline.

        Keeps "I am waiting for this" in one place rather than scattering timers through callers."""
        self.pending[mid] = _Pending(
            envelope=None,
            to=to,
            deadline=now + ttl,
            next_at=now + ttl,
            in_flight=True,
            awaiting_reply=True,
        )

    # -- the driver loop ------------------------------------------------------------------------ #

    def due(self, now: Millis) -> tuple[Transmit, ...]:
        """What should go out right now, restamped and re-signed by the caller if it must be.

        NOTE the envelope is emitted as-is: stamping IS signing (`Envelope.sign(kp, now)`), which
        needs the keypair, and the mailbox holds no secrets. A driver that retries a stale frame has
        it refused by the receiver's window — visibly, which beats a mailbox quietly holding signing
        authority."""
        # SORTED BY DEADLINE, explicitly. The returned order is one a driver acts on, so it must not
        # be mapping order: Python preserves insertion, Go randomises, Rust's HashMap is arbitrary.
        # Soonest deadline first, because that is the message with least room left to be retried.
        out: list[Transmit] = []
        for mid, p in sorted(self.pending.items(), key=lambda kv: (kv[1].deadline, kv[0])):
            if p.envelope is None or p.in_flight or now < p.next_at or now >= p.deadline:
                continue
            p.in_flight = True
            out.append(Transmit(p.to, p.envelope, mid, len(p.attempts)))
        return tuple(out)

    def sent(
        self,
        mid: MessageId,
        address: Address,
        ts: int,
        now: Millis,
        again_at: Millis | None = None,
    ) -> None:
        """A transmit succeeded at the link level. Which means only that the bytes left — not that
        anybody received them, and certainly not that anybody acted on them.

        `ts` is the stamp the driver signed. The mailbox holds no keypair, so it cannot restamp and
        therefore cannot know it; asking for it back is what keeps signing authority out of here
        while still allowing per-attempt attribution."""
        p = self.pending.get(mid)
        if p is None:
            return
        p.attempts = (*p.attempts, Attempt(address, now, ts))
        if again_at is not None:
            # A STAGGER, not a retry: this attempt is still outstanding and another link should be
            # tried anyway (R7). The distinction matters because a retry replaces a failed attempt
            # while a stagger adds to a live one, and only the caller knows which this is — how many
            # links to use and how long to wait are Peer's policy, not the mailbox's.
            p.in_flight, p.next_at = False, again_at
            return
        if p.awaiting_reply:
            p.in_flight = True  # nothing more to send; the deadline is now the only clock
        else:
            del self.pending[mid]

    def failed(self, mid: MessageId, retry_at: Millis) -> None:
        """An attempt did not happen, or the link errored. Back in the box until `retry_at`.

        `retry_at` is COMPUTED BY THE CALLER (`Plan.retry_at`) and merely stored here. The mailbox
        used to own a `backoff` constant, which is policy sitting next to state — exactly the shape
        that made this object start reaching for addresses."""
        p = self.pending.get(mid)
        if p is None:
            return
        p.in_flight = False
        p.next_at = retry_at

    def arrived(self, envelope: SignedEnvelope, now: Millis) -> Reply | None:
        """An inbound envelope. If it answers something outstanding, retire that entry and report
        what may be believed about it; otherwise `None`, and the caller treats it as unsolicited.

        ATTRIBUTION, in the order the rules apply (#rtt-attribution):

        1. **One attempt outstanding** — unambiguous by construction. Karn is satisfied with no
           echo at all, so a peer that never sets `reply_ts` still yields samples on that path.
        2. **Several attempts, and `reply_ts` names exactly one** — recovered. This is the whole
           purpose of the field: it identifies the transmission, and since each went out on a known
           link it identifies the link too.
        3. **Anything else** — unattributable. Returned with both fields `None` rather than guessed
           at, because a wrong sample is worse than no sample: it charges one link for another's
           latency, and R3's estimator has no way to notice.

        Correlation itself is by `mid` and NEVER by the link it arrived on (R1) — send on A, receive
        on B is ordinary traffic. `SignedEnvelope.accept` has already established that it is
        addressed to us, fresh, correctly signed, and echoes the right id.

        AND BY THE PEER WE ASKED `[H]`, which it was not. SPEC states the rule and the reason
        (#peer-not-path) —
        *"the dedup key is `(frm, mid)`, never `mid` alone... `mid` is chosen by the sender"* — and
        `arrived` popped on the id alone, so ANY identity that learned an outstanding id could have
        its answer taken as solicited. Frames are sealed, so an id is not observable; but the peer
        we asked knows it, and can pass it on. That matters most where a reply is not otherwise
        verifiable: a `HASHES` answer steers a state walk, and `SOLICITED` is all that stands
        between it and a stranger.

        The table is keyed by id because these ids are OURS — we generate them, so they do not
        collide. The binding that matters is the destination, checked here."""
        reply_to = envelope.env.reply_to
        p = self.pending.get(reply_to) if reply_to else None
        if p is None or p.to != envelope.frm:
            return None  # nobody asked THEM, whatever they are echoing
        del self.pending[reply_to]
        match = self._attribute(p, envelope.env.reply_ts)
        if match is None:
            return Reply(reply_to, None, None)
        return Reply(reply_to, match.address, now - match.sent_at)

    @staticmethod
    def _attribute(p: _Pending, reply_ts: int) -> Attempt | None:
        if len(p.attempts) == 1:
            return p.attempts[0]
        if not reply_ts:
            return None
        named = [a for a in p.attempts if a.ts == reply_ts]
        # Exactly one, or nothing. Two attempts sharing a stamp — same millisecond — are as
        # ambiguous as no stamp at all, so this refuses rather than taking the first.
        return named[0] if len(named) == 1 else None

    def expired(self, now: Millis) -> tuple[Expired, ...]:
        """Deadlines that have fired, removed from the box.

        One method for both flavours because they are the same clock: a message nobody would take
        and a message nobody answered both end here."""
        done: list[Expired] = []
        # Sorted for the same reason `due` is: the returned tuple's order is observable.
        for mid in sorted((m for m, p in self.pending.items() if now >= p.deadline)):
            p = self.pending.pop(mid)
            n = len(p.attempts)
            why = Expiry.UNANSWERED if n and p.awaiting_reply else Expiry.UNDELIVERED
            charge = p.attempts[0].address if n == 1 else None
            done.append(Expired(mid, p.to, why, n, charge))
        return tuple(done)

    # -- introspection -------------------------------------------------------------------------- #

    def __len__(self) -> int:
        return len(self.pending)

    def deadline(self, mid: MessageId) -> Millis:
        """When this message stops being worth attempting. Exposed because `Plan` needs it and the
        mailbox is where it is stored — reading state is not the same as owning policy."""
        p = self.pending.get(mid)
        return p.deadline if p else 0

    def outstanding(self) -> tuple[MessageId, ...]:
        return tuple(self.pending)
