from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum

from ..core import crypto
from ..core.units import Millis
from .address import Address
from .envelope import MessageId, SignedEnvelope


class Expiry(Enum):
    UNDELIVERED = "undelivered"
    UNANSWERED = "unanswered"


@dataclass(frozen=True, slots=True)
class Transmit:
    to: crypto.PublicKey
    envelope: SignedEnvelope
    mid: MessageId
    attempt: int


@dataclass(frozen=True, slots=True)
class Attempt:
    address: Address
    sent_at: Millis
    ts: int


@dataclass(frozen=True, slots=True)
class Reply:
    mid: MessageId
    address: Address | None
    rtt: Millis | None


@dataclass(frozen=True, slots=True)
class Expired:
    mid: MessageId
    to: crypto.PublicKey
    why: Expiry
    attempts: int
    address: Address | None = None
    """The link this expiry may be CHARGED to. Set ONLY when exactly one attempt was made:
    charging an unattributable expiry lets a healthy link accumulate another's failures until
    the breaker opens on the wrong one."""


@dataclass(slots=True)
class _Pending:
    envelope: SignedEnvelope | None

    to: crypto.PublicKey
    deadline: Millis
    next_at: Millis
    attempts: tuple[Attempt, ...] = ()
    in_flight: bool = False
    awaiting_reply: bool = False


@dataclass(slots=True)
class Mailbox:
    pending: dict[MessageId, _Pending] = field(default_factory=dict)

    def post(
        self,
        envelope: SignedEnvelope,
        now: Millis,
        ttl: Millis,
        await_reply: bool,  # NO DEFAULT: every production request once forgot it, so every
        # solicited answer in the system was served correctly and discarded at the door.
    ) -> None:
        self.pending[envelope.env.mid] = _Pending(
            envelope=envelope,
            to=envelope.env.to,
            deadline=now + ttl,
            next_at=now,
            awaiting_reply=await_reply,
        )

    def expect(self, mid: MessageId, to: crypto.PublicKey, now: Millis, ttl: Millis) -> None:
        self.pending[mid] = _Pending(
            envelope=None,
            to=to,
            deadline=now + ttl,
            next_at=now + ttl,
            in_flight=True,
            awaiting_reply=True,
        )

    def due(self, now: Millis) -> tuple[Transmit, ...]:
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
        p = self.pending.get(mid)
        if p is None:
            return
        p.attempts = (*p.attempts, Attempt(address, now, ts))
        if again_at is not None:
            p.in_flight, p.next_at = False, again_at
            return
        if p.awaiting_reply:
            p.in_flight = True
        else:
            del self.pending[mid]

    def failed(self, mid: MessageId, retry_at: Millis) -> None:
        p = self.pending.get(mid)
        if p is None:
            return
        p.in_flight = False
        p.next_at = retry_at

    def arrived(self, envelope: SignedEnvelope, now: Millis) -> Reply | None:
        reply_to = envelope.env.reply_to
        p = self.pending.get(reply_to) if reply_to else None
        if p is None or p.to != envelope.frm:
            return None
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
        return named[0] if len(named) == 1 else None

    def expired(self, now: Millis) -> tuple[Expired, ...]:
        done: list[Expired] = []
        for mid in sorted((m for m, p in self.pending.items() if now >= p.deadline)):
            p = self.pending.pop(mid)
            n = len(p.attempts)
            why = Expiry.UNANSWERED if n and p.awaiting_reply else Expiry.UNDELIVERED
            charge = p.attempts[0].address if n == 1 else None
            done.append(Expired(mid, p.to, why, n, charge))
        return tuple(done)

    def __len__(self) -> int:
        return len(self.pending)

    def deadline(self, mid: MessageId) -> Millis:
        p = self.pending.get(mid)
        return p.deadline if p else 0

    def outstanding(self) -> tuple[MessageId, ...]:
        return tuple(self.pending)
