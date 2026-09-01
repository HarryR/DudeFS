from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum

from ..core import crypto
from ..core.units import Millis
from .address import Address
from .envelope import Envelope, MessageId, SignedEnvelope


class Expiry(Enum):
    UNDELIVERED = "undelivered"
    UNANSWERED = "unanswered"


@dataclass(frozen=True, slots=True)
class Transmit:
    to: crypto.PublicKey
    envelope: Envelope
    prefix: bytes
    attempt: int


@dataclass(frozen=True, slots=True)
class Attempt:
    address: Address
    sent_at: Millis


@dataclass(frozen=True, slots=True)
class Reply:
    prefix: bytes
    address: Address | None
    rtt: Millis | None


@dataclass(frozen=True, slots=True)
class Expired:
    prefix: bytes
    to: crypto.PublicKey
    why: Expiry
    attempts: int
    address: Address | None = None


@dataclass(slots=True)
class _Pending:
    envelope: Envelope | None

    to: crypto.PublicKey
    prefix: bytes
    deadline: Millis
    next_at: Millis
    attempts: dict[int, Attempt] = field(default_factory=dict)
    in_flight: bool = False
    awaiting_reply: bool = False


@dataclass(slots=True)
class Mailbox:
    pending: dict[bytes, _Pending] = field(default_factory=dict)

    def post(
        self,
        envelope: Envelope,
        now: Millis,
        ttl: Millis,
        await_reply: bool,
    ) -> bytes:
        prefix = envelope.mid.correlation_id
        while prefix in self.pending:
            prefix = MessageId.random().correlation_id
        self.pending[prefix] = _Pending(
            envelope=envelope,
            to=envelope.to,
            prefix=prefix,
            deadline=now + ttl,
            next_at=now,
            awaiting_reply=await_reply,
        )
        return prefix

    def expect(self, prefix: bytes, to: crypto.PublicKey, now: Millis, ttl: Millis) -> None:
        self.pending[prefix] = _Pending(
            envelope=None,
            to=to,
            prefix=prefix,
            deadline=now + ttl,
            next_at=now + ttl,
            in_flight=True,
            awaiting_reply=True,
        )

    def due(self, now: Millis) -> tuple[Transmit, ...]:
        out: list[Transmit] = []
        for prefix, p in sorted(self.pending.items(), key=lambda kv: (kv[1].deadline, kv[0])):
            if p.envelope is None or p.in_flight or now < p.next_at or now >= p.deadline:
                continue
            p.in_flight = True
            out.append(Transmit(p.to, p.envelope, prefix, len(p.attempts)))
        return tuple(out)

    def sent(
        self,
        prefix: bytes,
        attempt: int,
        address: Address,
        now: Millis,
        again_at: Millis | None = None,
    ) -> None:
        p = self.pending.get(prefix)
        if p is None:
            return
        p.attempts[attempt] = Attempt(address, now)
        if again_at is not None:
            p.in_flight, p.next_at = False, again_at
            return
        if p.awaiting_reply:
            p.in_flight = True
        else:
            del self.pending[prefix]

    def failed(self, prefix: bytes, retry_at: Millis) -> None:
        p = self.pending.get(prefix)
        if p is None:
            return
        p.in_flight = False
        p.next_at = retry_at

    def arrived(self, envelope: SignedEnvelope, now: Millis) -> Reply | None:
        reply_to = envelope.env.reply_to
        if len(reply_to) != MessageId.SIZE:
            return None
        mid = MessageId(reply_to)
        p = self.pending.get(mid.correlation_id)
        if p is None or p.to != envelope.frm:
            return None
        del self.pending[mid.correlation_id]
        attempt = p.attempts.get(mid.attempt)
        if attempt is None:
            return Reply(mid.correlation_id, None, None)
        return Reply(mid.correlation_id, attempt.address, now - attempt.sent_at)

    def failed_on(self, address: Address, retry_at: Millis) -> int:
        hit = 0
        for p in self.pending.values():
            if not p.in_flight or not p.attempts:
                continue
            last = p.attempts[max(p.attempts)]
            if last.address == address:
                p.in_flight, p.next_at = False, retry_at
                hit += 1
        return hit

    def expired(self, now: Millis) -> tuple[Expired, ...]:
        done: list[Expired] = []
        for prefix in sorted(m for m, p in self.pending.items() if now >= p.deadline):
            p = self.pending.pop(prefix)
            n = len(p.attempts)
            why = Expiry.UNANSWERED if n and p.awaiting_reply else Expiry.UNDELIVERED
            charge = next(iter(p.attempts.values())).address if n == 1 else None
            done.append(Expired(prefix, p.to, why, n, charge))
        return tuple(done)

    def __len__(self) -> int:
        return len(self.pending)

    def deadline(self, prefix: bytes) -> Millis:
        p = self.pending.get(prefix)
        return p.deadline if p else Millis(0)

    def outstanding(self) -> tuple[bytes, ...]:
        return tuple(self.pending)
