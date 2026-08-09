from __future__ import annotations

from dataclasses import dataclass
from enum import IntEnum
from typing import Self

from ..core import codec, crypto
from ..core.errors import DudeError


class EnvelopeError(DudeError): ...


class Verb(IntEnum):
    PING = 1
    PONG = 2

    SUBMIT = 10
    ACCEPTED = 11
    """Admitted to my mempool, and NOTHING more -- not included, not settled, not durable."""

    BODIES = 13

    HELD = 22
    SIG = 23

    SETTLE_SIG = 24

    HEIGHT = 30
    HEIGHT_REPLY = 31
    GETBLOCK = 32
    SETTLED_BLOCK = 33
    SYNC_REFUSED = 34
    """A Node's answer to a Node's GETBLOCK. SEPARATE FROM `REFUSED`, which answers a client's
    SUBMIT: one verb carried both, so the body was a `SyncRefusal` value or a `mempool.Refusal`
    value depending on who sent it and nothing said which. The two value sets merely happened not
    to overlap; both are still growing."""

    GET_ANCHORS = 40
    ANCHORS_REPLY = 41
    GET_PROOF = 42
    PROOF_REPLY = 43
    LITE_REFUSED = 44

    REFUSED = 90
    """A node's answer to a client's SUBMIT, body a `mempool.Refusal` value. Sync refusals are
    `SYNC_REFUSED`."""


type MessageId = bytes
MESSAGE_ID_SIZE = 16

MAX_FRAME_BYTES = 1 << 24
"""CLUSTER-WIDE INVARIANT, not a tunable: two peers with different caps see each other's
well-formed frames as refusals. Big enough for any envelope here, small enough that a stream
advertising "the next frame is 4 GiB" costs a length-word read, not a 4 GiB allocation."""


def new_message_id() -> MessageId:
    return crypto.random_bytes(MESSAGE_ID_SIZE)


@dataclass(frozen=True, slots=True)
class Envelope:
    to: crypto.PublicKey
    verb: Verb
    mid: MessageId
    body: bytes = b""

    reply_to: MessageId = b""

    reply_ts: int = 0
    """The `ts` of the ATTEMPT this answers. Without it Karn's rule discards the RTT sample from
    anything sent more than once, which under multi-homing is most traffic -- the more paths you
    use, the less you know about any of them (#rtt-attribution)."""

    def encode(self) -> bytes:
        return codec.encode(
            [self.to, int(self.verb), self.mid, self.body, self.reply_to, self.reply_ts]
        )

    @classmethod
    def decode(cls, raw: bytes) -> Envelope:
        try:
            f = codec.as_seq(codec.decode(raw), 6)
            to = crypto.PublicKey(codec.as_bytes(f[0]))
            verb_int = codec.as_int(f[1])
            mid = codec.as_bytes(f[2])
            body = codec.as_bytes(f[3])
            reply_to = codec.as_bytes(f[4])
            reply_ts = codec.as_int(f[5])
        except (codec.CodecError, crypto.CryptoError) as exc:
            raise EnvelopeError(f"malformed envelope: {exc}") from exc
        try:
            verb = Verb(verb_int)
        except ValueError as exc:
            raise EnvelopeError(f"unknown verb {verb_int}") from exc
        return cls(to, verb, mid, body, reply_to, reply_ts)

    def sign(self, kp: crypto.Keypair, ts: int) -> SignedEnvelope:
        return SignedEnvelope(kp.public, ts, self, kp.sign(_body_bytes(kp.public, ts, self)))


def _body_bytes(frm: crypto.PublicKey, ts: int, env: Envelope) -> bytes:
    """EVERY field is signed, and `to` especially: without it under the signature, a valid
    envelope can be lifted and re-delivered to someone who never was its recipient."""
    return codec.encode([frm, ts, env.encode()])


@dataclass(frozen=True, slots=True)
class SignedEnvelope:
    frm: crypto.PublicKey
    ts: int
    env: Envelope
    sig: crypto.Signature

    @property
    def _body(self) -> bytes:
        return _body_bytes(self.frm, self.ts, self.env)

    @property
    def raw(self) -> bytes:
        return codec.encode([self._body, self.sig])

    def verify(self) -> bool:
        return self.frm.verify(self._body, self.sig)

    def seal(self) -> Frame:
        sealed = self.env.to.seal(self.raw)
        return Frame(crypto.screen_tag(self.env.to, sealed), sealed)

    def fresh(self, now: int, window: int) -> bool:
        return abs(now - self.ts) <= window

    def answer(self, verb: Verb, body: bytes = b"") -> Envelope:
        return Envelope(self.frm, verb, new_message_id(), body, self.env.mid, self.ts)

    def accept(
        self, me: crypto.PublicKey, now: int, window: int, in_reply_to: MessageId | None = None
    ) -> None:
        if self.env.to != me:
            raise EnvelopeError(f"addressed to {self.env.to.hex()[:8]}, not us")
        if not self.fresh(now, window):
            raise EnvelopeError(
                f"outside the {window}ms conversation window (ts={self.ts}, now={now})"
            )
        if not self.verify():
            raise EnvelopeError(f"signature does not match sender {self.frm.hex()[:8]}")
        if in_reply_to is not None and self.env.reply_to != in_reply_to:
            raise EnvelopeError("reply does not echo the request id it claims to answer")

    @classmethod
    def decode(cls, raw: bytes) -> Self:
        outer = codec.as_seq(codec.decode(raw), 2)
        f = codec.as_seq(codec.decode(codec.as_bytes(outer[0])), 3)
        return cls(
            crypto.PublicKey(codec.as_bytes(f[0])),
            codec.as_int(f[1]),
            Envelope.decode(codec.as_bytes(f[2])),
            crypto.Signature(codec.as_bytes(outer[1])),
        )


def request(
    kp: crypto.Keypair, to: crypto.PublicKey, verb: Verb, ts: int, body: bytes = b""
) -> SignedEnvelope:
    return Envelope(to, verb, new_message_id(), body).sign(kp, ts)


@dataclass(frozen=True, slots=True)
class Frame:
    tag: crypto.ScreenTag
    sealed: crypto.SealedBlob

    @property
    def raw(self) -> bytes:
        return codec.encode([self.tag, self.sealed])

    @classmethod
    def decode(cls, raw: bytes) -> Self:
        f = codec.as_seq(codec.decode(raw), 2)
        return cls(crypto.ScreenTag(codec.as_bytes(f[0])), crypto.SealedBlob(codec.as_bytes(f[1])))

    def addressed_to(self, me: crypto.PublicKey) -> bool:
        return crypto.screen_tag(me, self.sealed) == self.tag

    def unseal(self, kp: crypto.Keypair) -> SignedEnvelope:
        try:
            raw = kp.open_sealed_raw(self.sealed)
        except crypto.SealedBoxError as e:
            raise EnvelopeError("frame would not unseal (not ours, or tampered)") from e
        return SignedEnvelope.decode(raw)
