# dude.net.round_adapter -- bridges Round's abstract protocol to the wire.
#
# ROUND OWNS ITS MESSAGES; THIS MODULE OWNS THEIR ENCODING. The two verbs (`HELD`, `SIG`) live in
# `dude.net.Verb` because that is where the wire vocabulary lives; their bodies are encoded here
# because that is where the boundary between abstract-messages and byte-frames belongs.
#
# STATELESS. This is a translation layer, not a coordinator. It does not know which Round instance
# an incoming message belongs to -- that mapping is bucket -> Round and it belongs to the
# `Coordinator` (Phase 6). The three functions here are pure:
#
#     encode(msg)       RoundMsg    -> (Verb, body_bytes)
#     decode(verb, body) (Verb, bytes) -> RoundMsg
#     bucket_of(body)   body_bytes  -> Bucket    (peek without full decode, so the Coordinator can
#                                                 dispatch to the right Round instance)
#
# The `RoundAdapter` class is a thin composition: hold a Postman, encode outbound to envelopes,
# expose `deliver` for inbound. It could be free functions; the class exists because the flush path
# needs the keypair + peer set + TTL together, and passing that three-tuple every call reads badly.

from __future__ import annotations

from ..core import codec, crypto
from ..core.errors import DudeError
from ..net.envelope import Envelope, MessageId, SignedEnvelope, Verb, new_message_id
from ..net.postman import Postman
from .round import Bucket, Held, Recipient, Round, RoundMsg, Sig, Target

type Millis = int


class RoundAdapterError(DudeError):
    """A wire message that names a Round verb but is not one -- malformed body, wrong shape.

    Not for a `Sig` whose signature does not verify (that is Round's own concern, checked in
    `Round.receive`), and not for a foreign-bucket message (Round drops those silently). This is
    for messages that could not have come from an honest peer using the same protocol at all."""


# --------------------------------------------------------------------------------------------- #
# Encoding                                                                                      #
# --------------------------------------------------------------------------------------------- #


def encode(msg: RoundMsg) -> tuple[Verb, bytes]:
    """A Round message to its wire form: `(verb, body_bytes)`. The bucket travels IN THE BODY,
    not as a separate wire field, because a Round instance's bucket check is what makes an
    envelope's `to` field the only routing key at the transport layer."""
    if isinstance(msg, Held):
        return Verb.HELD, codec.encode([msg.bucket, sorted(msg.hashes)])
    return Verb.SIG, codec.encode([msg.bucket, msg.slice_hash, msg.sig])


def decode(verb: Verb, body: bytes) -> RoundMsg:
    """The inverse of `encode`. Raises `RoundAdapterError` on malformed body; the caller is
    expected to be inside the crash-only boundary that already catches `DudeError`."""
    try:
        if verb is Verb.HELD:
            p = codec.as_seq(codec.decode(body), 2)
            hashes = frozenset(crypto.Digest(codec.as_bytes(h)) for h in codec.as_seq(p[1]))
            return Held(bucket=codec.as_int(p[0]), hashes=hashes)
        if verb is Verb.SIG:
            p = codec.as_seq(codec.decode(body), 3)
            return Sig(
                bucket=codec.as_int(p[0]),
                slice_hash=crypto.Digest(codec.as_bytes(p[1])),
                sig=crypto.Signature(codec.as_bytes(p[2])),
            )
    except DudeError as e:
        raise RoundAdapterError(f"malformed {verb.name} body: {e}") from e
    raise RoundAdapterError(f"not a Round verb: {verb.name}")


def bucket_of(body: bytes) -> Bucket:
    """The bucket named in a Round-verb body, extracted without fully decoding. The `HELD` and
    `SIG` shapes both start with an int bucket, so this is a single decode + read. Used by the
    Coordinator to route the message to the right Round instance before doing full validation."""
    try:
        p = codec.as_seq(codec.decode(body))
        return codec.as_int(p[0])
    except DudeError as e:
        raise RoundAdapterError(f"cannot read bucket from body: {e}") from e


# --------------------------------------------------------------------------------------------- #
# The adapter                                                                                   #
# --------------------------------------------------------------------------------------------- #


class RoundAdapter:
    """Send Round outbound messages via a Postman; deliver inbound envelopes to a Round.

    NOT a Coordinator -- this class holds no Round-instance-per-bucket mapping. Callers hand a
    specific `Round` to `flush` and `deliver`; the Coordinator's job (Phase 6) is deciding which
    Round that is."""

    def __init__(self, me: crypto.Keypair, postman: Postman, ttl: Millis) -> None:
        self.me = me
        self.postman = postman
        self.ttl = ttl

    def flush(self, round_: Round, now: Millis) -> None:
        """Drain a Round's outbox, encode each message, post to the mailbox.

        `HELD` and `SIG` are BROADCASTS by nature -- Round emits `(Recipient.ALL, msg)` -- but
        this method preserves whatever target the Round used, in case a future scenario adds
        directed sends (e.g., a "please retransmit" request to one peer)."""
        for target, msg in round_.outbox():
            verb, body = encode(msg)
            for peer in _resolve(target, self.postman, self.me.public):
                env = Envelope(peer, verb, new_message_id(), body).sign(self.me, now)
                # No answer is awaited: `HELD` and `SIG` are not correlated by mid. Convergence
                # is by observation over the collect window, not by request/reply.
                self.postman.mailbox.post(env, now, self.ttl, await_reply=False)

    def deliver(self, env: SignedEnvelope, round_: Round, now: Millis) -> None:
        """One inbound envelope carrying a Round verb -> the matching Round instance.

        The envelope's `frm` becomes Round's `from_`. Round verifies the message's own signature
        (`Sig` bodies are signed independently of the envelope), verifies bucket, and updates
        state. Foreign-bucket and bad-sig drops happen inside Round; this method just decodes and
        hands over."""
        round_.receive(decode(env.env.verb, env.env.body), from_=env.frm, now=now)


def _resolve(target: Target, postman: Postman, me: crypto.PublicKey) -> list[crypto.PublicKey]:
    """Expand a `Target` into concrete peer keys via the Postman's known peer set."""
    if target is Recipient.ALL:
        return [p for p in postman.peers if p != me]
    return [target] if target != me else []


__all__ = ["MessageId", "RoundAdapter", "RoundAdapterError", "bucket_of", "decode", "encode"]
