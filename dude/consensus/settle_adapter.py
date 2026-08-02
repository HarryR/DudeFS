# dude.net.settle_adapter -- bridges SettleRound's abstract protocol to the wire.
#
# SETTLEROUND OWNS ITS MESSAGE; THIS MODULE OWNS ITS ENCODING. The one verb (`SETTLE_SIG`) lives
# in `dude.net.Verb`; its body is encoded here.
#
# STATELESS. Translation layer, not a coordinator. Does not know which SettleRound instance an
# incoming message belongs to -- that mapping is slice_hash -> SettleRound and it belongs to the
# `Coordinator` (Stage 3). Three functions:
#
#     encode(msg)          SettleSig     -> (Verb, body_bytes)
#     decode(verb, body)   (Verb, bytes) -> SettleSig
#     slice_hash_of(body)  body_bytes  -> Digest  (peek without full decode, so the Coordinator
#                                                  can dispatch to the right SettleRound instance)
#
# The `SettleAdapter` class mirrors `RoundAdapter`: hold a Postman, encode outbound to envelopes,
# expose `deliver` for inbound.

from __future__ import annotations

from ..core import codec, crypto
from ..core.errors import DudeError
from ..core.units import Millis
from ..net.envelope import Envelope, SignedEnvelope, Verb, new_message_id
from ..net.postman import Postman
from .settle_round import Anchors, SettleRound, SettleSig


class SettleAdapterError(DudeError):
    """A wire message that names SETTLE_SIG but is not one -- malformed body, wrong shape.

    Not for a `SettleSig` whose signature does not verify (that is SettleRound's own concern),
    and not for a foreign-slice sig (SettleRound drops those silently). For messages that could
    not have come from an honest peer using the same protocol at all."""


# --------------------------------------------------------------------------------------------- #
# Encoding                                                                                      #
# --------------------------------------------------------------------------------------------- #


def encode(msg: SettleSig) -> tuple[Verb, bytes]:
    """A SettleRound message to its wire form: `(verb, body_bytes)`.

    Body layout: `[slice_hash, block_num, height, prev_block, state_root, acc_state, acc_log,
    sig]`. slice_hash comes first because `slice_hash_of` reads only that field to route the
    message."""
    a = msg.anchors
    return Verb.SETTLE_SIG, codec.encode(
        [
            msg.slice_hash,
            a.block_num,
            a.height,
            a.prev_block,
            a.state_root,
            a.acc_state,
            a.acc_log,
            msg.sig,
        ]
    )


def decode(verb: Verb, body: bytes) -> SettleSig:
    """The inverse of `encode`. Raises `SettleAdapterError` on malformed body; the caller is
    expected to be inside the crash-only boundary that catches `DudeError`."""
    if verb is not Verb.SETTLE_SIG:
        raise SettleAdapterError(f"not a SettleRound verb: {verb.name}")
    try:
        p = codec.as_seq(codec.decode(body), 8)
        return SettleSig(
            slice_hash=crypto.Digest(codec.as_bytes(p[0])),
            anchors=Anchors(
                block_num=codec.as_int(p[1]),
                height=codec.as_int(p[2]),
                prev_block=crypto.Digest(codec.as_bytes(p[3])),
                state_root=crypto.Digest(codec.as_bytes(p[4])),
                acc_state=crypto.Accumulator(codec.as_bytes(p[5])),
                acc_log=crypto.Accumulator(codec.as_bytes(p[6])),
            ),
            sig=crypto.Signature(codec.as_bytes(p[7])),
        )
    except DudeError as e:
        raise SettleAdapterError(f"malformed SETTLE_SIG body: {e}") from e


def slice_hash_of(body: bytes) -> crypto.Digest:
    """The slice_hash named in a SETTLE_SIG body, extracted without fully decoding. Used by the
    Coordinator to route the message to the right SettleRound instance before full validation."""
    try:
        p = codec.as_seq(codec.decode(body))
        return crypto.Digest(codec.as_bytes(p[0]))
    except DudeError as e:
        raise SettleAdapterError(f"cannot read slice_hash from body: {e}") from e


# --------------------------------------------------------------------------------------------- #
# The adapter                                                                                   #
# --------------------------------------------------------------------------------------------- #


class SettleAdapter:
    """Send SettleRound outbound messages via a Postman; deliver inbound envelopes to a
    SettleRound.

    NOT a Coordinator -- this class holds no SettleRound-per-slice mapping. Callers hand a
    specific `SettleRound` to `flush` and `deliver`; the Coordinator's job (Stage 3) is deciding
    which SettleRound that is."""

    def __init__(self, me: crypto.Keypair, postman: Postman, ttl: Millis) -> None:
        self.me = me
        self.postman = postman
        self.ttl = ttl

    def flush(self, round_: SettleRound, now: Millis) -> None:
        """Drain a SettleRound's outbox, encode each message, post to the mailbox.

        `SETTLE_SIG` is a broadcast by nature -- SettleRound emits `(Recipient.ALL, msg)`.
        Preserved as `Target` in case a future scenario adds directed sends."""
        for target, msg in round_.outbox():
            verb, body = encode(msg)
            for peer in self.postman.recipients(target):
                env = Envelope(peer, verb, new_message_id(), body).sign(self.me, now)
                # No answer awaited: convergence is by observation, not by request/reply.
                self.postman.mailbox.post(env, now, self.ttl, await_reply=False)

    def deliver(self, env: SignedEnvelope, round_: SettleRound, now: Millis) -> None:
        """One inbound envelope carrying SETTLE_SIG -> the matching SettleRound instance.

        The envelope's `frm` becomes SettleRound's `from_`. SettleRound verifies the message's
        own signature (SettleSig is signed independently of the envelope), verifies the slice
        binding, and updates state. Foreign-slice and bad-sig drops happen inside SettleRound;
        this method just decodes and hands over."""
        round_.receive(decode(env.env.verb, env.env.body), from_=env.frm, now=now)


__all__ = ["SettleAdapter", "SettleAdapterError", "decode", "encode", "slice_hash_of"]
