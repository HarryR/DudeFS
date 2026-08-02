# dude.consensus.settle_adapter -- Postman binding for SettleRound's protocol message.
#
# SETTLEROUND OWNS ITS MESSAGE AND ITS ENCODING. The one verb (`SETTLE_SIG`) lives in
# `dude.net.Verb`; `SettleSig` owns its own `encode()` / `decode(verb, body)` methods, and the
# `slice_hash_of(body)` peek (see `dude.consensus.settle_round`).
#
# STATELESS. This module is the Postman seam only: flush a SettleRound's outbox as envelopes,
# deliver an inbound envelope to a SettleRound. Slice-to-SettleRound dispatch is NOT this
# module's job -- that is the Coordinator's, via `SettleSig.slice_hash_of` on the raw body.

from __future__ import annotations

from ..core import crypto
from ..core.units import Millis
from ..net.envelope import Envelope, SignedEnvelope, new_message_id
from ..net.postman import Postman
from .settle_round import SettleAdapterError, SettleRound, SettleSig


class SettleAdapter:
    """Send SettleRound outbound messages via a Postman; deliver inbound envelopes to a
    SettleRound.

    NOT a Coordinator -- this class holds no SettleRound-per-slice mapping. Callers hand a
    specific `SettleRound` to `flush` and `deliver`; the Coordinator's job is deciding which
    SettleRound that is."""

    def __init__(self, me: crypto.Keypair, postman: Postman, ttl: Millis) -> None:
        self.me = me
        self.postman = postman
        self.ttl = ttl

    def flush(self, round_: SettleRound, now: Millis) -> None:
        """Drain a SettleRound's outbox, encode each message via its own `encode()`, post to the
        mailbox.

        `SETTLE_SIG` is a broadcast by nature -- SettleRound emits `(Recipient.ALL, msg)`.
        Preserved as `Target` in case a future scenario adds directed sends."""
        for target, msg in round_.outbox():
            verb, body = msg.encode()
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
        round_.receive(SettleSig.decode(env.env.verb, env.env.body), from_=env.frm, now=now)


__all__ = ["SettleAdapter", "SettleAdapterError"]
