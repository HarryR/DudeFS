# dude.consensus.round_adapter -- Postman binding for Round's protocol messages.
#
# ROUND OWNS ITS MESSAGES AND THEIR ENCODING. The two verbs (`HELD`, `SIG`) live in
# `dude.net.Verb`; each message subclass owns its own `encode()` / `_decode()` methods, and
# dispatch happens via `RoundMsg.decode(verb, body)` (see `dude.consensus.round`).
#
# STATELESS. This module is the Postman seam only: flush a Round's outbox as envelopes, deliver
# an inbound envelope to a Round. Bucket-to-Round dispatch is NOT this module's job -- that is
# the Coordinator's, via `RoundMsg.bucket_of` on the raw body.

from __future__ import annotations

from ..core import crypto
from ..core.units import Millis
from ..net.envelope import Envelope, MessageId, SignedEnvelope, new_message_id
from ..net.postman import Postman
from .round import Round, RoundAdapterError, RoundMsg


class RoundAdapter:
    """Send Round outbound messages via a Postman; deliver inbound envelopes to a Round.

    NOT a Coordinator -- this class holds no Round-instance-per-bucket mapping. Callers hand a
    specific `Round` to `flush` and `deliver`; the Coordinator's job is deciding which
    Round that is."""

    def __init__(self, me: crypto.Keypair, postman: Postman, ttl: Millis) -> None:
        self.me = me
        self.postman = postman
        self.ttl = ttl

    def flush(self, round_: Round, now: Millis) -> None:
        """Drain a Round's outbox, encode each message via its own `encode()`, post to the
        mailbox.

        `HELD` and `SIG` are BROADCASTS by nature -- Round emits `(Recipient.ALL, msg)` -- but
        this method preserves whatever target the Round used, in case a future scenario adds
        directed sends (e.g., a "please retransmit" request to one peer)."""
        for target, msg in round_.outbox():
            verb, body = msg.encode()
            for peer in self.postman.recipients(target):
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
        round_.receive(RoundMsg.decode(env.env.verb, env.env.body), from_=env.frm, now=now)


__all__ = ["MessageId", "RoundAdapter", "RoundAdapterError"]
