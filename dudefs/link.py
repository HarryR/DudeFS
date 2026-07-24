# dudefs/link.py — the peer connection abstraction (PROTOCOL §7.5). ONE seam where
# L_msg meets the transport: talk to one peer (`to_pub`) at one Endpoint, as `self`.
# It composes the two honest layers — lmsg (pure encode/verify, and the seal once
# step C lands) and transports (the I/O edge) — so client, daemon, and manager stop
# re-rolling author→dial→classify. Behaviour is chosen from the Endpoint: plain today,
# sealed rides the same seam (Endpoint.sealed). NOT the deleted peerwire: no I/O hidden
# behind a callback — it calls transports.dial directly and returns a typed outcome.
from __future__ import annotations

from dataclasses import dataclass

from . import crypto as C
from . import lmsg, transports


@dataclass(frozen=True)
class Link:
    """A logical connection from `identity` (its `.public` is `self_pub`) to peer `to_pub`
    at `endpoint`. Carriers are connectionless (a fresh dial per request), so a Link is a
    cheap value, not a held socket — reuse or rebuild freely."""

    identity: C.Keypair
    to_pub: C.PublicKey
    endpoint: transports.Endpoint

    def request(
        self, verb: bytes, body: bytes, *, epoch: int, ts: int, timeout: float = 5.0
    ) -> lmsg.ReplyOutcome:
        """Author an L_msg request to the peer, dial it over the endpoint's carrier, and
        return the verified reply outcome (Reply / NoReply / MalformedReply / WrongPeer).
        Seals iff `endpoint.sealed` — sign-then-seal to the peer with a fresh ephemeral
        reply-key, and open the reply with it; otherwise plain."""
        env = lmsg.author(self.identity, self.to_pub, verb, body, epoch=epoch, ts=ts)
        if not self.endpoint.sealed:
            raw = transports.dial(
                self.endpoint.transport, self.endpoint.uri, env.encode(), timeout=timeout
            )
            return lmsg.classify_reply(raw, expect_from=self.to_pub, expect_to=self.identity.public)
        reply = C.SoftwareKeypair.generate()  # ephemeral reply identity, sealed INSIDE the request
        sealed = lmsg.seal_request(env, self.to_pub, reply.public)
        raw = transports.dial(self.endpoint.transport, self.endpoint.uri, sealed, timeout=timeout)
        return lmsg.classify_sealed_reply(
            raw, reply=reply, expect_from=self.to_pub, expect_to=self.identity.public
        )
