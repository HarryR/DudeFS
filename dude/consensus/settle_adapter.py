from __future__ import annotations

from ..core import crypto
from ..core.units import Millis
from ..net.envelope import Verb
from ..net.postman import Postman, recipients
from .settle_round import SettleAdapterError, SettleRound, SettleSig


class SettleAdapter:
    def __init__(self, me: crypto.Keypair, postman: Postman, ttl: Millis) -> None:
        self.me = me
        self.postman = postman
        self.ttl = ttl

    def flush(self, round_: SettleRound, now: Millis) -> None:
        for target, msg in round_.outbox():
            verb, body = msg.encode()
            for peer in recipients(target, round_.roster(), self.me.public):
                self.postman.send_raw(peer, verb, body, self.ttl, await_reply=False)

    def deliver(self, frm: crypto.PublicKey, verb: Verb, body: bytes, round_: SettleRound, now: Millis) -> None:
        round_.receive(SettleSig.decode(verb, body), from_=frm, now=now)


__all__ = ["SettleAdapter", "SettleAdapterError"]
