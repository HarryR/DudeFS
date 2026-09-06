import threading

from .core import crypto
from .core.units import Millis
from .net import MessageId, Verb
from .net.link import Acceptor, Dialer
from .net.postman import Encodable, Postman
from .session import Inflight, InflightHandle


class Participant:
    def __init__(self, me: crypto.Keypair, postman: Postman) -> None:
        self.me = me
        self.postman = postman
        self.inflight = Inflight()
        self.commit_cond = threading.Condition()
        self.commit_seq: int = 0

    @property
    def tunables(self):
        return self.postman.tunables

    def add_acceptor(self, acceptor: Acceptor) -> None:
        self.postman.add_acceptor(acceptor)

    def add_dialer(self, dialer: Dialer) -> None:
        self.postman.add_dialer(dialer)

    def request_raw(
        self,
        peer: crypto.PublicKey,
        verb: Verb,
        body: bytes,
        ttl: Millis,
        handle: InflightHandle,
    ) -> MessageId:
        mid = MessageId.random()
        self.inflight.register(mid, handle)
        self.postman.send_raw(peer, verb, body, ttl, mid=mid)
        return mid

    def request(
        self,
        peer: crypto.PublicKey,
        msg: Encodable,
        ttl: Millis,
        handle: InflightHandle,
    ) -> MessageId:
        verb, body = msg.encode()
        return self.request_raw(peer, verb, body, ttl, handle)
