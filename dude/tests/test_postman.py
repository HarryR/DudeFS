"""Tests for the Postman actor — the public API, over real transports.

No manual pump, no internal state inspection, no envelope construction. Two postmen
talk to each other; the tests observe what comes out via OutputQueue. Every test runs
over both inproc and TCP so the transport is exercised by the same assertions.
"""

from __future__ import annotations

import time
import unittest
from dataclasses import dataclass

from ..core import crypto
from ..core.units import Millis
from ..net.address import Endpoint
from ..net.envelope import MessageId, Verb
from ..net.postman import Delivered, Encodable, OutputQueue, Postman
from ..net.transports.inproc import InProcListener, InProcNexus
from ..net.transports.tcp import TCPListener
from ..tunables import Tunables

T = Tunables(rtt_max=Millis(200), clock_skew=Millis(200))

type _Pair = tuple[crypto.Keypair, crypto.Keypair, Postman, OutputQueue, Postman, OutputQueue]


@dataclass(frozen=True)
class Ping(Encodable):
    def encode(self) -> tuple[Verb, bytes]:
        return Verb.HEIGHT, b""


@dataclass(frozen=True)
class Pong(Encodable):
    def encode(self) -> tuple[Verb, bytes]:
        return Verb.HEIGHT_REPLY, b""


@dataclass(frozen=True)
class Payload(Encodable):
    data: bytes

    def encode(self) -> tuple[Verb, bytes]:
        return Verb.SUBMIT, self.data


def _pair_inproc() -> _Pair:
    a = crypto.Keypair.generate()
    b = crypto.Keypair.generate()
    nexus = InProcNexus()

    aq, bq = OutputQueue(), OutputQueue()
    ap = Postman(a, T, on_output=aq)
    bp = Postman(b, T, on_output=bq)

    al = nexus.attach(ap)
    bl = nexus.attach(bp)

    ap.add_peer(b.public, (bl.endpoint,))
    bp.add_peer(a.public, (al.endpoint,))

    ap.start()
    bp.start()

    return a, b, ap, aq, bp, bq


def _pair_tcp() -> _Pair:
    a = crypto.Keypair.generate()
    b = crypto.Keypair.generate()

    al = TCPListener(T)
    bl = TCPListener(T)

    aq, bq = OutputQueue(), OutputQueue()
    ap = Postman(a, T, on_output=aq)
    bp = Postman(b, T, on_output=bq)

    ap.add_acceptor(al)
    bp.add_acceptor(bl)

    ap.add_peer(b.public, (Endpoint(bl.bound_address),))
    bp.add_peer(a.public, (Endpoint(al.bound_address),))

    ap.start()
    bp.start()

    return a, b, ap, aq, bp, bq


def _drain_delivered(
    q: OutputQueue, timeout: float = T.ttl_exchange.as_seconds, count: int = 1
) -> list[Delivered]:
    deadline = time.monotonic() + timeout
    out: list[Delivered] = []
    while time.monotonic() < deadline:
        result = q.get(timeout=0.02)
        if result is not None:
            out.extend(result.delivered)
        if len(out) >= count:
            return out
    return out


class _PostmanTests(unittest.TestCase):
    __test__ = False
    _pair: staticmethod

    def setUp(self) -> None:
        self._postmen: list[Postman] = []

    def tearDown(self) -> None:
        for p in self._postmen:
            p.stop()

    def _make_pair(self) -> _Pair:
        a, b, ap, aq, bp, bq = self._pair()
        self._postmen.extend([ap, bp])
        return a, b, ap, aq, bp, bq

    def test_a_message_arrives_at_the_peer(self) -> None:
        a, b, ap, _aq, _bp, bq = self._make_pair()
        ap.send(b.public, Ping(), T.ttl_exchange)
        got = _drain_delivered(bq)
        self.assertEqual(len(got), 1)
        self.assertEqual(got[0].frm, a.public)
        self.assertEqual(got[0].verb, Verb.HEIGHT)

    def test_body_is_delivered_intact(self) -> None:
        _a, b, ap, _aq, _bp, bq = self._make_pair()
        payload = b"hello world"
        ap.send(b.public, Payload(payload), T.ttl_exchange)
        got = _drain_delivered(bq)
        self.assertEqual(len(got), 1)
        self.assertEqual(got[0].body, payload)

    def test_reply_correlates(self) -> None:
        _a, b, ap, aq, bp, bq = self._make_pair()
        mid = ap.send(b.public, Ping(), T.ttl_exchange)

        got = _drain_delivered(bq)
        self.assertEqual(len(got), 1)

        bp.reply(got[0], Pong(), T.ttl_exchange)

        reply = _drain_delivered(aq)
        self.assertEqual(len(reply), 1)
        self.assertEqual(reply[0].verb, Verb.HEIGHT_REPLY)
        irt = reply[0].in_reply_to
        self.assertIsNotNone(irt)
        assert irt is not None
        self.assertEqual(irt.correlation_id, mid.correlation_id)

    def test_send_returns_message_id(self) -> None:
        _a, b, ap, _aq, _bp, _bq = self._make_pair()
        mid = ap.send(b.public, Ping(), T.ttl_exchange)
        self.assertIsInstance(mid, MessageId)
        self.assertEqual(len(mid), MessageId.SIZE)

    def test_unauthorized_sender_is_dropped(self) -> None:
        a = crypto.Keypair.generate()
        b = crypto.Keypair.generate()
        stranger = crypto.Keypair.generate()
        nexus = InProcNexus()

        InProcListener(a.public, nexus)

        bq = OutputQueue()
        bp = Postman(b, T, on_output=bq)
        sp = Postman(stranger, T, on_output=OutputQueue())

        bl = nexus.attach(bp)
        nexus.attach(sp)

        bp.add_peer(a.public, (nexus.endpoint_for(a.public),))
        sp.add_peer(b.public, (bl.endpoint,))

        bp.start()
        sp.start()
        self._postmen.extend([bp, sp])

        sp.send(b.public, Ping(), T.ttl_exchange)
        got = _drain_delivered(bq, timeout=T.rtt_max.as_seconds)
        self.assertEqual(len(got), 0, "unauthorized sender should be dropped")

    def test_authorized_non_peer_is_accepted(self) -> None:
        a = crypto.Keypair.generate()
        client = crypto.Keypair.generate()
        nexus = InProcNexus()

        aq = OutputQueue()
        ap = Postman(a, T, on_output=aq)
        cp = Postman(client, T, on_output=OutputQueue())

        al = nexus.attach(ap)
        nexus.attach(cp)

        cp.add_peer(a.public, (al.endpoint,))
        ap.sync({}, authorized=frozenset({client.public}))

        ap.start()
        cp.start()
        self._postmen.extend([ap, cp])

        cp.send(a.public, Ping(), T.ttl_exchange)
        got = _drain_delivered(aq)
        self.assertEqual(len(got), 1)
        self.assertEqual(got[0].frm, client.public)

    def test_multiple_messages_all_arrive(self) -> None:
        _a, b, ap, _aq, _bp, bq = self._make_pair()
        for i in range(5):
            ap.send(b.public, Payload(i.to_bytes(1)), T.ttl_exchange)
        got = _drain_delivered(bq, count=5)
        self.assertEqual(len(got), 5)
        received = sorted(d.body for d in got)
        self.assertEqual(received, [i.to_bytes(1) for i in range(5)])

    def test_bidirectional_exchange(self) -> None:
        a, b, ap, aq, bp, bq = self._make_pair()
        ap.send(b.public, Payload(b"from-a"), T.ttl_exchange)
        bp.send(a.public, Payload(b"from-b"), T.ttl_exchange)

        got_by_b = _drain_delivered(bq)
        got_by_a = _drain_delivered(aq)
        self.assertEqual(len(got_by_b), 1)
        self.assertEqual(got_by_b[0].body, b"from-a")
        self.assertEqual(len(got_by_a), 1)
        self.assertEqual(got_by_a[0].body, b"from-b")


class TestInProc(_PostmanTests):
    __test__ = True
    _pair = staticmethod(_pair_inproc)


class TestTCP(_PostmanTests):
    __test__ = True
    _pair = staticmethod(_pair_tcp)


if __name__ == "__main__":
    unittest.main()
