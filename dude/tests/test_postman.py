"""Tests for the Postman actor — the public API, over real transports.

No manual pump, no internal state inspection, no envelope construction. Two postmen
talk to each other; the tests observe what comes out of drain_output. Every test runs
over both inproc and TCP so the transport is exercised by the same assertions.
"""

from __future__ import annotations

import time
import unittest
from dataclasses import dataclass

from ..core import crypto
from ..net.address import Endpoint
from ..net.envelope import MessageId, Verb
from ..net.postman import Delivered, Encodable, Postman
from ..net.transports.inproc import InProcListener
from ..net.transports.tcp import TCPDialer, TCPListener, TCPTiming
from ..tunables import Tunables

T = Tunables(rtt_max=200, clock_skew=200)
TCP_TIMING = TCPTiming(connect=1000, send=1000)


@dataclass(frozen=True)
class Ping(Encodable):
    def encode(self) -> tuple[Verb, bytes]:
        return Verb.PING, b""


@dataclass(frozen=True)
class Pong(Encodable):
    def encode(self) -> tuple[Verb, bytes]:
        return Verb.PONG, b""


@dataclass(frozen=True)
class Payload(Encodable):
    data: bytes

    def encode(self) -> tuple[Verb, bytes]:
        return Verb.SUBMIT, self.data


def _pair_inproc() -> tuple[crypto.Keypair, crypto.Keypair, Postman, Postman]:
    a = crypto.Keypair.generate()
    b = crypto.Keypair.generate()
    nexus: dict[bytes, InProcListener] = {}

    al = InProcListener(a.public, nexus)
    bl = InProcListener(b.public, nexus)

    ap = Postman(a, T)
    bp = Postman(b, T)

    ap.add_listener(al)
    bp.add_listener(bl)

    ap.add_peer(b.public, (bl.endpoint,))
    bp.add_peer(a.public, (al.endpoint,))

    ap.start()
    bp.start()

    return a, b, ap, bp


def _pair_tcp() -> tuple[crypto.Keypair, crypto.Keypair, Postman, Postman]:
    a = crypto.Keypair.generate()
    b = crypto.Keypair.generate()

    al = TCPListener(timing=TCP_TIMING)
    bl = TCPListener(timing=TCP_TIMING)
    ad = TCPDialer(timing=TCP_TIMING)
    bd = TCPDialer(timing=TCP_TIMING)

    ap = Postman(a, T)
    bp = Postman(b, T)

    ap.add_listener(al)
    ap.add_listener(ad)
    bp.add_listener(bl)
    bp.add_listener(bd)

    ap.add_peer(b.public, (Endpoint(bl.bound_address),))
    bp.add_peer(a.public, (Endpoint(al.bound_address),))

    ap.start()
    bp.start()

    return a, b, ap, bp


def _drain_delivered(p: Postman, timeout: float = 0.5) -> list[Delivered]:
    deadline = time.monotonic() + timeout
    out: list[Delivered] = []
    while time.monotonic() < deadline:
        for output in p.drain_output():
            out.extend(output.delivered)
        if out:
            return out
        time.sleep(0.02)
    return out


class _PostmanTests:
    """Mixin: the actual test methods. Subclasses set `_pair` to the transport factory."""

    _pair: staticmethod

    def setUp(self) -> None:
        self._postmen: list[Postman] = []

    def tearDown(self) -> None:
        for p in self._postmen:
            p.stop()

    def _make_pair(self) -> tuple[crypto.Keypair, crypto.Keypair, Postman, Postman]:
        a, b, ap, bp = self._pair()
        self._postmen.extend([ap, bp])
        return a, b, ap, bp

    def test_a_message_arrives_at_the_peer(self) -> None:
        a, b, ap, bp = self._make_pair()
        ap.send(b.public, Ping(), T.ttl_exchange)
        got = _drain_delivered(bp)
        self.assertEqual(len(got), 1)
        self.assertEqual(got[0].frm, a.public)
        self.assertEqual(got[0].verb, Verb.PING)

    def test_body_is_delivered_intact(self) -> None:
        a, b, ap, bp = self._make_pair()
        payload = b"hello world"
        ap.send(b.public, Payload(payload), T.ttl_exchange)
        got = _drain_delivered(bp)
        self.assertEqual(len(got), 1)
        self.assertEqual(got[0].body, payload)

    def test_reply_correlates(self) -> None:
        a, b, ap, bp = self._make_pair()
        mid = ap.send(b.public, Ping(), T.ttl_exchange)

        got = _drain_delivered(bp)
        self.assertEqual(len(got), 1)

        bp.reply(got[0], Pong(), T.ttl_exchange)

        reply = _drain_delivered(ap)
        self.assertEqual(len(reply), 1)
        self.assertEqual(reply[0].verb, Verb.PONG)
        irt = reply[0].in_reply_to
        self.assertIsNotNone(irt)
        assert irt is not None
        self.assertEqual(irt.correlation_id, mid.correlation_id)

    def test_send_returns_message_id(self) -> None:
        a, b, ap, bp = self._make_pair()
        mid = ap.send(b.public, Ping(), T.ttl_exchange)
        self.assertIsInstance(mid, MessageId)
        self.assertEqual(len(mid), MessageId.SIZE)

    def test_unauthorized_sender_is_dropped(self) -> None:
        a = crypto.Keypair.generate()
        b = crypto.Keypair.generate()
        stranger = crypto.Keypair.generate()
        nexus: dict[bytes, InProcListener] = {}

        al = InProcListener(a.public, nexus)
        bl = InProcListener(b.public, nexus)
        sl = InProcListener(stranger.public, nexus)

        bp = Postman(b, T)
        sp = Postman(stranger, T)

        bp.add_listener(bl)
        sp.add_listener(sl)

        bp.add_peer(a.public, (al.endpoint,))
        sp.add_peer(b.public, (bl.endpoint,))

        bp.start()
        sp.start()
        self._postmen.extend([bp, sp])

        sp.send(b.public, Ping(), T.ttl_exchange)
        got = _drain_delivered(bp, timeout=0.3)
        self.assertEqual(len(got), 0, "unauthorized sender should be dropped")

    def test_authorized_non_peer_is_accepted(self) -> None:
        a = crypto.Keypair.generate()
        client = crypto.Keypair.generate()
        nexus: dict[bytes, InProcListener] = {}

        al = InProcListener(a.public, nexus)
        cl = InProcListener(client.public, nexus)

        ap = Postman(a, T)
        cp = Postman(client, T)

        ap.add_listener(al)
        cp.add_listener(cl)

        cp.add_peer(a.public, (al.endpoint,))
        ap.sync({}, authorized=frozenset({client.public}))

        ap.start()
        cp.start()
        self._postmen.extend([ap, cp])

        cp.send(a.public, Ping(), T.ttl_exchange)
        got = _drain_delivered(ap)
        self.assertEqual(len(got), 1)
        self.assertEqual(got[0].frm, client.public)

    def test_multiple_messages_all_arrive(self) -> None:
        a, b, ap, bp = self._make_pair()
        for i in range(5):
            ap.send(b.public, Payload(i.to_bytes(1)), T.ttl_exchange)
        got = _drain_delivered(bp, timeout=1.0)
        self.assertEqual(len(got), 5)
        received = sorted(d.body for d in got)
        self.assertEqual(received, [i.to_bytes(1) for i in range(5)])

    def test_bidirectional_exchange(self) -> None:
        a, b, ap, bp = self._make_pair()
        ap.send(b.public, Payload(b"from-a"), T.ttl_exchange)
        bp.send(a.public, Payload(b"from-b"), T.ttl_exchange)

        got_by_b = _drain_delivered(bp)
        got_by_a = _drain_delivered(ap)

        self.assertEqual(len(got_by_b), 1)
        self.assertEqual(got_by_b[0].body, b"from-a")
        self.assertEqual(len(got_by_a), 1)
        self.assertEqual(got_by_a[0].body, b"from-b")


class TestInProc(_PostmanTests, unittest.TestCase):
    _pair = staticmethod(_pair_inproc)


class TestTCP(_PostmanTests, unittest.TestCase):
    _pair = staticmethod(_pair_tcp)

    def _drain(self, p: Postman, **kw) -> list[Delivered]:
        return _drain_delivered(p, timeout=kw.get("timeout", 2.0))


if __name__ == "__main__":
    unittest.main()
