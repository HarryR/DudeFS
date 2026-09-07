"""Tests for link lifecycle: authentication timeout, peer-change notifications,
and the _SyncPeers race where frames arrive before the postman knows about a
peer.  Behavioral tests run over both InProc and TCP.
"""

from __future__ import annotations

import socket
import struct
import time
import unittest

from ..core import crypto
from ..core.units import Millis
from ..net.address import Endpoint
from ..net.envelope import Envelope, Frame, MessageId, Verb
from ..net.postman import Delivered, Encodable, OutputQueue, Postman
from ..net.transports.inproc import InProcListener, InProcNexus
from ..net.transports.tcp import TCPListener
from ..tunables import Tunables

FAST = Tunables(rtt_max=Millis(50), clock_skew=Millis(25))


class Ping(Encodable):
    def encode(self) -> tuple[Verb, bytes]:
        return Verb.HEIGHT, b""


def _drain(q: OutputQueue, timeout: float = 0.5) -> list[Delivered]:
    deadline = time.monotonic() + timeout
    out: list[Delivered] = []
    while time.monotonic() < deadline:
        result = q.get(timeout=0.02)
        if result is not None:
            out.extend(result.delivered)
    return out


# ---------------------------------------------------------------------------
# Behavioral tests — shared base, run over both InProc and TCP.
# ---------------------------------------------------------------------------


class _LinkLifecycleTests(unittest.TestCase):
    __test__ = False

    def setUp(self) -> None:
        self._postmen: list[Postman] = []

    def tearDown(self) -> None:
        for p in self._postmen:
            p.stop()

    def _postman(
        self, kp: crypto.Keypair | None = None
    ) -> tuple[crypto.Keypair, Postman, OutputQueue, Endpoint]:
        raise NotImplementedError

    def _endpoint(self, kp: crypto.Keypair) -> Endpoint:
        raise NotImplementedError

    def _inject_frame(self, target: Postman, frame: Frame) -> None:
        raise NotImplementedError

    def _track(self, p: Postman) -> Postman:
        self._postmen.append(p)
        return p

    # -- peer-change callback tests -----------------------------------------

    def test_sync_fires_added_and_removed(self) -> None:
        _, p, _, _ = self._postman()
        self._track(p)

        k1, k2, k3 = (crypto.Keypair.generate() for _ in range(3))
        ep1, ep2, ep3 = self._endpoint(k1), self._endpoint(k2), self._endpoint(k3)

        changes: list[tuple[frozenset, frozenset]] = []
        p.on_peers_changed = lambda a, r: changes.append((a, r))
        p.start()

        p.sync({k1.public: (ep1,), k2.public: (ep2,)})
        time.sleep(0.1)
        self.assertEqual(len(changes), 1)
        added, removed = changes[0]
        self.assertEqual(added, frozenset({k1.public, k2.public}))
        self.assertEqual(removed, frozenset())

        p.sync({k2.public: (ep2,), k3.public: (ep3,)})
        time.sleep(0.1)
        self.assertEqual(len(changes), 2)
        added, removed = changes[1]
        self.assertEqual(added, frozenset({k3.public}))
        self.assertEqual(removed, frozenset({k1.public}))

    def test_add_peer_fires_callback(self) -> None:
        _, p, _, _ = self._postman()
        self._track(p)
        k1 = crypto.Keypair.generate()

        changes: list[tuple[frozenset, frozenset]] = []
        p.on_peers_changed = lambda a, r: changes.append((a, r))
        p.start()

        p.add_peer(k1.public, (self._endpoint(k1),))
        time.sleep(0.1)
        self.assertEqual(len(changes), 1)
        self.assertEqual(changes[0][0], frozenset({k1.public}))

    def test_remove_peer_fires_callback(self) -> None:
        _, p, _, _ = self._postman()
        self._track(p)
        k1 = crypto.Keypair.generate()

        changes: list[tuple[frozenset, frozenset]] = []
        p.on_peers_changed = lambda a, r: changes.append((a, r))
        p.start()

        p.add_peer(k1.public, (self._endpoint(k1),))
        time.sleep(0.05)
        p.remove_peer(k1.public)
        time.sleep(0.1)
        self.assertEqual(len(changes), 2)
        self.assertEqual(changes[1][1], frozenset({k1.public}))

    def test_no_callback_on_no_change(self) -> None:
        _, p, _, _ = self._postman()
        self._track(p)

        changes: list[tuple[frozenset, frozenset]] = []
        p.on_peers_changed = lambda a, r: changes.append((a, r))
        p.start()

        p.sync({})
        time.sleep(0.1)
        self.assertEqual(len(changes), 0, "empty sync should not fire callback")

    # -- stranger / authorization tests -------------------------------------

    def test_stranger_frame_dropped(self) -> None:
        node_kp, node_p, node_q, node_ep = self._postman()
        _stranger_kp, stranger_p, _, _ = self._postman()
        self._track(node_p)
        self._track(stranger_p)

        stranger_p.add_peer(node_kp.public, (node_ep,))
        node_p.start()
        stranger_p.start()

        stranger_p.send(node_kp.public, Ping(), FAST.ttl_exchange)
        got = _drain(node_q, timeout=FAST.rtt_max.as_seconds * 4)
        self.assertEqual(len(got), 0, "stranger's frame should not be delivered")

    # -- _SyncPeers race test -----------------------------------------------

    def test_sync_race_dropped_then_recovered(self) -> None:
        a_kp, a_p, a_q, a_ep = self._postman()
        b_kp, b_p, _, b_ep = self._postman()
        self._track(a_p)
        self._track(b_p)

        a_p.start()
        b_p.start()

        b_p.add_peer(a_kp.public, (a_ep,))
        b_p.send(a_kp.public, Ping(), FAST.ttl_exchange)
        time.sleep(FAST.rtt_max.as_seconds)
        got = _drain(a_q, timeout=0.1)
        self.assertEqual(len(got), 0, "frame before sync should be dropped")

        a_p.add_peer(b_kp.public, (b_ep,))
        time.sleep(FAST.block_time_floor.as_seconds)

        b_p.send(a_kp.public, Ping(), FAST.ttl_exchange)
        got2 = _drain(a_q, timeout=FAST.block_time.as_seconds)
        self.assertEqual(len(got2), 1, "frame after sync should be delivered")

    # -- bad frame tests ----------------------------------------------------

    def test_wrong_recipient_closes_link(self) -> None:
        _node_kp, node_p, node_q, _ = self._postman()
        peer_kp, _, _, peer_ep = self._postman()
        self._track(node_p)

        node_p.sync({peer_kp.public: (peer_ep,)})
        node_p.start()
        time.sleep(0.05)

        wrong_dest = crypto.Keypair.generate()
        env = Envelope(wrong_dest.public, Verb.HEIGHT, MessageId.random(), b"")
        frame = env.sign(peer_kp, Millis.now()).seal()
        self._inject_frame(node_p, frame)
        time.sleep(0.1)

        got = _drain(node_q, timeout=0.05)
        self.assertEqual(len(got), 0, "wrong-recipient frame should be dropped")

    def test_bad_unseal_closes_link(self) -> None:
        node_kp, node_p, node_q, _ = self._postman()
        peer_kp, _, _, peer_ep = self._postman()
        self._track(node_p)

        node_p.sync({peer_kp.public: (peer_ep,)})
        node_p.start()
        time.sleep(0.05)

        tag = crypto.screen_tag(node_kp.public, b"garbage-sealed-blob")
        frame = Frame(tag, crypto.SealedBlob(b"garbage-sealed-blob"))
        self._inject_frame(node_p, frame)
        time.sleep(0.1)

        got = _drain(node_q, timeout=0.05)
        self.assertEqual(len(got), 0, "bad-unseal frame should be dropped")


# ---------------------------------------------------------------------------
# InProc
# ---------------------------------------------------------------------------


class TestInProcLifecycle(_LinkLifecycleTests):
    __test__ = True

    def setUp(self) -> None:
        super().setUp()
        self._nexus = InProcNexus()

    def _postman(
        self, kp: crypto.Keypair | None = None
    ) -> tuple[crypto.Keypair, Postman, OutputQueue, Endpoint]:
        kp = kp or crypto.Keypair.generate()
        q = OutputQueue()
        p = Postman(kp, FAST, on_output=q)
        listener = self._nexus.attach(p)
        return kp, p, q, listener.endpoint

    def _endpoint(self, kp: crypto.Keypair) -> Endpoint:
        return self._nexus.endpoint_for(kp.public)

    def _inject_frame(self, target: Postman, frame: Frame) -> None:
        listener = next(a for a in target._acceptors if isinstance(a, InProcListener))
        sender = crypto.Keypair.generate()
        listener.deliver(frame, sender=bytes(sender.public))


# ---------------------------------------------------------------------------
# TCP
# ---------------------------------------------------------------------------


class TestTCPLifecycle(_LinkLifecycleTests):
    __test__ = True

    def _postman(
        self, kp: crypto.Keypair | None = None
    ) -> tuple[crypto.Keypair, Postman, OutputQueue, Endpoint]:
        kp = kp or crypto.Keypair.generate()
        q = OutputQueue()
        p = Postman(kp, FAST, on_output=q)
        listener = TCPListener(FAST)
        p.add_acceptor(listener)
        return kp, p, q, Endpoint(listener.bound_address)

    def _endpoint(self, kp: crypto.Keypair) -> Endpoint:
        del kp
        listener = TCPListener(FAST)
        return Endpoint(listener.bound_address)

    def _inject_frame(self, target: Postman, frame: Frame) -> None:
        listener = next(a for a in target._acceptors if isinstance(a, TCPListener))
        addr = listener.bound_address
        host, port = addr.value.rsplit(":", 1)
        raw = frame.raw
        payload = struct.pack(">I", len(raw)) + raw
        with socket.create_connection((host, int(port)), timeout=1.0) as sock:
            sock.sendall(payload)
            time.sleep(0.05)

    def _tcp_addr(self, p: Postman) -> tuple[str, int]:
        listener = next(a for a in p._acceptors if isinstance(a, TCPListener))
        addr = listener.bound_address
        host, port = addr.value.rsplit(":", 1)
        return host, int(port)

    def test_oversize_frame_kills_connection(self) -> None:
        _, node_p, _, _ = self._postman()
        self._track(node_p)
        node_p.start()
        host, port = self._tcp_addr(node_p)

        with socket.create_connection((host, port), timeout=1.0) as sock:
            sock.sendall(struct.pack(">I", (1 << 24) + 1))
            time.sleep(0.1)
            data = sock.recv(1)
            self.assertEqual(data, b"", "oversize length should kill the connection")

    def test_garbage_payload_kills_connection(self) -> None:
        _, node_p, _, _ = self._postman()
        self._track(node_p)
        node_p.start()
        host, port = self._tcp_addr(node_p)

        garbage = b"\xff" * 64
        with socket.create_connection((host, port), timeout=1.0) as sock:
            sock.sendall(struct.pack(">I", len(garbage)) + garbage)
            time.sleep(0.1)
            data = sock.recv(1)
            self.assertEqual(data, b"", "garbage payload should kill the connection")


# ---------------------------------------------------------------------------
# InProc-specific: conn dict cleanup (no TCP equivalent).
# ---------------------------------------------------------------------------


class TestInProcConnCleanup(unittest.TestCase):
    def test_conn_removed_from_dict_on_close(self) -> None:
        a = crypto.Keypair.generate()
        b = crypto.Keypair.generate()
        nexus = InProcNexus()

        InProcListener(a.public, nexus)
        bl = InProcListener(b.public, nexus)
        bl.start(lambda _f, _l: None, lambda _l: None)

        addr = InProcListener.endpoint_for(a.public).address
        self.assertTrue(bl.dial(addr), "initial dial should succeed")
        a_key = bytes(a.public)
        self.assertIn(a_key, bl.conns)

        self.assertFalse(bl.dial(addr), "duplicate dial should fail")

        bl.conns[a_key].link.close()
        self.assertNotIn(a_key, bl.conns, "close should remove conn")

        self.assertTrue(bl.dial(addr), "re-dial after cleanup should succeed")

        bl.stop()


# ---------------------------------------------------------------------------
# InProc-specific: unbound link reap timer.
# ---------------------------------------------------------------------------


class TestUnboundLinkReap(unittest.TestCase):
    def test_stranger_link_reaped_after_lifetime(self) -> None:
        node = crypto.Keypair.generate()
        stranger = crypto.Keypair.generate()
        nexus = InProcNexus()

        nq = OutputQueue()
        np = Postman(node, FAST, on_output=nq)
        nexus.attach(np)
        np.start()

        sp = Postman(stranger, FAST, on_output=OutputQueue())
        sl = nexus.attach(sp)
        sp.add_peer(node.public, (sl.endpoint_for(node.public),))
        sp.start()

        sp.send(node.public, Ping(), FAST.ttl_exchange)
        time.sleep(FAST.rtt_max.as_seconds)

        node_listener = next(a for a in np._acceptors if isinstance(a, InProcListener))
        stranger_key = bytes(stranger.public)
        self.assertIn(stranger_key, node_listener.conns)

        time.sleep(FAST.unauthenticated_link_lifetime.as_seconds + 0.1)
        self.assertNotIn(stranger_key, node_listener.conns)

        np.stop()
        sp.stop()


if __name__ == "__main__":
    unittest.main()
