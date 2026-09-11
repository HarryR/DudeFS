import time
import unittest

from ..core import crypto, serde
from ..core.units import Millis
from ..introspect import NodeStatusReply
from ..net.envelope import Verb
from ..net.link import LinkDirection
from ..net.postman import OutputQueue, Postman
from ..sync.lite_client import LightClient
from ..sync.observer import ClusterObserver
from .cluster import Cluster, TCPFabric


class TestNodeStatusFromAnchor(unittest.TestCase):
    def setUp(self) -> None:
        self.c = Cluster(nodes=3, mgmt=1)
        self.c.wait_block(1)

    def tearDown(self) -> None:
        self.c.close()

    def test_anchor_gets_status(self) -> None:
        replies = OutputQueue()
        postman = Postman(self.c.anchor, self.c.tunables, on_output=replies)
        self.c.fabric.attach(postman)
        target = self.c.nodes[0]
        postman.add_peer(
            target.me.public,
            (self.c.fabric.endpoint_for(target.me.public),),
        )
        postman.start()

        postman.send_raw(
            target.me.public,
            Verb.NODE_STATUS,
            b"",
            self.c.tunables.ttl_exchange,
        )

        deadline = time.monotonic() + self.c.tunables.ttl_exchange.as_seconds
        reply_body = None
        while time.monotonic() < deadline:
            out = replies.get(timeout=0.05)
            if out is None:
                continue
            for d in out.delivered:
                if d.verb is Verb.NODE_STATUS_REPLY:
                    reply_body = d.body
                    break
            if reply_body is not None:
                break

        postman.stop()
        assert reply_body is not None, "no NODE_STATUS_REPLY received"

        status = NodeStatusReply.decode(reply_body)
        self.assertGreaterEqual(status.head_block, 1)
        self.assertEqual(status.roster_size, 3)
        self.assertIsNotNone(status.mempool_size)
        self.assertGreater(len(status.peers), 0)
        self.assertGreater(len(status.listeners), 0)

    def test_client_gets_refused(self) -> None:
        c = Cluster(nodes=3, mgmt=1, rw=1)
        c.wait_block(1)

        client_lc = c.rw_clients[0]
        client_lc.bootstrap()

        replies = OutputQueue()
        client_lc.postman.on_output = replies
        target = c.nodes[0]

        client_lc.postman.send_raw(
            target.me.public,
            Verb.NODE_STATUS,
            b"",
            c.tunables.ttl_exchange,
        )

        deadline = time.monotonic() + c.tunables.ttl_exchange.as_seconds
        refused = False
        while time.monotonic() < deadline:
            out = replies.get(timeout=0.05)
            if out is None:
                continue
            for d in out.delivered:
                if d.verb is Verb.REFUSED:
                    refused = True
                    break
            if refused:
                break

        c.close()
        self.assertTrue(refused, "client was not refused NODE_STATUS")


class TestSerdeRoundTrip(unittest.TestCase):
    def test_node_status_reply_survives(self) -> None:
        original = NodeStatusReply(
            head_block=42,
            head_hash=crypto.Digest(b"\xab" * 32),
            roster_size=3,
            mempool_size=7,
            peers=[],
            listeners=[],
        )
        raw = serde.dump(original)
        restored = serde.load(NodeStatusReply, raw)
        self.assertEqual(restored.head_block, 42)
        self.assertEqual(restored.head_hash, original.head_hash)
        self.assertEqual(restored.roster_size, 3)
        self.assertEqual(restored.mempool_size, 7)
        self.assertEqual(serde.dump(restored), raw)

    def test_none_mempool_survives(self) -> None:
        original = NodeStatusReply(
            head_block=0,
            head_hash=crypto.Digest(b"\x00" * 32),
            roster_size=0,
            mempool_size=None,
            peers=[],
            listeners=[],
        )
        restored = serde.load(NodeStatusReply, serde.dump(original))
        self.assertIsNone(restored.mempool_size)


class TestLinkCounters(unittest.TestCase):
    def test_counters_and_direction(self) -> None:
        c = Cluster(nodes=3, mgmt=0, rw=1)
        c.wait_block(1)

        lc = c.rw_clients[0]
        lc.bootstrap()

        s = lc.session_rw()
        c.wait_settled(s.put("counter-test", b"v").wait())

        node = c.nodes[0]
        node_status = node.postman.peer_status()
        client_pub = lc.me.public
        node_peer = node_status.get(client_pub)
        assert node_peer is not None, "node doesn't see client as peer"
        node_link = node_peer.links[0]

        self.assertGreater(node_link.msgs_recv, 0)
        self.assertGreater(node_link.bytes_recv, 0)
        self.assertGreater(node_link.msgs_sent, 0)
        self.assertGreater(node_link.bytes_sent, 0)
        self.assertEqual(node_link.direction, LinkDirection.INBOUND)
        self.assertGreater(node_link.established_at, Millis(0))

        client_status = lc.postman.peer_status()
        client_peer = client_status.get(node.me.public)
        assert client_peer is not None, "client doesn't see node as peer"
        client_link = client_peer.links[0]

        self.assertGreater(client_link.msgs_sent, 0)
        self.assertGreater(client_link.bytes_sent, 0)
        self.assertEqual(client_link.direction, LinkDirection.OUTBOUND)

        c.close()


class TestObserverTopology(unittest.TestCase):
    def test_query_returns_snapshots(self) -> None:
        c = Cluster(nodes=3, mgmt=0, ro=0, rw=0)
        c.wait_block(1)

        postman = Postman(c.anchor, c.tunables, on_output=OutputQueue())
        c.fabric.attach(postman)

        lc = LightClient(me=c.anchor, anchor=c.anchor.public, postman=postman)
        for node in c.nodes:
            lc.add_bootstrap_peer(
                node.me.public,
                (c.fabric.endpoint_for(node.me.public),),
            )
        obs = ClusterObserver(lc)
        lc.start()
        lc.bootstrap()

        obs.query_topology()

        deadline = time.monotonic() + c.tunables.ttl_exchange.as_seconds
        while time.monotonic() < deadline:
            topo = obs.topology()
            if len(topo.nodes) == 3:
                break
            time.sleep(0.05)

        lc.stop()
        c.close()

        topo = obs.topology()
        self.assertEqual(len(topo.nodes), 3, f"expected 3 node snapshots, got {len(topo.nodes)}")
        for snap in topo.nodes.values():
            self.assertGreaterEqual(snap.head_block, 1)
            self.assertEqual(snap.roster_size, 3)


class TestTCPFabric(unittest.TestCase):
    def test_consensus_over_tcp(self) -> None:
        c = Cluster(nodes=3, mgmt=1, fabric=TCPFabric())
        c.wait_block(1)

        s = c.replicas[0].session_rw()
        c.wait_settled(s.put("tcp-test", b"works").wait())
        self.assertEqual(s.get("tcp-test").value, b"works")

        c.close()

    def test_tcp_counters_and_direction(self) -> None:
        c = Cluster(nodes=3, mgmt=0, rw=1, fabric=TCPFabric())
        c.wait_block(1)

        lc = c.rw_clients[0]
        lc.bootstrap()

        s = lc.session_rw()
        c.wait_settled(s.put("tcp-counter", b"v").wait())

        node = c.nodes[0]
        node_status = node.postman.peer_status()
        client_pub = lc.me.public
        node_peer = node_status.get(client_pub)
        assert node_peer is not None, "node doesn't see client as peer"
        node_link = node_peer.links[0]

        self.assertGreater(node_link.msgs_recv, 0)
        self.assertGreater(node_link.bytes_recv, 0)
        self.assertEqual(node_link.direction, LinkDirection.INBOUND)
        self.assertIsNotNone(node_link.listener_addr)

        client_status = lc.postman.peer_status()
        client_peer = client_status.get(node.me.public)
        assert client_peer is not None, "client doesn't see node as peer"
        client_link = client_peer.links[0]

        self.assertGreater(client_link.msgs_sent, 0)
        self.assertEqual(client_link.direction, LinkDirection.OUTBOUND)
        self.assertIsNone(client_link.listener_addr)

        listener_stats = node.postman.listener_stats()
        self.assertGreater(len(listener_stats), 0)
        tcp_stats = listener_stats[0]
        self.assertGreater(int(tcp_stats.extra["conns_accepted"]), 0)

        c.close()


if __name__ == "__main__":
    unittest.main()
