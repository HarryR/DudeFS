from __future__ import annotations

import os
import tempfile
import unittest

from ..net.socket_server import SocketServer
from ..net.socket_substrate import SocketSubstrate
from ..node import _ReplicaSubstrate
from ..session import SessionRW
from ..store import ops
from ..tunables import DEFAULT
from .cluster import Cluster


class TestSocketSubstrate(unittest.TestCase):
    def setUp(self) -> None:
        self.c = Cluster(nodes=3, mgmt=1)
        self._tmpdir = tempfile.mkdtemp()
        self._sock_path = os.path.join(self._tmpdir, "test.sock")
        replica = self.c.replicas[0]
        self._real_sub = _ReplicaSubstrate(replica)
        self._server = SocketServer(self._sock_path, self._real_sub)
        self._server.start()

    def tearDown(self) -> None:
        self._server.stop()
        self.c.close()
        os.rmdir(self._tmpdir)

    def _session(self, store_id: int = ops.STORE_DATA) -> SessionRW:
        sub = SocketSubstrate(self._sock_path, DEFAULT)
        self.addCleanup(sub.close)
        return SessionRW(sub, store_id)

    def test_put_and_get(self) -> None:
        s = self._session()
        result = s.put("hello", b"world").wait()
        self.c.wait_settled(result)
        rec = s.get("hello")
        self.assertFalse(rec.absent)
        self.assertEqual(rec.value, b"world")

    def test_delete(self) -> None:
        s = self._session()
        self.c.wait_settled(s.put("gone", b"val").wait())
        self.c.wait_settled(s.delete("gone").wait())
        rec = s.get("gone")
        self.assertTrue(rec.absent)

    def test_cas_with_expect(self) -> None:
        s = self._session()
        self.c.wait_settled(s.put("counter", b"1").wait())
        rec = s.get("counter")
        self.c.wait_settled(s.put("counter", b"2", expect=rec).wait())
        updated = s.get("counter")
        self.assertEqual(updated.value, b"2")

    def test_multi_step_transaction(self) -> None:
        s = self._session()
        self.c.wait_settled(s.put("a", b"10").wait())
        self.c.wait_settled(s.put("b", b"20").wait())
        rec_a = s.get("a")
        rec_b = s.get("b")
        tx = s.begin()
        tx.put("a", b"11", expect=rec_a)
        tx.put("b", b"21", expect=rec_b)
        self.c.wait_settled(tx.submit().wait())
        self.assertEqual(s.get("a").value, b"11")
        self.assertEqual(s.get("b").value, b"21")

    def test_management_session(self) -> None:
        s = self._session(store_id=ops.STORE_MANAGEMENT)
        rec = s.get(b"roster")
        self.assertFalse(rec.absent)

    def test_anchor(self) -> None:
        s = self._session()
        self.assertEqual(s.anchor, self.c.anchor.public)

    def test_multiple_clients(self) -> None:
        s1 = self._session()
        s2 = self._session()
        self.c.wait_settled(s1.put("from_s1", b"v1").wait())
        self.c.wait_settled(s2.put("from_s2", b"v2").wait())
        self.assertEqual(s1.get("from_s2").value, b"v2")
        self.assertEqual(s2.get("from_s1").value, b"v1")

    def test_concurrent_submits(self) -> None:
        s = self._session()
        h1 = s.put("x", b"1")
        h2 = s.put("y", b"2")
        self.c.wait_settled(h1.wait())
        self.c.wait_settled(h2.wait())
        self.assertEqual(s.get("x").value, b"1")
        self.assertEqual(s.get("y").value, b"2")

    def test_client_disconnect_does_not_break_server(self) -> None:
        s1 = self._session()
        self.c.wait_settled(s1.put("before", b"v").wait())
        s1._sub.close()
        s2 = self._session()
        rec = s2.get("before")
        self.assertFalse(rec.absent)
        self.assertEqual(rec.value, b"v")

    def test_head_updates_after_commit(self) -> None:
        sub = SocketSubstrate(self._sock_path, DEFAULT)
        self.addCleanup(sub.close)
        s = SessionRW(sub, ops.STORE_DATA)
        self.c.wait_settled(s.put("probe", b"v").wait())
        h = sub.head()
        self.assertIsNotNone(h)
        assert h is not None
        self.assertGreater(h.block_num, 0)
        self.assertEqual(len(h.block_hash), 32)


if __name__ == "__main__":
    unittest.main()
