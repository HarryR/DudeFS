from __future__ import annotations

import os
import shutil
import tempfile
import time
import unittest

from ..net.socket_server import SocketServer
from ..net.socket_substrate import SocketSubstrate
from ..node import _ReplicaSubstrate
from ..session import SessionRW, Settled
from ..store import ops
from ..sync.lite_client import _LiteSubstrate
from .cluster import Cluster


class TestSettlementLatency(unittest.TestCase):
    def _measure(self, session, cluster, label: str, n: int = 3) -> None:
        for i in range(n):
            t0 = time.monotonic()
            result = session.put(f"latency/{label}/{i}", b"v").wait()
            elapsed = time.monotonic() - t0
            self.assertIsInstance(result, Settled, f"{label} #{i} @ {elapsed:.3f}s: {result!r}")
            cluster.wait_settled(result)

    def test_replica_direct(self) -> None:
        with Cluster(nodes=3, mgmt=1) as c:
            self._measure(c.replicas[0].session(), c, "replica_direct")

    def test_replica_via_socket(self) -> None:
        tmpdir = tempfile.mkdtemp()
        sock_path = os.path.join(tmpdir, "test.sock")
        try:
            with Cluster(nodes=3, mgmt=1) as c:
                sub = _ReplicaSubstrate(c.replicas[0])
                with (
                    SocketServer(sock_path, sub),
                    SocketSubstrate(sock_path, c.tunables) as client_sub,
                ):
                    self._measure(SessionRW(client_sub, ops.STORE_DATA), c, "replica_socket")
        finally:
            shutil.rmtree(tmpdir)

    def test_light_client_direct(self) -> None:
        with Cluster(nodes=3, mgmt=0, rw=1) as c:
            lc = c.rw_clients[0]
            lc.bootstrap()
            self._measure(lc.session(), c, "lite_direct")

    def test_light_client_via_socket(self) -> None:
        tmpdir = tempfile.mkdtemp()
        sock_path = os.path.join(tmpdir, "test.sock")
        try:
            with Cluster(nodes=3, mgmt=0, rw=1) as c:
                lc = c.rw_clients[0]
                lc.bootstrap()

                sub = _LiteSubstrate(lc)
                with (
                    SocketServer(sock_path, sub),
                    SocketSubstrate(sock_path, c.tunables) as client_sub,
                ):
                    self._measure(SessionRW(client_sub, ops.STORE_DATA), c, "lite_socket")
        finally:
            shutil.rmtree(tmpdir)


if __name__ == "__main__":
    unittest.main()
