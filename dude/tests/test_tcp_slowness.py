"""Minimal reproducer for SQLite read slowness with TCP cluster active.

With InProc fabric, mgmt_reader.nodes() takes ~2ms.
With TCP fabric (same store, same data, same thread), it takes 1-4 seconds.

Run:
    python -m pytest dude/tests/test_tcp_slowness.py -v -s
"""

import time
import unittest

from .cluster import Cluster, TCPFabric


class TestSQLiteSlownessWithTCP(unittest.TestCase):
    def _bench_reads(self, store, iterations: int = 5) -> float:
        t0 = time.monotonic()
        for _ in range(iterations):
            mr = store.mgmt_reader
            mr.nodes()
            mr.roster()
            mr.authorized_identities()
        return (time.monotonic() - t0) * 1000 / iterations

    def test_inproc_reads_are_fast(self) -> None:
        c = Cluster(nodes=3, mgmt=0)
        try:
            time.sleep(1)
            ms = self._bench_reads(c.nodes[0].store)
            print(f"\nInProc: {ms:.1f}ms per read cycle")
            self.assertLess(ms, 50, "InProc reads should be under 50ms")
        finally:
            c.close()

    def test_tcp_reads_are_slow(self) -> None:
        c = Cluster(nodes=3, mgmt=0, fabric=TCPFabric())
        try:
            time.sleep(1)
            ms = self._bench_reads(c.nodes[0].store)
            print(f"\nTCP: {ms:.1f}ms per read cycle")
            # This currently fails — TCP reads take 1-4 seconds
            # The test documents the bug; remove the skip when fixed
            if ms > 100:
                self.fail(f"TCP reads take {ms:.0f}ms per cycle (expected <50ms, same as InProc)")
        finally:
            c.close()


if __name__ == "__main__":
    unittest.main()
