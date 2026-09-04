from __future__ import annotations

import time
import unittest

from ..core import crypto
from ..core.units import Millis
from ..net.postman import OutputQueue, Postman
from ..net.transports.inproc import InProcNexus
from ..tunables import Tunables

T = Tunables(rtt_max=Millis(50), clock_skew=Millis(25), held_convergence_max=2)


def _connected_pair() -> tuple[Postman, OutputQueue, Postman, OutputQueue, InProcNexus]:
    a = crypto.Keypair.generate()
    b = crypto.Keypair.generate()
    nexus = InProcNexus()

    aq, bq = OutputQueue(), OutputQueue()
    ap = Postman(a, T, on_output=aq)
    bp = Postman(b, T, on_output=bq)

    nexus.attach(ap)
    bl = nexus.attach(bp)

    ap.add_peer(b.public, (bl.endpoint,))
    bp.add_peer(a.public, (nexus.endpoint_for(a.public),))

    ap.start()
    bp.start()

    return ap, aq, bp, bq, nexus


class TestPingOnConnect(unittest.TestCase):
    def test_keepalive_pong_not_visible_to_consumer(self) -> None:
        ap, aq, bp, bq, _nexus = _connected_pair()
        try:
            deadline = time.monotonic() + T.ttl_exchange.as_seconds
            while time.monotonic() < deadline:
                status = ap.peer_status()
                if status and next(iter(status.values())).connected:
                    break
                time.sleep(0.01)

            time.sleep(T.block_time.as_seconds * 0.5)

            pongs_a = 0
            while True:
                out = aq.get(timeout=0.0)
                if out is None:
                    break
                for d in out.delivered:
                    if d.verb.name == "PONG":
                        pongs_a += 1

            pongs_b = 0
            while True:
                out = bq.get(timeout=0.0)
                if out is None:
                    break
                for d in out.delivered:
                    if d.verb.name == "PONG":
                        pongs_b += 1

            self.assertEqual(pongs_a, 0, "keepalive PONG leaked to consumer A")
            self.assertEqual(pongs_b, 0, "keepalive PONG leaked to consumer B")
        finally:
            ap.stop()
            bp.stop()

    def test_peer_status_reports_connection(self) -> None:
        ap, _aq, bp, _bq, _nexus = _connected_pair()
        try:
            deadline = time.monotonic() + T.ttl_exchange.as_seconds
            while time.monotonic() < deadline:
                status = ap.peer_status()
                if status and next(iter(status.values())).connected:
                    break
                time.sleep(0.01)
            else:
                self.fail("peer never connected")

            status = ap.peer_status()
            self.assertEqual(len(status), 1)
            peer = next(iter(status.values()))
            self.assertTrue(peer.connected)
            self.assertGreater(len(peer.links), 0)
        finally:
            ap.stop()
            bp.stop()


if __name__ == "__main__":
    unittest.main()
