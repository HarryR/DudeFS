# Link — the peer connection abstraction (L_msg over a carrier). Tested directly
# against a tiny signed-reply server, independent of the daemon.

import os
import tempfile
import threading
import time
import unittest

from dudefs import crypto as C
from dudefs import lmsg, transports
from dudefs.link import Link

A_SK, B_SK = bytes([1] * 32), bytes([2] * 32)
A, B = C.SIGNER.public(A_SK), C.SIGNER.public(B_SK)


def _echo_reply(payload: bytes) -> bytes | None:
    """A minimal peer: verify the request, sign a reply back to its sender (what a
    daemon's serve does, minus the gate/dispatch)."""
    env = lmsg.Envelope.decode(payload)
    if not env.verify_sig():
        return None
    return lmsg.author(B_SK, env.frm, env.verb, b"pong:" + env.body, epoch=0, ts=env.ts).encode()


class TestLink(unittest.TestCase):
    def _serve(self, td, handler):
        srv = transports.open_server(transports.UNIX)
        uri = os.path.join(td, "b.sock")
        ready = threading.Event()
        threading.Thread(target=srv.serve, args=(uri, handler, ready), daemon=True).start()
        self.assertTrue(ready.wait(2))
        return srv, uri

    def test_request_round_trips_a_verified_reply(self):
        with tempfile.TemporaryDirectory() as td:
            srv, uri = self._serve(td, _echo_reply)
            link = Link(A_SK, A, B, transports.Endpoint(transports.UNIX, uri))
            out = link.request(b"PING", b"hi", epoch=0, ts=100)
            self.assertIsInstance(out, lmsg.Reply)
            assert isinstance(out, lmsg.Reply)
            self.assertEqual(out.env.body, b"pong:hi")
            self.assertEqual(out.env.frm, B)  # signed by the peer I addressed
            srv.close()
            time.sleep(0.05)

    def test_unreachable_peer_is_a_typed_no_reply(self):
        link = Link(A_SK, A, B, transports.Endpoint(transports.UNIX, "/nonexistent.sock"))
        out = link.request(b"PING", b"hi", epoch=0, ts=100, timeout=0.3)
        self.assertIsInstance(out, lmsg.NoReply)

    def test_a_reply_from_the_wrong_peer_is_rejected(self):
        # the server signs its reply as SOMEONE ELSE -> not the peer I addressed
        def imposter(payload: bytes) -> bytes:
            e = lmsg.Envelope.decode(payload)
            return lmsg.author(bytes([9] * 32), e.frm, e.verb, b"x", epoch=0, ts=e.ts).encode()

        with tempfile.TemporaryDirectory() as td:
            srv, uri = self._serve(td, imposter)
            link = Link(A_SK, A, B, transports.Endpoint(transports.UNIX, uri))
            self.assertIsInstance(link.request(b"P", b"h", epoch=0, ts=100), lmsg.WrongPeer)
            srv.close()
            time.sleep(0.05)


if __name__ == "__main__":
    unittest.main()
