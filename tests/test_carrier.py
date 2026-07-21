# The L_txport seam (transport.py): a carrier owns the I/O + framing and takes a pure
# handler. Tested directly over a real unix socket, independent of the daemon.
# (NB: tests/test_transport.py covers the SIM fault-carrier — dudefs.transports.memory
# — a distinct thing; the transport/transports proximity is flagged for review.)

import os
import socket
import tempfile
import threading
import time
import unittest

from dudefs import transport


class TestUnixCarrier(unittest.TestCase):
    def _serve(self, td, handler):
        srv = transport.open_server(transport.UNIX)
        uri = os.path.join(td, "n.sock")
        ready = threading.Event()
        threading.Thread(target=srv.serve, args=(uri, handler, ready), daemon=True).start()
        self.assertTrue(ready.wait(2))
        return srv, uri

    def test_dial_serve_round_trip(self):
        # the carrier frames + moves the payload; the handler sees/returns raw payloads
        with tempfile.TemporaryDirectory() as td:
            srv, uri = self._serve(td, lambda payload: b"echo:" + payload)
            self.assertEqual(transport.dial(transport.UNIX, uri, b"hello"), b"echo:hello")
            srv.close()
            time.sleep(0.05)

    def test_handler_none_renders_carrier_silence(self):
        # a None reply -> the carrier's 'nothing' (a closed conn) -> the dialer reads b""
        with tempfile.TemporaryDirectory() as td:
            srv, uri = self._serve(td, lambda _payload: None)
            self.assertEqual(transport.dial(transport.UNIX, uri, b"x"), b"")
            srv.close()
            time.sleep(0.05)

    def test_unreachable_dials_to_empty_not_a_crash(self):
        with tempfile.TemporaryDirectory() as td:
            missing = os.path.join(td, "nope.sock")
            self.assertEqual(transport.dial(transport.UNIX, missing, b"x", timeout=0.3), b"")

    def test_unknown_scheme_is_a_loud_config_error(self):
        # an unknown carrier is a real misconfiguration -> KeyError, never a silent no-op
        with self.assertRaises(KeyError):
            transport.dial(b"carrier-pigeon", "somewhere", b"x")


class TestHttpCarrier(unittest.TestCase):
    def _serve(self, handler):
        with socket.socket() as probe:  # a free port, then serve HTTP on it
            probe.bind(("127.0.0.1", 0))
            uri = f"http://127.0.0.1:{probe.getsockname()[1]}/dude"
        srv = transport.open_server(transport.HTTP)
        ready = threading.Event()
        threading.Thread(target=srv.serve, args=(uri, handler, ready), daemon=True).start()
        self.assertTrue(ready.wait(2))
        return srv, uri

    def test_dial_serve_round_trip_over_http(self):
        # HTTP's Content-Length is the framing; the payload is the raw POST body
        srv, uri = self._serve(lambda payload: b"echo:" + payload)
        self.assertEqual(transport.dial(transport.HTTP, uri, b"hello"), b"echo:hello")
        srv.close()

    def test_none_renders_http_404_as_silence(self):
        srv, uri = self._serve(lambda _payload: None)
        self.assertEqual(transport.dial(transport.HTTP, uri, b"x"), b"")  # 404 -> b""
        srv.close()

    def test_unreachable_http_dials_to_empty(self):
        with socket.socket() as probe:  # a port nobody is listening on
            probe.bind(("127.0.0.1", 0))
            uri = f"http://127.0.0.1:{probe.getsockname()[1]}/dude"
        self.assertEqual(transport.dial(transport.HTTP, uri, b"x", timeout=0.3), b"")


if __name__ == "__main__":
    unittest.main()
