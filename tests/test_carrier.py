# The L_txport seam (transport.py): a carrier owns the I/O + framing and takes a pure
# handler. Tested directly over a real unix socket, independent of the daemon.
# (NB: tests/test_transport.py covers the SIM fault-carrier — dudefs.transports.memory
# — a distinct thing; the transport/transports proximity is flagged for review.)

import os
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


if __name__ == "__main__":
    unittest.main()
