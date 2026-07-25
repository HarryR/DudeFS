# The L_txport carriers (dudefs.transports): a carrier owns the I/O + framing and takes
# a pure handler. Tested directly over real unix + HTTP, independent of the daemon.
# (The deterministic SIM fault-carrier — tests/_carrier.py — is a different API driven
# by the quorum property tests; this file covers the real unix/http carriers.)

import os
import socket
import tempfile
import threading
import time
import unittest

from dudefs import transports


class TestUnixCarrier(unittest.TestCase):
    def _serve(self, td, handler):
        srv = transports.open_server(transports.UNIX)
        uri = os.path.join(td, "n.sock")
        ready = threading.Event()
        threading.Thread(target=srv.serve, args=(uri, handler, ready), daemon=True).start()
        self.assertTrue(ready.wait(2))
        return srv, uri

    def test_dial_serve_round_trip(self):
        # the carrier frames + moves the payload; the handler sees/returns raw payloads
        with tempfile.TemporaryDirectory() as td:
            srv, uri = self._serve(td, lambda payload: b"echo:" + payload)
            self.assertEqual(transports.dial(transports.UNIX, uri, b"hello"), b"echo:hello")
            srv.close()
            time.sleep(0.05)

    def test_handler_none_renders_carrier_silence(self):
        # a None reply -> the carrier's 'nothing' (a closed conn) -> the dialer reads b""
        with tempfile.TemporaryDirectory() as td:
            srv, uri = self._serve(td, lambda _payload: None)
            self.assertEqual(transports.dial(transports.UNIX, uri, b"x"), b"")
            srv.close()
            time.sleep(0.05)

    def test_unreachable_dials_to_empty_not_a_crash(self):
        with tempfile.TemporaryDirectory() as td:
            missing = os.path.join(td, "nope.sock")
            self.assertEqual(transports.dial(transports.UNIX, missing, b"x", timeout=0.3), b"")

    def test_unknown_scheme_is_a_loud_config_error(self):
        # an unknown carrier is a real misconfiguration -> KeyError, never a silent no-op
        with self.assertRaises(KeyError):
            transports.dial(b"carrier-pigeon", "somewhere", b"x")


class TestHttpCarrier(unittest.TestCase):
    def _serve(self, handler):
        with socket.socket() as probe:  # a free port, then serve HTTP on it
            probe.bind(("127.0.0.1", 0))
            uri = f"http://127.0.0.1:{probe.getsockname()[1]}/dude"
        srv = transports.open_server(transports.HTTP)
        ready = threading.Event()
        threading.Thread(target=srv.serve, args=(uri, handler, ready), daemon=True).start()
        self.assertTrue(ready.wait(2))
        return srv, uri

    def test_dial_serve_round_trip_over_http(self):
        # HTTP's Content-Length is the framing; the payload is the raw POST body
        srv, uri = self._serve(lambda payload: b"echo:" + payload)
        self.assertEqual(transports.dial(transports.HTTP, uri, b"hello"), b"echo:hello")
        srv.close()

    def test_none_renders_http_404_as_silence(self):
        srv, uri = self._serve(lambda _payload: None)
        self.assertEqual(transports.dial(transports.HTTP, uri, b"x"), b"")  # 404 -> b""
        srv.close()

    def test_unreachable_http_dials_to_empty(self):
        with socket.socket() as probe:  # a port nobody is listening on
            probe.bind(("127.0.0.1", 0))
            uri = f"http://127.0.0.1:{probe.getsockname()[1]}/dude"
        self.assertEqual(transports.dial(transports.HTTP, uri, b"x", timeout=0.3), b"")


class TestParseEndpoint(unittest.TestCase):
    """The edge decomposer: an operator URL -> a dial `Endpoint`, parsed ONCE. Custom
    composite schemes let one URL replace a pile of flags."""

    def test_bare_path_defaults_to_unix(self):
        self.assertEqual(
            transports.parse_endpoint("/run/n.sock"), transports.Endpoint(b"unix", "/run/n.sock")
        )

    def test_explicit_unix_scheme_strips_to_the_path(self):
        self.assertEqual(
            transports.parse_endpoint("unix:/run/n.sock"),
            transports.Endpoint(b"unix", "/run/n.sock"),
        )

    def test_http_url_keeps_its_base_url(self):
        self.assertEqual(
            transports.parse_endpoint("http://host:8080/dude"),
            transports.Endpoint(b"http", "http://host:8080/dude"),
        )

    def test_composite_sealed_http_decomposes_carrier_and_profile(self):
        self.assertEqual(
            transports.parse_endpoint("sealed+http://host/dude"),
            transports.Endpoint(b"http", "http://host/dude", True),
        )

    def test_parse_scheme_splits_modifiers_from_the_carrier(self):
        self.assertEqual(transports.parse_scheme(b"sealed+http"), (frozenset({b"sealed"}), b"http"))
        self.assertEqual(transports.parse_scheme(b"http"), (frozenset(), b"http"))


if __name__ == "__main__":
    unittest.main()
