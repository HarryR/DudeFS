# Unit tests for the TCP transport in isolation. Nothing above the transport is exercised
# here -- these test the CARRIER, not the protocol. Frame construction is minimal-real
# (through Envelope.sign().seal()) so we're moving actual sealed frame bytes.

from __future__ import annotations

import time
import unittest

from dude.core import crypto
from dude.net.address import Address, Scheme
from dude.net.envelope import Envelope, Verb
from dude.net.link import LinkError
from dude.net.transports.tcp import TCP


def _make_frame(sender: crypto.Keypair, recipient: crypto.PublicKey, body: bytes = b"hi"):
    env = Envelope(to=recipient, verb=Verb.PING, mid=b"m" * 16, body=body)
    return env.sign(sender, 1_000_000).seal()


def _drain_until(rx: TCP, want: int, tries: int = 200) -> tuple:
    """Poll `rx.receive()` up to `tries` times, sleeping between polls, until we have at
    least `want` frames or run out of tries. TCP is asynchronous under the hood: even on
    loopback, the accept + data + read chain takes multiple event-loop turns."""
    got: list = []
    for _ in range(tries):
        got.extend(rx.receive())
        if len(got) >= want:
            return tuple(got)
        time.sleep(0.001)
    return tuple(got)


class TestTCPRoundTrip(unittest.TestCase):
    def test_one_frame_end_to_end(self):
        """Send one frame; the receiver drains it. Baseline correctness."""
        a_kp = crypto.Keypair.generate()
        b_kp = crypto.Keypair.generate()

        b = TCP()  # binds to 127.0.0.1:0
        a = TCP()
        try:
            frame = _make_frame(a_kp, b_kp.public)
            a.send(b.bound_address, frame)
            got = _drain_until(b, 1)
            self.assertEqual(len(got), 1, "expected one frame")
            self.assertEqual(got[0].sealed, frame.sealed)
            self.assertEqual(got[0].tag, frame.tag)
        finally:
            a.close()
            b.close()

    def test_many_frames_preserve_order_on_one_connection(self):
        """Multiple sends on the reused outbound socket arrive in order at the receiver."""
        a_kp = crypto.Keypair.generate()
        b_kp = crypto.Keypair.generate()
        b = TCP()
        a = TCP()
        try:
            frames = [_make_frame(a_kp, b_kp.public, body=f"n={i}".encode()) for i in range(20)]
            for f in frames:
                a.send(b.bound_address, f)
            got = _drain_until(b, len(frames))
            self.assertEqual(len(got), len(frames))
            # Order preserved.
            for i, f in enumerate(got):
                self.assertEqual(f.sealed, frames[i].sealed)
        finally:
            a.close()
            b.close()

    def test_split_stream_reassembles_across_reads(self):
        """The receiver's read buffer must reassemble a frame that arrives in multiple
        chunks. The kernel usually delivers loopback writes as single reads, so we force
        the fragmentation by writing a big frame that exceeds the receiver's recv buffer
        for a single call. If reassembly is broken, this test either fails to produce a
        complete frame or produces a corrupt one."""
        a_kp = crypto.Keypair.generate()
        b_kp = crypto.Keypair.generate()
        b = TCP()
        a = TCP()
        try:
            big_body = b"x" * (128 * 1024)  # 128 KiB body -> forces multi-read
            frame = _make_frame(a_kp, b_kp.public, body=big_body)
            a.send(b.bound_address, frame)
            got = _drain_until(b, 1, tries=500)
            self.assertEqual(len(got), 1)
            self.assertEqual(got[0].sealed, frame.sealed)
        finally:
            a.close()
            b.close()

    def test_connect_refused_raises_link_error(self):
        """Send to an address nobody's bound to: LinkError from the transport, caller's
        problem to translate (Refused.TRANSPORT at the link layer)."""
        a_kp = crypto.Keypair.generate()
        b_kp = crypto.Keypair.generate()
        a = TCP()
        try:
            # Bind + close to reserve then release a port -- best-effort unbound target.
            probe = TCP()
            dead_address = probe.bound_address
            probe.close()

            frame = _make_frame(a_kp, b_kp.public)
            with self.assertRaises(LinkError):
                a.send(dead_address, frame)
        finally:
            a.close()

    def test_wrong_scheme_raises_link_error(self):
        """A TCP transport asked to dial `inproc:` refuses at the transport layer -- the
        scheme-dispatch cache above should never route wrong-scheme addresses here, but
        the transport still refuses defensively."""
        a_kp = crypto.Keypair.generate()
        b_kp = crypto.Keypair.generate()
        a = TCP()
        try:
            frame = _make_frame(a_kp, b_kp.public)
            with self.assertRaises(LinkError):
                a.send(Address(Scheme.INPROC, "not-a-tcp-address"), frame)
        finally:
            a.close()

    def test_receive_is_idempotent_when_empty(self):
        """`receive()` on a quiet transport returns () and doesn't block."""
        b = TCP()
        try:
            self.assertEqual(b.receive(), ())
            self.assertEqual(b.receive(), ())
        finally:
            b.close()

    def test_close_is_idempotent(self):
        """Two `close()` calls are safe."""
        t = TCP()
        t.close()
        t.close()  # no raise


if __name__ == "__main__":
    unittest.main()
