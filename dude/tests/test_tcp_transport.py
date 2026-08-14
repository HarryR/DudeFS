# Unit tests for the TCP transport in isolation. Nothing above the transport is exercised
# here -- these test the CARRIER, not the protocol. Frame construction is minimal-real
# (through Envelope.sign().seal()) so we're moving actual sealed frame bytes.
#
# TWO CONCRETE TYPES: `TCPDialer` (send-only) and `TCPListener` (receive-only). Tests
# exercise the split explicitly -- a client sends to a listener's bound_address; the
# listener drains via `drain()` (test path, no threads).

from __future__ import annotations

import queue
import socket
import threading
import time
import unittest

from dude.core import crypto
from dude.net.address import Address, Scheme
from dude.net.envelope import Envelope, Frame, Verb
from dude.net.link import LinkError
from dude.net.session import Inbound
from dude.net.transports.tcp import (
    _LEN,
    TCPDialer,
    TCPListener,
    TCPSession,
    TCPTiming,
)

_TIMING = TCPTiming()
"""TCP's own defaults. These tests are about the transport's behaviour under its own bounds, so
they read them from the transport rather than from a deployment that has no say in them."""


def _make_frame(sender: crypto.Keypair, recipient: crypto.PublicKey, body: bytes = b"hi") -> Frame:
    env = Envelope(to=recipient, verb=Verb.PING, mid=b"m" * 16, body=body)
    return env.sign(sender, 1_000_000).seal()


def _connected(client: TCPDialer, address: Address, tries: int = 2_000) -> None:
    """Ask for a link, then wait for it. `send` does not dial any more -- it is the tick thread's
    caller, and a dial is not the tick thread's work. `Connectivity` keeps a link unusable until
    the carrier reports `ready`, so a test that sends has to do what a link does."""
    client.begin_connect(address)
    for _ in range(tries):
        if client.ready(address):
            return
        time.sleep(0.001)
    raise AssertionError(f"dialer never became ready for {address.value}")


def _drain_until(rx: TCPListener, want: int, tries: int = 200) -> tuple[Frame, ...]:
    """Poll `rx.drain()` up to `tries` times, sleeping between polls, until we have at
    least `want` frames or run out of tries. TCP is asynchronous under the hood: even on
    loopback, the accept + data + read chain takes multiple event-loop turns.

    Unwraps `Inbound(frame, session)` -- tests here care about the frames only, session
    binding is exercised elsewhere via Node.receive."""
    got: list[Frame] = []
    for _ in range(tries):
        got.extend(inbound.frame for inbound in rx.drain())
        if len(got) >= want:
            return tuple(got)
        time.sleep(0.001)
    return tuple(got)


class TestTCPRoundTripViaDrain(unittest.TestCase):
    """Test-path driver: `drain()` on the listener, no threads. Same primitives the
    non-threaded test pumps use."""

    def test_one_frame_end_to_end(self):
        a_kp = crypto.Keypair.generate()
        b_kp = crypto.Keypair.generate()
        listener = TCPListener()  # binds to 127.0.0.1:0
        client = TCPDialer()
        try:
            frame = _make_frame(a_kp, b_kp.public)
            _connected(client, listener.bound_address)
            client.send(listener.bound_address, frame)
            got = _drain_until(listener, 1)
            self.assertEqual(len(got), 1, "expected one frame")
            self.assertEqual(got[0].sealed, frame.sealed)
            self.assertEqual(got[0].tag, frame.tag)
        finally:
            client.close()
            listener.stop()

    def test_many_frames_preserve_order_on_one_connection(self):
        """Multiple sends on the reused outbound socket arrive in order at the receiver."""
        a_kp = crypto.Keypair.generate()
        b_kp = crypto.Keypair.generate()
        listener = TCPListener()
        client = TCPDialer()
        try:
            frames = [_make_frame(a_kp, b_kp.public, body=f"n={i}".encode()) for i in range(20)]
            _connected(client, listener.bound_address)
            for f in frames:
                client.send(listener.bound_address, f)
            got = _drain_until(listener, len(frames))
            self.assertEqual(len(got), len(frames))
            for i, f in enumerate(got):
                self.assertEqual(f.sealed, frames[i].sealed)
        finally:
            client.close()
            listener.stop()

    def test_split_stream_reassembles_across_reads(self):
        """A frame that arrives in multiple recv() chunks must be reassembled. Forced with
        a 128 KiB body -- kernel usually delivers loopback writes as single reads, but a
        body of this size exceeds one recv() buffer."""
        a_kp = crypto.Keypair.generate()
        b_kp = crypto.Keypair.generate()
        listener = TCPListener()
        client = TCPDialer()
        try:
            big_body = b"x" * (128 * 1024)
            frame = _make_frame(a_kp, b_kp.public, body=big_body)
            _connected(client, listener.bound_address)
            client.send(listener.bound_address, frame)
            got = _drain_until(listener, 1, tries=500)
            self.assertEqual(len(got), 1)
            self.assertEqual(got[0].sealed, frame.sealed)
        finally:
            client.close()
            listener.stop()

    def test_connect_refused_raises_link_error(self):
        """Send to an address nobody's bound to: `LinkError` from the client, caller's
        problem to translate (Refused.TRANSPORT at the link layer)."""
        a_kp = crypto.Keypair.generate()
        b_kp = crypto.Keypair.generate()
        client = TCPDialer()
        try:
            # Bind + immediately stop to reserve then release a port -- best-effort dead target.
            probe = TCPListener()
            dead_address = probe.bound_address
            probe.stop()

            frame = _make_frame(a_kp, b_kp.public)
            # The dial fails on the carrier's thread, so the link simply never becomes ready --
            # and a send without one is an error, because `Connectivity` should have stopped it.
            client.begin_connect(dead_address)
            for _ in range(2_000):
                if client.ready(dead_address):
                    break
                time.sleep(0.001)
            self.assertFalse(client.ready(dead_address), "a refused connect produced a session")
            with self.assertRaises(LinkError):
                client.send(dead_address, frame)
        finally:
            client.close()

    def test_wrong_scheme_raises_link_error(self):
        """A `TCPDialer` asked to dial an INPROC address refuses at the transport layer.
        The scheme dispatch above should never route wrong-scheme addresses here, but the
        client still refuses defensively."""
        a_kp = crypto.Keypair.generate()
        b_kp = crypto.Keypair.generate()
        client = TCPDialer()
        try:
            frame = _make_frame(a_kp, b_kp.public)
            with self.assertRaises(LinkError):
                client.send(Address(Scheme.INPROC, "not-a-tcp-address"), frame)
        finally:
            client.close()

    def test_drain_is_idempotent_when_empty(self):
        """`drain()` on a quiet listener returns () and doesn't block."""
        listener = TCPListener()
        try:
            self.assertEqual(listener.drain(), ())
            self.assertEqual(listener.drain(), ())
        finally:
            listener.stop()

    def test_stop_is_idempotent(self):
        """Two `stop()` calls are safe. Same for client.close()."""
        listener = TCPListener()
        listener.stop()
        listener.stop()  # no raise
        client = TCPDialer()
        client.close()
        client.close()


class TestTCPListenerStartStop(unittest.TestCase):
    """Production-path driver: `listener.start(inbox)` spawns a reader thread that pushes
    each complete frame into the caller's queue. `stop()` signals + joins."""

    def test_frames_appear_in_inbox_after_start(self):
        a_kp = crypto.Keypair.generate()
        b_kp = crypto.Keypair.generate()
        inbox: queue.SimpleQueue[Inbound] = queue.SimpleQueue()
        listener = TCPListener()
        client = TCPDialer()
        try:
            listener.start(inbox)
            frame = _make_frame(a_kp, b_kp.public)
            _connected(client, listener.bound_address)
            client.send(listener.bound_address, frame)
            # Reader thread should push within a few select-cycles.
            got = inbox.get(timeout=2.0)
            self.assertEqual(got.frame.sealed, frame.sealed)
        finally:
            client.close()
            listener.stop()

    def test_stop_returns_within_timeout(self):
        """`stop()` must return within a bounded time -- specifically well under the
        reader-thread's `select()` block. Otherwise process shutdown drags."""
        listener = TCPListener()
        inbox: queue.SimpleQueue[Inbound] = queue.SimpleQueue()
        listener.start(inbox)
        # Give the reader a moment to enter its select() loop.
        time.sleep(0.05)
        start = time.monotonic()
        listener.stop()
        elapsed = time.monotonic() - start
        # `_SELECT_TIMEOUT_SEC` is 0.5s + a 2s join budget in stop(); we should be well
        # under the join budget in practice because listener.shutdown() wakes select().
        self.assertLess(elapsed, 2.5, f"stop() took {elapsed:.2f}s, expected < 2.5s")

    def test_start_twice_with_same_inbox_is_idempotent(self):
        listener = TCPListener()
        inbox: queue.SimpleQueue[Inbound] = queue.SimpleQueue()
        try:
            listener.start(inbox)
            listener.start(inbox)  # same inbox -- no raise
        finally:
            listener.stop()

    def test_start_twice_with_different_inbox_raises(self):
        """A different inbox after start is a caller error -- the reader thread is
        already pushing into the first one, and the object doesn't support two."""
        listener = TCPListener()
        inbox_a: queue.SimpleQueue[Inbound] = queue.SimpleQueue()
        inbox_b: queue.SimpleQueue[Inbound] = queue.SimpleQueue()
        try:
            listener.start(inbox_a)
            with self.assertRaises(RuntimeError):
                listener.start(inbox_b)
        finally:
            listener.stop()

    def test_bind_failure_surfaces_at_construction(self):
        """Fail-loud on bind: if a port is taken, `TCPListener(...)` raises `OSError`
        before the caller can even reach `start()`. This is the property `Node.start(...)`
        depends on for atomic-start rollback on partial listener failure."""
        first = TCPListener()
        port = int(first.bound_address.value.rsplit(":", 1)[1])
        try:
            with self.assertRaises(OSError):
                TCPListener(listen_port=port)
        finally:
            first.stop()


class TestReaderThreadShape(unittest.TestCase):
    """Sanity check that the reader thread is actually a background thread (not the
    calling thread) and that it exits when `stop()` is called."""

    def test_reader_thread_exits_on_stop(self):
        listener = TCPListener()
        inbox: queue.SimpleQueue[Inbound] = queue.SimpleQueue()
        listener.start(inbox)
        thread = listener._thread
        self.assertIsNotNone(thread)
        assert thread is not None
        self.assertTrue(thread.is_alive())
        self.assertNotEqual(thread.ident, threading.get_ident())  # NOT the test thread
        listener.stop()
        self.assertFalse(thread.is_alive())


def _big_frame(size: int) -> Frame:
    """A structurally valid frame around an opaque sealed blob -- the carrier never opens it."""
    kp = crypto.Keypair.generate()
    return Frame(crypto.screen_tag(kp.public, b"big"), crypto.SealedBlob(bytes(size)))


def _backpressured_session(
    sndbuf: int = 8192, timing: TCPTiming = _TIMING
) -> tuple[TCPSession, socket.socket, list[Address]]:
    """A session whose peer socket nobody reads, so the kernel buffer fills. Returns the list the
    session appends to when its link breaks -- the report the scheduler needs."""
    left, right = socket.socketpair()
    left.setsockopt(socket.SOL_SOCKET, socket.SO_SNDBUF, sndbuf)
    broken: list[Address] = []
    session = TCPSession(
        left, Address(Scheme.TCP, "pair:0"), timing, lambda _item: None, broken.append
    )
    return session, right, broken


class TestDiallingNeverBlocksTheCaller(unittest.TestCase):
    """THE INVARIANT: nothing on the caller's path may block on the wire. The caller is the node's
    single tick thread, so a blocking dial there stalls consensus and sync for as long as it takes.

    It was a blocking `connect()` with no timeout -- the OS SYN timeout, minutes -- and the first
    fix only bounded it, which chose how long the stall lasted rather than removing it. The bound
    then derived from the block time, so at production settings one firewalled address stalled the
    tick thread for 22 seconds.

    192.0.2.1 is TEST-NET-1 (RFC 5737): never routable, so the SYN goes unanswered -- exactly the
    firewalled-peer shape."""

    def test_begin_connect_to_a_blackholed_address_returns_at_once(self):
        client = TCPDialer()
        black_hole = Address(Scheme.TCP, "192.0.2.1:9")
        try:
            start = time.monotonic()
            for _ in range(5):  # a link asks on every tick it is due; none of them may pay
                client.begin_connect(black_hole)
            elapsed = time.monotonic() - start
            self.assertLess(
                elapsed,
                0.05,
                f"begin_connect blocked {elapsed:.2f}s: the wire is back on the caller's thread",
            )
            self.assertFalse(client.ready(black_hole), "an unroutable address reported ready")
        finally:
            client.close()

    def test_asking_repeatedly_makes_one_connection_not_a_backlog(self):
        """A link asks on every tick it is due, so `begin_connect` is called constantly. One peer
        means one connection paced by its own thread -- there is no queue to fill and no rate
        limiter to tune, which is what the shared dial worker needed to stay sane."""
        client = TCPDialer()
        black_hole = Address(Scheme.TCP, "192.0.2.1:9")
        before = threading.active_count()
        try:
            for _ in range(50):
                client.begin_connect(black_hole)
            self.assertEqual(len(client._peers), 1, "asking 50 times built more than one peer")
            self.assertLessEqual(
                threading.active_count() - before, 2, "a thread per ask, not per peer"
            )
        finally:
            client.close()

    def test_one_dead_peer_does_not_delay_another(self):
        """The reason a peer owns its own thread. Behind a shared dial worker an unroutable
        address blocked the queue for a whole connect bound, so a reachable peer waited behind
        every dead one -- during a partition recovery, which is when it matters most."""
        listener = TCPListener()
        client = TCPDialer()
        try:
            for i in range(4):  # four black holes, asked for FIRST
                client.begin_connect(Address(Scheme.TCP, f"192.0.2.{i + 1}:9"))
            client.begin_connect(listener.bound_address)
            deadline = time.monotonic() + 5.0
            while time.monotonic() < deadline and not client.ready(listener.bound_address):
                time.sleep(0.005)
            self.assertTrue(
                client.ready(listener.bound_address),
                "a reachable peer waited behind four unreachable ones",
            )
        finally:
            client.close()
            listener.stop()


class TestBackpressureIsBoundedNotDropped(unittest.TestCase):
    """`sendall` on the non-blocking socket raised BlockingIOError the moment the kernel buffer
    filled: session torn down, consensus frame dropped, indistinguishable from packet loss.

    Backpressure is now the writer thread's business -- it blocks, which is its job -- so the
    caller never waits and the frame still arrives whole."""

    def test_a_send_the_reader_catches_up_on_completes_intact(self):
        session, right, _broken = _backpressured_session()
        frame = _big_frame(4_000_000)  # far above any socketpair buffer: EAGAIN guaranteed
        expected = _LEN.pack(len(frame.raw)) + frame.raw
        received = bytearray()

        def _reader() -> None:
            time.sleep(0.05)  # let the writer hit the full buffer first
            while len(received) < len(expected):
                chunk = right.recv(65536)
                if not chunk:
                    return
                received.extend(chunk)

        t = threading.Thread(target=_reader)
        t.start()
        try:
            start = time.monotonic()
            session.send(frame)  # enqueue only: the wire is the writer thread's problem
            handed_off = time.monotonic() - start
            # The reader below sleeps 0.05s before draining, so an inline write cannot beat that.
            # A queue put is microseconds, so the two are three orders of magnitude apart.
            self.assertLess(handed_off, 0.02, f"send blocked {handed_off:.3f}s on the caller")
            t.join(timeout=10.0)
            self.assertEqual(bytes(received), expected, "the frame did not arrive intact")
        finally:
            session.close()
            right.close()

    def test_a_peer_that_never_reads_breaks_its_own_link_and_reports_it(self):
        """The writer waits out its bound and then fails -- and REPORTS, because a send that was
        only accepted for delivery leaves the scheduler holding an in-flight message that will
        never be answered. Without the report it waits out the whole message deadline instead of
        trying the next link."""
        timing = TCPTiming(send=300)
        session, right, broken = _backpressured_session(timing=timing)
        try:
            for _ in range(4):  # more than the socket buffer can absorb
                session.send(_big_frame(4_000_000))
            deadline = time.monotonic() + 10.0
            while time.monotonic() < deadline and not broken:
                time.sleep(0.01)
            self.assertEqual(
                [a.value for a in broken], ["pair:0"], "a dead link was never reported"
            )
            self.assertTrue(session.closed, "a broken session stayed open")
        finally:
            session.close()
            right.close()


if __name__ == "__main__":
    unittest.main()
