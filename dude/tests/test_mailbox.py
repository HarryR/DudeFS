# Tests for dude.net.address, dude.net.mailbox, and dude.net.plan.

from __future__ import annotations

import unittest
from dataclasses import replace

from ..core import crypto
from ..core.units import Millis
from ..net import (
    Address,
    AddressError,
    Envelope,
    Expiry,
    Mailbox,
    MessageId,
    Scheme,
    Verb,
    parse_all,
    request,
)
from ..net.link import Link, Peer
from ..net.plan import GiveUp, Send, Wait, backoff, decorrelated, plan_next
from ..tunables import DEFAULT

T0 = Millis(1_700_000_000_000)
TTL = Millis(10_000)

A1 = Address(Scheme.UNIX, "/run/dude/a.sock")
A2 = Address(Scheme.TCP, "10.0.0.2:9001")
A3 = Address(Scheme.INPROC, "node-c")


class TestAddress(unittest.TestCase):
    def test_roundtrip_and_first_colon_only(self):
        for a in (A1, A2, A3, Address(Scheme.UNIX, "/odd:path:with:colons")):
            self.assertEqual(Address.parse(a.encode()), a)
        self.assertEqual(Address.parse(b"tcp:[::1]:9001").value, "[::1]:9001")

    def test_malformed_is_refused(self):
        for raw in (b"nocolon", b"smoke:signals", b"", b"tcp"):
            with self.assertRaises(AddressError):
                Address.parse(raw)

    def test_undialable_schemes_are_skipped_not_fatal(self):
        got = parse_all((A1.encode(), b"smoke:signals", A2.encode()))
        self.assertEqual(set(got), {A1, A2})


def _noop_send(_frame):
    pass


def _noop_close():
    pass


def _link(address: Address) -> Link:
    return Link(
        address=address,
        identity=None,
        _send_frame=_noop_send,
        _close_transport=_noop_close,
    )


def _peer(*addresses: Address, t=None) -> Peer:
    p = Peer(crypto.Keypair.generate().public, t or DEFAULT)
    for a in addresses:
        p.links.append(_link(a))
    return p


class TestSelection(unittest.TestCase):
    def test_usable_excludes_broken_links(self):
        peer = _peer(A1, A2, A3)
        self.assertEqual(len(peer.usable(Millis(0))), 3)
        peer.links[0].breaker_open = True
        peer.links[0].breaker_opened_at = Millis(0)
        usable_addrs = [ln.address for ln in peer.usable(Millis(0))]
        self.assertNotIn(A1, usable_addrs)
        self.assertTrue(peer.deliverable(Millis(0)))

    def test_measurement_moves_a_link_in_the_sort(self):
        t = replace(DEFAULT, rtt_max=Millis(100))
        peer = _peer(A1, A2, t=t)
        peer.links[0].on_reply(Millis(0), Millis(400))  # A1 measured well above 100ms prior
        self.assertEqual(peer.usable(Millis(0))[0].address, A2)

    def test_no_paths_at_all_is_not_deliverable(self):
        peer = _peer()
        self.assertFalse(peer.deliverable(Millis(0)))
        self.assertEqual(peer.usable(Millis(0)), ())


class TestPlan(unittest.TestCase):
    def test_gives_up_on_the_deadline_and_on_attempts(self):
        t = replace(DEFAULT, max_attempts=3)
        peer = _peer(A1)
        self.assertIsInstance(plan_next(t, peer, 0, T0, T0), GiveUp)
        self.assertIsInstance(plan_next(t, peer, 3, T0, T0 + 1000), GiveUp)

    def test_no_usable_link_waits_rather_than_giving_up(self):
        d = plan_next(DEFAULT, _peer(), 0, T0, T0 + 10_000)
        assert isinstance(d, Wait)
        self.assertGreater(d.until, T0)

    def test_picks_best_link_by_rto(self):
        t = replace(DEFAULT, rtt_max=Millis(200))
        peer = _peer(A1, A2)
        peer.links[0].on_reply(Millis(0), Millis(300))  # A1 slow
        peer.links[1].on_reply(Millis(0), Millis(50))  # A2 fast
        d = plan_next(t, peer, 0, T0, T0 + 10_000)
        assert isinstance(d, Send)
        self.assertEqual(d.link.address, A2)

    def test_stagger_set_when_more_links_available(self):
        peer = _peer(A1, A2)
        d = plan_next(DEFAULT, peer, 0, T0, T0 + 10_000)
        assert isinstance(d, Send)
        self.assertIsNotNone(d.again_at)

    def test_no_stagger_with_single_link(self):
        d = plan_next(DEFAULT, _peer(A1), 0, T0, T0 + 10_000)
        assert isinstance(d, Send)
        self.assertIsNone(d.again_at)

    def test_backoff_grows_and_is_capped(self):
        t = replace(DEFAULT, rtt_max=Millis(100))
        delays = [backoff(t, n) for n in range(1, 6)]
        self.assertEqual(delays, sorted(delays))
        self.assertLessEqual(max(delays), t.backoff_cap)
        self.assertGreaterEqual(min(delays), t.backoff_base)

    def test_jitter_is_deterministic_by_default(self):
        t = replace(DEFAULT, rtt_max=Millis(100))
        self.assertEqual(backoff(t, 2), backoff(t, 2))
        spread = {decorrelated(100, 10_000) for _ in range(50)}
        self.assertGreater(len(spread), 40)


class TestMaybeReply(unittest.TestCase):
    def setUp(self):
        self.me = crypto.Keypair.generate()
        self.peer = crypto.Keypair.generate()
        self.box = Mailbox()

    def _post_request(self) -> tuple[Envelope, bytes]:
        signed = request(self.me, self.peer.public, Verb.PING, T0)
        prefix = self.box.post(signed.env, T0, TTL, await_reply=True)
        return signed.env, prefix

    def test_a_reply_retires_what_was_waiting_for_it(self):
        env, prefix = self._post_request()
        (t,) = self.box.due(T0)
        self.box.sent(t.prefix, t.attempt, A1, T0)
        self.assertEqual(len(self.box), 1)

        request(self.peer, self.me.public, Verb.PONG, T0 + 5, b"data")
        # Set reply_to to the original mid so the mailbox correlates
        reply_env = Envelope(
            self.me.public,
            Verb.PONG,
            MessageId.random(),
            b"data",
            reply_to=env.mid.with_attempt(t.attempt),
        )
        reply_signed = reply_env.sign(self.peer, T0 + 5)
        got = self.box.arrived(reply_signed, T0 + 5)
        assert got is not None
        self.assertEqual(got.prefix, prefix)
        self.assertEqual(len(self.box), 0)

    def test_it_died_before_replying_is_an_ordinary_expiry(self):
        self._post_request()
        (t,) = self.box.due(T0)
        self.box.sent(t.prefix, t.attempt, A1, T0)
        self.assertEqual(self.box.expired(T0 + TTL - 1), ())
        (e,) = self.box.expired(T0 + TTL)
        self.assertEqual((e.why, e.to), (Expiry.UNANSWERED, self.peer.public))

    def test_unanswered_and_undelivered_are_distinguished(self):
        env1, _ = self._post_request()
        (t,) = self.box.due(T0)
        self.box.sent(t.prefix, t.attempt, A1, T0)

        env2, _ = self._post_request()

        why = {e.prefix: e.why for e in self.box.expired(T0 + TTL)}
        sent_prefix = env1.mid.correlation_id
        unsent_prefix = env2.mid.correlation_id
        self.assertEqual(why[sent_prefix], Expiry.UNANSWERED)
        self.assertEqual(why[unsent_prefix], Expiry.UNDELIVERED)

    def test_an_unsolicited_message_is_not_a_reply(self):
        unsolicited = request(self.peer, self.me.public, Verb.PING, T0)
        self.assertIsNone(self.box.arrived(unsolicited, T0))

    def test_a_reply_to_something_we_stopped_waiting_for_is_not_matched(self):
        env, _prefix = self._post_request()
        (t,) = self.box.due(T0)
        self.box.sent(t.prefix, t.attempt, A1, T0)
        self.box.expired(T0 + TTL)

        late_reply = Envelope(
            self.me.public,
            Verb.PONG,
            MessageId.random(),
            b"data",
            reply_to=env.mid.with_attempt(t.attempt),
        ).sign(self.peer, T0 + TTL + 1)
        self.assertIsNone(self.box.arrived(late_reply, T0 + TTL + 1))

    def test_attempt_byte_attributes_the_link(self):
        env, _prefix = self._post_request()
        (t,) = self.box.due(T0)
        self.box.sent(t.prefix, t.attempt, A1, T0)

        reply = Envelope(
            self.me.public,
            Verb.PONG,
            MessageId.random(),
            b"",
            reply_to=env.mid.with_attempt(t.attempt),
        ).sign(self.peer, T0 + 40)
        got = self.box.arrived(reply, T0 + 40)
        assert got is not None
        self.assertEqual((got.address, got.rtt), (A1, 40))

    def test_second_attempt_on_different_link_attributed_correctly(self):
        env, _prefix = self._post_request()
        (t0,) = self.box.due(T0)
        self.box.sent(t0.prefix, t0.attempt, A1, T0)
        self.box.failed(t0.prefix, T0 + 100)

        (t1,) = self.box.due(T0 + 100)
        self.box.sent(t1.prefix, t1.attempt, A2, T0 + 500)

        reply = Envelope(
            self.me.public,
            Verb.PONG,
            MessageId.random(),
            b"",
            reply_to=env.mid.with_attempt(t1.attempt),
        ).sign(self.peer, T0 + 600)
        got = self.box.arrived(reply, T0 + 600)
        assert got is not None
        self.assertEqual((got.address, got.rtt), (A2, 100))

    def test_expect_awaits_a_reply_without_sending_anything(self):
        prefix = MessageId.random().correlation_id
        self.box.expect(prefix, self.peer.public, T0, TTL)
        self.assertEqual(self.box.due(T0), ())
        self.assertEqual(self.box.outstanding(), (prefix,))
        (e,) = self.box.expired(T0 + TTL)
        self.assertEqual(e.why, Expiry.UNDELIVERED)


class TestOnlyThePeerWeAskedMayAnswer(unittest.TestCase):
    def setUp(self):
        self.me = crypto.Keypair.generate()
        self.asked = crypto.Keypair.generate()
        self.other = crypto.Keypair.generate()
        self.box = Mailbox()

    def _question(self) -> Envelope:
        signed = request(self.me, self.asked.public, Verb.PING, T0)
        self.box.post(signed.env, T0, ttl=Millis(10_000), await_reply=True)
        return signed.env

    def test_the_peer_we_asked_is_answered(self):
        env = self._question()
        (t,) = self.box.due(T0)
        self.box.sent(t.prefix, t.attempt, A1, T0)
        reply = Envelope(
            self.me.public,
            Verb.PONG,
            MessageId.random(),
            b"",
            reply_to=env.mid.with_attempt(t.attempt),
        ).sign(self.asked, T0 + 5)
        self.assertIsNotNone(self.box.arrived(reply, T0 + 5))

    def test_a_third_party_echoing_the_id_is_not(self):
        env = self._question()
        (t,) = self.box.due(T0)
        self.box.sent(t.prefix, t.attempt, A1, T0)
        theirs = Envelope(
            self.me.public,
            Verb.PONG,
            MessageId.random(),
            b"",
            reply_to=env.mid.with_attempt(t.attempt),
        ).sign(self.other, T0 + 5)
        self.assertIsNone(self.box.arrived(theirs, T0 + 5))
        self.assertEqual(len(self.box), 1)


if __name__ == "__main__":
    unittest.main()
