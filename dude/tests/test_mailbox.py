# Tests for dude.net.address and dude.net.mailbox.
#
# NOT ONE SOCKET IS OPENED HERE. That is the entire justification for the mailbox/transport split:
# link failure, partition, backoff, multi-homed failover and "it died before replying" are all
# VALUES a test constructs, not an environment it has to arrange. Anything below needing a real
# transport to exercise would be a design failure of this layer.

from __future__ import annotations

import unittest

from ..core import crypto
from ..net import (
    Address,
    AddressError,
    Attempt,
    Envelope,
    Expiry,
    Mailbox,
    Scheme,
    SignedEnvelope,
    Verb,
    new_message_id,
    parse_all,
    request,
)
from ..net.address import Endpoint
from ..net.link import LinkError, LinkTunables, Peer
from ..net.plan import GiveUp, Plan, PlanTunables, Send, Wait, decorrelated

T0 = 1_700_000_000_000
TTL = 10_000

A1 = Address(Scheme.UNIX, "/run/dude/a.sock")
A2 = Address(Scheme.TCP, "10.0.0.2:9001")
A3 = Address(Scheme.INPROC, "node-c")


class TestAddress(unittest.TestCase):
    def test_roundtrip_and_first_colon_only(self):
        """Split on the FIRST colon: a tcp address contains one and a unix path may contain several,
        so anything else mangles valid locators."""
        for a in (A1, A2, A3, Address(Scheme.UNIX, "/odd:path:with:colons")):
            self.assertEqual(Address.parse(a.encode()), a)
        self.assertEqual(Address.parse(b"tcp:[::1]:9001").value, "[::1]:9001")

    def test_malformed_is_refused(self):
        for raw in (b"nocolon", b"smoke:signals", b"", b"tcp"):
            with self.assertRaises(AddressError):
                Address.parse(raw)

    def test_undialable_schemes_are_skipped_not_fatal(self):
        """A roster is shared by nodes with different transports compiled in, so "I cannot dial
        that" is a local capability fact rather than a malformed record. Refusing the whole record
        would let one peer advertising an exotic carrier make itself unreachable to everybody, and
        the failure would look like a roster problem instead of a build difference."""
        got = parse_all((A1.encode(), b"smoke:signals", A2.encode()))
        self.assertEqual(set(got), {A1, A2})

    def test_dial_order_is_cheapest_first_and_stable(self):
        """Stable across implementations (Go randomises map iteration) AND meaningful: a peer
        reachable both in-process and over TCP must not be dialled over TCP. Sorting by scheme name
        would have been stable and wrong, since b"tcp" sorts before b"unix"."""
        self.assertEqual(parse_all((A2.encode(), A1.encode(), A3.encode())), (A3, A1, A2))
        self.assertEqual([a.scheme for a in (A3, A1, A2)], [Scheme.INPROC, Scheme.UNIX, Scheme.TCP])


class Dead:
    """Always refuses, so a link failure is a value rather than an environment to arrange."""

    def send(self, _address, _frame):
        raise LinkError("blackhole")


class Live:
    def send(self, _address, _frame):
        pass


def peer_with(*addresses, transports=None, t=None):
    """A peer over bare addresses. `Endpoint(a)` with no options is the common case; wrapping it
    here keeps every test from repeating it."""
    tr = transports or {}
    p = Peer(
        crypto.Keypair.generate().public,
        lambda e: tr.get(e.address, Live()),
        t or LinkTunables(),
    )
    p.reconfigure(tuple(Endpoint(a) for a in addresses))
    return p


class TestSelection(unittest.TestCase):
    """Selection is a FACT about paths, so it lives on `Peer`. These tests used to be written
    against `Mailbox` — which is what a state-holding object looks like once it absorbs policy."""

    def test_usable_is_ordered_and_excludes_refusing_links(self):
        """A refusing link is dropped, not attempted and failed — what the breaker is for."""
        t = LinkTunables(breaker_threshold=1)
        peer = peer_with(A1, A2, A3, t=t)
        self.assertEqual(len(peer.usable(0)), 3)
        peer.links[A1].expired(0)  # one failure at threshold 1 opens it
        self.assertNotIn(A1, [ln.address for ln in peer.usable(0)])
        self.assertTrue(peer.deliverable(0))

    def test_measurement_overrides_the_cost_prior(self):
        """Unmeasured links start in cost order; a measured RTO beats it as soon as one exists."""
        peer = peer_with(A1, A2)
        self.assertEqual([ln.address for ln in peer.usable(0)], [A1, A2])  # unix before tcp
        peer.links[A2].reply(0, 5)  # tcp turns out to be fast
        self.assertEqual(next(ln.address for ln in peer.usable(0)), A2)

    def test_no_paths_at_all_is_not_deliverable(self):
        peer = peer_with()
        self.assertFalse(peer.deliverable(0))
        self.assertEqual(peer.usable(0), ())


class TestPlan(unittest.TestCase):
    """Policy, pure: no mailbox, no clock, no sockets. A retry change touches this file only."""

    def test_gives_up_on_the_deadline_and_on_attempts(self):
        plan = Plan(PlanTunables(max_attempts=3))
        peer = peer_with(A1)
        self.assertIsInstance(plan.next(peer, 0, T0, T0), GiveUp)  # now == deadline
        self.assertIsInstance(plan.next(peer, 3, T0, T0 + 1000), GiveUp)

    def test_no_usable_link_waits_rather_than_giving_up(self):
        """A breaker's cooldown expires and a roster update may add a link, so unreachable now is
        not unreachable for ever."""
        plan = Plan()
        d = plan.next(peer_with(), 0, T0, T0 + 10_000)
        assert isinstance(d, Wait)
        self.assertGreater(d.until, T0)

    def test_first_attempt_is_free_and_the_budget_bounds_parallelism(self):
        """R6 and R7 interlocking: a healthy peer staggers freely, and an exhausted budget collapses
        it back to serial failover with nothing else deciding that."""
        peer = peer_with(A1, A2, A3)
        plan = Plan(PlanTunables(max_parallel=2))
        d = plan.next(peer, 0, T0, T0 + 10_000)
        assert isinstance(d, Send)
        self.assertEqual(len(d.links), 2)
        self.assertIsNotNone(d.again_at)  # a third link remains, so keep the message schedulable

        while peer.budget.spend():
            pass
        d = plan.next(peer, 0, T0, T0 + 10_000)
        assert isinstance(d, Send)
        self.assertEqual(len(d.links), 1)  # budget spent: serial, but never zero

    def test_stagger_is_derived_from_the_link_not_a_constant(self):
        """RFC 8305's flat 250 ms exists because a browser has no history. We have per-link history,
        so the constant is a CAP."""
        peer = peer_with(A1, A2, A3)  # three, so one remains and `again_at` is populated
        peer.links[A1].reply(0, 20)  # a fast unix socket
        d = Plan(PlanTunables(stagger_cap=250)).next(peer, 0, T0, T0 + 10_000)
        assert isinstance(d, Send)
        assert d.again_at is not None
        self.assertLess(d.again_at - T0, 250)

    def test_backoff_grows_and_is_capped(self):
        plan = Plan(PlanTunables(backoff_base=100, backoff_cap=1_000))
        delays = [plan.backoff(n) for n in range(1, 6)]
        self.assertEqual(delays, sorted(delays))
        self.assertLessEqual(max(delays), 1_000)
        self.assertGreaterEqual(min(delays), 100)

    def test_jitter_is_injected_so_nothing_above_becomes_flaky(self):
        """The default is the midpoint, not a random draw: a module that silently randomised would
        make every test above it flaky, so unpredictability has to be asked for."""
        plan = Plan(PlanTunables(backoff_base=100, backoff_cap=10_000))
        self.assertEqual(plan.backoff(2), plan.backoff(2))
        spread = {decorrelated(100, 10_000) for _ in range(50)}
        self.assertGreater(len(spread), 40)


class TestMaybeReply(unittest.TestCase):
    """The decision this layer exists to make honestly: a sender cannot distinguish "it died", "it
    declined" and "the reply was lost", so all three end in one outcome instead of a type pretending
    to tell them apart."""

    def setUp(self):
        self.me = crypto.Keypair.generate()
        self.peer = crypto.Keypair.generate()
        self.box = Mailbox()

    def test_a_reply_retires_what_was_waiting_for_it(self):
        env = request(self.me, self.peer.public, Verb.FETCH, T0)
        self.box.post(env, T0, TTL, await_reply=True)
        (t,) = self.box.due(T0)
        self.box.sent(t.mid, A1, t.envelope.ts, T0)
        self.assertEqual(len(self.box), 1)  # sent, still waiting

        reply = env.answer(Verb.BODIES, b"data").sign(self.peer, T0 + 5)
        got = self.box.arrived(reply, T0 + 5)
        assert got is not None
        self.assertEqual(got.mid, env.env.mid)
        self.assertEqual(len(self.box), 0)

    def test_it_died_before_replying_is_an_ordinary_expiry(self):
        """The case that made "maybe reply" look hard. It is one event, and it costs no extra code
        because it shares its clock with the send deadline."""
        env = request(self.me, self.peer.public, Verb.FETCH, T0)
        self.box.post(env, T0, TTL, await_reply=True)
        (t,) = self.box.due(T0)
        self.box.sent(t.mid, A1, t.envelope.ts, T0)  # bytes left; receipt not implied
        self.assertEqual(self.box.expired(T0 + TTL - 1), ())
        (e,) = self.box.expired(T0 + TTL)
        self.assertEqual((e.why, e.to), (Expiry.UNANSWERED, self.peer.public))

    def test_unanswered_and_undelivered_are_distinguished(self):
        """Both are "timeout", and conflating them in a log loses the difference between a peer that
        cannot be reached and a peer that will not answer."""
        reachable = request(self.me, self.peer.public, Verb.FETCH, T0)
        self.box.post(reachable, T0, TTL, await_reply=True)
        (t,) = self.box.due(T0)
        self.box.sent(t.mid, A1, t.envelope.ts, T0)

        unreachable = request(self.me, self.peer.public, Verb.PING, T0)
        self.box.post(unreachable, T0, TTL, await_reply=True)

        why = {e.mid: e.why for e in self.box.expired(T0 + TTL)}
        self.assertEqual(why[reachable.env.mid], Expiry.UNANSWERED)
        self.assertEqual(why[unreachable.env.mid], Expiry.UNDELIVERED)

    def test_an_unsolicited_message_is_not_a_reply(self):
        """`arrived` correlates and nothing more. A message that answers nothing we are waiting for
        is handled as unsolicited rather than silently dropped or silently matched."""
        self.assertIsNone(
            self.box.arrived(request(self.peer, self.me.public, Verb.ANNOUNCE, T0), T0)
        )

    def test_a_reply_to_something_we_stopped_waiting_for_is_not_matched(self):
        """A late reply arriving after the deadline must not resurrect a retired entry."""
        env = request(self.me, self.peer.public, Verb.FETCH, T0)
        self.box.post(env, T0, TTL, await_reply=True)
        (t,) = self.box.due(T0)
        self.box.sent(t.mid, A1, t.envelope.ts, T0)
        self.box.expired(T0 + TTL)

        late = env.answer(Verb.BODIES, b"data").sign(self.peer, T0 + TTL + 1)
        self.assertIsNone(self.box.arrived(late, T0 + TTL + 1))

    def test_a_single_attempt_is_attributable_with_no_echo(self):
        """Karn is satisfied by construction when only one transmission is outstanding, so the
        common path yields samples even from a peer that never sets `reply_ts`."""
        env = request(self.me, self.peer.public, Verb.FETCH, T0)
        self.box.post(env, T0, TTL, await_reply=True)
        (t,) = self.box.due(T0)
        self.box.sent(t.mid, A1, t.envelope.ts, T0)
        reply = env.answer(Verb.BODIES).sign(self.peer, T0 + 40)
        got = self.box.arrived(reply, T0 + 40)
        assert got is not None  # narrowing: `arrived` returns None for the unsolicited
        self.assertEqual((got.address, got.rtt), (A1, 40))

    def test_reply_ts_recovers_a_sample_that_karn_would_discard(self):
        """The point of the field. Two attempts on two links: without an echo the reply is
        unattributable, and with one it names the transmission AND therefore the link."""
        env = request(self.me, self.peer.public, Verb.FETCH, T0)
        self.box.post(env, T0, TTL, await_reply=True)
        (first,) = self.box.due(T0)
        self.box.sent(first.mid, A1, T0, T0)
        self.box.failed(first.mid, T0 + 100)
        (second,) = self.box.due(T0 + 100)
        self.box.sent(second.mid, A2, T0 + 500, T0 + 500)  # the SECOND link

        reply = env.answer(Verb.BODIES).sign(self.peer, T0 + 600)
        echoed = SignedEnvelope(
            reply.frm,
            reply.ts,
            Envelope(
                reply.env.to,
                reply.env.verb,
                reply.env.mid,
                reply.env.body,
                reply.env.reply_to,
                T0 + 500,  # the echo names the SECOND attempt
            ),
            reply.sig,
        )
        got = self.box.arrived(echoed, T0 + 600)
        assert got is not None  # narrowing: `arrived` returns None for the unsolicited
        self.assertEqual((got.address, got.rtt), (A2, 100))

    def test_two_attempts_sharing_a_stamp_are_unattributable(self):
        """R2, and the branch that refuses rather than guesses. `reply_ts` disambiguates only when
        it names exactly ONE attempt; two transmissions inside the same millisecond are as ambiguous
        as no echo at all. Both fields come back None together, because a wrong sample charges one
        link for another's latency and R3's estimator has no way to notice."""
        env = request(self.me, self.peer.public, Verb.FETCH, T0)
        self.box.post(env, T0, TTL, await_reply=True)
        for offset in (0, 100):
            (t,) = self.box.due(T0 + offset)
            self.box.sent(t.mid, A1, T0 + offset, T0 + offset)
            self.box.failed(t.mid, T0 + offset)
        self.box.post(env, T0, TTL, await_reply=True)  # re-register to receive the reply
        self.box.pending[env.env.mid].attempts = (
            Attempt(A1, T0, T0),
            Attempt(A2, T0 + 100, T0),  # SAME stamp, different link
        )
        got = self.box.arrived(env.answer(Verb.BODIES).sign(self.peer, T0 + 9), T0 + 9)
        assert got is not None  # narrowing: `arrived` returns None for the unsolicited
        self.assertEqual((got.address, got.rtt), (None, None))
        self.assertIsNotNone(got.mid)  # still a reply: liveness counts even when measurement cannot

    def test_expect_awaits_a_reply_without_sending_anything(self):
        """For a message despatched by other means: a deadline with no transmits, so "I am waiting
        for this" lives in one place instead of being a timer in every caller."""
        mid = new_message_id()
        self.box.expect(mid, self.peer.public, T0, TTL)
        self.assertEqual(self.box.due(T0), ())
        self.assertEqual(self.box.outstanding(), (mid,))
        (e,) = self.box.expired(T0 + TTL)
        self.assertEqual(e.why, Expiry.UNDELIVERED)  # never attempted, so not "unanswered"


class TestOnlyThePeerWeAskedMayAnswer(unittest.TestCase):
    """LINKS.md's rule, which the code did not follow: *"the dedup key is `(frm, mid)`, never `mid`
    alone... `mid` is chosen by the sender."*

    Correlation popped on the id alone, so any identity that learned an outstanding id had its
    answer taken as solicited. Frames are sealed so an id is not observable — but the peer we asked
    knows it, and `SOLICITED` is all that stands between a `HASHES` reply and a stranger."""

    def setUp(self):
        self.me = crypto.Keypair.generate()
        self.asked = crypto.Keypair.generate()
        self.other = crypto.Keypair.generate()
        self.box = Mailbox()

    def _question(self):
        env = request(self.me, self.asked.public, Verb.PULL, T0)
        self.box.post(env, T0, ttl=10_000)
        return env

    def test_the_peer_we_asked_is_answered(self):
        env = self._question()
        reply = env.answer(Verb.ENTRIES).sign(self.asked, T0 + 5)

        self.assertIsNotNone(self.box.arrived(reply, T0 + 5), "the peer we asked was not credited")

    def test_a_third_party_echoing_the_id_is_not(self):
        """The stranger's envelope is perfectly valid — signed, addressed to us, in window, echoing
        a live id. Only the destination we recorded says it is not an answer to our question."""
        env = self._question()
        theirs = env.answer(Verb.ENTRIES).sign(self.other, T0 + 5)

        self.assertIsNone(
            self.box.arrived(theirs, T0 + 5), "a stranger's answer was taken as solicited"
        )
        self.assertEqual(len(self.box), 1, "and it retired the question we were still asking")


if __name__ == "__main__":
    unittest.main()
