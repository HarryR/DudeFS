# Tests for Round's protocol messages + Postman binding.
#
# `Held`/`Sig` each own their own `encode()`/`_decode()`; dispatch is via `RoundMsg.decode(verb,
# body)` and `RoundMsg.bucket_of(body)`. The `RoundAdapter` class adds a Postman + keypair so
# callers can flush a Round's outbox as envelopes. Bucket-to-Round dispatch is NOT this
# module's job -- that is the Coordinator's.

from __future__ import annotations

import unittest

from ..consensus.round import Bodies, Held, Round, RoundAdapterError, RoundMsg, Sig
from ..consensus.round_adapter import RoundAdapter
from ..core import codec, crypto
from ..net import Verb
from ..net.address import Address, Endpoint, Scheme
from ..net.envelope import Envelope
from ..net.link import Peer
from ..net.postman import Postman
from .test_round import _stubs

T0 = 1_700_000_000_000
DELTA = 1_000


class TestEncodeDecodeRoundtrip(unittest.TestCase):
    """encode/decode must be a total inverse for well-formed Round messages. Any deviation is a
    silent split -- one side of the wire builds one message, the other reads a different one."""

    def test_held_roundtrips(self):
        hashes = frozenset({crypto.h(b"a"), crypto.h(b"b"), crypto.h(b"c")})
        original = Held(bucket=7, prev_block=crypto.h(b"prev"), hashes=hashes)
        verb, body = original.encode()
        self.assertIs(verb, Verb.HELD)
        self.assertEqual(RoundMsg.decode(verb, body), original)

    def test_sig_roundtrips(self):
        kp = crypto.Keypair.generate()
        original = Sig.sign(kp, 3, crypto.h(b"prev"), crypto.h(b"a-slice"))
        verb, body = original.encode()
        self.assertIs(verb, Verb.SIG)
        self.assertEqual(RoundMsg.decode(verb, body), original)

    def test_empty_held_roundtrips(self):
        """An empty bucket produces a `Held` with an empty hash set. Must not become a decode
        failure."""
        original = Held(bucket=1, prev_block=crypto.h(b"prev"), hashes=frozenset())
        verb, body = original.encode()
        self.assertEqual(RoundMsg.decode(verb, body), original)


class TestBucketOf(unittest.TestCase):
    """The coordinator needs to route by bucket before doing full validation.
    `RoundMsg.bucket_of` reads just the leading field."""

    def test_reads_the_bucket_from_a_held_body(self):
        _, body = Held(
            bucket=42, prev_block=crypto.h(b"prev"), hashes=frozenset({crypto.h(b"x")})
        ).encode()
        self.assertEqual(RoundMsg.bucket_of(body), 42)

    def test_reads_the_bucket_from_a_sig_body(self):
        kp = crypto.Keypair.generate()
        _, body = Sig.sign(kp, 99, crypto.h(b"prev"), crypto.h(b"s")).encode()
        self.assertEqual(RoundMsg.bucket_of(body), 99)

    def test_malformed_body_raises(self):
        with self.assertRaises(RoundAdapterError):
            RoundMsg.bucket_of(b"not bencode")


class TestDecodeFailures(unittest.TestCase):
    """A wire message that names a Round verb but is not one -- garbage body, wrong shape --
    raises `RoundAdapterError` rather than silently producing a bogus message."""

    def test_malformed_held_body_raises(self):
        with self.assertRaises(RoundAdapterError):
            RoundMsg.decode(Verb.HELD, b"garbage")

    def test_malformed_sig_body_raises(self):
        with self.assertRaises(RoundAdapterError):
            RoundMsg.decode(Verb.SIG, b"garbage")

    def test_wrong_field_count_raises(self):
        # Held emits [bucket, prev_block, [hashes]] -- three fields. Anything else is refused.
        for wrong in ([1, []], [1, b"p", [], b"extra"]):
            with self.assertRaises(RoundAdapterError):
                RoundMsg.decode(Verb.HELD, codec.encode(wrong))

    def test_bodies_roundtrips_and_pins_its_field_count(self):
        original = Bodies(bucket=5, prev_block=crypto.h(b"prev"), txs=_stubs("a", "b"))
        verb, body = original.encode()
        self.assertIs(verb, Verb.BODIES)
        self.assertEqual(RoundMsg.decode(verb, body), original)
        for wrong in ([5, b"p"], [5, b"p", [], b"extra"]):
            with self.assertRaises(RoundAdapterError):
                RoundMsg.decode(Verb.BODIES, codec.encode(wrong))

    def test_sig_wrong_field_count_raises(self):
        # Sig emits [bucket, prev_block, slice_hash, sig] -- and prev_block is inside what the
        # signature covers, so a half added to one side is a signature nobody can check.
        for wrong in ([1, b"p", b"s"], [1, b"p", b"s", b"sig", b"extra"]):
            with self.assertRaises(RoundAdapterError):
                RoundMsg.decode(Verb.SIG, codec.encode(wrong))

    def test_non_round_verb_raises(self):
        with self.assertRaises(RoundAdapterError):
            RoundMsg.decode(Verb.PING, b"")


class TestGossipGoesToTheRosterNotThePeerTable(unittest.TestCase):
    """`Recipient.ALL` on a Round message means the consensus peers, which are exactly the roster.
    It was resolved against `postman.peers`, which gains an entry for every identity that opens a
    session -- so every connected client was sent HELD and SIG."""

    def test_a_non_roster_peer_is_not_sent_held(self):
        keys = [crypto.Keypair.generate() for _ in range(3)]
        roster = tuple(sorted(k.public for k in keys))
        client = crypto.Keypair.generate()

        postman = Postman(keys[0])
        for k in keys[1:]:
            postman.add_peer(k.public, (Endpoint(Address(Scheme.INPROC, "peer")),))
        postman.add_peer(client.public, (Endpoint(Address(Scheme.INPROC, "client")),))
        self.assertIn(client.public, postman.peers)

        r = Round(
            bucket=1,
            me=keys[0],
            roster=roster,
            prev_block=crypto.h(b"prev"),
            now=T0,
            close_by=T0 + 1000,
            abandon_by=T0 + 2000,
        )
        r.add_local(())
        RoundAdapter(keys[0], postman, ttl=5_000).flush(r, T0)

        addressed = {postman.mailbox.pending[m].to for m in postman.mailbox.outstanding()}
        self.assertEqual(addressed, set(roster) - {keys[0].public})
        self.assertNotIn(client.public, addressed)


class TestRoundMsgIsAbstract(unittest.TestCase):
    """`RoundMsg` itself is abstract -- instantiating it fails. Concrete subclasses
    (`Held`, `Sig`) implement `encode` and are constructible."""

    def test_roundmsg_cannot_be_instantiated_directly(self):
        with self.assertRaises(TypeError):
            RoundMsg()


class TestFlushToMailbox(unittest.TestCase):
    """A Round's outbox drained through `flush` produces envelopes queued in the mailbox, one per
    peer (for `Recipient.ALL`). Signatures are the sender's; verbs are `HELD`/`SIG`; bodies match
    what `encode` produces for the message."""

    def setUp(self):
        # A quorum-worthy roster of three, plus a Postman with the other two as peers.
        self.keys = [crypto.Keypair.generate() for _ in range(3)]
        self.roster = tuple(k.public for k in self.keys)
        self.me = self.keys[0]

        # Postman + a peer table. We do not need a real Transport here -- `flush` posts to the
        # mailbox and stops there; delivery is another test's concern.
        self.postman = Postman(self.me)
        for k in self.keys[1:]:
            addr = Address(scheme=Scheme.INPROC, value=k.public.hex())
            # Transport factory that never gets called (we do not post beyond the mailbox here).
            peer = Peer(k.public, lambda _addr: _NoTransport())
            peer.reconfigure((Endpoint(addr),))
            self.postman.peers[k.public] = peer

    def test_a_broadcast_becomes_one_envelope_per_peer(self):
        r = Round(
            bucket=1,
            me=self.me,
            roster=self.roster,
            prev_block=crypto.h(b"prev"),
            now=T0,
            close_by=T0 + 5 * DELTA,
            abandon_by=T0 + 1_000 * DELTA,
        )
        r.add_local(_stubs("tx1"))

        adapter = RoundAdapter(self.me, self.postman, ttl=10_000)
        adapter.flush(r, now=T0)

        pending = list(self.postman.mailbox.pending.values())
        self.assertEqual(len(pending), 2, "one envelope per peer (excluding self)")
        for p in pending:
            env = p.envelope
            assert env is not None, "flush queued an await-only entry"
            self.assertIs(env.env.verb, Verb.HELD)  # first outbox item is the Held
            self.assertEqual(env.frm, self.me.public)
            # The recipient is one of our peers.
            self.assertIn(env.env.to, {k.public for k in self.keys[1:]})

    def test_second_flush_is_empty_if_nothing_new(self):
        """A Round's outbox drains on read. A flush after that -- with no intervening tick or
        receive -- posts nothing."""
        r = Round(
            bucket=1,
            me=self.me,
            roster=self.roster,
            prev_block=crypto.h(b"prev"),
            now=T0,
            close_by=T0 + 5 * DELTA,
            abandon_by=T0 + 1_000 * DELTA,
        )
        r.add_local(_stubs("tx1"))
        adapter = RoundAdapter(self.me, self.postman, ttl=10_000)

        adapter.flush(r, now=T0)
        before = len(self.postman.mailbox.pending)
        adapter.flush(r, now=T0)
        after = len(self.postman.mailbox.pending)
        self.assertEqual(before, after, "flushing an empty outbox posted something")


class TestDeliverToRound(unittest.TestCase):
    """Inbound envelope + a Round instance -> Round.receive gets the decoded message."""

    def test_a_held_envelope_updates_the_round(self):
        keys = [crypto.Keypair.generate() for _ in range(3)]
        roster = tuple(k.public for k in keys)
        me, peer = keys[0], keys[1]

        r = Round(
            bucket=1,
            me=me,
            roster=roster,
            prev_block=crypto.h(b"prev"),
            now=T0,
            close_by=T0 + 5 * DELTA,
            abandon_by=T0 + 1_000 * DELTA,
        )
        r.add_local(_stubs("local"))

        peer_hashes = frozenset({crypto.h(b"peer-a"), crypto.h(b"peer-b")})
        verb, body = Held(bucket=1, prev_block=crypto.h(b"prev"), hashes=peer_hashes).encode()
        env = Envelope(me.public, verb, b"m" * 16, body).sign(peer, T0)

        # Adapter needs a Postman to construct, but `deliver` does not use it.
        adapter = RoundAdapter(me, Postman(me), ttl=10_000)
        adapter.deliver(env, r, now=T0)

        # Round has stored the peer's holdings.
        self.assertEqual(r._peer_holds.get(peer.public), peer_hashes)


class _NoTransport:
    """Test double: a Transport that raises if the mailbox actually tries to send. `flush` only
    posts to the mailbox -- delivery is downstream, and we do not exercise it here."""

    def send(self, address, frame):  # noqa: ARG002 -- protocol arity, unused in this stub
        raise AssertionError("test should not reach transport-level send")


if __name__ == "__main__":
    unittest.main()
