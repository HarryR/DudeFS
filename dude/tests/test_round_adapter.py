# Tests for dude.net.round_adapter -- the wire binding for Round's abstract protocol.
#
# THE ADAPTER IS STATELESS. The three functions (encode, decode, bucket_of) are pure translations
# between Round's `Held`/`Sig` and the wire's `HELD`/`SIG` verbs; the `RoundAdapter` class adds a
# Postman + keypair so callers can flush a Round's outbox as envelopes. Bucket-to-Round dispatch
# is NOT this module's job -- that is the Coordinator's, in Phase 6.

from __future__ import annotations

import unittest

from ..consensus.round import Held, Round, Sig, _slice_body
from ..consensus.round_adapter import (
    RoundAdapter,
    RoundAdapterError,
    bucket_of,
    decode,
    encode,
)
from ..core import codec, crypto
from ..net import Verb
from ..net.address import Address, Endpoint, Scheme
from ..net.envelope import Envelope
from ..net.link import Peer
from ..net.postman import Postman

T0 = 1_700_000_000_000
DELTA = 1_000


class TestEncodeDecodeRoundtrip(unittest.TestCase):
    """encode/decode must be a total inverse for well-formed Round messages. Any deviation is a
    silent split -- one side of the wire builds one message, the other reads a different one."""

    def test_held_roundtrips(self):
        hashes = frozenset({crypto.h(b"a"), crypto.h(b"b"), crypto.h(b"c")})
        original = Held(bucket=7, hashes=hashes)
        verb, body = encode(original)
        self.assertIs(verb, Verb.HELD)
        got = decode(verb, body)
        self.assertEqual(got, original)

    def test_sig_roundtrips(self):
        kp = crypto.Keypair.generate()
        slice_hash = crypto.h(b"a-slice")
        body_bytes = _slice_body(3, slice_hash)
        original = Sig(bucket=3, slice_hash=slice_hash, sig=kp.sign(body_bytes))
        verb, body = encode(original)
        self.assertIs(verb, Verb.SIG)
        got = decode(verb, body)
        self.assertEqual(got, original)

    def test_empty_held_roundtrips(self):
        """An empty bucket produces a `Held` with an empty hash set. Must not become a decode
        failure."""
        original = Held(bucket=1, hashes=frozenset())
        verb, body = encode(original)
        got = decode(verb, body)
        self.assertEqual(got, original)


class TestBucketOf(unittest.TestCase):
    """The coordinator needs to route by bucket before doing full validation. `bucket_of` reads
    just the leading field."""

    def test_reads_the_bucket_from_a_held_body(self):
        _, body = encode(Held(bucket=42, hashes=frozenset({crypto.h(b"x")})))
        self.assertEqual(bucket_of(body), 42)

    def test_reads_the_bucket_from_a_sig_body(self):
        kp = crypto.Keypair.generate()
        h = crypto.h(b"s")
        _, body = encode(Sig(bucket=99, slice_hash=h, sig=kp.sign(_slice_body(99, h))))
        self.assertEqual(bucket_of(body), 99)

    def test_malformed_body_raises(self):
        with self.assertRaises(RoundAdapterError):
            bucket_of(b"not bencode")


class TestDecodeFailures(unittest.TestCase):
    """A wire message that names a Round verb but is not one -- garbage body, wrong shape --
    raises `RoundAdapterError` rather than silently producing a bogus message."""

    def test_malformed_held_body_raises(self):
        with self.assertRaises(RoundAdapterError):
            decode(Verb.HELD, b"garbage")

    def test_malformed_sig_body_raises(self):
        with self.assertRaises(RoundAdapterError):
            decode(Verb.SIG, b"garbage")

    def test_wrong_field_count_raises(self):
        # Held expects [bucket, [hashes]]; give it three fields.
        with self.assertRaises(RoundAdapterError):
            decode(Verb.HELD, codec.encode([1, [], b"extra"]))

    def test_non_round_verb_raises(self):
        with self.assertRaises(RoundAdapterError):
            decode(Verb.PING, b"")


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
            now=T0,
            close_by=T0 + 5 * DELTA,
        )
        r.add_local(frozenset({crypto.h(b"tx1")}))

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
        r = Round(bucket=1, me=self.me, roster=self.roster, now=T0, close_by=T0 + 5 * DELTA)
        r.add_local(frozenset({crypto.h(b"tx1")}))
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

        r = Round(bucket=1, me=me, roster=roster, now=T0, close_by=T0 + 5 * DELTA)
        r.add_local(frozenset({crypto.h(b"local")}))

        peer_hashes = frozenset({crypto.h(b"peer-a"), crypto.h(b"peer-b")})
        verb, body = encode(Held(bucket=1, hashes=peer_hashes))
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
