# Tests for dude.net.envelope — the three layers, and what each one refuses.
#
# The theme: every test here corresponds to something an attacker could do for free if a field were
# left out of the signature, or to a defect the previous package actually shipped.

from __future__ import annotations

import unittest

from ..core import codec, crypto
from ..net import Envelope, EnvelopeError, Frame, SignedEnvelope, Verb, request
from ..net.postman import Postman
from ..store import ops

T0 = 1_700_000_000_000
WINDOW = 5_000


class TestLayering(unittest.TestCase):
    """The inner artifact is distributable; the envelope is not. That separation IS the design."""

    def setUp(self):
        self.client = crypto.Keypair.generate()
        self.node_a = crypto.Keypair.generate()
        self.node_b = crypto.Keypair.generate()

    def test_two_signatures_answer_two_questions(self):
        """A client signs the transaction, then signs the envelope that submits it. The gate
        authorises the envelope's `frm` (the requester); the log authorises the inner author."""
        tx = ops.writes(ops.Set(ops.STORE_DATA, crypto.h(b"k"), b"v")).sign(self.client, T0)
        env = request(self.client, self.node_a.public, Verb.SUBMIT, T0, tx.raw)
        self.assertTrue(env.verify())  # the hop
        self.assertTrue(ops.SignedTransaction.decode(env.env.body).verify())  # the content
        self.assertEqual(env.frm, self.client.public)

    def test_the_inner_survives_re_enveloping_but_the_outer_does_not(self):
        """Forwarding means RE-ENVELOPING. Node A relays a client's transaction to node B under its
        OWN envelope; the transaction's author signature is untouched and still verifies, while the
        client's envelope is not reusable for a different hop."""
        tx = ops.writes(ops.Set(ops.STORE_DATA, crypto.h(b"k"), b"v")).sign(self.client, T0)
        to_a = request(self.client, self.node_a.public, Verb.SUBMIT, T0, tx.raw)

        relayed = request(self.node_a, self.node_b.public, Verb.SUBMIT, T0, to_a.env.body)
        relayed.accept(self.node_b.public, T0, WINDOW)  # B accepts A as the requester
        inner = ops.SignedTransaction.decode(relayed.env.body)
        self.assertTrue(inner.verify())
        self.assertEqual(inner.author, self.client.public)  # authorship unchanged by the relay
        self.assertNotEqual(relayed.frm, inner.author)  # requester != author

    def test_the_envelope_does_not_parse_its_body(self):
        """`body` is opaque here — the framing layer works with no idea what it carries, which is
        what keeps carrier vocabulary out of the log."""
        env = request(self.node_a, self.node_b.public, Verb.PING, T0, b"\xff\x00not-bencode")
        env.accept(self.node_b.public, T0, WINDOW)
        self.assertEqual(env.env.body, b"\xff\x00not-bencode")


class TestSignedFields(unittest.TestCase):
    """Each test = a field that, if unsigned, an attacker rewrites for free."""

    def setUp(self):
        self.a = crypto.Keypair.generate()
        self.b = crypto.Keypair.generate()
        self.c = crypto.Keypair.generate()
        self.env = request(self.a, self.b.public, Verb.PING, T0)

    def test_recipient_is_signed_so_a_frame_cannot_be_redirected(self):
        """Without `to` under the signature, a valid envelope could be lifted and re-delivered to
        someone else, who would see a correctly-signed message never addressed to them."""
        redirected = SignedEnvelope(
            self.env.frm,
            self.env.ts,
            Envelope(self.c.public, Verb.PING, self.env.env.mid),
            self.env.sig,
        )
        self.assertFalse(redirected.verify())
        with self.assertRaises(EnvelopeError):
            redirected.accept(self.c.public, T0, WINDOW)

    def test_verb_is_signed_so_a_request_cannot_be_repurposed(self):
        swapped = SignedEnvelope(
            self.env.frm,
            self.env.ts,
            Envelope(self.env.env.to, Verb.SUBMIT, self.env.env.mid),
            self.env.sig,
        )
        self.assertFalse(swapped.verify())

    def test_wrong_recipient_is_refused_before_the_signature_is_checked(self):
        """Addressing and freshness precede verification: a misdelivered frame costs no crypto."""
        with self.assertRaises(EnvelopeError) as cm:
            self.env.accept(self.c.public, T0, WINDOW)
        self.assertIn("not us", str(cm.exception))

    def test_attribution_to_a_non_signer_is_unconstructible(self):
        """This replaces a test that asserted `sign()` RAISED when the envelope named someone else.

        There is no longer anything to raise about: an unsigned envelope has no author, so the
        state the check guarded cannot be built. `frm` and `ts` arrive with the signature, exactly
        as `SignedTransaction` carries them for the store."""
        self.assertNotIn("frm", Envelope.__slots__)
        self.assertNotIn("ts", Envelope.__slots__)
        signed = Envelope(self.b.public, Verb.PING, b"x" * 16).sign(self.a, T0)
        self.assertEqual(signed.frm, self.a.public)  # the signer, and only ever the signer

    def test_roundtrip(self):
        self.assertEqual(SignedEnvelope.decode(self.env.raw), self.env)

    def test_an_unknown_verb_is_refused_at_decode(self):
        """Built at the CODEC level, not by constructing a mistyped `Envelope` — a hostile peer
        sends bytes, and the type system would not let it build the object anyway. This is where the
        closed enumeration earns its keep: an unrecognised verb is a hard refusal rather than
        something that falls through to a default branch."""
        inner = codec.encode([self.b.public, 999, b"x" * 16, b"", b"", 0])
        body = codec.encode([self.a.public, T0, inner])
        with self.assertRaises(EnvelopeError) as cm:
            SignedEnvelope.decode(codec.encode([body, self.a.sign(body)]))
        self.assertIn("999", str(cm.exception))


class TestCorrelation(unittest.TestCase):
    """The message id exists for a BUG: with no request-response binding there is no relationship
    between an answer and the question it claims to answer — message-order malleability."""

    def setUp(self):
        self.a = crypto.Keypair.generate()
        self.b = crypto.Keypair.generate()

    def test_a_reply_must_echo_the_id_it_answers(self):
        q1 = request(self.a, self.b.public, Verb.PING, T0)
        q2 = request(self.a, self.b.public, Verb.PING, T0)
        self.assertNotEqual(q1.env.mid, q2.env.mid)

        answer_to_q1 = q1.answer(Verb.BODIES, b"payload").sign(self.b, T0)
        answer_to_q1.accept(self.a.public, T0, WINDOW, in_reply_to=q1.env.mid)
        with self.assertRaises(EnvelopeError) as cm:  # cannot be passed off as q2's answer
            answer_to_q1.accept(self.a.public, T0, WINDOW, in_reply_to=q2.env.mid)
        self.assertIn("echo", str(cm.exception))

    def test_answer_reverses_the_addressing(self):
        q = request(self.a, self.b.public, Verb.PING, T0)
        r = q.answer(Verb.PONG)
        self.assertEqual(r.to, self.a.public)  # addressed back to the requester
        self.assertEqual(r.reply_to, q.env.mid)
        self.assertEqual(r.reply_ts, q.ts)  # echoes the attempt it answers

    def test_a_request_carries_no_reply_to(self):
        self.assertEqual(request(self.a, self.b.public, Verb.PING, T0).env.reply_to, b"")


class TestTheDoorClosesOnDefect(unittest.TestCase):
    """The gated timestamp is a PARTICIPATION gate, not a DoS filter: a node whose clock is outside
    the window cannot hold a conversation, and since both ends check, it self-partitions."""

    def setUp(self):
        self.good = crypto.Keypair.generate()
        self.skewed = crypto.Keypair.generate()

    def test_a_skewed_sender_cannot_be_heard(self):
        far = request(self.skewed, self.good.public, Verb.PING, T0 - 60_000)
        self.assertTrue(far.verify())  # perfectly well-formed and correctly signed...
        with self.assertRaises(EnvelopeError) as cm:
            far.accept(self.good.public, T0, WINDOW)  # ...and still refused
        self.assertIn("window", str(cm.exception))

    def test_the_gate_is_symmetric(self):
        """Both directions fail, so the skewed node is not partially present — it is partitioned."""
        skew = 60_000
        inbound = request(self.skewed, self.good.public, Verb.PING, T0 - skew)
        outbound = request(self.good, self.skewed.public, Verb.PING, T0)
        self.assertFalse(inbound.fresh(T0, WINDOW))  # correct node refuses the skewed node
        self.assertFalse(outbound.fresh(T0 - skew, WINDOW))  # and vice versa

    def test_within_the_window_both_directions_work(self):
        for offset in (-WINDOW, 0, WINDOW):
            env = request(self.skewed, self.good.public, Verb.PING, T0 + offset)
            env.accept(self.good.public, T0, WINDOW)

    def test_a_retransmit_is_a_new_message(self):
        """Restamping is why the conversation window need not stretch to cover retry behaviour."""
        env = request(self.good, self.skewed.public, Verb.PING, T0)
        again = env.env.sign(self.good, T0 + 60_000)  # same envelope, signed again later
        self.assertEqual(again.env.mid, env.env.mid)  # same logical request...
        self.assertTrue(again.fresh(T0 + 60_000, WINDOW))  # ...fresh again
        self.assertFalse(env.fresh(T0 + 60_000, WINDOW))  # the old frame is not


class TestSealing(unittest.TestCase):
    def setUp(self):
        self.a = crypto.Keypair.generate()
        self.b = crypto.Keypair.generate()
        self.eve = crypto.Keypair.generate()
        self.env = request(self.a, self.b.public, Verb.PROPOSE, T0, b"slice")
        self.frame = self.env.seal()

    def test_roundtrip(self):
        self.assertEqual(self.frame.unseal(self.b), self.env)
        self.assertEqual(Frame.decode(self.frame.raw), self.frame)

    def test_sign_then_seal_hides_the_sender(self):
        """Sealing after signing means an observer sees no identity. Signing a ciphertext instead
        would leave the sender's key in the clear and leak the social graph."""
        wire = self.frame.raw
        self.assertNotIn(bytes(self.a.public), wire)
        self.assertNotIn(bytes(self.b.public), wire)
        self.assertNotIn(b"slice", wire)

    def test_a_stranger_cannot_open_it(self):
        with self.assertRaises(EnvelopeError):
            self.frame.unseal(self.eve)

    def test_the_screen_tag_covers_the_sealed_bytes(self):
        """The reason the tag is not keyed on identity alone: it would then be a constant, i.e. a
        permanent per-node fingerprint linking every frame ever sent to that node. Two frames to the
        same recipient must carry different tags."""
        other = request(self.a, self.b.public, Verb.PROPOSE, T0, b"different").seal()
        self.assertNotEqual(self.frame.tag, other.tag)
        self.assertTrue(self.frame.addressed_to(self.b.public))
        self.assertTrue(other.addressed_to(self.b.public))
        self.assertFalse(self.frame.addressed_to(self.eve.public))

    def test_a_frame_tagged_for_someone_else_is_declined_at_the_door(self):
        """The other half of the tag's job, and it was performed by no layer at all.

        `crypto.screen_tag` says the receiver keys on its OWN identity and compares, and that this
        is what makes garbage cost ONE HASH rather than an ECDH against an ephemeral key. Nothing
        compared: the transports never touch the tag and `Postman.deliver` went straight to
        `unseal`. So the check was not "pushed into the transport" -- it was nowhere, and only the
        sealed box declining to open kept a misaddressed frame out.

        The box here WOULD open, which is what makes this test about ordering rather than about
        secrecy: the sealed blob is genuinely ours and only the tag says otherwise. Under the old
        code it was accepted."""
        openable = Frame(crypto.screen_tag(self.eve.public, self.frame.sealed), self.frame.sealed)
        self.assertEqual(openable.unseal(self.b), self.env, "the box really is ours")

        post = Postman(self.b)
        with self.assertRaises(EnvelopeError) as cm:
            post.deliver(openable, T0)
        self.assertIn("not addressed to us", str(cm.exception))

        self.assertEqual(post.deliver(self.frame, T0).envelope, self.env, "the honest frame lands")

    def test_the_tag_is_a_hint_and_authorises_nothing(self):
        """A tampered frame keeps a matching tag if the tag is recomputed over it, so `addressed_to`
        must never be treated as authentication — everything real happens after unsealing."""
        tampered = Frame(
            crypto.screen_tag(self.b.public, crypto.SealedBlob(self.frame.sealed + b"x")),
            crypto.SealedBlob(self.frame.sealed + b"x"),
        )
        self.assertTrue(tampered.addressed_to(self.b.public))  # the hint says yes...
        with self.assertRaises(EnvelopeError):  # ...and the real check says no
            tampered.unseal(self.b)


class TestTwoEnumerations(unittest.TestCase):
    def test_verbs_and_store_ids_share_integers_harmlessly(self):
        """Request verbs (what you may ASK a node to do, gated by the envelope's `frm`) and the
        log's own axes (stores, operation kinds — gated by the inner author) are separate
        enumerations by ruling. Collapsing them would let "may write the data store" imply "may
        demand a state transfer".

        Numeric overlap is therefore EXPECTED and safe rather than a collision: `1` means `PING` in
        one namespace and the data store in the other, and no code path substitutes one for the
        other. Asserting the overlap documents the separation better than asserting its absence
        would — an earlier version of this test demanded the values be disjoint, which is a
        requirement the design does not have and could not keep as both spaces grow."""
        self.assertEqual(int(Verb.PING), 1)
        self.assertEqual(ops.STORE_DATA, 1)
        self.assertNotIsInstance(ops.STORE_DATA, Verb)  # same integer, different type and meaning

    def test_the_verb_space_is_closed(self):
        """Closed so the request gate can enumerate its domain, and so a Rust or Go port matches
        exhaustively instead of carrying a default branch."""
        for value in (0, 3, 99, 1_000):
            with self.assertRaises(ValueError):
                Verb(value)


if __name__ == "__main__":
    unittest.main()
