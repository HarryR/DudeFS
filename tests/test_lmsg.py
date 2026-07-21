# L_msg — the authenticated (± sealed) envelope substrate (TRANSPORT.md). Tests the
# message-level auth/confidentiality layer the whole control-plane wave shares: plain
# + sealed round-trips, the identity-keyed screening tag, the cost-ladder rungs, and
# the request gate (including epoch-as-diagnostic as a false-rejection pair).

import unittest

from dudefs import crypto as C
from dudefs import lmsg

A_SK, B_SK, X_SK = bytes([1] * 32), bytes([2] * 32), bytes([9] * 32)
A, B, X = C.SIGNER.public(A_SK), C.SIGNER.public(B_SK), C.SIGNER.public(X_SK)
NOW, DELTA = 1000, 150


def _member(*pubs):
    allow = set(pubs)
    return lambda frm: frm in allow


class TestPlainEnvelope(unittest.TestCase):
    def test_author_verifies_and_binds_every_field(self):
        env = lmsg.author(A_SK, B, b"FRONTIER", b"payload", epoch=3, ts=NOW, nonce=b"n1")
        self.assertEqual(env.frm, A)  # from is derived from the signing key
        self.assertTrue(env.verify_sig())
        self.assertEqual(lmsg.Envelope.decode(env.encode()), env)  # canon round-trip

    def test_tamper_any_signed_field_breaks_the_sig(self):
        env = lmsg.author(A_SK, B, b"SUBMIT", b"payload", epoch=0, ts=NOW)
        import dataclasses

        for field, val in [
            ("to", X),
            ("verb", b"ACCEPT"),
            ("body", b"other"),
            ("epoch", 1),
            ("ts", NOW + 1),
            ("nonce", b"n2"),
        ]:
            self.assertFalse(dataclasses.replace(env, **{field: val}).verify_sig(), field)

    def test_an_unsigned_envelope_never_verifies(self):
        self.assertFalse(lmsg.Envelope(A, B, 0, NOW, b"", b"V", b"b").verify_sig())


class TestSealedEnvelope(unittest.TestCase):
    def _reply_kp(self):
        rsk = bytes([77] * 32)
        return rsk, C.SIGNER.public(rsk)

    def test_sign_then_seal_round_trip_hides_everything_but_the_hint(self):
        rsk, rpub = self._reply_kp()
        env = lmsg.author(A_SK, B, b"SUBMIT", b"top-secret", epoch=0, ts=NOW)
        outer = lmsg.seal_request(env, B, rpub, hinted=True)
        # the intermediary sees neither the verb, the from, nor the body
        self.assertNotIn(b"SUBMIT", outer)
        self.assertNotIn(b"top-secret", outer)
        self.assertNotIn(A, outer)
        opened = lmsg.unseal_request(B_SK, outer)
        assert opened is not None
        inner, reply_key = opened
        self.assertEqual(inner, env)  # the exact signed struct, recovered
        self.assertTrue(inner.verify_sig())
        self.assertEqual(reply_key, rpub)  # the reply-key rides inside the seal

    def test_only_the_addressee_can_unseal(self):
        rsk, rpub = self._reply_kp()
        env = lmsg.author(A_SK, B, b"GET", b"q", epoch=0, ts=NOW)
        outer = lmsg.seal_request(env, B, rpub, hinted=True)
        self.assertIsNone(lmsg.unseal_request(X_SK, outer))  # wrong recipient key
        self.assertIsNone(lmsg.unseal_request(B_SK, outer[:-1] + bytes([outer[-1] ^ 1])))  # tamper

    def test_sealed_mode_requires_a_reply_key(self):
        env = lmsg.author(A_SK, B, b"GET", b"q", epoch=0, ts=NOW)
        with self.assertRaises(ValueError):
            lmsg.seal_request(env, B, b"", hinted=True)  # no downgrade lever

    def test_sealed_reply_round_trips_to_the_ephemeral_key(self):
        rsk, rpub = self._reply_kp()
        reply = lmsg.author(B_SK, A, b"FRONTIER", b"bundle", epoch=0, ts=NOW)
        sealed = lmsg.seal_reply(reply, rpub)
        self.assertNotIn(b"bundle", sealed)
        got = lmsg.unseal_reply(rsk, sealed)
        self.assertEqual(got, reply)
        self.assertIsNone(lmsg.unseal_reply(X_SK, sealed))  # only the requester opens


class TestScreeningTag(unittest.TestCase):
    def test_hint_matches_only_the_target_identity(self):
        rpub = C.SIGNER.public(bytes([77] * 32))
        env = lmsg.author(A_SK, B, b"SUBMIT", b"x", epoch=0, ts=NOW)
        outer = lmsg.seal_request(env, B, rpub, hinted=True)
        self.assertTrue(lmsg.matches_tag(B, outer))  # the addressee screens IN
        self.assertFalse(lmsg.matches_tag(X, outer))  # a bystander node screens OUT

    def test_direct_carrier_has_no_hint_so_everyone_trial_opens(self):
        # hinted=False -> empty tag -> matches_tag True for anyone (the trial-decrypt
        # fallback on a direct carrier; `to` still lives inside the seal).
        rpub = C.SIGNER.public(bytes([77] * 32))
        env = lmsg.author(A_SK, B, b"SUBMIT", b"x", epoch=0, ts=NOW)
        outer = lmsg.seal_request(env, B, rpub, hinted=False)
        self.assertTrue(lmsg.matches_tag(B, outer))
        self.assertTrue(lmsg.matches_tag(X, outer))

    def test_the_tag_is_identity_keyed_so_a_wrong_key_diverges(self):
        # the free-drop rung: the tag is keyed by the TARGET identity, so a party
        # keying on any other identity computes a different value and screens OUT
        # before any ECDH — random internet traffic costs one symmetric hash.
        from dudefs import codec

        rpub = C.SIGNER.public(bytes([77] * 32))
        env = lmsg.author(A_SK, B, b"SUBMIT", b"x", epoch=0, ts=NOW)
        outer = lmsg.seal_request(env, B, rpub, hinted=True)
        tag, sealed = (codec.as_bytes(p) for p in codec.as_seq(codec.decode(outer), length=2))
        self.assertEqual(tag, C.screen_tag(B, sealed))  # the addressee reproduces it
        self.assertNotEqual(tag, C.screen_tag(X, sealed))  # any other key diverges


class TestRequestGate(unittest.TestCase):
    def _env(self, *, verb=b"SUBMIT", body=b"b", epoch=0, ts=NOW, nonce=b""):
        return lmsg.author(A_SK, B, verb, body, epoch=epoch, ts=ts, nonce=nonce)

    def test_member_at_the_door_is_admitted(self):
        env = self._env()
        g = lmsg.gate(env, self_pub=B, now=NOW, delta=DELTA, authorized=_member(A))
        self.assertIs(g, lmsg.Gate.OK)

    def test_non_member_is_refused_at_the_door(self):
        env = self._env()
        g = lmsg.gate(env, self_pub=B, now=NOW, delta=DELTA, authorized=_member(X))
        self.assertIs(g, lmsg.Gate.NOT_A_MEMBER)  # from A, roster = {X} -> refused

    def test_reflection_to_the_wrong_node_is_refused(self):
        # an envelope A->B replayed at node X: `to` is inside the sig, so X rejects it.
        env = self._env()
        g = lmsg.gate(env, self_pub=X, now=NOW, delta=DELTA, authorized=_member(A))
        self.assertIs(g, lmsg.Gate.WRONG_RECIPIENT)

    def test_a_forged_signature_is_refused(self):
        import dataclasses

        env = dataclasses.replace(self._env(), body=b"swapped-after-signing")
        g = lmsg.gate(env, self_pub=B, now=NOW, delta=DELTA, authorized=_member(A))
        self.assertIs(g, lmsg.Gate.BAD_SIG)

    def test_a_stale_timestamp_is_refused(self):
        env = self._env(ts=NOW - DELTA - 1)
        g = lmsg.gate(env, self_pub=B, now=NOW, delta=DELTA, authorized=_member(A))
        self.assertIs(g, lmsg.Gate.STALE)

    def test_epoch_is_diagnostic_not_a_gate(self):
        # THE false-rejection pair (⟦F⟧): the ONLY difference is the envelope epoch.
        # A hard epoch gate would wedge the roster-bridge window; the gate must admit.
        fresh_current = self._env(epoch=5)
        stale_epoch = self._env(epoch=2)  # activated peer talking to a lagging one
        for env in (fresh_current, stale_epoch):
            g = lmsg.gate(env, self_pub=B, now=NOW, delta=DELTA, authorized=_member(A))
            self.assertIs(g, lmsg.Gate.OK)  # epoch never decides admission


class TestClassifyInbound(unittest.TestCase):
    """The typed inbound outcome the transport renders (no None, no exceptions)."""

    def _env(self, *, frm_sk=A_SK, to=B, verb=b"SUBMIT", body=b"b", epoch=0, ts=NOW):
        return lmsg.author(frm_sk, to, verb, body, epoch=epoch, ts=ts)

    def _classify(self, env):
        return lmsg.classify_inbound(
            env.encode(), self_pub=B, now=NOW, delta=DELTA, authorized=_member(A)
        )

    def test_member_is_gated(self):
        self.assertIsInstance(self._classify(self._env()), lmsg.Gated)

    def test_non_member_is_refused_not_dropped(self):
        out = lmsg.classify_inbound(
            self._env().encode(), self_pub=B, now=NOW, delta=DELTA, authorized=_member(X)
        )
        self.assertIsInstance(out, lmsg.Refused)  # authenticated + addressed to us
        assert isinstance(out, lmsg.Refused)
        self.assertIs(out.reason, lmsg.Gate.NOT_A_MEMBER)

    def test_stale_is_refused(self):
        out = self._classify(self._env(ts=NOW - DELTA - 1))
        self.assertIsInstance(out, lmsg.Refused)

    def test_wrong_recipient_and_bad_sig_and_garbage_are_dropped(self):
        import dataclasses

        # addressed elsewhere -> hasn't proven it holds OUR identity -> Dropped (silence)
        self.assertIsInstance(self._classify(self._env(to=X)), lmsg.Dropped)
        # a tampered sig -> Dropped
        forged = dataclasses.replace(self._env(), body=b"swapped")
        self.assertIsInstance(self._classify(forged), lmsg.Dropped)
        # a non-envelope frame -> Dropped, never a crash
        self.assertIsInstance(self._classify_raw(b"not-bencode"), lmsg.Dropped)

    def _classify_raw(self, raw):
        return lmsg.classify_inbound(raw, self_pub=B, now=NOW, delta=DELTA, authorized=_member(A))


class TestClassifyReply(unittest.TestCase):
    def test_valid_reply_from_the_addressed_peer(self):
        reply = lmsg.author(B_SK, A, b"SUBMIT", b"receipt", epoch=0, ts=NOW)
        out = lmsg.classify_reply(reply.encode(), expect_from=B, expect_to=A)
        self.assertIsInstance(out, lmsg.Reply)

    def test_absent_and_wrong_peer_and_garbage_are_unusable(self):
        self.assertIsInstance(lmsg.classify_reply(b"", expect_from=B, expect_to=A), lmsg.Unusable)
        self.assertIsInstance(
            lmsg.classify_reply(b"junk", expect_from=B, expect_to=A), lmsg.Unusable
        )
        # a well-formed reply, but from a peer I didn't address -> not my reply
        other = lmsg.author(X_SK, A, b"SUBMIT", b"r", epoch=0, ts=NOW)
        self.assertIsInstance(
            lmsg.classify_reply(other.encode(), expect_from=B, expect_to=A), lmsg.Unusable
        )


if __name__ == "__main__":
    unittest.main()
