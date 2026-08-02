"""Tests for dude.sync.adapter -- the wire encoding for the four sync verbs.

Encode/decode round-trip for every verb. Malformed bodies raise SyncAdapterError, which is a
DudeError the crash-only boundary catches -- not InvariantError, which would terminate.
"""

from __future__ import annotations

import unittest

from ..consensus.round import Block
from ..consensus.settle_round import (
    Anchors,
    SettledBlock,
    SettledBlockWithBodies,
)
from ..core import crypto
from ..net import Verb
from ..store import ops
from ..sync.adapter import (
    SyncAdapterError,
    SyncRefusal,
    decode_getblock,
    decode_height_reply,
    decode_refusal,
    decode_settled_block,
    encode_getblock,
    encode_height,
    encode_height_reply,
    encode_refusal,
    encode_settled_block,
)


class TestHeightPoll(unittest.TestCase):
    """HEIGHT is a bodyless request; HEIGHT_REPLY carries (block_num, tip_hash)."""

    def test_height_has_empty_body(self):
        verb, body = encode_height()
        self.assertIs(verb, Verb.HEIGHT)
        self.assertEqual(body, b"")

    def test_height_reply_roundtrips(self):
        tip = crypto.h(b"some-block")
        verb, body = encode_height_reply(42, tip)
        self.assertIs(verb, Verb.HEIGHT_REPLY)
        got_num, got_hash = decode_height_reply(body)
        self.assertEqual(got_num, 42)
        self.assertEqual(got_hash, tip)

    def test_height_reply_zero_is_valid(self):
        """A node with no SETTLED blocks yet MUST be able to reply 0. Follower interprets
        this as 'peer holds nothing beyond what I have' -- perfectly common early in a
        cluster's life."""
        _verb, body = encode_height_reply(0, crypto.Digest(bytes(32)))
        got_num, got_hash = decode_height_reply(body)
        self.assertEqual(got_num, 0)
        self.assertEqual(got_hash, crypto.Digest(bytes(32)))

    def test_malformed_height_reply_raises(self):
        with self.assertRaises(SyncAdapterError):
            decode_height_reply(b"not bencode")


class TestGetBlock(unittest.TestCase):
    """GETBLOCK carries a single integer; SETTLED_BLOCK carries the block bytes verbatim."""

    def test_getblock_roundtrips(self):
        verb, body = encode_getblock(7)
        self.assertIs(verb, Verb.GETBLOCK)
        self.assertEqual(decode_getblock(body), 7)

    def test_settled_block_roundtrips_with_bodies(self):
        """The reply carries `SettledBlockWithBodies` -- the SETTLED block's identity + proof,
        plus the tx bodies a joiner needs for replay. Encode/decode is byte-canonical so a
        joiner recomputes the same `block_hash` as the producer."""
        kp = crypto.Keypair.generate()
        tx = ops.writes(ops.Set(0, crypto.h(b"k"), b"v")).sign(kp, 1_000)
        anchors = Anchors(
            block_num=1,
            height=1,
            prev_block=crypto.h(b"prev"),
            state_root=crypto.h(b"state"),
            acc_state=crypto.acc_element(b"acc-s"),
            acc_log=crypto.acc_element(b"acc-l"),
        )
        block = Block(
            bucket=42,
            hashes=(tx.op_hash,),
            signers=crypto.SignerBitmap(b""),
            sigs=(),
        )
        sb = SettledBlock(
            block=block,
            anchors=anchors,
            signers=crypto.SignerBitmap(b""),
            settle_sigs=(),
        )
        sbwb = SettledBlockWithBodies(block=sb, bodies=(tx,))

        verb, body = encode_settled_block(sbwb)
        self.assertIs(verb, Verb.SETTLED_BLOCK)
        got = decode_settled_block(body)
        self.assertEqual(got.block.anchors, sb.anchors)
        self.assertEqual(got.block.block.hashes, sb.block.hashes)
        self.assertEqual(len(got.bodies), 1)
        self.assertEqual(got.bodies[0].op_hash, tx.op_hash)

    def test_malformed_getblock_raises(self):
        with self.assertRaises(SyncAdapterError):
            decode_getblock(b"not bencode either")


class TestRefusal(unittest.TestCase):
    """REFUSED bodies carry a closed-enum reason (#getblock-refuses-with-reason)."""

    def test_each_reason_roundtrips(self):
        for reason in (SyncRefusal.NOT_YET_SETTLED, SyncRefusal.UNKNOWN):
            verb, body = encode_refusal(reason)
            self.assertIs(verb, Verb.REFUSED)
            self.assertIs(decode_refusal(body), reason)

    def test_unknown_reason_string_raises(self):
        """An honest peer's REFUSED body MUST name a known reason; a stringly-typed unknown
        value means protocol mismatch, not a routine drop."""
        with self.assertRaises(SyncAdapterError):
            decode_refusal(b"some-reason-we-do-not-know")

    def test_non_utf8_body_raises(self):
        with self.assertRaises(SyncAdapterError):
            decode_refusal(b"\xff\xfe")

    def test_invalid_is_not_a_valid_wire_reason(self):
        """`INVALID` is the port-safety zero -- MUST NOT be sent. `decode_refusal(b"invalid")`
        would parse (it's a valid enum value) but this is a semantic hazard rather than a wire
        failure; documented here as a known intentional gap: an honest peer will not send it,
        and if a byzantine one does, it lands on the same 'try another peer' branch as any
        other REFUSED reason. The port-safety property is what stops a Go zero-valued field
        silently meaning NOT_YET_SETTLED."""
        # Just pin the current behaviour: INVALID does parse via the wire encoding.
        _, body = encode_refusal(SyncRefusal.INVALID)
        self.assertIs(decode_refusal(body), SyncRefusal.INVALID)


if __name__ == "__main__":
    unittest.main()
