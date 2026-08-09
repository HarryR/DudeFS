"""Tests for dude.sync.adapter -- typed messages + wire encoding for the four sync verbs.

Encode/decode round-trip for every message type. Malformed bodies raise SyncAdapterError, which
is a DudeError the crash-only boundary catches -- not InvariantError, which would terminate.
"""

from __future__ import annotations

import unittest

from ..consensus.mempool import Refusal
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
    GetBlocks,
    HeightAsk,
    HeightReply,
    Refused,
    SettledBlockReply,
    SyncAdapterError,
    SyncMsg,
)
from ..sync.refusal import SyncRefusal


class TestHeightPoll(unittest.TestCase):
    """`HeightAsk` is bodyless; `HeightReply` carries `(block_num, tip_hash)`."""

    def test_height_ask_has_empty_body(self):
        verb, body = HeightAsk().encode()
        self.assertIs(verb, Verb.HEIGHT)
        self.assertEqual(body, b"")
        got = SyncMsg.decode(verb, body)
        self.assertIsInstance(got, HeightAsk)

    def test_height_reply_roundtrips(self):
        tip = crypto.h(b"some-block")
        msg = HeightReply(block_num=42, tip_hash=tip)
        verb, body = msg.encode()
        self.assertIs(verb, Verb.HEIGHT_REPLY)
        self.assertEqual(SyncMsg.decode(verb, body), msg)

    def test_height_reply_zero_is_valid(self):
        """A node with no SETTLED blocks yet MUST be able to reply 0. Follower interprets
        this as 'peer holds nothing beyond what I have' -- common early in a cluster's life."""
        msg = HeightReply(block_num=0, tip_hash=crypto.Digest(bytes(32)))
        verb, body = msg.encode()
        self.assertEqual(SyncMsg.decode(verb, body), msg)

    def test_malformed_height_reply_raises(self):
        with self.assertRaises(SyncAdapterError):
            SyncMsg.decode(Verb.HEIGHT_REPLY, b"not bencode")


class TestGetBlocks(unittest.TestCase):
    """`GetBlocks` names a range; `SettledBlockReply` carries as many blocks as the server
    served, which is how a follower behind a live cluster closes the gap instead of widening
    it one round trip at a time."""

    def test_getblocks_roundtrips(self):
        msg = GetBlocks(frm=7, count=32)
        verb, body = msg.encode()
        self.assertIs(verb, Verb.GETBLOCK)
        self.assertEqual(SyncMsg.decode(verb, body), msg)

    def test_settled_block_reply_roundtrips_with_bodies(self):
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
        block = Block(bucket=42, hashes=(tx.op_hash,), multisig=crypto.UNSIGNED)
        sb = SettledBlock(block=block, anchors=anchors, multisig=crypto.UNSIGNED)
        msg = SettledBlockReply(payload=(SettledBlockWithBodies(block=sb, bodies=(tx,)),))

        verb, body = msg.encode()
        self.assertIs(verb, Verb.SETTLED_BLOCK)
        got = SyncMsg.decode(verb, body)
        self.assertIsInstance(got, SettledBlockReply)
        assert isinstance(got, SettledBlockReply)  # for the type checker
        self.assertEqual(got.payload[0].block.anchors, sb.anchors)
        self.assertEqual(got.payload[0].block.block.hashes, sb.block.hashes)
        self.assertEqual(len(got.payload[0].bodies), 1)
        self.assertEqual(got.payload[0].bodies[0].op_hash, tx.op_hash)

    def test_malformed_getblock_raises(self):
        with self.assertRaises(SyncAdapterError):
            SyncMsg.decode(Verb.GETBLOCK, b"not bencode either")


class TestRefusal(unittest.TestCase):
    """`Refused` bodies carry a closed-enum reason (#getblock-refuses-with-reason)."""

    def test_each_reason_roundtrips(self):
        for reason in (SyncRefusal.NOT_YET_SETTLED, SyncRefusal.UNKNOWN):
            msg = Refused(reason=reason)
            verb, body = msg.encode()
            self.assertIs(verb, Verb.SYNC_REFUSED)
            self.assertEqual(SyncMsg.decode(verb, body), msg)

    def test_unknown_reason_string_raises(self):
        """An honest peer's `Refused` body MUST name a known reason; a stringly-typed unknown
        value means protocol mismatch, not a routine drop."""
        with self.assertRaises(SyncAdapterError):
            SyncMsg.decode(Verb.SYNC_REFUSED, b"some-reason-we-do-not-know")

    def test_non_utf8_body_raises(self):
        with self.assertRaises(SyncAdapterError):
            SyncMsg.decode(Verb.SYNC_REFUSED, b"\xff\xfe")

    def test_invalid_is_not_a_valid_wire_reason(self):
        """`INVALID` is the port-safety zero -- MUST NOT be sent. `SyncMsg.decode(REFUSED,
        b"invalid")` would parse (it's a valid enum value) but this is a semantic hazard rather
        than a wire failure; documented here as a known intentional gap: an honest peer will
        not send it, and if a byzantine one does, it lands on the same 'try another peer'
        branch as any other `Refused` reason. The port-safety property is what stops a Go
        zero-valued field silently meaning NOT_YET_SETTLED."""
        _, body = Refused(reason=SyncRefusal.INVALID).encode()
        self.assertEqual(
            SyncMsg.decode(Verb.SYNC_REFUSED, body), Refused(reason=SyncRefusal.INVALID)
        )


class TestSubmitRefusalsAreNotSyncRefusals(unittest.TestCase):
    """One verb used to carry both vocabularies: `REFUSED` answered a client's SUBMIT with a
    `mempool.Refusal` value AND a peer's GETBLOCK with a `SyncRefusal` value, and the body said
    nothing about which. Decoding was unambiguous only because the two value sets happened not to
    overlap, while both kept growing -- the first collision would have had a submit refusal
    correcting down a peer's claimed head."""

    def test_the_two_verbs_are_distinct(self):
        self.assertIsNot(Verb.REFUSED, Verb.SYNC_REFUSED)

    def test_a_submit_refusal_body_is_not_decodable_as_a_sync_message(self):
        for refusal in Refusal:
            with self.assertRaises(SyncAdapterError):
                SyncMsg.decode(Verb.REFUSED, refusal.value.encode())


class TestDecodeVerbGuard(unittest.TestCase):
    """`SyncMsg.decode` returns a subclass instance -- but only for the five sync verbs. A
    non-sync verb is a protocol confusion, not a decode failure of a well-formed sync body."""

    def test_non_sync_verb_raises(self):
        with self.assertRaises(SyncAdapterError):
            SyncMsg.decode(Verb.SUBMIT, b"")


class TestSyncMsgIsAbstract(unittest.TestCase):
    """`SyncMsg` itself is abstract -- instantiating it should fail. Concrete subclasses
    (`HeightAsk`, `HeightReply`, ...) implement `encode` and are constructible."""

    def test_syncmsg_cannot_be_instantiated_directly(self):
        with self.assertRaises(TypeError):
            SyncMsg()


class TestTheRefusalVocabularyIsOneClosedSet(unittest.TestCase):
    """Both sync paths share `SyncRefusal`, and both are expected to match it EXHAUSTIVELY --
    `Follower._on_refused` and `LightClient._on_read_reply`. Nothing at runtime notices a member
    with no case: a `match` without a wildcard just falls through. This pins the set so adding
    one is a decision that visits both handlers, the same reason encode/decode pairs are pinned
    by field count."""

    def test_the_members_and_their_wire_strings(self):
        self.assertEqual(
            [(r.name, r.value) for r in SyncRefusal],
            [
                ("INVALID", "invalid"),
                ("NOT_YET_SETTLED", "not-yet-settled"),
                ("UNKNOWN", "unknown"),
                ("NO_STATE", "no-state"),
                ("UNKNOWN_STORE", "unknown-store"),
                ("MALFORMED_QUERY", "malformed-query"),
                ("FORK_DETECTED", "fork-detected"),
                ("INTERNAL", "internal"),
            ],
            "add a member -> give it a case in Follower._on_refused AND the light client",
        )

    def test_every_member_survives_the_wire(self):
        for reason in SyncRefusal:
            verb, body = Refused(reason=reason).encode()
            self.assertEqual(SyncMsg.decode(verb, body), Refused(reason=reason))


if __name__ == "__main__":
    unittest.main()
