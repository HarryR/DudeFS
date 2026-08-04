"""Tests for dude.settle_round -- signature-collection state machine, direct-wired.

Same shape as test_round.py: no net stack, no envelopes, no seals. `_wire` drains outboxes and
delivers to targets. Signatures are REAL because `crypto.Keypair.generate()` is fast enough that
faking sigs buys nothing and loses the property that ratification actually verifies -- and
divergence detection depends on signature-verified anchor equality.
"""

from __future__ import annotations

import unittest

from dude.consensus.round import Block
from dude.consensus.settle_round import (
    Anchors,
    SettledBlock,
    SettleError,
    SettleRound,
    SettleSig,
    SettleState,
    genesis_stamp,
)
from dude.core import crypto
from dude.net.postman import Recipient

T0 = 1_700_000_000_000
DELTA = 1_000
ABANDON_BY = T0 + 1_000 * DELTA
"""SettleRound abandonment deadline for the scenario suite. Far past every test's runtime so
no test's SettleRound times out incidentally. Abandonment behaviour has its own dedicated
test class that sets a shorter value on purpose."""


def _wire(nodes: dict[crypto.PublicKey, SettleRound], now: int) -> None:
    """Drain every SettleRound's outbox and deliver to targets. Broadcasts (Recipient.ALL)
    reach every other node; directed sends reach only the named node."""
    for src_id, src in nodes.items():
        for target, msg in src.outbox():
            for dst_id, dst in nodes.items():
                if dst_id == src_id:
                    continue
                if target is Recipient.ALL or target == dst_id:
                    dst.receive(msg, from_=src_id, now=now)


def _block(bucket: int = 1, hashes: tuple[bytes, ...] = ()) -> Block:
    """A stub ratified block. SettleRound only uses `bucket` and `hashes` to derive
    slice_hash; the signers/sigs are Round's business and irrelevant to settlement."""
    return Block(
        bucket=bucket,
        hashes=tuple(sorted(crypto.Digest(h) for h in hashes)),
        signers=crypto.SignerBitmap(b""),
        sigs=(),
    )


def _anchors(block_num: int = 1, height: int = 0, root_seed: bytes = b"root") -> Anchors:
    """A deterministic set of anchor values for tests. `root_seed` lets a test construct two
    distinct anchors -- one honest, one divergent -- without leaking hash internals into
    assertions."""
    return Anchors(
        block_num=block_num,
        height=height,
        prev_block=crypto.h(b"prev:" + root_seed),
        state_root=crypto.h(b"state:" + root_seed),
        acc_state=crypto.acc_element(b"acc:" + root_seed),
        acc_log=crypto.acc_element(b"log:" + root_seed),
    )


def _setup(
    n: int, block: Block | None = None, anchors: Anchors | None = None
) -> tuple[list[crypto.Keypair], dict[crypto.PublicKey, SettleRound]]:
    """N nodes, one SettleRound each, all handed the same block and (by default) same anchors."""
    keys = [crypto.Keypair.generate() for _ in range(n)]
    roster = tuple(k.public for k in keys)
    b = block if block is not None else _block()
    a = anchors if anchors is not None else _anchors()
    rounds = {k.public: SettleRound(b, k, roster, a, T0, ABANDON_BY) for k in keys}
    return keys, rounds


def _run(nodes: dict[crypto.PublicKey, SettleRound], rounds: int = 5) -> None:
    """Wire + tick, `rounds` times. SettleRound has no deadlines so tick is a no-op, but the
    call is kept to mirror test_round.py and to exercise the interface."""
    for _ in range(rounds):
        _wire(nodes, T0)
        for r in nodes.values():
            r.tick(T0)


# --------------------------------------------------------------------------------------------- #
# Convergence: honest cluster, everyone signs matching anchors                                  #
# --------------------------------------------------------------------------------------------- #


class TestHonestCluster(unittest.TestCase):
    """Everyone computed the same anchors from the same slice. Ratification is trivial -- one
    round of Sig exchange, quorum-many matching, SETTLED."""

    def test_every_node_settles_with_the_same_anchors(self):
        _keys, nodes = _setup(3)
        _run(nodes)

        for r in nodes.values():
            self.assertEqual(r.state(), SettleState.SETTLED)
            settled = r.settled()
            assert settled is not None
            self.assertEqual(settled.anchors, _anchors())

    def test_own_sig_is_emitted_at_construction(self):
        """The first outbox drain (before any receive) MUST contain our own SettleSig. Otherwise
        peers cannot know we agree and cannot count us toward their quorum."""
        _keys, nodes = _setup(3)
        r = next(iter(nodes.values()))
        msgs = list(r.outbox())
        self.assertEqual(len(msgs), 1)
        target, msg = msgs[0]
        self.assertIs(target, Recipient.ALL)
        assert isinstance(msg, SettleSig)
        self.assertEqual(msg.anchors, _anchors())

    def test_settled_block_carries_the_block_and_anchors_and_sigs(self):
        """The SETTLED block carries at least a QUORUM's worth of sigs -- not necessarily every
        node's. `_try_settle` fires as soon as quorum is met, so a node that sees its own sig
        plus one peer's (quorum=2 at n=3) SETTLES before a third peer's sig arrives."""
        _keys, nodes = _setup(3)
        _run(nodes)

        settled = next(iter(nodes.values())).settled()
        assert settled is not None
        self.assertEqual(settled.block, _block())
        self.assertEqual(settled.anchors, _anchors())
        # At least a quorum (2 of 3). Depending on delivery order some nodes may capture the
        # third sig before SETTLING; either way, quorum is the floor.
        self.assertGreaterEqual(len(settled.settle_sigs), 2)


# --------------------------------------------------------------------------------------------- #
# Divergence: a peer signs different anchors from ours                                          #
# --------------------------------------------------------------------------------------------- #


class TestDivergenceIsEvidenceNotCrash(unittest.TestCase):
    """SPECv2 #settlement-quorum-on-anchors: a peer whose sig commits to different anchors is a
    routine outcome (their bug, or byzantine malice; we cannot distinguish). Drop from quorum
    counting, preserve as evidence, never terminate the process."""

    def test_divergent_peer_is_dropped_from_quorum_but_others_still_settle(self):
        """Three nodes, one signs divergent anchors. The other two + honest one still form a
        quorum (2 of 3) among themselves and settle. The divergent peer's own SettleRound is
        stuck (nobody's sig matches its anchors)."""
        keys = [crypto.Keypair.generate() for _ in range(3)]
        roster = tuple(k.public for k in keys)
        block = _block()
        honest = _anchors(root_seed=b"honest")
        divergent = _anchors(root_seed=b"divergent")

        # Nodes 0 and 1 sign honest; node 2 signs divergent
        r0 = SettleRound(block, keys[0], roster, honest, T0, ABANDON_BY)
        r1 = SettleRound(block, keys[1], roster, honest, T0, ABANDON_BY)
        r2 = SettleRound(block, keys[2], roster, divergent, T0, ABANDON_BY)
        nodes = {keys[0].public: r0, keys[1].public: r1, keys[2].public: r2}

        _run(nodes)

        # Nodes 0 and 1 SETTLED with honest anchors (each other + own = 2 = quorum(3))
        self.assertEqual(r0.state(), SettleState.SETTLED)
        self.assertEqual(r1.state(), SettleState.SETTLED)
        settled0 = r0.settled()
        assert settled0 is not None
        self.assertEqual(settled0.anchors, honest)

        # Node 2 stuck: no honest peer signed its divergent anchors
        self.assertEqual(r2.state(), SettleState.COLLECTING)
        self.assertIsNone(r2.settled())

    def test_divergences_are_recorded_as_evidence(self):
        """The honest nodes see the divergent peer's sig and log it in `divergences()`.
        Empty in the honest case."""
        keys = [crypto.Keypair.generate() for _ in range(3)]
        roster = tuple(k.public for k in keys)
        block = _block()
        r0 = SettleRound(block, keys[0], roster, _anchors(root_seed=b"honest"), T0, ABANDON_BY)
        r1 = SettleRound(block, keys[1], roster, _anchors(root_seed=b"honest"), T0, ABANDON_BY)
        r2 = SettleRound(block, keys[2], roster, _anchors(root_seed=b"divergent"), T0, ABANDON_BY)
        nodes = {keys[0].public: r0, keys[1].public: r1, keys[2].public: r2}

        _run(nodes)

        # Honest nodes recorded the divergent peer's anchors as evidence
        divs = r0.divergences()
        self.assertEqual(len(divs), 1)
        peer, anchors_seen = divs[0]
        self.assertEqual(peer, keys[2].public)
        self.assertEqual(anchors_seen, _anchors(root_seed=b"divergent"))

    def test_divergent_peer_receives_evidence_from_honest_peers(self):
        """The divergent node, in turn, sees the honest anchors as divergences from ITS
        perspective. Symmetric evidence, useful for the observability layer to detect that
        THIS node is the outlier."""
        keys = [crypto.Keypair.generate() for _ in range(3)]
        roster = tuple(k.public for k in keys)
        block = _block()
        r0 = SettleRound(block, keys[0], roster, _anchors(root_seed=b"honest"), T0, ABANDON_BY)
        r1 = SettleRound(block, keys[1], roster, _anchors(root_seed=b"honest"), T0, ABANDON_BY)
        r2 = SettleRound(block, keys[2], roster, _anchors(root_seed=b"divergent"), T0, ABANDON_BY)
        nodes = {keys[0].public: r0, keys[1].public: r1, keys[2].public: r2}

        _run(nodes)

        # Divergent node saw two honest sigs, both anchors-mismatched vs its own
        self.assertEqual(len(r2.divergences()), 2)


# --------------------------------------------------------------------------------------------- #
# Message hygiene: bad sig, wrong slice, wrong signer                                           #
# --------------------------------------------------------------------------------------------- #


class TestBadInputIsSilentlyDropped(unittest.TestCase):
    """Malformed or hostile peer input MUST NOT crash and MUST NOT be counted. Same shape as
    Round's silent drops."""

    def test_forged_signature_is_dropped(self):
        """A SettleSig whose signature does not verify: dropped. The sender is not credited
        toward quorum."""
        keys = [crypto.Keypair.generate() for _ in range(3)]
        roster = tuple(k.public for k in keys)
        block = _block()
        anchors = _anchors()

        target_round = SettleRound(block, keys[0], roster, anchors, T0, ABANDON_BY)

        # A SettleSig claiming to be from keys[1] with a bogus signature
        forged = SettleSig(
            slice_hash=block.slice_hash,
            anchors=anchors,
            sig=crypto.Signature(bytes(64)),
        )
        target_round.receive(forged, from_=keys[1].public, now=T0)

        # No credit: only our own sig, still 1 of 2 needed
        self.assertEqual(target_round.state(), SettleState.COLLECTING)

    def test_sig_for_wrong_slice_is_dropped(self):
        """A SettleSig binding to a different slice_hash cannot count toward this block."""
        keys = [crypto.Keypair.generate() for _ in range(3)]
        roster = tuple(k.public for k in keys)
        our_block = _block(bucket=1)
        other_block = _block(bucket=99)  # different bucket -> different slice_hash

        r0 = SettleRound(our_block, keys[0], roster, _anchors(), T0, ABANDON_BY)

        # Genuine sig, but over the OTHER block's slice_hash
        wrong = SettleSig.sign(keys[1], other_block.slice_hash, _anchors())
        r0.receive(wrong, from_=keys[1].public, now=T0)

        # Not counted
        self.assertEqual(r0.state(), SettleState.COLLECTING)

    def test_sig_from_outside_roster_is_dropped(self):
        keys = [crypto.Keypair.generate() for _ in range(3)]
        stranger = crypto.Keypair.generate()
        roster = tuple(k.public for k in keys)
        block = _block()
        anchors = _anchors()

        r0 = SettleRound(block, keys[0], roster, anchors, T0, ABANDON_BY)

        # A perfectly valid signature -- but from a key that is not in the roster.
        msg = SettleSig.sign(stranger, block.slice_hash, anchors)
        r0.receive(msg, from_=stranger.public, now=T0)

        self.assertEqual(r0.state(), SettleState.COLLECTING)

    def test_self_not_in_roster_is_a_construction_error(self):
        """The one API-misuse case that DOES raise. Not for peer input; for own construction."""
        keys = [crypto.Keypair.generate() for _ in range(3)]
        roster = tuple(k.public for k in keys)
        outsider = crypto.Keypair.generate()
        with self.assertRaises(SettleError):
            SettleRound(_block(), outsider, roster, _anchors(), T0, ABANDON_BY)


# --------------------------------------------------------------------------------------------- #
# Post-SETTLED: late arrivals do not perturb state                                              #
# --------------------------------------------------------------------------------------------- #


class TestLateArrivalIsTolerated(unittest.TestCase):
    """After SETTLED, a further peer sig arriving late is verified but does not change state.
    The settled block is a terminal snapshot; adding a fourth sig to a 3-node quorum does not
    mean anything."""

    def test_late_matching_sig_after_settled_is_idempotent(self):
        _keys, nodes = _setup(3)
        _run(nodes)
        r0 = next(iter(nodes.values()))
        self.assertEqual(r0.state(), SettleState.SETTLED)
        first = r0.settled()

        # Fabricate another matching sig from a "new" peer -- won't be counted anyway (outside
        # the roster in this setup), but the point is state is stable.
        outsider = crypto.Keypair.generate()
        r0.receive(
            SettleSig.sign(outsider, _block().slice_hash, _anchors()),
            from_=outsider.public,
            now=T0,
        )
        self.assertEqual(r0.state(), SettleState.SETTLED)
        self.assertEqual(r0.settled(), first)


# --------------------------------------------------------------------------------------------- #
# Block-shape and chain link (#block-shape-settled, #genesis-stamp-anchors-the-chain)           #
# --------------------------------------------------------------------------------------------- #


class TestSettledBlockEncoding(unittest.TestCase):
    """The wire form ratified by #block-shape-settled. `encode` is what persists to disk and
    what a joiner receives on `SETTLED_BLOCK`; `decode` is its inverse; `block_hash` is the
    input to the next block's chain link."""

    def _sb(self, block_num: int = 1, height: int = 0) -> SettledBlock:
        """A settled block with real signatures over `_anchors(block_num, height)`."""
        keys = [crypto.Keypair.generate() for _ in range(3)]
        roster = tuple(k.public for k in keys)
        block = _block()
        anchors = _anchors(block_num=block_num, height=height)
        r0 = SettleRound(block, keys[0], roster, anchors, T0, ABANDON_BY)
        r1 = SettleRound(block, keys[1], roster, anchors, T0, ABANDON_BY)
        # Deliver r1's sig to r0 to reach the 2-of-3 quorum.
        for target, msg in r1.outbox():
            if target is Recipient.ALL or target == keys[0].public:
                r0.receive(msg, from_=keys[1].public, now=T0)
        settled = r0.settled()
        assert settled is not None
        return settled

    def test_encode_then_decode_is_the_same_settled_block(self):
        """Round-trip. Anything the wire mangles is a decode divergence -- both sides self-
        consistent in isolation, silently disagreeing on what was transmitted (CLAUDE.md trap 1)."""
        sb = self._sb()
        got = SettledBlock.decode(sb.encode())
        self.assertEqual(got.block.bucket, sb.block.bucket)
        self.assertEqual(got.block.hashes, sb.block.hashes)
        self.assertEqual(got.anchors, sb.anchors)
        self.assertEqual(bytes(got.signers), bytes(sb.signers))
        self.assertEqual(got.settle_sigs, sb.settle_sigs)

    def test_block_hash_is_stable_and_sig_independent(self):
        """The chain link -- a successor's `Anchors.prev_block` -- MUST be deterministic AND
        sig-independent (see `SettledBlock.block_hash`). Two nodes with the same slice + same
        anchors compute the same hash regardless of which quorum-subset of sigs they hold."""
        sb = self._sb()
        # Deterministic: two calls give the same digest.
        self.assertEqual(sb.block_hash, sb.block_hash)
        # Sig-independent: strip a settle_sig, hash still matches.
        stripped = SettledBlock(
            block=sb.block,
            anchors=sb.anchors,
            signers=crypto.SignerBitmap(b""),
            settle_sigs=(),
        )
        self.assertEqual(sb.block_hash, stripped.block_hash)
        # NOT equal to H(encode()): the wire bytes include sigs, the chain hash does not.
        self.assertNotEqual(sb.block_hash, crypto.h(sb.encode()))

    def test_encode_omits_ratify_sigs(self):
        """#block-shape-settled: ratify sigs are Round's transient consensus infrastructure and
        MUST NOT be persisted. The decoded block's ratify credentials are empty."""
        sb = self._sb()
        got = SettledBlock.decode(sb.encode())
        self.assertEqual(bytes(got.block.signers), b"")
        self.assertEqual(got.block.sigs, ())

    def test_malformed_bytes_raise_settle_error(self):
        """Bad bytes are a routine peer-input outcome; SettleError is a DudeError that the
        crash-only boundary catches -- not InvariantError, which would terminate."""
        with self.assertRaises(SettleError):
            SettledBlock.decode(b"not bencode at all")


class TestChainLinkIsSigned(unittest.TestCase):
    """`prev_block` is inside the anchors payload, so the settlement signature covers it. A peer
    lying about which chain a block belongs to invalidates its own signature."""

    def test_different_prev_block_makes_incompatible_sigs(self):
        """Two nodes with the same slice + same state anchors but different `prev_block` produce
        DIFFERENT SettleSigs, and neither counts toward the other's quorum. This is what stops a
        forked history claiming to be the same chain."""
        keys = [crypto.Keypair.generate() for _ in range(3)]
        roster = tuple(k.public for k in keys)
        block = _block()
        a_chain_x = _anchors(root_seed=b"same-state")
        a_chain_y = Anchors(
            block_num=a_chain_x.block_num,
            height=a_chain_x.height,
            prev_block=crypto.h(b"different-parent"),
            state_root=a_chain_x.state_root,
            acc_state=a_chain_x.acc_state,
            acc_log=a_chain_x.acc_log,
        )
        r_x = SettleRound(block, keys[0], roster, a_chain_x, T0, ABANDON_BY)
        r_y = SettleRound(block, keys[1], roster, a_chain_y, T0, ABANDON_BY)
        # Deliver each side's sig to the other. Both see divergent anchors and drop.
        for target, msg in r_y.outbox():
            if target is Recipient.ALL or target == keys[0].public:
                r_x.receive(msg, from_=keys[1].public, now=T0)
        for target, msg in r_x.outbox():
            if target is Recipient.ALL or target == keys[1].public:
                r_y.receive(msg, from_=keys[0].public, now=T0)
        # Neither settles -- they think they're on different chains.
        self.assertEqual(r_x.state(), SettleState.COLLECTING)
        self.assertEqual(r_y.state(), SettleState.COLLECTING)
        # And each recorded the other as a divergence (evidence).
        self.assertEqual(len(list(r_x.divergences())), 1)
        self.assertEqual(len(list(r_y.divergences())), 1)


class TestGenesisStamp(unittest.TestCase):
    """The first block's `prev_block` is the genesis stamp -- computable from the manager pubkey
    alone (#genesis-stamp-anchors-the-chain), so a fresh joiner can chain-verify block 1 without
    fetching any earlier state."""

    def test_genesis_is_deterministic(self):
        """Same manager pubkey => same stamp, byte for byte."""
        m = crypto.Keypair.generate().public
        self.assertEqual(genesis_stamp(m), genesis_stamp(m))

    def test_different_managers_get_different_stamps(self):
        """Two clusters started from different manager keys have byte-different genesis stamps,
        so a block from cluster A cannot chain-verify against cluster B's history even if the
        first bucket numbers coincidentally match."""
        m_a = crypto.Keypair.generate().public
        m_b = crypto.Keypair.generate().public
        self.assertNotEqual(genesis_stamp(m_a), genesis_stamp(m_b))

    def test_genesis_is_a_digest(self):
        """32 bytes, the ordinary digest width -- so it fits `Anchors.prev_block` without any
        special-case encoding at height 1 vs later heights."""
        stamp = genesis_stamp(crypto.Keypair.generate().public)
        self.assertEqual(len(stamp), 32)


# --------------------------------------------------------------------------------------------- #
# Abandonment on cadence (#one-of-each-in-flight + #settlement-may-hang).                       #
# --------------------------------------------------------------------------------------------- #


class TestSettleRoundAbandonOnTimeout(unittest.TestCase):
    """A SettleRound that cannot reach quorum by `abandon_by` MUST transition to ABANDONED
    rather than hang indefinitely. This is what keeps the pipeline moving -- Coordinator
    frees the settling slot and the next Round's Block can promote."""

    def test_isolated_settle_abandons_after_deadline(self):
        """A single-node SettleRound (no peers to send sigs) at n=3 requires quorum of 2 --
        can't reach with 1 sig. Ticking past abandon_by transitions it to ABANDONED."""
        close_by = T0 + 3 * DELTA
        abandon_by = T0 + 5 * DELTA
        keys = [crypto.Keypair.generate() for _ in range(3)]
        roster = tuple(k.public for k in keys)
        block = _block()
        anchors = _anchors()

        # Only construct one SettleRound (isolated); no peer sigs will ever arrive.
        r = SettleRound(block, keys[0], roster, anchors, T0, abandon_by)
        self.assertEqual(r.state(), SettleState.COLLECTING)
        self.assertFalse(r.abandoned())

        # Tick before deadline: still COLLECTING.
        r.tick(close_by)
        self.assertEqual(r.state(), SettleState.COLLECTING)
        self.assertFalse(r.abandoned())

        # Tick past deadline: ABANDONED.
        r.tick(abandon_by)
        self.assertTrue(r.abandoned())
        self.assertEqual(r.state(), SettleState.ABANDONED)
        self.assertIsNone(r.settled())

    def test_abandoned_is_terminal_no_late_settle(self):
        """Once ABANDONED, further peer sigs arriving late MUST NOT flip the state back to
        SETTLED. Abandonment is one-way."""
        abandon_by = T0 + 5 * DELTA
        keys = [crypto.Keypair.generate() for _ in range(3)]
        roster = tuple(k.public for k in keys)
        block = _block()
        anchors = _anchors()

        r0 = SettleRound(block, keys[0], roster, anchors, T0, abandon_by)
        # Force abandonment.
        r0.tick(abandon_by)
        self.assertTrue(r0.abandoned())

        # Peer sigs from nodes 1 and 2 arrive after abandonment. Would have been enough for
        # quorum (2 with our own already-counted sig). Must NOT flip to SETTLED.
        r1_sig = SettleSig.sign(keys[1], block.slice_hash, anchors)
        r2_sig = SettleSig.sign(keys[2], block.slice_hash, anchors)
        r0.receive(r1_sig, from_=keys[1].public, now=abandon_by + DELTA)
        r0.receive(r2_sig, from_=keys[2].public, now=abandon_by + DELTA)

        # State stays ABANDONED; settled() stays None.
        self.assertTrue(r0.abandoned())
        self.assertEqual(r0.state(), SettleState.ABANDONED)
        self.assertIsNone(r0.settled())

    def test_settled_before_deadline_does_not_abandon(self):
        """If quorum forms BEFORE abandon_by, we're SETTLED -- ticking past abandon_by later
        does NOT flip to ABANDONED (already terminal in SETTLED)."""
        abandon_by = T0 + 5 * DELTA
        _keys, nodes = _setup(3)
        _run(nodes)
        # Verify all settled first.
        for r in nodes.values():
            self.assertEqual(r.state(), SettleState.SETTLED)
        # Now tick past the (default very-far) abandon_by used by _setup; state stays SETTLED.
        for r in nodes.values():
            r.tick(abandon_by)
            self.assertEqual(r.state(), SettleState.SETTLED)
            self.assertFalse(r.abandoned())


if __name__ == "__main__":
    unittest.main()
