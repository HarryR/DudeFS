# The shared chain walk, and the property that unification exists to make checkable.
#
# A node and a light client both advance a trusted head along a verified chain. They were two
# implementations of one loop, and every sync defect sat where the copies disagreed: one spelled
# "no block yet" as 32 zero bytes and the other as the genesis stamp; one walked a range and the
# other a single block; one acted on refusals and the other discarded them. None of it was
# visible to `test_sync.py` or `test_lite_*.py`, because each tests its own path against itself.
#
# The test at the bottom is the one that would have caught all of it: same chain, both paths,
# same head.

from __future__ import annotations

import unittest

from ..consensus.settle_round import SettledBlock, genesis_stamp
from ..core import crypto
from ..store import Store
from ..store.management import MgmtReader
from ..sync import chain
from ..sync.adapter import GetBlocks, SettledBlockReply
from ..sync.follower import PullInFlight, serve_getblocks, serve_height
from .cluster import T0, Cluster
from .test_sync import _make_follower, _run_cluster_producing_n_blocks


def _blocks_from(store: Store, frm: int, to: int) -> tuple[SettledBlock, ...]:
    out = []
    for n in range(frm, to + 1):
        raw = store.settled_at(n)
        assert raw is not None, f"block {n} missing"
        out.append(SettledBlock.decode(raw))
    return tuple(out)


class TestTheGenesisSpellingIsShared(unittest.TestCase):
    """`serve_height` answered `Digest(bytes(32))` for "no block yet" while `caught_up` used the
    genesis stamp. Two fresh nodes therefore reported the same height with different tips --
    which is the FORK signal -- and could never count each other toward `f+1`."""

    def test_a_fresh_store_serves_the_same_tip_it_compares_against(self):
        c = Cluster()
        fresh = Store()
        fresh.provision(c.mgr.public)  # provisioned, not bootstrapped: no block yet

        served = serve_height(fresh)
        self.assertEqual(served.block_num, 0)
        self.assertEqual(served.tip_hash, genesis_stamp(c.mgr.public))
        self.assertEqual(served.tip_hash, chain.TrustedHead.genesis(c.mgr.public).block_hash)

    def test_what_one_fresh_node_serves_is_what_another_compares_against(self):
        """The cross-check, not serve-vs-serve: two fresh nodes both answered zeros and so agreed
        with each other. The break was between the tip a node SERVES and the tip its own
        `caught_up` COMPARES to, which is why it never showed up in either path alone."""
        c = Cluster()
        a, b = Store(), Store()
        for s in (a, b):
            s.provision(c.mgr.public)
        self.assertEqual(serve_height(a).tip_hash, _make_follower(b)._tip())


class TestAdvanceRefusesWhatItShould(unittest.TestCase):
    def setUp(self):
        self.c = Cluster()
        _run_cluster_producing_n_blocks(self.c, 3)
        self.store = self.c.nodes[0].store
        self.roster = MgmtReader(self.store).roster()
        self.anchor = self.c.mgr.public

    def test_a_broken_link_is_refused(self):
        blocks = _blocks_from(self.store, 2, 3)
        # Start from block 1's head but offer block 3 first: the link does not hold.
        start = chain.TrustedHead(1, blocks[0].anchors.prev_block, blocks[0].anchors.state_root, 0)
        self.assertIs(
            chain.advance(start.block_hash, (blocks[1],), self.roster, self.anchor),
            chain.ChainRefusal.BROKEN_LINK,
        )

    def test_a_block_the_roster_did_not_sign_is_refused(self):
        blocks = _blocks_from(self.store, 2, 2)
        start = chain.TrustedHead(1, blocks[0].anchors.prev_block, blocks[0].anchors.state_root, 0)
        stranger = crypto.Keypair.generate().public
        self.assertIs(
            chain.advance(start.block_hash, blocks, (stranger,), stranger),
            chain.ChainRefusal.UNAUTHORISED,
        )


class TestOneRosterPerWalk(unittest.TestCase):
    """`advance` takes ONE roster, so a caller must not span a roster change with it. Block 1 is
    manager-signed against an empty roster -- the manager occupies slot `len(roster)`, so the same
    bytes verified against a 3-member roster look for the signature in slot 3 and find nothing.

    Neither path actually does this: a node walks one block at a time and re-reads the roster
    after each commit, and a light client re-bootstraps on a moved fingerprint before it walks."""

    def test_block_one_does_not_verify_against_the_roster_it_created(self):
        c = Cluster()
        producer = c.nodes[0].store
        walked = chain.advance(
            chain.TrustedHead.genesis(c.mgr.public).block_hash,
            _blocks_from(producer, 1, 1),
            MgmtReader(producer).roster(),  # the roster block 1 established, not the one before it
            c.mgr.public,
        )
        self.assertIs(walked, chain.ChainRefusal.UNAUTHORISED)


class TestBothPathsReachTheSameHead(unittest.TestCase):
    """THE POINT. A node walks blocks-with-bodies pulled by GETBLOCK; a light client walks
    headers piggybacked on a read. Both start where they really start -- the node from the
    bootstrap block it was provisioned with, the light client from a corroborated head -- and
    both must land in the same place. If the two implementations diverge again, this fails
    instead of becoming a bug found months later in whichever one nobody was looking at."""

    def test_node_replay_and_header_walk_agree(self):
        c = Cluster()
        _run_cluster_producing_n_blocks(c, 3)
        producer = c.nodes[0].store
        target = producer.head_block_num()
        assert target is not None and target >= 3

        block_one = _blocks_from(producer, 1, 1)[0]
        start = chain.TrustedHead(
            1, block_one.block_hash, block_one.anchors.state_root, block_one.block.bucket
        )
        roster = MgmtReader(producer).roster()

        # Light-client shape: one call over the whole range of headers.
        walked = chain.advance(
            start.block_hash, _blocks_from(producer, 2, target), roster, c.mgr.public
        )
        assert not isinstance(walked, chain.ChainRefusal), walked

        # Node shape: pull each block with its bodies, verify, commit, one at a time.
        follower = _make_follower(c.provisioned())
        peer = c.keys[0].public
        follower.add_peer(peer, now=T0)
        reply = serve_getblocks(producer, GetBlocks(frm=2, count=target - 1), cap=64)
        assert isinstance(reply, SettledBlockReply), reply
        follower._pulling = PullInFlight(peer, 2, target - 1, T0)
        follower.receive(reply, peer, T0)

        self.assertEqual(follower.store.head_block_num(), target, "the node stopped short")
        node_head = chain.TrustedHead(
            follower.store.head_block_num() or 0,
            follower._tip(),
            follower.store.state_root(),
            follower._head_bucket(),
        )
        self.assertEqual(node_head, walked, "the two paths disagree about where the chain ends")
