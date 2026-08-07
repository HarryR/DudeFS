"""Tests for dude.sync.follower -- the L6 catch-up state machine, direct-wired.

SAME HARNESS SHAPE AS test_round.py. No net stack, no envelopes, no seals. `_pump` drains the
follower's outbox, calls `serve_*` against a producer store to build the reply, and hands it
back to `follower.receive`. Everything is deterministic in `(now, inputs)`.

TWO CATCH-UP SCENARIOS:
  * LAGGING: joiner has the same block 1 as the cluster (via `bootstrap`), missed blocks 2..N.
  * FRESH: joiner has only `store.provision(manager)` and pulls block 1 via GETBLOCK first.
Both use the same Follower with no branching -- the "same trigger for every failure mode"
property from #height-poll-is-the-trigger.
"""

from __future__ import annotations

import unittest

from dude.consensus.settle_round import Anchors, SettledBlock, SettledBlockWithBodies
from dude.core import crypto
from dude.store import Store, ops
from dude.store.management import MgmtReader
from dude.sync.adapter import (
    GetBlock,
    HeightAsk,
    HeightReply,
    Refused,
    SettledBlockReply,
    SyncRefusal,
)
from dude.sync.follower import Follower, HeightReport, serve_getblock, serve_height
from dude.tunables import DEFAULT

from .cluster import DELTA, T0, Cluster, D

POLL = DEFAULT.sync.poll_interval
PULL_TIMEOUT = DEFAULT.sync.pull_timeout


# --------------------------------------------------------------------------------------------- #
# Harness                                                                                       #
# --------------------------------------------------------------------------------------------- #


def _make_follower(store: Store) -> Follower:
    """Follower over an existing store, no peers added yet."""
    return Follower(
        me=crypto.Keypair.generate(),
        store=store,
        mgmt=MgmtReader(store),
        tunables=DEFAULT.sync,
    )


def _pump(
    follower: Follower,
    producer: Store,
    producer_key: crypto.PublicKey,
    now: int,
) -> None:
    """One pump: tick the follower, then translate every outbox message into a reply from
    `producer` (if the message is a HeightAsk/GetBlock addressed at `producer_key`) and deliver
    it back. Mirrors what Node's dispatcher will do end-to-end, but in-process."""
    follower.tick(now)
    for peer, msg in follower.outbox():
        if peer != producer_key:
            continue  # message directed at a peer that isn't our producer stub
        if isinstance(msg, HeightAsk):
            follower.receive(serve_height(producer), producer_key, now)
        elif isinstance(msg, GetBlock):
            follower.receive(serve_getblock(producer, msg), producer_key, now)


def _catch_up(
    follower: Follower,
    producer: Store,
    producer_key: crypto.PublicKey,
    start: int = T0,
    max_pumps: int = 40,
) -> int:
    """Pump until the follower's head_block_num matches the producer's. Returns the final
    `now`. Raises AssertionError if it doesn't converge inside `max_pumps`."""
    now = start
    producer_head = producer.head_block_num() or 0
    for _ in range(max_pumps):
        _pump(follower, producer, producer_key, now)
        if (follower.store.head_block_num() or 0) >= producer_head:
            return now
        now += POLL
    raise AssertionError(
        f"follower did not catch up: my={follower.store.head_block_num()} producer={producer_head}"
    )


def _run_cluster_producing_n_blocks(c: Cluster, n: int) -> None:
    """Submit txs and pump the cluster until block_num >= n on every node."""
    now = T0
    submissions = 0
    while True:
        if all((node.store.head_block_num() or 0) >= n for node in c.nodes):
            return
        # One tx per bucket, submitted to node 0.
        tx = ops.writes(ops.Set(D, crypto.h(f"tx-{submissions}".encode()), b"v")).sign(c.mgr, now)
        c.submit(c.mgr, tx, to=0, now=now)
        c.pump(now)
        submissions += 1
        now += DELTA
        if submissions > 20:
            raise AssertionError(
                f"cluster failed to produce {n} blocks after {submissions} submissions"
            )


# --------------------------------------------------------------------------------------------- #
# Scenario A: LAGGING node catches up.                                                          #
#                                                                                                #
# Joiner has block 1 (bootstrap same as producer), missed blocks 2..N. Pulls each in order.     #
# --------------------------------------------------------------------------------------------- #


class TestLaggingNodeCatchesUp(unittest.TestCase):
    """The primary L6 use case: node crashed / rebooted / was unavailable, needs to catch up."""

    def setUp(self):
        self.c = Cluster()
        _run_cluster_producing_n_blocks(self.c, 3)
        # Joiner: fresh store, bootstrap same block 1 as the cluster. Now at block_num == 1,
        # missing blocks 2 and 3.
        self.joiner_store = self.c.provisioned()
        self.follower = _make_follower(self.joiner_store)
        self.producer = self.c.nodes[0]
        self.follower.add_peer(self.producer.me.public, now=T0)

    def test_joiner_catches_up_to_producer_head(self):
        _catch_up(self.follower, self.producer.store, self.producer.me.public)
        self.assertEqual(
            self.joiner_store.head_block_num(),
            self.producer.store.head_block_num(),
        )

    def test_chain_verifies_end_to_end(self):
        """After catch-up, the joiner's chain hashes each equal the producer's -- so a joiner
        that goes on to serve blocks would return byte-identical (identity portion) data."""
        _catch_up(self.follower, self.producer.store, self.producer.me.public)
        head = self.producer.store.head_block_num()
        assert head is not None
        for n in range(1, head + 1):
            joiner_bytes = self.joiner_store.settled_at(n)
            producer_bytes = self.producer.store.settled_at(n)
            assert joiner_bytes is not None and producer_bytes is not None
            # Block identity hash MUST match (sig-independent; wire bytes may differ per node
            # in quorum-authorized blocks per #block-shape-settled).
            self.assertEqual(
                SettledBlock.decode(joiner_bytes).block_hash,
                SettledBlock.decode(producer_bytes).block_hash,
                f"chain diverged at block_num={n}",
            )

    def test_state_matches_producer_after_catch_up(self):
        """The whole point: joiner's application state ends up equal to producer's."""
        _catch_up(self.follower, self.producer.store, self.producer.me.public)
        self.assertEqual(self.joiner_store.state_root(), self.producer.store.state_root())
        self.assertEqual(self.joiner_store.accumulator(), self.producer.store.accumulator())
        self.assertEqual(self.joiner_store.log_accumulator(), self.producer.store.log_accumulator())


# --------------------------------------------------------------------------------------------- #
# Scenario B: FRESH joiner starts from the manager pubkey alone.                                #
#                                                                                                #
# Joiner has NOT bootstrapped. Follower pulls block 1 via GETBLOCK, then continues.             #
# --------------------------------------------------------------------------------------------- #


class TestFreshJoinerFromAnchor(unittest.TestCase):
    """SPECv2 #joiner-starts-from-anchor: a fresh node with only the manager pubkey syncs
    from block 1 via the same pull loop -- no separate 'join' flow."""

    def setUp(self):
        self.c = Cluster()
        _run_cluster_producing_n_blocks(self.c, 3)
        # Fresh joiner: provision the manager anchor, then NOTHING ELSE. No bootstrap.
        self.joiner_store = Store()
        self.joiner_store.provision(self.c.mgr.public)
        self.follower = _make_follower(self.joiner_store)
        self.producer = self.c.nodes[0]
        self.follower.add_peer(self.producer.me.public, now=T0)

    def test_fresh_joiner_pulls_block_1_via_manager_sig(self):
        """The load-bearing property: block 1 is manager-signed, joiner has no roster to
        verify against, but `MgmtReader.authorises` accepts the manager-slot sig."""
        _catch_up(self.follower, self.producer.store, self.producer.me.public)
        self.assertEqual(
            self.joiner_store.head_block_num(),
            self.producer.store.head_block_num(),
        )
        self.assertGreaterEqual(self.joiner_store.head_block_num() or 0, 3)

    def test_fresh_joiner_ends_up_with_correct_roster(self):
        """After block 1 applies, the joiner's roster reflects the cluster's roster.
        Subsequent blocks then verify via quorum-of-that-roster."""
        _catch_up(self.follower, self.producer.store, self.producer.me.public)
        joiner_roster = self.joiner_store.mgmt.roster()
        producer_roster = self.producer.store.mgmt.roster()
        self.assertEqual(set(joiner_roster), set(producer_roster))


# --------------------------------------------------------------------------------------------- #
# Byzantine peer: lies about height, serves garbage, omits bodies.                              #
# --------------------------------------------------------------------------------------------- #


class TestByzantinePeerIsHandled(unittest.TestCase):
    """A peer serving bad data must cost its message and nothing more -- and the Follower
    must not touch Store on any failed verification path."""

    def setUp(self):
        self.c = Cluster()
        _run_cluster_producing_n_blocks(self.c, 2)
        self.joiner_store = self.c.provisioned()
        self.follower = _make_follower(self.joiner_store)
        self.honest = self.c.nodes[0]
        self.byz = crypto.Keypair.generate()  # not on the cluster; just a fake pubkey

    def test_lied_higher_height_wastes_one_getblock_then_pull_clears(self):
        """Byzantine peer says head=999, we ask GetBlock(2), they refuse -- pull clears, state
        unchanged. Per #no-shun-only-priority, byz is NOT blacklisted: they remain a valid
        pull candidate and would be tried again if they were the only source above us. The
        cost of the lie is one round-trip, not permanent exclusion."""
        self.follower.add_peer(self.byz.public, now=T0)
        self.follower.tick(T0)
        # First outbox drain: a HeightAsk to byz. Serve a lying reply.
        drained = self.follower.outbox()
        self.assertEqual(len(drained), 1)
        self.follower.receive(
            HeightReply(block_num=999, tip_hash=crypto.h(b"pretend")),
            self.byz.public,
            T0,
        )
        # Next tick: follower sees byz is above us, sends GetBlock(2) to byz.
        now = T0 + POLL
        self.follower.tick(now)
        drained = self.follower.outbox()
        self.assertTrue(any(isinstance(m, GetBlock) for _, m in drained))
        # Byz has no such block -- respond with Refused.
        self.follower.receive(
            Refused(reason=SyncRefusal.NOT_YET_SETTLED),
            self.byz.public,
            now,
        )
        # Pull cleared, state unchanged. Byz remains an eligible candidate -- picking again
        # next tick returns byz because they're the only peer above us.
        self.assertIsNone(self.follower._pulling)
        self.assertEqual(self.joiner_store.head_block_num(), 1)
        # Prove no exclusion: byz is still the pick.
        self.assertEqual(self.follower._pick_pull_source(), self.byz.public)

    def test_bad_settle_sig_dropped(self):
        """A peer serves a block whose settle_sigs don't verify. Follower drops without touching
        Store."""
        self.follower.add_peer(self.byz.public, now=T0)
        self.follower.tick(T0)
        self.follower.outbox()  # drain the HeightAsk
        # Say we're one block ahead of us
        self.follower.receive(
            HeightReply(block_num=2, tip_hash=crypto.h(b"bogus-tip")),
            self.byz.public,
            T0,
        )
        # Follower asks for GetBlock(2). Craft a garbage block: real shape but a sig that
        # verifies against nobody. We can build one from the honest producer's block 2 with
        # the settle_sigs replaced.
        now = T0 + POLL
        self.follower.tick(now)
        self.follower.outbox()  # drain the GetBlock
        real_bytes = self.honest.store.settled_at(2)
        assert real_bytes is not None
        real_sb = SettledBlock.decode(real_bytes)
        # Substitute the sigs with garbage. Verification should fail.
        bad_sb = SettledBlock(
            block=real_sb.block,
            anchors=real_sb.anchors,
            multisig=crypto.MultiSig(
                real_sb.multisig.bitmap,
                tuple(crypto.Signature(bytes(64)) for _ in real_sb.multisig.sigs),
            ),
        )
        bad_bodies = self.honest.store.bodies_of_block(2)
        self.follower.receive(
            SettledBlockReply(payload=SettledBlockWithBodies(block=bad_sb, bodies=bad_bodies)),
            self.byz.public,
            now,
        )
        # Pull cleared, state unchanged. Byz stays eligible (#no-shun-only-priority) --
        # verification failure does not shun.
        self.assertIsNone(self.follower._pulling)
        self.assertEqual(self.joiner_store.head_block_num(), 1)

    def test_bad_chain_link_clears_pull_no_shun(self):
        """A peer serves a block whose prev_block doesn't chain back to our head. Pull
        clears; peer stays eligible per #no-shun-only-priority."""
        self.follower.add_peer(self.byz.public, now=T0)
        self.follower.tick(T0)
        self.follower.outbox()
        self.follower.receive(
            HeightReply(block_num=2, tip_hash=crypto.h(b"any")),
            self.byz.public,
            T0,
        )
        now = T0 + POLL
        self.follower.tick(now)
        self.follower.outbox()
        # Real block 2 but rewrite prev_block. Anchors change → settle_sigs won't verify either
        # (they signed the original anchors), but chain-link check fires first.
        real_bytes = self.honest.store.settled_at(2)
        assert real_bytes is not None
        real_sb = SettledBlock.decode(real_bytes)
        bad_anchors = Anchors(
            block_num=real_sb.anchors.block_num,
            height=real_sb.anchors.height,
            prev_block=crypto.h(b"wrong-parent"),
            state_root=real_sb.anchors.state_root,
            acc_state=real_sb.anchors.acc_state,
            acc_log=real_sb.anchors.acc_log,
        )
        bad_sb = SettledBlock(
            block=real_sb.block,
            anchors=bad_anchors,
            multisig=real_sb.multisig,
        )
        bad_bodies = self.honest.store.bodies_of_block(2)
        self.follower.receive(
            SettledBlockReply(payload=SettledBlockWithBodies(block=bad_sb, bodies=bad_bodies)),
            self.byz.public,
            now,
        )
        self.assertIsNone(self.follower._pulling)
        self.assertEqual(self.joiner_store.head_block_num(), 1)

    def test_omitted_bodies_clear_pull_via_preview_mismatch(self):
        """A peer serves a real block but omits some of the applied bodies. Preview computes
        different anchors → mismatch → pull clears (no state touched). Peer stays eligible
        per #no-shun-only-priority.

        SETUP: fresh joiner at block 1; byz is the only peer. Byz claims height N and serves
        block N with the last body omitted. Preview against the truncated body set yields
        different anchors than what block N's sigs cover -> mismatch -> clear pull.
        """
        # Ensure block 2 has multiple bodies to have something to omit.
        for i in range(3):
            tx = ops.writes(ops.Set(D, crypto.h(f"multi-{i}".encode()), b"v")).sign(self.c.mgr, T0)
            self.c.submit(self.c.mgr, tx, to=0, now=T0)
        self.c.pump(T0)
        self.c.pump(T0 + DELTA)
        self.c.pump(T0 + 2 * DELTA)
        # Find a block with 2+ bodies (the multi-tx block).
        target_num = None
        head = self.honest.store.head_block_num()
        assert head is not None
        for n in range(2, head + 1):
            if len(self.honest.store.bodies_of_block(n)) >= 2:
                target_num = n
                break
        assert target_num is not None, "cluster did not produce a multi-body block"

        # Fresh joiner, byz is the ONLY peer. We hand-craft the state manually.
        fresh_joiner = self.c.provisioned()
        follower = _make_follower(fresh_joiner)
        follower.add_peer(self.byz.public, now=T0)

        # Byz reports target_num as its head.
        follower.receive(
            HeightReply(block_num=target_num, tip_hash=crypto.h(b"any")),
            self.byz.public,
            T0,
        )
        # Bring joiner up to target_num - 1 using honest's real blocks, applied directly to
        # the joiner's store (bypassing the follower's own pull loop for setup). This is a
        # test convenience: we're setting up a specific "joiner at N-1, byz claims N with bad
        # bodies" scenario without needing another honest peer in the follower's polling loop.
        # Real integration is covered by other tests.
        for n in range(2, target_num):
            real_bytes = self.honest.store.settled_at(n)
            assert real_bytes is not None
            real_bodies = self.honest.store.bodies_of_block(n)
            real_sb = SettledBlock.decode(real_bytes)
            first_height = fresh_joiner.head() + 1
            fresh_joiner.commit_block(
                real_sb.anchors.block_num,
                first_height=first_height,
                block_bytes=real_bytes,
                block_hash=real_sb.block_hash,
                batch=real_bodies,
                auth=MgmtReader(fresh_joiner),
            )

        # Follower ticks: sees byz above (target_num > our target_num - 1), issues GetBlock.
        follower.tick(T0 + POLL)
        outbox = follower.outbox()
        assert any(isinstance(m, GetBlock) for _, m in outbox), f"expected GetBlock, got {outbox}"
        # Craft the bad block: real block target_num but with the last body omitted.
        real_bytes = self.honest.store.settled_at(target_num)
        assert real_bytes is not None
        real_sb = SettledBlock.decode(real_bytes)
        real_bodies = self.honest.store.bodies_of_block(target_num)
        truncated = real_bodies[:-1]
        follower.receive(
            SettledBlockReply(payload=SettledBlockWithBodies(block=real_sb, bodies=truncated)),
            self.byz.public,
            T0 + POLL,
        )
        # Pull cleared, joiner head still at target_num - 1. Byz stays a candidate.
        self.assertIsNone(follower._pulling)
        self.assertEqual(fresh_joiner.head_block_num(), target_num - 1)


# --------------------------------------------------------------------------------------------- #
# Fork detection at poll time.                                                                  #
# --------------------------------------------------------------------------------------------- #


class TestForkDetectionAtPollTime(unittest.TestCase):
    """SPECv2 #poll-detects-divergent-tips: a peer reporting same block_num but different
    tip_hash than ours is on a different chain. Per #no-shun-only-priority + the updated
    #poll-detects-divergent-tips, this is an observability signal, NOT an exclusion decision
    -- WE may be the wrong side of the fork, so locking in "they're bad" is a permanent
    misconfiguration hazard. Sync stays safe regardless: a peer on the wrong chain serves
    blocks that fail chain-link check on our side."""

    def test_same_num_different_tip_is_observability_only(self):
        c = Cluster()
        _run_cluster_producing_n_blocks(c, 2)
        joiner_store = c.provisioned()
        # Catch up joiner via honest first, so it has a definite head/tip.
        honest = c.nodes[0]
        follower = _make_follower(joiner_store)
        follower.add_peer(honest.me.public, now=T0)
        _catch_up(follower, honest.store, honest.me.public)

        my_num = joiner_store.head_block_num()
        assert my_num is not None
        byz = crypto.Keypair.generate()
        follower.receive(
            HeightReply(block_num=my_num, tip_hash=crypto.h(b"different-chain")),
            byz.public,
            T0,
        )
        # Fork observed: HeightReport recorded. No exclusion, no blacklist -- byz stays a
        # regular peer. Only reason byz isn't picked as a pull source right now is that it
        # reports the same block_num as our head (not strictly ABOVE), not because we're
        # shunning it.
        self.assertIn(byz.public, follower._heads)
        # State untouched.
        self.assertEqual(joiner_store.head_block_num(), my_num)


# --------------------------------------------------------------------------------------------- #
# f+1 fresh witnesses for `caught_up()`.                                                        #
# --------------------------------------------------------------------------------------------- #


class TestCaughtUpRequiresFreshWitnesses(unittest.TestCase):
    """SPECv2 #height-poll-is-the-trigger, #freshness-needs-many: declaring caught-up MUST
    rest on f+1 fresh peers agreeing on `(my_block_num, my_tip_hash)`. A single peer's
    silence or agreement is not enough."""

    def test_caught_up_false_with_no_reports(self):
        """No peers heard from yet -- not caught up regardless of local state."""
        c = Cluster()
        _run_cluster_producing_n_blocks(c, 1)  # just the bootstrap block 1
        joiner_store = c.provisioned()
        follower = _make_follower(joiner_store)
        self.assertFalse(follower.caught_up())

    def test_caught_up_with_quorum_of_matching_reports(self):
        """Fresh HEIGHT_REPLYs from f+1 roster peers all agreeing with our tip → caught_up."""
        c = Cluster()
        _run_cluster_producing_n_blocks(c, 1)
        joiner_store = c.provisioned()
        follower = _make_follower(joiner_store)
        my_num = joiner_store.head_block_num() or 0
        my_tip = joiner_store.head_block_hash()
        assert my_tip is not None
        # corroboration(3) = tolerates(3) + 1 = 0 + 1 = 1. One matching report suffices, but
        # deliver two -- higher-than-threshold is still a valid "caught up" state.
        for node in c.nodes[:2]:
            follower.receive(
                HeightReply(block_num=my_num, tip_hash=my_tip),
                node.me.public,
                T0,
            )
        self.assertTrue(follower.caught_up())

    def test_caught_up_false_when_reports_are_stale(self):
        """Reports older than freshness_window don't count."""
        c = Cluster()
        _run_cluster_producing_n_blocks(c, 1)
        joiner_store = c.provisioned()
        follower = _make_follower(joiner_store)
        my_num = joiner_store.head_block_num() or 0
        my_tip = joiner_store.head_block_hash()
        assert my_tip is not None
        # Deliver two reports at T0; freshness_window is fixed; the "latest now" advances
        # past freshness_window by receiving a THIRD (stale-counter) report far in the future.
        for node in c.nodes[:2]:
            follower.receive(
                HeightReply(block_num=my_num, tip_hash=my_tip),
                node.me.public,
                T0,
            )
        # Third report from an out-of-roster peer far in the future: this advances _last_now(),
        # making the first two reports stale.
        far_future = T0 + DEFAULT.sync.freshness_window * 2 + 1
        stranger = crypto.Keypair.generate()
        follower.receive(
            HeightReply(block_num=my_num, tip_hash=my_tip),
            stranger.public,
            far_future,
        )
        # Now `_last_now()` is far_future; the two roster reports at T0 are stale.
        self.assertFalse(follower.caught_up())


# --------------------------------------------------------------------------------------------- #
# Pull timeout.                                                                                 #
# --------------------------------------------------------------------------------------------- #


class TestPullTimeout(unittest.TestCase):
    """A peer that answers HEIGHT but never SETTLED_BLOCK/REFUSED has its in-flight pull
    cleared at `pull_timeout` so the joiner can try another source. Per
    #no-shun-only-priority, the silent peer is NOT excluded from future picks -- if it stays
    the highest-reporting peer, it gets picked again."""

    def test_silent_peer_pull_clears_after_timeout(self):
        c = Cluster()
        _run_cluster_producing_n_blocks(c, 2)
        joiner_store = c.provisioned()
        follower = _make_follower(joiner_store)
        silent = crypto.Keypair.generate()
        follower.add_peer(silent.public, now=T0)
        # Silent peer answers HeightAsk (says they're ahead of us) but never replies to GetBlock.
        follower.tick(T0)
        follower.outbox()  # drain HeightAsk
        follower.receive(
            HeightReply(block_num=2, tip_hash=crypto.h(b"any")),
            silent.public,
            T0,
        )
        # Tick advances past pull_timeout without a reply.
        follower.tick(T0 + POLL)
        # A GetBlock went out; drain it.
        follower.outbox()
        # Now advance beyond pull_timeout. Tick clears the stale pull AND (in the same tick)
        # the picker immediately re-picks silent because they're the only source above us --
        # that IS the "no shun" behavior: we retry against the same peer rather than exclude.
        follower.tick(T0 + POLL + PULL_TIMEOUT + 1)
        assert follower._pulling is not None, "expected a fresh pull to the still-eligible peer"
        self.assertEqual(follower._pulling.peer, silent.public)
        # sent_at is the new tick, not the old one -- proves it's a fresh pull, not the stale one.
        self.assertEqual(follower._pulling.sent_at, T0 + POLL + PULL_TIMEOUT + 1)


# --------------------------------------------------------------------------------------------- #
# Priority-based pull picking (#no-shun-only-priority).                                         #
# --------------------------------------------------------------------------------------------- #


class TestPickPullSourcePriority(unittest.TestCase):
    """`_pick_pull_source` prefers peers with a more recent successful reply (`_last_ok_at`),
    falls back to reported head height, and NEVER excludes any peer above our head. Every
    peer that reports a head above ours is a candidate every time."""

    def test_recent_success_wins_over_older_success(self):
        """Two peers above our head, one answered a poll more recently -- it gets picked."""
        c = Cluster()
        _run_cluster_producing_n_blocks(c, 2)
        joiner_store = c.provisioned()
        follower = _make_follower(joiner_store)
        older = crypto.Keypair.generate()
        newer = crypto.Keypair.generate()
        follower.add_peer(older.public, now=T0)
        follower.add_peer(newer.public, now=T0)

        # Both report the same head; older's HeightReply arrives at T0, newer's at T0 + 1.
        follower.receive(HeightReply(block_num=2, tip_hash=crypto.h(b"tip")), older.public, T0)
        follower.receive(HeightReply(block_num=2, tip_hash=crypto.h(b"tip")), newer.public, T0 + 1)

        # Priority: newer's _last_ok_at is more recent, so newer is picked.
        self.assertEqual(follower._pick_pull_source(), newer.public)

    def test_no_success_history_still_picked_when_only_candidate(self):
        """A peer with NO `_last_ok_at` entry -- never verified anything -- is still picked
        when nobody higher-priority exists. The default of 0 means 'pick last', not
        'exclude'."""
        c = Cluster()
        _run_cluster_producing_n_blocks(c, 2)
        joiner_store = c.provisioned()
        follower = _make_follower(joiner_store)
        rando = crypto.Keypair.generate()
        follower.add_peer(rando.public, now=T0)

        # Directly inject a HeightReport WITHOUT the _last_ok_at update path -- simulates a
        # scenario where we know about a peer via some other channel but never got a valid
        # reply from them. (In practice this is not how HeightReport arrives, but the picker
        # must tolerate the state.)
        follower._heads[rando.public] = HeightReport(block_num=2, tip_hash=crypto.h(b"tip"), at=T0)

        # Rando has no _last_ok_at, but is the only peer above -- picked anyway.
        self.assertEqual(follower._pick_pull_source(), rando.public)

    def test_higher_head_wins_ties_on_recency(self):
        """Two peers with equal `_last_ok_at`, different reported heights -- higher head
        wins."""
        c = Cluster()
        _run_cluster_producing_n_blocks(c, 2)
        joiner_store = c.provisioned()
        follower = _make_follower(joiner_store)
        lower = crypto.Keypair.generate()
        higher = crypto.Keypair.generate()
        follower.add_peer(lower.public, now=T0)
        follower.add_peer(higher.public, now=T0)

        # Both HeightReplys at the same `now` -- same _last_ok_at.
        follower.receive(HeightReply(block_num=2, tip_hash=crypto.h(b"a")), lower.public, T0)
        follower.receive(HeightReply(block_num=5, tip_hash=crypto.h(b"b")), higher.public, T0)

        self.assertEqual(follower._pick_pull_source(), higher.public)

    def test_failed_peer_stays_eligible_when_alone(self):
        """A peer whose pull failed (bad block) has `_pulling` cleared but is NOT excluded.
        When they're the only source above us, next tick picks them again."""
        c = Cluster()
        _run_cluster_producing_n_blocks(c, 2)
        joiner_store = c.provisioned()
        follower = _make_follower(joiner_store)
        honest = c.nodes[0]
        follower.add_peer(honest.me.public, now=T0)

        # Honest is above us; picker picks honest.
        follower.receive(
            HeightReply(block_num=2, tip_hash=crypto.h(b"any")),
            honest.me.public,
            T0,
        )
        self.assertEqual(follower._pick_pull_source(), honest.me.public)

        # Simulate a bad reply: cancel the (hypothetical) pull. Peer stays picked-eligible.
        follower._pulling = None  # what a verification failure would leave us at
        # Picker returns the same peer -- no exclusion happened.
        self.assertEqual(follower._pick_pull_source(), honest.me.public)


if __name__ == "__main__":
    unittest.main()
