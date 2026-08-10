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
from dataclasses import replace

from dude.consensus.round import Block
from dude.consensus.settle_round import (
    Anchors,
    SettledBlock,
    SettledBlockWithBodies,
    _settle_payload,
)
from dude.core import crypto
from dude.node import Node
from dude.store import Store
from dude.store.management import MgmtReader
from dude.sync.adapter import (
    GetBlocks,
    HeightAsk,
    HeightReply,
    Refused,
    SettledBlockReply,
    SyncRefusal,
)
from dude.sync.follower import Follower, HeightReport, serve_getblocks, serve_height
from dude.tunables import DEFAULT, SyncTunables, Tunables

from .cluster import DELTA, T0, TUNABLES, Cluster

POLL = DEFAULT.sync.poll_interval
PULL_TIMEOUT = DEFAULT.sync.pull_timeout


# --------------------------------------------------------------------------------------------- #
# Harness                                                                                       #
# --------------------------------------------------------------------------------------------- #


def _make_follower(store: Store, tunables: Tunables = TUNABLES) -> Follower:
    """Follower over an existing store, no peers added yet. TUNABLES, not DEFAULT: freshness is
    bucket arithmetic, so a follower reading a fast-profile store under the production block time
    computes head buckets on a different scale entirely and never finds anything stale."""
    return Follower(
        me=crypto.Keypair.generate(),
        store=store,
        mgmt=MgmtReader(store),
        tunables=tunables,
    )


def _pump(
    follower: Follower,
    producer: Store,
    producer_key: crypto.PublicKey,
    now: int,
) -> None:
    """One pump: tick the follower, then translate every outbox message into a reply from
    `producer` (if the message is a HeightAsk/GetBlocks addressed at `producer_key`) and deliver
    it back. Mirrors what Node's dispatcher will do end-to-end, but in-process."""
    follower.tick(now)
    for peer, msg in follower.outbox():
        if peer != producer_key:
            continue  # message directed at a peer that isn't our producer stub
        if isinstance(msg, HeightAsk):
            follower.receive(serve_height(producer), producer_key, now)
        elif isinstance(msg, GetBlocks):
            follower.receive(
                serve_getblocks(producer, msg, DEFAULT.sync.pull_batch), producer_key, now
            )


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
        c.put(f"tx-{submissions}", b"v", now=now)
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
        verify against, but the quorum-proof rule accepts the manager-slot sig."""
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


class TestAFollowerBehindConverges(unittest.TestCase):
    """A node that falls behind must CLOSE the gap, not widen it.

    `_pick_pull_source` gated every pull on a `_heads` entry that refreshes once per
    `poll_interval`, so after each block the follower believed itself level and idled. Measured
    against a live cluster it gained ~0.8 blocks per bucket against 1.0 produced: the gap grew
    without bound and a node that fell behind never recovered."""

    def test_the_gap_closes_rather_than_grows(self):
        c = Cluster()
        now = c.pump(T0, rounds=3)
        now = c.pump_without(now, away={2}, rounds=6)

        def gap() -> int:
            return (c.nodes[0].store.head_block_num() or 0) - (
                c.nodes[2].store.head_block_num() or 0
            )

        behind = gap()
        self.assertGreater(behind, 1, "the outage did not put node 2 meaningfully behind")

        now = c.pump(now, rounds=10)
        self.assertLess(gap(), behind, f"the gap grew: {behind} -> {gap()}")
        self.assertLessEqual(gap(), 2, f"still {gap()} blocks behind after 10 buckets")


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
        """Byzantine peer says head=999, we ask GetBlocks from 2, they refuse -- pull clears, state
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
        # Next tick: follower sees byz is above us, sends GetBlocks from 2 to byz.
        now = T0 + POLL
        self.follower.tick(now)
        drained = self.follower.outbox()
        self.assertTrue(any(isinstance(m, GetBlocks) for _, m in drained))
        # Byz has no such block -- respond with Refused.
        self.follower.receive(
            Refused(reason=SyncRefusal.NOT_YET_SETTLED),
            self.byz.public,
            now,
        )
        # Pull cleared, state unchanged, and their claim corrected DOWN to what they actually
        # demonstrated -- so they are not picked again on the strength of the lie they just told.
        self.assertIsNone(self.follower._pulling)
        self.assertEqual(self.joiner_store.head_block_num(), 1)
        self.assertIsNone(self.follower._pick_pull_source())
        # NOT a blacklist (#no-shun-only-priority): the moment they claim height again they are
        # a candidate again, and the lie costs one more round trip. Correcting the claim bounds
        # the cost at one round trip PER LIE; leaving it standing let one lie cost every tick.
        self.follower.receive(
            HeightReply(block_num=999, tip_hash=crypto.h(b"pretend")), self.byz.public, now
        )
        self.assertEqual(self.follower._pick_pull_source(), self.byz.public)

    def test_a_refusal_costs_a_round_trip_not_a_tick(self):
        """The reason used to be discarded and the pull simply cleared, so the next source was
        tried a whole tick later. With two peers claiming height, the refusal from one must put
        a GetBlocks on the wire to the other before `tick` is called again."""
        other = crypto.Keypair.generate()
        for peer in (self.byz.public, other.public):
            self.follower.add_peer(peer, now=T0)
        self.follower.tick(T0)
        self.follower.outbox()
        for peer in (self.byz.public, other.public):
            self.follower.receive(
                HeightReply(block_num=999, tip_hash=crypto.h(b"pretend")), peer, T0
            )
        now = T0 + POLL
        self.follower.tick(now)
        self.follower.outbox()
        asked = self.follower._pulling
        assert asked is not None, "no pull was in flight to refuse"

        self.follower.receive(Refused(reason=SyncRefusal.NOT_YET_SETTLED), asked.peer, now)

        retried = self.follower._pulling
        assert retried is not None, "the refusal did not start another pull"
        self.assertNotEqual(retried.peer, asked.peer, "retried the peer that just refused")
        self.assertTrue(
            any(isinstance(m, GetBlocks) and to == retried.peer for to, m in self.follower.outbox())
        )

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
        # Follower asks for blocks from 2. Craft a garbage block: real shape but a sig that
        # verifies against nobody. We can build one from the honest producer's block 2 with
        # the settle_sigs replaced.
        now = T0 + POLL
        self.follower.tick(now)
        self.follower.outbox()  # drain the GetBlocks
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
            SettledBlockReply(payload=(SettledBlockWithBodies(block=bad_sb, bodies=bad_bodies),)),
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
            SettledBlockReply(payload=(SettledBlockWithBodies(block=bad_sb, bodies=bad_bodies),)),
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
            self.c.put(f"multi-{i}", b"v", now=T0)
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

        # Follower ticks: sees byz above (target_num > our target_num - 1), issues GetBlocks.
        follower.tick(T0 + POLL)
        outbox = follower.outbox()
        assert any(isinstance(m, GetBlocks) for _, m in outbox), f"expected GetBlocks, got {outbox}"
        # Craft the bad block: real block target_num but with the last body omitted.
        real_bytes = self.honest.store.settled_at(target_num)
        assert real_bytes is not None
        real_sb = SettledBlock.decode(real_bytes)
        real_bodies = self.honest.store.bodies_of_block(target_num)
        truncated = real_bodies[:-1]
        follower.receive(
            SettledBlockReply(payload=(SettledBlockWithBodies(block=real_sb, bodies=truncated),)),
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
# f+1 fresh witnesses for `behind()`, and the Round it gates.                                    #
# --------------------------------------------------------------------------------------------- #


class TestBehindRequiresFreshWitnessesAboveUs(unittest.TestCase):
    """`behind` gates whether a node leads a bucket, so EVERY way of knowing nothing must answer
    False. Read the other way -- `f+1` witnesses agreeing with our tip -- it looks equivalent and
    fails the opposite way, and a cluster whose reports age out between buckets stops producing."""

    def _joiner(self, tunables: Tunables = TUNABLES) -> tuple[Cluster, Follower]:
        c = Cluster()
        _run_cluster_producing_n_blocks(c, 1)  # just the bootstrap block 1
        return c, _make_follower(c.provisioned(), tunables)

    def _report(self, c: Cluster, f: Follower, now: int, at: int, count: int = 2) -> None:
        for node in c.nodes[:count]:
            f.receive(HeightReply(block_num=at, tip_hash=crypto.h(b"theirs")), node.me.public, now)

    def test_no_reports_is_not_behind(self):
        """Knowing nothing is not evidence of being behind. Answering True here is how the gate
        stops a cluster that has simply not polled yet."""
        _, follower = self._joiner()
        self.assertFalse(follower.behind(T0))

    def test_an_empty_roster_is_not_behind(self):
        c = Cluster()
        _run_cluster_producing_n_blocks(c, 1)
        fresh = Store()
        fresh.provision(c.mgr.public)  # provisioned, not bootstrapped: no roster yet
        self.assertFalse(_make_follower(fresh).behind(T0))

    def test_f_plus_one_fresh_witnesses_above_us_is_behind(self):
        """corroboration(3) = tolerates(3) + 1 = 1, so one suffices; two is still behind."""
        c, follower = self._joiner()
        mine = follower.store.head_block_num() or 0
        self._report(c, follower, T0, at=mine + 5)
        self.assertTrue(follower.behind(T0))

    def test_witnesses_at_our_own_head_is_not_behind(self):
        c, follower = self._joiner()
        self._report(c, follower, T0, at=follower.store.head_block_num() or 0)
        self.assertFalse(follower.behind(T0))

    def test_reports_age_against_the_clock_not_against_each_other(self):
        """Freshness was measured against the newest report held, so the window was satisfied by
        the reports themselves and a peer that fell silent vouched for its last word forever."""
        tight = replace(TUNABLES, sync=SyncTunables(freshness_window=2 * DELTA))
        c, follower = self._joiner(tight)
        mine = follower.store.head_block_num() or 0
        self._report(c, follower, T0, at=mine + 5)
        self.assertTrue(follower.behind(T0))
        self.assertFalse(follower.behind(T0 + 2 * DELTA + 1))


class TestABehindNodeDoesNotLeadABucket(unittest.TestCase):
    """Driven through the node's own `tick`, because the point is not that the predicate computes
    -- it did, for a long time, with nothing calling it -- but that the Round path consults it."""

    def _node_and_peers(self) -> tuple[Cluster, Node, list[crypto.PublicKey]]:
        """A ROSTER MEMBER on a fresh store -- a node that lost its disk. `_open_round` refuses
        a non-member outright, so a stranger would prove nothing about the gate."""
        c = Cluster()
        _run_cluster_producing_n_blocks(c, 1)
        node = Node(c.keys[0], c.provisioned(), TUNABLES)
        return c, node, [n.me.public for n in c.nodes[1:3]]

    def _tick_into_a_leadable_window(self, node: Node) -> int:
        """The first tick only adopts the current bucket; a Round can open once a whole bucket
        has closed under us."""
        node.tick(T0)
        return T0 + 2 * DELTA

    def test_a_node_nobody_reports_above_opens_its_round(self):
        """The control. Without it, the test below passes for any reason at all."""
        _, node, _ = self._node_and_peers()
        node.tick(self._tick_into_a_leadable_window(node))
        self.assertIsNotNone(node.coordinator.current_round)

    def test_a_node_with_witnesses_above_it_opens_no_round(self):
        _, node, peers = self._node_and_peers()
        now = self._tick_into_a_leadable_window(node)
        mine = node.store.head_block_num() or 0
        for peer in peers:
            node.follower.receive(
                HeightReply(block_num=mine + 5, tip_hash=crypto.h(b"theirs")), peer, now
            )
        self.assertTrue(node.follower.behind(now), "the setup did not make the node behind")
        node.tick(now)
        self.assertIsNone(node.coordinator.current_round, "a behind node led a bucket")


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
        # Silent peer answers HeightAsk (says they're ahead of us) but never replies to GetBlocks.
        follower.tick(T0)
        follower.outbox()  # drain HeightAsk
        follower.receive(
            HeightReply(block_num=2, tip_hash=crypto.h(b"any")),
            silent.public,
            T0,
        )
        # Tick advances past pull_timeout without a reply.
        follower.tick(T0 + POLL)
        # A GetBlocks went out; drain it.
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
        """Two peers above our head, one SERVED US A BLOCK more recently -- it gets picked.

        Answering a height poll does not count. Credited for that, a peer keeps top priority by
        replying while failing every pull, and the joiner retries it forever."""
        c = Cluster()
        _run_cluster_producing_n_blocks(c, 2)
        joiner_store = c.provisioned()
        follower = _make_follower(joiner_store)
        older = crypto.Keypair.generate()
        newer = crypto.Keypair.generate()
        follower.add_peer(older.public, now=T0)
        follower.add_peer(newer.public, now=T0)

        follower.receive(HeightReply(block_num=2, tip_hash=crypto.h(b"tip")), older.public, T0)
        follower.receive(HeightReply(block_num=2, tip_hash=crypto.h(b"tip")), newer.public, T0)
        self.assertEqual(follower._last_ok_at, {}, "a height reply credited pull-source priority")

        # What a committed block records, which is the only thing that does.
        follower._last_ok_at[older.public] = T0
        follower._last_ok_at[newer.public] = T0 + 1

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

    def test_a_garbage_serving_peer_loses_the_pick_to_an_honest_source(self):
        """A peer that SERVES unverifiable blocks -- unlike one that refuses -- got no claim
        correct-down, so on a fresh joiner (no ok-history anywhere) its inflated claim won the
        pick on height every tick: honest sources were never asked and the joiner never
        converged. A failed pull now orders the peer behind peers that have not failed; still
        no exclusion (#no-shun-only-priority)."""
        c = Cluster()
        _run_cluster_producing_n_blocks(c, 2)
        joiner_store = c.provisioned()
        follower = _make_follower(joiner_store)
        honest = c.nodes[0]
        byz = crypto.Keypair.generate()
        follower.add_peer(byz.public, now=T0)
        follower.add_peer(honest.me.public, now=T0)
        follower.receive(HeightReply(block_num=999, tip_hash=crypto.h(b"lie")), byz.public, T0)
        follower.receive(serve_height(honest.store), honest.me.public, T0)

        follower.tick(T0)
        follower.outbox()
        pull = follower._pulling
        assert pull is not None and pull.peer == byz.public, "setup: byz's claim must win first"

        real_bytes = honest.store.settled_at(2)
        assert real_bytes is not None
        real_sb = SettledBlock.decode(real_bytes)
        bad_sb = SettledBlock(
            block=real_sb.block,
            anchors=Anchors(
                block_num=real_sb.anchors.block_num,
                height=real_sb.anchors.height,
                prev_block=crypto.h(b"wrong-parent"),
                state_root=real_sb.anchors.state_root,
                acc_state=real_sb.anchors.acc_state,
                acc_log=real_sb.anchors.acc_log,
            ),
            multisig=real_sb.multisig,
        )
        follower.receive(
            SettledBlockReply(
                payload=(
                    SettledBlockWithBodies(block=bad_sb, bodies=honest.store.bodies_of_block(2)),
                )
            ),
            byz.public,
            T0,
        )
        self.assertIsNone(follower._pulling)

        follower.tick(T0 + 1)
        pull = follower._pulling
        assert pull is not None, "no new pull opened"
        self.assertEqual(pull.peer, honest.me.public, "the garbage server won the pick again")

    def test_a_timed_out_pull_deprioritises_the_silent_peer_given_an_alternative(self):
        """`test_silent_peer_pull_clears_after_timeout` blesses retrying the ONLY candidate;
        with an honest alternative present, the silent peer's claim used to keep winning on
        height, so the honest source was never asked and every cycle spent a full
        pull_timeout for nothing."""
        c = Cluster()
        _run_cluster_producing_n_blocks(c, 2)
        joiner_store = c.provisioned()
        follower = _make_follower(joiner_store)
        honest = c.nodes[0]
        silent = crypto.Keypair.generate()
        follower.add_peer(silent.public, now=T0)
        follower.add_peer(honest.me.public, now=T0)
        follower.receive(HeightReply(block_num=999, tip_hash=crypto.h(b"claim")), silent.public, T0)
        follower.receive(serve_height(honest.store), honest.me.public, T0)

        follower.tick(T0)
        follower.outbox()
        pull = follower._pulling
        assert pull is not None and pull.peer == silent.public, "setup: silent's claim must win"

        follower.tick(T0 + PULL_TIMEOUT + 1)
        pull = follower._pulling
        assert pull is not None, "the timeout must immediately re-pick"
        self.assertEqual(pull.peer, honest.me.public, "the silent peer won the pick again")

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


class TestABlockMustDeliverEverythingItNames(unittest.TestCase):
    """A block names exactly what it applied, so a sender that serves fewer bodies than the block
    names is withholding -- and adopting it would commit a state_root for a set we never saw.

    The check used to be `issubset`, which was right only while a producer could ratify a slice
    wider than it applied: `bodies_of_block` returns the APPLIED range, so honest bodies were a
    proper subset of the hash list whenever anything was screened out after ratification. With
    the screen ahead of the signature the two sets are the same set, and subset is a tolerance
    for exactly the shape an attacker wants."""

    def test_a_signed_block_naming_a_tx_it_does_not_deliver_is_refused(self):
        c = Cluster()
        _run_cluster_producing_n_blocks(c, 2)
        honest = c.nodes[0]
        follower = _make_follower(c.provisioned())
        follower.add_peer(honest.me.public, now=T0)

        real_bytes = honest.store.settled_at(2)
        assert real_bytes is not None
        real = SettledBlock.decode(real_bytes)
        bodies = honest.store.bodies_of_block(2)
        self.assertEqual(
            frozenset(tx.op_hash for tx in bodies),
            frozenset(real.block.hashes),
            "the honest block already fails to deliver what it names",
        )

        # Over-claim by one, and AUTHORISE it: the manager slot is a valid quorum proof all by
        # itself, so this reaches the body check instead of dying at `chain.advance`.
        over = Block(bucket=real.block.bucket, hashes=(*real.block.hashes, crypto.h(b"never-sent")))
        roster = MgmtReader(honest.store).roster()
        n = len(roster) + 1
        forged = SettledBlock(
            block=over,
            anchors=real.anchors,
            multisig=crypto.MultiSig.combine(
                {n - 1: c.mgr.sign(_settle_payload(over.slice_hash, real.anchors))}, n
            ),
        )

        follower.tick(T0)
        follower.outbox()
        follower.receive(serve_height(honest.store), honest.me.public, T0)
        follower.tick(T0 + 1)
        follower.outbox()

        before = follower.store.head_block_num() or 0
        adopted = follower._adopt(SettledBlockWithBodies(block=forged, bodies=bodies))
        self.assertFalse(adopted, "a block naming a body it never delivered was adopted")
        self.assertEqual(
            follower.store.head_block_num() or 0, before, "the withheld block was committed"
        )

        # The control: the same block, unforged, IS adopted -- so the refusal above is about the
        # over-claim and not about the fixture being unadoptable for some other reason.
        self.assertTrue(
            follower._adopt(SettledBlockWithBodies(block=real, bodies=bodies)),
            "the honest block was refused too; the assertion above proves nothing",
        )


if __name__ == "__main__":
    unittest.main()
