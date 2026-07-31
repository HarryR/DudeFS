# Collection, in a cluster: the first time nodes have to AGREE that a segment may be forgotten.
#
# `Store.collect` is unit-tested alone elsewhere. What is here is the part that needs more than one
# node — ratification, the dedup floor, migration draining a segment, and the housekeeping that
# drives all of it without anyone asking.

from __future__ import annotations

import unittest

from ..core import codec, crypto
from ..net import Verb
from ..net.envelope import Envelope, seal, unseal
from ..net.transports import InProc, name_of
from ..node import (
    Node,
)
from ..store import Commitment, Entry, Store, attest, ops, smt
from ..store.witness import Witness
from ..tunables import DEFAULT
from .cluster import DELTA, T0, Cluster, D, gaps_in_the_retained_log


class TestClusterCollection(unittest.TestCase):
    """Collection, in a cluster. Everything above was end-to-end but never touched a compaction
    path; `Store.collect` was only ever unit-tested alone. This is the first time nodes have to
    AGREE that a segment may be forgotten."""

    WIDTH = 8
    AGE = DEFAULT.mempool.w_admit + DEFAULT.mempool.w_valid_margin + DELTA
    """How long a segment must age before it may be collected. Every test here used to collect
    inside this window and pass, because the floor was only applied on the locally-driven path --
    which is to say those collections would have made their transactions replayable."""

    def setUp(self):
        self.c = Cluster()
        self.client = self.c.mgr
        for node in self.c.nodes:
            # Narrow segments so a handful of writes ages one out. Width has to exceed the number
            # of stragglers migrated in one go, or migration -- which writes at the HEAD -- lands
            # part of its own output back inside the segment it is draining.
            node.store.SEGMENT_WIDTH = self.WIDTH
            # THESE TESTS DRIVE HOUSEKEEPING THEMSELVES, one step at a time, because most of them
            # are about what a collection REFUSES. `Node.tick` now migrates and collects on its own
            # (`housekeep`), which would race every sequence below. Suppressed by moving the
            # once-per-bucket marker past any bucket the test reaches -- a real field, not a
            # production off-switch, so nothing here can pass because the driver was disabled.
            node.last_housekept = 1 << 62

    def _churn(self, n: int) -> int:
        """Overwrite one key repeatedly, so early entries are entirely superseded. Returns `now`.

        A settled bucket will not reopen, so each write needs its own bucket -- which is also the
        realistic shape: this is a register rewritten over time, not a burst."""
        now = T0
        for i in range(n):
            tx = ops.writes(ops.Set(D, crypto.h(b"hot"), f"v{i}".encode())).sign(self.client, now)
            self.c.submit(self.client, tx, to=i % len(self.c.nodes), now=now)
            self.c.pump(now)
            now += DELTA
            self.c.pump(now)
        return now

    def _drain(self, seg: int, now: int) -> int:
        """ONE node offers the relocation; the quorum settles it. Every node then holds the same
        entries, which per-node migration did not give -- it left `A_state` and the head identical
        while the logs themselves differed."""
        assert self.c.nodes[0].drain(seg, now), "nothing to relocate"
        self.c.pump(now)
        self.c.pump(now + DELTA)
        return now + DELTA + self.AGE  # past the dedup floor, or collection is rightly refused

    def test_every_node_collects_and_they_stay_identical(self):
        """The property the design rests on: a segment is forgotten by all three, and `A_state`
        still agrees afterwards. Collection must lose history without losing state."""
        now = self._churn(12)
        now = self._drain(0, now)
        before = {n.store.accumulator() for n in self.c.nodes}

        for node in self.c.nodes:
            self.assertEqual(node.maybe_collect(now), 0, "every node found segment 0 collectable")
        self.c.pump(now)

        for i, node in enumerate(self.c.nodes):
            self.assertNotIn(0, node.store.segments(), f"node {i} did not collect")
        self.assertEqual({n.store.accumulator() for n in self.c.nodes}, before, "state moved")
        self.assertEqual(len({n.store.head() for n in self.c.nodes}), 1, "log lengths diverged")
        # A_LOG, not just A_state. Per-node migration used to leave these three assertions' worth
        # of agreement -- same state, same head -- over byte-different logs, and only this one
        # noticed. It is the assertion that was missing when the divergence shipped.
        self.assertEqual(
            len({n.store.log_accumulator() for n in self.c.nodes}), 1, "the LOGS diverged"
        )

    def test_one_node_noticing_is_enough(self):
        """No distinguished proposer, and no requirement that everyone notice: one node proposes,
        the others ratify what they can recompute, and all three collect."""
        now = self._churn(12)
        now = self._drain(0, now)

        self.assertEqual(self.c.nodes[0].maybe_collect(now), 0)
        self.c.pump(now)

        for i, node in enumerate(self.c.nodes):
            self.assertNotIn(0, node.store.segments(), f"node {i} did not collect")

    def test_concurrent_proposals_are_byte_identical(self):
        """Two nodes proposing the same segment is harmless because the claim is a function of the
        segment and the fold, not of who spoke first -- so their signatures POOL rather than split
        the quorum between two rival claims."""
        now = self._churn(12)
        now = self._drain(0, now)
        a, b = self.c.nodes[0], self.c.nodes[1]

        self.assertEqual(a.maybe_collect(now), 0)
        self.assertEqual(b.maybe_collect(now), 0)
        self.assertEqual(a.collecting[0].attest_bytes(), b.collecting[0].attest_bytes())
        self.c.pump(now)
        for node in self.c.nodes:
            self.assertNotIn(0, node.store.segments())

    def test_a_wrong_fold_is_refused(self):
        """Ratification happens WHILE the evidence still exists. A peer that recomputes a different
        fold signs nothing -- and after collection nobody could ever have checked it."""
        now = self._churn(12)
        now = self._drain(0, now)
        liar, honest = self.c.nodes[0], self.c.nodes[1]

        forged = ops.Compaction(0, honest.store.head(), crypto.ACC_IDENTITY)  # not the real fold
        env = Envelope(honest.me.public, Verb.COLLECT, b"z" * 16, forged.attest_bytes())
        honest.receive(seal(env.sign(liar.me, now)), now)

        self.assertNotIn(forged.attest_bytes(), honest.shares, "signed a fold it cannot reproduce")
        self.assertIn(0, honest.store.segments(), "and collected on one node's word")

    def test_a_pull_for_a_collected_range_is_not_answered_with_a_hole(self):
        """A joiner asks from `head+1`. If collection deleted that range, `entries(frm)` would begin
        at the first index still held -- a run with a hole at the front, through no lie by anybody,
        which the joiner commits and never revisits, since `catch_up` asks from the NEW head.

        Serving nothing is the honest answer: below `retained_from` those entries exist nowhere, so
        no reply can be both complete and non-empty. The requester learns the frontier from the
        ratified marker gossip already carries, and concludes it must bootstrap."""
        now = self._churn(12)
        now = self._drain(0, now)
        server, asker = self.c.nodes[0], self.c.nodes[1]
        self.assertEqual(server.maybe_collect(now), 0)
        self.c.pump(now)
        self.assertNotIn(0, server.store.segments(), "the segment was never collected")
        self.c.board.drain(name_of(asker.me.public))  # clear unrelated traffic first

        frm = 2  # inside the collected prefix, and therefore gone
        env = Envelope(server.me.public, Verb.PULL, b"m" * 16, codec.encode([frm])).sign(
            asker.me, now
        )
        server.receive(seal(env), now)
        server.tick(now)  # `_reply` posts to the mailbox; a tick is what puts it on the wire

        opened = [unseal(f, asker.me) for f in self.c.board.drain(name_of(asker.me.public))]
        replies = [e for e in opened if e.env.verb == Verb.ENTRIES]
        self.assertNotEqual(replies, [], "a PULL below the horizon went unanswered entirely")
        run = codec.as_seq(codec.decode(replies[0].env.body))

        self.assertEqual(list(run), [], "served a run beginning past what was asked for")
        self.assertLess(frm, server.store.retained_from(), "the range under test is not collected")

    def test_collection_gives_every_node_an_attested_floor(self):
        """Where C1 meets C2. Before the first collection there is no floor at all and a node has
        only its own head, which is a hint; afterwards every node carries a quorum-signed height
        that cannot be forged upward (#monotonicity)."""
        now = self._churn(12)
        now = self._drain(0, now)
        for node in self.c.nodes:
            self.assertEqual(node.store.floor(), 0, "a floor before any checkpoint existed")

        self.assertEqual(self.c.nodes[0].maybe_collect(now), 0)
        self.c.pump(now)

        floors = set()
        for i, node in enumerate(self.c.nodes):
            ck = node.store.checkpoint()
            assert ck is not None, f"node {i} collected without keeping the checkpoint"
            self.assertIsNone(ck.attested(list(node.roster())), f"node {i}: floor not ratified")
            self.assertEqual(node.attestation(now).claim.floor, ck.height)
            floors.add(ck.height)
        self.assertEqual(len(floors), 1, "nodes disagree about the attested floor")

    def test_a_replayed_collection_keeps_the_quorums_signatures(self):
        """`replay` used to call `_collect` with NO marker, so it fabricated a local one -- no
        signers, no sigs -- and wrote that to `checkpoint` meta as its floor, discarding the
        ratification that arrived in the entry. The node then advertised the fabrication as
        `ratified` in its own attestations, so an unverifiable floor SPREAD."""
        now = self._churn(12)
        now = self._drain(0, now)
        source, joiner = self.c.nodes[0], self.c.nodes[1]
        self.assertEqual(source.maybe_collect(now), 0)
        self.c.pump(now)

        fresh = Node(crypto.Keypair.generate(), Store())
        fresh.store.replay(list(source.store.entries()))

        ck = fresh.store.checkpoint()
        assert ck is not None, "the replayed collection left no checkpoint at all"
        self.assertNotEqual(ck.sigs, (), "the quorum's signatures were dropped on replay")
        self.assertIsNone(
            ck.attested(list(joiner.roster())), "a replayed floor nobody could verify"
        )

    def test_an_unratified_collection_in_a_run_is_refused(self):
        """One peer must not be able to make us forget a segment. `replay` applied any `Compaction`
        in a run with no signature check at all, which made bulk transfer a DATA-LOSS primitive --
        and the loss is irreversible, unlike every other refusal on this path."""
        now = self._churn(12)
        now = self._drain(0, now)
        source = self.c.nodes[0]
        entries = list(source.store.entries())
        self.assertEqual(source.maybe_collect(now), 0)
        self.c.pump(now)
        marker = next(e for e in source.store.entries() if isinstance(e.item, ops.Compaction))
        real = marker.item
        assert isinstance(real, ops.Compaction)

        victim = Store()
        self.assertIsNone(victim.replay(entries), "the honest prefix should apply")
        held = victim.head()
        stripped = ops.Compaction(  # the same claim, with the ratification taken off
            real.segment, real.height, real.acc_state, real.acc_log, real.root
        )

        why = victim.replay([Entry(marker.idx, stripped)])

        assert why is not None, "an unratified collection was applied"
        self.assertIn("not ratified", why)
        self.assertEqual(victim.head(), held, "state moved on a refused collection")
        self.assertIn(0, victim.segments(), "the segment was forgotten anyway")

    def test_the_horizon_is_the_frontier_of_collection(self):
        """One ratified marker describes where the retained log starts, because collection is
        oldest-first. A per-collection ledger would explain the same holes and would be the only
        structure in the system that grows without bound."""
        now = self._churn(12)
        now = self._drain(0, now)
        node = self.c.nodes[0]
        self.assertEqual(node.store.horizon(), 0, "a frontier before anything was collected")
        self.assertEqual(node.store.retained_from(), 1, "index 0 is not a thing a log holds")

        self.assertEqual(node.maybe_collect(now), 0)
        self.c.pump(now)

        self.assertEqual(node.store.horizon(), 1, "segment 0 is collected, so 1 is the frontier")
        self.assertEqual(node.store.retained_from(), self.WIDTH)
        self.assertEqual(gaps_in_the_retained_log(node.store), (), "the suffix is not contiguous")

    def test_a_blocked_segment_stops_a_later_one_from_being_collected(self):
        """IN ORDER, and it breaks rather than skips. Skipping a straggler-blocked segment let a
        later one collect, which is what produced interior holes — and an interior hole can only be
        explained by a record per collection, which grows for ever.

        The cost is visible here: segment 0 holds genesis roster rows, so until they are migrated
        NOTHING is collected, even though a later segment is entirely dead. That obligation belongs
        to `drain`, and it is why migration is not optional housekeeping."""
        now = self._churn(20)  # several segments, all but the first entirely superseded
        node = self.c.nodes[0]
        self.assertGreater(len(node.store.segments()), 2, "not enough segments to skip past")
        self.assertNotEqual(node.store.stragglers(0), (), "segment 0 is not blocked")
        self.assertEqual(node.store.stragglers(1), (), "segment 1 is not collectable anyway")

        self.assertIsNone(node.maybe_collect(now), "it skipped past a blocked segment")

    def test_a_node_behind_the_frontier_stops_asking(self):
        """The decision the sync path did not have. `catch_up` asked from `head + 1` for ever and a
        server answered from whatever it still held, so being too far behind to catch up was
        indistinguishable from being slightly behind.

        The action this calls for -- bootstrap -- is still OWED, so this only stops a node asking
        for what cannot be served: honest rather than useful, and where §2 continues."""
        now = self._churn(12)
        now = self._drain(0, now)
        source = self.c.nodes[0]
        self.assertEqual(source.maybe_collect(now), 0)
        self.c.pump(now)

        joiner = Node(crypto.Keypair.generate(), self.c.provisioned())
        joiner.connect(source.me.public, InProc(name_of(joiner.me.public), self.c.board))
        joiner.witness.heard(source.attestation(now))  # carries the ratified marker

        self.assertGreater(joiner.store.retained_from(), joiner.store.head() + 1)
        self.assertTrue(joiner.behind_the_horizon(), "it thinks it can still catch up")

        before = len(joiner.postman.mailbox.due(now))
        joiner.catch_up(now)

        self.assertEqual(
            len(joiner.postman.mailbox.due(now)), before, "it asked for what cannot be served"
        )

    def test_a_far_behind_node_adopts_a_ratified_floor_from_gossip(self):
        """The only way a node that has never collected gets an anchor at all.

        `checkpoint` meta used to be written by exactly one code path -- a collection this node
        performed itself -- so a node that missed everything had floor 0 for ever and nothing to
        check any transfer against. The checkpoint it needed was arriving on every attestation it
        heard and being dropped.

        Note the floor landing ABOVE the head. That is not a defect to guard against: it is the
        true, signed, locally-checkable statement *"the cluster has ratified state I do not
        hold"* -- the bootstrap trigger, and refusing it would discard the fact that says so."""
        now = self._churn(12)
        now = self._drain(0, now)
        source = self.c.nodes[0]
        self.assertEqual(source.maybe_collect(now), 0)
        self.c.pump(now)
        ck = source.store.checkpoint()
        assert ck is not None

        joiner = self.c.provisioned()
        self.assertEqual(joiner.floor(), 0, "a floor out of nowhere")

        Witness(joiner).heard(source.attestation(now))  # the ordinary gossip path

        self.assertEqual(joiner.floor(), ck.height, "the ratified floor was not adopted")
        self.assertGreater(joiner.floor(), joiner.head(), "floor above head must be expressible")

    def test_a_floor_nobody_signed_is_not_adopted(self):
        """`attested_floor`'s licence to take a MAX is that a floor carries the quorum. A node that
        could name any height and be believed would defeat #monotonicity outright."""
        joiner = self.c.provisioned()
        liar = crypto.Keypair.generate()
        forged = ops.Compaction(0, 999_999, crypto.ACC_IDENTITY)  # a height nobody ratified

        self.assertIsNotNone(joiner.adopt(forged), "an unsigned checkpoint was adopted")
        self.assertEqual(joiner.floor(), 0)

        # And by the route it would really arrive: inside a signed attestation. The attestation's
        # own signature is good -- it is the FLOOR it carries that nobody ratified.
        told = attest.Attestation(1, 2, crypto.ACC_IDENTITY, crypto.ACC_IDENTITY, ratified=forged)
        Witness(joiner).heard(attest.SignedAttestation.make(liar, told))
        self.assertEqual(joiner.floor(), 0, "a forged floor rode in on a valid signature")

    def test_a_floor_one_node_signed_is_not_adopted(self):
        """A signature that verifies is not a quorum that agreed.

        Adoption is where the missing count would have hurt most: a joiner's floor is the anchor it
        checks every later transfer against, so one member minting a height would have been believed
        about everything downstream of it."""
        joiner = self.c.provisioned()
        roster = list(joiner.roster())
        claim = ops.Compaction(0, 500, crypto.ACC_IDENTITY)
        lone = next(k for k in self.c.keys if k.public == roster[0])
        shares = {0: crypto.Ed25519ListMultiSig.sign_share(lone._seed, claim.attest_bytes())}
        bitmap, sigs = crypto.Ed25519ListMultiSig.combine(shares, len(roster))
        minted = ops.Compaction(
            0, claim.height, claim.acc_state, claim.acc_log, claim.root, bitmap, tuple(sigs)
        )

        why = joiner.adopt(minted)

        assert why is not None, "one node's signature was taken for a quorum"
        self.assertIn("quorum is", why)
        self.assertEqual(joiner.floor(), 0, "one node minted a floor")

    def test_a_self_consistent_lie_is_refused_by_the_quorums_checkpoint(self):
        """THE test for anchoring on the quorum rather than on the sender.

        A transfer was verified against `expect` -- the SENDER'S OWN attestation -- so a roster
        member could serve any history it liked provided it signed a statement matching it. Self
        consistency is not authenticity, and a liar has no trouble being self-consistent: it simply
        keeps its own store.

        The contrast is the whole point. Same run, same signed commitment: accepted by a node with
        no ratified floor, refused by a node holding the quorum's checkpoint."""
        now = self._churn(12)
        now = self._drain(0, now)
        source = self.c.nodes[0]
        self.assertEqual(source.maybe_collect(now), 0)
        self.c.pump(now)
        ck = source.store.checkpoint()
        assert ck is not None

        liar, rogue = crypto.Keypair.generate(), Store()
        rogue.apply(self.c._genesis(), auth=None)
        while rogue.head() < ck.height:  # a whole fabricated history, up to the ratified height
            key = crypto.h(f"lie{rogue.head()}".encode())
            rogue.apply((ops.writes(ops.Set(D, key, b"x")).sign(liar, T0),), auth=None)
        self.assertEqual(rogue.head(), ck.height, "the lie must reach the ratified height")
        told = Commitment(
            rogue.head(), rogue.accumulator(), rogue.log_accumulator(), rogue.state_root()
        )
        run = list(rogue.entries(2))

        gullible = self.c.provisioned()  # no collection, so no floor: only the sender's word
        self.assertIsNone(gullible.replay(run, told), "the lie is not even self-consistent")

        joiner = self.c.provisioned()
        self.assertIsNone(joiner.adopt(ck))

        why = joiner.replay(run, told)

        assert why is not None, "a self-consistent lie was accepted at a ratified height"
        self.assertEqual(joiner.head(), 1, "the lie was committed anyway")

    def test_the_floor_never_drops(self):
        """The retention is monotone at exactly one place, so a node cannot adopt an older
        checkpoint than the one it has already attested -- which would read as a regression and
        convict it."""
        now = self._churn(12)
        now = self._drain(0, now)
        node = self.c.nodes[0]
        self.assertEqual(node.maybe_collect(now), 0)
        self.c.pump(now)
        was = node.store.floor()
        self.assertGreater(was, 0)

        # Straight at `_collect`: the public path would refuse this marker on other grounds and
        # the guard under test would never be reached.
        stale = ops.Compaction(0, 1, node.store.accumulator())
        node.store._collect(1, at=node.store.head() + 1, marker=stale)
        self.assertEqual(node.store.floor(), was, "an older checkpoint lowered the floor")

    def test_the_checkpoint_carries_a_state_root_a_client_can_use(self):
        """The point of putting the root in the checkpoint: a client holding nothing but a
        quorum-signed height can be shown that one key holds one value, and that another key holds
        nothing at all (#state-root). `acc_state` can do neither."""
        now = self._churn(12)
        now = self._drain(0, now)
        self.assertEqual(self.c.nodes[0].maybe_collect(now), 0)
        self.c.pump(now)

        node = self.c.nodes[0]
        ck = node.store.checkpoint()
        assert ck is not None
        self.assertIsNone(ck.attested(list(node.roster())), "the root is not quorum-signed")

        hot = crypto.h(b"hot")
        held = node.store.get(D, hot)
        assert held is not None
        self.assertTrue(
            smt.verify(ck.root, D, hot, (held.value, held.cred), node.store.prove(D, hot))
        )
        self.assertTrue(
            smt.verify(ck.root, D, b"never-written", None, node.store.prove(D, b"never-written"))
        )

    def test_a_wrong_root_is_refused_like_a_wrong_fold(self):
        """Ratification covers the root too. A node that claims a height and a fold it really has,
        with a root it does not, gets no signature -- otherwise the quorum would be vouching for a
        commitment nobody checked."""
        now = self._churn(12)
        now = self._drain(0, now)
        liar, honest = self.c.nodes[0], self.c.nodes[1]

        forged = ops.Compaction(
            0,
            honest.store.head(),
            honest.store.accumulator(),
            honest.store.log_accumulator(),
            smt.EMPTY,
        )
        env = Envelope(honest.me.public, Verb.COLLECT, b"z" * 16, forged.attest_bytes())
        honest.receive(seal(env.sign(liar.me, now)), now)

        self.assertNotIn(forged.attest_bytes(), honest.shares, "signed a root it did not recompute")
        self.assertIn(0, honest.store.segments())

    def test_a_segment_inside_the_dedup_window_is_refused(self):
        """The floor, on the PEER-driven path. It used to be a parameter of `maybe_collect` stashed
        on the node for `_try_collect` to read later, so a collection driven by a peer used whatever
        a local call had last left behind -- usually zero. Collection forgets `op_hash`, so a
        segment collected inside the mempool's admission window makes its transactions replayable
        again, and a floor that applies on one path and not the other is not a floor."""
        now = self._churn(12)
        assert self.c.nodes[0].drain(0, now), "nothing to relocate"
        self.c.pump(now)
        self.c.pump(now + DELTA)
        young = now + DELTA  # deliberately NOT past the floor

        self.assertEqual(self.c.nodes[0].maybe_collect(young), 0, "it may still PROPOSE")
        self.c.pump(young)
        for i, node in enumerate(self.c.nodes):
            self.assertIn(0, node.store.segments(), f"node {i} collected a young segment")

        # ...and the same segment collects once it has aged, so the refusal is the floor and not
        # some other obstacle.
        older = young + self.AGE
        for node in self.c.nodes:
            node.collecting.clear()
        self.assertEqual(self.c.nodes[0].maybe_collect(older), 0)
        self.c.pump(older)
        for i, node in enumerate(self.c.nodes):
            self.assertNotIn(0, node.store.segments(), f"node {i} never collected")

    def test_a_partitioned_node_does_not_collect_alone(self):
        """One node is not a quorum, however sure it is. Collection is irreversible, so the node
        that cannot reach its peers must simply keep the segment."""
        now = self._churn(12)
        now = self._drain(0, now)
        lone = name_of(self.c.keys[0].public)
        for other in self.c.keys[1:]:
            self.c.board.cut(lone, name_of(other.public))
            self.c.board.cut(name_of(other.public), lone)

        self.assertEqual(self.c.nodes[0].maybe_collect(now), 0, "it may still PROPOSE")
        self.c.pump(now)
        self.assertIn(0, self.c.nodes[0].store.segments(), "no quorum, no collection")


class TestCompactionRunsByItself(unittest.TestCase):
    """The round performs the duties, with no test reaching in to drive them.

    `Node.drain` and `Node.maybe_collect` were correct, tested and called by NOTHING, so no node
    ever migrated or collected: the log grew for ever while #compaction-is-required says compaction
    is not an optimisation. Every other collection test here drives the sequence by hand, which is
    how that went unnoticed so long — so this one is forbidden from touching either."""

    WIDTH = 8
    AGE = DEFAULT.mempool.w_admit + DEFAULT.mempool.w_valid_margin + DELTA

    def setUp(self):
        self.c = Cluster()
        self.client = self.c.mgr
        for node in self.c.nodes:
            node.store.SEGMENT_WIDTH = self.WIDTH

    def test_a_cluster_left_alone_migrates_and_collects(self):
        """One key rewritten repeatedly, then time passes. Nothing else."""
        now = T0
        for i in range(12):
            tx = ops.writes(ops.Set(D, crypto.h(b"hot"), f"v{i}".encode())).sign(self.client, now)
            self.c.submit(self.client, tx, to=i % len(self.c.nodes), now=now)
            self.c.pump(now)
            now += DELTA
            self.c.pump(now)
        node = self.c.nodes[0]
        self.assertEqual(
            node.store.stragglers(0), (), "housekeeping never migrated the genesis roster rows"
        )
        self.assertIn(0, node.store.segments(), "collected before the dedup floor allowed it")

        # Past the dedup floor, still doing nothing but advancing the clock.
        for _ in range(4):
            now += self.AGE
            self.c.pump(now)

        for i, n in enumerate(self.c.nodes):
            self.assertGreaterEqual(n.store.horizon(), 1, f"node {i} never collected anything")
            self.assertNotIn(0, n.store.segments(), f"node {i} still holds segment 0")
        self.assertEqual(
            len({n.store.horizon() for n in self.c.nodes}), 1, "the frontiers diverged"
        )
        self.assertEqual(
            len({n.store.log_accumulator() for n in self.c.nodes}), 1, "the LOGS diverged"
        )
        self.assertEqual(len({n.store.accumulator() for n in self.c.nodes}), 1, "state moved")

    def test_the_current_segment_is_never_drained_into_itself(self):
        """Migration writes at the head, so relocating out of the segment that holds the head puts
        the row back where it was. The first version of `housekeep` did exactly that, every bucket,
        for the whole life of a young cluster."""
        node = self.c.nodes[0]
        self.assertEqual(node.store.horizon(), 0)
        self.assertEqual(
            node.store.segment_of(node.store.head() + 1), 0, "segment 0 is not current"
        )
        before = node.store.head()

        for r in range(3):
            self.c.pump(T0 + r * DELTA)

        self.assertEqual(node.store.head(), before, "it relocated rows inside the current segment")

    def test_housekeeping_happens_once_per_bucket(self):
        """`migration` signs with `now`, so authoring the same relocation twice yields two different
        op_hashes, both valid — a `Move` asserts nothing, so the second still applies — and both
        consume log entries. The gate is a correctness matter, not politeness."""
        node = self.c.nodes[0]
        node.last_housekept = -1
        bucket = node.tunables.mempool.bucket(T0)

        node.housekeep(T0)
        self.assertEqual(node.last_housekept, bucket)
        node.housekeep(T0 + 1)  # same bucket

        self.assertEqual(node.last_housekept, bucket, "it housekept twice in one bucket")


if __name__ == "__main__":
    unittest.main()
