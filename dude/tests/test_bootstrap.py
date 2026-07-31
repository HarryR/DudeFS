# Becoming current from nothing: the bootstrap chain and the state walk.
#
# A node arrives holding what it was given out of band — the manager key, and the seed addresses
# that let it reach anyone at all. Everything else it comes to believe is reached from there: the
# roster by the manager's own signatures, the quorum by that roster, the state by a root the quorum
# signed. These suites walk that chain and then break each link in turn.

from __future__ import annotations

import unittest

from .. import quorum
from ..core import codec, crypto
from ..core.errors import InvariantError
from ..net import Verb
from ..net.envelope import Envelope
from ..node import (
    Node,
    _folds_to,
)
from ..store import Entry, Store, ops, settle, smt
from ..store.management import P_NODE, P_ROSTER, Management, Role
from ..tunables import DEFAULT
from .cluster import DELTA, T0, Cluster, D, M


class TestTheBootstrapAnchor(unittest.TestCase):
    """Steps 1 and 2 of #bootstrap-anchor: the one value not derived from anything, and the check
    that ties a log to it.

    `[H]` *"the manager public key is provided to the new node when it bootstraps and would be
    retained through a new bootstrap."* Everything else a node believes is reached from here, so a
    log that introduces its OWN manager checks out against itself; only the anchor can refuse it."""

    def setUp(self):
        self.c = Cluster()
        self.client = self.c.mgr

    def test_a_provisioned_node_recognises_its_own_cluster(self):
        node = self.c.nodes[0]
        self.assertEqual(node.store.anchor(), self.c.mgr.public)
        self.assertIsNone(node.store.wrong_cluster())

    def test_an_unprovisioned_node_can_verify_nothing_and_says_so(self):
        """It holds no axiom, so it does not pass by default — and `adopt` refuses it a floor, which
        bounds what an unprovisioned node can be talked into."""
        bare = Store()
        bare.apply(self.c._genesis(), auth=None)
        self.assertIsNone(bare.anchor())
        why = bare.wrong_cluster()
        assert why is not None
        self.assertIn("never provisioned", why)

    def test_re_provisioning_to_another_manager_is_refused(self):
        """It would move a node between clusters while keeping its identity, its attestation history
        and its monotone height — the one quantity #monotonicity says cannot be forged. An operator
        who means it deletes the store, which is the same act as retiring the identity."""
        node = self.c.nodes[0]
        node.store.provision(self.c.mgr.public)  # idempotent for the same key

        with self.assertRaises(InvariantError) as cm:
            node.store.provision(crypto.Keypair.generate().public)
        self.assertIn("different manager", str(cm.exception))

    def test_a_strangers_genesis_is_refused_and_rolled_back(self):
        """THE ATTACK THE ANCHOR EXISTS FOR. A whole coherent log — its own manager, its own
        roster, internally consistent, correctly signed throughout — offered to a provisioned but
        empty node. Every signature verifies. Only the anchor can say it is the wrong world."""
        stranger = Cluster()  # a different manager, a different roster, all of it valid
        joiner = Store()
        joiner.provision(self.c.mgr.public)  # ours
        run = list(stranger.nodes[0].store.entries())

        why = joiner.replay(run)

        assert why is not None, "a stranger's whole log was adopted"
        self.assertIn("anchor does not authorise", why)
        self.assertEqual(joiner.head(), 0, "it kept part of a foreign log")
        self.assertEqual(joiner.roster(), (), "it took a foreign roster")

    def test_our_own_genesis_replays_into_an_empty_provisioned_node(self):
        """The control, and the reason the check runs AFTER applying: a from-scratch replay begins
        with genesis, so the manager grant does not exist until the run lands. Checking first would
        refuse the only run that could ever establish it."""
        joiner = Store()
        joiner.provision(self.c.mgr.public)

        self.assertIsNone(joiner.replay(list(self.c.nodes[0].store.entries())))

        self.assertIsNone(joiner.wrong_cluster())
        self.assertEqual(joiner.roster(), self.c.nodes[0].store.roster())

    def test_a_checkpoint_from_another_cluster_is_not_adopted(self):
        """The chain has an order: a checkpoint is verified against the roster, and the roster is
        worth something only if the log holding it is the one our anchor authorises."""
        joiner = self.c.provisioned()
        foreign = Cluster()
        for node in foreign.nodes:
            node.store.SEGMENT_WIDTH = 8
        joiner.provision(self.c.mgr.public)
        rogue = ops.Compaction(0, 500, crypto.ACC_IDENTITY)

        self.assertIsNotNone(joiner.adopt(rogue))
        self.assertEqual(joiner.floor(), 0)


class TestTheRosterTracesToTheAnchor(unittest.TestCase):
    """Step 6 of #bootstrap-anchor: every roster row vouched by the key we were provisioned with.

    This is what the credential travelling with the row is FOR. Collection eventually forgets the
    entry that first set a roster row, so without the carried credential a joiner could only take
    the roster on the word of the quorum — and the roster is what defines that quorum."""

    def setUp(self):
        self.c = Cluster()
        self.client = self.c.mgr

    def test_an_honest_roster_traces_to_the_anchor(self):
        node = self.c.nodes[0]
        self.assertIsNone(node.store.unvouched_roster())

    def test_a_roster_row_with_its_credential_stripped_is_refused(self):
        """Not a hypothetical: collection deletes the entry that authorised the row, so a row whose
        credential did not travel is exactly what a compacted log would leave behind."""
        node = self.c.nodes[0]
        who = node.store.roster()[0]
        node.store.db.execute(
            "UPDATE live SET cred=x'' WHERE store=? AND name=?", (M, P_NODE + bytes(who))
        )

        why = node.store.unvouched_roster()

        assert why is not None, "a roster row with no credential was accepted"
        self.assertIn("no credential", why)

    def test_a_roster_the_log_calls_authorised_but_the_anchor_never_signed(self):
        """THE CASE THAT DECIDES ANCHOR-vs-MANAGER. `replay` does not re-adjudicate authority, so a
        forged log can carry a `grant` row naming a manager nobody ever authorised — and a roster
        vouched by that manager. Checking "signed by some manager in this log" accepts it; checking
        against the anchor does not.

        Built the way an attacker would: its own manager, its own node, internally consistent, every
        signature valid, replayed into a store provisioned to OUR manager."""
        forger = crypto.Keypair.generate()
        mgmt = Management(Store())
        tx = mgmt.authorise(
            forger.public, Role.MANAGER, frozenset({M, D}), frozenset(), forger.prove_possession()
        )
        tx = tx + mgmt.add_node(forger.public, (b"attacker:1",))
        theirs = tx.sign(forger, T0)

        victim = Store()
        victim.provision(self.c.mgr.public)  # ours, not the forger's

        why = victim.replay([Entry(1, theirs)])

        assert why is not None, "a self-authorised manager wrote the roster"
        self.assertEqual(victim.roster(), (), "it took a roster the anchor never signed")

    def test_a_migrated_roster_row_still_traces_to_the_anchor(self):
        """The property the conveyor has to preserve. A `Move` relocates provenance to the head and
        carries the credential with it, so a row that has been through compaction is still vouched.
        That is the whole reason `ops.Move` carries one."""
        node = self.c.nodes[0]
        node.store.SEGMENT_WIDTH = 8
        node.last_housekept = 1 << 62  # this test drives the migration itself
        before = node.store.credential(M, P_NODE + bytes(node.store.roster()[0]))
        self.assertNotEqual(before, b"")

        now = T0
        for i in range(12):
            tx = ops.writes(ops.Set(D, crypto.h(b"hot"), f"v{i}".encode())).sign(self.client, now)
            self.c.submit(self.client, tx, to=0, now=now)
            self.c.pump(now)
            now += DELTA
            self.c.pump(now)
        self.assertTrue(node.drain(0, now), "there was nothing to relocate")
        self.c.pump(now)
        self.c.pump(now + DELTA)

        self.assertEqual(node.store.stragglers(0), (), "the roster rows never moved")
        self.assertIsNone(node.store.unvouched_roster(), "a relocated row lost its credential")


class TestTheRosterIsComplete(unittest.TestCase):
    """Step 7 of #bootstrap-anchor: no member is missing, and no old roster comes back.

    Step 6 proves every member was authorised by the anchor. It cannot prove that none is MISSING —
    and a subset is a smaller roster, which is a smaller quorum, so a party handed three of eleven
    rows would compute a quorum of two and believe it."""

    def setUp(self):
        self.c = Cluster()
        self.client = self.c.mgr

    def test_an_honest_roster_is_complete(self):
        node = self.c.nodes[0]
        commitment = Management(node.store).roster_commitment()
        assert commitment is not None
        serial, members = commitment
        self.assertEqual(serial, 1)
        self.assertEqual(members, node.store.roster())
        self.assertIsNone(node.store.roster_incomplete())

    def test_a_subset_of_the_roster_is_refused(self):
        """THE ATTACK. Hand a party fewer rows than the manager signed and it computes a smaller
        quorum — two of three here — from perfectly valid, individually vouched rows."""
        node = self.c.nodes[0]
        dropped = node.store.roster()[0]
        node.store.db.execute(
            "DELETE FROM live WHERE store=? AND name=?", (M, P_NODE + bytes(dropped))
        )
        self.assertEqual(len(node.store.roster()), 2, "the row did not come out")

        why = node.store.roster_incomplete()

        assert why is not None, "a subset of the roster passed as the whole"
        self.assertIn("different set", why)

    def test_a_log_that_states_no_membership_is_refused(self):
        """Enumeration cannot detect its own incompleteness, so a log with rows and no commitment is
        unverifiable rather than merely undocumented."""
        node = self.c.nodes[0]
        node.store.db.execute("DELETE FROM live WHERE store=? AND name=?", (M, P_ROSTER))

        why = node.store.roster_incomplete()

        assert why is not None
        self.assertIn("no roster commitment", why)

    def test_an_older_roster_cannot_come_back(self):
        """The rollback rule. A genuine-but-superseded roster — members since removed, whose keys an
        adversary may still hold — verifies perfectly against the anchor, so only the serial refuses
        it. The high-water mark is durable so a restart does not reopen the window."""
        node = self.c.nodes[0]
        self.assertIsNone(node.store.roster_incomplete())
        node.store._set_meta("roster_serial", (5).to_bytes(8))  # we have seen revision 5

        why = node.store.roster_incomplete()

        assert why is not None, "a roster older than one already accepted was accepted again"
        self.assertIn("older than", why)

    def test_a_commitment_the_anchor_did_not_sign_is_refused(self):
        """Otherwise a forged log states its own membership, which is the step-6 attack moved one
        level up: the members would each be vouched, by a manager who vouched for himself."""
        node = self.c.nodes[0]
        node.store.db.execute("UPDATE live SET cred=x'' WHERE store=? AND name=?", (M, P_ROSTER))

        why = node.store.roster_incomplete()

        assert why is not None
        self.assertIn("vouched by nobody", why)

    def test_a_replayed_log_carries_its_membership_or_is_refused(self):
        """The chain end to end on the path that matters: a provisioned but empty node replaying a
        whole log accepts it only if the membership is stated and vouched."""
        joiner = Store()
        joiner.provision(self.c.mgr.public)

        self.assertIsNone(joiner.replay(list(self.c.nodes[0].store.entries())))

        self.assertEqual(joiner.roster(), self.c.nodes[0].store.roster())
        self.assertEqual(joiner.roster_serial(), 1, "the high-water mark did not advance")


class TestTheStateWalk(unittest.TestCase):
    """Step 9 of #bootstrap-anchor: state taken against the root a quorum signed.

    This is the half a log cannot do. Past the frontier the entries that built the state are gone,
    so a joiner cannot replay them — it takes the STATE and checks every piece against the root the
    ratified checkpoint carries. `smt.verify` gets its first production caller here."""

    def setUp(self):
        self.c = Cluster()
        self.client = self.c.mgr
        for i in range(6):
            tx = ops.writes(ops.Set(D, crypto.h(f"k{i}".encode()), f"v{i}".encode())).sign(
                self.client, T0
            )
            self.c.submit(self.client, tx, to=0, now=T0)
        self.c.pump(T0)
        self.c.pump(T0 + DELTA)
        self.source = self.c.nodes[0]
        self.root = self.source.store.state_root()

    def _rows_with_proofs(self, prefix=b"", depth=0):
        return [
            (store, name, value, cred, self.source.store.prove(store, name))
            for store, name, value, cred in self.source.store.rows_under(prefix, depth)
        ]

    def test_a_wiped_node_takes_the_whole_state_against_the_root(self):
        """The case the walk exists for: no log, no entries to replay, and the state arrives anyway
        — verified row by row against something the quorum signed."""
        wiped = Store()
        wiped.provision(self.c.mgr.public)

        self.assertIsNone(wiped.adopt_state(self._rows_with_proofs(), self.root))

        self.assertEqual(wiped.state_root(), self.root, "the rebuilt tree is a different tree")
        self.assertEqual(wiped.accumulator(), self.source.store.accumulator())
        for i in range(6):
            got = wiped.get(D, crypto.h(f"k{i}".encode()))
            assert got is not None, f"k{i} did not arrive"
            self.assertEqual(got.value, f"v{i}".encode())

    def test_a_row_that_does_not_fold_to_the_root_is_refused(self):
        """A chunk is refused WHERE IT ARRIVES, which is what lets the walk be optimistic: a bad
        reply costs one round trip instead of poisoning a transfer checked only at the end."""
        wiped = Store()
        wiped.provision(self.c.mgr.public)
        rows = self._rows_with_proofs()
        store, name, _value, cred, proof = rows[0]
        rows[0] = (store, name, b"not-what-was-committed", cred, proof)

        why = wiped.adopt_state(rows, self.root)

        assert why is not None, "a value the root does not commit to was applied"
        self.assertIn("does not verify", why)
        self.assertEqual(wiped.get(store, name), None, "part of a poisoned chunk landed")

    def test_a_row_whose_credential_was_substituted_is_refused(self):
        """The transfer's half of `[H]`'s ruling. The VALUE here is genuine and really was
        committed — only the credential differs, and the fold still refuses the row. So a peer
        cannot hand a joiner real data under an authorisation of its own choosing."""
        wiped = Store()
        wiped.provision(self.c.mgr.public)
        rows = self._rows_with_proofs()
        store, name, value, _cred, proof = rows[0]
        rows[0] = (store, name, value, b"authorised-by-whoever-is-serving-you", proof)

        why = wiped.adopt_state(rows, self.root)

        assert why is not None, "a row arrived with a credential the root does not commit to"
        self.assertIn("does not verify", why)

    def test_a_transferred_roster_row_still_traces_to_the_manager(self):
        """THE PAYOFF, and the reason the credential is in the leaf rather than only in the log.
        This node holds no entries at all — it replayed nothing — and can still answer "who was
        permitted to write this" for a row a stranger handed it, WITHOUT asking the quorum that the
        roster itself defines."""
        wiped = Store()
        wiped.provision(self.c.mgr.public)
        self.assertIsNone(wiped.adopt_state(self._rows_with_proofs(), self.root))
        self.assertEqual(wiped.head(), 0, "the premise is wrong: this node replayed history")

        key = P_NODE + bytes(self.source.me.public)
        who = settle.vouched(wiped, ops.STORE_MANAGEMENT, key, wiped.credential(M, key))

        self.assertEqual(who, self.c.mgr.public, "the chain back to the manager did not survive")

    def test_a_subtree_that_already_agrees_is_never_transferred(self):
        """Cost degrades smoothly with absence: the walk descends only where the hashes differ, so a
        node that is slightly stale moves almost nothing."""
        mirror = Store()
        mirror.provision(self.c.mgr.public)
        mirror.adopt_state(self._rows_with_proofs(), self.root)

        left, right = self.source.store.subtree(b"", 0)
        self.assertEqual(mirror.subtree(b"", 0), (left, right), "an identical store disagreed")
        self.assertEqual(mirror.state_root(), self.source.store.state_root())

    def test_the_walk_asks_only_where_the_two_trees_differ(self):
        """The comparison step, through the real handler: a joiner that already agrees asks for
        nothing at all, which is the property that makes cost track absence."""
        joiner = self.c.nodes[2]
        top = bytes(crypto.DIGEST_SIZE)
        joiner.walking = {(top, 0): self.root}
        left, right = self.source.store.subtree(top, 0)
        body = codec.encode([top, 0, left, right])
        env = Envelope(joiner.me.public, Verb.HASHES, b"h" * 16, body).sign(self.source.me, T0)

        joiner._on_hashes(env, T0)

        self.assertEqual(joiner.walking, {}, "it queued work for a subtree it already agrees on")

    def test_hashes_that_do_not_fold_to_the_root_are_ignored(self):
        """THE STEERING ATTACK, and the reason this reply is verified rather than believed. A peer
        that answers with anything the root does not commit to — including our own hashes echoed
        back, which would end the walk holding nothing — is refused before it can direct a single
        descent."""
        joiner = Node(crypto.Keypair.generate(), self.c.provisioned())
        top = bytes(crypto.DIGEST_SIZE)
        joiner.walking = {(top, 0): self.root}
        lies = codec.encode([top, 0, crypto.h(b"not"), crypto.h(b"the-root")])
        env = Envelope(joiner.me.public, Verb.HASHES, b"h" * 16, lies).sign(self.source.me, T0)

        joiner._on_hashes(env, T0)

        self.assertEqual(joiner.walking, {(top, 0): self.root}, "a lie steered the walk")
        self.assertEqual(len(joiner.postman.mailbox.due(T0)), 0, "and it asked a question on it")

    def test_an_answer_to_a_question_we_did_not_ask_is_ignored(self):
        """Replies are asynchronous, so an answer must name its own question. Pairing by arrival
        order — which a stack does — attributes an answer to whatever was asked most recently."""
        joiner = Node(crypto.Keypair.generate(), self.c.provisioned())
        top = bytes(crypto.DIGEST_SIZE)
        joiner.walking = {(top, 0): self.root}
        elsewhere = smt.with_bit(top, 0, 1)
        left, right = self.source.store.subtree(elsewhere, 1)
        body = codec.encode([elsewhere, 1, left, right])
        env = Envelope(joiner.me.public, Verb.HASHES, b"h" * 16, body).sign(self.source.me, T0)

        joiner._on_hashes(env, T0)

        self.assertEqual(joiner.walking, {(top, 0): self.root}, "it acted on an unasked answer")

    def test_a_walk_needs_a_ratified_root_to_check_against(self):
        """Without a checkpoint there is nothing signed to verify rows against, so there is nothing
        to start. Refusing here is what stops a walk becoming "trust whoever answered"."""
        joiner = Node(crypto.Keypair.generate(), self.c.provisioned())
        self.assertIsNone(joiner.store.checkpoint())

        self.assertFalse(joiner.bootstrap(T0))
        self.assertIsNone(joiner.walking)


class TestFreshnessIsThePrecondition(unittest.TestCase):
    """`[H]` *"we were supposed to first verify f+1 nodes' attestations before anything else."*

    Every other check establishes AUTHENTICITY. None establishes CURRENCY — a malicious node can
    serve a perfectly authentic, perfectly stale world, correctly signed throughout, and only the
    count of fresh independent statements tells that from the truth."""

    WIDTH = 8
    AGE = DEFAULT.mempool.w_admit + DEFAULT.mempool.w_valid_margin + DELTA

    def setUp(self):
        self.c = Cluster()
        self.client = self.c.mgr
        for node in self.c.nodes:
            node.store.SEGMENT_WIDTH = self.WIDTH

    def _collected(self) -> int:
        now = T0
        for i in range(12):
            tx = ops.writes(ops.Set(D, crypto.h(b"hot"), f"v{i}".encode())).sign(self.client, now)
            self.c.submit(self.client, tx, to=i % 3, now=now)
            self.c.pump(now)
            now += DELTA
            self.c.pump(now)
        for _ in range(4):
            now += self.AGE
            self.c.pump(now)
        assert self.c.nodes[0].store.checkpoint() is not None, "nothing was ever collected"
        return now

    def test_a_checkpoint_f_plus_one_fresh_responders_vouch_for_is_taken(self):
        now = self._collected()
        node = self.c.nodes[0]

        ck = node.corroborated(now)

        assert ck is not None, "a cluster all talking to each other could not corroborate anything"
        self.assertEqual(ck.height, node.store.floor())

    def test_a_node_does_not_count_its_own_view_toward_currency(self):
        """Asking "is my view current" and counting our own attestation is asking ourselves. At the
        size that matters it decides the answer: with one peer, self plus peer reaches two."""
        now = self._collected()
        alone = Node(crypto.Keypair.generate(), self.c.provisioned())
        alone.store.witness(self.c.nodes[0].attestation(now))

        self.assertEqual(len(alone.gathered(now)), 2)
        self.assertEqual(len(alone.gathered(now, me=False)), 1, "it counted itself as a responder")

    def test_f_plus_one_is_f_plus_one_not_a_quorum(self):
        """Different questions. At n=3 two-thirds tolerates 0 faults, so ONE honest fresh answer is
        `f+1` and demanding a quorum would refuse a cluster that is answering correctly; at n=11 it
        tolerates 4 and five are needed. Reading `size()` here asks a quorum a question that is not
        a quorum's to answer."""
        self.assertEqual(quorum.DEFAULT.tolerates(3) + 1, 1)
        self.assertEqual(quorum.DEFAULT.tolerates(11) + 1, 5)
        self.assertEqual(quorum.size(3), 2, "the two numbers are not the same number")

    def test_stale_answers_do_not_count_however_many(self):
        """An adversary without `f+1` keys can only replay old statements, and old statements look
        old. The window is what makes staleness visible rather than silent."""
        now = self._collected()
        node = self.c.nodes[0]
        self.assertIsNotNone(node.corroborated(now))

        much_later = now + DEFAULT.attest.fresh_within * 10

        self.assertIsNone(node.corroborated(much_later), "a bundle nobody refreshed stayed current")

    def test_the_seeds_are_provisioning_input_like_the_anchor(self):
        """`f+1` responders need `f+1` addresses, and an address cannot be obtained by asking,
        because asking requires one."""
        s = Store()
        s.provision(self.c.mgr.public, seeds=[b"inproc:a", b"inproc:b"])
        self.assertEqual(s.seeds(), (b"inproc:a", b"inproc:b"))
        self.assertEqual(Store().seeds(), (), "an unprovisioned node invented an address")


class TestAFinishedWalkIsCorroborated(unittest.TestCase):
    """An empty queue is not success. A walk that lost replies — or was steered into asking for
    nothing — empties exactly like one that worked, so the finish is checked against the fold the
    quorum signed. That fold is O(1) and already in the checkpoint."""

    WIDTH = 8
    AGE = DEFAULT.mempool.w_admit + DEFAULT.mempool.w_valid_margin + DELTA

    def setUp(self):
        self.c = Cluster()
        self.client = self.c.mgr
        for node in self.c.nodes:
            node.store.SEGMENT_WIDTH = self.WIDTH
        now = T0
        for i in range(12):
            tx = ops.writes(ops.Set(D, crypto.h(f"k{i}".encode()), b"v")).sign(self.client, now)
            self.c.submit(self.client, tx, to=i % 3, now=now)
            self.c.pump(now)
            now += DELTA
            self.c.pump(now)
        for _ in range(4):
            now += self.AGE
            self.c.pump(now)
        self.now = now
        self.source = self.c.nodes[0]
        ck = self.source.store.checkpoint()
        assert ck is not None, "nothing was collected, so there is no checkpoint to walk to"
        self.ck = ck  # narrowed before it is stored, so every use below is a Compaction

    def _bare(self) -> Store:
        """Provisioned and EMPTY: the state a bootstrapping node is actually in. It holds the anchor
        and nothing else, which is why its head is zero until a walk is corroborated."""
        s = Store()
        s.provision(self.c.mgr.public, seeds=[b"inproc:0"])
        return s

    def _walked(self) -> Store:
        joiner = self._bare()
        rows = [
            (store, name, value, cred, self.source.store.prove(store, name))
            for store, name, value, cred in self.source.store.rows_under(b"", 0)
        ]
        assert joiner.adopt_state(rows, self.ck.root) is None
        return joiner

    def test_a_walk_that_holds_what_was_committed_is_accepted(self):
        joiner = self._walked()

        self.assertIsNone(joiner.adopted_at(self.ck))

        self.assertEqual(joiner.accumulator(), self.source.store.accumulator())
        self.assertEqual(joiner.state_root(), self.ck.root)

    def test_an_honest_answer_with_one_empty_child_is_accepted(self):
        """THE STALL. A subtree with one empty child and SEVERAL leaves on the other side is an
        ordinary branch over `EMPTY`, not a compressed lone leaf — and the two are indistinguishable
        from the hashes alone, because a digest does not say how many leaves are under it.

        Taking only the compressed reading refused the honest answer, and refusing keeps the
        question outstanding: the walk never emptied its queue, never adopted, and looked precisely
        like a peer that had stopped replying. Found by a node re-joining, not by a unit test —
        which is the point, since every walk test until then handed `_on_hashes` its own answers."""
        src = self.source.store
        # A REAL node from a real tree, found by descending it — not a hand-built shape, because
        # the bug was that this shape is ordinary and the code assumed it could not occur.
        shape, frontier = None, [(bytes(crypto.DIGEST_SIZE), 0)]
        while frontier and shape is None:
            prefix, depth = frontier.pop()
            left, right = src.subtree(prefix, depth)
            kids = (smt.with_bit(prefix, depth, 0), smt.with_bit(prefix, depth, 1))
            if (left == smt.EMPTY) != (right == smt.EMPTY):
                solid = kids[1] if left == smt.EMPTY else kids[0]
                if len(src.rows_under(solid, depth + 1)) > 1:
                    shape = (prefix, depth, left, right)
                    break
            if depth < 12:
                frontier += [
                    (k, depth + 1)
                    for k, h in zip(kids, (left, right), strict=True)
                    if h != smt.EMPTY
                ]
        assert shape is not None, "no such node in this tree; the test proves nothing"

        prefix, depth, left, right = shape
        expect = src.tree.hash_under(prefix, depth)

        self.assertTrue(
            _folds_to(expect, prefix, depth, left, right),
            "an honest answer about a sparse subtree was refused, which stalls the walk",
        )
        # The SOLID side replaced, not the empty one: zeroing the empty child changes nothing, so
        # that negative would have passed against a check that accepted everything.
        forged = crypto.h(b"not this subtree")
        bad = (left, forged) if right != smt.EMPTY else (forged, right)
        self.assertFalse(
            _folds_to(expect, prefix, depth, *bad), "the check accepts anything at all"
        )

    def test_a_walk_that_does_not_corroborate_leaves_room_for_another(self):
        """It restarts BY ENDING, and that distinction is the whole of it. The old restart reseeded
        `walking` with the top of the tree and never asked the question — so the entry stayed
        outstanding for ever, and `bootstrap`, which refuses to start while a walk is live, could
        never open another. A walk that failed to corroborate ended the node's ability to sync."""
        joiner = Node(crypto.Keypair.generate(), self._bare())
        joiner.walking = {}  # nothing outstanding, and nothing transferred either

        joiner._walk_done(self.ck)

        self.assertIsNone(joiner.walking, "a failed walk left one outstanding that nothing answers")
        self.assertEqual(joiner.store.head(), 0, "it adopted a height it had not earned")

    def test_a_short_walk_is_refused_however_valid_each_row_was(self):
        """THE CASE THIS EXISTS FOR. Every row that arrived verified against the root — they are
        genuine rows. The walk simply did not finish, and only the fold can say so."""
        joiner = self._bare()
        rows = [
            (store, name, value, cred, self.source.store.prove(store, name))
            for store, name, value, cred in self.source.store.rows_under(b"", 0)
        ][:3]
        self.assertIsNone(joiner.adopt_state(rows, self.ck.root))

        why = joiner.adopted_at(self.ck)

        assert why is not None, "a partial walk was taken as complete"
        self.assertIn("does not match", why)

    def test_adoption_gives_the_node_a_height_it_can_carry_on_from(self):
        """`MAX(idx)` alone would report zero for a node holding no entries, so it would be behind
        the frontier for ever and bootstrap again every round — the walk succeeding and changing
        nothing."""
        joiner = self._walked()
        self.assertEqual(joiner.head(), 0, "it had a height before it corroborated anything")

        self.assertIsNone(joiner.adopted_at(self.ck))

        self.assertEqual(joiner.head(), self.ck.height)
        self.assertEqual(joiner.log_accumulator(), self.ck.acc_log, "A_log was not adopted")

    def test_a_log_fold_a_joiner_cannot_compute_is_adopted_not_derived(self):
        """`A_log` is a fold over every entry ever, minus what has been collected. A node that held
        none of them cannot compute it, which is why the ratified marker carries it."""
        joiner = self._walked()
        self.assertEqual(joiner.log_accumulator(), crypto.ACC_IDENTITY, "it computed one somehow")

        joiner.adopted_at(self.ck)

        self.assertEqual(joiner.log_accumulator(), self.ck.acc_log)
        self.assertNotEqual(
            joiner.log_accumulator(),
            self.source.store.log_accumulator(),
            "the checkpoint's fold is at ITS height, not the source's current one -- the joiner is "
            "at the checkpoint and catches up from there",
        )

    def test_adoption_never_steps_back(self):
        joiner = self._walked()
        self.assertIsNone(joiner.adopted_at(self.ck))
        older = ops.Compaction(
            0, self.ck.height - 5, self.ck.acc_state, crypto.ACC_IDENTITY, self.ck.root
        )

        self.assertIsNone(joiner.adopted_at(older))

        self.assertEqual(joiner.head(), self.ck.height, "an older checkpoint moved it backwards")


class TestANodeRejoinsByItself(unittest.TestCase):
    """THE POINT OF ALL OF IT, driven by nothing but `tick`.

    Every part of the state walk was tested by calling it. Nothing called it: `bootstrap` had no
    caller in the round, so a node too far behind to catch up sat asking for entries no one holds,
    for ever, and the failure was indistinguishable from a quiet network. Here the round does it.

    The absent node misses a whole collection, so the entries it needs are gone from every log in
    the cluster. It cannot be told what it missed; it has to take state instead."""

    WIDTH = 8
    AGE = DEFAULT.mempool.w_admit + DEFAULT.mempool.w_valid_margin + DELTA

    def setUp(self):
        self.c = Cluster()
        self.client = self.c.mgr
        for node in self.c.nodes:
            node.store.SEGMENT_WIDTH = self.WIDTH
        self.away = len(self.c.nodes) - 1
        self.present = [i for i in range(len(self.c.nodes)) if i != self.away]

    def _churn_without_it(self) -> int:
        """Write, relocate and collect while one node is off. Two of three is a quorum, so the
        cluster makes progress without it — which is why it can fall this far behind at all."""
        now = T0
        for i in range(12):
            tx = ops.writes(ops.Set(D, crypto.h(b"hot"), f"v{i}".encode())).sign(self.client, now)
            self.c.submit(self.client, tx, to=self.present[i % len(self.present)], now=now)
            self.c.pump_without(now, {self.away})
            now += DELTA
            self.c.pump_without(now, {self.away})
        # HOUSEKEEPING IS NOT DRIVEN BY THE TEST. `tick` migrates and collects on its own, so all
        # this does is let time pass the dedup floor and keep ticking. A test that drove the
        # collection itself would prove the collection works and say nothing about whether the
        # cluster performs one.
        now += self.AGE
        for _ in range(8):
            now += DELTA
            self.c.pump_without(now, {self.away})
        assert self.c.nodes[self.present[0]].store.checkpoint() is not None, (
            "the cluster never collected, so nothing is behind any horizon"
        )
        return now

    def test_a_node_that_missed_a_collection_rejoins_from_the_round_alone(self):
        now = self._churn_without_it()
        rip = self.c.nodes[self.away]
        live = self.c.nodes[self.present[0]]
        self.assertLess(rip.store.head(), live.store.retained_from(), "it is not actually stranded")
        self.assertIsNone(rip.store.checkpoint(), "it already knows about the collection")

        # It comes back. Nobody tells it anything: it ticks, like every other node.
        for _ in range(8):
            now += DELTA
            self.c.pump(now)

        self.assertEqual(rip.store.state_root(), live.store.state_root(), "it did not converge")
        self.assertEqual(rip.store.accumulator(), live.store.accumulator())
        self.assertGreaterEqual(
            rip.store.head(), live.store.retained_from(), "it is still behind the frontier"
        )

    def test_it_took_state_rather_than_being_told_the_entries(self):
        """The distinction the whole horizon exists for. The entries between its head and the
        frontier were collected everywhere, so no `PULL` could have produced this state — it can
        only have come from a walk checked against a root the quorum signed."""
        now = self._churn_without_it()
        rip = self.c.nodes[self.away]
        stranded_at = rip.store.head()

        for _ in range(8):
            now += DELTA
            self.c.pump(now)

        held = rip.store.get(D, crypto.h(b"hot"))
        assert held is not None, "the value never arrived"
        self.assertEqual(held.value, b"v11", "it holds a stale value")
        self.assertEqual(
            tuple(rip.store.entries(stranded_at + 1, 1)),
            (),
            "it was handed entries that no log retains",
        )

    def test_a_node_that_is_merely_behind_catches_up_instead(self):
        """The cheap path stays the default: a walk moves the whole state, so it must fire only
        when the log genuinely cannot reach a node. Nothing was collected here."""
        now = T0
        for i in range(3):
            tx = ops.writes(ops.Set(D, crypto.h(b"warm"), f"v{i}".encode())).sign(self.client, now)
            self.c.submit(self.client, tx, to=self.present[0], now=now)
            self.c.pump_without(now, {self.away})
            now += DELTA
            self.c.pump_without(now, {self.away})
        rip = self.c.nodes[self.away]

        for _ in range(4):
            now += DELTA
            self.c.pump(now)

        self.assertIsNone(rip.walking, "it started a walk it did not need")
        self.assertEqual(rip.store.state_root(), self.c.nodes[0].store.state_root())


if __name__ == "__main__":
    unittest.main()
