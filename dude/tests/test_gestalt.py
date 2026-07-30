# The gestalt: every layer, joined, in one process.
#
# Each part below has its own tests and passes them in isolation. THIS file exists to answer the
# different question — whether isolation was the right decomposition — by making a transaction go
# the whole way: client -> envelope -> seal -> transport -> postman -> mempool -> propose ->
# quorum -> settle -> log, on three nodes at once.
#
# No sockets, no threads, no sleeping. `now` is an integer the test advances, so a whole cluster's
# round is deterministic and a partition is a value.

from __future__ import annotations

import unittest

from .. import quorum
from ..core import codec, crypto
from ..core.errors import DudeError, InvariantError
from ..net import Verb
from ..net.envelope import Envelope, Frame, seal, unseal
from ..net.transports import InProc, Switchboard, address_of, name_of
from ..node import _DISPATCH, HANDLED, REPLIES, UNIMPLEMENTED, Node, _encode_slice, _slice_digest
from ..store import Commitment, Entry, Store, attest, ops, smt
from ..store.management import P_NODE, P_ROSTER, Management, Role
from ..store.store import StoreError
from ..tunables import DEFAULT

WINDOW = DEFAULT.attest.fresh_within

D = ops.STORE_DATA
M = ops.STORE_MANAGEMENT
T0 = 1_700_000_000_000
DELTA = DEFAULT.mempool.delta


class Cluster:
    """Three nodes and a switchboard. Deliberately not a fixture helper with options — a cluster you
    can configure is a cluster whose test failures need debugging first."""

    def __init__(self, size: int = 3):
        self.board = Switchboard()
        self.mgr = crypto.Keypair.generate()
        self.keys = [crypto.Keypair.generate() for _ in range(size)]
        self.nodes: list[Node] = []

        # One genesis log, replayed into each node's store, so every node starts from the SAME
        # roster and the same manager grant — membership is log state, not configuration.
        genesis = self._genesis()
        for kp in self.keys:
            store = Store()
            # PROVISIONED with the manager key before anything else: it is the axiom the rest of the
            # chain hangs from, and `adopt` refuses a checkpoint from a log it does not authorise.
            store.provision(self.mgr.public)
            # The manager's own grant has to precede the authority that checks it.
            store.apply(genesis, auth=None)
            node = Node(kp, store)
            self.board.bind(name_of(kp.public))
            self.nodes.append(node)
        for node in self.nodes:
            for other in self.keys:
                if other.public != node.me.public:
                    node.connect(other.public, InProc(name_of(node.me.public), self.board))

    def _genesis(self) -> tuple[ops.SignedTransaction, ...]:
        mgmt = Management(Store())
        tx = mgmt.authorise(
            self.mgr.public,
            Role.MANAGER,
            frozenset({M, D}),
            frozenset(),
            self.mgr.prove_possession(),
        )
        for kp in self.keys:
            tx = tx + mgmt.authorise(
                kp.public, Role.NODE, frozenset({D}), frozenset(), kp.prove_possession()
            )
            tx = tx + mgmt.add_node(kp.public, (address_of(kp.public).encode(),))
        # STEP 7: membership is stated ONCE, in the same transaction that creates the rows. A
        # `node/` row set with no commitment cannot be checked for completeness, so a verifier
        # refuses the log -- `#roster-change-is-atomic` is why both land together or neither does.
        tx = tx + mgmt.set_roster([kp.public for kp in self.keys], serial=1)
        return (tx.sign(self.mgr, T0),)

    def provisioned(self) -> Store:
        """A store as a JOINER really arrives: provisioned with the manager key, holding genesis.

        The anchor is the axiom of the bootstrap chain, so a store without one verifies nothing and
        `Store.adopt` refuses it a floor. Tests that hand-built a bare `Store()` relied on that
        check not existing."""
        s = Store()
        s.provision(self.mgr.public)
        s.apply(self._genesis(), auth=None)
        return s

    def pump(self, now: int, rounds: int = 6) -> None:
        """Advance every node, then deliver everything in flight, `rounds` times.

        Delivery is explicit rather than a side effect of sending: the switchboard queues, so
        nothing recurses and the call stack never becomes the scheduler."""
        for _ in range(rounds):
            for node in self.nodes:
                node.tick(now)
            for node in self.nodes:
                for frame in self.board.drain(name_of(node.me.public)):
                    node.receive(frame, now)

    def submit(self, client: crypto.Keypair, tx: ops.SignedTransaction, to: int, now: int) -> None:
        """A client hands a transaction to ONE node — the whole point of the protocol being that it
        needs a link to one node, not to all of them."""
        node = self.nodes[to]
        env = Envelope(node.me.public, Verb.SUBMIT, b"c" * 16, tx.raw).sign(client, now)
        node.receive(seal(env), now)


class TestGestalt(unittest.TestCase):
    def setUp(self):
        self.c = Cluster()
        self.client = self.c.mgr  # the manager is already authorised to write the data store

    def test_one_transaction_reaches_every_log(self):
        """The whole system, end to end. Submitted to node 0 only; settled on all three."""
        key = crypto.h(b"hello")
        tx = ops.writes(ops.Set(D, key, b"world")).sign(self.client, T0)

        self.c.submit(self.client, tx, to=0, now=T0)
        self.c.pump(T0)  # disseminate within the bucket
        self.c.pump(T0 + DELTA)  # the bucket closes: propose, endorse, settle

        for i, node in enumerate(self.c.nodes):
            got = node.store.get(D, key)
            assert got is not None, f"node {i} did not settle it"
            self.assertEqual(got.value, b"world", f"node {i} settled the wrong value")

    def test_every_node_settles_the_same_log(self):
        """Not merely "all have the value" — the same operations at the same indices, which is what
        the accumulator is for. Two nodes agreeing on a value while disagreeing on history is the
        failure this catches and a value check does not."""
        for n in range(3):
            tx = ops.writes(ops.Set(D, crypto.h(f"k{n}".encode()), f"v{n}".encode())).sign(
                self.client, T0 + n
            )
            self.c.submit(self.client, tx, to=n, now=T0)
        self.c.pump(T0)
        self.c.pump(T0 + DELTA)

        accs = {node.store.accumulator() for node in self.c.nodes}
        heads = {node.store.head() for node in self.c.nodes}
        self.assertEqual(len(accs), 1, "nodes disagree on state")
        self.assertEqual(len(heads), 1, "nodes disagree on log length")

    def test_a_partitioned_node_still_settles_through_the_others(self):
        """Node 2 cannot hear node 0 directly. It must still learn the transaction, because the
        client needs a link to ONE node and the rest is the cluster's problem."""
        a, c = name_of(self.c.keys[0].public), name_of(self.c.keys[2].public)
        self.c.board.cut(a, c)
        self.c.board.cut(c, a)

        key = crypto.h(b"partitioned")
        tx = ops.writes(ops.Set(D, key, b"relayed")).sign(self.client, T0)
        self.c.submit(self.client, tx, to=0, now=T0)
        self.c.pump(T0)
        self.c.pump(T0 + DELTA)

        got = self.c.nodes[2].store.get(D, key)
        self.assertIsNotNone(got, "the partitioned node never learned it")

    def test_an_unauthorised_client_is_refused_everywhere(self):
        """Authority is log state, so a stranger is refused by every node without any of them
        conferring about it."""
        stranger = crypto.Keypair.generate()
        key = crypto.h(b"nope")
        tx = ops.writes(ops.Set(D, key, b"x")).sign(stranger, T0)
        self.c.submit(stranger, tx, to=0, now=T0)
        self.c.pump(T0)
        self.c.pump(T0 + DELTA)

        for i, node in enumerate(self.c.nodes):
            self.assertIsNone(node.store.get(D, key), f"node {i} settled an unauthorised write")

    def test_garbage_costs_a_frame_and_nothing_else(self):
        """The crash-only boundary: hostile bytes are an expected outcome at a decode boundary, so
        a peer sending rubbish loses its frame while the node keeps serving."""
        node = self.c.nodes[0]
        junk = Frame(crypto.screen_tag(node.me.public, b"junk"), crypto.SealedBlob(b"junk"))
        node.receive(junk, T0)  # must not raise

        key = crypto.h(b"after-junk")
        tx = ops.writes(ops.Set(D, key, b"still-alive")).sign(self.client, T0)
        self.c.submit(self.client, tx, to=0, now=T0)
        self.c.pump(T0)
        self.c.pump(T0 + DELTA)
        self.assertIsNotNone(node.store.get(D, key), "the node stopped working after junk")

    def test_a_garbage_body_costs_a_frame_too_not_the_process(self):
        """The frame-level test above passed while this one would have killed the node, because the
        catch only covered `deliver` and a handler's first act is to DECODE a peer-supplied body.

        A STRANGER -- no grant, no roster seat, signature proving only *who* -- sends `SUBMIT` with
        twelve bytes of non-bencode. With `crashonly` installed, the escaping `CodecError` is
        `os._exit`: the unauthenticated remote kill switch that crashonly.py names as the one thing
        its typed-parsing precondition exists to prevent. `SOLICITED` is no help, since `SUBMIT` is
        not an answer to anything."""
        node = self.c.nodes[0]
        stranger = crypto.Keypair.generate()
        for body in (b"\xff\x00not-bencode", codec.encode([1, 2, 3])):  # bad tag, then bad arity
            env = Envelope(node.me.public, Verb.SUBMIT, b"c" * 16, body).sign(stranger, T0)
            node.receive(seal(env), T0)  # must not raise

        key = crypto.h(b"after-garbage-body")
        tx = ops.writes(ops.Set(D, key, b"still-alive")).sign(self.client, T0)
        self.c.submit(self.client, tx, to=0, now=T0)
        self.c.pump(T0)
        self.c.pump(T0 + DELTA)
        self.assertIsNotNone(node.store.get(D, key), "the node stopped working after a bad body")

    def test_our_error_is_structurally_not_their_error(self):
        """The boundary catches `DudeError` and nothing else, so the ONLY thing keeping our own
        broken invariants from being swallowed as "hostile input" is that they are not in that tree.

        Pinned as a type relationship rather than trusted as a convention `[H]`: if someone makes
        `InvariantError` a `DudeError` for convenience, every `except DudeError` in the codebase
        silently becomes a place where "our fold is wrong" is discarded — which is the failure the
        two-tree split exists to make unconstructible (core/errors.py)."""
        self.assertTrue(issubclass(StoreError, DudeError))
        self.assertFalse(
            issubclass(InvariantError, DudeError), "our error became catchable as theirs"
        )


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
            (store, name, value, self.source.store.prove(store, name))
            for store, name, value in self.source.store.rows_under(prefix, depth)
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
        store, name, _value, proof = rows[0]
        rows[0] = (store, name, b"not-what-was-committed", proof)

        why = wiped.adopt_state(rows, self.root)

        assert why is not None, "a value the root does not commit to was applied"
        self.assertIn("does not verify", why)
        self.assertEqual(wiped.get(store, name), None, "part of a poisoned chunk landed")

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
            (store, name, value, self.source.store.prove(store, name))
            for store, name, value in self.source.store.rows_under(b"", 0)
        ]
        assert joiner.adopt_state(rows, self.ck.root) is None
        return joiner

    def test_a_walk_that_holds_what_was_committed_is_accepted(self):
        joiner = self._walked()

        self.assertIsNone(joiner.adopted_at(self.ck))

        self.assertEqual(joiner.accumulator(), self.source.store.accumulator())
        self.assertEqual(joiner.state_root(), self.ck.root)

    def test_a_short_walk_is_refused_however_valid_each_row_was(self):
        """THE CASE THIS EXISTS FOR. Every row that arrived verified against the root — they are
        genuine rows. The walk simply did not finish, and only the fold can say so."""
        joiner = self._bare()
        rows = [
            (store, name, value, self.source.store.prove(store, name))
            for store, name, value in self.source.store.rows_under(b"", 0)
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


class TestEndorsementHasABound(unittest.TestCase):
    """`Mempool.endorsable` is the `w_valid` bound, and it had NO CALLER — so the rule whose stated
    purpose is "to stop an unguarded write being replayable indefinitely" was enforced nowhere, and
    the only thing limiting a transaction's life was an eviction horizon that also never ran."""

    def setUp(self):
        self.c = Cluster()
        self.client = self.c.mgr
        self.node, self.proposer = self.c.nodes[1], self.c.nodes[0]
        self.tx = ops.writes(ops.Set(D, crypto.h(b"aged"), b"v")).sign(self.client, T0)
        assert self.node.mempool.admit(self.tx, T0, self.node.store, self.node.mgmt) is None
        self.bucket = self.node.tunables.mempool.bucket(T0)
        self.body = _encode_slice(self.bucket, (self.tx.op_hash,))
        self.digest = _slice_digest(self.bucket, (self.tx.op_hash,))

    def _propose_at(self, when: int) -> None:
        env = Envelope(self.node.me.public, Verb.PROPOSE, b"p" * 16, self.body)
        self.node.receive(seal(env.sign(self.proposer.me, when)), when)

    def test_a_slice_inside_the_bound_is_endorsed(self):
        """The control: without this the test below would pass for any reason at all."""
        self._propose_at(T0 + DELTA)
        self.assertIn((self.bucket, self.digest), self.node.endorsements)

    def test_a_slice_past_the_bound_is_not_endorsed(self):
        """A malicious proposer sits on a transaction and offers it long after its author's window.
        Silence is the refusal, as with a wrong fold: we do not endorse, so a quorum of honest nodes
        cannot form around it."""
        late = T0 + self.node.tunables.mempool.w_valid + 1
        self.assertFalse(self.node.mempool.endorsable(self.tx, late))

        self._propose_at(late)

        self.assertNotIn((self.bucket, self.digest), self.node.endorsements)


class TestVerbCoverage(unittest.TestCase):
    """What the node does and does not answer, pinned.

    A test rather than a comment because the interesting property is that the set does not drift:
    add a `Verb` and it lands in `UNIMPLEMENTED` and this fails, instead of falling through a
    default branch and being discovered when a peer sends it."""

    def test_every_verb_is_accounted_for(self):
        self.assertEqual(HANDLED | REPLIES | UNIMPLEMENTED, frozenset(Verb))
        self.assertFalse(HANDLED & REPLIES)

    def test_the_unimplemented_set_is_exactly_mempool_dissemination(self):
        """One cluster left, and it is known work rather than an open question: `ANNOUNCE` /
        `FETCH` are MEMPOOL.md §3's flood-announce-pull-bodies dissemination. Today a transaction
        spreads by re-flooding the whole `SUBMIT`, which works and does not scale."""
        self.assertEqual(UNIMPLEMENTED, {Verb.ANNOUNCE, Verb.FETCH})

    def test_every_handled_verb_has_a_handler(self):
        """Derived, not listed: `_DISPATCH` is built from `HANDLED`, so a verb claimed as handled
        with no `_on_<verb>` fails at import rather than falling into a silent default."""
        self.assertEqual(set(_DISPATCH), HANDLED)

    def test_an_unimplemented_verb_is_ignored_not_fatal(self):
        """A peer sending a verb we have not built must cost its message and nothing more."""
        node, other = self.c.nodes[0], self.c.nodes[1]
        env = Envelope(node.me.public, Verb.FETCH, b"z" * 16).sign(other.me, T0)
        node.receive(seal(env), T0)  # must not raise

        key = crypto.h(b"after-unimplemented")
        tx = ops.writes(ops.Set(D, key, b"fine")).sign(self.client, T0)
        self.c.submit(self.client, tx, to=0, now=T0)
        self.c.pump(T0)
        self.c.pump(T0 + DELTA)
        self.assertIsNotNone(node.store.get(D, key))

    def setUp(self):
        self.c = Cluster()
        self.client = self.c.mgr


if __name__ == "__main__":
    unittest.main()


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
        self.assertEqual(_gaps_in_the_retained_log(node.store), (), "the suffix is not contiguous")

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
        joiner.store.witness(source.attestation(now))  # carries the ratified marker

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

        joiner.witness(source.attestation(now))  # the ordinary gossip path, nothing bespoke

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
        joiner.witness(attest.SignedAttestation.make(liar, told))
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
        self.assertTrue(smt.verify(ck.root, D, hot, held.value, node.store.prove(D, hot)))
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


class TestTheAngelDuty(unittest.TestCase):
    """Attestation in a cluster (#monotonicity, #cross-attestation). The point of building this
    against real nodes rather than in isolation is that the keeping is what matters: evidence has
    to end up somewhere other than the culprit."""

    def setUp(self):
        self.c = Cluster()
        self.client = self.c.mgr

    def _write(self, n: int, now: int = T0) -> int:
        for i in range(n):
            tx = ops.writes(ops.Set(D, crypto.h(f"k{i}".encode()), b"v")).sign(self.client, now)
            self.c.submit(self.client, tx, to=i % len(self.c.nodes), now=now)
            self.c.pump(now)
            now += DELTA
            self.c.pump(now)
        return now

    def test_peers_hold_evidence_the_culprit_never_gave_them(self):
        """The whole reason for cross-attestation. Accountability must not depend on a client
        having happened to be watching — the accident this catches is a snapshot restored at 04:00,
        which is precisely when nobody is."""
        now = self._write(3)
        for node in self.c.nodes:
            node.probe(now)
        self.c.pump(now)

        for i, node in enumerate(self.c.nodes):
            heard = {s.by for s in node.store.sightings()}
            peers = {n.me.public for n in self.c.nodes} - {node.me.public}
            self.assertEqual(heard, peers, f"node {i} is keeping nothing about its peers")

    def test_a_rolled_back_node_is_convicted_by_its_peers(self):
        """A restore regresses the height. Nobody prevents it; everyone can prove it afterwards,
        and conviction is terminal for the identity."""
        now = self._write(4)
        victim = self.c.nodes[0]
        for node in self.c.nodes:
            node.probe(now)
        self.c.pump(now)

        rolled_back = attest.Attestation(
            victim.store.attestation(now).seq
            + 5,  # a restored image still moves its counter forward
            1,  # ...but its head went backwards
            crypto.acc_element(b"stale"),
            crypto.acc_element(b"stale"),
        )
        signed = attest.SignedAttestation.make(victim.me, rolled_back)

        watcher = self.c.nodes[1]
        found = watcher.store.witness(signed)
        assert found is not None, "the peer did not notice a regression it had the evidence for"
        self.assertEqual(found.fault, attest.Fault.REGRESSION)
        self.assertEqual(found.culprit, victim.me.public)
        self.assertIn(victim.me.public, watcher.shunned())

    def test_evidence_is_transitive(self):
        """A node that never spoke to the culprit can still convict it: sightings are relayed
        verbatim, so the pair travels even where the link does not."""
        now = self._write(3)
        a, b, c = self.c.nodes
        self.c.board.cut(name_of(a.me.public), name_of(c.me.public))
        self.c.board.cut(name_of(c.me.public), name_of(a.me.public))

        for node in self.c.nodes:
            node.probe(now)
        self.c.pump(now)
        self.assertIsNotNone(b.store.sighting(a.me.public), "B never heard A directly")

        forged = attest.SignedAttestation.make(
            a.me,
            attest.Attestation(
                a.store.attestation(now).seq + 5,
                1,
                crypto.acc_element(b"x"),
                crypto.acc_element(b"x"),
            ),
        )
        b.store.witness(forged)
        # C asks, B answers. Evidence is PULLED like every other body in this system, so it
        # travels on the next probe round rather than being pushed at anyone.
        for node in self.c.nodes:
            node.probe(now + DELTA)
        self.c.pump(now + DELTA)
        self.assertIn(a.me.public, c.shunned(), "C could not convict a node it cannot even reach")

    def test_a_partition_convicts_nobody(self):
        """The failure mode that would eat the cluster. Cut every link and let the nodes run: they
        look stalled to each other, and staleness is not a fault."""
        now = self._write(3)
        for one in self.c.keys:
            for other in self.c.keys:
                if one.public != other.public:
                    self.c.board.cut(name_of(one.public), name_of(other.public))
        for _ in range(3):
            for node in self.c.nodes:
                node.probe(now)
            self.c.pump(now)
            now += DELTA

        for i, node in enumerate(self.c.nodes):
            self.assertEqual(node.shunned(), frozenset(), f"node {i} shunned over a partition")

    def test_an_honest_cluster_convicts_nobody(self):
        """Run the thing normally and nothing is ever proved against anyone. Stated as a test
        because the cost of a false conviction is a permanently dead paid-for node."""
        now = T0
        for _ in range(4):
            now = self._write(2, now)
            for node in self.c.nodes:
                node.probe(now)
            self.c.pump(now)
            now += DELTA

        for i, node in enumerate(self.c.nodes):
            self.assertEqual(node.shunned(), frozenset(), f"node {i} convicted an honest peer")

    def test_a_restart_does_not_convict(self):
        """The interlock, end to end: attest, drop the claim as a crash would, attest again. The
        counter skips and nothing is provable — a gap is free where reuse is fatal."""
        now = self._write(2)
        node, watcher = self.c.nodes[0], self.c.nodes[1]
        watcher.store.witness(node.attestation(now))
        node.store.attestation(now)  # built, never signed: the process died here
        self.assertIsNone(watcher.store.witness(node.attestation(now)))
        self.assertEqual(watcher.shunned(), frozenset())

    def test_a_single_node_can_be_held_to_its_own_root(self):
        """The floor is what a quorum vouches for; the root in an attestation is what ONE node
        stakes its identity on. A client can check a key against the node's current state and, if
        the node lied, keep a signed statement saying so."""
        now = self._write(4)
        node = self.c.nodes[0]
        said = node.attestation(now)
        self.assertTrue(said.verify())

        k0 = crypto.h(b"k0")
        held = node.store.get(D, k0)
        assert held is not None
        self.assertTrue(smt.verify(said.claim.root, D, k0, held.value, node.store.prove(D, k0)))
        self.assertTrue(
            smt.verify(
                said.claim.root, D, b"nothing-here", None, node.store.prove(D, b"nothing-here")
            )
        )
        self.assertFalse(
            smt.verify(said.claim.root, D, k0, b"not what it holds", node.store.prove(D, k0))
        )

    def test_the_floor_needs_more_than_one_answer(self):
        """#freshness-needs-many, in a cluster: a lone responder does not answer the freshness
        question at all, and the max is taken over f+1."""
        now = self._write(3)
        node = self.c.nodes[0]
        self.assertIsNone(node.floor(need=4, now=now), "four distinct answers do not exist here")
        for n in self.c.nodes:
            n.probe(now)
        self.c.pump(now)
        self.assertIsNotNone(node.floor(need=3, now=now))

    def test_one_link_is_enough_to_gather_the_whole_cluster(self):
        """THE SINGLE-LINK CLIENT, back in scope without a priest (#freshness-is-gathered).

        A client reaching exactly ONE node still ends up holding f+1 statements, each signed by the
        node that made it. The relay can withhold or replay; it holds no key but its own, so it
        cannot forge, and the client checks every signature itself."""
        now = self._write(3)
        for node in self.c.nodes:
            node.probe(now)
        self.c.pump(now)

        relay = self.c.nodes[0]
        bundle = relay.gathered(now)
        self.assertEqual(len({a.by for a in bundle}), 3, "one link did not reach the cluster")
        for one in bundle:
            self.assertTrue(one.verify(), "a relayed statement lost its own signature")
        self.assertIsNotNone(
            attest.attested_floor(bundle, 3, now, WINDOW, roster=list(relay.roster()))
        )

    def test_a_starved_client_sees_that_it_is_starved(self):
        """The gain, stated as the failure it prevents. A relay that goes quiet cannot make a
        client believe it is current -- the bundle it holds ages in plain sight."""
        now = self._write(3)
        for node in self.c.nodes:
            node.probe(now)
        self.c.pump(now)
        relay = self.c.nodes[0]
        bundle = relay.gathered(now)

        much_later = now + WINDOW * 10
        self.assertIsNone(
            attest.attested_floor(bundle, 3, much_later, WINDOW, roster=list(relay.roster()))
        )
        self.assertIsNone(attest.staleness(bundle, much_later, WINDOW))
        self.assertEqual(attest.staleness(bundle, now + 5_000, WINDOW), 5_000)

    def test_a_node_reports_how_long_since_it_heard_from_anyone(self):
        """Peers only. A node's own statement carries the clock it is asking about, so counting it
        would report zero forever and measure nothing."""
        now = self._write(2)
        node = self.c.nodes[0]
        # Nobody called `probe` here: `tick` does it on its own cadence, which is what keeps the
        # duty from being machinery that only ever runs because a test asked it to.
        self.assertIsNotNone(node.staleness(now), "the probe cadence never fired")

        node.probe(now)
        self.c.pump(now)
        self.assertEqual(node.staleness(now), 0)
        self.assertEqual(node.staleness(now + 20_000), 20_000)
        self.assertIsNone(node.staleness(now + WINDOW * 10), "an old view still read as fresh")

    def test_a_shunned_node_cannot_make_up_the_quorum_it_is_checked_against(self):
        """Shunned keys are dropped BEFORE counting, not after — otherwise a convicted node would
        still be one of the f+1 answers that are supposed to check it."""
        now = self._write(3)
        node, victim = self.c.nodes[0], self.c.nodes[1]
        for n in self.c.nodes:
            n.probe(now)
        self.c.pump(now)
        self.assertIsNotNone(node.floor(need=3, now=now))

        node.store.witness(
            attest.SignedAttestation.make(
                victim.me,
                attest.Attestation(999, 0, crypto.acc_element(b"x"), crypto.acc_element(b"x")),
            )
        )
        self.assertIn(victim.me.public, node.shunned())
        self.assertIsNone(node.floor(need=3, now=now), "a convicted node still counted toward f+1")

    def test_the_roster_is_untouched_by_shunning(self):
        """A local read policy. Shunning must not thin the quorum — a heavily-shunned cluster
        stalls, which is the safe direction, rather than proceeding on fewer signatures."""
        self._write(2)
        node, victim = self.c.nodes[0], self.c.nodes[1]
        before = node.roster()
        node.store.witness(
            attest.SignedAttestation.make(
                victim.me,
                attest.Attestation(999, 0, crypto.acc_element(b"x"), crypto.acc_element(b"x")),
            )
        )
        self.assertIn(victim.me.public, node.shunned())
        self.assertEqual(node.roster(), before, "shunning changed the roster")
        self.assertIn(victim.me.public, node.roster())


class TestCatchUp(unittest.TestCase):
    """Log transfer (`PULL` / `ENTRIES`). A node that fell behind must be able to come back on its
    own -- out-of-band restore is forbidden, so this is the ONLY way back for a node that is merely
    behind, and the first half of the only way back for one that is wiped."""

    def setUp(self):
        self.c = Cluster()
        self.client = self.c.mgr

    def _write(self, n: int, now: int = T0, deaf=()) -> int:
        """Write `n` transactions. Nodes in `deaf` are simply not ticked or delivered to, which is
        a cleaner model of "was down" than cutting links: it misses the round entirely."""
        for i in range(n):
            tx = ops.writes(ops.Set(D, crypto.h(f"k{i}".encode()), f"v{i}".encode())).sign(
                self.client, now
            )
            self.c.submit(self.client, tx, to=_first_awake(self.c, deaf), now=now)
            for when in (now, now + DELTA):
                for node in self.c.nodes:
                    if node.me.public in deaf:
                        continue
                    node.tick(when)
                for node in self.c.nodes:
                    if node.me.public in deaf:
                        continue
                    for frame in self.c.board.drain(name_of(node.me.public)):
                        node.receive(frame, when)
            now += DELTA
        return now

    def test_a_node_that_missed_everything_catches_up(self):
        """The whole point, end to end: it slept, it woke, it asked, it is level."""
        asleep = self.c.nodes[2]
        now = self._write(4, deaf={asleep.me.public})
        self.assertLess(asleep.store.head(), self.c.nodes[0].store.head(), "it did not fall behind")

        for _ in range(4):
            for node in self.c.nodes:
                node.tick(now)
            for node in self.c.nodes:
                for frame in self.c.board.drain(name_of(node.me.public)):
                    node.receive(frame, now)
            now += DELTA

        self.assertEqual(asleep.store.head(), self.c.nodes[0].store.head())
        self.assertEqual(asleep.store.accumulator(), self.c.nodes[0].store.accumulator())
        self.assertEqual(asleep.store.state_root(), self.c.nodes[0].store.state_root())

    def test_being_behind_is_noticed_not_announced(self):
        """A node learns it is behind from the gossip it already runs -- a sighting carries the
        peer's head -- so nobody has to tell it, and nobody could lie it into a false sense of
        being level without forging a signature."""
        asleep = self.c.nodes[2]
        now = self._write(3, deaf={asleep.me.public})

        # Hand-driven rather than pumped, because a pump would close the gap in the same breath as
        # revealing it -- `tick` catches up -- and then there would be nothing left to observe.
        asleep.probe(now)
        asleep.tick(now)
        for node in self.c.nodes[:2]:
            for frame in self.c.board.drain(name_of(node.me.public)):
                node.receive(frame, now)
            node.tick(now)
        for frame in self.c.board.drain(name_of(asleep.me.public)):
            asleep.receive(frame, now)

        ahead = [s for s in asleep.store.sightings() if s.claim.head > asleep.store.head()]
        self.assertNotEqual(ahead, [], "the gossip did not reveal the gap")

    def test_a_pull_is_bounded(self):
        """A joiner asking from 1 must not pull the entire log into one message. It asks again from
        where it got to, so the bound costs round trips and never correctness."""
        now = self._write(3)
        a, b = self.c.nodes[0], self.c.nodes[1]
        env = Envelope(a.me.public, Verb.PULL, b"m" * 16, codec.encode([1])).sign(b.me, now)
        a.receive(seal(env), now)
        frames = self.c.board.drain(name_of(b.me.public))
        self.assertNotEqual(frames, [], "no reply to a PULL")

    def test_replaying_what_we_already_hold_is_refused_not_duplicated(self):
        """`replay` preserves positions, so an entry we already hold would COLLIDE rather than be
        idempotent. The filter is what makes a re-sent range harmless."""
        now = self._write(3)
        a, b = self.c.nodes[0], self.c.nodes[1]
        before = b.store.head()
        env = Envelope(b.me.public, Verb.PULL, b"m" * 16, codec.encode([1])).sign(a.me, now)
        b.receive(seal(env), now)
        for frame in self.c.board.drain(name_of(a.me.public)):
            a.receive(frame, now)  # everything here is already held
        self.assertEqual(a.store.head(), before)
        self.assertEqual(a.store.accumulator(), b.store.accumulator())

    def test_a_run_with_a_hole_in_it_is_refused(self):
        """Head unchanged, refused — never a partial commit.

        A compacted log is SUPPOSED to have gaps -- collection deletes whole segments -- so the
        invariant is not "no holes". It is that `(floor, head]` is complete: below the ratified
        floor a checkpoint authorises the absence, above it nothing does. Here nothing has been
        collected at all, so every index is owed, and a missing one is simply lost.

        Nothing used to require an `ENTRIES` run to be contiguous with our head, so the run was
        applied anyway -- and `catch_up` then asks from the NEW head, so that gap was never
        revisited and never filled.

        This is not only what a liar can send. An honest server answers a `PULL` from its own
        `entries(frm)`, which silently starts at the first index it still holds, so the far-behind
        joiner is served exactly this run by a node doing nothing wrong."""
        asleep, peer = self.c.nodes[2], self.c.nodes[0]
        now = self._write(4, deaf={asleep.me.public})
        want = asleep.store.head() + 1
        before = asleep.store.head()
        self.assertLess(asleep.store.head(), peer.store.head(), "it did not fall behind")

        run = [row for row in _run_from(peer, want) if row[0] != want + 1]
        self.assertNotIn(want + 1, [row[0] for row in run], "the run under test has no hole in it")
        env = Envelope(asleep.me.public, Verb.ENTRIES, b"z" * 16, codec.encode(run)).sign(
            peer.me, now
        )
        asleep._on_entries(env, now)  # refused, and refusing raises nothing `[H]`

        self.assertEqual(asleep.store.head(), before, "part of a holed run was committed")
        self.assertEqual(
            _gaps_in_the_retained_log(asleep.store),
            (),
            "an unauthorised gap was committed into the log",
        )


def _first_awake(c: Cluster, deaf) -> int:
    for i, node in enumerate(c.nodes):
        if node.me.public not in deaf:
            return i
    raise AssertionError("every node is deaf")


def _run_from(peer: Node, frm: int) -> list:
    """The rows an `ENTRIES` reply carries, built exactly as `_on_pull` builds them."""
    run = []
    for e in peer.store.entries(frm):
        kind = ops.KIND_COMPACTION if isinstance(e.item, ops.Compaction) else ops.KIND_TRANSACTION
        run.append([e.idx, kind, e.item.raw])
    return run


def _gaps_in_the_retained_log(store: Store) -> tuple[int, ...]:
    """Indices missing from `[retained_from, head]` — the part of the log that must be COMPLETE.

    "No holes" is the wrong invariant: collection deletes whole segments, so a compacted log is
    *supposed* to have gaps. What separates a legitimate gap from a lost entry is the HORIZON, the
    frontier of collection named by the one ratified marker the node retains. Below it absence is
    accounted for; at or above it every index is owed.

    This used the floor, which is the wrong quantity: the floor is the head at the moment of
    collecting, so it sits far ABOVE the indices that were actually forgotten. Collection being
    oldest-first is what makes a single frontier sufficient."""
    have = {e.idx for e in store.entries()}
    return tuple(i for i in range(store.retained_from(), store.head() + 1) if i not in have)


class TestTransferIsNotTrusted(unittest.TestCase):
    """Bulk transfer moves state, so it is the single richest thing to lie to. Each test here is a
    lie that WAS believed: an unsolicited run of entries could rewrite a catching-up node's roster,
    which is to say its quorum."""

    def setUp(self):
        self.c = Cluster()
        self.client = self.c.mgr
        self.victim = self.c.nodes[2]
        self.mgmt = Management(self.victim.store)

    def _forged_roster_entry(self, author, at=None):
        """A well-formed transaction that adds `author` to the roster, signed by `author`."""
        who = P_NODE + bytes(author.public)
        tx = ops.writes(
            ops.Set(ops.STORE_MANAGEMENT, who, codec.encode([[b"attacker:1234"], []]))
        ).sign(author, T0)
        idx = self.victim.store.head() + 1 if at is None else at
        return codec.encode([[idx, ops.KIND_TRANSACTION, tx.raw]])

    def test_an_unsolicited_transfer_is_dropped(self):
        """THE regression. A stranger holding no grant and no roster seat used to add itself to a
        catching-up node's roster with one frame -- and a roster is a quorum."""
        stranger = crypto.Keypair.generate()
        before = self.mgmt.node_set()
        env = Envelope(
            self.victim.me.public, Verb.ENTRIES, b"z" * 16, self._forged_roster_entry(stranger)
        ).sign(stranger, T0)
        self.victim.receive(seal(env), T0)

        self.assertEqual(self.mgmt.node_set(), before, "an unsolicited transfer was applied")
        self.assertNotIn(stranger.public, self.mgmt.node_set())

    def test_an_unsolicited_transfer_from_a_roster_member_is_dropped_too(self):
        """Being in the roster does not make a shout an answer. Solicitation is checked before
        membership, so a peer cannot push state at us either."""
        peer = self.c.keys[0]
        before = self.mgmt.node_set()
        env = Envelope(
            self.victim.me.public, Verb.ENTRIES, b"z" * 16, self._forged_roster_entry(peer)
        ).sign(peer, T0)
        self.victim.receive(seal(env), T0)
        self.assertEqual(self.mgmt.node_set(), before)

    def test_a_run_repeating_an_index_is_refused_not_a_crash(self):
        """Head unchanged, refused — and nothing raised.

        `want` is computed once before the filter loop, so two rows claiming ONE index both survived
        it and the second INSERT reached `entry.idx PRIMARY KEY`. `sqlite3.IntegrityError` is not a
        `DudeError`, so it escaped the frame boundary and took the PROCESS down -- trap 3 exactly,
        and the same shape as the duplicate-settlement crash already fixed once here.

        Two entries claiming one position is a malformed run: THEIR fault, routine, and therefore
        refused rather than raised `[H]`."""
        peer = self.c.keys[0]
        at = self.victim.store.head() + 1
        one = ops.writes(ops.Set(D, crypto.h(b"one"), b"v")).sign(self.client, T0)
        two = ops.writes(ops.Set(D, crypto.h(b"two"), b"v")).sign(self.client, T0)
        run = [[at, ops.KIND_TRANSACTION, one.raw], [at, ops.KIND_TRANSACTION, two.raw]]
        env = Envelope(self.victim.me.public, Verb.ENTRIES, b"z" * 16, codec.encode(run)).sign(
            peer, T0
        )
        before = self.victim.store.head()

        self.victim._on_entries(env, T0)  # no raise: not a crash, and not an exception either

        self.assertEqual(self.victim.store.head(), before, "half a malformed run was committed")

    def test_a_transfer_disagreeing_with_the_senders_signature_is_rolled_back(self):
        """The sender signed a head, both accumulators and a root. A run that does not reproduce
        them is refused BEFORE it commits -- not detected afterwards.

        The refusal is RETURNED, not raised `[H]`. A bounded `PULL` races the sender's own progress
        and a sighting goes stale, so this is a routine outcome of honest operation as much as a
        lie -- and raising it out of a frame handler made one peer's ordinary message able to take
        this node's process down."""
        peer, now = self.c.nodes[0], T0
        awake = self.c.nodes[:2]
        for i in range(3):  # the victim is never ticked, so it stays behind
            tx = ops.writes(ops.Set(D, crypto.h(f"k{i}".encode()), b"v")).sign(self.client, now)
            self.c.submit(self.client, tx, to=0, now=now)
            for when in (now, now + DELTA):
                for node in awake:
                    node.tick(when)
                for node in awake:
                    for frame in self.c.board.drain(name_of(node.me.public)):
                        node.receive(frame, when)
            now += DELTA
        before = self.victim.store.head()
        self.assertLess(before, peer.store.head(), "the victim is not behind")

        # A signed position that does not match the log the peer is about to send.
        real = peer.store.attestation(now)
        lie = attest.Attestation(
            real.seq,
            real.head,
            crypto.acc_element(b"not the real fold"),
            real.acc_log,
            at=real.at,
            root=real.root,
        )
        self.victim.store.witness(attest.SignedAttestation.make(peer.me, lie))

        run = []
        for e in peer.store.entries(before + 1):
            kind = (
                ops.KIND_COMPACTION if isinstance(e.item, ops.Compaction) else ops.KIND_TRANSACTION
            )
            run.append([e.idx, kind, e.item.raw])
        env = Envelope(self.victim.me.public, Verb.ENTRIES, b"z" * 16, codec.encode(run)).sign(
            peer.me, now
        )
        self.victim._on_entries(env, now)
        self.assertEqual(self.victim.store.head(), before, "a disagreeing run was committed")

    def test_the_refusal_says_which_commitment_disagreed(self):
        """The reason is returned in words a log line can carry, so "refused" and "applied" are not
        the same silence. `None` means it landed; anything else means nothing did."""
        s = Store()
        kp = crypto.Keypair.generate()
        tx = ops.writes(ops.Set(D, crypto.h(b"k"), b"v")).sign(kp, T0)
        expect = Commitment(1, crypto.ACC_IDENTITY, crypto.ACC_IDENTITY, smt.EMPTY)

        why = s.replay([Entry(1, tx)], expect)

        assert why is not None, "a disagreeing run reported success"
        self.assertIn("state", why)
        self.assertEqual(s.head(), 0, "a refused run was committed anyway")
        self.assertIsNone(s.replay([Entry(1, tx)]), "an unchecked run should apply")
