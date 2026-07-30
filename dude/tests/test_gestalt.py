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

from ..core import codec, crypto
from ..core.errors import DudeError, InvariantError
from ..net import Verb
from ..net.envelope import Envelope, Frame, seal, unseal
from ..net.transports import InProc, Switchboard, address_of, name_of
from ..node import _DISPATCH, HANDLED, REPLIES, UNIMPLEMENTED, Node
from ..store import Commitment, Entry, Store, attest, ops, smt
from ..store.management import P_NODE, Management, Role
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
            # The anchor: the manager's own grant has to precede the authority that checks it.
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
        return (tx.sign(self.mgr, T0),)

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
        """REPRODUCER — RED ON PURPOSE, and it is the open step's missing DECISION (HANDOFF.md §2).

        A joiner asks from `head+1`. If collection has deleted that range, `_on_pull` answers from
        `entries(frm)` -- which simply begins at the first index it still holds. Nobody lied and
        nothing was detected: the reply is a run with a hole at the front, which the joiner commits.

        The server has no way to say *"that range is gone, bootstrap instead"*, and the joiner has
        no way to conclude it. Until one of them can, being too far behind to catch up is
        indistinguishable from being slightly behind -- which is the whole of the work that is
        left."""
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
        self.assertNotEqual(replies, [], "no reply to a PULL")
        run = codec.as_seq(codec.decode(replies[0].env.body))
        if not run:
            return  # an empty answer is honest: it holds nothing from `frm` and said so
        first = codec.as_int(codec.as_seq(run[0], 3)[0])
        self.assertEqual(first, frm, "served a run starting past what was asked for")

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
        self.assertIsNotNone(attest.attested_floor(bundle, 3, now, WINDOW))

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
        self.assertIsNone(attest.attested_floor(bundle, 3, much_later, WINDOW))
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
            _gaps_above_the_floor(asleep.store),
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


def _gaps_above_the_floor(store: Store) -> tuple[int, ...]:
    """Indices missing from `(floor, head]` — the part of the log that must be COMPLETE.

    "No holes" is the wrong invariant and it matters: collection deletes whole segments, so a
    compacted log is *supposed* to have gaps. What separates a legitimate gap from a missing entry
    is the quorum-ratified checkpoint. Below the floor, the checkpoint is the authority and entry
    presence says nothing; above it, every index must be held, because nothing has authorised
    forgetting any of them.

    It holds whatever ORDER segments are collected in, which is why the floor is the right line to
    draw and "no holes" is not. `collect` refuses the segment holding `head+1`, so a collectable
    segment lies entirely at or below the head at the moment it is collected — and that head is the
    height its own checkpoint records. A collected index is therefore always below the floor, even
    when a straggler-blocked segment is skipped and a later one goes first."""
    floor = store.floor()
    have = {e.idx for e in store.entries()}
    return tuple(i for i in range(floor + 1, store.head() + 1) if i not in have)


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
