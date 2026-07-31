# Log transfer: being handed entries, and refusing to believe them.
#
# The other half of becoming current. A walk takes STATE against a signed root; this takes HISTORY,
# which cannot be checked a chunk at a time the same way — so what matters here is the shape of a
# run (contiguous from what is owed) and what a server does when it no longer holds what was asked
# for.

from __future__ import annotations

import unittest

from ..core import codec, crypto
from ..net import Verb
from ..net.envelope import Envelope, seal
from ..net.transports import name_of
from ..node import (
    Node,
)
from ..store import Commitment, Entry, Store, attest, ops, smt
from ..store.management import P_NODE, Management
from .cluster import DELTA, T0, Cluster, D, gaps_in_the_retained_log


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

        ahead = [s for s in asleep.witness.sightings() if s.claim.head > asleep.store.head()]
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
            gaps_in_the_retained_log(asleep.store),
            (),
            "an unauthorised gap was committed into the log",
        )


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
        self.victim.witness.heard(attest.SignedAttestation.make(peer.me, lie))

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


if __name__ == "__main__":
    unittest.main()
