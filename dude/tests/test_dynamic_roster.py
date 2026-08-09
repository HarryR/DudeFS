# End-to-end: dynamic roster changes flow through the transport layer.
#
# The gap #roster-drives-peers closed: before reconciliation, a `change_roster` only
# updated state -- the affected node was in the log's roster but nobody in the cluster
# could reach them. This test asserts the reverse: a `change_roster` LANDING settles into
# every node's `postman.peers` on the very next `tick` (serial-gated, one pass per change).

from __future__ import annotations

import unittest

from dude.consensus.bootstrap import intervene
from dude.consensus.mempool import Refusal
from dude.consensus.round import Bodies, Round
from dude.core import crypto
from dude.net.address import Endpoint
from dude.net.envelope import Envelope, Verb
from dude.net.postman import Recipient
from dude.net.transports import address_of
from dude.node import Node
from dude.store import ops
from dude.store.management import P_ROSTER, Cert, MgmtWriter, NodeRecord

from .cluster import DELTA, T0, TUNABLES, Cluster


class TestRosterAdditionReachesPostman(unittest.TestCase):
    """A `change_roster(add=...)` landing on every store MUST populate the new member into
    every existing node's `postman.peers` on the next tick. Before Wave D of the network
    redesign, this was silently broken: state advanced, transports did not."""

    def test_new_node_appears_in_every_existing_postman(self):
        c = Cluster(size=3)
        # Baseline: every node has 2 peers (the other two).
        for node in c.nodes:
            self.assertEqual(len(node.postman.peers), 2, f"node {node.me.public.hex()[:6]}")
        baseline_commitment = c.nodes[0].mgmt.roster_commitment()
        assert baseline_commitment is not None
        old_serial = baseline_commitment.serial

        # Manager authors a change_roster that adds a fourth identity. Applied via
        # intervene so the roster advances immediately on every node's store without
        # needing a full consensus round in the harness.
        new_kp = crypto.Keypair.generate()
        new_endpoint = Endpoint(address_of(new_kp.public))
        mgmt_scratch = MgmtWriter(c.nodes[0].store)
        add_tx = mgmt_scratch.change_roster(
            commitment_signer=c.mgr,
            add=(
                NodeRecord(
                    new_kp.public,
                    (new_endpoint,),
                    Cert.sign_roster(c.mgr, new_kp.public),
                    frozenset(),
                ),
            ),
        ).sign(c.mgr, T0)
        for node in c.nodes:
            intervene(node.store, c.mgr, bodies=(add_tx,), bucket=999)

        # Every existing node now shows the new roster on disk.
        for node in c.nodes:
            self.assertIn(new_kp.public, node.mgmt.roster())
            after = node.mgmt.roster_commitment()
            assert after is not None
            self.assertGreater(after.serial, old_serial)
            # But peers still stale until tick reconciles.
            self.assertNotIn(new_kp.public, node.postman.peers)

        # Reconcile on tick.
        for node in c.nodes:
            node.tick(T0 + DELTA)

        # New identity is in every existing node's postman.
        for node in c.nodes:
            self.assertIn(
                new_kp.public,
                node.postman.peers,
                f"reconcile missed adding {new_kp.public.hex()[:6]} to "
                f"{node.me.public.hex()[:6]}'s postman",
            )

    def test_reconcile_is_serial_gated(self):
        """A tick that does not advance the roster serial does no full reconcile pass.
        Verified by observing `_last_reconciled_serial` stays constant across unchanged
        ticks, and advances only when a change_roster lands."""
        c = Cluster(size=3)
        node = c.nodes[0]
        first_serial = node._last_reconciled_serial
        self.assertGreater(first_serial, -1, "reconcile should have run on first tick")

        # A tick without any roster change: serial-gate short-circuits.
        node.tick(T0 + DELTA)
        self.assertEqual(node._last_reconciled_serial, first_serial)

        # After a change_roster lands, next tick advances the serial.
        add_kp = crypto.Keypair.generate()
        add_tx = (
            MgmtWriter(node.store)
            .change_roster(
                commitment_signer=c.mgr,
                add=(
                    NodeRecord(
                        add_kp.public,
                        (Endpoint(address_of(add_kp.public)),),
                        Cert.sign_roster(c.mgr, add_kp.public),
                        frozenset(),
                    ),
                ),
            )
            .sign(c.mgr, T0)
        )
        for n in c.nodes:
            intervene(n.store, c.mgr, bodies=(add_tx,), bucket=888)
        node.tick(T0 + 2 * DELTA)
        self.assertGreater(node._last_reconciled_serial, first_serial)


class TestRosterRemovalDropsPeer(unittest.TestCase):
    """`change_roster(remove=X)` landing on every store MUST cause every other node's
    postman to drop X on the next tick."""

    def test_removed_node_is_dropped_from_every_other_postman(self):
        # Start at 4 so removing one leaves us safe (n=3 not bricked).
        c = Cluster(size=4)
        victim = c.keys[3].public
        # Every non-victim node has victim in its peers (each node doesn't peer itself).
        for node in c.nodes[:3]:
            self.assertIn(victim, node.postman.peers)

        # Manager removes the victim.
        remove_tx = (
            MgmtWriter(c.nodes[0].store)
            .change_roster(
                commitment_signer=c.mgr,
                remove=(victim,),
            )
            .sign(c.mgr, T0)
        )
        for node in c.nodes:
            intervene(node.store, c.mgr, bodies=(remove_tx,), bucket=777)

        # Reconcile on tick drops victim.
        for node in c.nodes:
            node.tick(T0 + DELTA)

        for i, node in enumerate(c.nodes[:3]):
            self.assertNotIn(
                victim,
                node.postman.peers,
                f"reconcile did not drop {victim.hex()[:6]} from node[{i}]",
            )


class TestAGarbageRosterRowDoesNotStopTheNode(unittest.TestCase):
    """A manager has blanket authorship of the management store, so a hand-composed
    `ops.Set(P_ROSTER, garbage)` can land. The read side must treat the row as absent, not raise:
    `roster_commitment` had two implementations, one catching the decode error and one not, and
    the one on the tick path let a single bad row take down every node's tick thread."""

    def test_tick_survives_and_the_commitment_reads_as_absent(self):
        c = Cluster(size=3)
        node = c.nodes[0]
        poison = ops.writes(ops.Set(ops.STORE_MANAGEMENT, P_ROSTER, b"not bencode at all")).sign(
            c.mgr, T0
        )
        intervene(node.store, c.mgr, bodies=(poison,), bucket=555)

        self.assertIsNone(node.mgmt.roster_commitment())
        node.tick(T0 + DELTA)  # must not raise
        self.assertIsNotNone(node.store.roster_incomplete())


def _wire_rounds(rounds: dict[crypto.PublicKey, Round], now: int) -> None:
    """Drain every Round's outbox and deliver to targets -- test_round's `_wire` shape."""
    for src_id, src in rounds.items():
        for target, msg in src.outbox():
            for dst_id, dst in rounds.items():
                if dst_id == src_id:
                    continue
                if target is not Recipient.ALL and target != dst_id:
                    continue
                if isinstance(msg, Bodies):
                    dst.absorb(msg, src_id, msg.txs)
                else:
                    dst.receive(msg, from_=src_id, now=now)


class TestRosterRemovalRacingAnInFlightRound(unittest.TestCase):
    """The follower can adopt a roster change that removes this node between a Round's
    ratification and its promote tick. `_open_round` guards membership; promote did not:
    SettleRound's raise (a DudeError) unwound AFTER current_round was cleared and BEFORE
    settling was assigned -- swallowed at the frame boundary, the ratified slice neither
    committed nor re-admitted, and the tick simply moved on."""

    def _ratified_round_for(
        self, c: Cluster, tx: ops.SignedTransaction
    ) -> dict[crypto.PublicKey, Round]:
        """One Round per roster member, all holding `tx`, HELD/SIG exchanged for real until
        every member ratifies -- over the cluster's actual roster and chain tip."""
        roster = c.nodes[0].mgmt.roster()
        prev = c.nodes[0].store.head_block_hash()
        assert prev is not None
        rounds = {
            kp.public: Round(
                bucket=TUNABLES.mempool.bucket(T0),
                me=kp,
                roster=roster,
                prev_block=prev,
                now=T0,
                close_by=T0 + 100,
                abandon_by=T0 + 10_000,
            )
            for kp in c.keys
        }
        for r in rounds.values():
            r.add_local([tx])
        now = T0
        for _ in range(30):
            for r in rounds.values():
                r.tick(now)
            _wire_rounds(rounds, now)
            if all(r.ratified() is not None for r in rounds.values()):
                return rounds
            now += 20
        raise AssertionError("rounds failed to ratify in the harness")

    def test_promote_sits_out_when_we_were_removed_mid_round(self):
        c = Cluster(size=4)
        node = c.nodes[0]
        tx = ops.writes(ops.Set(ops.STORE_DATA, crypto.h(b"race"), b"v")).sign(c.mgr, T0)
        rounds = self._ratified_round_for(c, tx)
        node.coordinator.current_round = rounds[node.me.public]

        # The removal lands (adopted the way this file lands roster changes) BEFORE the
        # tick that would promote the ratified round.
        remove_tx = (
            MgmtWriter(node.store)
            .change_roster(commitment_signer=c.mgr, remove=(node.me.public,))
            .sign(c.mgr, T0)
        )
        intervene(node.store, c.mgr, bodies=(remove_tx,), bucket=666)
        self.assertNotIn(node.me.public, node.mgmt.roster())

        node.coordinator.tick(T0 + 200)  # must not raise
        self.assertIsNone(node.coordinator.current_round, "the round must be released")
        self.assertIsNone(node.coordinator.settling, "a non-member must not settle")
        node.tick(T0 + DELTA)  # and the node keeps ticking


class TestANonMemberRefusesSubmissions(unittest.TestCase):
    """A node outside the roster ACCEPTED submissions, then discarded its whole mempool at
    the next bucket boundary -- rotation happens before _open_round declines -- so the
    client held an ACCEPTED for a tx that vanished with no trace, no error anywhere."""

    def test_submit_to_a_non_member_is_refused_not_swallowed(self):
        c = Cluster(size=3)
        outsider = Node(crypto.Keypair.generate(), c.provisioned(), TUNABLES)
        tx = ops.writes(ops.Set(ops.STORE_DATA, crypto.h(b"k"), b"v")).sign(c.mgr, T0)
        self.assertIs(outsider.coordinator.submit(tx, T0), Refusal.NOT_IN_ROSTER)

        # Driven the way production drives it: the SUBMIT frame must leave no trace in the
        # mempool (it used to sit there until the rotation silently dropped it).
        env = Envelope(outsider.me.public, Verb.SUBMIT, b"s" * 16, tx.raw).sign(c.mgr, T0)
        outsider.receive(env.seal(), T0)
        self.assertEqual(len(outsider.mempool), 0)

        # The control: a roster member admits the same tx.
        self.assertIsNone(c.nodes[0].coordinator.submit(tx, T0))


if __name__ == "__main__":
    unittest.main()
