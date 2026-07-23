# M3 end-to-end (IMPLEMENTATION §6): CAS at n=3/5 over the fault-injecting
# transport, with the harness asserting the invariants that hold continuously —
# rev 5 cross-ballot B1 (at most ONE op ever decided per slot), B2 durability,
# B3 floor monotonicity. Seeds 5 (n=3) and 11 (n=5) are the two fast-path
# collision cases that minted two QCs before rev 5 dropped the fast path; they
# are kept as regression tests asserting exactly one decided op. Names carry the
# FORMAL hypothesis ids; every run is a pure function of its seed (replayable).

import random
import unittest

from dudefs import artifacts as A
from dudefs import fold
from dudefs import quorum as Q
from dudefs.sim.harness import Sim
from dudefs.store import AppendStatus
from dudefs.transports.memory import CLIENT, Faults, Link, NetworkLinks
from tests._builders import World, create
from tests._cluster import creation_op

CHAOS = Faults(loss=0.25, dup=0.2, delay_lo=1, delay_hi=6)


def _applied_winner(sim: Sim, w: World, slot: bytes):
    """Fold every op that got a QC for `slot` (with its authorizing control
    chain); return (applied_op_hashes, foldresult). The committed set is exactly
    what a client would fold — so this is the real CAS-success verdict."""
    decided = [op for h in sim.decided_ops(slot) if (op := sim.get_op(h)) is not None]
    r = fold.fold([*w.all_control(), *decided], w.keyring, w.genesis)
    applied = [h for h, v in r.verdicts.items() if v is fold.Verdict.APPLIED]
    return applied, r


class TestHappyPath(unittest.TestCase):
    def test_B1_single_cas_one_rtt(self):
        sim = Sim(seed=1, n=3)
        w = World(seed=1, n_clients=1)
        op = creation_op(w, 0, b"v")
        assert op.slot_tag is not None
        r = sim.commit(op)
        sim.run()
        self.assertIsInstance(r.outcome, Q.Committed)
        assert isinstance(r.outcome, Q.Committed)
        self.assertTrue(r.outcome.qc.verify(sim.roster))
        self.assertEqual(sim.decided_ops(op.slot_tag), {op.op_hash})  # uncontended: one QC
        self.assertTrue(sim.trace)  # transitions traced from day one


class TestContention(unittest.TestCase):
    def test_B1_two_clients_one_slot_single_decree(self):
        # Regression: seed 5 / n=3 minted two QCs under the old fast path. rev 5
        # (two-phase only) decides exactly one op; the loser learns the winner.
        sim = Sim(seed=5, n=3, faults=CHAOS)
        w = World(seed=5, n_clients=2)
        a = creation_op(w, 0, b"A")
        b = creation_op(w, 1, b"B")
        assert a.slot_tag is not None
        self.assertEqual(a.slot_tag, b.slot_tag)  # true contention on one slot
        ra, rb = sim.commit(a), sim.commit(b)
        sim.run()
        # LIVENESS (NOTES item 23, resolved): both duelers terminate — randomized
        # backoff + a round timeout keep a loser from wedging under loss.
        self.assertTrue(ra.done and rb.done)
        # SAFETY (the fast-path regression): exactly one op is ever decided for
        # the slot, cross-ballot, and it folds `applied`.
        self.assertEqual(len(sim.decided_ops(a.slot_tag)), 1)
        decided = next(iter(sim.decided_ops(a.slot_tag)))
        for o in (ra.outcome, rb.outcome):  # any client that decided agrees
            if isinstance(o, Q.LostSlot):
                self.assertEqual(o.winner, decided)
            if isinstance(o, Q.Committed):
                self.assertEqual(o.qc.op_hash, decided)
        applied, r = _applied_winner(sim, w, a.slot_tag)
        self.assertEqual(applied, [decided])
        self.assertEqual(r.state.get(b"k"), b"A" if decided == a.op_hash else b"B")

    def test_B1_contention_always_terminates_single_decree(self):
        # NOTES item 23: the dueling-proposer liveness fix (backoff + round
        # timeout) must hold across seeds, not just seed 5. Every scenario:
        # both clients terminate, and at most one op is ever decided.
        for seed in range(20):
            for n in (3, 5):
                sim = Sim(seed=seed, n=n, faults=CHAOS)
                w = World(seed=seed, n_clients=2)
                a, b = creation_op(w, 0, b"A"), creation_op(w, 1, b"B")
                ra, rb = sim.commit(a), sim.commit(b)
                sim.run()
                assert a.slot_tag is not None
                self.assertTrue(ra.done and rb.done, f"seed={seed} n={n}: a dueler wedged")
                self.assertLessEqual(len(sim.decided_ops(a.slot_tag)), 1, f"seed={seed} n={n}")


class TestSplitVoteRegression(unittest.TestCase):
    def test_B1_split_vote_recovery_converges_n5(self):
        # Two regressions in one: (1) the rev-1 deadlock — 3 proposers contend one
        # slot at n=5, recovery ballots MUST converge/terminate, never wedge; and
        # (2) the rev-5 fast-path collision — seed 11 / n=5 minted two QCs before
        # the fast path was dropped. Now exactly one op decides.
        sim = Sim(seed=11, n=5, faults=CHAOS)
        w = World(seed=11, n_clients=3)
        ops = [creation_op(w, i, bytes([65 + i])) for i in range(3)]
        slot = ops[0].slot_tag
        assert slot is not None
        runners = [sim.commit(op) for op in ops]
        sim.run()
        self.assertTrue(all(r.done for r in runners), "recovery wedged — B1 liveness")
        self.assertEqual(len(sim.decided_ops(slot)), 1)  # B1: exactly one decided
        decided = next(iter(sim.decided_ops(slot)))
        self.assertIn(decided, {op.op_hash for op in ops})
        applied, _ = _applied_winner(sim, w, slot)
        self.assertEqual(applied, [decided])


class TestPartitions(unittest.TestCase):
    """WP2.2: partitions + node↔node gossip heal. Minority writes park, the
    majority continues, and healing converges (the gossip fixpoint)."""

    def test_minority_parks_majority_commits_then_heal_converges(self):
        net = NetworkLinks(default=Link(base_ms=2, jitter_ms=1))
        sim = Sim(seed=5, n=3, net=net)
        w = World(seed=5, n_clients=2)
        MAJ, MIN = -2, -1  # two client endpoints, one on each side
        sim.partition([0], [1, 2])  # node 0 (minority) | {1,2} (majority)
        net.cut(MIN, 1)
        net.cut(MIN, 2)  # minority client reaches only node 0
        net.cut(MAJ, 0)  # majority client reaches only {1,2}

        maj = create(w, 0, b"maj", b"1")
        mino = create(w, 1, b"min", b"1")
        r_maj = sim.commit(maj, src_id=MAJ)
        r_min = sim.commit(mino, src_id=MIN, round_timeout_ms=50, max_rounds=4)
        sim.run()

        self.assertIsInstance(r_maj.outcome, Q.Committed)  # quorum {1,2} decides
        self.assertNotIsInstance(r_min.outcome, Q.Committed)  # only 1 node -> parks
        with sim.raw[0].acc.store.read_txn() as tx:
            self.assertIsNone(tx.get_op(maj.op_hash))  # node 0 hasn't seen it

        # heal + anti-entropy: node 0 catches up, every node reaches the union
        net.down.clear()
        for _ in range(4):
            sim.gossip_round()
        self.assertTrue(sim.converged())
        with sim.raw[0].acc.store.read_txn() as tx:
            self.assertIsNotNone(tx.get_op(maj.op_hash))

    def test_one_way_link_blocks_gossip_in_the_cut_direction_only(self):
        net = NetworkLinks(default=Link(base_ms=2, jitter_ms=1))
        sim = Sim(seed=6, n=3, net=net)
        w = World(seed=6, n_clients=1)
        # node 0 alone holds `solo`; cut 0→{1,2} one-way (1→0, 2→0 stay up)
        solo = create(w, 0, b"solo", b"1")
        with sim.raw[0].acc.store.write_txn() as tx:
            tx.append(solo)
        net.cut(0, 1, both=False)
        net.cut(0, 2, both=False)
        sim.gossip_round()
        # the cut direction blocks it; nodes 1,2 never learn `solo`
        with sim.raw[1].acc.store.read_txn() as tx:
            self.assertIsNone(tx.get_op(solo.op_hash))
        with sim.raw[2].acc.store.read_txn() as tx:
            self.assertIsNone(tx.get_op(solo.op_hash))
        # heal -> it propagates
        net.heal(0, 1, both=False)
        net.heal(0, 2, both=False)
        sim.gossip_round()
        with sim.raw[1].acc.store.read_txn() as tx:
            self.assertIsNotNone(tx.get_op(solo.op_hash))
        self.assertTrue(sim.converged())

    def test_flapping_partition_commit_lands_in_a_healed_window(self):
        net = NetworkLinks(default=Link(base_ms=2, jitter_ms=1))
        sim = Sim(seed=8, n=3, net=net)
        w = World(seed=8, n_clients=1)

        # flap the client's links to {1,2}: cut then heal on a 60ms cadence, so the
        # client oscillates between reaching only node 0 (no quorum) and all three.
        def flap() -> None:
            if sim.sched.now > 600:
                return
            if (CLIENT, 1) in net.down:
                net.heal(CLIENT, 1)
                net.heal(CLIENT, 2)
            else:
                net.cut(CLIENT, 1)
                net.cut(CLIENT, 2)
            sim.sched.after(60, flap)

        net.cut(CLIENT, 1)
        net.cut(CLIENT, 2)  # start cut
        sim.sched.after(60, flap)
        r = sim.commit(create(w, 0, b"k", b"1"))
        sim.run()
        self.assertIsInstance(r.outcome, Q.Committed)  # retransmit rides a healed window


class TestTimeSkew(unittest.TestCase):
    """WP2.3: per-node clock skew (offset / drift / NTP-style step jumps) feeding
    the acceptor's floor and skew gates under the sim composition."""

    def test_backward_step_jump_keeps_floor_monotone(self):
        # node 0's floor rises with the clock; an NTP-style backward step jump must
        # NOT regress the DURABLE attested floor (floor = max(computed, attested)).
        # The sim's _on_floor asserts B3 monotonicity, so finishing IS the proof.
        sim = Sim(seed=3, n=3, delta=50)
        floors: list[A.HLC] = []
        for t in (100, 200, 300, 400, 500):
            sim.sched.at(t, lambda: floors.append(sim.nodes[0].watermark().floor))
        sim.sched.at(250, lambda: sim.set_skew(0, -400))  # jump the clock back 400ms
        while sim.sched.step():
            if sim.sched.now > 600:
                break
        self.assertEqual(floors, sorted(floors))  # never regressed across the jump
        self.assertGreater(floors[-1], floors[0])  # and it did advance beforehand

    def test_a_node_running_ahead_rejects_via_the_past_gate(self):
        # node 2 runs 300ms ahead (δ=10): its finality floor sits far above a
        # normal op's hlc, so its PAST gate rejects an accept the in-sync node takes.
        sim = Sim(seed=4, n=3, delta=10, skew={2: 300})
        w = World(seed=4, n_clients=1)
        op = create(w, 0, b"k", b"1")
        assert op.slot_tag is not None
        b = A.Ballot(1, b"x")
        self.assertIsInstance(sim.nodes[0].accept(op.slot_tag, b, op), A.Receipt)  # in sync
        self.assertNotIsInstance(sim.nodes[2].accept(op.slot_tag, b, op), A.Receipt)  # ahead

    def test_commit_survives_nodes_skewed_within_delta(self):
        # nodes skewed ±50ms with δ=200 (within tolerance) still reach agreement.
        sim = Sim(seed=7, n=3, delta=200, skew={0: 50, 1: -50})
        w = World(seed=7, n_clients=1)
        r = sim.commit(create(w, 0, b"k", b"1"))
        sim.run()
        self.assertIsInstance(r.outcome, Q.Committed)


class TestA1AndB6(unittest.TestCase):
    """WP2.5: A1 (the fold is a pure function of the committed SET — byte-identical
    at quiescence regardless of assembly order) and B6 (a violation mints portable
    evidence; honest runs mint none)."""

    def test_A1_fold_is_order_independent_and_no_evidence(self):
        sim = Sim(seed=5, n=3, faults=CHAOS)
        w = World(seed=5, n_clients=2)
        a, b = creation_op(w, 0, b"A"), creation_op(w, 1, b"B")
        sim.commit(a)
        sim.commit(b)
        sim.run()
        assert a.slot_tag is not None
        decided = [op for h in sim.decided_ops(a.slot_tag) if (op := sim.get_op(h)) is not None]
        base = [*w.all_control(), *decided]
        roots = set()
        for s in range(6):
            shuffled = base[:]
            random.Random(s).shuffle(shuffled)
            roots.add(fold.state_acc(fold.fold(shuffled, w.keyring, w.genesis)))
        self.assertEqual(len(roots), 1)  # A1: one state_acc across every order
        self.assertEqual(sim.evidence(), [])  # B6: honest chaos run mints no proof

    def test_B6_a_fork_mints_portable_evidence(self):
        # the one violation an honest sim can be *fed* today: two signed ops at one
        # (author, seq). append detects it and mints self-verifying FORK evidence.
        sim = Sim(seed=9, n=3)
        w = World(seed=9, n_clients=1)
        op1 = w.blind(0, [], [[A.Mutation.SET, b"k", b"A"]])  # client 0, seq 0
        w.clients[0].seq, w.clients[0].prev = 0, A.GENESIS_PREV  # rewind -> equivocate
        op2 = w.blind(0, [], [[A.Mutation.SET, b"k", b"B"]])  # seq 0 AGAIN (a fork)
        self.assertNotEqual(op1.op_hash, op2.op_hash)
        store = sim.raw[0].acc.store
        with store.write_txn() as tx:
            self.assertTrue(tx.append(op1))
            res = tx.append(op2)
        self.assertEqual(res.status, AppendStatus.FORK)
        assert res.evidence is not None
        self.assertTrue(res.evidence.verify())  # self-verifying portable proof
        self.assertTrue(sim.evidence())  # B6: the node minted it


class TestFinalityAndVerdict(unittest.TestCase):
    def test_B3_finality_then_applied_verdict(self):
        # δ=5 so floors pass the op's small hlc quickly; clean link keeps the
        # SUBMIT inside the skew window.
        sim = Sim(seed=2, n=3, delta=5)
        w = World(seed=2, n_clients=1)
        op = creation_op(w, 0, b"v")
        assert op.slot_tag is not None
        rc = sim.commit(op)
        sim.run()
        self.assertIsInstance(rc.outcome, Q.Committed)

        rf = sim.finalize(op.hlc)
        sim.run()
        self.assertIsInstance(rf.outcome, Q.Final)
        assert isinstance(rf.outcome, Q.Final)
        self.assertLessEqual(op.hlc, rf.outcome.frontier)

        # verdict correctness: the finalized CAS folds `applied`, key holds value.
        applied, r = _applied_winner(sim, w, op.slot_tag)
        self.assertEqual(applied, [op.op_hash])
        self.assertEqual(r.verdicts[op.op_hash], fold.Verdict.APPLIED)
        self.assertEqual(r.state.get(b"k"), b"v")


if __name__ == "__main__":
    unittest.main()
