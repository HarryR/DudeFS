# The fault-injecting carrier + driver, tested in isolation (IMPLEMENTATION §4):
# a single Commit/Finalize must survive seeded loss / duplication / reorder /
# delay, and the run must be reproducible from its seed.

import random
import unittest

from dudefs import artifacts as A
from dudefs import quorum as Q
from dudefs.transports.memory import (
    CLIENT,
    Faults,
    Link,
    MemoryTransport,
    NetworkLinks,
    Scheduler,
    drive,
)
from tests._builders import World
from tests._cluster import cfg_for, creation_op, make_cluster

NO_FAULTS = Faults()  # frozen singleton — safe as a default (ruff B008)


def _setup(seed, n=3, faults=NO_FAULTS, delta=10_000, n_clients=2, links=None):
    sched = Scheduler()
    w = World(seed=seed, n_clients=n_clients)
    nodes, roster = make_cluster(n, lambda: sched.now, delta)
    rng = random.Random(seed ^ 0x9E3779B9)
    return sched, w, roster, MemoryTransport(sched, nodes, faults, rng, links=links)


class TestHappyPath(unittest.TestCase):
    def test_commit_over_a_clean_link(self):
        sched, w, roster, tr = _setup(1)
        op = creation_op(w, 0, b"v")
        outcome = drive(Q.Commit(cfg_for(roster, op.author), op), tr, sched)
        self.assertIsInstance(outcome, Q.Committed)
        assert isinstance(outcome, Q.Committed)
        self.assertEqual(outcome.qc.op_hash, op.op_hash)
        self.assertTrue(outcome.qc.verify(roster))


class TestUnderChaos(unittest.TestCase):
    FAULTS = Faults(loss=0.3, dup=0.25, delay_lo=1, delay_hi=8)

    def test_commit_survives_loss_dup_reorder_delay(self):
        sched, w, roster, tr = _setup(7, faults=self.FAULTS)
        op = creation_op(w, 0, b"v")
        outcome = drive(Q.Commit(cfg_for(roster, op.author), op), tr, sched)
        self.assertIsInstance(outcome, Q.Committed)
        assert isinstance(outcome, Q.Committed)
        self.assertTrue(outcome.qc.verify(roster))  # dup receipts never corrupt the QC
        self.assertGreater(tr.dropped, 0)  # the fault injector actually fired

    def test_finality_advances_under_chaos(self):
        # δ=5: floor = now−5, so hlc 50 finalizes once sim-time passes ~55.
        sched, _w, roster, tr = _setup(3, n=5, faults=self.FAULTS, delta=5)
        outcome = drive(Q.Finalize(cfg_for(roster, b"client"), A.HLC(50, 0)), tr, sched)
        self.assertIsInstance(outcome, Q.Final)
        assert isinstance(outcome, Q.Final)
        self.assertLessEqual(A.HLC(50, 0), outcome.frontier)
        self.assertTrue(all(wm.verify() for wm in outcome.watermarks))


class TestPerLinkFaults(unittest.TestCase):
    """WP2.1: the per-directed-link fault model — asymmetry, heavy-tail spikes
    (a slow-not-failed node the hedge must mask), burst loss."""

    def test_link_model_is_directional(self):
        # an override on one direction only, and a one-way cut, are per-direction.
        rng = random.Random(5)
        slow = Link(base_ms=999, jitter_ms=0)
        net = NetworkLinks(default=Link(base_ms=2, jitter_ms=0), overrides={(0, 1): slow})
        self.assertEqual(net.plan(0, 1, rng, 0).delay_ms, 999)  # the slow direction
        self.assertEqual(net.plan(1, 0, rng, 0).delay_ms, 2)  # the reverse is default
        net.cut(0, 1, both=False)  # one-way partition: 0→1 down, 1→0 still up
        self.assertFalse(net.plan(0, 1, rng, 0).deliver)
        self.assertTrue(net.plan(1, 0, rng, 0).deliver)

    def test_heavy_tail_spike_on_one_node_is_masked_by_hedge(self):
        # node 2's links always spike to ~10s; the commit must finish via {0,1}
        # long before that — hedging masks a slow (not failed) node.
        SPIKE = Link(base_ms=2, jitter_ms=0, spike_p=1.0, spike_mult=5000)  # ~10_000ms
        net = NetworkLinks(
            default=Link(base_ms=2, jitter_ms=1),
            overrides={(CLIENT, 2): SPIKE, (2, CLIENT): SPIKE},
        )
        sched, w, roster, tr = _setup(11, links=net)
        op = creation_op(w, 0, b"v")
        outcome = drive(Q.Commit(cfg_for(roster, op.author), op), tr, sched)
        self.assertIsInstance(outcome, Q.Committed)
        self.assertLess(sched.now, 1_000)  # decided via the fast quorum, not the 10s node

    def test_burst_loss_survives(self):
        # Gilbert-Elliott burst loss on every link; the idempotent-retransmit
        # driver still commits, and the injector actually dropped messages.
        burst = Link(base_ms=2, jitter_ms=1, p_bad=0.4, p_good=0.3, bad_loss=0.9)
        net = NetworkLinks(default=burst)
        sched, w, roster, tr = _setup(9, links=net)
        op = creation_op(w, 0, b"v")
        outcome = drive(Q.Commit(cfg_for(roster, op.author), op), tr, sched)
        self.assertIsInstance(outcome, Q.Committed)
        assert isinstance(outcome, Q.Committed)
        self.assertTrue(outcome.qc.verify(roster))
        self.assertGreater(tr.dropped, 0)

    def test_asymmetric_dead_return_link_commits_via_others(self):
        # node 2's RETURN hop (2→client) is fully lost: the client never hears
        # node 2 yet commits via {0,1}. (One-way link at the protocol edge.)
        net = NetworkLinks(
            default=Link(base_ms=2, jitter_ms=1), overrides={(2, CLIENT): Link(loss=1.0)}
        )
        sched, w, roster, tr = _setup(13, links=net)
        op = creation_op(w, 0, b"v")
        outcome = drive(Q.Commit(cfg_for(roster, op.author), op), tr, sched)
        self.assertIsInstance(outcome, Q.Committed)
        assert isinstance(outcome, Q.Committed)
        self.assertTrue(outcome.qc.verify(roster))


class TestDeterminism(unittest.TestCase):
    def test_same_seed_replays_identically(self):
        def run_once():
            sched, w, roster, tr = _setup(42, faults=Faults(loss=0.2, dup=0.3, delay_hi=6))
            op = creation_op(w, 0, b"v")
            outcome = drive(Q.Commit(cfg_for(roster, op.author), op), tr, sched)
            return outcome, tr.sent, tr.dropped, sched.now

        a = run_once()
        b = run_once()
        self.assertIsInstance(a[0], Q.Committed)
        self.assertEqual(a[1:], b[1:])  # identical message counts, drops, end-time
        assert isinstance(a[0], Q.Committed) and isinstance(b[0], Q.Committed)
        self.assertEqual(a[0].qc.op_hash, b[0].qc.op_hash)


if __name__ == "__main__":
    unittest.main()
