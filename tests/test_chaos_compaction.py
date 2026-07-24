# WP3.5 / WP4.4 — chaos scenarios that COMPOSE partitions/personas with compaction
# (they need the checkpoint-aware sim plumbing: adopt/GC hooks + cut-aware gossip).

import unittest

from dudefs import artifacts as A
from dudefs import compactor, fold
from dudefs.acceptor import Acceptor
from dudefs.crypto import SIGNER
from dudefs.store import ChainStore
from dudefs.transports.memory import Link, NetworkLinks
from tests._builders import World, cut_of
from tests._harness import Sim

NOW = 100


def _overwrite(w):
    """control + create k (first, dies) + overwrite (winner). Returns (below, first, winner)."""
    below = list(w.control_ops)
    first = w.cas(
        0, b"k", A.VERSION_ABSENT, 0, [[A.Guard.ABSENT, b"k"]], [[A.Mutation.SET, b"k", b"v1"]]
    )
    below.append(first)
    v, a = fold.fold(below, w.keyring, w.genesis).lineage(b"k")
    winner = w.cas(0, b"k", v, a, [[A.Guard.VERSION_EQ, b"k", v]], [[A.Mutation.SET, b"k", b"v2"]])
    below.append(winner)
    return below, first, winner


class TestMixedLazinessGC(unittest.TestCase):
    """WP3.5: nodes adopt one checkpoint but GC at wildly different times. Not
    malicious, just wonky. The retained-projection digest stays identical (WP1.3)
    and cut-aware gossip never re-pulls dead ops (no oscillation)."""

    def test_digests_stable_and_no_oscillation(self):
        net = NetworkLinks(default=Link(base_ms=2, jitter_ms=1))
        sim = Sim(seed=20, n=3, net=net)
        w = World(seed=20, n_clients=1)
        below, first, _winner = _overwrite(w)
        cut = cut_of(w)
        cr = compactor.compact_genesis(below, w.keyring, w.genesis, cut)
        committed = A.retained_commitment(cr.retained)
        for nd in sim.raw:  # every node holds the full below-cut history
            with nd.acc.store.write_txn() as tx:
                for o in below:
                    tx.append(o)
        sim.adopt_checkpoint(cut, committed, cr.dead)

        sim.gc(cr.dead, nodes=[0])  # node 0 GCs now; 1,2 stay lazy (mixed laziness)
        digs = []
        for nd in sim.raw:
            with nd.acc.store.read_txn() as tx:
                digs.append(tx.baseline_commitment())
        self.assertTrue(all(d == committed for d in digs))  # identical despite mixed GC

        for _ in range(3):  # cut-aware gossip must not re-introduce the dead `first`
            sim.gossip_round()
        with sim.raw[0].acc.store.read_txn() as tx:
            self.assertIsNone(tx.get_op(first.op_hash))  # no oscillation
        digs2 = []
        for nd in sim.raw:
            with nd.acc.store.read_txn() as tx:
                digs2.append(tx.baseline_commitment())
        self.assertTrue(all(d == committed for d in digs2))  # still stable

        sim.gc(cr.dead, nodes=[1, 2])  # the lazy nodes finally GC
        for _ in range(2):
            sim.gossip_round()
        self.assertTrue(sim.converged())  # all fully GC'd -> identical op sets too


class TestStaleFrontierRoster(unittest.TestCase):
    """WP4.4: a roster op whose sync_frontier sits BELOW the active cut (naming a
    GC'd envelope) must pass the possession barrier via baseline completeness
    (WP1.2 finding 11), not wedge."""

    def test_stale_frontier_below_cut_does_not_wedge(self):
        w = World(seed=21, n_clients=1)
        below, first, _winner = _overwrite(w)
        cut = cut_of(w)
        cr = compactor.compact_genesis(below, w.keyring, w.genesis, cut)
        committed = A.retained_commitment(cr.retained)

        nsk = bytes([230] * 32)
        acc = Acceptor(nsk, SIGNER.public(nsk), ChainStore(), config_epoch=0, delta_ms=10_000)
        with acc.store.write_txn() as tx:
            for o in below:
                tx.append(o)
            tx.adopt_checkpoint(cut, committed, list(cr.dead))
            tx.gc_checkpoint(list(cr.dead))
        with acc.store.read_txn() as tx:
            self.assertIsNone(tx.get_op(first.op_hash))  # first is GC'd

        rop = A.Op.build(
            author_sk=w.mgr_sk,
            author_pub=w.mgr_pub,
            cls_=A.OpClass.CONTROL,
            seq=0,
            prev=A.GENESIS_PREV,
            hlc=A.HLC(NOW, 0),
            deps=[],
            authz=b"root",
            keyepoch=0,
            payload=b"",
            slot_tag=A.roster_slot_tag(0),
        )
        # sync_frontier names the GC'd `first` (below the cut) -> possession must
        # resolve via baseline completeness, and the accept succeeds (not wedged).
        assert rop.slot_tag is not None
        sf = {w.clients[0].pub: (0, first.op_hash)}
        r = acc.on_roster_accept(rop.slot_tag, A.Ballot(1, b"m"), rop, sf, 1, NOW)
        self.assertIsInstance(r, A.Receipt)


if __name__ == "__main__":
    unittest.main()
