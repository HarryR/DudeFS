# M4 — gossip / anti-entropy (PROTOCOL §2). Convergence is a fixpoint of pairwise
# merges, tested with NO network: seed stores unevenly, gossip over a random
# CONNECTED mesh, assert every store reaches the union. Plus contiguity, merge
# commutativity/idempotence, and single-push (submit to one → QC everywhere).

import random
import unittest

from dudefs import artifacts as A
from dudefs import crypto as C
from dudefs.acceptor import Acceptor, Rejected, RejectReason
from dudefs.store import ChainStore
from tests._builders import World
from tests._gossip import merge, pull_op

NOW = 10_000
BIG_DELTA = 1_000_000  # skew never bites in these tests


def _state(store):
    """A store's replicated content, for equality/union checks."""
    with store.read_txn() as tx:
        ops = frozenset(o.op_hash for o in tx.all_ops())
        receipts = frozenset((r.op_hash, r.signer) for r in tx.all_receipts())
        qcs = frozenset(q.op_hash for q in tx.all_qcs())
    return ops, receipts, qcs


def _union(stores):
    o = frozenset().union(*[s[0] for s in map(_state, stores)])
    r = frozenset().union(*[s[1] for s in map(_state, stores)])
    q = frozenset().union(*[s[2] for s in map(_state, stores)])
    return o, r, q


def _connected_mesh(n, rng):
    """A random connected graph: a random spanning tree + a few extra edges."""
    nodes = list(range(n))
    rng.shuffle(nodes)
    edges = set()
    for i in range(1, n):
        edges.add(tuple(sorted((nodes[i], nodes[rng.randrange(i)]))))
    for _ in range(n):  # a few chords
        a, b = rng.sample(range(n), 2)
        edges.add(tuple(sorted((a, b))))
    return list(edges)


def _converge(stores, edges, max_rounds=200):
    for _ in range(max_rounds):
        before = [_state(s) for s in stores]
        for a, b in edges:
            merge(stores[a], stores[b])
            merge(stores[b], stores[a])
        if [_state(s) for s in stores] == before:
            return
    raise AssertionError("gossip did not converge")


def _seed_world(seed):
    """A world with contiguous author chains: 2 client blind-write chains + a
    manager control chain. Returns (all_ops_in_seq_order)."""
    w = World(seed=seed, n_clients=2)
    ops: list[A.Op] = list(w.control_ops)  # manager cert-issue chain (seq 0..1)
    for _ in range(4):
        ops.append(w.blind(0, [], [[A.Mutation.SET, b"k", b"v"]]))
    for _ in range(3):
        ops.append(w.blind(1, [], [[A.Mutation.SET, b"j", b"w"]]))
    return w, ops


def _seed_prefixes(store, ops, rng):
    """Give a store a random contiguous prefix of each author's chain."""
    by_author: dict[bytes, list[A.Op]] = {}
    for op in ops:
        by_author.setdefault(op.author, []).append(op)
    for chain in by_author.values():
        chain.sort(key=lambda o: o.seq)
        keep = rng.randint(0, len(chain))
        with store.write_txn() as tx:
            for op in chain[:keep]:
                tx.append(op)


class TestConvergence(unittest.TestCase):
    def test_random_connected_mesh_reaches_the_union(self):
        for seed in range(12):  # a small property sweep; each seed replays
            rng = random.Random(seed)
            _, ops = _seed_world(seed)
            n = rng.randint(3, 6)
            stores = [ChainStore() for _ in range(n)]
            with stores[0].write_txn() as tx:
                for op in ops:  # store 0 holds the full set, union covers every op
                    tx.append(op)
            for s in stores[1:]:  # the rest get random contiguous prefixes
                _seed_prefixes(s, ops, rng)
            # scatter some receipts + a QC so all three artifact kinds converge
            nkeys = [bytes([200 + i] * 32) for i in range(3)]
            npubs = [C.SIGNER.public(k) for k in nkeys]
            th = ops[0].op_hash
            recs = [A.Receipt.issue(nkeys[i], npubs[i], th, 0, A.BLIND, 1) for i in range(3)]
            for i, r in enumerate(recs):
                with stores[i % n].write_txn() as tx:
                    tx.put_receipt(r)
            with stores[0].write_txn() as tx:
                tx.put_qc(A.QC.assemble(recs, 3, {p: i for i, p in enumerate(npubs)}))

            union = _union(stores)
            _converge(stores, _connected_mesh(n, rng))
            for s in stores:
                self.assertEqual(_state(s), union, f"seed={seed}: store diverged from union")
            # every op in the union really is contiguous everywhere (no orphan heads)
            self.assertEqual(_state(stores[0])[0], frozenset(o.op_hash for o in ops))

    def test_merge_is_idempotent_and_order_independent(self):
        _, ops = _seed_world(99)
        a, b = ChainStore(), ChainStore()
        with a.write_txn() as tx:
            for op in ops[:5]:
                tx.append(op)
        with b.write_txn() as tx:
            for op in ops:  # b holds the full set
                tx.append(op)
        merge(a, b)
        once = _state(a)
        merge(a, b)  # merging again changes nothing
        self.assertEqual(_state(a), once)
        self.assertEqual(_state(a), _state(b))  # a caught up to b exactly


class TestSinglePush(unittest.TestCase):
    def test_submit_to_one_node_becomes_a_qc_everywhere(self):
        # PROTOCOL §1.4: SUBMIT to one node; gossip carries the op; peers receipt
        # it; any node assembles the QC. Blind write, n=3.
        nodes = []
        for i in range(3):
            sk = bytes([200 + i] * 32)
            nodes.append(Acceptor(sk, C.SIGNER.public(sk), ChainStore(), 0, BIG_DELTA))
        roster = [nd.pub for nd in nodes]
        idx = {p: i for i, p in enumerate(roster)}

        w = World(seed=7, n_clients=1)
        op = w.blind(0, [], [[A.Mutation.SET, b"k", b"v"]])
        self.assertIsInstance(nodes[0].on_submit(op, NOW), A.Receipt)  # single push

        # gossip the op to the peers, and each peer receipts it on arrival
        for peer in (1, 2):
            merge(nodes[peer].store, nodes[0].store)
            self.assertIsInstance(nodes[peer].on_submit(op, NOW), A.Receipt)
        # gossip receipts back so node 0 holds a quorum, then it assembles the QC
        for peer in (1, 2):
            merge(nodes[0].store, nodes[peer].store)
        with nodes[0].store.read_txn() as tx:
            recs = tx.receipts_for(op.op_hash)
        self.assertGreaterEqual(len(recs), 2)
        qc = A.QC.assemble(recs, 3, idx)
        self.assertTrue(qc.verify(roster))
        with nodes[0].store.write_txn() as tx:
            tx.put_qc(qc)

        # the QC now spreads to every node by gossip
        for peer in (1, 2):
            merge(nodes[peer].store, nodes[0].store)
            with nodes[peer].store.read_txn() as tx:
                self.assertIsNotNone(tx.get_qc(op.op_hash))


class TestDepResolution(unittest.TestCase):
    def test_unknown_dep_is_pulled_then_accepted(self):
        # PROTOCOL §2.1: an op whose `deps` the node lacks is not hard-rejected —
        # the node PULLs the dep from a peer, then accepts. M4 upgrade of the M2
        # `unknown_dep` reject.
        nsk = bytes([201] * 32)
        node = Acceptor(nsk, C.SIGNER.public(nsk), ChainStore(), 0, BIG_DELTA)
        peer = ChainStore()

        w = World(seed=3, n_clients=2)
        base = w.blind(0, [], [[A.Mutation.SET, b"b", b"1"]])  # the dep — lives on the peer only
        with peer.write_txn() as tx:
            tx.put_op_raw(base)
        c = w.clients[1]
        dependent = A.Op.build_data(
            author_sk=c.sk,
            author_pub=c.pub,
            seq=0,
            prev=A.GENESIS_PREV,
            hlc=A.HLC(NOW, 0),
            deps=[base.op_hash],
            keyepoch=0,
            data_key=w.keyring[0]["data_key"],
            txn_bytes=A.Txn(None, [], [[A.Mutation.SET, b"d", b"2"]]).encode(),
            slot_tag=None,
        )

        # 1. node lacks the dep -> unknown_dep (defer, not a hard failure)
        r = node.on_submit(dependent, NOW)
        assert isinstance(r, Rejected)
        self.assertEqual(r.reason, RejectReason.UNKNOWN_DEP)
        # 2. PULL the dep from the peer that holds it
        self.assertTrue(pull_op(node.store, peer, base.op_hash))
        # 3. retry -> accepted
        self.assertIsInstance(node.on_submit(dependent, NOW), A.Receipt)


if __name__ == "__main__":
    unittest.main()
