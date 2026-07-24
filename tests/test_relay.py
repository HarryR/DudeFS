# M4 §7.3 — a linearizable read survives RELAY through one reachable node.
#
# The client reaches only node R; R forwards its peers' signed frontier bundles.
# Because a bundle's signature is over its content (heads ‖ checkpoint ‖ epoch ‖
# floor), `q` verifiable bundles establish the same finality frontier whether
# fetched directly or relayed — the pipe adds no trust. Staleness is conservative
# (floors are monotone lower bounds), so a lagging relay costs freshness, never
# safety (PROTOCOL §7.3 / §1.2).

import unittest

from dudefs import artifacts as A
from dudefs import crypto as C
from dudefs import fold
from dudefs.acceptor import Acceptor
from dudefs.store import ChainStore
from tests._builders import World
from tests._gossip import pull_op

DELTA = 5
SUBMIT = 10_000  # the write is dated here (inside the skew window at submit time)
READ = 10_050  # time advances so floors pass the write's hlc -> it can be final


def _cluster(n):
    nodes = []
    for i in range(n):
        sk = bytes([200 + i] * 32)
        nodes.append(Acceptor(C.SoftwareKeypair.from_seed(sk), ChainStore(), 0, DELTA))
    return nodes, [nd.node.public for nd in nodes]


def _finality_frontier(bundles, quorum):
    """The highest hlc a quorum of bundles attests: the q-th largest floor
    (mirrors quorum.Finalize — a conservative monotone lower bound)."""
    floors = sorted((b.floor for b in bundles), reverse=True)
    return floors[quorum - 1]


class TestRelayRead(unittest.TestCase):
    def _commit_write(self, nodes, roster, attest=None):
        """Seed committed state: the client's authorizing cert + a blind write
        SET k=V, committed to a QC on every node. Durably advance the floor past
        the write on the `attest` nodes (default all)."""
        attest = range(len(nodes)) if attest is None else attest
        w = World(seed=5, n_clients=1)
        control = w.control_ops  # manager cert-issue chain (authorizes the client)
        txn = A.Txn(slot=None, guards=[], mutations=[[A.Mutation.SET, b"k", b"V"]])
        write = w.data_op(0, txn=txn, slot_tag=None, hlc=A.HLC(SUBMIT, 0))
        idx = {p: i for i, p in enumerate(roster)}
        recs = []
        for nd in nodes:
            with nd.store.write_txn() as tx:
                for op in control:
                    tx.append(op)
            r = nd.on_submit(write, SUBMIT)
            assert isinstance(r, A.Receipt)
            recs.append(r)
        qc = A.QC.assemble(recs, len(nodes), idx)
        for nd in nodes:
            with nd.store.write_txn() as tx:
                tx.put_qc(qc)
        for i in attest:
            nodes[i].issue_watermark(READ)  # floor = READ − δ ≥ write.hlc
        return w, control, write, qc

    def test_linearizable_read_survives_relay(self):
        nodes, roster = _cluster(3)
        q = A.quorum_size(3)
        w, control, write, _qc = self._commit_write(nodes, roster)

        # every node issues a signed frontier bundle; the client reaches only R=0,
        # which relays the peers' bundles it holds.
        relay = nodes[0]
        relayed = [nd.issue_frontier(READ) for nd in nodes]  # forwarded via R

        # 1. relayed bundles verify identically to direct — the sig is over the
        #    content, not the pipe.
        self.assertTrue(all(b.verify() for b in relayed))
        self.assertGreaterEqual(len({b.signer for b in relayed} & set(roster)), q)

        # 2. q verifiable bundles establish the finality frontier; the write is final
        frontier = _finality_frontier(relayed, q)
        self.assertLessEqual(write.hlc, frontier)

        # 3. intersection: every op committed below the frontier is covered by some
        #    bundle's heads, so the client knows to pull the write.
        self.assertTrue(any(write.author in b.heads for b in relayed))

        # 4. PULL what we lack through the relay, then fold locally -> the value.
        reader = ChainStore()
        for op in control:
            pull_op(reader, relay.store, op.op_hash)
        pull_op(reader, relay.store, write.op_hash)
        with reader.read_txn() as tx:
            reader_ops = tx.all_ops()
        r = fold.fold(reader_ops, w.keyring, w.genesis)
        self.assertEqual(r.state[b"k"], b"V")

        # 5. path independence: a DIRECT quorum read yields the identical frontier.
        direct = [nodes[i].issue_frontier(READ) for i in range(q)]
        self.assertEqual(_finality_frontier(direct, q), frontier)

    def test_lagging_relay_is_conservative_never_unsafe(self):
        # node 2 lags: it never attested past the write and its clock trails. A
        # quorum leaning on it reports a LOWER frontier — it may not yet call the
        # write final, but it never calls an uncommitted op final.
        nodes, roster = _cluster(3)
        q = A.quorum_size(3)
        _w, _c, write, _qc = self._commit_write(nodes, roster, attest={0, 1})
        fresh = [nodes[i].issue_frontier(READ) for i in (0, 1)]  # floor READ − δ
        lagging = nodes[2].issue_frontier(SUBMIT)  # clock trails -> floor SUBMIT − δ

        # a fresh quorum {0,1} finalizes the write
        self.assertLessEqual(write.hlc, _finality_frontier(fresh, q))
        # a pair leaning on the laggard is strictly lower AND does not finalize the
        # write — conservative: never above the fresh frontier, never falsely final.
        mixed = _finality_frontier([fresh[0], lagging], 2)
        self.assertLess(mixed, _finality_frontier(fresh, q))
        self.assertLess(mixed, write.hlc)


if __name__ == "__main__":
    unittest.main()
