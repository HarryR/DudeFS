# R6 WP-G — the compactor DRIVER, end to end against a live 3-node socket cluster: a
# Cap.COMPACT compactor syncs the log, authors a real checkpoint, blind-commits it to a
# node quorum, and the nodes adopt it. Covers the genesis pass AND the INCREMENTAL pass
# (a second checkpoint that folds only the band since the last cut).

import os
import tempfile
import threading
import time
import unittest

from dudefs import artifacts as A
from dudefs import compactor
from dudefs import crypto as C
from dudefs.artifacts import VERSION_ABSENT
from dudefs.client import ClientDaemon
from dudefs.compactor_daemon import CompactorDaemon
from dudefs.daemon import NodeDaemon, Peer
from dudefs.handlers import control as ctl
from dudefs.store import covered
from tests._builders import World, now_ms, poll_until, unix_eps

DELTA = 150


class _Fixture:
    """A live 3-node socket roster + a client + an authorized compactor."""

    def __init__(self, tmp: str, seed: int):
        self.w = w = World(seed=seed, n_clients=1)
        comp_sk = bytes([150] * 32)
        self.comp_pub = C.SIGNER.public(comp_sk)
        w.control_ops.append(w._mgr_op(ctl.cert_issue_body(self.comp_pub, [ctl.Cap.COMPACT], 0)))
        w.control_ops.append(w._mgr_op(ctl.sealed_wrap_set_body(0, w.masters[0], [self.comp_pub])))
        node_sks = [bytes([200 + i] * 32) for i in range(3)]
        self.roster = [C.SIGNER.public(s) for s in node_sks]
        self.paths = [os.path.join(tmp, f"n{i}.sock") for i in range(3)]
        self.nodes = []
        for i in range(3):
            nd = NodeDaemon(
                node_sks[i],
                self.roster[i],
                roster=self.roster,
                manager_pub=w.mgr_pub,
                control_ops=w.control_ops,
                clock=now_ms,
                delta_ms=DELTA,
            )
            ev = threading.Event()
            threading.Thread(target=nd.serve_forever, args=(self.paths[i], ev), daemon=True).start()
            assert ev.wait(2)
            self.nodes.append(nd)
        addrs = unix_eps(self.paths)
        for i, nd in enumerate(self.nodes):  # wire node gossip so a lagging baseline fills
            nd.peers = [Peer(self.roster[j], addrs[j]) for j in range(3) if j != i]
        self.client = ClientDaemon(
            w.clients[0].sk,
            w.clients[0].pub,
            roster=self.roster,
            roster_addrs=addrs,
            manager_pub=w.mgr_pub,
            control_ops=w.control_ops,
            epoch=0,
        )
        self.comp = CompactorDaemon(
            comp_sk,
            self.comp_pub,
            roster=self.roster,
            roster_addrs=addrs,
            manager_pub=w.mgr_pub,
            control_ops=w.control_ops,
            epoch=0,
        )

    def write(self, slot, guards, muts):
        op = self.client.submit(slot, guards, muts)
        assert poll_until(lambda: self.client.status(op).phase == "committed")
        assert poll_until(lambda: not self.client.status(op).may_flip)  # final
        return op

    def compact(self):
        for _ in range(25):
            ck = self.comp.compact_once()
            if ck is not None:
                return ck
            time.sleep(0.2)
        return None

    def adopt(self, ck) -> bool:
        def done():
            for nd in self.nodes:
                nd.sync_once()
            with self.nodes[0].store.read_txn() as tx:
                return tx.get_meta("checkpoint") == ck

        return poll_until(done)

    def close(self):
        self.comp.close()
        self.client.close()
        for nd in self.nodes:
            nd.close()
        time.sleep(0.05)


class TestCompactorDriver(unittest.TestCase):
    def test_compact_once_drives_a_checkpoint_the_nodes_adopt(self):
        with tempfile.TemporaryDirectory() as tmp:
            fx = _Fixture(tmp, seed=41)
            try:
                op1 = fx.write(
                    (b"k", VERSION_ABSENT, 0),
                    [[A.Guard.ABSENT, b"k"]],
                    [[A.Mutation.SET, b"k", b"v1"]],
                )
                v1 = fx.client.get(b"k")["version"]
                fx.write(
                    (b"k", v1, 0),
                    [[A.Guard.VERSION_EQ, b"k", v1]],
                    [[A.Mutation.SET, b"k", b"v2"]],
                )  # supersedes v1 -> op1 dead
                ck = fx.compact()
                self.assertIsNotNone(ck, "compactor committed a checkpoint")
                self.assertTrue(fx.adopt(ck))
                with fx.nodes[0].store.read_txn() as tx:
                    self.assertGreater(tx.get_horizon().as_tuple(), (0, 0))  # horizon advanced
                    self.assertIsNone(tx.get_op(op1))  # the superseded op was GC'd
            finally:
                fx.close()

    def test_incremental_second_pass_equals_a_full_recompute(self):
        with tempfile.TemporaryDirectory() as tmp:
            fx = _Fixture(tmp, seed=42)
            try:
                # PASS 1 (genesis, prev=∅): create k1
                fx.write(
                    (b"k1", VERSION_ABSENT, 0),
                    [[A.Guard.ABSENT, b"k1"]],
                    [[A.Mutation.SET, b"k1", b"a1"]],
                )
                ck1 = fx.compact()
                self.assertIsNotNone(ck1)
                self.assertTrue(fx.adopt(ck1))
                self.assertIsNotNone(fx.comp._prev_cr)  # state carried forward
                cut1 = dict(fx.comp._prev_cut)

                # PASS 2 (incremental): supersede k1 (a1 dead) + create k2 in the new band
                v1 = fx.client.get(b"k1")["version"]  # the a1 op's hash — dead once superseded
                fx.write(
                    (b"k1", v1, 0),
                    [[A.Guard.VERSION_EQ, b"k1", v1]],
                    [[A.Mutation.SET, b"k1", b"a2"]],
                )
                fx.write(
                    (b"k2", VERSION_ABSENT, 0),
                    [[A.Guard.ABSENT, b"k2"]],
                    [[A.Mutation.SET, b"k2", b"b1"]],
                )
                ck2 = fx.compact()
                self.assertIsNotNone(ck2)
                assert ck2 is not None  # narrow for the type checker
                self.assertNotEqual(ck1, ck2)
                cut2 = dict(fx.comp._prev_cut)
                self.assertTrue(
                    any(cut2[a][0] > cut1.get(a, (-1, b""))[0] for a in cut2)
                )  # the cut advanced

                # the INCREMENTAL checkpoint's state_acc must equal a from-scratch compact at
                # the same cut (A4) — proof the band-only fold is exact, not lossy.
                with fx.comp.store.read_txn() as tx:
                    committed = [
                        o for o in tx.all_ops() if o.is_control or tx.get_qc(o.op_hash) is not None
                    ]
                    ck2_op = tx.get_op(ck2)
                assert ck2_op is not None
                ck2_body = ctl.decode(ck2_op)
                full = compactor.compact_genesis(
                    [o for o in committed if covered(o, cut2)],
                    fx.w.keyring,
                    fx.w.genesis,
                    cut2,
                )
                assert isinstance(ck2_body, ctl.Checkpoint)
                self.assertEqual(ck2_body.state_acc, full.state_acc)  # incremental == full

                # nodes adopt the incremental checkpoint; the newly-dead op is GC'd
                self.assertTrue(fx.adopt(ck2))
                with fx.nodes[0].store.read_txn() as tx:
                    self.assertIsNone(tx.get_op(v1))  # the superseded a1 op was GC'd
            finally:
                fx.close()


if __name__ == "__main__":
    unittest.main()
