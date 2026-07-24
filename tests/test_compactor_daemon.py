# R6 WP-G — the compactor DRIVER, end to end against a live 3-node socket cluster: a
# Cap.COMPACT compactor syncs the log, authors a real checkpoint, blind-commits it to a
# node quorum, and the nodes adopt it. Covers the genesis pass AND the INCREMENTAL pass
# (a second checkpoint that folds only the band since the last cut).

import os
import tempfile
import threading
import time
import unittest
from functools import partial

from dudefs import artifacts as A
from dudefs import compactor
from dudefs import crypto as C
from dudefs.artifacts import VERSION_ABSENT, covered
from dudefs.client import ClientDaemon
from dudefs.compactor_daemon import CompactorDaemon
from dudefs.daemon import NodeDaemon, Peer
from tests._builders import World, now_ms, poll_until, unix_eps

DELTA = 2000  # generous skew tolerance — these tests exercise compaction, not the skew gate


class _Fixture:
    """A live 3-node socket roster + a client + an authorized compactor."""

    def __init__(self, tmp: str, seed: int):
        self.w = w = World(seed=seed, n_clients=1)
        comp_sk = bytes([150] * 32)
        self.comp_pub = C.SIGNER.public(comp_sk)
        w.control_ops.append(
            w._mgr_op(
                partial(A.CertIssueOp.build, subject=self.comp_pub, caps=[A.Cap.COMPACT], epoch=0)
            )
        )
        w.control_ops.append(
            w._mgr_op(
                partial(
                    A.WrapSetOp.build, keyepoch=0, group_key=w.masters[0], members=[self.comp_pub]
                )
            )
        )
        # a SECOND, distinct Cap.COMPACT identity — a genuine concurrent/failover compactor
        # (its own key + chain, so no equivocation) for the divergence-impossibility tests.
        comp2_sk = bytes([151] * 32)
        self.comp2_pub = C.SIGNER.public(comp2_sk)
        w.control_ops.append(
            w._mgr_op(
                partial(A.CertIssueOp.build, subject=self.comp2_pub, caps=[A.Cap.COMPACT], epoch=0)
            )
        )
        w.control_ops.append(
            w._mgr_op(
                partial(
                    A.WrapSetOp.build, keyepoch=0, group_key=w.masters[0], members=[self.comp2_pub]
                )
            )
        )
        self._comp2_sk = comp2_sk
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
        # the compactor runs on a PERSISTENT store so `restart_compactor` reopens it — the
        # restart path (in-memory prev lost, reconstructed from disk) is the critical one.
        self._comp_sk = comp_sk
        self._addrs = addrs
        self._tmp = tmp
        self._comp_store = os.path.join(tmp, "compactor.sqlite")
        self.comp = self._new_compactor()

    def _new_compactor(self) -> CompactorDaemon:
        return CompactorDaemon(
            self._comp_sk,
            self.comp_pub,
            roster=self.roster,
            roster_addrs=self._addrs,
            manager_pub=self.w.mgr_pub,
            control_ops=self.w.control_ops,
            store_path=self._comp_store,
            epoch=0,
        )

    def restart_compactor(self) -> None:
        """Simulate a compactor restart: tear the daemon down and rebuild it on the SAME
        durable store — the new instance must reconstruct its incremental prev from disk."""
        self.comp.close()
        self.comp = self._new_compactor()

    def write(self, slot, guards, muts):
        op = self.client.submit(slot, guards, muts)
        assert poll_until(lambda: self.client.status(op).phase == "committed")
        assert poll_until(lambda: not self.client.status(op).may_flip)  # final
        return op

    def make_comp2(self) -> CompactorDaemon:
        """A second, distinct-identity compactor on its own durable store (concurrent/failover)."""
        return CompactorDaemon(
            self._comp2_sk,
            self.comp2_pub,
            roster=self.roster,
            roster_addrs=self._addrs,
            manager_pub=self.w.mgr_pub,
            control_ops=self.w.control_ops,
            store_path=os.path.join(self._tmp, "compactor2.sqlite"),
            epoch=0,
        )

    def compact(self, deadline_s: float = 20.0):
        return self.compact_with(self.comp, deadline_s)

    def compact_with(self, comp, deadline_s: float = 20.0):
        # deadline-based (not a fixed iteration count): on slow CI the pass-N writes' finality
        # can take several rounds to land in the compactor's quorum-floor read. Pump the nodes
        # each round so the cluster stays converged and any frontier read is complete.
        end = time.monotonic() + deadline_s
        while time.monotonic() < end:
            for nd in self.nodes:
                nd.sync_once()
            ck = comp.compact_once()
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

    def comp_cut(self) -> dict:
        with self.comp.store.read_txn() as tx:
            return dict(tx.cut())

    def full_state_acc(self, cut) -> bytes:
        """A from-scratch compact at `cut` over the CLIENT's un-GC'd full history — the
        independent A4 oracle the incremental checkpoint must match."""
        with self.client.store.read_txn() as tx:
            ops = [o for o in tx.all_ops() if o.is_control or tx.get_qc(o.op_hash) is not None]
        below = [o for o in ops if covered(o, cut)]
        return compactor.compact_genesis(below, self.w.keyring, self.w.genesis, cut).state_acc

    def ckpt_state_acc(self, ck) -> bytes:
        with self.comp.store.read_txn() as tx:
            op = tx.get_op(ck)
        assert op is not None
        assert isinstance(op, A.CheckpointOp)
        return op.state_acc

    def ckpt_seq(self, ck) -> int:
        """The (sequence, slot binding) of a checkpoint, read from a NODE so it survives a
        compactor store swap. Asserts the seq binds its slot — the invariant adoption trusts."""
        with self.nodes[0].store.read_txn() as tx:
            op = tx.get_op(ck)
        assert op is not None
        assert isinstance(op, A.CheckpointOp)
        assert op.slot_tag == A.checkpoint_slot_tag(op.checkpoint_seq)  # seq is slot-bound
        return op.checkpoint_seq

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
                with fx.comp.store.read_txn() as tx:
                    cut1 = dict(
                        tx.cut()
                    )  # the compactor adopted its own checkpoint (state persisted)
                self.assertTrue(cut1)

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
                with fx.comp.store.read_txn() as tx:
                    cut2 = dict(tx.cut())
                self.assertTrue(
                    any(cut2[a][0] > cut1.get(a, (-1, b""))[0] for a in cut2)
                )  # the cut advanced

                # the INCREMENTAL checkpoint's state_acc must equal a from-scratch compact at
                # the same cut (A4) — proof the band-only fold is exact, not lossy. Baseline
                # is the CLIENT's UN-GC'd full history (the compactor already GC'd its dead).
                with fx.client.store.read_txn() as tx:
                    full_ops = [
                        o for o in tx.all_ops() if o.is_control or tx.get_qc(o.op_hash) is not None
                    ]
                with fx.comp.store.read_txn() as tx:
                    ck2_op = tx.get_op(ck2)
                assert ck2_op is not None
                full = compactor.compact_genesis(
                    [o for o in full_ops if covered(o, cut2)],
                    fx.w.keyring,
                    fx.w.genesis,
                    cut2,
                )
                assert isinstance(ck2_op, A.CheckpointOp)
                self.assertEqual(ck2_op.state_acc, full.state_acc)  # incremental == full

                # nodes adopt the incremental checkpoint; the newly-dead op is GC'd
                self.assertTrue(fx.adopt(ck2))
                with fx.nodes[0].store.read_txn() as tx:
                    self.assertIsNone(tx.get_op(v1))  # the superseded a1 op was GC'd
            finally:
                fx.close()


class TestCompactorRestart(unittest.TestCase):
    """The DESTRUCTIVE state machine: a compactor's incremental `prev` lives only in its
    durable store, so every restart transition (in-memory state lost -> reconstructed from
    disk -> next pass GCs against it) must preserve A4. A wrong reconstruction silently GCs
    live data, which coverage alone never catches — so each ordering asserts incremental ==
    full recompute across the restart."""

    def _create(self, fx, key, val):
        return fx.write(
            (key, VERSION_ABSENT, 0), [[A.Guard.ABSENT, key]], [[A.Mutation.SET, key, val]]
        )

    def test_restart_resumes_incremental_not_genesis(self):
        with tempfile.TemporaryDirectory() as tmp:
            fx = _Fixture(tmp, seed=43)
            try:
                self._create(fx, b"k1", b"a1")
                ck1 = fx.compact()
                self.assertIsNotNone(ck1)
                self.assertTrue(fx.adopt(ck1))
                cut1 = fx.comp_cut()

                fx.restart_compactor()  # <-- in-memory prev lost; must come back from disk
                self.assertEqual(fx.comp_cut(), cut1)  # the adopted cut survived the restart

                # new work after the restart -> an incremental pass off the reconstructed prev
                v1 = fx.client.get(b"k1")["version"]
                fx.write(
                    (b"k1", v1, 0),
                    [[A.Guard.VERSION_EQ, b"k1", v1]],
                    [[A.Mutation.SET, b"k1", b"a2"]],
                )
                self._create(fx, b"k2", b"b1")
                ck2 = fx.compact()
                self.assertIsNotNone(ck2)
                self.assertNotEqual(ck1, ck2)
                cut2 = fx.comp_cut()
                self.assertTrue(any(cut2[a][0] > cut1.get(a, (-1, b""))[0] for a in cut2))
                # A4 across the restart: the post-restart incremental == a full recompute
                self.assertEqual(fx.ckpt_state_acc(ck2), fx.full_state_acc(cut2))
                self.assertTrue(fx.adopt(ck2))
                with fx.nodes[0].store.read_txn() as tx:
                    self.assertIsNone(tx.get_op(v1))  # the superseded a1 was GC'd
            finally:
                fx.close()

    def test_restart_with_no_new_work_is_a_noop(self):
        with tempfile.TemporaryDirectory() as tmp:
            fx = _Fixture(tmp, seed=44)
            try:
                self._create(fx, b"k", b"v")
                ck1 = fx.compact()
                self.assertIsNotNone(ck1)
                fx.restart_compactor()
                # nothing new is final since the cut on disk -> the pass must SKIP, not
                # author an empty checkpoint (else a scheduled `run` churns junk every tick).
                self.assertIsNone(fx.comp.compact_once())
            finally:
                fx.close()

    def test_restart_before_first_checkpoint_does_genesis(self):
        with tempfile.TemporaryDirectory() as tmp:
            fx = _Fixture(tmp, seed=45)
            try:
                self._create(fx, b"k", b"v")  # committed, but NOT yet compacted
                fx.restart_compactor()  # store has no cut -> prev is genuinely empty
                self.assertEqual(fx.comp_cut(), {})
                ck = fx.compact()  # first checkpoint is authored AFTER the restart
                self.assertIsNotNone(ck)
                self.assertEqual(fx.ckpt_state_acc(ck), fx.full_state_acc(fx.comp_cut()))
                self.assertTrue(fx.adopt(ck))
            finally:
                fx.close()

    def test_interleaved_restarts_chain_incremental_checkpoints(self):
        # write -> compact -> RESTART, repeated: a chain of incremental checkpoints, each of
        # which must still equal a full recompute at its cut (no drift accumulates).
        with tempfile.TemporaryDirectory() as tmp:
            fx = _Fixture(tmp, seed=46)
            try:
                last = None
                for i in range(3):
                    self._create(fx, f"key{i}".encode(), f"val{i}".encode())
                    ck = fx.compact()
                    self.assertIsNotNone(ck, f"pass {i}")
                    self.assertNotEqual(ck, last)
                    self.assertEqual(fx.ckpt_state_acc(ck), fx.full_state_acc(fx.comp_cut()))
                    self.assertTrue(fx.adopt(ck))
                    last = ck
                    fx.restart_compactor()  # restart between every pass
            finally:
                fx.close()


class TestCheckpointSequencing(unittest.TestCase):
    """WP-F(c): checkpoints are SLOTTED by a monotone sequence so divergence is impossible by
    construction — the quorum decrees at most one per seq. Covers the sequence advancing across
    passes and a FAILOVER successor contending the next uncontended seq (never wedging on a
    decided one)."""

    def test_checkpoints_carry_a_monotone_bound_sequence(self):
        with tempfile.TemporaryDirectory() as tmp:
            fx = _Fixture(tmp, seed=48)
            try:
                seqs = []
                for i in range(3):  # three passes, each with new final work -> a new link
                    key = f"k{i}".encode()
                    fx.write(
                        (key, VERSION_ABSENT, 0),
                        [[A.Guard.ABSENT, key]],
                        [[A.Mutation.SET, key, b"v"]],
                    )
                    ck = fx.compact()
                    self.assertIsNotNone(ck, f"pass {i}")
                    self.assertTrue(fx.adopt(ck))
                    seqs.append(fx.ckpt_seq(ck))  # ckpt_seq also asserts the slot binding
                self.assertEqual(seqs, [0, 1, 2])  # strictly monotone, gapless
            finally:
                fx.close()

    def test_second_compactor_contends_the_next_seq_never_a_decided_one(self):
        # A SECOND, distinct compactor that never adopted the first's checkpoint must NOT
        # re-author the seq the quorum already committed — that op would only ever LOSE the
        # decided slot, wedging it forever. Reading committed checkpoints from the synced log,
        # it contends the next uncontended seq and makes progress. This is the failover/
        # concurrent case that proves one-checkpoint-per-seq holds across compactors.
        with tempfile.TemporaryDirectory() as tmp:
            fx = _Fixture(tmp, seed=49)
            comp2 = fx.make_comp2()
            try:
                fx.write(
                    (b"k0", VERSION_ABSENT, 0),
                    [[A.Guard.ABSENT, b"k0"]],
                    [[A.Mutation.SET, b"k0", b"v"]],
                )
                ck0 = fx.compact()  # compactor A commits seq 0
                self.assertIsNotNone(ck0)
                self.assertEqual(fx.ckpt_seq(ck0), 0)
                self.assertTrue(fx.adopt(ck0))

                fx.write(
                    (b"k1", VERSION_ABSENT, 0),
                    [[A.Guard.ABSENT, b"k1"]],
                    [[A.Mutation.SET, b"k1", b"v"]],
                )  # new final work so there is a dominating cut to seal at seq 1
                ck1 = fx.compact_with(comp2)  # compactor B, never adopted seq 0
                self.assertIsNotNone(ck1)
                self.assertNotEqual(ck0, ck1)
                self.assertEqual(fx.ckpt_seq(ck1), 1)  # contended seq 1, not re-tried seq 0
                self.assertTrue(fx.adopt(ck1))
            finally:
                comp2.close()
                fx.close()


if __name__ == "__main__":
    unittest.main()
