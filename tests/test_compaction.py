# M6 — log-compaction (DESIGN §12 rev 6). A4: a bootstrap client that folds the
# RETAINED winners (mutations-only) + attempts sidecar derives byte-identical
# state to a full-history client. The resurrection and sidecar vectors MUST fail
# if their mechanism is removed — that is what proves they are load-bearing.

import os
import tempfile
import unittest

from dudefs import artifacts as A
from dudefs import compactor, crypto, fold, gossip
from dudefs.acceptor import Acceptor
from dudefs.handlers import control as ctl
from dudefs.store import AppendStatus, ChainStore
from tests._builders import World

BIG_DELTA = 1_000_000


def _cut(w):
    """The frontier of everything authored so far (per-author (seq, hash))."""
    cut = {c.pub: (c.seq - 1, c.prev) for c in w.clients if c.seq > 0}
    cut[w.mgr_pub] = (w._mseq - 1, w._mprev)
    return cut


def _boot(w, cr, control_below, tail, cut):
    """Bootstrap fold: barrier from the retained winners + sidecar, then the tail."""
    data_retained = [o for o in cr.retained if not o.is_control]
    barrier = compactor.barrier_state(data_retained, cr.attempts, w.keyring)
    return fold.fold(control_below + tail, w.keyring, w.genesis, barrier=barrier, cut_frontier=cut)


class TestA4RetainedBootstrap(unittest.TestCase):
    def test_A4_retained_bootstrap_equals_full_history(self):
        w = World(seed=1, n_clients=2)
        control = list(w.control_ops)
        below = list(control)
        # k1 written then overwritten (first write dies); k2 written once
        below.append(
            w.cas(
                0,
                b"k1",
                A.VERSION_ABSENT,
                0,
                [[A.Guard.ABSENT, b"k1"]],
                [[A.Mutation.SET, b"k1", b"v1"]],
            )
        )
        v, a = fold.fold(below, w.keyring, w.genesis).lineage(b"k1")
        below.append(
            w.cas(
                0, b"k1", v, a, [[A.Guard.VERSION_EQ, b"k1", v]], [[A.Mutation.SET, b"k1", b"v2"]]
            )
        )
        below.append(
            w.cas(
                1,
                b"k2",
                A.VERSION_ABSENT,
                0,
                [[A.Guard.ABSENT, b"k2"]],
                [[A.Mutation.SET, b"k2", b"w1"]],
            )
        )
        cut = _cut(w)

        v2, a2 = fold.fold(below, w.keyring, w.genesis).lineage(b"k1")
        tail = [
            w.cas(
                0,
                b"k1",
                v2,
                a2,
                [[A.Guard.VERSION_EQ, b"k1", v2]],
                [[A.Mutation.SET, b"k1", b"v3"]],
            )
        ]

        cr = compactor.compact(below, w.keyring, w.genesis, cut)
        ckpt = w.checkpoint(cut=cut, state_root=cr.state_root, dead=cr.dead)
        full = fold.fold(below + [ckpt] + tail, w.keyring, w.genesis)
        boot = _boot(w, cr, control, tail, cut)

        self.assertEqual(full.state, boot.state)
        self.assertEqual(full.state, {b"k1": b"v3", b"k2": b"w1"})
        self.assertIn(  # the superseded first write is dead (GC'd)
            fold.fold(below[: len(control) + 1], w.keyring, w.genesis).state, [{b"k1": b"v1"}]
        )

    def test_A4_resurrection_mask_is_a_fixpoint(self):
        # R1 adversarial finding: a retained MASK tombstone is itself replayed at
        # bootstrap, so the mask closure must reach a fixpoint (NOTES 29b: "no
        # RETAINED op mutates its key"). Chain: W sets A,B; X deletes B AND sets C;
        # Z deletes C. W is A's winner; X is retained to mask B — but X sets C, so
        # C's tombstone Z must ALSO be retained, else bootstrap resurrects C.
        w = World(seed=12, n_clients=1)
        control = list(w.control_ops)
        below = list(control)
        below.append(w.blind(0, [], [[A.Mutation.SET, b"A", b"1"], [A.Mutation.SET, b"B", b"1"]]))
        below.append(w.blind(0, [], [[A.Mutation.DEL, b"B"], [A.Mutation.SET, b"C", b"1"]]))
        z = w.blind(0, [], [[A.Mutation.DEL, b"C"]])
        below.append(z)
        cut = _cut(w)
        cr = compactor.compact(below, w.keyring, w.genesis, cut)
        ckpt = w.checkpoint(cut=cut, state_root=cr.state_root, dead=cr.dead)
        full = fold.fold(below + [ckpt], w.keyring, w.genesis)
        boot = _boot(w, cr, control, [], cut)
        self.assertEqual(boot.state, full.state)  # C not resurrected
        self.assertEqual(full.state, {b"A": b"1"})
        self.assertIn(
            z.op_hash, {o.op_hash for o in cr.retained}
        )  # C's tombstone kept via fixpoint

    def test_A4_resurrection_vector(self):
        # A retained multi-key winner (sets A and B) whose key B is later deleted
        # below the cut. WITHOUT the resurrection mask, bootstrap replays the
        # B-mutation and resurrects a key full-history clients hold deleted.
        w = World(seed=2, n_clients=2)
        control = list(w.control_ops)
        below = list(control)
        winner = w.blind(0, [], [[A.Mutation.SET, b"A", b"1"], [A.Mutation.SET, b"B", b"1"]])
        below.append(winner)
        tomb = w.blind(1, [], [[A.Mutation.DEL, b"B"]])  # B dies below the cut
        below.append(tomb)
        cut = _cut(w)

        cr = compactor.compact(below, w.keyring, w.genesis, cut)
        ckpt = w.checkpoint(cut=cut, state_root=cr.state_root, dead=cr.dead)
        full = fold.fold(below + [ckpt], w.keyring, w.genesis)
        self.assertEqual(full.state, {b"A": b"1"})  # B is gone

        boot = _boot(w, cr, control, [], cut)
        self.assertEqual(boot.state, full.state)  # mask -> B stays deleted
        self.assertIn(tomb.op_hash, {o.op_hash for o in cr.retained})  # tombstone retained as mask

        # remove the mask -> bootstrap resurrects B (the mechanism is load-bearing)
        winner_only = [o for o in cr.retained if not o.is_control and o.op_hash == winner.op_hash]
        no_mask = compactor.barrier_state(winner_only, cr.attempts, w.keyring)
        self.assertIn(b"B", no_mask)  # RESURRECTED without the mask

    def test_A4_sidecar_vector(self):
        # A live key with a NONZERO attempt at the cut (a rejected CAS consumed a
        # slot). WITHOUT the attempts sidecar, bootstrap derives attempt=0, a tail
        # CAS computes a different expected tag, and the two diverge.
        w = World(seed=3, n_clients=2)
        control = list(w.control_ops)
        below = list(control)
        below.append(
            w.cas(
                0,
                b"k",
                A.VERSION_ABSENT,
                0,
                [[A.Guard.ABSENT, b"k"]],
                [[A.Mutation.SET, b"k", b"v1"]],
            )
        )
        v, a = fold.fold(below, w.keyring, w.genesis).lineage(b"k")
        # a CAS attributed to k whose guard FAILS -> rejected, slot consumed (attempt 1)
        below.append(
            w.cas(
                1, b"k", v, a, [[A.Guard.VALUE_EQ, b"k", b"wrong"]], [[A.Mutation.SET, b"k", b"x"]]
            )
        )
        cut = _cut(w)

        v1, a1 = fold.fold(below, w.keyring, w.genesis).lineage(b"k")
        self.assertEqual(a1, 1)  # the slot was consumed
        tail = [
            w.cas(
                0, b"k", v1, a1, [[A.Guard.VERSION_EQ, b"k", v1]], [[A.Mutation.SET, b"k", b"v3"]]
            )
        ]

        cr = compactor.compact(below, w.keyring, w.genesis, cut)
        self.assertEqual(cr.attempts, {b"k": 1})  # the sidecar carries it
        ckpt = w.checkpoint(cut=cut, state_root=cr.state_root, dead=cr.dead)
        full = fold.fold(below + [ckpt] + tail, w.keyring, w.genesis)
        boot = _boot(w, cr, control, tail, cut)
        self.assertEqual(full.state, boot.state)
        self.assertEqual(full.state, {b"k": b"v3"})

        # drop the sidecar -> the tail CAS is unattributable (wrong tag) -> diverges
        data_retained = [o for o in cr.retained if not o.is_control]
        no_sidecar = compactor.barrier_state(data_retained, {}, w.keyring)
        bad = fold.fold(control + tail, w.keyring, w.genesis, barrier=no_sidecar, cut_frontier=cut)
        self.assertNotEqual(bad.state, full.state)  # diverged without the sidecar


class TestNodeGC(unittest.TestCase):
    def test_gc_drops_dead_keeps_retained(self):
        # A node applies a checkpoint's `dead` delta: superseded ops go, the
        # retained winner (and control liveness) stay (DESIGN §12).
        w = World(seed=8, n_clients=1)
        control = list(w.control_ops)
        below = list(control)
        first = w.cas(
            0, b"k", A.VERSION_ABSENT, 0, [[A.Guard.ABSENT, b"k"]], [[A.Mutation.SET, b"k", b"v1"]]
        )
        below.append(first)
        v, a = fold.fold(below, w.keyring, w.genesis).lineage(b"k")
        winner = w.cas(
            0, b"k", v, a, [[A.Guard.VERSION_EQ, b"k", v]], [[A.Mutation.SET, b"k", b"v2"]]
        )
        below.append(winner)
        cut = _cut(w)
        cr = compactor.compact(below, w.keyring, w.genesis, cut)

        store = ChainStore()
        for op in below:
            store.append(op)
        self.assertIn(first.op_hash, cr.dead)
        self.assertIn(winner.op_hash, {o.op_hash for o in cr.retained})

        store.gc_checkpoint(cr.dead)
        self.assertIsNone(store.get_op(first.op_hash))  # superseded op GC'd
        self.assertIsNotNone(store.get_op(winner.op_hash))  # retained winner kept
        self.assertIsNotNone(store.get_op(control[0].op_hash))  # control liveness kept


class TestCutAwareStore(unittest.TestCase):
    """WP1.2 (findings 1/2/11): the store's heads()/append()/possession gates
    must stay correct once the below-cut log is sparse (GC'd). Each gate ships
    with its boundary-valid-ACCEPTED case beside the reject/severed case."""

    def _creates(self, w, ci, n):
        """n independent creates by client `ci` -> seqs 0..n-1 for that author."""
        return [
            w.cas(
                ci,
                b"k%d" % i,
                A.VERSION_ABSENT,
                0,
                [[A.Guard.ABSENT, b"k%d" % i]],
                [[A.Mutation.SET, b"k%d" % i, b"v"]],
            )
            for i in range(n)
        ]

    def test_finding1_heads_serves_dense_tail_after_below_cut_gc(self):
        w = World(seed=20, n_clients=1)
        pub = w.clients[0].pub
        ops = self._creates(w, 0, 4)  # seqs 0,1,2,3
        cut = {pub: (1, ops[1].op_hash)}  # seqs 0,1 below the cut; 2,3 dense tail

        store = ChainStore()
        for o in ops:
            self.assertTrue(store.append(o))
        store.adopt_checkpoint(cut, {})
        store.gc_checkpoint([ops[0].op_hash, ops[1].op_hash])  # drop below-cut ops

        # ACCEPT: the tail is anchored at the pin and still reported in full —
        # seq-0 is gone but the author does NOT vanish (finding 1).
        self.assertEqual(store.heads()[pub], (3, ops[3].op_hash))

        # boundary: an author whose whole chain is below the cut (fully GC'd,
        # idle) reports its PIN, not nothing.
        idle = w.clients[0].pub  # reuse: build a store with only below-cut ops
        s2 = ChainStore()
        for o in ops[:2]:
            s2.append(o)
        s2.adopt_checkpoint(cut, {})
        s2.gc_checkpoint([ops[0].op_hash, ops[1].op_hash])
        self.assertEqual(s2.heads()[idle], (1, ops[1].op_hash))  # the pin itself

    def test_finding2_append_cut_exemption_is_bounded(self):
        w = World(seed=21, n_clients=1)
        pub = w.clients[0].pub
        ops = self._creates(w, 0, 4)  # seqs 0,1,2,3
        cut = {pub: (1, ops[1].op_hash)}  # cut_seq = 1

        # ACCEPT (exemption): a tail op at cut_seq+1 whose predecessor sits at the
        # cut (legitimately GC'd, absent) is contiguous-by-fiat, not a gap.
        s = ChainStore()
        s.adopt_checkpoint(cut, {})
        self.assertEqual(s.append(ops[2]).status, AppendStatus.OK)  # pred seq1 <= cut

        # REJECT (genuine gap): one seq further, at cut_seq+2, whose predecessor is
        # neither present nor below the cut, still defers.
        s2 = ChainStore()
        s2.adopt_checkpoint(cut, {})
        self.assertEqual(s2.append(ops[3]).status, AppendStatus.GAP)  # pred seq2 missing

    def test_finding11_possession_below_cut_is_baseline_completeness(self):
        # An author's below-cut envelope is GC'd; a possession barrier whose entry
        # names it must pass via baseline completeness, not wedge on the missing
        # envelope (finding 11) — the roster change would otherwise never activate.
        w = World(seed=22, n_clients=1)
        control = list(w.control_ops)
        below = list(control)
        first = w.cas(
            0, b"k", A.VERSION_ABSENT, 0, [[A.Guard.ABSENT, b"k"]], [[A.Mutation.SET, b"k", b"v1"]]
        )
        below.append(first)
        v, a = fold.fold(below, w.keyring, w.genesis).lineage(b"k")
        winner = w.cas(
            0, b"k", v, a, [[A.Guard.VERSION_EQ, b"k", v]], [[A.Mutation.SET, b"k", b"v2"]]
        )
        below.append(winner)
        cut = _cut(w)
        cr = compactor.compact(below, w.keyring, w.genesis, cut)
        committed = A.retained_commitment(cr.retained)
        self.assertIn(first.op_hash, cr.dead)

        store = ChainStore()
        for o in below:
            store.append(o)
        store.adopt_checkpoint(cut, committed)
        store.gc_checkpoint(cr.dead)
        self.assertIsNone(store.get_op(first.op_hash))  # the named envelope is gone

        sk = bytes([170] * 32)
        acc = Acceptor(sk, crypto.SIGNER.public(sk), store, config_epoch=0, delta_ms=BIG_DELTA)
        # a frontier entry BELOW the cut naming the GC'd (dead) envelope:
        sf = {w.clients[0].pub: (0, first.op_hash)}
        # ACCEPT: baseline is complete (winner + control held) -> possession holds
        self.assertTrue(acc.holds_frontier(sf))

        # REJECT (pair): a node MISSING the retained winner has an incomplete
        # baseline -> its digest diverges for that author -> possession fails.
        gap = ChainStore()
        for o in cr.retained:
            if o.op_hash != winner.op_hash:
                gap.put_op_raw(o)
        gap.adopt_checkpoint(cut, committed)
        gacc = Acceptor(sk, crypto.SIGNER.public(sk), gap, config_epoch=0, delta_ms=BIG_DELTA)
        self.assertFalse(gacc.holds_frontier(sf))

    def test_adopted_cut_survives_crash_restart(self):
        # The cut is in the durability domain (WP1.2): it re-parametrizes the
        # gates below it, so it must outlive a restart like the floor.
        w = World(seed=23, n_clients=1)
        pub = w.clients[0].pub
        cut = {pub: (2, b"\x11" * 32)}
        committed = {pub: (1, b"\x22" * 32)}
        with tempfile.TemporaryDirectory() as d:
            path = os.path.join(d, "store.db")
            s = ChainStore(path)
            s.adopt_checkpoint(cut, committed)
            s.close()
            s2 = ChainStore(path)
            self.assertEqual(s2.cut(), cut)
            self.assertEqual(s2.cut_retained(), committed)
            s2.close()


class TestCheckpointArtifact(unittest.TestCase):
    def test_checkpoint_encode_decode_roundtrip(self):
        # the rev-6 schema round-trips through the wire (golden-vector shape).
        w = World(seed=9, n_clients=1)
        below = list(w.control_ops)
        below.append(
            w.cas(
                0,
                b"k",
                A.VERSION_ABSENT,
                0,
                [[A.Guard.ABSENT, b"k"]],
                [[A.Mutation.SET, b"k", b"v"]],
            )
        )
        cut = _cut(w)
        cr = compactor.compact(below, w.keyring, w.genesis, cut)
        retained = A.retained_commitment(cr.retained)
        ckpt = w.checkpoint(
            cut=cut, state_root=cr.state_root, dead=cr.dead, retained=retained, attempts=b"ct"
        )
        body = ctl.decode(ckpt)
        assert body is not None
        self.assertEqual(body[ctl.BK_KIND], ctl.ControlKind.CHECKPOINT)
        self.assertEqual(body[b"cut"], cut)
        self.assertEqual(body[b"state_root"], cr.state_root)
        self.assertEqual(body[b"dead"], cr.dead)
        self.assertEqual(body[b"retained"], retained)
        self.assertEqual(body[b"attempts"], b"ct")

    def test_retained_digest_detects_omission_per_author(self):
        w = World(seed=10, n_clients=2)
        below = list(w.control_ops)
        below.append(
            w.cas(
                0,
                b"k",
                A.VERSION_ABSENT,
                0,
                [[A.Guard.ABSENT, b"k"]],
                [[A.Mutation.SET, b"k", b"v"]],
            )
        )
        below.append(
            w.cas(
                1,
                b"j",
                A.VERSION_ABSENT,
                0,
                [[A.Guard.ABSENT, b"j"]],
                [[A.Mutation.SET, b"j", b"w"]],
            )
        )
        cut = _cut(w)
        cr = compactor.compact(below, w.keyring, w.genesis, cut)
        commit = A.retained_commitment(cr.retained)
        # a node holding the full retained set recomputes the identical digest
        self.assertEqual(A.retained_commitment(cr.retained), commit)
        # drop one retained op -> only its author's (count, digest) changes
        dropped = cr.retained[-1]
        partial = A.retained_commitment(cr.retained[:-1])
        self.assertNotEqual(partial.get(dropped.author), commit.get(dropped.author))


class TestBaselineSync(unittest.TestCase):
    def test_sparse_baseline_syncs_and_verifies_against_checkpoint(self):
        # Below the cut the log is sparse (no receipts/QCs — the checkpoint
        # certifies commitment). A lagging node compares per-author retained
        # digests, pulls only the author it lacks (envelopes), and verifies its
        # baseline against the checkpoint's signed `retained` field (DESIGN §12).
        w = World(seed=11, n_clients=2)
        below = list(w.control_ops)
        below.append(
            w.cas(
                0,
                b"k",
                A.VERSION_ABSENT,
                0,
                [[A.Guard.ABSENT, b"k"]],
                [[A.Mutation.SET, b"k", b"v"]],
            )
        )
        below.append(
            w.cas(
                1,
                b"j",
                A.VERSION_ABSENT,
                0,
                [[A.Guard.ABSENT, b"j"]],
                [[A.Mutation.SET, b"j", b"w"]],
            )
        )
        cut = _cut(w)
        cr = compactor.compact(below, w.keyring, w.genesis, cut)
        committed = A.retained_commitment(cr.retained)  # the checkpoint's `retained` field

        # SUMMARY carries the per-author baseline digest + the active checkpoint
        src = ChainStore()
        for op in cr.retained:
            src.put_op_raw(op)
        s = gossip.summary(src, cut=cut, checkpoint=b"ckpt")
        self.assertEqual(s.retained, committed)
        self.assertEqual(s.checkpoint, b"ckpt")

        # a lagging node is missing client 1's baseline -> digest mismatch localizes
        dst = ChainStore()
        for op in cr.retained:
            if op.author != w.clients[1].pub:
                dst.put_op_raw(op)
        self.assertEqual(gossip.verify_baseline(dst, cut, committed), {w.clients[1].pub})

        # pull the missing author's sparse baseline, then it verifies complete
        self.assertGreater(gossip.pull_baseline(dst, src, cut), 0)
        self.assertEqual(gossip.verify_baseline(dst, cut, committed), set())


class TestBaselineProjection(unittest.TestCase):
    """WP1.3: below-cut completeness is compared over the RETAINED projection
    (covered ∖ dead), so a lazy-GC node agrees with a GC'd node and with the
    checkpoint's winners-only commitment. Each test pins the bug by showing the
    OLD all-covered digest gets it wrong."""

    def _overwrite_world(self, seed):
        # k written (first, dies) then overwritten (winner, retained).
        w = World(seed=seed, n_clients=1)
        below = list(w.control_ops)
        first = w.cas(
            0, b"k", A.VERSION_ABSENT, 0, [[A.Guard.ABSENT, b"k"]], [[A.Mutation.SET, b"k", b"v1"]]
        )
        below.append(first)
        v, a = fold.fold(below, w.keyring, w.genesis).lineage(b"k")
        winner = w.cas(
            0, b"k", v, a, [[A.Guard.VERSION_EQ, b"k", v]], [[A.Mutation.SET, b"k", b"v2"]]
        )
        below.append(winner)
        cut = _cut(w)
        cr = compactor.compact(below, w.keyring, w.genesis, cut)
        committed = A.retained_commitment(cr.retained)
        return w, below, cut, cr, committed, first, winner

    def test_lazy_gc_node_verifies_complete(self):
        w, below, cut, cr, committed, first, _winner = self._overwrite_world(30)
        dead = frozenset(cr.dead)
        self.assertIn(first.op_hash, dead)

        # a LAZY node: adopted the checkpoint, holds the winner AND the not-yet-GC'd
        # dead `first`.
        lazy = ChainStore()
        for o in below:
            lazy.append(o)
        lazy.adopt_checkpoint(cut, committed, cr.dead)
        self.assertIsNotNone(lazy.get_op(first.op_hash))  # dead op still physically held

        # ACCEPT: over the retained projection it is complete...
        self.assertEqual(gossip.verify_baseline(lazy, cut, committed, dead), set())
        # ...and the store's own possession digest agrees (holds_frontier path).
        self.assertEqual(lazy.baseline_commitment(), committed)
        # load-bearing: the OLD all-covered digest (no dead mask) FALSE-rejects it.
        self.assertNotEqual(gossip.verify_baseline(lazy, cut, committed), set())

    def test_gc_and_lazy_peers_converge_no_oscillation(self):
        w, below, cut, cr, committed, first, _winner = self._overwrite_world(31)
        dead = frozenset(cr.dead)

        lazy = ChainStore()  # holds winner + dead first
        for o in below:
            lazy.append(o)
        lazy.adopt_checkpoint(cut, committed, cr.dead)

        gc = ChainStore()  # adopted + physically GC'd: winner only
        for o in below:
            gc.append(o)
        gc.adopt_checkpoint(cut, committed, cr.dead)
        gc.gc_checkpoint(cr.dead)
        self.assertIsNone(gc.get_op(first.op_hash))

        # ACCEPT/converge: neither direction re-pulls the dead envelope.
        self.assertEqual(gossip.pull_baseline(gc, lazy, cut, dead), 0)
        self.assertEqual(gossip.pull_baseline(lazy, gc, cut, dead), 0)
        self.assertIsNone(gc.get_op(first.op_hash))  # gc did NOT re-acquire the dead op

        # load-bearing: WITHOUT the dead mask the GC'd node re-pulls `first` from
        # the lazy peer — the oscillation the projection fix removes.
        self.assertGreater(gossip.pull_baseline(gc, lazy, cut), 0)
        self.assertIsNotNone(gc.get_op(first.op_hash))  # re-acquired (the bug)


class TestVoidRule(unittest.TestCase):
    def test_reborn_tag_below_horizon_is_voided_on_prepare(self):
        # NOTES 27: a reborn creation tag whose old slot decision sits un-GC'd
        # below the checkpoint horizon must NOT be re-proposed (a livelock — its
        # hlc is below the floor and can never re-commit). The acceptor voids the
        # below-horizon accept on PREPARE, so the reborn op proposes itself.
        nsk = bytes([200] * 32)
        node = Acceptor(nsk, crypto.SIGNER.public(nsk), ChainStore(), 0, BIG_DELTA)
        w = World(seed=7, n_clients=1)
        tag = A.compute_slot_tag(w.keyring[0]["slot_secret"], b"k", A.VERSION_ABSENT, 0)
        ancient = w.data_op(
            0,
            txn=A.Txn(
                slot=(b"k", A.VERSION_ABSENT, 0),
                guards=[],
                mutations=[[A.Mutation.SET, b"k", b"old"]],
            ),
            slot_tag=tag,
            hlc=A.HLC(100, 0),
        )
        self.assertIsInstance(node.on_accept(tag, A.Ballot(1, b"a"), ancient, 100), A.Receipt)

        # before the horizon advances, PREPARE reports the ancient decided op
        before = node.on_prepare(tag, A.Ballot(2, b"x"))
        assert isinstance(before, A.Promise)
        self.assertEqual(before.accepted_op_hash, ancient.op_hash)

        # a checkpoint seals past hlc 100 -> the horizon rises above the ancient op
        node.advance_horizon(A.HLC(200, 0))
        after = node.on_prepare(tag, A.Ballot(3, b"y"))
        assert isinstance(after, A.Promise)
        self.assertIsNone(after.accepted_op_hash)  # voided -> fresh slot, reborn op wins


if __name__ == "__main__":
    unittest.main()
