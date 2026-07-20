# M6 — log-compaction (DESIGN §12 rev 6). A4: a bootstrap client that folds the
# RETAINED winners (mutations-only) + attempts sidecar derives byte-identical
# state to a full-history client. The resurrection and sidecar vectors MUST fail
# if their mechanism is removed — that is what proves they are load-bearing.

import unittest

from dudefs import artifacts as A
from dudefs import compactor, crypto, fold, gossip
from dudefs.acceptor import Acceptor
from dudefs.handlers import control as ctl
from dudefs.store import ChainStore
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
