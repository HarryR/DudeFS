# M6 — log-compaction (DESIGN §12 rev 6). A4: a bootstrap client that folds the
# RETAINED winners (mutations-only) + attempts sidecar derives byte-identical
# state to a full-history client. The resurrection and sidecar vectors MUST fail
# if their mechanism is removed — that is what proves they are load-bearing.

import os
import random
import tempfile
import unittest

from dudefs import artifacts as A
from dudefs import compactor, crypto, fold, gossip
from dudefs.acceptor import Acceptor, Rejected, RejectReason
from dudefs.handlers import control as ctl
from dudefs.store import AppendStatus, ChainStore
from tests._builders import World, cut_of

BIG_DELTA = 1_000_000


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
        cut = cut_of(w)

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

        cr = compactor.compact_genesis(below, w.keyring, w.genesis, cut)
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
        cut = cut_of(w)
        cr = compactor.compact_genesis(below, w.keyring, w.genesis, cut)
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
        cut = cut_of(w)

        cr = compactor.compact_genesis(below, w.keyring, w.genesis, cut)
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
        cut = cut_of(w)

        v1, a1 = fold.fold(below, w.keyring, w.genesis).lineage(b"k")
        self.assertEqual(a1, 1)  # the slot was consumed
        tail = [
            w.cas(
                0, b"k", v1, a1, [[A.Guard.VERSION_EQ, b"k", v1]], [[A.Mutation.SET, b"k", b"v3"]]
            )
        ]

        cr = compactor.compact_genesis(below, w.keyring, w.genesis, cut)
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


class TestA4RejectedOps(unittest.TestCase):
    """D3 finding 13: a committed-but-REJECTED op's mutations never applied, so the
    mask meta must NOT be a mutations-only fold of the whole band — it takes the
    band's truth from the guard-evaluated r.meta. Both reproduced vectors: without
    the fix, bootstrap resurrects a key a full-history client holds dead."""

    def test_rejected_write_to_dead_key_does_not_resurrect_it(self):
        # W(set A, set B); Z(del B); R(guard fails, set B) — committed REJECTED,
        # sorting after Z. A mutations-only band fold would read B live (R's set)
        # and drop Z; bootstrap would resurrect B.
        w = World(seed=60, n_clients=2)
        control = list(w.control_ops)
        below = list(control)
        below.append(w.blind(0, [], [[A.Mutation.SET, b"A", b"1"], [A.Mutation.SET, b"B", b"1"]]))
        below.append(w.blind(1, [], [[A.Mutation.DEL, b"B"]]))
        rej = w.blind(0, [[A.Guard.PRESENT, b"B"]], [[A.Mutation.SET, b"B", b"resurrect"]])
        below.append(rej)
        cut = cut_of(w)
        cr = compactor.compact_genesis(below, w.keyring, w.genesis, cut)
        full = fold.fold(below, w.keyring, w.genesis)
        boot = _boot(w, cr, control, [], cut)
        self.assertEqual(full.verdicts[rej.op_hash], fold.Verdict.REJECTED)
        self.assertEqual(full.state, {b"A": b"1"})  # B dead
        self.assertEqual(boot.state, full.state)  # B NOT resurrected
        self.assertNotIn(rej.op_hash, {o.op_hash for o in cr.retained})

    def test_rejected_op_is_not_retained_as_a_tombstone(self):
        # Mirror: a REJECTED op that names `del C` must not be nominated as C's
        # tombstone — retaining it would replay its OTHER mutation (set D) at
        # bootstrap. C's real tombstone T must be kept instead.
        w = World(seed=61, n_clients=2)
        control = list(w.control_ops)
        below = list(control)
        below.append(w.blind(0, [], [[A.Mutation.SET, b"A", b"1"], [A.Mutation.SET, b"C", b"1"]]))
        below.append(w.blind(1, [], [[A.Mutation.DEL, b"C"]]))  # T: real tombstone
        rej = w.blind(
            0, [[A.Guard.PRESENT, b"C"]], [[A.Mutation.DEL, b"C"], [A.Mutation.SET, b"D", b"1"]]
        )
        below.append(rej)  # rejected (C absent): neither the del nor the set apply
        cut = cut_of(w)
        cr = compactor.compact_genesis(below, w.keyring, w.genesis, cut)
        full = fold.fold(below, w.keyring, w.genesis)
        boot = _boot(w, cr, control, [], cut)
        self.assertEqual(full.verdicts[rej.op_hash], fold.Verdict.REJECTED)
        self.assertEqual(full.state, {b"A": b"1"})  # C dead, D never set
        self.assertEqual(boot.state, full.state)  # D NOT resurrected
        self.assertNotIn(rej.op_hash, {o.op_hash for o in cr.retained})


class TestA4TwoCheckpoints(unittest.TestCase):
    """WP1.4: A4 must hold across SUCCESSIVE incremental checkpoints, not just a
    single genesis compaction. The dangerous case the incremental fold's r.meta
    misses — a mask for a key that died below the previous cut — is carried by the
    universe-wide _mut_meta scan."""

    def test_mask_carries_across_two_checkpoints(self):
        w = World(seed=40, n_clients=2)
        control = list(w.control_ops)
        below1 = list(control)
        # W sets A and B; X deletes B -> B dead below cut1, A live (winner W).
        wop = w.blind(0, [], [[A.Mutation.SET, b"A", b"1"], [A.Mutation.SET, b"B", b"1"]])
        below1.append(wop)
        xop = w.blind(1, [], [[A.Mutation.DEL, b"B"]])
        below1.append(xop)
        cut1 = cut_of(w)
        ckpt1 = compactor.compact_genesis(below1, w.keyring, w.genesis, cut1)
        self.assertIn(xop.op_hash, {o.op_hash for o in ckpt1.retained})  # mask in ckpt1

        # tail2: a fresh key D; A/B untouched. cut2 covers it.
        tail2 = [w.blind(0, [], [[A.Mutation.SET, b"D", b"1"]])]
        cut2 = cut_of(w)
        ckpt2 = compactor.compact(
            ckpt1.retained, ckpt1.attempts, cut1, tail2, w.keyring, w.genesis, cut2
        )
        # THE carry-forward: X survives into ckpt2 though B died below cut1 (the
        # incremental fold's r.meta has no B entry — only _mut_meta over the
        # universe finds the tombstone).
        self.assertIn(xop.op_hash, {o.op_hash for o in ckpt2.retained})

        # A4 across two checkpoints: bootstrap from ckpt2 == full fold to cut2.
        full = fold.fold(below1 + tail2, w.keyring, w.genesis)
        ckpt2_control = [o for o in ckpt2.retained if o.is_control]
        boot = _boot(w, ckpt2, ckpt2_control, [], cut2)
        self.assertEqual(boot.state, full.state)
        self.assertEqual(full.state, {b"A": b"1", b"D": b"1"})  # B stayed dead

        # load-bearing: drop X and bootstrap resurrects B.
        no_x = [o for o in ckpt2.retained if not o.is_control and o.op_hash != xop.op_hash]
        self.assertIn(b"B", compactor.barrier_state(no_x, ckpt2.attempts, w.keyring))

    def test_prev_winner_dies_in_next_delta(self):
        # An op retained by checkpoint 1 (a winner) superseded in checkpoint 2's
        # tail lands in ckpt2.dead (the incremental GC delta) and bootstrap tracks
        # the new winner.
        w = World(seed=41, n_clients=1)
        control = list(w.control_ops)
        below1 = list(control)
        first = w.cas(
            0, b"k", A.VERSION_ABSENT, 0, [[A.Guard.ABSENT, b"k"]], [[A.Mutation.SET, b"k", b"v1"]]
        )
        below1.append(first)
        cut1 = cut_of(w)
        ckpt1 = compactor.compact_genesis(below1, w.keyring, w.genesis, cut1)
        self.assertIn(first.op_hash, {o.op_hash for o in ckpt1.retained})  # winner of k

        v, a = fold.fold(below1, w.keyring, w.genesis).lineage(b"k")
        second = w.cas(
            0, b"k", v, a, [[A.Guard.VERSION_EQ, b"k", v]], [[A.Mutation.SET, b"k", b"v2"]]
        )
        tail2 = [second]
        cut2 = cut_of(w)
        ckpt2 = compactor.compact(
            ckpt1.retained, ckpt1.attempts, cut1, tail2, w.keyring, w.genesis, cut2
        )
        self.assertIn(first.op_hash, ckpt2.dead)  # prev winner now in the GC delta
        self.assertIn(second.op_hash, {o.op_hash for o in ckpt2.retained})  # new winner kept

        full = fold.fold(below1 + tail2, w.keyring, w.genesis)
        ckpt2_control = [o for o in ckpt2.retained if o.is_control]
        boot = _boot(w, ckpt2, ckpt2_control, [], cut2)
        self.assertEqual(boot.state, full.state)
        self.assertEqual(full.state, {b"k": b"v2"})


class TestA4PropertyFuzz(unittest.TestCase):
    """WP1.6: the resurrection-mask fixpoint and the incremental carry-forward are
    CLASSES of behavior; a hand-built vector catches one member. Seeded random
    chains (multi-key set/del + CAS + rejected-CAS-consumes-attempt) compacted at
    a random cut must satisfy A4 byte-for-byte: fold(full) ≡ bootstrap(retained ∘
    tail). All seeded -> deterministic and replayable."""

    KEYS = [b"k0", b"k1", b"k2", b"k3"]

    def _gen(self, rng, w, below):
        """Append one random VALID op to `below`, tracking live state for guards."""
        folded = fold.fold(below, w.keyring, w.genesis)
        state = folded.state
        ci = rng.randrange(len(w.clients))
        roll = rng.random()
        if roll < 0.4 or not state:  # blind multi-key set (2-3 keys -> shared dead keys)
            ks = rng.sample(self.KEYS, rng.randint(2, 3))
            muts = [[A.Mutation.SET, k, bytes([rng.randrange(256)])] for k in ks]
            op = w.blind(ci, [], muts)
        elif roll < 0.55:  # blind delete of a live key
            k = rng.choice(list(state))
            op = w.blind(ci, [], [[A.Mutation.DEL, k]])
        elif roll < 0.7:  # CAS overwrite of a live key
            k = rng.choice(list(state))
            v, a = folded.lineage(k)
            nv = bytes([rng.randrange(256)])
            op = w.cas(ci, k, v, a, [[A.Guard.VERSION_EQ, k, v]], [[A.Mutation.SET, k, nv]])
        elif roll < 0.85 and set(self.KEYS) - set(state):
            # a REJECTED write AIMED AT A DEAD KEY (D3 finding 13): a mutations-only
            # band fold would treat this as applied and drop the key's real
            # tombstone. The old arm targeted live keys only, which is why 50 seeds
            # missed the resurrection.
            dead = rng.choice(list(set(self.KEYS) - set(state)))
            op = w.blind(
                ci, [[A.Guard.PRESENT, dead]], [[A.Mutation.SET, dead, bytes([rng.randrange(256)])]]
            )
        else:  # a CAS whose guard FAILS on a live key -> rejected, attempt consumed
            k = rng.choice(list(state))
            v, a = folded.lineage(k)
            op = w.cas(ci, k, v, a, [[A.Guard.VALUE_EQ, k, b"never"]], [[A.Mutation.SET, k, b"z"]])
        below.append(op)

    def test_single_checkpoint_A4_holds(self):
        for seed in range(25):
            rng = random.Random(seed)
            w = World(seed=seed, n_clients=3)
            below = list(w.control_ops)
            n_below = rng.randint(4, 14)
            for _ in range(n_below):
                self._gen(rng, w, below)
            cut = cut_of(w)
            seg = len(below)
            for _ in range(rng.randint(0, 8)):
                self._gen(rng, w, below)
            full_ops = list(below)
            below_only = full_ops[:seg]
            tail = full_ops[seg:]

            cr = compactor.compact_genesis(below_only, w.keyring, w.genesis, cut)
            boot = _boot(w, cr, list(w.control_ops), tail, cut)
            full = fold.fold(full_ops, w.keyring, w.genesis)
            self.assertEqual(boot.state, full.state, f"seed {seed}: state diverged")
            self.assertEqual(
                fold.state_root(boot), fold.state_root(full), f"seed {seed}: root diverged"
            )

    def test_two_checkpoint_A4_holds(self):
        for seed in range(25):
            rng = random.Random(1000 + seed)
            w = World(seed=seed, n_clients=3)
            below1 = list(w.control_ops)
            for _ in range(rng.randint(3, 10)):
                self._gen(rng, w, below1)
            cut1 = cut_of(w)
            seg1 = len(below1)
            for _ in range(rng.randint(1, 6)):
                self._gen(rng, w, below1)
            cut2 = cut_of(w)
            seg2 = len(below1)
            for _ in range(rng.randint(0, 6)):
                self._gen(rng, w, below1)

            full_ops = list(below1)
            below1_only = full_ops[:seg1]
            tail1 = full_ops[seg1:seg2]
            tail2 = full_ops[seg2:]

            ckpt1 = compactor.compact_genesis(below1_only, w.keyring, w.genesis, cut1)
            ckpt2 = compactor.compact(
                ckpt1.retained, ckpt1.attempts, cut1, tail1, w.keyring, w.genesis, cut2
            )
            boot = _boot(w, ckpt2, list(w.control_ops), tail2, cut2)
            full = fold.fold(full_ops, w.keyring, w.genesis)
            self.assertEqual(boot.state, full.state, f"seed {seed}: state diverged")
            self.assertEqual(
                fold.state_root(boot), fold.state_root(full), f"seed {seed}: root diverged"
            )


class TestDelegateCheckpointBarrier(unittest.TestCase):
    """WP1.4 amendment (finding 12 / NOTES 37): a compact-delegate's checkpoint
    must place a real BARRIER, not merely fold CONTROL. Asserts barrier semantics
    (universe reset -> a reborn creation tag commits above the cut) through a
    delegate-minted checkpoint, identical to a root-minted one; a write-only
    author places no barrier (the reborn tag collides and stays dead)."""

    def _ckpt(self, sk, pub, cut, hlc_ms, pver=0):
        return A.Op.build(
            author_sk=sk,
            author_pub=pub,
            cls_=A.OpClass.CONTROL,
            seq=0,
            prev=A.GENESIS_PREV,
            hlc=A.HLC(hlc_ms, 0),
            deps=[],
            authz=b"cert",
            keyepoch=0,
            payload=ctl.checkpoint_body(cut, b"", [], {}, b"", 0, A.HLC(0, 0)),
            pver=pver,
        )

    def _reborn_world(self, seed):
        """A history where a checkpoint's barrier decides a reborn tag: k created
        then deleted below the cut, and a byte-identical recreation above it."""
        w = World(seed=seed, n_clients=1)
        c1 = w.cas(
            0, b"k", A.VERSION_ABSENT, 0, [[A.Guard.ABSENT, b"k"]], [[A.Mutation.SET, b"k", b"v1"]]
        )
        v1, a1 = fold.fold([*w.control_ops, c1], w.keyring, w.genesis).lineage(b"k")
        d = w.cas(0, b"k", v1, a1, [[A.Guard.VERSION_EQ, b"k", v1]], [[A.Mutation.DEL, b"k"]])
        below = [*w.control_ops, c1, d]
        cut = cut_of(w)
        base = w._hlc
        tag = A.compute_slot_tag(w.keyring[0]["slot_secret"], b"k", A.VERSION_ABSENT, 0)
        c2 = w.data_op(
            0,
            txn=A.Txn(
                (b"k", A.VERSION_ABSENT, 0),
                [[A.Guard.ABSENT, b"k"]],
                [[A.Mutation.SET, b"k", b"v2"]],
            ),
            slot_tag=tag,
            hlc=A.HLC(base + 10, 0),
        )
        return w, below, cut, base, c2

    def test_finding14_fenced_checkpoint_places_no_barrier(self):
        # D3 finding 14: a checkpoint stamped op.pver > active folds INVALID, so its
        # barrier must NOT run. Contrast a valid pver-0 checkpoint (barrier placed,
        # reborn commits) with a fenced pver-1 one (no barrier, reborn stays dead).
        w, below, cut, base, c2 = self._reborn_world(45)
        valid = self._ckpt(w.mgr_sk, w.mgr_pub, cut, base + 5, pver=0)
        fenced = self._ckpt(w.mgr_sk, w.mgr_pub, cut, base + 5, pver=fold.SUPPORTED_PVER + 1)

        r_valid = fold.fold([*below, valid, c2], w.keyring, w.genesis)
        self.assertEqual(r_valid.state.get(b"k"), b"v2")  # barrier -> reborn commits

        r_fenced = fold.fold([*below, fenced, c2], w.keyring, w.genesis)
        self.assertEqual(r_fenced.verdicts[fenced.op_hash], fold.Verdict.INVALID)
        self.assertNotIn(b"k", r_fenced.state)  # fenced -> NO barrier -> reborn stays dead

        # and the pre-walk itself excludes the fenced cut, includes the valid one
        # white-box: fold._total_order_key / _authorized_cuts are internal fold
        # helpers, asserted directly to pin the cut-authorization logic.
        ordered = sorted([*below, valid, c2], key=fold._total_order_key)
        self.assertIn(cut, fold._authorized_cuts(ordered, set(), w.genesis))
        ordered_f = sorted([*below, fenced, c2], key=fold._total_order_key)
        self.assertNotIn(cut, fold._authorized_cuts(ordered_f, set(), w.genesis))

    def test_delegate_minted_checkpoint_places_the_barrier(self):
        w = World(seed=44, n_clients=1)
        dsk, dpub = bytes([90] * 32), crypto.SIGNER.public(bytes([90] * 32))
        wsk, wpub = bytes([91] * 32), crypto.SIGNER.public(bytes([91] * 32))
        cert_d = w._mgr_op(ctl.cert_issue_body(dpub, [ctl.Cap.COMPACT], 0))
        cert_w = w._mgr_op(ctl.cert_issue_body(wpub, [ctl.Cap.WRITE], 0))

        # k created then deleted below the cut: its creation slot T is consumed and
        # k is dead — the sealed key that must leave the attributable universe.
        c1 = w.cas(
            0, b"k", A.VERSION_ABSENT, 0, [[A.Guard.ABSENT, b"k"]], [[A.Mutation.SET, b"k", b"v1"]]
        )
        v1, a1 = fold.fold([*w.control_ops, cert_d, cert_w, c1], w.keyring, w.genesis).lineage(b"k")
        d = w.cas(0, b"k", v1, a1, [[A.Guard.VERSION_EQ, b"k", v1]], [[A.Mutation.DEL, b"k"]])
        below = [*w.control_ops, cert_d, cert_w, c1, d]
        cut = cut_of(w)  # covers the certs, c1, d (captured before the reborn op)
        base = w._hlc

        # a reborn creation of k above the cut: byte-identical tag to c1's.
        tag = A.compute_slot_tag(w.keyring[0]["slot_secret"], b"k", A.VERSION_ABSENT, 0)
        self.assertEqual(tag, c1.slot_tag)  # the reborn collision the barrier resolves
        c2 = w.data_op(
            0,
            txn=A.Txn(
                (b"k", A.VERSION_ABSENT, 0),
                [[A.Guard.ABSENT, b"k"]],
                [[A.Mutation.SET, b"k", b"v2"]],
            ),
            slot_tag=tag,
            hlc=A.HLC(base + 10, 0),
        )

        ckpt_del = self._ckpt(dsk, dpub, cut, base + 5)  # compact delegate -> barrier
        ckpt_write = self._ckpt(wsk, wpub, cut, base + 5)  # write-only -> NO barrier
        ckpt_mgr = w.checkpoint(cut=cut)  # root baseline

        r_del = fold.fold([*below, ckpt_del, c2], w.keyring, w.genesis)
        r_mgr = fold.fold([*below, ckpt_mgr, c2], w.keyring, w.genesis)
        r_write = fold.fold([*below, ckpt_write, c2], w.keyring, w.genesis)

        # the delegate checkpoint is authorized AND places the barrier: the reborn
        # op commits above the cut (universe reset), exactly as the root's does.
        self.assertEqual(r_del.verdicts[ckpt_del.op_hash], fold.Verdict.CONTROL)
        self.assertEqual(r_del.state, r_mgr.state)
        self.assertEqual(r_del.state.get(b"k"), b"v2")  # reborn committed

        # load-bearing: the write-only author is NOT authorized -> no barrier ->
        # the reborn tag collides with the sealed decision -> k stays dead.
        self.assertEqual(r_write.verdicts[ckpt_write.op_hash], fold.Verdict.INVALID)
        self.assertNotIn(b"k", r_write.state)
        self.assertNotEqual(r_write.state, r_del.state)


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
        cut = cut_of(w)
        cr = compactor.compact_genesis(below, w.keyring, w.genesis, cut)

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
        cut = cut_of(w)
        cr = compactor.compact_genesis(below, w.keyring, w.genesis, cut)
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
        cut = cut_of(w)
        cr = compactor.compact_genesis(below, w.keyring, w.genesis, cut)
        retained = A.retained_commitment(cr.retained)
        ckpt = w.checkpoint(
            cut=cut,
            state_root=cr.state_root,
            dead=cr.dead,
            retained=retained,
            attempts=b"ct",
            horizon=A.HLC(200, 3),
        )
        body = ctl.decode(ckpt)
        assert isinstance(body, ctl.Checkpoint)
        self.assertEqual(body.cut, cut)
        self.assertEqual(body.state_root, cr.state_root)
        self.assertEqual(body.dead, cr.dead)
        self.assertEqual(body.retained, retained)
        self.assertEqual(body.attempts, b"ct")
        self.assertEqual(body.horizon, A.HLC(200, 3))  # WP1.5: F carried on the wire

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
        cut = cut_of(w)
        cr = compactor.compact_genesis(below, w.keyring, w.genesis, cut)
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
        cut = cut_of(w)
        cr = compactor.compact_genesis(below, w.keyring, w.genesis, cut)
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
        cut = cut_of(w)
        cr = compactor.compact_genesis(below, w.keyring, w.genesis, cut)
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


class TestReceiptFloorBackstop(unittest.TestCase):
    """§12 receipt-floor-at-horizon backstop (NOTES 34/Q5 third layer, M7 WP1.3):
    after GC forgets below-horizon slot state, the acceptor refuses to NEWLY receipt
    below the sealed horizon — a late contender can't resurrect a spent slot.
    Isolated from the skew gate (floor kept far below the horizon) to exercise the
    backstop alone."""

    def _node(self, key=190):
        nsk = bytes([key] * 32)
        return Acceptor(
            nsk, crypto.SIGNER.public(nsk), ChainStore(), config_epoch=0, delta_ms=BIG_DELTA
        )

    def _op(self, w, key, hlc):
        tag = A.compute_slot_tag(w.keyring[0]["slot_secret"], key, A.VERSION_ABSENT, 0)
        return w.data_op(
            0,
            txn=A.Txn((key, A.VERSION_ABSENT, 0), [], [[A.Mutation.SET, key, b"v"]]),
            slot_tag=tag,
            hlc=hlc,
        )

    def test_new_receipt_below_horizon_refused_boundary_accepted(self):
        acc = self._node()
        w = World(seed=50, n_clients=1)
        acc.advance_horizon(A.HLC(200, 0))
        b = A.Ballot(1, b"a")
        # REJECT: a fresh op strictly below the horizon (skew gate passes — floor<0)
        below = self._op(w, b"k1", A.HLC(100, 0))
        assert below.slot_tag is not None
        r = acc.on_accept(below.slot_tag, b, below, 100)
        self.assertIsInstance(r, Rejected)
        assert isinstance(r, Rejected)
        self.assertEqual(r.reason, RejectReason.BELOW_HORIZON)
        # ACCEPT (boundary): hlc == horizon is still committable (== floor passes)
        at = self._op(w, b"k2", A.HLC(200, 0))
        assert at.slot_tag is not None
        self.assertIsInstance(acc.on_accept(at.slot_tag, b, at, 100), A.Receipt)

    def test_idempotent_reaccept_below_horizon_is_still_served(self):
        # an op accepted BEFORE the horizon rose is re-served (serve-from-store),
        # never blocked by the backstop — a RERECEIPT across a bridge must not wedge.
        acc = self._node(191)
        w = World(seed=51, n_clients=1)
        b = A.Ballot(1, b"a")
        op = self._op(w, b"k", A.HLC(100, 0))
        assert op.slot_tag is not None
        r1 = acc.on_accept(op.slot_tag, b, op, 100)  # horizon 0 -> accepted
        assert isinstance(r1, A.Receipt)
        acc.advance_horizon(A.HLC(200, 0))  # horizon now above the op
        r2 = acc.on_accept(op.slot_tag, b, op, 100)  # re-accept -> served, not blocked
        assert isinstance(r2, A.Receipt)
        self.assertEqual(r1.issue_seq, r2.issue_seq)  # serve-from-store, same receipt


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

    def _one_accept_node(self, hlc):
        # a node holding a single decided op at `hlc`; returns (node, tag, op).
        nsk = bytes([201] * 32)
        node = Acceptor(nsk, crypto.SIGNER.public(nsk), ChainStore(), 0, BIG_DELTA)
        w = World(seed=17, n_clients=1)
        tag = A.compute_slot_tag(w.keyring[0]["slot_secret"], b"k", A.VERSION_ABSENT, 0)
        op = w.data_op(
            0,
            txn=A.Txn((b"k", A.VERSION_ABSENT, 0), [], [[A.Mutation.SET, b"k", b"x"]]),
            slot_tag=tag,
            hlc=hlc,
        )
        node.on_accept(tag, A.Ballot(1, b"a"), op, 100)
        return node, tag, op

    def test_accept_at_exactly_horizon_is_not_voided(self):
        # WP1.5 boundary (DESIGN §8, strict): an accept at exactly hlc == F may
        # still be newly committable (hlc == floor passes the past gate), so
        # voiding at equality would be a safety hole. ACCEPT: it survives PREPARE.
        node, tag, op = self._one_accept_node(A.HLC(100, 0))
        node.advance_horizon(A.HLC(100, 0))  # F == the op's hlc
        p = node.on_prepare(tag, A.Ballot(2, b"x"))
        assert isinstance(p, A.Promise)
        self.assertEqual(p.accepted_op_hash, op.op_hash)  # NOT voided at equality

        # one tick strictly below -> voided (the reject side of the pair)
        node.advance_horizon(A.HLC(101, 0))
        p2 = node.on_prepare(tag, A.Ballot(3, b"y"))
        assert isinstance(p2, A.Promise)
        self.assertIsNone(p2.accepted_op_hash)

    def test_horizon_sourced_from_checkpoint_field(self):
        # WP1.5 wiring: the value the void rule uses IS the checkpoint's `horizon`
        # field F, decoded and fed to advance_horizon (what the M7 daemon does on
        # adopting a checkpoint).
        node, tag, _op = self._one_accept_node(A.HLC(100, 0))
        w = World(seed=18, n_clients=1)
        ckpt = w.checkpoint(cut=cut_of(w), horizon=A.HLC(150, 0))
        body = ctl.decode(ckpt)
        assert isinstance(body, ctl.Checkpoint)
        node.advance_horizon(body.horizon)  # sourced from F on the wire
        p = node.on_prepare(tag, A.Ballot(2, b"z"))
        assert isinstance(p, A.Promise)
        self.assertIsNone(p.accepted_op_hash)  # F=150 > 100 -> voided


class TestHorizonPersistence(unittest.TestCase):
    """Finding 19: the checkpoint horizon must survive crash-restart. Persisted in
    the adopt_checkpoint transaction and restored on Acceptor init — otherwise the
    void rule + receipt-floor backstop reset to HLC(0,0) and go inert against a
    below-horizon reborn op after a restart."""

    def _op(self, w, key, hlc):
        tag = A.compute_slot_tag(w.keyring[0]["slot_secret"], key, A.VERSION_ABSENT, 0)
        return w.data_op(
            0,
            txn=A.Txn((key, A.VERSION_ABSENT, 0), [], [[A.Mutation.SET, key, b"v"]]),
            slot_tag=tag,
            hlc=hlc,
        )

    def test_horizon_restored_backstop_and_void_survive_restart(self):
        w = World(seed=190, n_clients=1)
        nsk = bytes([190] * 32)
        cut = {w.mgr_pub: (0, b"\x00" * 32)}
        with tempfile.TemporaryDirectory() as d:
            path = os.path.join(d, "store.db")
            # adopt a checkpoint sealing F=200, then simulate a crash (close+reopen)
            s = ChainStore(path)
            s.adopt_checkpoint(cut, {}, [], A.HLC(200, 0))
            self.assertEqual(s.get_horizon(), A.HLC(200, 0))
            s.close()

            s2 = ChainStore(path)
            acc = Acceptor(nsk, crypto.SIGNER.public(nsk), s2, 0, BIG_DELTA)
            self.assertEqual(acc.horizon, A.HLC(200, 0))  # restored, not reset to 0

            # backstop: a fresh op strictly below the restored horizon is refused
            below = self._op(w, b"k1", A.HLC(100, 0))
            assert below.slot_tag is not None
            r = acc.on_accept(below.slot_tag, A.Ballot(1, b"a"), below, 100)
            assert isinstance(r, Rejected)
            self.assertEqual(r.reason, RejectReason.BELOW_HORIZON)
            # boundary: hlc == horizon is still committable
            at = self._op(w, b"k2", A.HLC(200, 0))
            assert at.slot_tag is not None
            self.assertIsInstance(acc.on_accept(at.slot_tag, A.Ballot(1, b"a"), at, 100), A.Receipt)
            s2.close()

    def test_without_persistence_horizon_would_reset(self):
        # the negative control: a store that NEVER adopted a horizon restores to
        # HLC(0,0), so the backstop lets the below-horizon op through — this is
        # exactly the inertness finding 19 removes once a horizon IS persisted.
        w = World(seed=191, n_clients=1)
        nsk = bytes([191] * 32)
        with tempfile.TemporaryDirectory() as d:
            path = os.path.join(d, "store.db")
            s = ChainStore(path)
            self.assertEqual(s.get_horizon(), A.HLC(0, 0))
            acc = Acceptor(nsk, crypto.SIGNER.public(nsk), s, 0, BIG_DELTA)
            op = self._op(w, b"k", A.HLC(100, 0))
            assert op.slot_tag is not None
            # no horizon adopted -> the op commits (backstop inert, correctly)
            self.assertIsInstance(acc.on_accept(op.slot_tag, A.Ballot(1, b"a"), op, 100), A.Receipt)
            s.close()


if __name__ == "__main__":
    unittest.main()
