# M6 — log-compaction (DESIGN §12 rev 6). A4: a bootstrap client that folds the
# RETAINED winners (mutations-only) + attempts sidecar derives byte-identical
# state to a full-history client. The resurrection and sidecar vectors MUST fail
# if their mechanism is removed — that is what proves they are load-bearing.

import unittest

from dudefs import artifacts as A
from dudefs import compactor, fold
from tests._builders import World


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


if __name__ == "__main__":
    unittest.main()
