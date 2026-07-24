# M1 — the fold: A1-A7 hypotheses (FORMAL §2) plus targeted scenarios.
# Property tests use seeded committed-set "soups"; a failure replays from seed.

import random
import unittest

from dudefs import artifacts as A
from dudefs import crypto as C
from dudefs import fold
from dudefs.handlers import control as ctl
from tests._builders import World

# --------------------------------------------------------------------------- #
# Soup generator — realistic CAS traffic + garbage, forks, guard-only slots.  #
# --------------------------------------------------------------------------- #

_SOUP_CACHE = {}


def make_soup(seed, n_ops=40, n_keys=3, epochs=(0,)):
    # Memoize: soups are read-only in tests (shuffles copy), and rebuilding one
    # re-runs Ed25519 keygen + O(n^2) incremental folds. Sharing across the A1/
    # A2/A5 classes cuts the suite's wall-clock several-fold.
    key = (seed, n_ops, n_keys, epochs)
    hit = _SOUP_CACHE.get(key)
    if hit is not None:
        return hit
    w, ops = _build_soup(seed, n_ops, n_keys, epochs)
    _SOUP_CACHE[key] = (w, ops)
    return w, ops


def _build_soup(seed, n_ops, n_keys, epochs):
    w = World(seed=seed, n_clients=3, epochs=epochs)
    rng = random.Random(seed ^ 0x5151)
    keys = [f"k{i}".encode() for i in range(n_keys)]
    ops = list(w.all_control())

    def cur_lineage(key):
        r = fold.fold(ops, w.keyring, w.genesis)
        return r.lineage(key), r

    for _ in range(n_ops):
        ci = rng.randrange(len(w.clients))
        ke = rng.choice(epochs)
        choice = rng.randrange(10)
        key = rng.choice(keys)
        (ver, att), r = cur_lineage(key)
        present = key in r.state
        try:
            if choice in (0, 1, 2):  # honest CAS create/update
                guards = (
                    [[A.Guard.ABSENT, key]] if not present else [[A.Guard.VERSION_EQ, key, ver]]
                )
                ops.append(
                    w.cas(
                        ci,
                        key,
                        ver,
                        att,
                        guards,
                        [[A.Mutation.SET, key, f"v{rng.randrange(1000)}".encode()]],
                        ke,
                    )
                )
            elif choice == 3:  # CAS delete
                guards = [[A.Guard.PRESENT, key]] if present else [[A.Guard.ABSENT, key]]
                muts = [[A.Mutation.DEL, key]] if present else [[A.Mutation.SET, key, b"init"]]
                ops.append(w.cas(ci, key, ver, att, guards, muts, ke))
            elif choice == 4:  # guard-only slot (wins k, mutates k2)
                k2 = rng.choice(keys)
                ops.append(
                    w.cas(
                        ci,
                        key,
                        ver,
                        att,
                        [[A.Guard.PRESENT, key]] if present else [[A.Guard.ABSENT, key]],
                        [[A.Mutation.SET, k2, b"side"]],
                        ke,
                    )
                )
            elif choice == 5:  # CAS with a FALSE guard -> rejected
                ops.append(
                    w.cas(
                        ci,
                        key,
                        ver,
                        att,
                        [[A.Guard.VALUE_EQ, key, b"\x00never"]],
                        [[A.Mutation.SET, key, b"x"]],
                        ke,
                    )
                )
            elif choice == 6:  # blind LWW
                ops.append(w.blind(ci, [], [[A.Mutation.SET, key, b"blind"]], ke))
            elif choice == 7:  # opaque (undecryptable) op at k's current tag
                tag = A.compute_slot_tag(w.keyring[ke]["slot_secret"], key, ver, att)
                ops.append(w.opaque(ci, tag, ke))
            elif choice == 8:  # stale CAS against a bogus old version
                ops.append(
                    w.cas(
                        ci,
                        key,
                        A.GENESIS_PREV,
                        99,
                        [[A.Guard.PRESENT, key]],
                        [[A.Mutation.SET, key, b"y"]],
                        ke,
                    )
                )
            else:  # garbage tag aimed at nothing
                ops.append(w.opaque(ci, bytes(rng.getrandbits(8) for _ in range(32)), ke))
        except Exception:
            pass
    return w, ops


# --------------------------------------------------------------------------- #
# A1 — Determinism / SEC                                                       #
# --------------------------------------------------------------------------- #


class TestA1Determinism(unittest.TestCase):
    def test_shuffle_invariance(self):
        for seed in range(35):
            w, ops = make_soup(seed)
            base = fold.fold(ops, w.keyring, w.genesis)
            for k in range(3):
                sh = ops[:]
                random.Random(seed * 31 + k).shuffle(sh)
                r = fold.fold(sh, w.keyring, w.genesis)
                self.assertEqual(r.state, base.state, f"seed={seed} k={k}")
                self.assertEqual(r.verdicts, base.verdicts, f"seed={seed} k={k}")

    def test_duplicates_are_noops(self):
        for seed in range(20):
            w, ops = make_soup(seed)
            base = fold.fold(ops, w.keyring, w.genesis)
            dup = ops + ops[: len(ops) // 2]  # re-deliver half
            r = fold.fold(dup, w.keyring, w.genesis)
            self.assertEqual(r.state, base.state, seed)
            self.assertEqual(r.verdicts, base.verdicts, seed)


# --------------------------------------------------------------------------- #
# A2 — Lineage advance / no wedge                                             #
# --------------------------------------------------------------------------- #


class TestA2NoWedge(unittest.TestCase):
    def test_fresh_tag_always_available(self):
        # Corollary: from any reachable state there is always a fresh,
        # never-decided tag — CAS can always proceed (FORMAL A2).
        keys = [b"k0", b"k1", b"k2"]
        for seed in range(35):
            w, ops = make_soup(seed)
            r = fold.fold(ops, w.keyring, w.genesis)
            existing_tags = {
                op.slot_tag for op in ops if not op.is_control and op.slot_tag is not None
            }
            for ring in w.keyring.values():
                for key in keys:
                    ver, att = r.lineage(key)
                    fresh = A.compute_slot_tag(ring["slot_secret"], key, ver, att)
                    self.assertNotIn(
                        fresh,
                        existing_tags,
                        f"seed={seed} key={key}: current tag already decided (wedge!)",
                    )

    def test_every_slotted_op_advances_or_is_stale(self):
        # A consumed slot never leaves the lineage where it was: an attributed
        # op is applied/rejected (advances), else stale (no change).
        for seed in range(25):
            w, ops = make_soup(seed)
            r = fold.fold(ops, w.keyring, w.genesis)
            for op in ops:
                if op.is_control or op.slot_tag is None:
                    continue
                self.assertIn(
                    r.verdicts[op.op_hash],
                    (
                        fold.Verdict.APPLIED,
                        fold.Verdict.REJECTED,
                        fold.Verdict.STALE,
                        fold.Verdict.INVALID,
                    ),
                )


# --------------------------------------------------------------------------- #
# A4 — Barrier equivalence (checkpoint snapshot ≡ full history)               #
# --------------------------------------------------------------------------- #


class TestA4Barrier(unittest.TestCase):
    def test_snapshot_bootstrap_equals_full_history(self):
        # DESIGN §12: the checkpoint is the CANONICAL fold barrier — everyone
        # (bootstrap AND full-history clients) folds snapshot ∘ tail. So the
        # equivalence is fold(below + checkpoint + tail) == fold(tail; snapshot).
        # Exercises tombstone death and an absent-but-lineage-advanced key that
        # both restart at (⊥, 0) across the barrier.
        w = World(seed=7, n_clients=2)
        control = list(w.all_control())
        below = list(control)
        # k1: created + updated (live across the barrier)
        below.append(
            w.cas(
                0,
                b"k1",
                A.VERSION_ABSENT,
                0,
                [[A.Guard.ABSENT, b"k1"]],
                [[A.Mutation.SET, b"k1", b"a"]],
            )
        )
        r = fold.fold(below, w.keyring, w.genesis)
        v, a = r.lineage(b"k1")
        below.append(
            w.cas(0, b"k1", v, a, [[A.Guard.VERSION_EQ, b"k1", v]], [[A.Mutation.SET, b"k1", b"b"]])
        )
        # k2: created + deleted (tombstone dies at barrier)
        below.append(
            w.cas(
                1,
                b"k2",
                A.VERSION_ABSENT,
                0,
                [[A.Guard.ABSENT, b"k2"]],
                [[A.Mutation.SET, b"k2", b"x"]],
            )
        )
        r = fold.fold(below, w.keyring, w.genesis)
        v2, a2 = r.lineage(b"k2")
        below.append(w.cas(1, b"k2", v2, a2, [[A.Guard.PRESENT, b"k2"]], [[A.Mutation.DEL, b"k2"]]))
        # k3: never valued but its ⊥-lineage advanced by a rejected CAS
        below.append(
            w.cas(
                0,
                b"k3",
                A.VERSION_ABSENT,
                0,
                [[A.Guard.PRESENT, b"k3"]],
                [[A.Mutation.SET, b"k3", b"no"]],
            )
        )

        r_below = fold.fold(below, w.keyring, w.genesis)
        snap = fold.make_barrier(r_below)
        # the checkpoint's pinned per-author heads (DESIGN §12) — EVERY author's
        # chain at the cut, including the manager's own (its cert ops are below).
        cut_frontier = {c.pub: (c.seq - 1, c.prev) for c in w.clients if c.seq > 0}
        cut_frontier[w.mgr_pub] = (w._mseq - 1, w._mprev)
        ckpt = w.checkpoint(cut=cut_frontier, keyepoch=0)

        # tail (hlc after the checkpoint via sequential ticks): all lineages fresh
        tail = []
        k1v, k1a = r_below.lineage(b"k1")
        tail.append(
            w.cas(
                0,
                b"k1",
                k1v,
                k1a,
                [[A.Guard.VERSION_EQ, b"k1", k1v]],
                [[A.Mutation.SET, b"k1", b"c"]],
            )
        )
        tail.append(
            w.cas(
                1,
                b"k2",
                A.VERSION_ABSENT,
                0,
                [[A.Guard.ABSENT, b"k2"]],
                [[A.Mutation.SET, b"k2", b"reborn"]],
            )
        )
        tail.append(
            w.cas(
                0,
                b"k3",
                A.VERSION_ABSENT,
                0,
                [[A.Guard.ABSENT, b"k3"]],
                [[A.Mutation.SET, b"k3", b"fresh"]],
            )
        )

        # full-history client: the barrier applies at the CUT (DESIGN §12 /
        # NOTES item 13) — located by the checkpoint's pinned frontier, not by
        # the checkpoint op's own hlc position.
        full = fold.fold(below + [ckpt] + tail, w.keyring, w.genesis)
        # bootstrap client: retained control chain + snapshot + tail, prev-
        # validated across the barrier via the pinned frontier.
        boot = fold.fold(
            control + tail, w.keyring, w.genesis, barrier=snap, cut_frontier=cut_frontier
        )
        self.assertEqual(boot.state, full.state)
        self.assertEqual(boot.state, {b"k1": b"c", b"k2": b"reborn", b"k3": b"fresh"})
        # k2/k3 restarted at (⊥,0) post-barrier, so their tail creations applied
        self.assertEqual(full.verdicts[tail[1].op_hash], fold.Verdict.APPLIED)
        self.assertEqual(full.verdicts[tail[2].op_hash], fold.Verdict.APPLIED)

    def test_tombstone_dies_at_barrier(self):
        w = World(seed=1, n_clients=1)
        ops = list(w.all_control())
        KEY = b"doomed"
        ops.append(
            w.cas(
                0, KEY, A.VERSION_ABSENT, 0, [[A.Guard.ABSENT, KEY]], [[A.Mutation.SET, KEY, b"v"]]
            )
        )
        r1 = fold.fold(ops, w.keyring, w.genesis)
        ver, att = r1.lineage(KEY)
        ops.append(w.cas(0, KEY, ver, att, [[A.Guard.PRESENT, KEY]], [[A.Mutation.DEL, KEY]]))
        r2 = fold.fold(ops, w.keyring, w.genesis)
        self.assertNotIn(KEY, r2.state)
        self.assertNotEqual(r2.lineage(KEY)[0], A.VERSION_ABSENT)  # tombstone anchors lineage
        # snapshot the deleted state -> tombstone is dropped, lineage restarts at ⊥
        snap = fold.make_barrier(r2)
        self.assertNotIn(KEY, snap)
        boot = fold.fold([], w.keyring, w.genesis, barrier=snap)
        self.assertEqual(boot.lineage(KEY), (A.VERSION_ABSENT, 0))


# --------------------------------------------------------------------------- #
# A5 — Prefix stability (fold-side finality)                                  #
# --------------------------------------------------------------------------- #


class TestA5PrefixStability(unittest.TestCase):
    def test_extending_above_h_leaves_prefix_frozen(self):
        for seed in range(25):
            w, ops = make_soup(seed, n_ops=25)
            data_ops = [o for o in ops if not o.is_control]
            if len(data_ops) < 6:
                continue
            hlcs = sorted({o.hlc.as_tuple() for o in data_ops})
            h = hlcs[len(hlcs) * 2 // 3]
            prefix = [o for o in ops if o.hlc.as_tuple() < h]
            r_prefix = fold.fold(prefix, w.keyring, w.genesis)
            r_full = fold.fold(ops, w.keyring, w.genesis)
            # A5: extending with hlc >= h flips NO applied-bit below h. (State
            # above h may legitimately move; state-at-h *is* r_prefix.state.)
            for op in prefix:
                self.assertEqual(
                    r_full.verdicts[op.op_hash],
                    r_prefix.verdicts[op.op_hash],
                    f"seed={seed} op below h changed verdict",
                )


# --------------------------------------------------------------------------- #
# A6 — Transactionality (all-or-nothing; guards see predecessor state)        #
# --------------------------------------------------------------------------- #


class TestA6Transactionality(unittest.TestCase):
    def test_multikey_all_or_nothing(self):
        w = World(seed=2, n_clients=1)
        ops = list(w.all_control())
        # create A and B
        ops.append(
            w.cas(
                0,
                b"A",
                A.VERSION_ABSENT,
                0,
                [[A.Guard.ABSENT, b"A"]],
                [[A.Mutation.SET, b"A", b"1"]],
            )
        )
        rA = fold.fold(ops, w.keyring, w.genesis)
        va, aa = rA.lineage(b"A")
        ops.append(
            w.cas(
                0,
                b"B",
                A.VERSION_ABSENT,
                0,
                [[A.Guard.ABSENT, b"B"]],
                [[A.Mutation.SET, b"B", b"1"]],
            )
        )
        r = fold.fold(ops, w.keyring, w.genesis)
        va, aa = r.lineage(b"A")
        # slot on A, guard requires B==WRONG -> whole txn rejected, neither mutated
        ops.append(
            w.cas(
                0,
                b"A",
                va,
                aa,
                [[A.Guard.VERSION_EQ, b"A", va], [A.Guard.VALUE_EQ, b"B", b"WRONG"]],
                [[A.Mutation.SET, b"A", b"2"], [A.Mutation.SET, b"B", b"2"]],
            )
        )
        r2 = fold.fold(ops, w.keyring, w.genesis)
        self.assertEqual(r2.verdicts[ops[-1].op_hash], fold.Verdict.REJECTED)
        self.assertEqual(r2.state[b"A"], b"1")  # unchanged
        self.assertEqual(r2.state[b"B"], b"1")  # unchanged
        # but A's slot was consumed (attempt advanced) — no wedge
        self.assertEqual(r2.lineage(b"A"), (va, aa + 1))


# --------------------------------------------------------------------------- #
# A7 — Epoch coherence (cross-epoch same-lineage race)                        #
# --------------------------------------------------------------------------- #


class TestA7EpochCoherence(unittest.TestCase):
    def test_cross_epoch_race_resolves_to_one_advance(self):
        w = World(seed=3, n_clients=2, epochs=(0, 1))
        ops = list(w.all_control())
        KEY = b"shared"
        # two clients create the same key under DIFFERENT keyepochs: different tags,
        # both may commit; the fold resolves like a cross-lineage race.
        o0 = w.cas(
            0,
            KEY,
            A.VERSION_ABSENT,
            0,
            [[A.Guard.ABSENT, KEY]],
            [[A.Mutation.SET, KEY, b"e0"]],
            keyepoch=0,
        )
        o1 = w.cas(
            1,
            KEY,
            A.VERSION_ABSENT,
            0,
            [[A.Guard.ABSENT, KEY]],
            [[A.Mutation.SET, KEY, b"e1"]],
            keyepoch=1,
        )
        ops += [o0, o1]
        r = fold.fold(ops, w.keyring, w.genesis)
        verds = sorted([r.verdicts[o0.op_hash], r.verdicts[o1.op_hash]])
        self.assertEqual(verds, [fold.Verdict.APPLIED, fold.Verdict.STALE])  # exactly one advance
        # determinism holds across epochs
        for k in range(5):
            sh = ops[:]
            random.Random(k).shuffle(sh)
            self.assertEqual(fold.fold(sh, w.keyring, w.genesis).state, r.state)


# --------------------------------------------------------------------------- #
# Authorization / revocation (fold-positional) + pver fence                    #
# --------------------------------------------------------------------------- #


class TestAuthzAndVersioning(unittest.TestCase):
    def test_revocation_is_fold_positional(self):
        w = World(seed=4, n_clients=1)
        ops = list(w.all_control())
        KEY = b"k"
        before = w.cas(
            0, KEY, A.VERSION_ABSENT, 0, [[A.Guard.ABSENT, KEY]], [[A.Mutation.SET, KEY, b"ok"]]
        )
        ops.append(before)
        rev = w.revoke(0)
        ops.append(rev)
        r1 = fold.fold(ops, w.keyring, w.genesis)
        v, a = r1.lineage(KEY)
        after = w.cas(
            0, KEY, v, a, [[A.Guard.VERSION_EQ, KEY, v]], [[A.Mutation.SET, KEY, b"nope"]]
        )
        ops.append(after)
        r2 = fold.fold(ops, w.keyring, w.genesis)
        self.assertEqual(
            r2.verdicts[before.op_hash], fold.Verdict.APPLIED
        )  # before revocation stands
        self.assertEqual(r2.verdicts[after.op_hash], fold.Verdict.INVALID)  # after is invalid
        self.assertEqual(r2.state[KEY], b"ok")

    def test_pver_above_active_is_invalid(self):
        w = World(seed=5, n_clients=1)
        ops = list(w.all_control())
        c = w.clients[0]
        txn = A.Txn(None, [], [[A.Mutation.SET, b"k", b"v"]])
        op = A.Op.build_data(
            author_sk=c.sk,
            author_pub=c.pub,
            seq=0,
            prev=A.GENESIS_PREV,
            hlc=w.tick(),
            deps=[],
            keyepoch=0,
            data_key=w.keyring[0]["data_key"],
            txn_bytes=txn.encode(),
            pver=1,
        )  # fold active pver is 0
        ops.append(op)
        r = fold.fold(ops, w.keyring, w.genesis)
        self.assertEqual(r.verdicts[op.op_hash], fold.Verdict.INVALID)


# --------------------------------------------------------------------------- #
# Control reducer (node profile) — control state without ordering             #
# --------------------------------------------------------------------------- #


class TestControlReducer(unittest.TestCase):
    def test_node_folds_control_only(self):
        w = World(seed=6, n_clients=2)
        red = fold.ControlReducer(w.mgr_pub)
        for op in w.all_control():
            self.assertTrue(red.observe(op))
        self.assertTrue(red.control.is_authorized(w.clients[0].pub, ctl.Cap.WRITE))
        # a data op is ignored by the node profile
        d = w.blind(0, [], [[A.Mutation.SET, b"k", b"v"]])
        self.assertFalse(red.observe(d))
        # order-independence: shuffle control ops -> same authorization set
        red2 = fold.ControlReducer(w.mgr_pub)
        cops = w.all_control()[:]
        random.Random(1).shuffle(cops)
        for op in cops:
            red2.observe(op)
        self.assertEqual(red.control.certs.keys(), red2.control.certs.keys())


class TestRostersByEpoch(unittest.TestCase):
    """issue #3: roster-per-epoch is the trust map a client verifies committed QCs
    against. It must fold ONLY authorized, signed ROSTER ops — a rogue compactor cannot
    author a roster op, so it can never rewrite roster history."""

    def test_folds_authorized_changes_and_excludes_a_compactor_forged_one(self):
        w = World(seed=31, n_clients=0)
        node = [C.SIGNER.public(bytes([i] * 32)) for i in (1, 2, 3)]
        genesis: fold.Genesis = {"manager_pub": w.mgr_pub, "epoch": 0, "roster": node}

        # manager (root) rotates the roster 0 -> 1: authorized.
        newd = C.SIGNER.public(bytes([4] * 32))
        new_roster = [node[0], node[1], newd]
        r_op = w._mgr_op(ctl.roster_body(0, new_roster, {}))

        # a compactor holds only Cap.COMPACT; its roster op (1 -> 2) folds INVALID.
        csk = bytes([9] * 32)
        cpub = C.SIGNER.public(csk)
        w.control_ops.append(w._mgr_op(ctl.cert_issue_body(cpub, [ctl.Cap.COMPACT], 0)))
        forged = A.Op.build(
            author_sk=csk,
            author_pub=cpub,
            cls_=A.OpClass.CONTROL,
            seq=0,
            prev=A.GENESIS_PREV,
            hlc=w.tick(),
            deps=[],
            keyepoch=0,
            payload=ctl.roster_body(1, [cpub, node[0], node[1]], {}),
        )

        rosters = fold.rosters_by_epoch([*w.control_ops, r_op, forged], genesis)
        self.assertEqual(rosters[0], node)  # the anchored founding roster
        self.assertEqual(rosters[1], new_roster)  # the manager-authorized change
        self.assertNotIn(2, rosters)  # the compactor-forged change was excluded


if __name__ == "__main__":
    unittest.main()
