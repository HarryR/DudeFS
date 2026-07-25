# M2.5 — regression tests for the post-M2 review resolutions (NOTES §M2.5).
# Each test names the finding it pins down; the doc reference is the rule.

import pathlib
import random
import subprocess
import sys
import unittest
from functools import partial

from dudefs import artifacts as A
from dudefs import codec, fold, wire
from dudefs import crypto as C
from dudefs.acceptor import Acceptor, Rejected, RejectReason
from dudefs.artifacts import HLC, Ballot
from dudefs.store import ChainStore
from tests._builders import World

NOW = 10_000
DELTA = 100


class TestQCBitmapStrictness(unittest.TestCase):
    """NOTES item 18: a malformed bitmap is a False verdict, never a crash."""

    def setUp(self):
        self.n = 5
        self.sks = [bytes([20 + i] * 32) for i in range(self.n)]
        self.pubs = [C.SIGNER.public(s) for s in self.sks]
        self.index = {p: i for i, p in enumerate(self.pubs)}

    def test_short_bitmap_is_false_not_crash(self):
        qc = A.QC(bytes(32), 0, A.BLIND, b"", [], [])
        self.assertFalse(A.QC.decode(qc.encode()).verify(self.pubs))

    def test_overlong_bitmap_is_false(self):
        oph = bytes([7] * 32)
        rs = [
            A.Receipt.issue(C.SoftwareKeypair.from_seed(self.sks[i]), oph, 0, A.BLIND, 1)
            for i in (0, 1, 2)
        ]
        qc = A.QC.assemble(rs, self.n, self.index)
        self.assertTrue(qc.verify(self.pubs))
        padded = A.QC(
            qc.op_hash,
            qc.config_epoch,
            qc.ballot,
            qc.signer_bitmap + b"\x00",
            qc.sigs,
            qc.issue_seqs,
        )
        self.assertFalse(padded.verify(self.pubs))

    def test_stray_bits_beyond_n_are_false(self):
        oph = bytes([7] * 32)
        rs = [
            A.Receipt.issue(C.SoftwareKeypair.from_seed(self.sks[i]), oph, 0, A.BLIND, 1)
            for i in (0, 1, 2)
        ]
        qc = A.QC.assemble(rs, self.n, self.index)
        bm = bytearray(qc.signer_bitmap)
        bm[-1] |= 0x01  # a bit above roster index n-1; same signer set, second encoding
        tampered = A.QC(qc.op_hash, qc.config_epoch, qc.ballot, bytes(bm), qc.sigs, qc.issue_seqs)
        self.assertFalse(tampered.verify(self.pubs))


class TestControlBodyValidation(unittest.TestCase):
    """NOTES item 17: malformed manager bodies fold `invalid`, never crash."""

    def test_missing_fields_fold_invalid(self):
        w = World(seed=10, n_clients=1)
        ops = list(w.all_control())
        from dudefs import codec

        bad = w._mgr_raw(codec.encode({b"kind": A.ControlKind.CERT_ISSUE}))  # no subject/caps
        ops.append(bad)
        r = fold.fold(ops, w.keyring, w.genesis)  # must not raise
        self.assertEqual(r.verdicts[bad.op_hash], fold.Verdict.INVALID)

    def test_unknown_kind_folds_invalid(self):
        w = World(seed=10, n_clients=1)
        ops = list(w.all_control())
        from dudefs import codec

        bad = w._mgr_raw(codec.encode({b"kind": b"launch_missiles"}))
        ops.append(bad)
        r = fold.fold(ops, w.keyring, w.genesis)
        self.assertEqual(r.verdicts[bad.op_hash], fold.Verdict.INVALID)

    def test_even_roster_folds_invalid(self):
        # DESIGN §13: roster size is always odd — validation rejects even counts.
        w = World(seed=10, n_clients=1)
        ops = list(w.all_control())
        pubs = [C.SIGNER.public(bytes([40 + i] * 32)) for i in range(4)]
        bad = w._mgr_op(partial(A.RosterOp.build, from_epoch=0, roster=pubs, sync_frontier={}))
        ops.append(bad)
        r = fold.fold(ops, w.keyring, w.genesis)
        self.assertEqual(r.verdicts[bad.op_hash], fold.Verdict.INVALID)
        self.assertIsNone(r.control.roster)


_REPO = pathlib.Path(__file__).resolve().parent.parent


class TestRC4CrashOnly(unittest.TestCase):
    """Review RC-4, per the ruling: routine, knowingly-recoverable conditions return typed
    results; everything else is THROWN, kills the thread, and must take the PROCESS with it so a
    supervisor respawns it and the cause is on the record. Broad `except Exception` at a loop top
    would be the bug, not the cure — a silently half-dead daemon (no gossip, no adoption, no
    evidence, `status()` fine) is strictly worse than a dead one.

    The two halves are ordered, and the order is load-bearing: hostile input must FIRST be a
    typed, expected outcome, or "crash on anything unexpected" hands any unauthenticated peer a
    remote kill switch."""

    def test_hostile_bencode_is_a_typed_CodecError_not_an_untyped_crash(self):
        # each of these used to escape the DudeFSError tree entirely (review K-9): a
        # RecursionError or a bare ValueError from int(), pre-authentication.
        for name, blob in [
            ("over-deep nesting", b"l" * 2000 + b"e" * 2000),
            ("oversized int literal", b"i" + b"9" * 5000 + b"e"),
            ("oversized length prefix", b"9" * 5000 + b":"),
        ]:
            with self.subTest(name), self.assertRaises(codec.CodecError):
                codec.decode(blob)

    def test_truncated_wire_requests_are_typed_not_IndexError(self):
        # IndexError is NOT in the DudeFSError tree, so `daemon.serve` never caught it and the
        # serving thread died on a malformed frame (review IO-11).
        for name, body in [
            ("accept missing fields", [b"accept"]),
            ("getqc missing op_hash", [b"getqc"]),
            ("empty body", []),
            ("unknown verb", [b"nope"]),
        ]:
            with self.subTest(name), self.assertRaises(codec.CodecError):
                wire.decode_request(codec.encode(body))

    def test_an_uncaught_thread_exception_kills_the_process(self):
        # the half that Python gets backwards by default: a `daemon=True` loop thread dies and
        # the process serves on, silently degraded. Run out-of-process — the whole point is
        # os._exit, which we cannot assert from inside.
        prog = "\n".join(
            [
                "import threading, logging, sys",
                f"sys.path.insert(0, {str(_REPO)!r})",
                "from dudefs import crashonly",
                "crashonly.configure_logging(logging.CRITICAL)",
                "crashonly.install()",
                "def boom(): raise RuntimeError('a genuine bug, not hostile input')",
                "threading.Thread(target=boom, name='maintenance', daemon=True).start()",
                "threading.Event().wait(5)",
                "print('STILL ALIVE')",
            ]
        )
        r = subprocess.run([sys.executable, "-c", prog], capture_output=True, text=True, timeout=30)
        self.assertEqual(r.returncode, 70)  # EX_SOFTWARE, not a quiet 0
        self.assertNotIn("STILL ALIVE", r.stdout)  # never reached the wait
        self.assertIn("RuntimeError", r.stderr)  # ...and the cause is on the record


class TestA4WindowRegression(unittest.TestCase):
    """NOTES item 13: an op committed in the (cut, checkpoint-op) hlc window
    that targets a lineage sealed below the cut folds IDENTICALLY for
    full-history and bootstrap clients — stale for both (the barrier sits at
    the cut, and dead keys leave the attributable universe)."""

    def test_window_op_folds_identically(self):
        w = World(seed=11, n_clients=2)
        control = list(w.all_control())
        below = list(control)
        KEY = b"doomed"
        below.append(
            w.cas(
                0, KEY, A.VERSION_ABSENT, 0, [[A.Guard.ABSENT, KEY]], [[A.Mutation.SET, KEY, b"v"]]
            )
        )
        r = fold.fold(below, w.keyring, w.genesis)
        v, a = r.lineage(KEY)
        below.append(w.cas(0, KEY, v, a, [[A.Guard.PRESENT, KEY]], [[A.Mutation.DEL, KEY]]))
        r_below = fold.fold(below, w.keyring, w.genesis)
        tomb_v, tomb_a = r_below.lineage(KEY)
        self.assertNotEqual(tomb_v, A.VERSION_ABSENT)  # tombstone anchors the lineage

        snap = fold.make_barrier(r_below)
        cut = {c.pub: A.HeadEntry(c.seq - 1, c.prev) for c in w.clients if c.seq > 0}
        cut[w.mgr_pub] = A.HeadEntry(w._mseq - 1, w._mprev)

        # x lands with hlc BELOW the checkpoint op's hlc (normal concurrent
        # traffic while the manager mints) but targets the sealed tombstone.
        x = w.cas(
            1,
            KEY,
            tomb_v,
            tomb_a,
            [[A.Guard.VERSION_EQ, KEY, tomb_v]],
            [[A.Mutation.SET, KEY, b"reborn"]],
        )
        ckpt = w.checkpoint(cut=cut, keyepoch=0)

        full = fold.fold(below + [x, ckpt], w.keyring, w.genesis)
        boot = fold.fold(control + [x], w.keyring, w.genesis, barrier=snap, cut_frontier=cut)
        self.assertEqual(full.verdicts[x.op_hash], fold.Verdict.STALE)
        self.assertEqual(boot.verdicts[x.op_hash], fold.Verdict.STALE)
        self.assertEqual(full.state, boot.state)
        self.assertNotIn(KEY, full.state)


class TestA2UniversalLineageAdvance(unittest.TestCase):
    """NOTES item 14: an op that folds `invalid` but is attributed to a
    current expected tag still consumes the slot — the revocation race can
    never wedge a key."""

    def test_revoked_authors_op_consumes_its_slot(self):
        w = World(seed=12, n_clients=2)
        ops = list(w.all_control())
        KEY = b"wedge"
        ops.append(
            w.cas(
                0, KEY, A.VERSION_ABSENT, 0, [[A.Guard.ABSENT, KEY]], [[A.Mutation.SET, KEY, b"v"]]
            )
        )
        r1 = fold.fold(ops, w.keyring, w.genesis)
        v, a = r1.lineage(KEY)
        ops.append(w.revoke(1))  # sorts before client 1's op below
        bad = w.cas(1, KEY, v, a, [[A.Guard.VERSION_EQ, KEY, v]], [[A.Mutation.SET, KEY, b"evil"]])
        ops.append(bad)
        r2 = fold.fold(ops, w.keyring, w.genesis)
        self.assertEqual(r2.verdicts[bad.op_hash], fold.Verdict.INVALID)
        self.assertEqual(r2.state[KEY], b"v")  # no mutation applied
        # the slot is consumed: lineage advanced, the decided tag is never
        # expected again (A2), the next CAS gets a fresh slot.
        self.assertEqual(r2.lineage(KEY), (v, a + 1))
        fresh = A.Slot(KEY, v, a + 1).tag(w.keyring[0].slot_secret)
        assert isinstance(bad, A.Slotted)
        self.assertNotEqual(fresh, bad.slot_tag)

    def test_shuffle_invariance_with_revocation(self):
        w = World(seed=13, n_clients=2)
        ops = list(w.all_control())
        ops.append(
            w.cas(
                0,
                b"k",
                A.VERSION_ABSENT,
                0,
                [[A.Guard.ABSENT, b"k"]],
                [[A.Mutation.SET, b"k", b"1"]],
            )
        )
        r = fold.fold(ops, w.keyring, w.genesis)
        v, a = r.lineage(b"k")
        ops.append(w.revoke(1))
        ops.append(w.cas(1, b"k", v, a, [], [[A.Mutation.SET, b"k", b"2"]]))
        base = fold.fold(ops, w.keyring, w.genesis)
        for k in range(4):
            sh = ops[:]
            random.Random(k).shuffle(sh)
            r2 = fold.fold(sh, w.keyring, w.genesis)
            self.assertEqual(r2.state, base.state)
            self.assertEqual(r2.verdicts, base.verdicts)


class TestLane2Fence(unittest.TestCase):
    """NOTES item 15: pver gates every op class; activation is pending until a
    checkpoint barrier; an unsupported activation halts the fold."""

    def test_pver_fence_gates_control_ops(self):
        w = World(seed=14, n_clients=1)
        ops = list(w.all_control())
        op = A.RotateOp.build(
            author=C.SoftwareKeypair.from_seed(w.mgr_sk),
            seq=w._mseq,
            prev=w._mprev,
            hlc=w.tick(),
            keyepoch=1,
            pver=99,
        )
        ops.append(op)
        r = fold.fold(ops, w.keyring, w.genesis)
        self.assertEqual(r.verdicts[op.op_hash], fold.Verdict.INVALID)
        self.assertEqual(r.control.active_keyepoch, 0)  # the rotate did NOT apply

    def test_activation_is_pending_until_barrier(self):
        w = World(seed=15, n_clients=1)
        ops = list(w.all_control())
        pv = w._mgr_op(partial(A.PverActivateOp.build, activate_pver=1))
        ops.append(pv)
        r = fold.fold(ops, w.keyring, w.genesis)  # no checkpoint -> no barrier
        self.assertEqual(r.verdicts[pv.op_hash], fold.Verdict.CONTROL)
        self.assertEqual(r.control.pver, 0)  # still pending
        self.assertEqual(r.control.pending_pver, 1)

    def test_unsupported_activation_halts_at_barrier(self):
        w = World(seed=16, n_clients=1)
        ops = list(w.all_control())
        pv = w._mgr_op(partial(A.PverActivateOp.build, activate_pver=fold.SUPPORTED_PVER + 1))
        ops.append(pv)
        cut = {w.mgr_pub: A.HeadEntry(w._mseq - 1, w._mprev)}
        ckpt = w.checkpoint(cut=cut, keyepoch=0)
        ops.append(ckpt)
        with self.assertRaises(fold.FoldHalted) as cm:
            fold.fold(ops, w.keyring, w.genesis)
        self.assertEqual(cm.exception.pver, fold.SUPPORTED_PVER + 1)
        # fail-stop read-only: the sealed result at the fence is served
        self.assertEqual(cm.exception.sealed.control.pver, fold.SUPPORTED_PVER + 1)

    def test_unknown_mutation_kind_is_malformed_not_partial(self):
        w = World(seed=17, n_clients=1)
        ops = list(w.all_control())
        op = w.blind(0, [], [[b"increment", b"ctr", b"5"], [A.Mutation.SET, b"k", b"v"]])
        ops.append(op)
        r = fold.fold(ops, w.keyring, w.genesis)
        self.assertEqual(r.verdicts[op.op_hash], fold.Verdict.REJECTED)  # whole txn
        self.assertNotIn(b"k", r.state)  # NOT a partial apply
        self.assertNotIn(b"ctr", r.state)


class TestSubmitGates(unittest.TestCase):
    """rev 5 (NOTES item 21 + item 16 amendment): a slotted op sent via SUBMIT is
    rejected `needs_ballot` (it must be proposed via PREPARE/ACCEPT); the SUBMIT
    contiguity gate now binds blind writes, and a signed frontier never claims an
    orphan head."""

    def _acceptor(self):
        nsk = bytes([77] * 32)
        return Acceptor(C.SoftwareKeypair.from_seed(nsk), ChainStore(), 0, DELTA)

    def _blind(self, w, ci, hlc_ms):
        txn = A.Txn(slot=None, guards=[], mutations=[[A.Mutation.SET, b"a", b"1"]])
        return w.data_op(ci, txn=txn, slot_tag=None, hlc=HLC(hlc_ms, 0))

    def _slotted(self, w, ci, key, hlc_ms):
        tag = A.Slot(key, A.VERSION_ABSENT, 0).tag(w.keyring[0].slot_secret)
        txn = A.Txn(
            slot=A.Slot(key, A.VERSION_ABSENT, 0),
            guards=[],
            mutations=[[A.Mutation.SET, key, b"1"]],
        )
        return w.data_op(ci, txn=txn, slot_tag=tag, hlc=HLC(hlc_ms, 0)), tag

    def test_slotted_submit_is_needs_ballot(self):
        w = World(seed=18, n_clients=1)
        acc = self._acceptor()
        op, _ = self._slotted(w, 0, b"a", NOW)
        r = acc.on_submit(op, NOW)
        assert isinstance(r, Rejected)
        self.assertEqual(r.reason, RejectReason.NEEDS_BALLOT)
        with acc.store.read_txn() as tx:
            self.assertEqual(tx.heads(), {})  # nothing stored via SUBMIT

    def test_blind_submit_with_gap_is_rejected(self):
        w = World(seed=18, n_clients=1)
        acc = self._acceptor()
        op0 = self._blind(w, 0, NOW)  # seq 0 — NOT submitted
        op1 = self._blind(w, 0, NOW + 1)  # seq 1
        r = acc.on_submit(op1, NOW)
        assert isinstance(r, Rejected)
        self.assertEqual(r.reason, RejectReason.UNKNOWN_PREV)
        with acc.store.read_txn() as tx:
            self.assertEqual(tx.heads(), {})  # nothing claimed
        # push the predecessor, then the op is accepted
        assert isinstance(acc.on_submit(op0, NOW), A.Receipt)
        assert isinstance(acc.on_submit(op1, NOW), A.Receipt)
        with acc.store.read_txn() as tx:
            self.assertEqual(tx.heads()[w.clients[0].pub][0], 1)

    def test_ballot_accept_orphan_is_stored_but_not_a_head(self):
        w = World(seed=19, n_clients=1)
        acc = self._acceptor()
        _skip0, _ = self._slotted(w, 0, b"a", NOW)  # seq 0 — never reaches the node
        op1, tag = self._slotted(w, 0, b"b", NOW + 1)  # seq 1 — via ballot recovery
        b = Ballot(1, b"recoverer")
        assert isinstance(acc.on_prepare(tag, b), A.Promise)
        assert isinstance(acc.on_accept(tag, b, op1, NOW), A.Receipt)
        with acc.store.read_txn() as tx:
            self.assertIsNotNone(tx.get_op(op1.op_hash))  # stored (re-proposable)
            self.assertEqual(tx.heads(), {})  # but never a frontier claim


class TestFoldTotalityOverGarbage(unittest.TestCase):
    """NOTES item 17: sig-invalid ops cannot poison an honest author's chain,
    and the fold is total over adversarial soups."""

    def test_forged_op_cannot_poison_author_chain(self):
        w = World(seed=20, n_clients=2)
        ops = list(w.all_control())
        victim = w.clients[0]
        o0 = w.blind(0, [], [[A.Mutation.SET, b"k", b"1"]])
        ops.append(o0)
        forged = w._forged_data(
            w.clients[1].sk,  # signed with the WRONG key on purpose
            victim.pub,
            seq=1,
            prev=o0.op_hash,
            hlc=A.HLC(10**12, 0),  # a poison-attempt hlc
            keyepoch=0,
            payload=b"x" * 48,
            slot_tag=None,
        )
        ops.append(forged)
        o1 = w.blind(0, [], [[A.Mutation.SET, b"k", b"2"]])
        o2 = w.blind(0, [], [[A.Mutation.SET, b"k", b"3"]])
        ops += [o1, o2]
        r = fold.fold(ops, w.keyring, w.genesis)
        self.assertEqual(r.verdicts[forged.op_hash], fold.Verdict.INVALID)
        self.assertEqual(r.verdicts[o1.op_hash], fold.Verdict.APPLIED)
        self.assertEqual(r.verdicts[o2.op_hash], fold.Verdict.APPLIED)  # NOT poisoned
        self.assertEqual(r.state[b"k"], b"3")

    def test_equivocating_author_folds_deterministically(self):
        # DESIGN §4: forked ops fold in op_hash order; determinism never waits
        # for punishment. (The missing "forks" coverage from IMPLEMENTATION M1.)
        w = World(seed=21, n_clients=1)
        ops = list(w.all_control())
        a = w.blind(0, [], [[A.Mutation.SET, b"k", b"one"]])  # seq 0
        w.clients[0].seq, w.clients[0].prev = 0, A.GENESIS_PREV  # self-fork
        b = w.blind(0, [], [[A.Mutation.SET, b"k", b"two"]])  # seq 0 again
        self.assertNotEqual(a.op_hash, b.op_hash)
        ops += [a, b]
        base = fold.fold(ops, w.keyring, w.genesis)
        # both verdicts exist; the state is single-valued and shuffle-invariant
        self.assertIn(base.verdicts[a.op_hash], (fold.Verdict.APPLIED, fold.Verdict.REJECTED))
        self.assertIn(base.verdicts[b.op_hash], (fold.Verdict.APPLIED, fold.Verdict.REJECTED))
        self.assertIn(base.state[b"k"], (b"one", b"two"))
        for k in range(4):
            sh = ops[:]
            random.Random(k).shuffle(sh)
            r2 = fold.fold(sh, w.keyring, w.genesis)
            self.assertEqual(r2.state, base.state)
            self.assertEqual(r2.verdicts, base.verdicts)


if __name__ == "__main__":
    unittest.main()
