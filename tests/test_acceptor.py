# M2 — L3 Acceptor: the B1 slot-safety scenarios (IMPLEMENTATION.md M2).
# rev 5 (NOTES item 21): the ballot-0 fast path is gone — slotted ops decide only
# via two-phase PREPARE/ACCEPT, so SUBMIT is blind-only. Covers: slotted SUBMIT
# -> needs_ballot, double-vote refusal, promise/accept ordering, skew gates,
# floor monotonicity, and single-decree via ballot recovery across a quorum.

import unittest

from dudefs import artifacts as A
from dudefs import crypto as C
from dudefs.acceptor import Acceptor, Nack, Rejected, RejectReason
from dudefs.artifacts import HLC, Ballot
from dudefs.store import ChainStore
from tests._builders import World

KEY = b"jobs/1/state"
NOW = 10_000
DELTA = 100


def _node(seed_byte):
    sk = bytes([seed_byte] * 32)
    return sk, C.SIGNER.public(sk)


def _slot_op(w, ci, val, hlc_ms):
    """A creation-CAS op on KEY at (⊥,0) — two clients produce the SAME tag."""
    tag = A.Slot(KEY, A.VERSION_ABSENT, 0).tag(w.keyring[0].slot_secret)
    txn = A.Txn(
        slot=A.Slot(KEY, A.VERSION_ABSENT, 0),
        guards=[[A.Guard.ABSENT, KEY]],
        mutations=[[A.Mutation.SET, KEY, val]],
    )
    return w.data_op(ci, txn=txn, slot_tag=tag, hlc=HLC(hlc_ms, 0)), tag


class TestSubmitRejectsSlotted(unittest.TestCase):
    def setUp(self):
        self.w = World(seed=1, n_clients=2)
        self.nsk, self.npub = _node(200)
        self.acc = Acceptor(C.SoftwareKeypair.from_seed(self.nsk), ChainStore(), 0, DELTA)

    def test_slotted_submit_is_needs_ballot(self):
        op, _ = _slot_op(self.w, 0, b"a", NOW)
        r = self.acc.on_submit(op, NOW)
        assert isinstance(r, Rejected)  # rev 5: no fast path — propose via ballot
        self.assertEqual(r.reason, RejectReason.NEEDS_BALLOT)
        with self.acc.store.read_txn() as tx:
            self.assertIsNone(tx.get_op(op.op_hash))  # not stored either

    def test_accept_then_idempotent(self):
        # the two-phase accept path is the only way in; re-accepting the same op
        # at the same (tag, ballot) re-yields the identical receipt.
        op, tag = _slot_op(self.w, 0, b"a", NOW)
        b = Ballot(1, b"client-x")
        r = self.acc.on_accept(tag, b, op, NOW)
        assert isinstance(r, A.Receipt)
        self.assertTrue(r.verify())
        self.assertEqual(r.ballot, b)
        r2 = self.acc.on_accept(tag, b, op, NOW)
        assert isinstance(r2, A.Receipt)
        self.assertEqual(r2.ballot, r.ballot)


class TestRecoveryOrdering(unittest.TestCase):
    def setUp(self):
        self.w = World(seed=2, n_clients=2)
        self.nsk, self.npub = _node(201)
        self.acc = Acceptor(C.SoftwareKeypair.from_seed(self.nsk), ChainStore(), 0, DELTA)

    def test_promise_accept_ordering_and_nack(self):
        opA, tag = _slot_op(self.w, 0, b"a", NOW)
        # accept opA at a low ballot (the only way a slotted op enters — rev 5)
        b0 = Ballot(1, b"aaa")
        assert isinstance(self.acc.on_accept(tag, b0, opA, NOW), A.Receipt)
        # prepare at a higher ballot -> Promise reporting the accepted op
        b1 = Ballot(2, b"client-x")
        pr = self.acc.on_prepare(tag, b1)
        assert isinstance(pr, A.Promise)
        self.assertTrue(pr.verify())
        self.assertEqual(pr.accepted_op_hash, opA.op_hash)
        self.assertEqual(pr.accepted_ballot, b0)
        # an accept BELOW the promise is Nack'd
        low = self.acc.on_accept(tag, b0, opA, NOW)
        assert isinstance(low, Nack)
        self.assertEqual(low.promised, b1)
        # accept AT the promised ballot -> receipt
        ok = self.acc.on_accept(tag, b1, opA, NOW)
        assert isinstance(ok, A.Receipt)
        self.assertEqual(ok.ballot, b1)

    def test_double_vote_guard(self):
        opA, tag = _slot_op(self.w, 0, b"a", NOW)
        opB, _ = _slot_op(self.w, 1, b"b", NOW)
        b = Ballot(2, b"cli")
        assert isinstance(self.acc.on_prepare(tag, b), A.Promise)
        assert isinstance(self.acc.on_accept(tag, b, opA, NOW), A.Receipt)
        # a second, DIFFERENT op at the same (tag, ballot) must be refused —
        # signing it would be portable equivocation (DESIGN §8).
        r = self.acc.on_accept(tag, b, opB, NOW)
        assert isinstance(r, Rejected)
        self.assertEqual(r.reason, RejectReason.EQUIVOCATION_GUARD)


class TestSkewAndFloor(unittest.TestCase):
    def setUp(self):
        self.w = World(seed=3, n_clients=1)
        self.nsk, self.npub = _node(202)
        self.acc = Acceptor(C.SoftwareKeypair.from_seed(self.nsk), ChainStore(), 0, DELTA)

    def test_future_and_past_gates(self):
        # skew gates bind ballot ACCEPT of slotted ops (rev 5: the slotted path);
        # a fresh slot's promised is the low BLIND sentinel, so the ballot passes
        # and the skew check is what fires.
        b = Ballot(1, b"x")
        future, tag = _slot_op(self.w, 0, b"a", NOW + 2 * DELTA)  # beyond now+δ
        r = self.acc.on_accept(tag, b, future, NOW)
        assert isinstance(r, Rejected)
        self.assertEqual(r.reason, RejectReason.FUTURE_HLC)
        # floor = max(hw, now) − δ advances on wall-clock alone, so an op dated
        # far below `now − δ` is refused as below_floor (DESIGN §9).
        past, tag2 = _slot_op(self.w, 0, b"c", NOW - 2 * DELTA)
        r2 = self.acc.on_accept(tag2, b, past, NOW)
        assert isinstance(r2, Rejected)
        self.assertEqual(r2.reason, RejectReason.BELOW_FLOOR)

    def test_floor_is_monotone(self):
        # advance the floor via a watermark, then a lower now must not lower it
        wm1 = self.acc.issue_watermark(NOW)
        self.assertTrue(wm1.verify())
        with self.acc.store.read_txn() as tx:
            f1 = self.acc.floor(tx, NOW)
        wm2 = self.acc.issue_watermark(NOW - 5 * DELTA)  # clock jumps backward
        with self.acc.store.read_txn() as tx:
            self.assertGreaterEqual(tx.get_attested().as_tuple(), f1.as_tuple())
        self.assertTrue(wm2.floor >= f1)  # never regresses


class TestSingleDecree(unittest.TestCase):
    """B1 (rev 5, unconditional): at most one op per slot_tag is ever decided,
    across all ballots. Here a 2–2 split (n=5, one down) is resolved by ballot
    recovery, which re-proposes the highest accepted op — never two winners."""

    def _cluster(self, n=5):
        nodes = []
        for i in range(n):
            sk, pub = _node(210 + i)
            nodes.append(Acceptor(C.SoftwareKeypair.from_seed(sk), ChainStore(), 0, DELTA))
        pubs = [nd.node.public for nd in nodes]
        return nodes, pubs, {p: i for i, p in enumerate(pubs)}

    def test_split_vote_recovers_to_one_winner(self):
        w = World(seed=4, n_clients=2)
        nodes, pubs, index = self._cluster(5)
        opA, tag = _slot_op(w, 0, b"A", NOW)
        opB, _ = _slot_op(w, 1, b"B", NOW)
        # split at ballot 1 (rev 5: slotted ops enter via ACCEPT): nodes 0,1
        # accept A; nodes 2,3 accept B; node 4 is down.
        bA, bB = Ballot(1, b"\x01"), Ballot(1, b"\x02")
        for i in (0, 1):
            assert isinstance(nodes[i].on_accept(tag, bA, opA, NOW), A.Receipt)
        for i in (2, 3):
            assert isinstance(nodes[i].on_accept(tag, bB, opB, NOW), A.Receipt)
        # neither has a quorum (need 3) -> recovery on a live quorum {0,1,2}
        quorum = [0, 1, 2]
        b = Ballot(2, b"recoverer")
        promises = [nodes[i].on_prepare(tag, b) for i in quorum]
        for p in promises:
            assert isinstance(p, A.Promise)
        # MUST re-propose the highest-ballot accepted op (DESIGN §8)
        best = None
        for p in promises:
            if p.accepted_op_hash is not None:
                if best is None or p.accepted_ballot > best[0]:
                    best = (p.accepted_ballot, p.accepted_op_hash)
        assert best is not None  # the split guarantees at least one accepted op
        chosen_hash = best[1]

        def _getop(nd):
            with nd.store.read_txn() as tx:
                return tx.get_op(chosen_hash)

        chosen = _getop(nodes[quorum[0]]) or _getop(nodes[quorum[1]]) or _getop(nodes[quorum[2]])
        receipts = []
        for i in quorum:
            r = nodes[i].on_accept(tag, b, chosen, NOW)
            assert isinstance(r, A.Receipt)
            receipts.append(r)
        qc = A.QC.assemble(receipts, 5, index)
        self.assertTrue(qc.verify(pubs))
        self.assertEqual(qc.op_hash, chosen_hash)
        # the OTHER op can never gather a same-ballot quorum now: any node in the
        # quorum has promised b, so a stale accept of the loser below b is Nack'd.
        loser = opB if chosen_hash == opA.op_hash else opA
        stale = nodes[0].on_accept(tag, Ballot(1, b"\x00"), loser, NOW)
        assert isinstance(stale, Nack)


if __name__ == "__main__":
    unittest.main()
