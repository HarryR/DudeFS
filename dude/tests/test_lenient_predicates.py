import unittest

from dude.core import crypto
from dude.store import management, ops, settle, store

D = ops.STORE_DATA


def provisioned(kp: crypto.Keypair) -> tuple[store.Store, management.MgmtReader]:
    s = store.Store()
    s.provision(kp.public)
    return s, s.mgmt_reader


class TestLenientPredicates(unittest.TestCase):
    def setUp(self):
        self.kp = crypto.Keypair.generate()
        self.s, self.mgmt = provisioned(self.kp)
        self.K = crypto.NameToken(crypto.h(b"K"))
        self.J = crypto.NameToken(crypto.h(b"J"))
        self.L = crypto.NameToken(crypto.h(b"L"))

    def _apply(self, tx: ops.Transaction) -> store.Applied:
        return self.s.apply((tx.sign(self.kp, 1),), auth=self.mgmt)

    def test_soft_steps_skip_on_guard_failure(self) -> None:
        self._apply(ops.Transaction(()).then(ops.Set(D, self.K, b"v1")))

        d_wrong = ops.value_digest(b"nope")

        tx = (
            ops.Transaction(())
            .then_soft(ops.Set(D, self.K, b"updated"), ops.Holds(D, self.K, d_wrong))
            .then(ops.Set(D, self.J, b"created"))
            .then_soft(ops.Set(D, self.L, b"also_created"), ops.Absent(D, self.L))
        )
        r = self._apply(tx)

        self.assertEqual(len(r.settled), 1)
        self.assertEqual(len(r.dropped), 0)

        k = self.s.get(D, self.K)
        assert k is not None
        self.assertEqual(k.value, b"v1")

        j = self.s.get(D, self.J)
        assert j is not None
        self.assertEqual(j.value, b"created")

        l_val = self.s.get(D, self.L)
        assert l_val is not None
        self.assertEqual(l_val.value, b"also_created")

    def test_hard_step_still_fails_whole_transaction(self) -> None:
        d_wrong = ops.value_digest(b"nope")

        tx = (
            ops.Transaction(())
            .then(ops.Set(D, self.J, b"should_not_land"))
            .then(ops.Set(D, self.K, b"fail_here"), ops.Holds(D, self.K, d_wrong))
        )
        r = self._apply(tx)

        self.assertEqual(len(r.settled), 0)
        self.assertEqual(len(r.dropped), 1)
        self.assertEqual(r.dropped[0][1], settle.Reason.GUARD)
        self.assertIsNone(self.s.get(D, self.J))

    def test_exists_and_holds_any(self) -> None:
        self._apply(ops.Transaction(()).then(ops.Set(D, self.K, b"v1")))

        d_v2 = ops.value_digest(b"v2")
        d_other = ops.value_digest(b"other")

        tx = (
            ops.Transaction(())
            .then(ops.Set(D, self.K, b"v2"), ops.Exists(D, self.K))
            .then_soft(
                ops.Set(D, self.J, b"skip_me"),
                ops.Exists(D, self.J),
            )
            .then(
                ops.Set(D, self.L, b"from_any"),
                ops.HoldsAny(D, self.K, (d_v2, d_other)),
            )
        )
        r = self._apply(tx)

        self.assertEqual(len(r.settled), 1)
        self.assertEqual(len(r.dropped), 0)

        k = self.s.get(D, self.K)
        assert k is not None
        self.assertEqual(k.value, b"v2")

        self.assertIsNone(self.s.get(D, self.J))

        l_val = self.s.get(D, self.L)
        assert l_val is not None
        self.assertEqual(l_val.value, b"from_any")

        tx2 = ops.Transaction(()).then(
            ops.Set(D, self.K, b"v3"),
            ops.HoldsAny(D, self.K, (d_v2, d_other)),
        )
        r2 = self._apply(tx2)
        self.assertEqual(len(r2.settled), 1)
        k2 = self.s.get(D, self.K)
        assert k2 is not None
        self.assertEqual(k2.value, b"v3")

    def test_holds_any_rejects_on_no_match(self) -> None:
        self._apply(ops.Transaction(()).then(ops.Set(D, self.K, b"v1")))

        tx = ops.Transaction(()).then(
            ops.Set(D, self.K, b"nope"),
            ops.HoldsAny(D, self.K, (ops.value_digest(b"a"), ops.value_digest(b"b"))),
        )
        r = self._apply(tx)

        self.assertEqual(len(r.dropped), 1)
        self.assertEqual(r.dropped[0][1], settle.Reason.GUARD)

    def test_encoding_roundtrip(self) -> None:
        tx = (
            ops.Transaction(())
            .then(ops.Set(D, self.K, b"v"), ops.Exists(D, self.K))
            .then_soft(
                ops.Set(D, self.J, b"w"),
                ops.HoldsAny(D, self.K, (ops.value_digest(b"a"), ops.value_digest(b"b"))),
            )
            .then(ops.Set(D, self.L, b"x"), ops.Absent(D, self.L))
        )
        decoded = ops.Transaction.decode(tx.encode())

        self.assertEqual(len(decoded.steps), 3)

        self.assertFalse(decoded.steps[0].soft)
        self.assertIsInstance(decoded.steps[0].guards[0], ops.Exists)

        self.assertTrue(decoded.steps[1].soft)
        g = decoded.steps[1].guards[0]
        self.assertIsInstance(g, ops.HoldsAny)
        assert isinstance(g, ops.HoldsAny)
        self.assertEqual(len(g.digests), 2)

        self.assertFalse(decoded.steps[2].soft)
        self.assertIsInstance(decoded.steps[2].guards[0], ops.Absent)


if __name__ == "__main__":
    unittest.main()
