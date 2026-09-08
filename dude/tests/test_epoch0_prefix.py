"""Tests for epoch=0 plaintext keys and prefix query primitives.

Verifies that epoch=0 writes settle on data stores, that count_prefix and
nth_prefix work correctly, and that the plaintext flag threads through
all substrate implementations.
"""

import unittest

from ..core import codec, crypto
from ..core.units import Millis
from ..store import management, ops, smt
from ..store.settle import Reason
from ..store.store import Store
from ..tests.cluster import Cluster


class TestEpoch0Settlement(unittest.TestCase):
    def setUp(self) -> None:
        self.kp = crypto.Keypair.generate()
        self.s = Store()
        self.s.provision(self.kp.public)
        self.mgmt = self.s.mgmt_reader

    def _apply(self, *muts: ops.Mutation) -> Reason | None:
        got = self.s.apply((ops.writes(*muts).sign(self.kp, Millis.now()),), auth=self.mgmt)
        return got.dropped[0].why if got.dropped else None

    def test_epoch0_plaintext_settles_on_data_store(self) -> None:
        self.assertIsNone(self._apply(ops.Set(ops.STORE_DATA, b"pending/job1", b"payload")))
        held = self.s.get(ops.STORE_DATA, b"pending/job1")
        assert held is not None
        self.assertEqual(held.value, b"payload")
        self.assertEqual(held.epoch, 0)

    def test_epoch0_coexists_with_encrypted_keys(self) -> None:
        token = crypto.NameToken(bytes(32))
        self.assertIsNone(
            self._apply(
                ops.Set(ops.STORE_DATA, b"queue/item", b"pointer", epoch=0),
                ops.Set(ops.STORE_DATA, token, b"encrypted", epoch=0),
            )
        )
        qi = self.s.get(ops.STORE_DATA, b"queue/item")
        assert qi is not None
        self.assertEqual(qi.value, b"pointer")
        tk = self.s.get(ops.STORE_DATA, token)
        assert tk is not None
        self.assertEqual(tk.value, b"encrypted")

    def test_epoch0_always_valid_after_rotation(self) -> None:
        self._apply(
            ops.Set(
                ops.STORE_MANAGEMENT,
                management.epoch_key(ops.STORE_DATA),
                codec.encode(1),
            )
        )
        self.assertEqual(self.mgmt.current_epoch(ops.STORE_DATA), 1)
        self.assertIsNone(
            self._apply(ops.Set(ops.STORE_DATA, b"still/works", b"yes", epoch=0)),
            "epoch=0 must be valid after rotation",
        )

    def test_name_over_128_bytes_rejected(self) -> None:
        self.assertIs(
            self._apply(ops.Set(ops.STORE_DATA, b"x" * 129, b"v", epoch=0)),
            Reason.NAME_SHAPE,
        )

    def test_128_byte_name_accepted(self) -> None:
        self.assertIsNone(self._apply(ops.Set(ops.STORE_DATA, b"x" * 128, b"v", epoch=0)))

    def test_two_epoch_grace_window(self) -> None:
        dk = bytes(32)
        self._apply(
            ops.Set(
                ops.STORE_MANAGEMENT,
                management.epoch_key(ops.STORE_DATA),
                codec.encode(1),
            )
        )
        self._apply(
            ops.Set(
                ops.STORE_MANAGEMENT,
                management.epoch_key(ops.STORE_DATA),
                codec.encode(2),
            )
        )
        self.assertEqual(self.mgmt.current_epoch(ops.STORE_DATA), 2)
        self.assertIsNone(
            self._apply(ops.Set(ops.STORE_DATA, dk, b"v", epoch=1)),
            "previous epoch should be accepted (grace window)",
        )
        self.assertIsNone(
            self._apply(ops.Set(ops.STORE_DATA, dk, b"v", epoch=2)),
            "current epoch should be accepted",
        )


class TestPrefixQueries(unittest.TestCase):
    def setUp(self) -> None:
        self.kp = crypto.Keypair.generate()
        self.s = Store()
        self.s.provision(self.kp.public)
        self.s.apply(
            (
                ops.writes(
                    ops.Set(ops.STORE_DATA, b"pending/aaa", b"p1"),
                    ops.Set(ops.STORE_DATA, b"pending/bbb", b"p2"),
                    ops.Set(ops.STORE_DATA, b"pending/ccc", b"p3"),
                    ops.Set(ops.STORE_DATA, b"active/w1/aaa", b"r1"),
                ).sign(self.kp, Millis.now()),
            ),
            auth=self.s.mgmt_reader,
        )

    def test_count_prefix(self) -> None:
        self.assertEqual(self.s.count_prefix(ops.STORE_DATA, b"pending/"), 3)
        self.assertEqual(self.s.count_prefix(ops.STORE_DATA, b"active/"), 1)
        self.assertEqual(self.s.count_prefix(ops.STORE_DATA, b"missing/"), 0)

    def test_nth_prefix_returns_sorted(self) -> None:
        r0 = self.s.nth_prefix(ops.STORE_DATA, b"pending/", 0)
        r1 = self.s.nth_prefix(ops.STORE_DATA, b"pending/", 1)
        r2 = self.s.nth_prefix(ops.STORE_DATA, b"pending/", 2)
        r3 = self.s.nth_prefix(ops.STORE_DATA, b"pending/", 3)
        assert r0 is not None
        assert r1 is not None
        assert r2 is not None
        self.assertIsNone(r3)
        self.assertEqual(r0[0], b"pending/aaa")
        self.assertEqual(r1[0], b"pending/bbb")
        self.assertEqual(r2[0], b"pending/ccc")

    def test_nth_prefix_result_is_provable(self) -> None:
        result = self.s.nth_prefix(ops.STORE_DATA, b"pending/", 0)
        assert result is not None
        name, held = result
        with self.s.snapshot() as r:
            proof = r.prove(ops.STORE_DATA, name)
            root = r.state_root()
        self.assertTrue(
            smt.verify(
                root,
                ops.STORE_DATA,
                name,
                (held.value, held.cred, held.epoch),
                proof,
            )
        )

    def test_count_only_matches_epoch0(self) -> None:
        self.s.apply(
            (
                ops.writes(
                    ops.Set(
                        ops.STORE_MANAGEMENT,
                        management.epoch_key(ops.STORE_DATA),
                        codec.encode(1),
                    )
                ).sign(self.kp, Millis.now()),
            ),
            auth=self.s.mgmt_reader,
        )
        token = bytes(32)
        self.s.apply(
            (
                ops.writes(ops.Set(ops.STORE_DATA, token, b"encrypted", epoch=1)).sign(
                    self.kp, Millis.now()
                ),
            ),
            auth=self.s.mgmt_reader,
        )
        self.assertEqual(
            self.s.count_prefix(ops.STORE_DATA, b"pending/"),
            3,
            "epoch!=0 key should not be counted",
        )


class TestSessionPlaintextFlag(unittest.TestCase):
    def test_replica_session_plaintext_put_and_get(self) -> None:
        c = Cluster(nodes=3)
        try:
            s = c.replicas[0].session()
            s.put("queue/job1", b"pointer", plaintext=True).wait()
            c.wait_settled(s.put("queue/job2", b"ptr2", plaintext=True).wait())

            rec = s.get("queue/job1", plaintext=True)
            self.assertFalse(rec.absent)
            self.assertEqual(rec.value, b"pointer")
            self.assertEqual(rec.epoch, 0)
            self.assertEqual(rec.token, b"queue/job1")

            rec2 = s.get("queue/job2", plaintext=True)
            self.assertFalse(rec2.absent)
            self.assertEqual(rec2.value, b"ptr2")
        finally:
            for n in c.nodes:
                n.stop()
            for r in c.replicas:
                r.stop()

    def test_direct_store_prefix_queries(self) -> None:
        c = Cluster(nodes=3)
        try:
            s = c.replicas[0].session()
            for i in range(3):
                s.put(f"q/{i}", f"v{i}".encode(), plaintext=True).wait()
            c.wait_settled(s.put("q/3", b"v3", plaintext=True).wait())

            store = c.replicas[0].store
            count = store.count_prefix(ops.STORE_DATA, b"q/")
            self.assertEqual(count, 4)

            nth = store.nth_prefix(ops.STORE_DATA, b"q/", 0)
            assert nth is not None
            name, held = nth
            self.assertEqual(name, b"q/0")
            self.assertEqual(held.value, b"v0")
        finally:
            for n in c.nodes:
                n.stop()
            for r in c.replicas:
                r.stop()


if __name__ == "__main__":
    unittest.main()
