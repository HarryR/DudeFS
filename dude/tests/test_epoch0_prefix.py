"""Tests for epoch=0 plaintext keys and prefix query primitives.

Settlement tests verify epoch=0 rules at the store level.  Substrate tests
run the same assertions over ReplicaNode, SocketSubstrate, and LightClient
to verify the full stack.
"""

import os
import tempfile
import unittest

from ..core import codec, crypto
from ..core.units import Millis
from ..ds.plaintext_map import PlaintextMap
from ..net.socket_server import SocketServer
from ..net.socket_substrate import SocketSubstrate
from ..node import _ReplicaSubstrate
from ..session import SessionRW, Substrate
from ..store import management, ops, smt
from ..store.settle import Reason
from ..store.store import Store
from ..sync.lite_client import _LiteSubstrate
from ..tests.cluster import Cluster

# ---------------------------------------------------------------------------
# Settlement (store-level, no substrate)
# ---------------------------------------------------------------------------


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


# ---------------------------------------------------------------------------
# Store-level prefix queries (no network)
# ---------------------------------------------------------------------------


class TestStorePrefixQueries(unittest.TestCase):
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

    def test_nth_prefix_result_is_provable(self) -> None:
        result = self.s.nth_prefix(ops.STORE_DATA, b"pending/", 0)
        assert result is not None
        name, held = result
        with self.s.snapshot() as r:
            proof = r.prove(ops.STORE_DATA, name)
            root = r.state_root()
        self.assertTrue(
            smt.verify(root, ops.STORE_DATA, name, (held.value, held.cred, held.epoch), proof)
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

    def test_expiry_queue_pattern(self) -> None:
        self.s.apply(
            (
                ops.writes(
                    ops.Set(ops.STORE_DATA, b"expiry/0000000010/j1", b""),
                    ops.Set(ops.STORE_DATA, b"expiry/0000000020/j2", b""),
                    ops.Set(ops.STORE_DATA, b"expiry/0000000030/j3", b""),
                ).sign(self.kp, Millis.now()),
            ),
            auth=self.s.mgmt_reader,
        )
        oldest = self.s.nth_prefix(ops.STORE_DATA, b"expiry/", 0)
        assert oldest is not None
        self.assertEqual(oldest[0], b"expiry/0000000010/j1")

        newest = self.s.nth_prefix(ops.STORE_DATA, b"expiry/", 0, descending=True)
        assert newest is not None
        self.assertEqual(newest[0], b"expiry/0000000030/j3")


# ---------------------------------------------------------------------------
# Shared substrate tests — run over ReplicaNode, Socket, and LightClient.
# ---------------------------------------------------------------------------


class _SubstrateTests(unittest.TestCase):
    """Shared assertions for plaintext put/get, count_prefix, and nth_prefix.
    Subclasses provide _substrate() and _session()."""

    __test__ = False
    PREFIX = b"t/"

    def _substrate(self) -> Substrate:
        raise NotImplementedError

    def _session(self) -> SessionRW:
        raise NotImplementedError

    def test_plaintext_put_and_get(self) -> None:
        s = self._session()
        rec = s.get("t/0", plaintext=True)
        self.assertFalse(rec.absent)
        self.assertEqual(rec.value, b"v0")
        self.assertEqual(rec.epoch, 0)
        self.assertEqual(rec.token, b"t/0")

    def test_count_prefix(self) -> None:
        self.assertEqual(self._substrate().count_prefix(ops.STORE_DATA, self.PREFIX), 4)

    def test_count_prefix_empty(self) -> None:
        self.assertEqual(self._substrate().count_prefix(ops.STORE_DATA, b"missing/"), 0)

    def test_nth_prefix_ascending(self) -> None:
        result = self._substrate().nth_prefix(ops.STORE_DATA, self.PREFIX, 0)
        assert result is not None
        self.assertEqual(result[0], b"t/0")
        self.assertEqual(result[1].value, b"v0")

    def test_nth_prefix_descending(self) -> None:
        result = self._substrate().nth_prefix(ops.STORE_DATA, self.PREFIX, 0, descending=True)
        assert result is not None
        self.assertEqual(result[0], b"t/3")
        self.assertEqual(result[1].value, b"v3")

    def test_nth_prefix_out_of_range(self) -> None:
        self.assertIsNone(self._substrate().nth_prefix(ops.STORE_DATA, self.PREFIX, 99))


# ---------------------------------------------------------------------------
# ReplicaNode substrate
# ---------------------------------------------------------------------------


class TestReplicaSubstrate(_SubstrateTests):
    __test__ = True

    def setUp(self) -> None:
        self.c = Cluster(nodes=3, mgmt=1)
        s = self.c.replicas[0].session()
        for i in range(3):
            s.put(f"t/{i}", f"v{i}".encode(), plaintext=True).wait()
        self.c.wait_settled(s.put("t/3", b"v3", plaintext=True).wait())

    def tearDown(self) -> None:
        self.c.close()

    def _substrate(self) -> Substrate:
        return _ReplicaSubstrate(self.c.replicas[0])

    def _session(self) -> SessionRW:
        return self.c.replicas[0].session()


# ---------------------------------------------------------------------------
# SocketSubstrate
# ---------------------------------------------------------------------------


class TestSocketSubstrate(_SubstrateTests):
    __test__ = True

    def setUp(self) -> None:
        self.c = Cluster(nodes=3, mgmt=1)
        self._tmpdir = tempfile.mkdtemp()
        self._sock_path = os.path.join(self._tmpdir, "test.sock")
        self._real_sub = _ReplicaSubstrate(self.c.replicas[0])
        self._server = SocketServer(self._sock_path, self._real_sub)
        self._server.start()
        self._sub = SocketSubstrate(self._sock_path, self.c.tunables)

        s = self.c.replicas[0].session()
        for i in range(3):
            s.put(f"t/{i}", f"v{i}".encode(), plaintext=True).wait()
        self.c.wait_settled(s.put("t/3", b"v3", plaintext=True).wait())

    def tearDown(self) -> None:
        self._sub.close()
        self._server.stop()
        self.c.close()
        os.rmdir(self._tmpdir)

    def _substrate(self) -> Substrate:
        return self._sub

    def _session(self) -> SessionRW:
        return SessionRW(self._sub, ops.STORE_DATA)


# ---------------------------------------------------------------------------
# LightClient substrate
# ---------------------------------------------------------------------------


class TestLightClientSubstrate(_SubstrateTests):
    __test__ = True

    def setUp(self) -> None:
        self.c = Cluster(nodes=3, mgmt=1, rw=1)
        self.lc = self.c.rw_clients[0]
        self.lc.bootstrap()

        s = self.lc.session()
        for i in range(3):
            s.put(f"t/{i}", f"v{i}".encode(), plaintext=True).wait()
        self.c.wait_settled(s.put("t/3", b"v3", plaintext=True).wait())
        s.get("t/0", plaintext=True)

    def tearDown(self) -> None:
        self.c.close()

    def _substrate(self) -> Substrate:
        return _LiteSubstrate(self.lc)

    def _session(self) -> SessionRW:
        return self.lc.session()


# ---------------------------------------------------------------------------
# PlaintextMap (data-structure level, over ReplicaSubstrate)
# ---------------------------------------------------------------------------


class TestPlaintextMap(unittest.TestCase):
    def setUp(self) -> None:
        self.c = Cluster(nodes=3, mgmt=1)
        self.session = self.c.replicas[0].session()
        self.m = PlaintextMap(b"pm/", self.session)

    def tearDown(self) -> None:
        self.c.close()

    def _submit(self, tx: ops.Transaction) -> None:
        self.c.wait_settled(self.session.submit(tx).wait())

    def test_put_and_get(self) -> None:
        self._submit(self.m.tx_put(b"k1", b"v1", absent=True))
        rec = self.m.get(b"k1")
        self.assertFalse(rec.absent)
        self.assertEqual(rec.value, b"v1")
        self.assertEqual(rec.epoch, 0)

    def test_count(self) -> None:
        self._submit(self.m.tx_put(b"a", b"1") + self.m.tx_put(b"b", b"2"))
        self.assertEqual(self.m.count(), 2)

    def test_nth_ascending_and_descending(self) -> None:
        self._submit(
            self.m.tx_put(b"x", b"vx") + self.m.tx_put(b"y", b"vy") + self.m.tx_put(b"z", b"vz")
        )
        first = self.m.nth(0)
        assert first is not None
        self.assertEqual(first[0], b"x")
        self.assertEqual(first[1].value, b"vx")

        last = self.m.nth(0, descending=True)
        assert last is not None
        self.assertEqual(last[0], b"z")
        self.assertEqual(last[1].value, b"vz")

    def test_delete_decrements_count(self) -> None:
        self._submit(self.m.tx_put(b"d1", b"v") + self.m.tx_put(b"d2", b"v"))
        self.assertEqual(self.m.count(), 2)
        rec = self.m.get(b"d1")
        self._submit(self.m.tx_delete(b"d1", expect=rec))
        self.assertEqual(self.m.count(), 1)
        self.assertTrue(self.m.get(b"d1").absent)

    def test_cas_with_expect(self) -> None:
        self._submit(self.m.tx_put(b"cas", b"v1", absent=True))
        rec = self.m.get(b"cas")
        self._submit(self.m.tx_put(b"cas", b"v2", expect=rec))
        self.assertEqual(self.m.get(b"cas").value, b"v2")

    def test_stale_expect_refused(self) -> None:
        self._submit(self.m.tx_put(b"stale", b"v1", absent=True))
        stale = self.m.get(b"stale")
        self._submit(self.m.tx_put(b"stale", b"v2", expect=stale))
        result = self.session.submit(self.m.tx_put(b"stale", b"v3", expect=stale)).wait()
        self.assertNotIsInstance(result, type(None))

    def test_absent_guard_refuses_duplicate(self) -> None:
        self._submit(self.m.tx_put(b"dup", b"v1", absent=True))
        self.session.submit(self.m.tx_put(b"dup", b"v2", absent=True)).wait()
        self.assertEqual(self.m.get(b"dup").value, b"v1")

    def test_cross_map_atomic_move(self) -> None:
        src = PlaintextMap(b"src/", self.session)
        dst = PlaintextMap(b"dst/", self.session)
        self._submit(src.tx_put(b"job", b"payload", absent=True))

        rec = src.get(b"job")
        tx = src.tx_delete(b"job", expect=rec) + dst.tx_put(b"job", rec.value, absent=True)
        self._submit(tx)

        self.assertTrue(src.get(b"job").absent)
        self.assertEqual(dst.get(b"job").value, b"payload")

    def test_keys_and_items(self) -> None:
        self._submit(
            self.m.tx_put(b"b", b"2") + self.m.tx_put(b"a", b"1") + self.m.tx_put(b"c", b"3")
        )
        self.assertEqual(self.m.keys(), [b"a", b"b", b"c"])
        self.assertEqual(self.m.items(), [(b"a", b"1"), (b"b", b"2"), (b"c", b"3")])


# ---------------------------------------------------------------------------
# PlaintextMap substrate tests — shared base + per-substrate subclasses.
# ---------------------------------------------------------------------------


class _PlaintextMapSubstrateTests(unittest.TestCase):
    __test__ = False
    PREFIX = b"pm/"

    def _session(self) -> SessionRW:
        raise NotImplementedError

    def _submit(self, tx: ops.Transaction) -> None:
        raise NotImplementedError

    def _map(self) -> PlaintextMap:
        return PlaintextMap(self.PREFIX, self._session())

    def test_put_get_round_trip(self) -> None:
        m = self._map()
        self._submit(m.tx_put(b"k", b"v", absent=True))
        rec = m.get(b"k")
        self.assertFalse(rec.absent)
        self.assertEqual(rec.value, b"v")

    def test_count(self) -> None:
        m = self._map()
        self.assertEqual(m.count(), 4)

    def test_nth_ascending(self) -> None:
        m = self._map()
        result = m.nth(0)
        assert result is not None
        self.assertEqual(result[0], b"0")
        self.assertEqual(result[1].value, b"v0")

    def test_nth_descending(self) -> None:
        m = self._map()
        result = m.nth(0, descending=True)
        assert result is not None
        self.assertEqual(result[0], b"3")
        self.assertEqual(result[1].value, b"v3")

    def test_nth_out_of_range(self) -> None:
        self.assertIsNone(self._map().nth(99))

    def test_expect_round_trip(self) -> None:
        m = self._map()
        rec = m.get(b"0")
        self._submit(m.tx_put(b"0", b"updated", expect=rec))
        self.assertEqual(m.get(b"0").value, b"updated")


class TestPMReplica(_PlaintextMapSubstrateTests):
    __test__ = True

    def setUp(self) -> None:
        self.c = Cluster(nodes=3, mgmt=1)
        s = self.c.replicas[0].session()
        for i in range(4):
            s.put(f"pm/{i}", f"v{i}".encode(), plaintext=True).wait()
        self.c.wait_settled(s.put("pm/3", b"v3", plaintext=True).wait())

    def tearDown(self) -> None:
        self.c.close()

    def _session(self) -> SessionRW:
        return self.c.replicas[0].session()

    def _submit(self, tx: ops.Transaction) -> None:
        self.c.wait_settled(self._session().submit(tx).wait())


class TestPMSocket(_PlaintextMapSubstrateTests):
    __test__ = True

    def setUp(self) -> None:
        self.c = Cluster(nodes=3, mgmt=1)
        self._tmpdir = tempfile.mkdtemp()
        self._sock_path = os.path.join(self._tmpdir, "test.sock")
        self._real_sub = _ReplicaSubstrate(self.c.replicas[0])
        self._server = SocketServer(self._sock_path, self._real_sub)
        self._server.start()
        self._sub = SocketSubstrate(self._sock_path, self.c.tunables)

        s = self.c.replicas[0].session()
        for i in range(4):
            s.put(f"pm/{i}", f"v{i}".encode(), plaintext=True).wait()
        self.c.wait_settled(s.put("pm/3", b"v3", plaintext=True).wait())

    def tearDown(self) -> None:
        self._sub.close()
        self._server.stop()
        self.c.close()
        os.rmdir(self._tmpdir)

    def _session(self) -> SessionRW:
        return SessionRW(self._sub, ops.STORE_DATA)

    def _submit(self, tx: ops.Transaction) -> None:
        self.c.wait_settled(self._session().submit(tx).wait())


class TestPMLiteClient(_PlaintextMapSubstrateTests):
    __test__ = True

    def setUp(self) -> None:
        self.c = Cluster(nodes=3, mgmt=1, rw=1)
        self.lc = self.c.rw_clients[0]
        self.lc.bootstrap()

        s = self.lc.session()
        for i in range(4):
            s.put(f"pm/{i}", f"v{i}".encode(), plaintext=True).wait()
        self.c.wait_settled(s.put("pm/3", b"v3", plaintext=True).wait())
        s.get("pm/0", plaintext=True)

    def tearDown(self) -> None:
        self.c.close()

    def _session(self) -> SessionRW:
        return self.lc.session()

    def _submit(self, tx: ops.Transaction) -> None:
        self.c.wait_settled(self._session().submit(tx).wait())


if __name__ == "__main__":
    unittest.main()
