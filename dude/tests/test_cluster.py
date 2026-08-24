
import unittest

from ..core.units import now_ms
from ..store import ops
from ..store.layer import Settled

from .cluster import Cluster

D = ops.STORE_DATA


class TestSessionViaReplicaNode(unittest.TestCase):

    def setUp(self) -> None:
        self.c = Cluster(nodes=3, mgmt=1, ro=0, rw=0)
        self.s = self.c.replicas[0].session()

    def tearDown(self) -> None:
        self.c.close()

    def test_put_and_get(self) -> None:
        self.c.wait_settled(self.s.put("hello", b"world").wait())
        rec = self.s.get("hello")
        self.assertFalse(rec.absent)
        self.assertEqual(rec.value, b"world")

    def test_value_is_encrypted_on_disk(self) -> None:
        self.s.put("secret", b"plaintext").wait()
        rec = self.s.get("secret")
        self.assertNotEqual(rec.raw, b"plaintext")
        self.assertEqual(rec.value, b"plaintext")

    def test_all_nodes_agree(self) -> None:
        self.c.wait_settled(self.s.put("consensus", b"check").wait())
        roots = {n.store.state_root() for n in self.c.nodes}
        accs = {n.store.accumulator() for n in self.c.nodes}
        self.assertEqual(len(roots), 1, "state roots disagree")
        self.assertEqual(len(accs), 1, "accumulators disagree")

    def test_management_node_syncs(self) -> None:
        self.c.wait_settled(self.s.put("sync-check", b"v").wait())
        rec = self.s.get("sync-check")
        self.assertEqual(rec.value, b"v")

    def test_guarded_put(self) -> None:
        self.c.wait_settled(self.s.put("k", b"v1").wait())
        rec = self.s.get("k")
        self.assertEqual(rec.value, b"v1")
        self.c.wait_settled(self.s.put("k", b"v2", expect=rec).wait())
        final = self.s.get("k")
        self.assertEqual(final.value, b"v2")

    def test_absent_guard(self) -> None:
        self.s.put("fresh", b"new", absent=True).wait()
        self.assertEqual(self.s.get("fresh").value, b"new")

    def test_conflicting_cas_is_refused_or_dropped(self) -> None:
        self.c.wait_settled(self.s.put("race", b"original").wait())
        rec = self.s.get("race")
        self.c.wait_settled(self.s.put("race", b"winner", expect=rec).wait())
        result = self.s.put("race", b"loser", expect=rec).wait()
        self.assertNotIsInstance(result, Settled)
        self.assertEqual(self.s.get("race").value, b"winner")

    def test_multi_step_transaction(self) -> None:
        self.c.wait_settled(self.s.put("a", b"1").wait())
        self.c.wait_settled(self.s.put("b", b"2").wait())
        rec_a = self.s.get("a")
        rec_b = self.s.get("b")
        self.assertFalse(rec_a.absent, "a absent after Settled")
        self.assertFalse(rec_b.absent, "b absent after Settled")
        tx = self.s.begin()
        tx.put("a", b"10", expect=rec_a)
        tx.put("b", b"20", expect=rec_b)
        self.c.wait_settled(tx.submit().wait())
        self.assertEqual(self.s.get("a").value, b"10")
        self.assertEqual(self.s.get("b").value, b"20")


class TestSessionViaLightClient(unittest.TestCase):

    def setUp(self) -> None:
        self.c = Cluster(nodes=3, mgmt=1, ro=0, rw=1)
        self.lc = self.c.rw_clients[0]
        self.lc.bootstrap(now_ms())
        self.c.wait(lambda _: self.lc.bootstrapped())

    def tearDown(self) -> None:
        self.c.close()

    def test_put_and_get(self) -> None:
        s = self.lc.session()
        self.c.wait_settled(s.put("hello", b"world").wait())
        rec = s.get("hello")
        self.assertFalse(rec.absent)
        self.assertEqual(rec.value, b"world")

    def test_value_is_encrypted(self) -> None:
        s = self.lc.session()
        s.put("secret", b"plaintext").wait()
        rec = s.get("secret")
        self.assertNotEqual(rec.raw, b"plaintext")
        self.assertEqual(rec.value, b"plaintext")

    def test_guarded_put(self) -> None:
        s = self.lc.session()
        s.put("k", b"v1").wait()
        rec = s.get("k")
        self.c.wait_settled(s.put("k", b"v2", expect=rec).wait())
        self.assertEqual(s.get("k").value, b"v2")


if __name__ == "__main__":
    unittest.main()
