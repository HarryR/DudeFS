# M2 — L2 ChainStore: contiguity, fork detection, idempotence, and durable
# monotone floor across process kill/reopen (IMPLEMENTATION.md M2).

import os
import unittest

from dudefs import artifacts as A
from dudefs.artifacts import HLC
from dudefs.store import AppendStatus, ChainStore
from tests._builders import World

SCRATCH = os.environ.get("DUDE_SCRATCH", "/tmp/claude-1000/dude_store_tests")


def _mk_ops(w, ci=0, n=3):
    """A contiguous blind-write chain for client ci."""
    return [w.blind(ci, [], [[A.Mutation.SET, f"k{i}".encode(), b"v"]]) for i in range(n)]


class TestContiguity(unittest.TestCase):
    def test_append_gap_and_order(self):
        w = World(seed=1, n_clients=1)
        s = ChainStore()
        ops = _mk_ops(w, 0, 3)
        self.assertEqual(s.append(ops[0]).status, AppendStatus.OK)
        self.assertEqual(s.append(ops[2]).status, AppendStatus.GAP)  # seq2 before seq1
        self.assertEqual(s.append(ops[1]).status, AppendStatus.OK)
        self.assertEqual(s.append(ops[2]).status, AppendStatus.OK)  # now contiguous
        self.assertEqual(s.append(ops[1]).status, AppendStatus.DUP)  # idempotent
        heads = s.heads()
        self.assertEqual(heads[w.clients[0].pub], (2, ops[2].op_hash))
        s.close()

    def test_fork_evidence(self):
        w = World(seed=2, n_clients=1)
        s = ChainStore()
        a = w.blind(0, [], [[A.Mutation.SET, b"k", b"1"]])  # client0 seq0
        # a second, different op at the SAME (author, seq0): reset chain head
        w.clients[0].seq = 0
        w.clients[0].prev = A.GENESIS_PREV
        b = w.blind(0, [], [[A.Mutation.SET, b"k", b"2"]])  # client0 seq0 again, different
        self.assertNotEqual(a.op_hash, b.op_hash)
        self.assertEqual(s.append(a).status, AppendStatus.OK)
        res = s.append(b)
        self.assertEqual(res.status, AppendStatus.FORK)
        assert res.evidence is not None  # FORK always carries evidence
        self.assertTrue(res.evidence.verify())  # portable equivocation proof
        self.assertEqual(len(s.evidence()), 1)
        s.close()


class TestFloorDurability(unittest.TestCase):
    def test_floor_survives_reopen(self):
        os.makedirs(SCRATCH, exist_ok=True)
        path = os.path.join(SCRATCH, "floor.db")
        if os.path.exists(path):
            os.remove(path)
        s = ChainStore(path)
        s._write_hw(HLC(5000, 3))
        s._write_attested(HLC(4000, 0))
        s.commit()
        s.close()
        # reopen == process restart: persisted floor/hw must survive (RESILIENCE §0)
        s2 = ChainStore(path)
        self.assertEqual(s2.get_hw(), HLC(5000, 3))
        self.assertEqual(s2.get_attested(), HLC(4000, 0))
        s2.close()
        os.remove(path)


class TestReceiptsQCs(unittest.TestCase):
    def test_put_get_roundtrip(self):
        from dudefs import crypto as C

        w = World(seed=3, n_clients=1)
        s = ChainStore()
        op = w.blind(0, [], [[A.Mutation.SET, b"k", b"v"]])
        s.append(op)
        nsk = bytes([5] * 32)
        npub = C.SIGNER.public(nsk)
        r = A.Receipt.issue(nsk, npub, op.op_hash, 0, A.BLIND)
        s.put_receipt(r)
        got = s.receipts_for(op.op_hash)
        self.assertEqual(len(got), 1)
        self.assertTrue(got[0].verify())
        s.close()


if __name__ == "__main__":
    unittest.main()
