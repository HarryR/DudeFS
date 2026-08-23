from __future__ import annotations

import unittest

from dude.core import crypto
from dude.session import Settled
from dude.store import ops
from dude.store.management import (
    P_COMPACT,
    Cert,
    MgmtReader,
    MgmtWriter,
    Role,
)
from dude.tests.cluster import Cluster


class TestCompactTransaction(unittest.TestCase):

    def setUp(self) -> None:
        self.c = Cluster(nodes=3, mgmt=1)
        self.s = self.c.replicas[0].session()

    def tearDown(self) -> None:
        self.c.close()

    def _grant_compactor(self) -> crypto.Keypair:
        compactor_kp = crypto.Keypair.generate()
        anchor_node = self.c.boot_replica(self.c.anchor)
        self.c.wait_head(self.c.nodes[0].store.head(), nodes=[anchor_node])
        anchor_s = anchor_node.session()
        store = anchor_node.store
        w = MgmtWriter(store)
        grant_tx = w.authorise(
            compactor_kp.public,
            Role.COMPACTOR,
            stores=frozenset({ops.STORE_MANAGEMENT}),
            pop=compactor_kp.prove_possession(),
            cert=Cert.sign_grant(self.c.anchor, compactor_kp.public, Role.COMPACTOR),
        )
        result = anchor_s.submit(grant_tx).wait()
        if not isinstance(result, Settled):
            raise AssertionError(f"grant did not settle: {result!r}")  # noqa: TRY004
        self.c.wait_head(self.c.nodes[0].store.head())
        return compactor_kp

    def _compactor_session(self, compactor_kp: crypto.Keypair):
        rn = self.c.boot_replica(compactor_kp)
        self.c.wait_head(self.c.nodes[0].store.head(), nodes=[rn])
        return rn.session()

    def test_compactor_can_write_compact_key(self):
        compactor_kp = self._grant_compactor()
        cs = self._compactor_session(compactor_kp)
        result = cs.compact(self.c.nodes[0].store.head_block_num() or 0).wait()
        self.assertIsInstance(result, Settled)
        held = self.c.nodes[0].store.get(ops.STORE_MANAGEMENT, P_COMPACT)
        self.assertIsNotNone(held)

    def test_non_compactor_cannot_write_compact_key(self):
        rogue = crypto.Keypair.generate()
        rn = self.c.boot_replica(rogue)
        self.c.wait_head(self.c.nodes[0].store.head(), nodes=[rn])
        rs = rn.session()
        result = rs.compact(0).wait()
        self.assertNotIsInstance(result, Settled)

    def test_compactor_role_is_isolated(self):
        self.assertTrue(Role.COMPACTOR.isolated)
        self.assertFalse(Role.MANAGER.isolated)
        self.assertFalse(Role.CLIENT_RW.isolated)
        self.assertFalse(Role.CLIENT_RO.isolated)

    def test_compact_block_has_one_transaction(self):
        compactor_kp = self._grant_compactor()
        cs = self._compactor_session(compactor_kp)
        head_before = self.c.nodes[0].store.head_block_num() or 0
        result = cs.compact(head_before).wait()
        self.assertIsInstance(result, Settled)
        self.c.wait_head(self.c.nodes[0].store.head())
        store = self.c.nodes[0].store
        mgmt = MgmtReader(store)
        for n in range(head_before + 1, (store.head_block_num() or 0) + 1):
            bodies = store.bodies_of_block(n)
            for body in bodies:
                grant = mgmt.grant_of(body.author)
                if grant is not None and grant.role.isolated:
                    self.assertEqual(len(bodies), 1)
                    return
        self.fail("compact tx not found in any post-grant block")

    def test_monotonicity_guard(self):
        compactor_kp = self._grant_compactor()
        cs = self._compactor_session(compactor_kp)
        r1 = cs.compact(self.c.nodes[0].store.head_block_num() or 0).wait()
        self.assertIsInstance(r1, Settled)
        self.c.wait_block(4)
        r2 = cs.compact(self.c.nodes[0].store.head_block_num() or 0).wait()
        self.assertIsInstance(r2, Settled)


if __name__ == "__main__":
    unittest.main()
