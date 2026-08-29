from __future__ import annotations

import unittest

from dude.core import crypto
from dude.store import ops
from dude.store.management import (
    P_COMPACT,
    Cert,
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
        self.c.wait_settled(
            anchor_node.session()
            .submit(
                anchor_node.store.mgmt_writer.authorise(
                    compactor_kp.public,
                    Role.COMPACTOR,
                    stores=frozenset({ops.STORE_MANAGEMENT}),
                    pop=compactor_kp.prove_possession(),
                    cert=Cert.sign_grant(
                        self.c.anchor,
                        compactor_kp.public,
                        Role.COMPACTOR,
                    ),
                )
            )
            .wait(),
        )
        return compactor_kp

    def _compactor_session(self, compactor_kp: crypto.Keypair):
        rn = self.c.boot_replica(compactor_kp)
        self.c.wait_head(self.c.nodes[0].store.head(), nodes=[rn])
        return rn.session(store_id=ops.STORE_MANAGEMENT)

    def test_compactor_can_write_compact_key(self):
        compactor_kp = self._grant_compactor()
        cs = self._compactor_session(compactor_kp)
        self.c.wait_settled(
            cs.submit(MgmtWriter(cs).compact(self.c.nodes[0].store.head_block_num() or 0)).wait()
        )
        held = self.c.nodes[0].store.get(ops.STORE_MANAGEMENT, P_COMPACT)
        self.assertIsNotNone(held)

    def test_compactor_role_is_isolated(self):
        self.assertTrue(Role.COMPACTOR.isolated)
        self.assertFalse(Role.MANAGER.isolated)
        self.assertFalse(Role.CLIENT_RW.isolated)
        self.assertFalse(Role.CLIENT_RO.isolated)

    def test_compact_block_has_one_transaction(self):
        compactor_kp = self._grant_compactor()
        cs = self._compactor_session(compactor_kp)
        head_before = self.c.nodes[0].store.head_block_num() or 0
        self.c.wait_settled(cs.submit(MgmtWriter(cs).compact(head_before)).wait())
        store = self.c.nodes[0].store
        mgmt = store.mgmt_reader
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
        self.c.wait_settled(
            cs.submit(MgmtWriter(cs).compact(self.c.nodes[0].store.head_block_num() or 0)).wait()
        )
        self.c.wait_settled(
            cs.submit(MgmtWriter(cs).compact(self.c.nodes[0].store.head_block_num() or 0)).wait()
        )


if __name__ == "__main__":
    unittest.main()
