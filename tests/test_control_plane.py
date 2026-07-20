# M5 — control plane. Capability authorization (DESIGN §15): control-op authz
# validates the CAPABILITY a delegate holds, not root identity (upgrades NOTES
# item 9's M1 root-only shortcut). Revocation is fold-positional.

import unittest

from dudefs import artifacts as A
from dudefs import crypto as C
from dudefs import fold
from dudefs.handlers import control as ctl
from tests._builders import World

CP = ctl.checkpoint_body({}, b"", b"", 0)  # authz-only body; no cut placed


def _key(b):
    sk = bytes([b] * 32)
    return sk, C.SIGNER.public(sk)


def _ctl(sk, pub, seq, prev, hlc_ms, payload):
    return A.Op.build(
        author_sk=sk,
        author_pub=pub,
        cls_=A.OpClass.CONTROL,
        seq=seq,
        prev=prev,
        hlc=A.HLC(hlc_ms, 0),
        deps=[],
        authz=b"root",
        keyepoch=0,
        payload=payload,
    )


class TestCapabilityAuthz(unittest.TestCase):
    def setUp(self):
        self.w = World(seed=1, n_clients=0)  # just the manager root
        self.msk, self.mpub = self.w.mgr_sk, self.w.mgr_pub

    def _fold(self, ops):
        return fold.fold(ops, self.w.keyring, self.w.genesis)

    def test_delegate_cap_gates_the_control_kind(self):
        dsk, dpub = _key(50)  # compact delegate
        csk, cpub = _key(51)  # plain client (write only)
        cert_d = _ctl(
            self.msk,
            self.mpub,
            0,
            A.GENESIS_PREV,
            1,
            ctl.cert_issue_body(dpub, [ctl.Cap.COMPACT], 0),
        )
        cert_c = _ctl(
            self.msk, self.mpub, 1, cert_d.op_hash, 2, ctl.cert_issue_body(cpub, [ctl.Cap.WRITE], 0)
        )
        cp_delegate = _ctl(dsk, dpub, 0, A.GENESIS_PREV, 100, CP)  # has compact -> ok
        cp_client = _ctl(csk, cpub, 0, A.GENESIS_PREV, 101, CP)  # write only -> not ok
        r = self._fold([cert_d, cert_c, cp_delegate, cp_client])
        self.assertEqual(r.verdicts[cp_delegate.op_hash], fold.Verdict.CONTROL)
        self.assertEqual(r.verdicts[cp_client.op_hash], fold.Verdict.INVALID)

    def test_root_authors_any_kind_without_a_cert(self):
        roster = _ctl(
            self.msk, self.mpub, 0, A.GENESIS_PREV, 1, ctl.roster_body(0, [self.mpub], {})
        )
        r = self._fold([roster])
        self.assertEqual(r.verdicts[roster.op_hash], fold.Verdict.CONTROL)

    def test_wrong_cap_is_rejected(self):
        # a manage-roster delegate cannot mint a checkpoint (that needs compact)
        dsk, dpub = _key(52)
        cert = _ctl(
            self.msk,
            self.mpub,
            0,
            A.GENESIS_PREV,
            1,
            ctl.cert_issue_body(dpub, [ctl.Cap.MANAGE_ROSTER], 0),
        )
        cp = _ctl(dsk, dpub, 0, A.GENESIS_PREV, 100, CP)
        r = self._fold([cert, cp])
        self.assertEqual(r.verdicts[cp.op_hash], fold.Verdict.INVALID)

    def test_revocation_is_fold_positional(self):
        dsk, dpub = _key(50)
        cert = _ctl(
            self.msk,
            self.mpub,
            0,
            A.GENESIS_PREV,
            1,
            ctl.cert_issue_body(dpub, [ctl.Cap.COMPACT], 0),
        )
        revoke = _ctl(self.msk, self.mpub, 1, cert.op_hash, 100, ctl.cert_revoke_body(dpub))
        cp_before = _ctl(dsk, dpub, 0, A.GENESIS_PREV, 50, CP)  # before the revoke in fold order
        cp_after = _ctl(dsk, dpub, 1, cp_before.op_hash, 150, CP)  # after -> invalid
        r = self._fold([cert, revoke, cp_before, cp_after])
        self.assertEqual(r.verdicts[cp_before.op_hash], fold.Verdict.CONTROL)
        self.assertEqual(r.verdicts[cp_after.op_hash], fold.Verdict.INVALID)


if __name__ == "__main__":
    unittest.main()
