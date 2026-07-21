# WP3 — the manager LIBRARY (dudefs/manager.py), tested directly (not via the CLI).
# The delicate, protocol-specific control-plane logic lives here and is exercised as
# a library so programmatic automation and the `dude` CLI share ONE tested
# implementation (Harry's rule: no CLI-only protocol logic). The recover interlock
# DECISION is a pure function, tested across its whole matrix.

import tempfile
import unittest

from dudefs import artifacts as A
from dudefs import crypto as C
from dudefs.artifacts import quorum_size
from dudefs.handlers import control as ctl
from dudefs.manager import (
    HLC,
    Manager,
    ManagerError,
    ManagerState,
    RecoverDecision,
    RecoverReport,
    recover_decision,
)

ZERO = HLC(0, 0)


def _report(n, reachable, salvage=ZERO):
    return RecoverReport(
        n=n,
        quorum=quorum_size(n),
        reachable=sorted(reachable),
        presumed_dead=[i for i in range(n) if i not in reachable],
        salvage=salvage,
    )


class TestRecoverDecisionPure(unittest.TestCase):
    # The load-bearing interlock as a pure function — the whole matrix, no sockets.
    def test_quorum_answering_always_refuses(self):
        # n=3, quorum=2: 2 or 3 answering -> REFUSE regardless of the ack flag
        for reachable in ([0, 1], [0, 1, 2]):
            for ack in (False, True):
                d = recover_decision(_report(3, reachable), ack)
                self.assertIs(d, RecoverDecision.REFUSE_QUORUM)

    def test_dead_quorum_needs_ack_then_proceeds(self):
        rep = _report(3, [0])  # only 1/3 answers -> below quorum, cluster is dead
        self.assertIs(recover_decision(rep, False), RecoverDecision.NEED_ACK)
        self.assertIs(recover_decision(rep, True), RecoverDecision.PROCEED)

    def test_none_answering_still_needs_ack(self):
        rep = _report(3, [])
        self.assertIs(recover_decision(rep, False), RecoverDecision.NEED_ACK)
        self.assertIs(recover_decision(rep, True), RecoverDecision.PROCEED)


class TestManagerOps(unittest.TestCase):
    def test_init_refuses_over_existing(self):
        with tempfile.TemporaryDirectory() as d:
            Manager.init(d)
            self.assertTrue(ManagerState.exists(d))
            with self.assertRaises(ManagerError):
                Manager.init(d)

    def test_cert_issue_authors_a_valid_write_cert(self):
        with tempfile.TemporaryDirectory() as d:
            m = Manager.init(d)
            sub = C.SIGNER.public(bytes([9] * 32))
            op = m.cert_issue("client", sub)
            body = ctl.decode(op)
            assert body is not None
            self.assertEqual(body[ctl.BK_KIND], ctl.ControlKind.CERT_ISSUE)
            self.assertEqual(body[b"subject"], sub)
            self.assertEqual(body[b"caps"], [ctl.Cap.WRITE])

    def test_revoke_stages_rotate_bumps_keyepoch_and_wraps_all_members(self):
        with tempfile.TemporaryDirectory() as d:
            m = Manager.init(d)
            sub = C.SIGNER.public(bytes([9] * 32))
            m.cert_issue("client", sub)
            self.assertEqual(m.state.keyepoch, 0)
            ops = m.cert_revoke(sub)  # rotate staged by default
            self.assertEqual(len(ops), 3)  # revoke + wrap-set + rotate
            self.assertEqual(m.state.keyepoch, 1)
            self.assertIn(1, m.state.masters)
            # the revoked subject is NOT wrapped into the new epoch; the roster is
            wrap_body = ctl.decode(ops[1])
            assert wrap_body is not None
            self.assertEqual(wrap_body[ctl.BK_KIND], ctl.ControlKind.WRAP_SET)
            self.assertIn(m.state.roster[0], wrap_body[b"wraps"])
            self.assertNotIn(sub, wrap_body[b"wraps"])  # revoked -> excluded

    def test_no_rotate_leaves_keyepoch(self):
        with tempfile.TemporaryDirectory() as d:
            m = Manager.init(d)
            sub = C.SIGNER.public(bytes([9] * 32))
            m.cert_issue("client", sub)
            ops = m.cert_revoke(sub, rotate=False)
            self.assertEqual(len(ops), 1)  # revoke only
            self.assertEqual(m.state.keyepoch, 0)

    def test_promote_refuses_even_roster(self):
        with tempfile.TemporaryDirectory() as d:
            m = Manager.init(d)  # roster = 1 (odd)
            npub = C.SIGNER.public(bytes([5] * 32))
            m.node_add(npub)
            with self.assertRaises(ManagerError):
                m.node_promote(npub)  # -> 2 voting = even
            self.assertEqual(len(m.state.roster), 1)  # unchanged

    def test_promote_requires_a_learner(self):
        with tempfile.TemporaryDirectory() as d:
            m = Manager.init(d)
            with self.assertRaises(ManagerError):
                m.node_promote(C.SIGNER.public(bytes([7] * 32)))  # never added

    def test_promote_to_odd_roster_authors_roster_op_and_bumps_epoch(self):
        # single-promote from an odd roster always hits an even intermediate (refused);
        # the success path needs an even STARTING roster (reached only via batch/replace,
        # out of WP3 scope). Simulate that pre-state directly to exercise the odd path.
        with tempfile.TemporaryDirectory() as d:
            m = Manager.init(d)  # roster = 1
            extra = C.SIGNER.public(bytes([6] * 32))
            m.state.roster.append(extra)  # roster now 2 (even) — a mid-replace state
            cand = C.SIGNER.public(bytes([5] * 32))
            m.node_add(cand)
            op = m.node_promote(cand)  # 2 -> 3 (odd) succeeds
            self.assertEqual(len(m.state.roster), 3)
            self.assertEqual(m.state.epoch, 1)
            body = ctl.decode(op)
            assert body is not None
            self.assertEqual(body[ctl.BK_KIND], ctl.ControlKind.ROSTER)

    def test_fence_authoring_produces_the_recovery_pair(self):
        with tempfile.TemporaryDirectory() as d:
            m = Manager.init(d)
            rep = _report(1, [], salvage=A.HLC(500, 0))  # nobody answers
            ckpt, rop = m.author_recovery_fence(rep)
            cbody = ctl.decode(ckpt)
            rbody = ctl.decode(rop)
            assert cbody is not None and rbody is not None
            self.assertEqual(cbody[ctl.BK_KIND], ctl.ControlKind.CHECKPOINT)
            self.assertEqual(cbody[b"horizon"], A.HLC(500, 0))  # salvage frontier = fiat horizon
            self.assertEqual(rbody[ctl.BK_KIND], ctl.ControlKind.ROSTER)
            self.assertEqual(rbody[b"recovery"], ckpt.op_hash)  # the pairing
            self.assertEqual(m.state.epoch, 1)

    def test_probe_roster_with_injected_prober(self):
        # probe I/O is injected -> the dwell/report logic is tested without sockets
        with tempfile.TemporaryDirectory() as d:
            m = Manager.init(d)  # roster = [node0], endpoint ""
            # a synthetic prober answers node0 with a floor — no sockets involved
            addr0 = m.state.node_addrs[m.state.roster[0].hex()]
            answers = {addr0: A.HLC(9, 0)}
            rep = m.probe_roster(lambda a: answers.get(a), dwell=0.0, sleep=lambda _s: None)
            self.assertEqual(rep.reachable, [0])
            self.assertEqual(rep.presumed_dead, [])
            self.assertEqual(rep.salvage, A.HLC(9, 0))

    def test_state_roundtrips_through_disk(self):
        with tempfile.TemporaryDirectory() as d:
            m = Manager.init(d)
            m.cert_issue("client", C.SIGNER.public(bytes([9] * 32)))
            reloaded = ManagerState.load(d)
            self.assertEqual(reloaded.manager_pub, m.state.manager_pub)
            self.assertEqual(reloaded.mseq, m.state.mseq)
            self.assertEqual(len(reloaded.certs), 1)


if __name__ == "__main__":
    unittest.main()
