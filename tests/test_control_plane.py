# M5 — control plane. Capability authorization (DESIGN §15): control-op authz
# validates the CAPABILITY a delegate holds, not root identity (upgrades NOTES
# item 9's M1 root-only shortcut). Revocation is fold-positional.

import os
import tempfile
import unittest

from dudefs import artifacts as A
from dudefs import crypto as C
from dudefs import fold, gossip, transports
from dudefs.acceptor import Acceptor, Rejected, RejectReason
from dudefs.handlers import control as ctl
from dudefs.store import ChainStore
from tests._builders import World

CP = ctl.checkpoint_body({}, b"", [], {}, b"", 0, A.HLC(0, 0))  # authz-only; no cut placed
NOW = 100
BIG_DELTA = 1_000_000  # skew never bites in these unit tests


def _acc_cluster(n, epoch=0):
    nodes = []
    for i in range(n):
        sk = bytes([180 + i] * 32)
        nodes.append(Acceptor(sk, C.SIGNER.public(sk), ChainStore(), epoch, BIG_DELTA))
    return nodes, [nd.pub for nd in nodes]


def _roster_op(msk, mpub, new_roster, sync_frontier, epoch=0):
    """A roster op: a slotted CONTROL op on the public slot H('roster' ‖ epoch)."""
    return A.Op.build(
        author_sk=msk,
        author_pub=mpub,
        cls_=A.OpClass.CONTROL,
        seq=0,
        prev=A.GENESIS_PREV,
        hlc=A.HLC(NOW, 0),
        deps=[],
        authz=b"root",
        keyepoch=0,
        payload=ctl.roster_body(epoch, new_roster, sync_frontier),
        slot_tag=A.roster_slot_tag(epoch),
    )


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


class TestEpochBridge(unittest.TestCase):
    def test_B5_rereceipt_gives_a_fresh_epoch_qc(self):
        # An op accepted under epoch 0 is in-flight when the roster activates
        # epoch 1. RERECEIPT re-issues receipts under e+1 — the slot state is
        # untouched — so a client assembles a fresh single-epoch QC (DESIGN §13).
        nodes, roster = _acc_cluster(3)
        idx = {p: i for i, p in enumerate(roster)}
        w = World(seed=2, n_clients=1)
        op = w.cas(
            0, b"k", A.VERSION_ABSENT, 0, [[A.Guard.ABSENT, b"k"]], [[A.Mutation.SET, b"k", b"v"]]
        )
        assert op.slot_tag is not None
        tag, b = op.slot_tag, A.Ballot(1, b"x")
        for nd in nodes:
            self.assertIsInstance(nd.on_accept(tag, b, op, NOW), A.Receipt)
        qc0 = A.QC.assemble([nd.store.receipts_for(op.op_hash)[0] for nd in nodes], 3, idx)
        self.assertEqual(qc0.config_epoch, 0)
        self.assertTrue(qc0.verify(roster))

        for nd in nodes:  # the joint certificate activates epoch 1 everywhere
            nd.activate_epoch(1)
        rr = [nd.on_rereceipt(tag) for nd in nodes]
        self.assertTrue(all(isinstance(r, A.Receipt) and r.config_epoch == 1 for r in rr))
        qc1 = A.QC.assemble([r for r in rr if r is not None], 3, idx)
        self.assertEqual(qc1.config_epoch, 1)
        self.assertTrue(qc1.verify(roster))  # fresh single-epoch QC under e+1
        for nd in nodes:  # slot state carried across the epoch untouched
            self.assertEqual(nd.store.get_slot(tag).accepted_op, op.op_hash)


class TestRecoveryFence(unittest.TestCase):
    """WP1.7 / NOTES 36a: activation-is-the-park. A ROOT-signed pair (a recovery
    checkpoint + a ROSTER op naming it via `recovery`) substitutes for the joint
    certificate to activate the new epoch — a restatement of activate_epoch, not
    new machinery. Fiat is root-only; the park is emergent (receipts stamp e+1)."""

    def setUp(self):
        self.w = World(seed=1, n_clients=1)
        self.msk, self.mpub = self.w.mgr_sk, self.w.mgr_pub

    def _fold(self, ops):
        return fold.fold(ops, self.w.keyring, self.w.genesis)

    def _pair(self, roster, from_epoch=0):
        """A root-signed recovery pair: (recovery checkpoint, roster naming it)."""
        rckpt = _ctl(
            self.msk,
            self.mpub,
            5,
            A.GENESIS_PREV,
            200,
            ctl.checkpoint_body({}, b"root", [], {}, b"", 0, A.HLC(0, 0)),
        )
        rop = _ctl(
            self.msk,
            self.mpub,
            6,
            rckpt.op_hash,
            201,
            ctl.roster_body(from_epoch, roster, {}, recovery=rckpt.op_hash),
        )
        return rckpt, rop

    def test_a_valid_root_pair_activates_without_joint_qc_and_parks(self):
        nodes, _r = _acc_cluster(3)
        rckpt, rop = self._pair([n.pub for n in nodes])
        n = nodes[0]
        self.assertEqual(n.epoch, 0)
        self.assertTrue(n.on_recovery_fence(rop, rckpt, 1, rckpt.op_hash, self.mpub))
        self.assertEqual(n.epoch, 1)  # activated with NO joint certificate

        # the park is emergent: receipts now stamp e+1, old-epoch coordination dies
        op = self.w.cas(
            0, b"k", A.VERSION_ABSENT, 0, [[A.Guard.ABSENT, b"k"]], [[A.Mutation.SET, b"k", b"v"]]
        )
        assert op.slot_tag is not None
        r = n.on_accept(op.slot_tag, A.Ballot(1, b"x"), op, NOW)
        assert isinstance(r, A.Receipt)
        self.assertEqual(r.config_epoch, 1)

    def test_b_delegate_recovery_roster_folds_invalid_and_no_fence(self):
        dsk, dpub = _key(60)
        cert = _ctl(
            self.msk,
            self.mpub,
            0,
            A.GENESIS_PREV,
            1,
            ctl.cert_issue_body(dpub, [ctl.Cap.MANAGE_ROSTER], 0),
        )
        rckpt = _ctl(
            self.msk,
            self.mpub,
            1,
            cert.op_hash,
            2,
            ctl.checkpoint_body({}, b"", [], {}, b"", 0, A.HLC(0, 0)),
        )
        # a manage-roster delegate authors a recovery-marked roster -> root-only -> invalid
        rop = _ctl(
            dsk,
            dpub,
            0,
            A.GENESIS_PREV,
            3,
            ctl.roster_body(0, [dpub], {}, recovery=rckpt.op_hash),
        )
        r = self._fold([cert, rckpt, rop])
        self.assertEqual(r.verdicts[rop.op_hash], fold.Verdict.INVALID)

        # load-bearing: the SAME delegate's NON-recovery roster IS authorized —
        # it is the recovery marking, not the delegate, that forces root.
        rop_ok = _ctl(dsk, dpub, 0, A.GENESIS_PREV, 3, ctl.roster_body(0, [dpub], {}))
        r2 = self._fold([cert, rop_ok])
        self.assertEqual(r2.verdicts[rop_ok.op_hash], fold.Verdict.CONTROL)

        # the acceptor fence also refuses a non-root-signed pair
        n = _acc_cluster(1)[0][0]
        self.assertFalse(n.on_recovery_fence(rop, rckpt, 1, rckpt.op_hash, self.mpub))
        self.assertEqual(n.epoch, 0)

    def test_c_replayed_fence_is_a_monotone_noop(self):
        nodes, _r = _acc_cluster(1)
        n = nodes[0]
        rckpt, rop = self._pair([n.pub])
        self.assertTrue(n.on_recovery_fence(rop, rckpt, 1, rckpt.op_hash, self.mpub))
        self.assertEqual(n.epoch, 1)
        # replay the identical fence for the now-passed epoch -> valid but no-op
        self.assertTrue(n.on_recovery_fence(rop, rckpt, 1, rckpt.op_hash, self.mpub))
        self.assertEqual(n.epoch, 1)  # no double-advance
        # a stale fence while at a higher epoch never regresses
        n.activate_epoch(2)
        n.on_recovery_fence(rop, rckpt, 1, rckpt.op_hash, self.mpub)
        self.assertEqual(n.epoch, 2)

    def test_d_normal_roster_is_not_a_fence(self):
        # a normal roster (no `recovery`) is delegable -> it takes the joint-
        # certificate route, not fiat; and the fence refuses to fire without the
        # explicit checkpoint pairing.
        dsk, dpub = _key(62)
        cert = _ctl(
            self.msk,
            self.mpub,
            0,
            A.GENESIS_PREV,
            1,
            ctl.cert_issue_body(dpub, [ctl.Cap.MANAGE_ROSTER], 0),
        )
        rop_normal = _ctl(dsk, dpub, 0, A.GENESIS_PREV, 2, ctl.roster_body(0, [dpub], {}))
        r = self._fold([cert, rop_normal])
        self.assertEqual(r.verdicts[rop_normal.op_hash], fold.Verdict.CONTROL)  # normal path

        rckpt = _ctl(
            self.msk,
            self.mpub,
            1,
            cert.op_hash,
            3,
            ctl.checkpoint_body({}, b"", [], {}, b"", 0, A.HLC(0, 0)),
        )
        n = _acc_cluster(1)[0][0]
        # the fence requires the explicit pairing: a wrong recovery hash won't fire
        self.assertFalse(n.on_recovery_fence(rop_normal, rckpt, 1, b"\x00" * 32, self.mpub))
        self.assertEqual(n.epoch, 0)


class TestPossessionBarrier(unittest.TestCase):
    def test_new_roster_node_receipts_only_if_it_holds_the_frontier(self):
        nodes, _roster = _acc_cluster(3)
        w = World(seed=3, n_clients=1)
        base = w.blind(0, [], [[A.Mutation.SET, b"k", b"v"]])  # a committed op ≤ the frontier
        sf = {base.author: (0, base.op_hash)}
        nodes[0].store.append(base)  # node 0 is caught up; node 1 is not
        self.assertTrue(nodes[0].holds_frontier(sf))
        self.assertFalse(nodes[1].holds_frontier(sf))

        msk, mpub = _key(90)
        rop = _roster_op(msk, mpub, [n.pub for n in nodes], sf)
        tag, b = A.roster_slot_tag(0), A.Ballot(1, b"m")
        # node 0 possesses the data -> receipts under e+1 (possession proof)
        r0 = nodes[0].on_roster_accept(tag, b, rop, sf, 1, NOW)
        self.assertIsInstance(r0, A.Receipt)
        assert isinstance(r0, A.Receipt)
        self.assertEqual(r0.config_epoch, 1)
        # node 1 lacks it -> deferred (PULL to baseline, then retry), never a false ack
        self.assertIsInstance(nodes[1].on_roster_accept(tag, b, rop, sf, 1, NOW), Rejected)

    def test_learner_catches_up_via_gossip_then_passes_barrier(self):
        # Add is two-phase (DESIGN §13): a learner starts empty and FAILS the
        # possession barrier; it catches up via M4 gossip, then honestly passes —
        # which is what makes its eventual promotion a real durability proof.
        nodes, _roster = _acc_cluster(2)
        w = World(seed=6, n_clients=1)
        base = w.blind(0, [], [[A.Mutation.SET, b"k", b"v"]])
        sf = {base.author: (0, base.op_hash)}
        nodes[0].store.append(base)  # the incumbent holds the frontier
        self.assertFalse(nodes[1].holds_frontier(sf))  # fresh learner: empty
        gossip.merge(nodes[1].store, nodes[0].store)  # anti-entropy catch-up
        self.assertTrue(nodes[1].holds_frontier(sf))  # now honestly caught up


class TestRosterSlot(unittest.TestCase):
    def test_B4_at_most_one_activation_per_epoch(self):
        # two managers author competing roster ops for e=0 on the public slot; the
        # old roster's ordinary slot machinery decides at most one (single-decree).
        nodes, _roster = _acc_cluster(3)
        tag = A.roster_slot_tag(0)
        aSk, aPub = _key(70)
        bSk, bPub = _key(71)
        rosterA = _roster_op(aSk, aPub, [nodes[0].pub], {})  # A: shrink to {node0}
        rosterB = _roster_op(bSk, bPub, [nodes[1].pub], {})  # B: shrink to {node1}
        self.assertNotEqual(rosterA.op_hash, rosterB.op_hash)

        bal = A.Ballot(1, b"\x01")
        for nd in nodes[:2]:  # A accepted on a quorum {0,1}
            self.assertIsInstance(nd.on_accept(tag, bal, rosterA, NOW), A.Receipt)
        # B at the SAME (tag, ballot) on a node that accepted A -> equivocation guard
        conflict = nodes[0].on_accept(tag, bal, rosterB, NOW)
        self.assertIsInstance(conflict, Rejected)
        assert isinstance(conflict, Rejected)
        self.assertEqual(conflict.reason, RejectReason.EQUIVOCATION_GUARD)
        # recovery at a higher ballot MUST re-propose A — B can never activate out of e=0
        promises = [nd.on_prepare(tag, A.Ballot(2, b"r")) for nd in nodes[:2]]
        winner = max(
            (p.accepted_ballot, p.accepted_op_hash)
            for p in promises
            if isinstance(p, A.Promise) and p.accepted_op_hash is not None
        )
        self.assertEqual(winner[1], rosterA.op_hash)


class TestRosterActivation(unittest.TestCase):
    def test_1_to_3_joint_certificate(self):
        # A 1->3 roster change: the OLD roster {n0} decides the roster op on the
        # public slot (old QC under e=0); the NEW roster {n0,n1,n2} — each having
        # passed the possession barrier — receipts under e=1 (new QC). The joint
        # certificate is both QCs; nodes then activate epoch 1 (DESIGN §13, B4/B5).
        nodes, roster3 = _acc_cluster(3)  # n0 (incumbent) + n1,n2 (caught-up learners)
        w = World(seed=4, n_clients=1)
        base = w.blind(0, [], [[A.Mutation.SET, b"k", b"v"]])
        sf = {base.author: (0, base.op_hash)}
        for nd in nodes:  # every new-roster node is caught up to the sync frontier
            nd.store.append(base)

        msk, mpub = _key(90)
        rop = _roster_op(msk, mpub, roster3, sf)
        tag, bal = A.roster_slot_tag(0), A.Ballot(1, b"m")

        # old-roster QC (epoch 0): the old roster is just {n0}
        r_old = nodes[0].on_accept(tag, bal, rop, NOW)
        assert isinstance(r_old, A.Receipt)
        old_qc = A.QC.assemble([r_old], 1, {nodes[0].pub: 0})
        self.assertEqual(old_qc.config_epoch, 0)
        self.assertTrue(old_qc.verify([nodes[0].pub]))

        # new-roster QC (epoch 1): possession-gated receipts from {n0,n1,n2}
        new_idx = {p: i for i, p in enumerate(roster3)}
        new_receipts = []
        for nd in nodes:
            r = nd.on_roster_accept(tag, bal, rop, sf, 1, NOW)
            assert isinstance(r, A.Receipt)
            self.assertEqual(r.config_epoch, 1)
            new_receipts.append(r)
        new_qc = A.QC.assemble(new_receipts, 3, new_idx)
        self.assertEqual(new_qc.config_epoch, 1)
        self.assertTrue(new_qc.verify(roster3))

        # joint certificate complete -> everyone activates epoch 1
        for nd in nodes:
            nd.activate_epoch(1)
        self.assertTrue(all(nd.epoch == 1 for nd in nodes))


class TestWrapSet(unittest.TestCase):
    """A WRAP_SET distributes the group key K_epoch to each member via `sbx1`
    sealed boxes (DESIGN §3). Only the addressed member unwraps its own copy."""

    def test_sealed_wrap_set_roundtrips_per_member(self):
        sks = [bytes([50 + i] * 32) for i in range(3)]
        members = [C.SIGNER.public(s) for s in sks]
        k_epoch = bytes(range(32))
        body = ctl.decode(
            A.Op.build(
                author_sk=bytes([1] * 32),
                author_pub=C.SIGNER.public(bytes([1] * 32)),
                cls_=A.OpClass.CONTROL,
                seq=0,
                prev=A.GENESIS_PREV,
                hlc=A.HLC(NOW, 0),
                deps=[],
                authz=b"root",
                keyepoch=1,
                payload=ctl.sealed_wrap_set_body(1, k_epoch, members),
            )
        )
        assert isinstance(body, ctl.WrapSet)
        self.assertEqual(body.keyepoch, 1)
        # each member recovers K_epoch; a non-member gets nothing
        for sk in sks:
            self.assertEqual(ctl.unwrap_group_key(body, sk), k_epoch)
        outsider = bytes([200] * 32)
        self.assertIsNone(ctl.unwrap_group_key(body, outsider))

    def test_unwrap_then_derive_installs_the_working_keyring(self):
        # the finding-21 loop: ONE master is wrapped/unwrapped, then BOTH working
        # keys derive from it (data_key + slot_secret) — the client never receives
        # them over the wire, it derives them locally.
        sk = bytes([60] * 32)
        member = C.SIGNER.public(sk)
        k_epoch = bytes([0xC3] * 32)
        body = ctl.decode(
            A.Op.build(
                author_sk=bytes([1] * 32),
                author_pub=C.SIGNER.public(bytes([1] * 32)),
                cls_=A.OpClass.CONTROL,
                seq=0,
                prev=A.GENESIS_PREV,
                hlc=A.HLC(NOW, 0),
                deps=[],
                authz=b"root",
                keyepoch=2,
                payload=ctl.sealed_wrap_set_body(2, k_epoch, [member]),
            )
        )
        assert isinstance(body, ctl.WrapSet)
        recovered = ctl.unwrap_group_key(body, sk)
        assert recovered is not None
        self.assertEqual(recovered, k_epoch)
        ring = fold.keyring_from_masters({2: recovered})
        self.assertEqual(ring[2]["data_key"], C.derive_data_key(k_epoch))
        self.assertEqual(ring[2]["slot_secret"], C.derive_slot_secret(k_epoch))


class TestEndpointRecords(unittest.TestCase):
    """ENDPOINT records (PROTOCOL §7 / NOTES 58): root-signed node reachability,
    latest-wins per subject, empty-addrs = removal, root-only authoring."""

    ADDRS1 = [(b"https", b"https://a/dude", {b"lmsg": b"sealed"})]
    ADDRS2 = [(b"tor", b"http://x.onion/dude", {b"lmsg": b"plain"})]

    def test_folds_latest_wins_and_removal(self):
        w = World(seed=30, n_clients=0)
        node = C.SIGNER.public(bytes([70] * 32))
        e1 = w._mgr_op(ctl.endpoint_body(node, self.ADDRS1))
        e2 = w._mgr_op(ctl.endpoint_body(node, self.ADDRS2))  # supersedes e1
        res = fold.fold([*w.control_ops, e1, e2], w.keyring, w.genesis)
        # decoded to dial Endpoints; latest wins, and the L_msg profile survives
        self.assertEqual(
            res.control.endpoints[node], [transports.Endpoint(b"tor", "http://x.onion/dude", False)]
        )
        self.assertFalse(res.control.endpoints[node][0].sealed)  # plain profile survived

        e3 = w._mgr_op(ctl.endpoint_body(node, []))  # empty addrs = removal
        res2 = fold.fold([*w.control_ops, e1, e2, e3], w.keyring, w.genesis)
        self.assertNotIn(node, res2.control.endpoints)

    def test_endpoint_is_root_only(self):
        # a WRITE-cert delegate cannot author an ENDPOINT — it stays root-only, so
        # the record is not applied (the reducer's endpoint map is unchanged).
        w = World(seed=31, n_clients=1)
        delegate = w.clients[0]
        node = C.SIGNER.public(bytes([71] * 32))
        ep = _ctl(
            delegate.sk, delegate.pub, 0, A.GENESIS_PREV, 100, ctl.endpoint_body(node, self.ADDRS1)
        )
        res = fold.fold([*w.control_ops, ep], w.keyring, w.genesis)
        self.assertNotIn(node, res.control.endpoints)  # unauthorized -> ignored


class TestEpochPersistence(unittest.TestCase):
    """Finding 20 (finding 19's twin): the config epoch stamps every receipt/
    watermark, so it must survive crash-restart. Persisted in activate_epoch
    (single-writer) and restored on Acceptor init — a virgin store falls back to
    the constructor seed."""

    def _acc(self, store, config_epoch=0):
        sk = bytes([170] * 32)
        return Acceptor(sk, C.SIGNER.public(sk), store, config_epoch, BIG_DELTA)

    def test_epoch_survives_restart_and_stamps_fresh_watermark(self):
        with tempfile.TemporaryDirectory() as d:
            path = os.path.join(d, "store.db")
            s = ChainStore(path)
            acc = self._acc(s, config_epoch=0)
            acc.activate_epoch(1)
            self.assertEqual(acc.epoch, 1)
            self.assertEqual(s.get_epoch(), 1)  # persisted single-writer
            s.close()

            # reopen: the constructor seed (0) is IGNORED — persisted epoch 1 wins,
            # and a fresh watermark stamps e=1 (the receipt clients would reject at 0)
            s2 = ChainStore(path)
            acc2 = self._acc(s2, config_epoch=0)
            self.assertEqual(acc2.epoch, 1)
            wm = acc2.issue_watermark(NOW)
            self.assertEqual(wm.config_epoch, 1)
            s2.close()

    def test_virgin_store_uses_constructor_seed(self):
        with tempfile.TemporaryDirectory() as d:
            s = ChainStore(os.path.join(d, "store.db"))
            self.assertIsNone(s.get_epoch())  # nothing activated yet
            self.assertEqual(self._acc(s, config_epoch=2).epoch, 2)  # seed wins on virgin
            s.close()


if __name__ == "__main__":
    unittest.main()
