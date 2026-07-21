# M7 WP1 — the node daemon. Behaviors are pure methods over the store, so they run
# in-process (two daemons calling each other's `serve`) exactly like the sim; the
# socket shell is exercised by one real unix-socket smoke test.

import os
import socket
import tempfile
import threading
import time
import unittest

from dudefs import artifacts as A
from dudefs import crypto as C
from dudefs import node as N
from dudefs import wire
from dudefs.acceptor import Acceptor
from dudefs.daemon import NodeDaemon, _bytesource
from dudefs.manager import Manager
from dudefs.node import LocalNode, dispatch
from dudefs.store import ChainStore
from tests._builders import World
from tests._cluster import creation_op

BIG = 1_000_000


def _daemon(w, i, roster):
    sk = bytes([200 + i] * 32)
    return NodeDaemon(
        sk,
        C.SIGNER.public(sk),
        roster=roster,
        manager_pub=w.mgr_pub,
        clock=lambda: 100,
        delta_ms=BIG,
    )


def _rpc(peer):
    """In-process peer transport: unframe the request, serve it, return UNFRAMED."""

    def rpc(framed):
        payload = wire.read_frame(_bytesource(framed))
        assert payload is not None
        return peer.serve(payload)

    return rpc


class TestDaemonGossip(unittest.TestCase):
    def test_two_daemons_converge_via_anti_entropy(self):
        w = World(seed=1, n_clients=2)
        roster = [C.SIGNER.public(bytes([200 + i] * 32)) for i in range(2)]
        a, b = _daemon(w, 0, roster), _daemon(w, 1, roster)
        x = w.blind(0, [], [[A.Mutation.SET, b"x", b"1"]])
        y = w.blind(1, [], [[A.Mutation.SET, b"y", b"1"]])
        a.store.append(x)
        b.store.append(y)
        # one round each direction -> both hold the union (gossip fixpoint)
        a.gossip_round(_rpc(b))
        b.gossip_round(_rpc(a))
        for d in (a, b):
            self.assertIsNotNone(d.store.get_op(x.op_hash))
            self.assertIsNotNone(d.store.get_op(y.op_hash))

    def test_serve_dispatches_node_verbs(self):
        w = World(seed=2, n_clients=1)
        roster = [C.SIGNER.public(bytes([200] * 32))]
        d = _daemon(w, 0, roster)
        op = creation_op(w, 0, b"v")
        assert op.slot_tag is not None
        req = wire.encode_request(N.AcceptReq(op.slot_tag, A.Ballot(1, b"x"), op))
        resp = wire.decode_response(d.serve(req))
        self.assertIsInstance(resp, A.Receipt)


class TestDaemonPeerSockets(unittest.TestCase):
    def test_sync_once_converges_over_real_sockets(self):
        w = World(seed=7, n_clients=2)
        roster = [C.SIGNER.public(bytes([200 + i] * 32)) for i in range(2)]
        with tempfile.TemporaryDirectory() as td:
            pa, pb = os.path.join(td, "a.sock"), os.path.join(td, "b.sock")
            a = _daemon(w, 0, roster)
            b = _daemon(w, 1, roster)
            a.peers = [pb]  # a pulls from b's socket
            b.peers = [pa]
            x = w.blind(0, [], [[A.Mutation.SET, b"x", b"1"]])
            y = w.blind(1, [], [[A.Mutation.SET, b"y", b"1"]])
            a.store.append(x)
            b.store.append(y)
            for d, path in ((a, pa), (b, pb)):
                ev = threading.Event()
                threading.Thread(target=d.serve_forever, args=(path, ev), daemon=True).start()
                self.assertTrue(ev.wait(2))
            a.sync_once()  # gossip against b's real socket
            b.sync_once()
            for d in (a, b):
                self.assertIsNotNone(d.store.get_op(x.op_hash))
                self.assertIsNotNone(d.store.get_op(y.op_hash))
            a.close()
            b.close()
            time.sleep(0.05)


class TestDaemonAdoption(unittest.TestCase):
    def test_adopts_committed_authorized_checkpoint(self):
        from dudefs import compactor, fold

        w = World(seed=3, n_clients=1)
        roster = [C.SIGNER.public(bytes([200 + i] * 32)) for i in range(3)]
        d = _daemon(w, 0, roster)
        below = list(w.control_ops)
        first = w.cas(
            0, b"k", A.VERSION_ABSENT, 0, [[A.Guard.ABSENT, b"k"]], [[A.Mutation.SET, b"k", b"v1"]]
        )
        below.append(first)
        v, at = fold.fold(below, w.keyring, w.genesis).lineage(b"k")
        winner = w.cas(
            0, b"k", v, at, [[A.Guard.VERSION_EQ, b"k", v]], [[A.Mutation.SET, b"k", b"v2"]]
        )
        below.append(winner)
        cut = {c.pub: (c.seq - 1, c.prev) for c in w.clients if c.seq > 0}
        cut[w.mgr_pub] = (w._mseq - 1, w._mprev)
        cr = compactor.compact_genesis(below, w.keyring, w.genesis, cut)
        committed = A.retained_commitment(cr.retained)
        ckpt = w.checkpoint(
            cut=cut,
            state_root=cr.state_root,
            dead=cr.dead,
            retained=committed,
            horizon=A.HLC(500, 0),
        )
        for o in [*below, ckpt]:  # the node holds the full history + the checkpoint op
            d.store.append(o)
        # a quorum-committed checkpoint: a QC over its op_hash from the roster
        sks = [bytes([200 + i] * 32) for i in range(3)]
        recs = [
            A.Receipt.issue(sks[i], roster[i], ckpt.op_hash, 0, A.Ballot(1, b"c"), 1)
            for i in range(3)
        ]
        d.store.put_qc(A.QC.assemble(recs, 3, {p: i for i, p in enumerate(roster)}))

        d.adopt_committed_checkpoints()
        self.assertEqual(d.store.get_meta("checkpoint"), ckpt.op_hash)  # adopted
        self.assertEqual(d.acc.horizon, A.HLC(500, 0))  # horizon advanced to F
        self.assertIsNone(d.store.get_op(first.op_hash))  # dead GC'd
        self.assertIsNotNone(d.store.get_op(winner.op_hash))  # winner retained


class TestDaemonFence(unittest.TestCase):
    def test_observes_root_recovery_pair_and_activates(self):
        from dudefs.handlers import control as ctl

        w = World(seed=4, n_clients=0)
        roster = [C.SIGNER.public(bytes([200] * 32))]
        d = _daemon(w, 0, roster)
        rckpt = A.Op.build(
            author_sk=w.mgr_sk,
            author_pub=w.mgr_pub,
            cls_=A.OpClass.CONTROL,
            seq=0,
            prev=A.GENESIS_PREV,
            hlc=A.HLC(500, 0),
            deps=[],
            authz=b"root",
            keyepoch=0,
            payload=ctl.checkpoint_body({}, b"r", [], {}, b"", 0, A.HLC(0, 0)),
        )
        rop = A.Op.build(
            author_sk=w.mgr_sk,
            author_pub=w.mgr_pub,
            cls_=A.OpClass.CONTROL,
            seq=1,
            prev=rckpt.op_hash,
            hlc=A.HLC(501, 0),
            deps=[],
            authz=b"root",
            keyepoch=0,
            payload=ctl.roster_body(0, roster, {}, recovery=rckpt.op_hash),
        )
        d.store.append(rckpt)
        d.store.append(rop)
        self.assertEqual(d.acc.epoch, 0)
        d.observe_fences()
        self.assertEqual(d.acc.epoch, 1)  # the fence propagated -> parked


class TestDaemonEvidence(unittest.TestCase):
    def test_evidence_duty_cycle_mints_a_gossiped_in_double_vote(self):
        w = World(seed=5, n_clients=2)
        roster = [C.SIGNER.public(bytes([200] * 32))]
        d = _daemon(w, 0, roster)
        a, b = creation_op(w, 0, b"A"), creation_op(w, 1, b"B")  # same slot
        nsk = bytes([250] * 32)
        npub = C.SIGNER.public(nsk)
        ballot = A.Ballot(1, b"x")
        d.store.put_op_raw(a)
        d.store.put_op_raw(b)
        d.store.put_receipt(A.Receipt.issue(nsk, npub, a.op_hash, 0, ballot, 1))
        d.store.put_receipt(A.Receipt.issue(nsk, npub, b.op_hash, 0, ballot, 2))
        self.assertEqual(d.evidence_cycle(), 1)  # DOUBLE_VOTE minted
        self.assertGreaterEqual(d.status()["evidence"], 1)
        self.assertEqual(d.evidence_cycle(), 0)  # idempotent


class TestDaemonSocket(unittest.TestCase):
    def test_real_unix_socket_serves_a_verb(self):
        w = World(seed=6, n_clients=1)
        roster = [C.SIGNER.public(bytes([200] * 32))]
        d = _daemon(w, 0, roster)
        with tempfile.TemporaryDirectory() as td:
            path = os.path.join(td, "node.sock")
            ready = threading.Event()
            t = threading.Thread(target=d.serve_forever, args=(path, ready), daemon=True)
            t.start()
            self.assertTrue(ready.wait(2))
            op = creation_op(w, 0, b"v")
            assert op.slot_tag is not None
            cli = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
            cli.connect(path)
            cli.sendall(
                wire.frame(wire.encode_request(N.AcceptReq(op.slot_tag, A.Ballot(1, b"x"), op)))
            )
            reply = wire.read_frame(cli.recv)
            assert reply is not None
            resp = wire.decode_response(reply)
            self.assertIsInstance(resp, A.Receipt)
            cli.close()
            d.close()
            time.sleep(0.05)


class TestJointCertActivation(unittest.TestCase):
    """The findings 23/24 follow-up: a daemon adopts a roster change once it holds
    the JOINT CERTIFICATE (old-roster QC at e + new-roster QC at e+1), and refuses
    to activate on either half alone."""

    def _joint_cert(self, m):
        """Drive a real epoch-0 roster change on an in-process cluster; return
        (RosterChange, old_roster, new_roster). node2 -> a fresh (caught-up) node."""
        w = World(seed=7, n_clients=1)
        base = w.blind(0, [], [[A.Mutation.SET, b"k", b"v"]])  # the sync frontier
        old_sks = [bytes([200 + i] * 32) for i in range(3)]
        old = [C.SIGNER.public(s) for s in old_sks]
        m.state.roster = list(old)
        fresh_sk, fresh = bytes([210] * 32), C.SIGNER.public(bytes([210] * 32))
        new = [old[0], old[1], fresh]
        nodes = {}
        for pub, sk in zip([*old, fresh], [*old_sks, fresh_sk], strict=True):
            acc = Acceptor(sk, pub, ChainStore(), 0, BIG)
            acc.store.append(base)
            nodes[pub] = LocalNode(acc, lambda: 100)
        rc = m.change_roster(new, lambda pub, req: dispatch(nodes[pub], req))
        return rc, old, old_sks, new

    def _fresh_daemon(self, m, old, old_sks):
        return NodeDaemon(
            old_sks[0],
            old[0],
            roster=list(old),
            manager_pub=m.state.manager_pub,
            clock=lambda: 100,
            delta_ms=BIG,
        )

    def test_activates_on_the_full_joint_certificate(self):
        with tempfile.TemporaryDirectory() as d:
            m = Manager.init(d)
            rc, old, old_sks, new = self._joint_cert(m)
            nd = self._fresh_daemon(m, old, old_sks)
            nd.store.append(rc.op)
            nd.store.put_qc(rc.old_qc)  # old-roster half (epoch 0)
            nd.store.put_qc(rc.new_qc)  # new-roster half (epoch 1, possession-gated)
            self.assertEqual(nd.acc.epoch, 0)
            nd.observe_roster_activations()
            self.assertEqual(nd.acc.epoch, 1)  # activated
            self.assertEqual(nd.roster, new)  # and adopted the new configuration
            self.assertEqual(nd.quorum, A.quorum_size(len(new)))
            nd.observe_roster_activations()  # monotone: a second pass is a no-op
            self.assertEqual(nd.acc.epoch, 1)

    def test_activation_survives_a_contended_roster_slot(self):
        # B4: a crash-retry re-authors the SAME roster slot, so the store can hold an
        # undecided contender (no QC) beside the joint-certified op. Activation must
        # pick the certified one, never let the contender starve it.
        from dudefs.handlers import control as ctl

        with tempfile.TemporaryDirectory() as d:
            m = Manager.init(d)
            rc, old, old_sks, new = self._joint_cert(m)
            other = C.SIGNER.public(bytes([211] * 32))
            contender = m.state.author_control(
                ctl.roster_body(0, [old[0], old[1], other], {}),
                slot_tag=A.roster_slot_tag(0),
            )
            nd = self._fresh_daemon(m, old, old_sks)
            nd.store.append(contender)  # the contender sits FIRST in the store
            nd.store.append(rc.op)
            nd.store.put_qc(rc.old_qc)
            nd.store.put_qc(rc.new_qc)
            nd.observe_roster_activations()
            self.assertEqual(nd.acc.epoch, 1)  # certified op wins, not starved
            self.assertEqual(nd.roster, new)

    def test_will_not_activate_on_the_new_half_alone(self):
        with tempfile.TemporaryDirectory() as d:
            m = Manager.init(d)
            rc, old, old_sks, _new = self._joint_cert(m)
            nd = self._fresh_daemon(m, old, old_sks)
            nd.store.append(rc.op)
            nd.store.put_qc(rc.new_qc)  # new half only -> not a joint cert
            nd.observe_roster_activations()
            self.assertEqual(nd.acc.epoch, 0)  # no activation
            self.assertEqual(nd.roster, old)

    def test_will_not_activate_on_the_old_half_alone(self):
        with tempfile.TemporaryDirectory() as d:
            m = Manager.init(d)
            rc, old, old_sks, _new = self._joint_cert(m)
            nd = self._fresh_daemon(m, old, old_sks)
            nd.store.append(rc.op)
            nd.store.put_qc(rc.old_qc)  # old half only -> the new roster never ratified
            nd.observe_roster_activations()
            self.assertEqual(nd.acc.epoch, 0)  # no activation
            self.assertEqual(nd.roster, old)


if __name__ == "__main__":
    unittest.main()
