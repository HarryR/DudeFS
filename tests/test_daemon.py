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
from dudefs import lmsg, transports, wire
from dudefs import node as N
from dudefs.acceptor import Acceptor
from dudefs.daemon import NodeDaemon, Peer
from dudefs.manager import Manager
from dudefs.node import LocalNode, dispatch
from dudefs.store import ChainStore
from tests._builders import World, call_node, enveloped, unix_peer
from tests._cluster import creation_op

BIG = 1_000_000


def _daemon(w, i, roster):
    sk = bytes([200 + i] * 32)
    return NodeDaemon(
        sk,
        C.SIGNER.public(sk),
        roster=roster,
        manager_pub=w.mgr_pub,
        control_ops=w.control_ops,  # certs the clients so the peer gate admits them
        clock=lambda: 100,
        delta_ms=BIG,
    )


def _rpc(peer):
    """In-process peer transport: a payload-level `dial` (no framing — that's the real
    carrier's job). Renders L_msg's silence (None) as this carrier's empty reply."""

    def dial(payload):
        reply = peer.serve(payload)
        return reply if reply is not None else b""

    return dial


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
        a.gossip_round(_rpc(b), b.pub)
        b.gossip_round(_rpc(a), a.pub)
        for d in (a, b):
            self.assertIsNotNone(d.store.get_op(x.op_hash))
            self.assertIsNotNone(d.store.get_op(y.op_hash))

    def test_serve_dispatches_node_verbs(self):
        w = World(seed=2, n_clients=1)
        roster = [C.SIGNER.public(bytes([200] * 32))]
        d = _daemon(w, 0, roster)
        op = creation_op(w, 0, b"v")
        assert op.slot_tag is not None
        resp = call_node(d, w.clients[0].sk, N.AcceptReq(op.slot_tag, A.Ballot(1, b"x"), op))
        self.assertIsInstance(resp, A.Receipt)


class TestPeerGate(unittest.TestCase):
    """The L_msg peer gate (PROTOCOL §7.5): its signed refusal says WHY — the specific
    door check the REQUESTER failed, distinct from the acceptor's op-author BAD_AUTHZ."""

    def test_non_member_requester_is_refused_with_not_a_member(self):
        from dudefs.acceptor import Rejected, RejectReason

        w = World(seed=8, n_clients=1)
        roster = [C.SIGNER.public(bytes([200] * 32))]
        d = _daemon(w, 0, roster)
        stranger = bytes([222] * 32)  # neither a roster node, a certed client, nor root
        op = creation_op(w, 0, b"v")
        assert op.slot_tag is not None
        resp = call_node(d, stranger, N.AcceptReq(op.slot_tag, A.Ballot(1, b"x"), op))
        assert isinstance(resp, Rejected)
        self.assertIs(resp.reason, RejectReason.NOT_A_MEMBER)  # says WHY, not BAD_AUTHZ
        d.close()

    def test_stale_envelope_is_refused_with_stale_envelope(self):
        from dudefs.acceptor import Rejected, RejectReason

        w = World(seed=9, n_clients=1)
        roster = [C.SIGNER.public(bytes([200] * 32))]
        d = _daemon(w, 0, roster)  # clock = 100, delta = BIG
        op = creation_op(w, 0, b"v")
        assert op.slot_tag is not None
        # a member's request, but stamped far outside δ -> stale, not unauthorized
        resp = call_node(
            d, w.clients[0].sk, N.AcceptReq(op.slot_tag, A.Ballot(1, b"x"), op), ts=100 + BIG + 1
        )
        assert isinstance(resp, Rejected)
        self.assertIs(resp.reason, RejectReason.STALE_ENVELOPE)  # distinct why
        d.close()


class TestMixedTransportCluster(unittest.TestCase):
    def test_unix_and_http_nodes_gossip_across_carriers_and_converge(self):
        # node A serves over a unix socket, node B over HTTP; they gossip to each other
        # across DIFFERENT carriers and converge — the seam makes the mesh carrier-agnostic.
        w = World(seed=15, n_clients=2)
        roster = [C.SIGNER.public(bytes([200] * 32)), C.SIGNER.public(bytes([201] * 32))]
        a, b = _daemon(w, 0, roster), _daemon(w, 1, roster)
        with tempfile.TemporaryDirectory() as td:
            a_path = os.path.join(td, "a.sock")
            with socket.socket() as probe:
                probe.bind(("127.0.0.1", 0))
                b_uri = f"http://127.0.0.1:{probe.getsockname()[1]}/dude"
            ev_a, ev_b = threading.Event(), threading.Event()
            threading.Thread(target=a.serve_forever, args=(a_path, ev_a), daemon=True).start()
            threading.Thread(
                target=b.serve_forever,
                args=(b_uri, ev_b),
                kwargs={"scheme": transports.HTTP},
                daemon=True,
            ).start()
            self.assertTrue(ev_a.wait(2))
            self.assertTrue(ev_b.wait(2))
            # each peers the OTHER over its own carrier
            a.peers = [Peer(b.pub, transports.Endpoint(transports.HTTP, b_uri))]
            b.peers = [Peer(a.pub, transports.Endpoint(transports.UNIX, a_path))]
            x = w.blind(0, [], [[A.Mutation.SET, b"x", b"1"]])
            y = w.blind(1, [], [[A.Mutation.SET, b"y", b"1"]])
            a.store.append(x)
            b.store.append(y)
            a.sync_once()  # A -> B over HTTP
            b.sync_once()  # B -> A over unix
            for d in (a, b):
                self.assertIsNotNone(d.store.get_op(x.op_hash))  # both hold the union
                self.assertIsNotNone(d.store.get_op(y.op_hash))
            a.close()
            b.close()
            time.sleep(0.05)


class TestHttpCarrier(unittest.TestCase):
    def test_daemon_serves_the_same_gated_wire_over_http(self):
        # cross-transport: the SAME L_msg envelope + peer gate + dispatch, carried over
        # HTTP instead of a unix socket — the seam proves the wire is carrier-agnostic.
        w = World(seed=12, n_clients=1)
        roster = [C.SIGNER.public(bytes([200] * 32))]
        d = _daemon(w, 0, roster)  # clock=100, delta=BIG, clients certed
        with socket.socket() as probe:  # grab a free port, then serve HTTP on it
            probe.bind(("127.0.0.1", 0))
            uri = f"http://127.0.0.1:{probe.getsockname()[1]}/dude"
        ready = threading.Event()
        threading.Thread(
            target=d.serve_forever,
            args=(uri, ready),
            kwargs={"scheme": transports.HTTP},
            daemon=True,
        ).start()
        self.assertTrue(ready.wait(2))
        op = creation_op(w, 0, b"v")
        assert op.slot_tag is not None
        out = enveloped(
            w.clients[0].sk, d.pub, N.AcceptReq(op.slot_tag, A.Ballot(1, b"x"), op), ts=d._clock()
        )
        raw = transports.dial(transports.HTTP, uri, out)
        match lmsg.classify_reply(raw, expect_from=d.pub, expect_to=w.clients[0].pub):
            case lmsg.Reply(env):
                resp = wire.decode_response(env.body)
            case _:
                resp = None
        self.assertIsInstance(resp, A.Receipt)  # full stack over HTTP
        d.close()
        time.sleep(0.05)

    def test_http_carrier_silence_when_non_member(self):
        # a non-member over HTTP: the node Dropped it (silence) -> HTTP 404 -> b"" -> None
        w = World(seed=14, n_clients=1)
        roster = [C.SIGNER.public(bytes([200] * 32))]
        d = _daemon(w, 0, roster)
        with socket.socket() as probe:
            probe.bind(("127.0.0.1", 0))
            uri = f"http://127.0.0.1:{probe.getsockname()[1]}/dude"
        ready = threading.Event()
        threading.Thread(
            target=d.serve_forever,
            args=(uri, ready),
            kwargs={"scheme": transports.HTTP},
            daemon=True,
        ).start()
        self.assertTrue(ready.wait(2))
        # a stranger addressing us by pubkey -> Refused is SIGNED (says why); but a
        # reflection to a wrong `to` -> Dropped -> 404 -> b"". Use the wrong-to probe:
        stranger = bytes([222] * 32)
        op = creation_op(w, 0, b"v")
        assert op.slot_tag is not None
        wrong_to = enveloped(
            stranger,
            C.SIGNER.public(bytes([1] * 32)),
            N.AcceptReq(op.slot_tag, A.Ballot(1, b"x"), op),
            ts=d._clock(),
        )
        self.assertEqual(
            transports.dial(transports.HTTP, uri, wrong_to), b""
        )  # silence rendered as 404
        d.close()
        time.sleep(0.05)


class TestDaemonPeerSockets(unittest.TestCase):
    def test_sync_once_converges_over_real_sockets(self):
        w = World(seed=7, n_clients=2)
        roster = [C.SIGNER.public(bytes([200 + i] * 32)) for i in range(2)]
        with tempfile.TemporaryDirectory() as td:
            pa, pb = os.path.join(td, "a.sock"), os.path.join(td, "b.sock")
            a = _daemon(w, 0, roster)
            b = _daemon(w, 1, roster)
            a.peers = [unix_peer(b.pub, pb)]  # a pulls from b's socket
            b.peers = [unix_peer(a.pub, pa)]
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
            out = enveloped(
                w.clients[0].sk,
                d.pub,
                N.AcceptReq(op.slot_tag, A.Ballot(1, b"x"), op),
                ts=d._clock(),
            )
            cli.sendall(wire.frame(out))
            reply = wire.read_frame(cli.recv)
            assert reply is not None
            match lmsg.classify_reply(reply, expect_from=d.pub, expect_to=w.clients[0].pub):
                case lmsg.Reply(env):
                    resp = wire.decode_response(env.body)
                case _:
                    resp = None
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
