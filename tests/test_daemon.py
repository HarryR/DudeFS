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
from dudefs.link import Link
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


class TestInprocCluster(unittest.TestCase):
    def test_real_gossip_converges_over_the_inproc_carrier(self):
        # WP-I: drive the REAL serve -> gossip_round -> apply_delta path of 3 daemons
        # wired together in ONE thread over the inproc carrier (no sockets, no threads,
        # deterministic). A submit to node 0 propagates to 1 and 2 through PRODUCTION
        # gossip — not the sim's direct store merge. This is the seam compaction
        # lifecycle tests move onto (adopt/gossip driven through the real daemon).
        w = World(seed=20, n_clients=1)
        roster = [C.SIGNER.public(bytes([200 + i] * 32)) for i in range(3)]
        daemons = [_daemon(w, i, roster) for i in range(3)]
        for i, d in enumerate(daemons):
            transports.inproc.register(roster[i].hex(), d.serve)
        for i, d in enumerate(daemons):
            d.peers = [
                Peer(roster[j], transports.Endpoint(transports.INPROC, roster[j].hex()))
                for j in range(3)
                if j != i
            ]
        try:
            op = w.blind(0, [], [[A.Mutation.SET, b"k", b"v"]])
            self.assertIsInstance(daemons[0].acc.on_submit(op, 100), A.Receipt)
            for _ in range(3):  # sweep to a fixpoint
                for d in daemons:
                    d.sync_once()
            for d in daemons[1:]:  # the other two acquired the op via real gossip
                with d.store.read_txn() as tx:
                    self.assertIsNotNone(tx.get_op(op.op_hash))
        finally:
            for i, d in enumerate(daemons):
                transports.inproc.unregister(roster[i].hex())
                d.close()


class TestDaemonGossip(unittest.TestCase):
    # Gossip end-to-end over real carriers is covered by TestDaemonPeerSockets (unix)
    # and TestMixedTransportCluster (unix↔http); gossip_round now dials via a Link.
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
            with a.store.write_txn() as tx:
                tx.append(x)
            with b.store.write_txn() as tx:
                tx.append(y)
            a.sync_once()  # A -> B over HTTP
            b.sync_once()  # B -> A over unix
            for d in (a, b):
                with d.store.read_txn() as tx:
                    self.assertIsNotNone(tx.get_op(x.op_hash))  # both hold the union
                    self.assertIsNotNone(tx.get_op(y.op_hash))
            a.close()
            b.close()
            time.sleep(0.05)


class TestSealedMode(unittest.TestCase):
    def _serve_sealed(self, d):
        with socket.socket() as probe:
            probe.bind(("127.0.0.1", 0))
            uri = f"http://127.0.0.1:{probe.getsockname()[1]}/dude"
        ready = threading.Event()
        threading.Thread(
            target=d.serve_forever,
            args=(uri, ready),
            kwargs={"scheme": transports.HTTP, "sealed": True},
            daemon=True,
        ).start()
        self.assertTrue(ready.wait(2))
        return uri

    def test_sealed_endpoint_round_trips_the_gated_wire(self):
        # a node on a SEALED http endpoint: the request is sign-then-sealed, the reply
        # sealed back to the ephemeral key — full L_msg + gate + dispatch, encrypted.
        w = World(seed=16, n_clients=1)
        d = _daemon(w, 0, [C.SIGNER.public(bytes([200] * 32))])
        uri = self._serve_sealed(d)
        op = creation_op(w, 0, b"v")
        assert op.slot_tag is not None
        link = Link(
            w.clients[0].sk,
            w.clients[0].pub,
            d.pub,
            transports.Endpoint(transports.HTTP, uri, sealed=True),
        )
        out = link.request(
            b"",
            wire.encode_request(N.AcceptReq(op.slot_tag, A.Ballot(1, b"x"), op)),
            epoch=0,
            ts=d._clock(),
        )
        self.assertIsInstance(out, lmsg.Reply)
        assert isinstance(out, lmsg.Reply)
        self.assertIsInstance(wire.decode_response(out.env.body), A.Receipt)  # sealed, end-to-end
        d.close()
        time.sleep(0.05)

    def test_plain_request_to_a_sealed_endpoint_is_silence(self):
        # §8: an endpoint expects ONE shape. A plain envelope can't be unsealed -> the
        # node reveals nothing (silence), and the plain caller reads NoReply.
        w = World(seed=17, n_clients=1)
        d = _daemon(w, 0, [C.SIGNER.public(bytes([200] * 32))])
        uri = self._serve_sealed(d)
        op = creation_op(w, 0, b"v")
        assert op.slot_tag is not None
        plain = Link(  # a PLAIN link to the sealed endpoint (mismatched profile)
            w.clients[0].sk, w.clients[0].pub, d.pub, transports.Endpoint(transports.HTTP, uri)
        )
        out = plain.request(
            b"",
            wire.encode_request(N.AcceptReq(op.slot_tag, A.Ballot(1, b"x"), op)),
            epoch=0,
            ts=d._clock(),
        )
        self.assertIsInstance(out, lmsg.NoReply)
        d.close()
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
            with a.store.write_txn() as tx:
                tx.append(x)
            with b.store.write_txn() as tx:
                tx.append(y)
            for d, path in ((a, pa), (b, pb)):
                ev = threading.Event()
                threading.Thread(target=d.serve_forever, args=(path, ev), daemon=True).start()
                self.assertTrue(ev.wait(2))
            a.sync_once()  # gossip against b's real socket
            b.sync_once()
            for d in (a, b):
                with d.store.read_txn() as tx:
                    self.assertIsNotNone(tx.get_op(x.op_hash))
                    self.assertIsNotNone(tx.get_op(y.op_hash))
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
            state_acc=cr.state_acc,
            dead=cr.dead,
            retained=committed,
            horizon=A.HLC(500, 0),
        )
        with d.store.write_txn() as tx:
            for o in [*below, ckpt]:  # the node holds the full history + the checkpoint op
                tx.append(o)
        # a quorum-committed checkpoint: a QC over its op_hash from the roster
        sks = [bytes([200 + i] * 32) for i in range(3)]
        recs = [
            A.Receipt.issue(sks[i], roster[i], ckpt.op_hash, 0, A.Ballot(1, b"c"), 1)
            for i in range(3)
        ]
        with d.store.write_txn() as tx:
            tx.put_qc(A.QC.assemble(recs, 3, {p: i for i, p in enumerate(roster)}))

        d.adopt_committed_checkpoints()
        with d.store.read_txn() as tx:
            self.assertEqual(tx.get_meta("checkpoint"), ckpt.op_hash)  # adopted
            self.assertEqual(tx.get_horizon(), A.HLC(500, 0))  # horizon advanced to F
            self.assertIsNone(tx.get_op(first.op_hash))  # dead GC'd

    def test_forged_qc_checkpoint_is_not_adopted(self):
        # WP-F(b) / finding #5: put_qc stores whatever gossips in, so adoption must
        # VERIFY the checkpoint QC, not just note its presence — else a forged QC drives
        # a GC on a lie. Same checkpoint, but its QC is signed by keys that are NOT the
        # roster: it must be refused (no adoption, no horizon advance, no GC).
        from dudefs import compactor, fold

        w = World(seed=8, n_clients=1)
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
        ckpt = w.checkpoint(
            cut=cut,
            state_acc=cr.state_acc,
            dead=cr.dead,
            retained=A.retained_commitment(cr.retained),
            horizon=A.HLC(500, 0),
        )
        with d.store.write_txn() as tx:
            for o in [*below, ckpt]:
                tx.append(o)
        # a FORGED QC: a full bitmap, but the signers are NOT the roster
        fake = [bytes([100 + i] * 32) for i in range(3)]
        fake_pubs = [C.SIGNER.public(s) for s in fake]
        recs = [
            A.Receipt.issue(fake[i], fake_pubs[i], ckpt.op_hash, 0, A.Ballot(1, b"c"), 1)
            for i in range(3)
        ]
        with d.store.write_txn() as tx:
            tx.put_qc(A.QC.assemble(recs, 3, {p: i for i, p in enumerate(fake_pubs)}))

        d.adopt_committed_checkpoints()
        with d.store.read_txn() as tx:
            self.assertIsNone(tx.get_meta("checkpoint"))  # NOT adopted
            self.assertEqual(tx.get_horizon(), A.HLC(0, 0))  # horizon not advanced
            self.assertIsNotNone(tx.get_op(first.op_hash))  # dead NOT GC'd
            self.assertIsNotNone(tx.get_op(winner.op_hash))  # winner retained

    def test_checkpoint_with_horizon_below_the_cut_is_not_adopted(self):
        # WP-D / finding #8: the horizon (= F) must COVER the cut. A checkpoint whose
        # horizon sits below an op it compacts (≤ cut) seals a not-yet-final region and
        # is refused — even with a valid QC + authorized minter. No cut-lag W: the
        # horizon is exactly F, and coverage is a structural (cleartext-hlc) check.
        from dudefs import compactor, fold

        w = World(seed=9, n_clients=1)
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
        # horizon ONE BELOW the highest compacted op -> does not cover the cut
        ckpt = w.checkpoint(
            cut=cut,
            state_acc=cr.state_acc,
            dead=cr.dead,
            retained=A.retained_commitment(cr.retained),
            horizon=A.HLC(winner.hlc.wall_ms - 1, 0),
        )
        with d.store.write_txn() as tx:
            for o in [*below, ckpt]:
                tx.append(o)
        sks = [bytes([200 + i] * 32) for i in range(3)]
        recs = [
            A.Receipt.issue(sks[i], roster[i], ckpt.op_hash, 0, A.Ballot(1, b"c"), 1)
            for i in range(3)
        ]
        with d.store.write_txn() as tx:
            tx.put_qc(A.QC.assemble(recs, 3, {p: i for i, p in enumerate(roster)}))

        d.adopt_committed_checkpoints()
        with d.store.read_txn() as tx:
            self.assertIsNone(tx.get_meta("checkpoint"))  # refused (horizon < cut)
            self.assertIsNotNone(tx.get_op(first.op_hash))  # dead NOT GC'd


class TestAdoptionValidityGate(unittest.TestCase):
    """WP-F(a) / #4: within the checkpoint chain, adoption refuses a NEXT-seq checkpoint that
    would REGRESS the cut or horizon — both are irreversible (destructive GC, monotone void-
    rule horizon), so a non-dominating link is impossible-by-definition. The sequence-slot
    (WP-F(c)) already forbids two checkpoints at the SAME seq; this dominance gate is the
    safety net against a chained link (seq+1) whose cut/horizon walks back — e.g. an adversary
    who won slot seq+1 with a regressing cut. Two INDEPENDENT keys (no supersession -> the
    first checkpoint GCs nothing), so the refused link's baseline still verifies and it is the
    DOMINANCE gate — not a missing-baseline defer — that refuses it."""

    def _setup(self, seed):
        from dudefs import fold
        from dudefs.store import covered

        w = World(seed=seed, n_clients=1)
        roster = [C.SIGNER.public(bytes([200 + i] * 32)) for i in range(3)]
        d = _daemon(w, 0, roster)
        full = list(w.control_ops)
        k1 = w.cas(
            0,
            b"k1",
            A.VERSION_ABSENT,
            0,
            [[A.Guard.ABSENT, b"k1"]],
            [[A.Mutation.SET, b"k1", b"a"]],
        )
        k2 = w.cas(
            0,
            b"k2",
            A.VERSION_ABSENT,
            0,
            [[A.Guard.ABSENT, b"k2"]],
            [[A.Mutation.SET, b"k2", b"b"]],
        )
        full += [k1, k2]
        mgr_head = (w._mseq - 1, w._mprev)  # manager frontier BEFORE any checkpoint op
        cut_big = {w.clients[0].pub: (1, k2.op_hash), w.mgr_pub: mgr_head}  # covers k1 + k2
        cut_small = {w.clients[0].pub: (0, k1.op_hash), w.mgr_pub: mgr_head}  # covers k1 only
        with d.store.write_txn() as tx:
            for o in full:
                tx.append(o)
        return w, d, roster, full, cut_big, cut_small, covered, fold

    def _present(self, d, w, roster, full, cut, horizon, covered, seq, slot_seq=None):
        """Author a committed checkpoint at `seq` and land it (op + verified QC) in d's store
        WITHOUT triggering adoption — the caller drives adopt_committed_checkpoints itself so
        it can control the ORDER seqs arrive in (sequential-catch-up tests)."""
        from dudefs import compactor

        below = [o for o in full if covered(o, cut)]
        cr = compactor.compact_genesis(below, w.keyring, w.genesis, cut)
        ckpt = w.checkpoint(
            cut=cut,
            state_acc=cr.state_acc,
            dead=cr.dead,
            retained=A.retained_commitment(cr.retained),
            horizon=horizon,
            seq=seq,
            slot_seq=slot_seq,
        )
        sks = [bytes([200 + i] * 32) for i in range(3)]
        recs = [
            A.Receipt.issue(sks[i], roster[i], ckpt.op_hash, 0, A.Ballot(1, b"c"), 1)
            for i in range(3)
        ]
        with d.store.write_txn() as tx:
            tx.append(ckpt)
            tx.put_qc(A.QC.assemble(recs, 3, {p: i for i, p in enumerate(roster)}))
        return ckpt

    def _adopt(self, d, w, roster, full, cut, horizon, covered, seq):
        ckpt = self._present(d, w, roster, full, cut, horizon, covered, seq)
        d.adopt_committed_checkpoints()
        return ckpt

    def test_regressing_cut_is_refused(self):
        w, d, roster, full, cut_big, cut_small, covered, _ = self._setup(50)
        try:
            big = self._adopt(d, w, roster, full, cut_big, A.HLC(500, 0), covered, seq=0)
            with d.store.read_txn() as tx:
                self.assertEqual(tx.get_meta("checkpoint"), big.op_hash)  # adopted
            # the NEXT link (seq 1) sits on the SMALLER cut (client seq 0 < 1) — it won its
            # slot but its cut regresses. Its baseline verifies (nothing GC'd), so only the
            # dominance gate can refuse it (not the sequence gate — seq 1 IS next).
            small = self._adopt(d, w, roster, full, cut_small, A.HLC(500, 0), covered, seq=1)
            with d.store.read_txn() as tx:
                self.assertEqual(tx.get_meta("checkpoint"), big.op_hash)  # STILL big
                self.assertEqual(dict(tx.cut()), cut_big)  # the cut did not regress
                self.assertNotEqual(dict(tx.cut()), cut_small)
                del small
        finally:
            d.close()

    def test_regressing_horizon_is_refused(self):
        w, d, roster, full, cut_big, _cut_small, covered, _ = self._setup(51)
        try:
            hi = self._adopt(d, w, roster, full, cut_big, A.HLC(1000, 0), covered, seq=0)
            with d.store.read_txn() as tx:
                self.assertEqual(tx.get_meta("checkpoint"), hi.op_hash)
                self.assertEqual(tx.get_horizon(), A.HLC(1000, 0))
            # the NEXT link (seq 1) at the SAME cut (so it dominates) but a LOWER horizon ->
            # refused: the void-rule horizon is monotone and must never walk back.
            self._adopt(d, w, roster, full, cut_big, A.HLC(500, 0), covered, seq=1)
            with d.store.read_txn() as tx:
                self.assertEqual(tx.get_meta("checkpoint"), hi.op_hash)  # unchanged
                self.assertEqual(tx.get_horizon(), A.HLC(1000, 0))  # horizon did not regress
        finally:
            d.close()

    def test_dominating_checkpoint_is_adopted(self):
        w, d, roster, full, cut_big, cut_small, covered, _ = self._setup(52)
        try:
            self._adopt(
                d, w, roster, full, cut_small, A.HLC(500, 0), covered, seq=0
            )  # adopt the small cut (seq 0)
            big = self._adopt(
                d, w, roster, full, cut_big, A.HLC(500, 0), covered, seq=1
            )  # seq 1 dominates -> adopt
            with d.store.read_txn() as tx:
                self.assertEqual(
                    tx.get_meta("checkpoint"), big.op_hash
                )  # advanced to the bigger cut
                self.assertEqual(dict(tx.cut()), cut_big)
        finally:
            d.close()

    def test_bootstrap_adopts_a_seq_distant_checkpoint_directly(self):
        # WARM/COLD far-behind: a node that never adopted seqs 0..1 (GC'd while it was away)
        # adopts a seq-2 checkpoint DIRECTLY because it holds the full retained baseline. This
        # is the mode that unblocks onboarding once compaction GCs the intermediate links —
        # finding #10 stays covered: the jump only happens against a fully-verified baseline.
        w, d, roster, full, cut_big, _cs, covered, _ = self._setup(53)
        try:
            ck2 = self._present(d, w, roster, full, cut_big, A.HLC(500, 0), covered, seq=2)
            d.adopt_committed_checkpoints()
            with d.store.read_txn() as tx:
                self.assertEqual(tx.get_meta("checkpoint"), ck2.op_hash)  # jumped straight to 2
                self.assertEqual(dict(tx.cut()), cut_big)
        finally:
            d.close()

    def test_defers_a_checkpoint_whose_baseline_is_incomplete(self):
        # the jump is gated on holding the FULL retained set: drop one below-cut winner and the
        # per-author digest no longer matches, so adoption defers (never GCs against a baseline
        # it can't reconstruct) until a later gossip round refills it.
        w, d, roster, full, cut_big, _cs, covered, _ = self._setup(56)
        try:
            k2 = full[-1]  # the second client op — drop it so my baseline has a gap
            with d.store.write_txn() as tx:
                tx.gc_checkpoint([k2.op_hash])
            self._present(d, w, roster, full, cut_big, A.HLC(500, 0), covered, seq=0)
            d.adopt_committed_checkpoints()
            with d.store.read_txn() as tx:
                self.assertIsNone(tx.get_meta("checkpoint"))  # incomplete baseline -> defer
        finally:
            d.close()

    def test_seq_slot_binding_is_enforced(self):
        # a checkpoint that CLAIMS seq 0 but was committed on a DIFFERENT slot (slot_seq=5) is
        # refused — the declared seq must bind the slot it actually won, else an adversary who
        # won some slot could relabel it to jump the chain. The correctly-bound seq 0 adopts.
        w, d, roster, full, _cut_big, cut_small, covered, _ = self._setup(54)
        try:
            self._present(d, w, roster, full, cut_small, A.HLC(500, 0), covered, seq=0, slot_seq=5)
            d.adopt_committed_checkpoints()
            with d.store.read_txn() as tx:
                self.assertIsNone(tx.get_meta("checkpoint"))  # seq/slot mismatch -> refused
            ck0 = self._present(d, w, roster, full, cut_small, A.HLC(500, 0), covered, seq=0)
            d.adopt_committed_checkpoints()
            with d.store.read_txn() as tx:
                self.assertEqual(tx.get_meta("checkpoint"), ck0.op_hash)  # bound seq 0 adopts
        finally:
            d.close()


class TestFreshBootstrap(unittest.TestCase):
    def test_fresh_member_bootstraps_the_sparse_baseline_over_gossip(self):
        # WP-E / Finding 1 (T-C): a node that adopted a checkpoint holds only the sparse
        # retained winners below the cut (their predecessors GC'd). A FRESH roster member
        # (disk-wiped) must re-acquire them over PRODUCTION gossip and re-adopt. The
        # contiguity gate blocked this — a winner whose predecessor is GC'd GAPs on
        # append, the bootstrap-vs-cut deadlock. The baseline now intakes contiguity-free
        # (it rides its own Delta field, put_op_raw). Reproduces Finding 1 (fails pre-fix).
        from dudefs import compactor, fold

        w = World(seed=22, n_clients=1)
        roster = [C.SIGNER.public(bytes([200 + i] * 32)) for i in range(3)]
        d = _daemon(w, 0, roster)  # node 0 — drive it into a compacted state
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
        ckpt = w.checkpoint(
            cut=cut,
            state_acc=cr.state_acc,
            dead=cr.dead,
            retained=A.retained_commitment(cr.retained),
            horizon=A.HLC(500, 0),
        )
        with d.store.write_txn() as tx:
            for o in [*below, ckpt]:
                tx.append(o)
        sks = [bytes([200 + i] * 32) for i in range(3)]
        recs = [
            A.Receipt.issue(sks[i], roster[i], ckpt.op_hash, 0, A.Ballot(1, b"c"), 1)
            for i in range(3)
        ]
        with d.store.write_txn() as tx:
            tx.put_qc(A.QC.assemble(recs, 3, {p: i for i, p in enumerate(roster)}))
        d.adopt_committed_checkpoints()
        with d.store.read_txn() as tx:
            self.assertEqual(tx.get_meta("checkpoint"), ckpt.op_hash)  # d compacted
            self.assertIsNone(tx.get_op(first.op_hash))  # d GC'd the dead predecessor
            self.assertIsNotNone(tx.get_op(winner.op_hash))  # d holds only the retained winner

        f = _daemon(w, 1, roster)  # a FRESH roster member (empty :memory: store)
        transports.inproc.register(roster[0].hex(), d.serve)
        transports.inproc.register(roster[1].hex(), f.serve)
        d.peers = [Peer(roster[1], transports.Endpoint(transports.INPROC, roster[1].hex()))]
        f.peers = [Peer(roster[0], transports.Endpoint(transports.INPROC, roster[0].hex()))]
        try:
            for _ in range(3):  # sweep: round 1 pulls the baseline + adopts
                f.sync_once()
            with f.store.read_txn() as tx:
                self.assertIsNotNone(tx.get_op(winner.op_hash))  # acquired the sparse baseline
                self.assertIsNotNone(tx.get_op(ckpt.op_hash))  # + the checkpoint op
                self.assertEqual(tx.get_meta("checkpoint"), ckpt.op_hash)  # and re-adopted it
                self.assertIsNone(tx.get_op(first.op_hash))  # never the GC'd dead op
        finally:
            transports.inproc.unregister(roster[0].hex())
            transports.inproc.unregister(roster[1].hex())
            d.close()
            f.close()


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
        with d.store.write_txn() as tx:
            tx.append(rckpt)
            tx.append(rop)
        self.assertEqual(d.acc.epoch, 0)
        d.observe_fences()
        self.assertEqual(d.acc.epoch, 1)  # the fence propagated -> parked


class TestDaemonEvidence(unittest.TestCase):
    def test_evidence_duty_cycle_mints_a_real_equivocators_double_vote(self):
        # PRODUCTION PATH (not a hand-planted receipt): the node IS an equivocator via
        # the acceptor_cls seam, so two accepts at one (tag, ballot) for different ops
        # flow the real on_accept -> put_receipt path and it SIGNS two conflicting
        # receipts; evidence_cycle then mints DOUBLE_VOTE from them. The whole
        # adversary-produces-then-detector-catches chain runs production code.
        from dudefs.sim.personas import EquivocatingAcceptor

        w = World(seed=5, n_clients=2)
        nsk = bytes([200] * 32)
        npub = C.SIGNER.public(nsk)
        d = NodeDaemon(
            nsk,
            npub,
            roster=[npub],
            manager_pub=w.mgr_pub,
            control_ops=w.control_ops,
            clock=lambda: 100,
            delta_ms=BIG,
            acceptor_cls=EquivocatingAcceptor,
        )
        a, b = creation_op(w, 0, b"A"), creation_op(w, 1, b"B")  # same slot, two ops
        assert a.slot_tag is not None and a.slot_tag == b.slot_tag
        ballot = A.Ballot(1, b"x")
        self.assertIsInstance(d.acc.on_accept(a.slot_tag, ballot, a, 100), A.Receipt)
        self.assertIsInstance(
            d.acc.on_accept(a.slot_tag, ballot, b, 100), A.Receipt
        )  # equivocates: re-signs the same ballot for a different op
        self.assertEqual(d.evidence_cycle(), 1)  # DOUBLE_VOTE minted from its own receipts
        self.assertGreaterEqual(d.status()["evidence"], 1)
        self.assertEqual(d.evidence_cycle(), 0)  # idempotent

    def test_evidence_duty_cycle_mints_a_real_floor_perjury(self):
        # PRODUCTION PATH: the node IS a floor-perjurer via acceptor_cls. It issues a
        # watermark attesting floor F (real issue_watermark), then receipts an op
        # BENEATH F through the real on_accept (its dropped past-gate lets it); the
        # watermark + that below-floor receipt are the FLOOR_PERJURY proof evidence_cycle
        # mints — the perjurer PRODUCES it on production code, not a hand-planted receipt.
        from dudefs.sim.personas import FloorPerjurer

        w = World(seed=1, n_clients=1)
        nsk = bytes([200] * 32)
        npub = C.SIGNER.public(nsk)
        d = NodeDaemon(
            nsk,
            npub,
            roster=[npub],
            manager_pub=w.mgr_pub,
            control_ops=w.control_ops,
            clock=lambda: 1000,
            delta_ms=10,  # small: floor = now - delta ~ 990 sits ABOVE the op's small hlc
            acceptor_cls=FloorPerjurer,
        )
        op = creation_op(w, 0, b"v")  # small hlc, beneath the sworn floor
        assert op.slot_tag is not None
        wm = d.acc.issue_watermark(1000)  # attests floor ~990
        self.assertGreater(wm.floor.wall_ms, op.hlc.wall_ms)  # op is beneath the floor
        rc = d.acc.on_accept(op.slot_tag, A.Ballot(1, b"x"), op, 1000)
        self.assertIsInstance(rc, A.Receipt)  # perjures: signs beneath its own sworn floor
        self.assertEqual(d.evidence_cycle(observed_watermarks=[wm]), 1)  # FLOOR_PERJURY minted
        self.assertGreaterEqual(d.status()["evidence"], 1)
        self.assertEqual(d.evidence_cycle(observed_watermarks=[wm]), 0)  # idempotent


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
            with acc.store.write_txn() as tx:
                tx.append(base)
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
            with nd.store.write_txn() as tx:
                tx.append(rc.op)
                tx.put_qc(rc.old_qc)  # old-roster half (epoch 0)
                tx.put_qc(rc.new_qc)  # new-roster half (epoch 1, possession-gated)
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
            with nd.store.write_txn() as tx:
                tx.append(contender)  # the contender sits FIRST in the store
                tx.append(rc.op)
                tx.put_qc(rc.old_qc)
                tx.put_qc(rc.new_qc)
            nd.observe_roster_activations()
            self.assertEqual(nd.acc.epoch, 1)  # certified op wins, not starved
            self.assertEqual(nd.roster, new)

    def test_will_not_activate_on_the_new_half_alone(self):
        with tempfile.TemporaryDirectory() as d:
            m = Manager.init(d)
            rc, old, old_sks, _new = self._joint_cert(m)
            nd = self._fresh_daemon(m, old, old_sks)
            with nd.store.write_txn() as tx:
                tx.append(rc.op)
                tx.put_qc(rc.new_qc)  # new half only -> not a joint cert
            nd.observe_roster_activations()
            self.assertEqual(nd.acc.epoch, 0)  # no activation
            self.assertEqual(nd.roster, old)

    def test_will_not_activate_on_the_old_half_alone(self):
        with tempfile.TemporaryDirectory() as d:
            m = Manager.init(d)
            rc, old, old_sks, _new = self._joint_cert(m)
            nd = self._fresh_daemon(m, old, old_sks)
            with nd.store.write_txn() as tx:
                tx.append(rc.op)
                tx.put_qc(rc.old_qc)  # old half only -> the new roster never ratified
            nd.observe_roster_activations()
            self.assertEqual(nd.acc.epoch, 0)  # no activation
            self.assertEqual(nd.roster, old)


class TestLearnerOnboarding(unittest.TestCase):
    """issue #2: the FULL node-addition flow with SYNCED ops on an inproc cluster. A
    STORE-certed learner is admitted by the peer gate, catches up read-only over real
    gossip, and only THEN — genuinely POSSESSING the sync frontier it earned by syncing,
    not one pre-arranged in its store — is promoted via the §13 joint certificate."""

    def test_learner_syncs_through_the_gate_then_is_promoted(self):
        with tempfile.TemporaryDirectory() as d:
            m = Manager.init(d)
            sks = [bytes([200 + i] * 32) for i in range(3)]
            pubs = [C.SIGNER.public(s) for s in sks]
            # founding node n0 (the on-chain founding roster is issue #2); seed it so every
            # manager refold falls back to n0 rather than init's auto-minted placeholder.
            m.state._set_meta(roster_seed=[pubs[0].hex()])
            m.state.roster = [pubs[0]]
            # the manager certs the two learners with SYNCED Cap.STORE ops (PoP-checked).
            certs = [m.cert_issue("node", pubs[i], C.prove_possession(sks[i])) for i in (1, 2)]

            w = World(seed=77, n_clients=1)
            base = w.blind(0, [], [[A.Mutation.SET, b"k", b"v"]])  # committed data, held by n0
            daemons = [
                NodeDaemon(
                    sks[i],
                    pubs[i],
                    roster=[pubs[0]],
                    manager_pub=m.state.manager_pub,
                    control_ops=certs,  # the synced STORE certs -> the gate admits the learners
                    clock=lambda: 100,
                    delta_ms=BIG,
                )
                for i in range(3)
            ]
            with daemons[0].store.write_txn() as tx:
                tx.append(base)  # only n0 holds the frontier; the learners start EMPTY
            for i, nd in enumerate(daemons):
                transports.inproc.register(pubs[i].hex(), nd.serve)
            for i, nd in enumerate(daemons):
                nd.peers = [
                    Peer(pubs[j], transports.Endpoint(transports.INPROC, pubs[j].hex()))
                    for j in range(3)
                    if j != i
                ]

            def rpc(pub, req):
                return dispatch(daemons[pubs.index(pub)].node, req)

            try:
                for i in (1, 2):  # precondition: a learner really is empty before it syncs
                    with daemons[i].store.read_txn() as tx:
                        self.assertIsNone(tx.get_op(base.op_hash))
                # 1) learners CATCH UP through the gate. Load-bearing: without Cap.STORE
                #    admission, n0 refuses their gossip and they stay empty (and step 2 fails).
                for _ in range(3):
                    for nd in daemons:
                        nd.sync_once()
                for i in (1, 2):
                    with daemons[i].store.read_txn() as tx:
                        self.assertIsNotNone(tx.get_op(base.op_hash), f"learner {i} synced")
                # 2) promote 1 -> 3 via the REAL joint cert; possession is now EARNED, not faked.
                change = m.change_roster(pubs, rpc)
                self.assertTrue(change.new_qc.verify(pubs))  # possession-gated on the synced nodes
                self.assertEqual(change.old_qc.config_epoch, 0)
                self.assertEqual(change.new_qc.config_epoch, 1)
                # 3) the nodes hold the roster op (via AcceptReq); feed the joint cert -> activate.
                for nd in daemons:
                    with nd.store.write_txn() as tx:
                        tx.put_qc(change.old_qc)
                        tx.put_qc(change.new_qc)
                    nd.observe_roster_activations()
                    self.assertEqual(nd.acc.epoch, 1)
                    self.assertEqual(nd.roster, pubs)
            finally:
                for i, nd in enumerate(daemons):
                    transports.inproc.unregister(pubs[i].hex())
                    nd.close()


if __name__ == "__main__":
    unittest.main()
