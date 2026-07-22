# WP2 — the client daemon + JSON-RPC worker API (CLIENT.md). The daemon DRIVES a
# real 3-node cluster over unix sockets (no sim scheduler): it authors ops, pushes
# to a QC itself, pursues finality, and answers the honest ladder. One end-to-end
# JSON-RPC smoke test exercises the worker socket exactly as a worker would.

import json
import os
import socket
import tempfile
import threading
import time
import unittest

from dudefs import artifacts as A
from dudefs import compactor
from dudefs import crypto as C
from dudefs import fold as F
from dudefs.artifacts import VERSION_ABSENT
from dudefs.client import ClientDaemon, KeyEntry
from dudefs.daemon import NodeDaemon
from dudefs.handlers import control as ctl
from dudefs.workerapi import WorkerServer
from tests._builders import World, cut_of, now_ms, poll_until, unix_eps

DELTA = 150  # ms — small enough that finality sweeps ~DELTA after a write, big
# enough that same-machine client/node clock jitter never trips the skew gate.
MASTER = bytes(range(32))  # the epoch-0 group master (finding 21 derives from it)


class _Cluster:
    """N node daemons on real unix sockets + a client daemon driving them."""

    def __init__(self, tmp, w, n=3):
        self.tmp = tmp
        self.node_sks = [bytes([200 + i] * 32) for i in range(n)]
        self.roster = [C.SIGNER.public(sk) for sk in self.node_sks]
        self.paths = [os.path.join(tmp, f"node{i}.sock") for i in range(n)]
        self.nodes = []
        for i in range(n):
            d = NodeDaemon(
                self.node_sks[i],
                self.roster[i],
                roster=self.roster,
                manager_pub=w.mgr_pub,
                control_ops=w.control_ops,  # the node holds the authz view (request gate)
                clock=now_ms,
                delta_ms=DELTA,
            )
            ev = threading.Event()
            threading.Thread(target=d.serve_forever, args=(self.paths[i], ev), daemon=True).start()
            assert ev.wait(2)
            self.nodes.append(d)

    def client(self, w, ci=0):
        return ClientDaemon(
            w.clients[ci].sk,
            w.clients[ci].pub,
            roster=self.roster,
            roster_addrs=unix_eps(self.paths),
            manager_pub=w.mgr_pub,
            masters={0: MASTER},
            control_ops=w.control_ops,
            epoch=0,
        )

    def close(self):
        for d in self.nodes:
            d.close()
        time.sleep(0.05)


class TestClientLadder(unittest.TestCase):
    def test_txn_create_commits_applies_and_finalizes(self):
        w = World(seed=1, n_clients=1)
        with tempfile.TemporaryDirectory() as tmp:
            cl = _Cluster(tmp, w)
            c = cl.client(w)
            op = c.submit(
                (b"k", VERSION_ABSENT, 0),
                [[A.Guard.ABSENT, b"k"]],
                [[A.Mutation.SET, b"k", b"v1"]],
            )
            # in-flight -> committed (~2 RTT), provisional applied, then GET sees it
            self.assertTrue(poll_until(lambda: c.status(op).phase == "committed"))
            self.assertEqual(c.status(op).provisional, "applied")
            self.assertEqual(c.get(b"k")["value"], b"v1")
            # the daemon finishes the job: pursues §9 finality -> frozen verdict
            self.assertTrue(poll_until(lambda: c.status(op).final == "applied"))
            self.assertFalse(c.status(op).may_flip)
            self.assertEqual(c.get(b"k", level="final")["tier"], "final")
            c.close()
            cl.close()

    def test_cas_contention_yields_one_winner_one_lost(self):
        w = World(seed=2, n_clients=2)
        with tempfile.TemporaryDirectory() as tmp:
            cl = _Cluster(tmp, w)
            a, b = cl.client(w, 0), cl.client(w, 1)
            slot = (b"k", VERSION_ABSENT, 0)
            guard = [[A.Guard.ABSENT, b"k"]]
            oa = a.submit(slot, guard, [[A.Mutation.SET, b"k", b"A"]])
            ob = b.submit(slot, guard, [[A.Mutation.SET, b"k", b"B"]])
            # both resolve; exactly one is committed, the other is `lost` (definitive)
            self.assertTrue(poll_until(lambda: a.status(oa).phase in ("committed", "lost")))
            self.assertTrue(poll_until(lambda: b.status(ob).phase in ("committed", "lost")))
            phases = {a.status(oa).phase, b.status(ob).phase}
            self.assertEqual(phases, {"committed", "lost"})
            a.close()
            b.close()
            cl.close()

    def test_put_blind_write_commits(self):
        w = World(seed=3, n_clients=1)
        with tempfile.TemporaryDirectory() as tmp:
            cl = _Cluster(tmp, w)
            c = cl.client(w)
            op = c.submit(None, [], [[A.Mutation.SET, b"log/1", b"hello"]])  # slotless PUT
            self.assertTrue(poll_until(lambda: c.status(op).phase == "committed"))
            self.assertEqual(c.get(b"log/1")["value"], b"hello")
            c.close()
            cl.close()

    def test_list_and_inspect_recovery_view(self):
        w = World(seed=4, n_clients=1)
        with tempfile.TemporaryDirectory() as tmp:
            cl = _Cluster(tmp, w)
            c = cl.client(w)
            for key, val in ((b"q/items/1", b"a"), (b"q/items/2", b"b")):
                op = c.submit(
                    (key, VERSION_ABSENT, 0),
                    [[A.Guard.ABSENT, key]],
                    [[A.Mutation.SET, key, val]],
                )
                self.assertTrue(poll_until(lambda o=op: c.status(o).phase == "committed"))
            rows = c.list_keys(b"q/items/", delimiter=b"/")
            keys = {r.key for r in rows if isinstance(r, KeyEntry)}
            self.assertEqual(keys, {b"q/items/1", b"q/items/2"})
            insp = c.inspect(b"q/items/1")
            self.assertTrue(insp["provisional"]["present"])
            self.assertEqual(insp["provisional"]["value"], b"a")
            c.close()
            cl.close()


class TestReadSideSync(unittest.TestCase):
    def test_second_client_sees_first_clients_committed_write(self):
        # Finding 22: the daemon's fold ranges over ops it HOLDS, so without a
        # read-side quorum sync, client B cannot see client A's committed writes AT
        # ALL. This fails against pre-sync code; the §1.2 quorum read fixes it.
        w = World(seed=6, n_clients=2)
        with tempfile.TemporaryDirectory() as tmp:
            cl = _Cluster(tmp, w)
            a, b = cl.client(w, 0), cl.client(w, 1)
            op = a.submit(
                (b"shared/x", VERSION_ABSENT, 0),
                [[A.Guard.ABSENT, b"shared/x"]],
                [[A.Mutation.SET, b"shared/x", b"from-A"]],
            )
            self.assertTrue(poll_until(lambda: a.status(op).phase == "committed"))

            # B pulls the quorum read -> sees A's committed write at `local`
            self.assertTrue(
                poll_until(lambda: (b.sync(), b.get(b"shared/x").get("value"))[1] == b"from-A")
            )
            # and `level=final` auto-syncs to the quorum-attested FROZEN truth
            self.assertTrue(
                poll_until(
                    lambda: (
                        b.get(b"shared/x", level="final")["value"] == b"from-A"
                        and b.get(b"shared/x", level="final")["tier"] == "final"
                    )
                )
            )
            insp = b.inspect(b"shared/x")
            self.assertTrue(insp["provisional"]["present"])
            self.assertEqual(insp["provisional"]["value"], b"from-A")
            a.close()
            b.close()
            cl.close()


class TestCasUpdate(unittest.TestCase):
    def test_version_cas_update_and_stale_cas_loses(self):
        # the guarded-UPDATE path (VERSION_EQ), distinct from create contention: a
        # CAS from the current version wins; a second CAS from the now-stale version
        # contends the already-decided slot and is `lost` (can't update from stale).
        w = World(seed=8, n_clients=1)
        with tempfile.TemporaryDirectory() as tmp:
            cl = _Cluster(tmp, w)
            c = cl.client(w)
            create = c.submit(
                (b"k", VERSION_ABSENT, 0), [[A.Guard.ABSENT, b"k"]], [[A.Mutation.SET, b"k", b"v1"]]
            )
            self.assertTrue(poll_until(lambda: c.status(create).phase == "committed"))
            v1 = c.get(b"k")["version"]  # the created version (op_hash)

            upd = c.submit(
                (b"k", v1, 0), [[A.Guard.VERSION_EQ, b"k", v1]], [[A.Mutation.SET, b"k", b"v2"]]
            )
            self.assertTrue(poll_until(lambda: c.status(upd).phase == "committed"))
            self.assertEqual(c.get(b"k")["value"], b"v2")

            stale = c.submit(
                (b"k", v1, 0), [[A.Guard.VERSION_EQ, b"k", v1]], [[A.Mutation.SET, b"k", b"v3"]]
            )
            self.assertTrue(poll_until(lambda: c.status(stale).phase == "lost"))
            self.assertEqual(c.get(b"k")["value"], b"v2")  # unchanged
            c.close()
            cl.close()


class TestWorkerAPIProtocol(unittest.TestCase):
    """The JSON-RPC 2.0 wire edges — pure, no cluster needed (they resolve before or
    at the verb layer): parse errors, notifications, batches, param validation."""

    def _daemon(self):
        w = World(seed=9, n_clients=1)
        # roster present but endpoints unreachable — reads fold locally, no RPC needed
        return ClientDaemon(
            w.clients[0].sk,
            w.clients[0].pub,
            roster=[C.SIGNER.public(bytes([1] * 32))],
            roster_addrs=unix_eps(["/nonexistent.sock"]),
            manager_pub=w.mgr_pub,
            masters={0: MASTER},
            control_ops=w.control_ops,
            epoch=0,
        )

    def test_parse_error_notification_batch_and_bad_params(self):
        d = self._daemon()
        srv = WorkerServer(d)

        def line(b):
            return srv.dispatch_line(b) or b""

        # malformed JSON -> -32700 parse error
        self.assertIn(b'"code":-32700', line(b"not json"))
        # a notification (no id) yields NO reply
        self.assertIsNone(
            srv.dispatch_line(b'{"jsonrpc":"2.0","method":"GET","params":{"path":"x"}}')
        )
        # unknown method -> -32601
        self.assertIn(
            b'"code":-32601', line(b'{"jsonrpc":"2.0","id":1,"method":"NOPE","params":{}}')
        )
        # missing required param -> -32602 invalid params
        self.assertIn(
            b'"code":-32602', line(b'{"jsonrpc":"2.0","id":2,"method":"GET","params":{}}')
        )
        # a batch: one good GET (absent key) + one unknown-method error, id-correlated
        out = srv.dispatch_line(
            b'[{"jsonrpc":"2.0","id":1,"method":"GET","params":{"path":"absent"}},'
            b'{"jsonrpc":"2.0","id":2,"method":"NOPE","params":{}}]'
        )
        assert out is not None
        batch = json.loads(out)
        self.assertEqual(len(batch), 2)
        ids = {r["id"] for r in batch}
        self.assertEqual(ids, {1, 2})
        d.close()

    def test_a_dudefs_error_becomes_a_json_rpc_internal_error_not_a_crash(self):
        # A known DudeFS condition raised WHILE handling a request (here the store is
        # closed under us at shutdown) travels the single `except DudeFSError` path and
        # is reported as JSON-RPC -32603 — never a crashed connection thread.
        d = self._daemon()
        srv = WorkerServer(d)
        d.close()  # the client store is now closed -> GET's read_txn raises StoreClosed
        out = srv.dispatch_line(b'{"jsonrpc":"2.0","id":1,"method":"GET","params":{"path":"k"}}')
        assert out is not None
        self.assertIn(b'"code":-32603', out)


class TestRequestGate(unittest.TestCase):
    """The op-author request gate (NOTES 58): a node refuses a non-authorized
    author's blind write AT THE DOOR (BAD_AUTHZ), best-effort — instead of storing +
    receipting it and letting the fold mark it invalid (the resource/DoS hole)."""

    def test_authorized_write_served_revoked_refused(self):
        from dudefs import node as N
        from dudefs.acceptor import Rejected, RejectReason

        w = World(seed=50, n_clients=2)  # client 0 authorized; revoke client 1
        control = [*w.control_ops, w.revoke(1)]
        sk = bytes([200] * 32)
        nd = NodeDaemon(
            sk,
            C.SIGNER.public(sk),
            roster=[C.SIGNER.public(sk)],
            manager_pub=w.mgr_pub,
            control_ops=control,
            clock=lambda: 100,  # small clock to match World's HLCs (skew gate off)
            delta_ms=10**9,
        )
        ok = w.blind(0, [], [[A.Mutation.SET, b"a", b"1"]])  # authorized author
        bad = w.blind(1, [], [[A.Mutation.SET, b"b", b"1"]])  # revoked author
        r_ok = N.dispatch(nd.node, N.SubmitReq(ok))
        r_bad = N.dispatch(nd.node, N.SubmitReq(bad))
        self.assertIsInstance(r_ok, A.Receipt)  # false-rejection guard: authorized served
        assert isinstance(r_bad, Rejected)
        self.assertEqual(r_bad.reason, RejectReason.BAD_AUTHZ)  # revoked refused at the door
        nd.close()

    def test_fail_closed_until_the_cert_propagates(self):
        # a node that has NOT yet heard the author's CERT_ISSUE refuses (fail-closed,
        # NOTES 59) — the documented bootstrap-latency behavior, not a bug.
        from dudefs import node as N
        from dudefs.acceptor import Rejected, RejectReason

        w = World(seed=51, n_clients=1)
        sk = bytes([201] * 32)
        nd = NodeDaemon(
            sk,
            C.SIGNER.public(sk),
            roster=[C.SIGNER.public(sk)],
            manager_pub=w.mgr_pub,
            control_ops=[],
            clock=lambda: 100,
            delta_ms=10**9,
        )  # NO control ops seeded -> the node knows only the manager
        op = w.blind(0, [], [[A.Mutation.SET, b"a", b"1"]])  # certed in the log, unheard here
        r = N.dispatch(nd.node, N.SubmitReq(op))
        assert isinstance(r, Rejected)
        self.assertEqual(r.reason, RejectReason.BAD_AUTHZ)
        nd.close()


class TestEndpointConsumption(unittest.TestCase):
    """The control plane IS the peer registry (NOTES 58): node daemons derive gossip
    peers and client daemons derive roster_addrs from ENDPOINT control ops."""

    def _endpoints(self, w, roster):
        return [
            w._mgr_op(ctl.endpoint_body(roster[i], [(b"unix", f"/n{i}.sock".encode(), {})]))
            for i in range(len(roster))
        ]

    def test_node_daemon_derives_peers_from_endpoints(self):
        w = World(seed=40, n_clients=0)
        sks = [bytes([200 + i] * 32) for i in range(3)]
        roster = [C.SIGNER.public(s) for s in sks]
        eps = self._endpoints(w, roster)
        nd = NodeDaemon(sks[0], roster[0], roster=roster, manager_pub=w.mgr_pub, delta_ms=10**9)
        with nd.store.write_txn() as tx:
            for op in [*w.control_ops, *eps]:
                tx.put_op_raw(op)
        nd.refresh_peers()
        # peers are (identity, address) pairs now (L_msg needs `to`); check the addresses
        self.assertEqual(
            {pr.endpoint.uri for pr in nd.peers}, {"/n1.sock", "/n2.sock"}
        )  # excludes self
        nd.close()

    def test_client_daemon_derives_roster_addrs_from_endpoints(self):
        w = World(seed=41, n_clients=1)
        sks = [bytes([200 + i] * 32) for i in range(3)]
        roster = [C.SIGNER.public(s) for s in sks]
        eps = self._endpoints(w, roster)
        c = ClientDaemon(
            w.clients[0].sk,
            w.clients[0].pub,
            roster=roster,
            roster_addrs=unix_eps(["seed", "seed", "seed"]),
            manager_pub=w.mgr_pub,
            masters={0: MASTER},
            control_ops=[*w.control_ops, *eps],
            epoch=0,
        )
        c.refresh_addrs()
        self.assertEqual([e.uri for e in c.roster_addrs], ["/n0.sock", "/n1.sock", "/n2.sock"])
        c.close()

    def test_derivation_takes_first_advertised_address_and_keeps_seed_when_missing(self):
        # node0: multi-homed (http + unix) -> take the FIRST advertised (http), carrying
        # its carrier + sealed flag; node1: http only -> taken; node2: no record -> keep
        # the seed. Since the transport seam a client dials any carrier, so the address
        # is the node's declared preference order, not a unix filter.
        w = World(seed=42, n_clients=1)
        roster = [C.SIGNER.public(bytes([200 + i] * 32)) for i in range(3)]
        eps = [
            w._mgr_op(
                ctl.endpoint_body(
                    roster[0],
                    [
                        (b"http", b"http://x/dude", {b"lmsg": b"sealed"}),
                        (b"unix", b"/n0.sock", {}),
                    ],
                )
            ),
            w._mgr_op(ctl.endpoint_body(roster[1], [(b"http", b"http://y/dude", {})])),
        ]
        c = ClientDaemon(
            w.clients[0].sk,
            w.clients[0].pub,
            roster=roster,
            roster_addrs=unix_eps(["s0", "s1", "s2"]),
            manager_pub=w.mgr_pub,
            masters={0: MASTER},
            control_ops=[*w.control_ops, *eps],
            epoch=0,
        )
        c.refresh_addrs()
        n0, n1, n2 = c.roster_addrs
        self.assertEqual((n0.transport, n0.uri, n0.sealed), (b"http", "http://x/dude", True))
        self.assertEqual((n1.transport, n1.uri), (b"http", "http://y/dude"))
        self.assertEqual((n2.transport, n2.uri), (b"unix", "s2"))  # no record -> seed kept
        c.close()


class TestWorkerAPIWire(unittest.TestCase):
    def test_json_rpc_txn_status_get_over_the_socket(self):
        w = World(seed=5, n_clients=1)
        with tempfile.TemporaryDirectory() as tmp:
            cl = _Cluster(tmp, w)
            c = cl.client(w)
            srv = WorkerServer(c)
            wpath = os.path.join(tmp, "worker.sock")
            ready = threading.Event()
            threading.Thread(target=srv.serve_forever, args=(wpath, ready), daemon=True).start()
            self.assertTrue(ready.wait(2))

            sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
            sock.connect(wpath)
            rf = sock.makefile("rb")

            def rpc(method, params, rid=1):
                sock.sendall(
                    (
                        json.dumps(
                            {"jsonrpc": "2.0", "id": rid, "method": method, "params": params}
                        )
                        + "\n"
                    ).encode()
                )
                return json.loads(rf.readline())

            # TXN create -> op_hash ticket immediately
            r = rpc(
                "TXN",
                {
                    "slot": {"path": "k", "version": "⊥", "attempt": 0},
                    "guards": [{"path": "k", "cond": "absent"}],
                    "mutations": [{"set": "k", "value": "v1"}],
                },
            )
            op_hex = r["result"]["op"]
            self.assertEqual(len(op_hex), 64)

            # poll STATUS to committed, then GET the value — all over JSON-RPC
            def committed():
                return rpc("STATUS", {"op": op_hex}, rid=2)["result"]["phase"] == "committed"

            self.assertTrue(poll_until(committed))
            got = rpc("GET", {"path": "k"}, rid=3)["result"]
            self.assertEqual(got["value"], "v1")
            self.assertEqual(got["tier"], "local")

            # an unknown verb is a JSON-RPC error, not a crash (no stubs, no bleed)
            err = rpc("PREPARE", {}, rid=4)  # a node verb must NOT be reachable here
            self.assertIn("error", err)
            self.assertEqual(err["error"]["code"], -32601)

            rf.close()
            sock.close()
            srv.close()
            c.close()
            cl.close()


class TestBootstrapConsumer(unittest.TestCase):
    """WP-C: a client whose below-cut band is GC'd (holds only the retained winners +
    the checkpoint + the tail, NOT the dead ops) reconstructs the barrier from the
    unsealed sidecar and reads BYTE-IDENTICALLY to a full-history client (A4) — the real
    client._fold path, verifying state_root at intake (WP-B)."""

    def _client(self, w):
        c = ClientDaemon(
            w.clients[0].sk,
            w.clients[0].pub,
            roster=[C.SIGNER.public(bytes([1] * 32))],
            roster_addrs=unix_eps(["/nonexistent.sock"]),  # reads fold locally, no RPC
            manager_pub=w.mgr_pub,
            masters={0: MASTER},
            control_ops=w.control_ops,
            epoch=0,
        )
        c.keyring, c.genesis = w.keyring, w.genesis  # align with the World's op keys
        return c

    @staticmethod
    def _qc(op):
        # a minimal 1-node QC — the fold only checks a QC is PRESENT (committed)
        nsk = bytes([200] * 32)
        npub = C.SIGNER.public(nsk)
        r = A.Receipt.issue(nsk, npub, op.op_hash, 0, A.BLIND, 1)
        return A.QC.assemble([r], 1, {npub: 0})

    def test_gc_d_client_bootstraps_from_checkpoint_equals_full_history(self):
        w = World(seed=70, n_clients=1)
        below = list(w.control_ops)
        below.append(
            w.cas(
                0,
                b"k1",
                VERSION_ABSENT,
                0,
                [[A.Guard.ABSENT, b"k1"]],
                [[A.Mutation.SET, b"k1", b"v1"]],
            )
        )
        v, a = F.fold(below, w.keyring, w.genesis).lineage(b"k1")
        below.append(
            w.cas(
                0, b"k1", v, a, [[A.Guard.VERSION_EQ, b"k1", v]], [[A.Mutation.SET, b"k1", b"v2"]]
            )
        )  # supersedes v1 -> v1 becomes dead (GC'd)
        below.append(
            w.cas(
                0,
                b"k2",
                VERSION_ABSENT,
                0,
                [[A.Guard.ABSENT, b"k2"]],
                [[A.Mutation.SET, b"k2", b"w1"]],
            )
        )
        cut = cut_of(w)
        cr = compactor.compact_genesis(below, w.keyring, w.genesis, cut)
        sealed = compactor.seal_attempts(cr.attempts, w.keyring[0]["data_key"])
        ckpt = w.checkpoint(cut=cut, state_root=cr.state_root, dead=cr.dead, attempts=sealed)
        v2, a2 = F.fold(below, w.keyring, w.genesis).lineage(b"k1")
        tail = w.cas(
            0, b"k1", v2, a2, [[A.Guard.VERSION_EQ, b"k1", v2]], [[A.Mutation.SET, b"k1", b"v3"]]
        )

        full = F.fold(below + [ckpt, tail], w.keyring, w.genesis)
        self.assertEqual(full.state, {b"k1": b"v3", b"k2": b"w1"})

        c = self._client(w)
        try:
            retained_data = [o for o in cr.retained if not o.is_control]
            with c.store.write_txn() as tx:
                for op in w.control_ops:  # authz chain (control ops fold without a QC)
                    tx.put_op_raw(op)
                for op in [*retained_data, ckpt, tail]:  # committed; the DEAD ops are absent
                    tx.put_op_raw(op)
                    tx.put_qc(self._qc(op))
            with c.store.read_txn() as tx:
                self.assertTrue(any(tx.get_op(h) is None for h in cr.dead))  # really sparse
                boot = c._fold(tx)
            self.assertEqual(boot.state, full.state)  # A4: sparse bootstrap == full history
        finally:
            c.close()


if __name__ == "__main__":
    unittest.main()
