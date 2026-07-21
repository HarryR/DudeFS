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
from dudefs import crypto as C
from dudefs.artifacts import VERSION_ABSENT
from dudefs.client import ClientDaemon
from dudefs.daemon import NodeDaemon
from dudefs.workerapi import WorkerServer
from tests._builders import World

DELTA = 150  # ms — small enough that finality sweeps ~DELTA after a write, big
# enough that same-machine client/node clock jitter never trips the skew gate.
MASTER = bytes(range(32))  # the epoch-0 group master (finding 21 derives from it)


def _now() -> int:
    return int(time.time() * 1000)


def _until(pred, timeout=6.0, step=0.01):
    """Poll `pred()` until truthy (returns it) or timeout (returns the last value)."""
    deadline = time.monotonic() + timeout
    val = pred()
    while not val and time.monotonic() < deadline:
        time.sleep(step)
        val = pred()
    return val


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
                clock=_now,
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
            roster_addrs=self.paths,
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
            self.assertTrue(_until(lambda: c.status(op).phase == "committed"))
            self.assertEqual(c.status(op).provisional, "applied")
            self.assertEqual(c.get(b"k")["value"], b"v1")
            # the daemon finishes the job: pursues §9 finality -> frozen verdict
            self.assertTrue(_until(lambda: c.status(op).final == "applied"))
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
            self.assertTrue(_until(lambda: a.status(oa).phase in ("committed", "lost")))
            self.assertTrue(_until(lambda: b.status(ob).phase in ("committed", "lost")))
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
            self.assertTrue(_until(lambda: c.status(op).phase == "committed"))
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
                self.assertTrue(_until(lambda o=op: c.status(o).phase == "committed"))
            rows = c.list_keys(b"q/items/", delimiter=b"/")
            keys = {r["key"] for r in rows if not r["prefix"]}
            self.assertEqual(keys, {b"q/items/1", b"q/items/2"})
            insp = c.inspect(b"q/items/1")
            self.assertTrue(insp["provisional"]["present"])
            self.assertEqual(insp["provisional"]["value"], b"a")
            c.close()
            cl.close()


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

            self.assertTrue(_until(committed))
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


if __name__ == "__main__":
    unittest.main()
