# WP3 — the `dude` CLI (MANAGER.md). Manager verbs author real root-signed control
# ops against an on-disk state dir; client verbs pass through to a live worker
# socket; `recover`'s interlocks are tested as behavior (a reachable quorum MUST
# hard-refuse — RESILIENCE §2.3). No stubs.

import contextlib
import io
import os
import tempfile
import threading
import time
import unittest

from dudefs import artifacts as A
from dudefs import crypto as C
from dudefs.cli import ManagerState, main
from dudefs.client import ClientDaemon
from dudefs.daemon import NodeDaemon
from dudefs.handlers import control as ctl
from dudefs.workerapi import WorkerServer
from tests._builders import World

MASTER = bytes(range(32))
DELTA = 150


def _run(argv):
    """Invoke the CLI, capturing (exit_code, stdout, stderr)."""
    out, err = io.StringIO(), io.StringIO()
    with contextlib.redirect_stdout(out), contextlib.redirect_stderr(err):
        code = main(argv)
    return code, out.getvalue(), err.getvalue()


def _now():
    return int(time.time() * 1000)


class TestManagerCommands(unittest.TestCase):
    def test_init_refuses_over_existing_state(self):
        with tempfile.TemporaryDirectory() as d:
            dd = os.path.join(d, "st")
            code, out, _ = _run(["init", "--dir", dd])
            self.assertEqual(code, 0)
            self.assertIn("zero-knowledge: ON", out)  # xcs1 is live
            self.assertTrue(ManagerState.exists(dd))
            # second init is refused (genesis-only interlock)
            code2, _, err2 = _run(["init", "--dir", dd])
            self.assertEqual(code2, 2)
            self.assertIn("refusing", err2)

    def test_cert_issue_authors_a_valid_write_cert(self):
        with tempfile.TemporaryDirectory() as d:
            _run(["init", "--dir", d])
            client_pub = C.SIGNER.public(bytes([9] * 32))
            code, out, _ = _run(["cert", "issue", "client", client_pub.hex(), "--dir", d])
            self.assertEqual(code, 0)
            # the control.log holds a decodable CERT_ISSUE naming the subject
            with open(os.path.join(d, "control.log")) as f:
                raw = bytes.fromhex(f.readlines()[-1].strip())
            body = ctl.decode(A.Op.from_bytes(raw))
            assert body is not None
            self.assertEqual(body[ctl.BK_KIND], ctl.ControlKind.CERT_ISSUE)
            self.assertEqual(body[b"subject"], client_pub)

    def test_revoke_stages_rotate_and_bumps_keyepoch(self):
        with tempfile.TemporaryDirectory() as d:
            _run(["init", "--dir", d])
            sub = C.SIGNER.public(bytes([9] * 32))
            _run(["cert", "issue", "client", sub.hex(), "--dir", d])
            self.assertEqual(ManagerState.load(d).keyepoch, 0)
            code, out, _ = _run(["cert", "revoke", sub.hex(), "--dir", d])
            self.assertEqual(code, 0)
            self.assertIn("rotated to keyepoch 1", out)
            st = ManagerState.load(d)
            self.assertEqual(st.keyepoch, 1)
            self.assertIn(1, st.masters)  # a fresh group master exists for the new epoch
            self.assertTrue(next(c for c in st.certs if c["subject"] == sub.hex())["revoked"])

    def test_no_rotate_flag_skips_rotation_loudly(self):
        with tempfile.TemporaryDirectory() as d:
            _run(["init", "--dir", d])
            sub = C.SIGNER.public(bytes([9] * 32))
            _run(["cert", "issue", "client", sub.hex(), "--dir", d])
            code, out, _ = _run(["cert", "revoke", sub.hex(), "--no-rotate", "--dir", d])
            self.assertEqual(code, 0)
            self.assertIn("WARNING", out)
            self.assertEqual(ManagerState.load(d).keyepoch, 0)  # NOT rotated

    def test_node_promote_refuses_even_roster(self):
        with tempfile.TemporaryDirectory() as d:
            _run(["init", "--dir", d])  # genesis roster = 1 node (odd)
            npub = C.SIGNER.public(bytes([5] * 32))
            _run(["node", "add", npub.hex(), "--dir", d])
            # promoting to 2 voting members is even -> client-side refusal
            code, _, err = _run(["node", "promote", npub.hex(), "--dir", d])
            self.assertEqual(code, 1)
            self.assertIn("EVEN", err)
            self.assertEqual(len(ManagerState.load(d).roster), 1)  # unchanged


class TestRecoverInterlock(unittest.TestCase):
    def test_recover_hard_refuses_while_a_quorum_answers(self):
        # THE load-bearing interlock (MANAGER §3 / RESILIENCE §2.3): a reachable
        # quorum must hard-refuse recovery — the cluster is not dead.
        w = World(seed=1, n_clients=0)
        with tempfile.TemporaryDirectory() as d:
            _run(["init", "--dir", d])
            st = ManagerState.load(d)
            # stand up a real 3-node roster on sockets and point the state at them
            sks = [bytes([200 + i] * 32) for i in range(3)]
            roster = [C.SIGNER.public(s) for s in sks]
            nodes, addrs = [], {}
            for i in range(3):
                path = os.path.join(d, f"node{i}.sock")
                nd = NodeDaemon(
                    sks[i],
                    roster[i],
                    roster=roster,
                    manager_pub=w.mgr_pub,
                    clock=_now,
                    delta_ms=DELTA,
                )
                ev = threading.Event()
                threading.Thread(target=nd.serve_forever, args=(path, ev), daemon=True).start()
                self.assertTrue(ev.wait(2))
                nodes.append(nd)
                addrs[roster[i].hex()] = path
            st.roster = roster
            st.node_addrs = addrs
            st.save()

            code, out, err = _run(["recover", "--dir", d, "--dwell", "0.3"])
            self.assertEqual(code, 3)  # REFUSE_RECOVER
            self.assertIn("REFUSING recovery", err)
            self.assertIn("reachable: 3/3", out)
            self.assertIn("never urgent", out)
            for nd in nodes:
                nd.close()
            time.sleep(0.05)


class TestClientPassthrough(unittest.TestCase):
    def _cluster(self, d, w):
        sks = [bytes([200 + i] * 32) for i in range(3)]
        roster = [C.SIGNER.public(s) for s in sks]
        paths = [os.path.join(d, f"n{i}.sock") for i in range(3)]
        nodes = []
        for i in range(3):
            nd = NodeDaemon(
                sks[i], roster[i], roster=roster, manager_pub=w.mgr_pub, clock=_now, delta_ms=DELTA
            )
            ev = threading.Event()
            threading.Thread(target=nd.serve_forever, args=(paths[i], ev), daemon=True).start()
            self.assertTrue(ev.wait(2))
            nodes.append(nd)
        client = ClientDaemon(
            w.clients[0].sk,
            w.clients[0].pub,
            roster=roster,
            roster_addrs=paths,
            manager_pub=w.mgr_pub,
            masters={0: MASTER},
            control_ops=w.control_ops,
            epoch=0,
        )
        wsock = os.path.join(d, "worker.sock")
        srv = WorkerServer(client)
        ready = threading.Event()
        threading.Thread(target=srv.serve_forever, args=(wsock, ready), daemon=True).start()
        self.assertTrue(ready.wait(2))
        return nodes, client, srv, wsock

    def test_set_get_and_wheres_through_the_worker_socket(self):
        w = World(seed=2, n_clients=1)
        with tempfile.TemporaryDirectory() as d:
            nodes, client, srv, wsock = self._cluster(d, w)
            # set (PUT) -> get reflects it
            code, out, _ = _run(["set", "my/car", "parked", "--sock", wsock])
            self.assertEqual(code, 0)
            self.assertIn("submitted", out)

            def committed():
                _, o, _ = _run(["get", "my/car", "--sock", wsock])
                return "parked" in o

            self.assertTrue(_until(committed))

            # `dude wheres my car` joins with '/' and renders INSPECT for a human
            code, out, _ = _run(["wheres", "my", "car", "--sock", wsock])
            self.assertEqual(code, 0)
            self.assertIn("where is my/car:", out)
            self.assertIn("parked", out)
            self.assertIn("fence:", out)

            srv.close()
            client.close()
            for nd in nodes:
                nd.close()
            time.sleep(0.05)


def _until(pred, timeout=6.0, step=0.02):
    deadline = time.monotonic() + timeout
    val = pred()
    while not val and time.monotonic() < deadline:
        time.sleep(step)
        val = pred()
    return val


if __name__ == "__main__":
    unittest.main()
