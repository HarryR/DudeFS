# WP4 — the IMPLEMENTATION §9 runbook as an executable, asserted test. The whole
# system end-to-end and ENCRYPTED (xcs1 throughout): 3 node daemons + 2 client
# daemons on real unix sockets. A CAS storm with genuine cross-client traffic; a
# node killed mid-storm (commits keep landing on the surviving quorum, the restarted
# node re-joins via gossip); disk-wipe identity retirement via a roster replace; and
# the recovery drill authoring a real fence once the quorum is genuinely dead.

import os
import tempfile
import threading
import time
import unittest

from dudefs import artifacts as A
from dudefs import crypto as C
from dudefs.acceptor import Acceptor
from dudefs.artifacts import VERSION_ABSENT
from dudefs.client import ClientDaemon
from dudefs.daemon import NodeDaemon
from dudefs.handlers import control as ctl
from dudefs.manager import Manager
from dudefs.node import LocalNode, dispatch
from dudefs.store import ChainStore
from tests._builders import World, now_ms, poll_until

DELTA = 150
MASTER = bytes(range(32))


def _k(s: str) -> bytes:
    return s.encode()


class Demo:
    """3 node daemons (peered for gossip) + 2 client daemons — the §9 topology."""

    def __init__(self, tmp, w, n=3):
        self.tmp = tmp
        self.w = w
        self.node_sks = [bytes([200 + i] * 32) for i in range(n)]
        self.roster = [C.SIGNER.public(sk) for sk in self.node_sks]
        self.paths = [os.path.join(tmp, f"node{i}.sock") for i in range(n)]
        self.nodes: list[NodeDaemon | None] = [None] * n
        for i in range(n):
            self._spawn_node(i)
        self.clients = [self._client(w, ci) for ci in range(2)]

    def _peers(self, i):
        return [self.paths[j] for j in range(len(self.paths)) if j != i]

    def _spawn_node(self, i, sk=None):
        if os.path.exists(self.paths[i]):
            os.unlink(self.paths[i])  # clear the stale socket file so re-bind succeeds
        nd = NodeDaemon(
            sk or self.node_sks[i],
            C.SIGNER.public(sk) if sk else self.roster[i],
            roster=self.roster,
            manager_pub=self.w.mgr_pub,
            peers=self._peers(i),
            clock=now_ms,
            delta_ms=DELTA,
        )
        ev = threading.Event()
        threading.Thread(target=nd.serve_forever, args=(self.paths[i], ev), daemon=True).start()
        assert ev.wait(2)
        self.nodes[i] = nd

    def _client(self, w, ci):
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

    def kill_node(self, i):
        node = self.nodes[i]
        assert node is not None
        node.close()  # kill -9: socket + store gone
        self.nodes[i] = None
        time.sleep(0.05)

    def restart_node(self, i):
        self._spawn_node(i)  # fresh :memory: store — must re-join via gossip

    def gossip_all(self, rounds=3):
        for _ in range(rounds):
            for nd in self.nodes:
                if nd is not None:
                    nd.sync_once()

    def close(self):
        for c in self.clients:
            c.close()
        for nd in self.nodes:
            if nd is not None:
                nd.close()
        time.sleep(0.05)


class TestDemoRunbook(unittest.TestCase):
    def test_cas_storm_two_clients_converge(self):
        # both clients write concurrently (distinct keys + one contended lock); every
        # distinct write commits, the lock resolves to exactly one winner, and after a
        # read-side sync EACH client sees the OTHER's committed writes (encrypted).
        w = World(seed=10, n_clients=2)
        with tempfile.TemporaryDirectory() as tmp:
            demo = Demo(tmp, w)
            a, b = demo.clients
            K = 4
            mine = []
            for i in range(K):
                mine.append(
                    (
                        a,
                        a.submit(
                            (_k(f"a/{i}"), VERSION_ABSENT, 0),
                            [[A.Guard.ABSENT, _k(f"a/{i}")]],
                            [[A.Mutation.SET, _k(f"a/{i}"), b"A"]],
                        ),
                    )
                )
                mine.append(
                    (
                        b,
                        b.submit(
                            (_k(f"b/{i}"), VERSION_ABSENT, 0),
                            [[A.Guard.ABSENT, _k(f"b/{i}")]],
                            [[A.Mutation.SET, _k(f"b/{i}"), b"B"]],
                        ),
                    )
                )
            la = a.submit(
                (b"lock", VERSION_ABSENT, 0),
                [[A.Guard.ABSENT, b"lock"]],
                [[A.Mutation.SET, b"lock", b"A"]],
            )
            lb = b.submit(
                (b"lock", VERSION_ABSENT, 0),
                [[A.Guard.ABSENT, b"lock"]],
                [[A.Mutation.SET, b"lock", b"B"]],
            )

            for who, op in mine:
                self.assertTrue(poll_until(lambda w=who, o=op: w.status(o).phase == "committed"))
            self.assertTrue(
                poll_until(
                    lambda: {a.status(la).phase, b.status(lb).phase} == {"committed", "lost"}
                )
            )

            # cross-client convergence: after sync each sees the other's writes + agrees
            self.assertTrue(
                poll_until(lambda: (a.sync(), b.sync(), a.get(_k("b/0"))["value"])[2] == b"B")
            )
            for i in range(K):
                self.assertEqual(a.get(_k(f"b/{i}"))["value"], b"B")  # A sees B's writes
                self.assertEqual(b.get(_k(f"a/{i}"))["value"], b"A")  # B sees A's writes
            self.assertEqual(a.get(b"lock")["value"], b.get(b"lock")["value"])  # agree on winner
            demo.close()

    def test_node_killed_midstorm_commits_land_and_node_rejoins(self):
        w = World(seed=11, n_clients=2)
        with tempfile.TemporaryDirectory() as tmp:
            demo = Demo(tmp, w)
            a = demo.clients[0]
            pre = a.submit(
                (b"jobs/1", VERSION_ABSENT, 0),
                [[A.Guard.ABSENT, b"jobs/1"]],
                [[A.Mutation.SET, b"jobs/1", b"v"]],
            )
            self.assertTrue(poll_until(lambda: a.status(pre).phase == "committed"))

            demo.kill_node(2)  # chaos, mid-traffic
            # commits STILL land on the surviving quorum (2 of 3)
            during = a.submit(
                (b"jobs/2", VERSION_ABSENT, 0),
                [[A.Guard.ABSENT, b"jobs/2"]],
                [[A.Mutation.SET, b"jobs/2", b"v"]],
            )
            self.assertTrue(poll_until(lambda: a.status(during).phase == "committed"))

            # the restarted node re-joins via gossip and re-acquires the missed commit
            demo.restart_node(2)
            demo.gossip_all()
            n2 = demo.nodes[2]
            assert n2 is not None
            self.assertTrue(poll_until(lambda: n2.store.get_op(during) is not None, timeout=3))
            self.assertIsNotNone(n2.store.get_qc(during))  # + the commit proof
            demo.close()

    def test_disk_wipe_identity_retirement_via_replace(self):
        # a wiped node's key is untrusted: revoke it + swap a fresh (caught-up)
        # identity into the roster via the REAL §13 joint-cert drive — decided on the
        # old roster, possession-gated on the new roster (findings 23/24).
        w = World(seed=13, n_clients=1)
        base = w.blind(0, [], [[A.Mutation.SET, b"k", b"v"]])
        with tempfile.TemporaryDirectory() as d:
            m = Manager.init(d)
            keys = [(C.SIGNER.public(bytes([i] * 32)), bytes([i] * 32)) for i in (21, 22, 23)]
            roster = [k[0] for k in keys]
            m.state.roster = list(roster)
            old = roster[2]
            m.cert_issue("node", old)  # the retiring node had a STORE cert
            m.cert_revoke(old, rotate=False)  # the old key is untrusted

            fresh_sk = bytes([24] * 32)
            fresh = C.SIGNER.public(fresh_sk)
            # in-process cluster: old roster + the fresh node, all holding `base` (the
            # fresh replacement caught up via gossip before joining)
            nodes = {}
            for pub, sk in [*keys, (fresh, fresh_sk)]:
                acc = Acceptor(sk, pub, ChainStore(), 0, 10**9)
                acc.store.append(base)
                nodes[pub] = LocalNode(acc, lambda: 100)
            change = m.node_replace(old, fresh, lambda pub, req: dispatch(nodes[pub], req))

            self.assertIn(fresh, m.state.roster)
            self.assertNotIn(old, m.state.roster)
            self.assertEqual(len(m.state.roster), 3)  # odd, unchanged
            self.assertTrue(change.new_qc.verify(m.state.roster))  # possession-gated
            self.assertEqual(change.op.slot_tag, A.roster_slot_tag(0))

    def test_recovery_drill_authors_fence_when_quorum_is_dead(self):
        # kill a QUORUM (2 of 3); a lone survivor cannot make progress, so recovery is
        # now legitimate — the drill authors a real fence (salvage = survivor's floor).
        w = World(seed=12, n_clients=2)
        with tempfile.TemporaryDirectory() as tmp:
            demo = Demo(tmp, w)
            a = demo.clients[0]
            op = a.submit(
                (b"kept", VERSION_ABSENT, 0),
                [[A.Guard.ABSENT, b"kept"]],
                [[A.Mutation.SET, b"kept", b"v"]],
            )
            self.assertTrue(poll_until(lambda: a.status(op).phase == "committed"))
            for c in demo.clients:
                c.close()
            demo.clients = []

            # a manager whose state points at the (now mostly-dead) cluster
            with tempfile.TemporaryDirectory() as md:
                m = Manager.init(md)
                m.state.roster = demo.roster
                m.state.node_addrs = {demo.roster[i].hex(): demo.paths[i] for i in range(3)}
                m.state.save()
                demo.kill_node(1)
                demo.kill_node(2)  # only node0 survives -> below quorum

                from dudefs.cli import _probe_floor
                from dudefs.manager import RecoverDecision, recover_decision

                report = m.probe_roster(_probe_floor, dwell=0.4, sleep=time.sleep)
                self.assertLess(len(report.reachable), report.quorum)  # quorum is dead
                self.assertIs(recover_decision(report, data_loss_ack=True), RecoverDecision.PROCEED)
                ckpt, rop = m.author_recovery_fence(report)
                rbody = ctl.decode(rop)
                assert rbody is not None
                self.assertEqual(rbody[b"recovery"], ckpt.op_hash)  # the recovery pairing
            demo.close()


if __name__ == "__main__":
    unittest.main()
