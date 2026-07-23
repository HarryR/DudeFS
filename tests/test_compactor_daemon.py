# R6 WP-G — the compactor DRIVER, end to end against a live 3-node socket cluster: a
# Cap.COMPACT compactor syncs the log, authors a real checkpoint, blind-commits it to a
# node quorum, and the nodes adopt it (horizon advances, the superseded op is GC'd).

import os
import tempfile
import threading
import time
import unittest

from dudefs import artifacts as A
from dudefs import crypto as C
from dudefs.artifacts import VERSION_ABSENT
from dudefs.client import ClientDaemon
from dudefs.compactor_daemon import CompactorDaemon
from dudefs.daemon import NodeDaemon, Peer
from dudefs.handlers import control as ctl
from tests._builders import World, now_ms, poll_until, unix_eps

DELTA = 150


class TestCompactorDriver(unittest.TestCase):
    def test_compact_once_drives_a_checkpoint_the_nodes_adopt(self):
        with tempfile.TemporaryDirectory() as tmp:
            w = World(seed=41, n_clients=1)
            # authorize a compactor: a Cap.COMPACT cert + the epoch-0 key back-wrapped to it
            comp_sk = bytes([150] * 32)
            comp_pub = C.SIGNER.public(comp_sk)
            w.control_ops.append(w._mgr_op(ctl.cert_issue_body(comp_pub, [ctl.Cap.COMPACT], 0)))
            w.control_ops.append(w._mgr_op(ctl.sealed_wrap_set_body(0, w.masters[0], [comp_pub])))

            node_sks = [bytes([200 + i] * 32) for i in range(3)]
            roster = [C.SIGNER.public(s) for s in node_sks]
            paths = [os.path.join(tmp, f"n{i}.sock") for i in range(3)]
            nodes = []
            for i in range(3):
                nd = NodeDaemon(
                    node_sks[i],
                    roster[i],
                    roster=roster,
                    manager_pub=w.mgr_pub,
                    control_ops=w.control_ops,
                    clock=now_ms,
                    delta_ms=DELTA,
                )
                ev = threading.Event()
                threading.Thread(target=nd.serve_forever, args=(paths[i], ev), daemon=True).start()
                assert ev.wait(2)
                nodes.append(nd)
            addrs = unix_eps(paths)
            client = ClientDaemon(
                w.clients[0].sk,
                w.clients[0].pub,
                roster=roster,
                roster_addrs=addrs,
                manager_pub=w.mgr_pub,
                control_ops=w.control_ops,
                epoch=0,
            )
            comp = CompactorDaemon(
                comp_sk,
                comp_pub,
                roster=roster,
                roster_addrs=addrs,
                manager_pub=w.mgr_pub,
                control_ops=w.control_ops,
                epoch=0,
            )
            try:
                # create k=v1, then supersede it -> v1 (op1) becomes DEAD below the cut
                op1 = client.submit(
                    (b"k", VERSION_ABSENT, 0),
                    [[A.Guard.ABSENT, b"k"]],
                    [[A.Mutation.SET, b"k", b"v1"]],
                )
                self.assertTrue(poll_until(lambda: client.status(op1).phase == "committed"))
                self.assertTrue(poll_until(lambda: client.get(b"k").get("present")))
                v1 = client.get(b"k")["version"]
                op2 = client.submit(
                    (b"k", v1, 0),
                    [[A.Guard.VERSION_EQ, b"k", v1]],
                    [[A.Mutation.SET, b"k", b"v2"]],
                )
                self.assertTrue(poll_until(lambda: client.status(op2).phase == "committed"))
                self.assertTrue(poll_until(lambda: not client.status(op2).may_flip))  # final

                # the compactor drives a real checkpoint to a quorum commit
                ckpt = None
                for _ in range(25):
                    ckpt = comp.compact_once()
                    if ckpt is not None:
                        break
                    time.sleep(0.2)
                self.assertIsNotNone(ckpt, "compactor committed a checkpoint")

                # wire the nodes for gossip so a node that lagged the write fills its
                # baseline before adopting; then every node adopts the committed checkpoint.
                for i, nd in enumerate(nodes):
                    nd.peers = [Peer(roster[j], addrs[j]) for j in range(3) if j != i]

                def adopted() -> bool:
                    for nd in nodes:
                        nd.sync_once()
                    with nodes[0].store.read_txn() as tx:
                        return tx.get_meta("checkpoint") == ckpt

                self.assertTrue(poll_until(adopted))
                with nodes[0].store.read_txn() as tx:
                    self.assertGreater(tx.get_horizon().as_tuple(), (0, 0))  # horizon advanced to F
                    self.assertIsNone(tx.get_op(op1))  # the superseded op was GC'd
            finally:
                comp.close()
                client.close()
                for nd in nodes:
                    nd.close()
                time.sleep(0.05)


if __name__ == "__main__":
    unittest.main()
