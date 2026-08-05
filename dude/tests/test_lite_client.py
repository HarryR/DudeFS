# End-to-end: LightClient through the InProc stack against a real Cluster.
#
# Bootstrap (RT1 + f+1 corroboration) + steady-state GET_PROOF, all wire-real. The
# module-scope InProc registry does the routing; both sides are real Postmen with real
# mailboxes; the light client's state machine drives the whole thing.

from __future__ import annotations

import unittest
from typing import cast

from dude.consensus.bootstrap import intervene
from dude.core import crypto
from dude.net.address import Endpoint, Scheme
from dude.net.postman import Postman
from dude.net.transports import InProc, address_of
from dude.store import ops
from dude.store.management import Cert, Management, Role
from dude.sync.lite_client import PENDING, Failed, GetResult, LightClient, State

from .cluster import DELTA, T0, Cluster


def _provision_client(c: Cluster, kp: crypto.Keypair) -> None:
    """Grant Role.CLIENT via intervene on every store, with the client's InProc endpoint
    baked into the P_GRANT row so nodes can dial back via `_reconcile_peers`
    (#roster-drives-peers)."""
    mgmt = Management(c.nodes[0].store)
    grant_tx = mgmt.authorise(
        kp.public,
        Role.CLIENT,
        stores=frozenset(),
        pop=kp.prove_possession(),
        cert=Cert.sign_grant(c.mgr, kp.public, Role.CLIENT),
        endpoints=(Endpoint(address_of(kp.public)),),
    ).sign(c.mgr, T0)
    for node in c.nodes:
        intervene(node.store, c.mgr, bodies=(grant_tx,), bucket=444)


def _pump(c: Cluster, client: LightClient, client_inbox: InProc, now: int, rounds: int = 5) -> None:
    """Drive the wire: reconcile each node's peers against the current membership
    (`_reconcile_peers` -- so the client's P_GRANT-declared endpoint becomes a
    dial-able peer), flush outbound on every side, and drain each inbox back into
    `receive`. Repeat until quiet or `rounds` exhausted.

    NOTE we call `_reconcile_peers` rather than the full `node.tick(now)` here: the
    latter also drives the consensus round, and `Cluster.pump` in the surrounding test
    is already the one advancing consensus. Duplicating that here races commit-block
    against itself. Peer reconciliation is the only part of `tick` a light-client test
    needs; consensus stays with the cluster."""
    for _ in range(rounds):
        # Peer reconciliation on every node -- picks up CLIENT/COMPACTOR grants.
        for node in c.nodes:
            node._reconcile_peers(now)
        # Client + nodes flush outbound.
        client.tick(now)
        for node in c.nodes:
            node.postman.tick(now)
        # Deliver each side's inbox.
        delivered = 0
        for node in c.nodes:
            for frame in c._transports[node.me.public].receive():
                node.receive(frame, now)
                delivered += 1
        for frame in client_inbox.receive():
            client.receive(frame, now)
            delivered += 1
        if delivered == 0:
            return


class TestLightClientBootstrap(unittest.TestCase):
    def test_bootstrap_reaches_ready(self):
        c = Cluster()
        client_kp = crypto.Keypair.generate()
        _provision_client(c, client_kp)

        # Build the LightClient. Its Postman uses the module-scope INPROC dialler. The
        # reverse direction (nodes dialling this client) is set up by each node's
        # `_reconcile_peers` on tick, using the endpoints baked into the P_GRANT row.
        client_postman = Postman(client_kp)
        client = LightClient(me=client_kp, anchor=c.mgr.public, postman=client_postman)
        for node in c.nodes:
            client.add_bootstrap_peer(node.me.public, (Endpoint(address_of(node.me.public)),))
        client_inbox = cast("InProc", client_postman._transports_by_scheme[Scheme.INPROC])

        # Kick off bootstrap.
        client.bootstrap(T0 + DELTA)
        _pump(c, client, client_inbox, T0 + DELTA)
        _pump(c, client, client_inbox, T0 + 2 * DELTA)

        self.assertTrue(client.bootstrapped(), f"state {client.state.name}")
        ts = client.trusted_state
        assert ts is not None
        self.assertEqual(len(ts.roster), 3)
        self.assertEqual(len(ts.managers), 1)
        self.assertGreater(ts.head[0], 0)


class TestLightClientRead(unittest.TestCase):
    def test_get_proof_returns_head_value(self):
        c = Cluster()
        # Land a value.
        key = crypto.h(b"lite-client-e2e")
        tx = ops.writes(ops.Set(ops.STORE_DATA, key, b"present")).sign(c.mgr, T0)
        c.submit(c.mgr, tx, to=0, now=T0)
        c.pump(T0)
        c.pump(T0 + DELTA)

        client_kp = crypto.Keypair.generate()
        _provision_client(c, client_kp)

        client_postman = Postman(client_kp)
        client = LightClient(me=client_kp, anchor=c.mgr.public, postman=client_postman)
        for node in c.nodes:
            client.add_bootstrap_peer(node.me.public, (Endpoint(address_of(node.me.public)),))

        client_inbox = cast("InProc", client_postman._transports_by_scheme[Scheme.INPROC])

        client.bootstrap(T0 + 2 * DELTA)
        _pump(c, client, client_inbox, T0 + 2 * DELTA)
        _pump(c, client, client_inbox, T0 + 3 * DELTA)
        self.assertTrue(client.bootstrapped())

        # Now do a read.
        rid = client.request_get(
            store_id=ops.STORE_DATA,
            name=key,
            peer=c.nodes[0].me.public,
            now=T0 + 4 * DELTA,
        )
        _pump(c, client, client_inbox, T0 + 4 * DELTA)

        result = client.poll(rid)
        self.assertNotIsInstance(result, type(PENDING), "read still pending")
        self.assertIsInstance(result, GetResult, f"got {result!r}")
        assert isinstance(result, GetResult)
        self.assertFalse(result.absent)
        self.assertEqual(result.value, b"present")

    def test_stale_client_gets_refusal_and_drops_trusted_state(self):
        c = Cluster()
        client_kp = crypto.Keypair.generate()
        _provision_client(c, client_kp)

        client_postman = Postman(client_kp)
        client = LightClient(me=client_kp, anchor=c.mgr.public, postman=client_postman)
        for node in c.nodes:
            client.add_bootstrap_peer(node.me.public, (Endpoint(address_of(node.me.public)),))

        client_inbox = cast("InProc", client_postman._transports_by_scheme[Scheme.INPROC])

        client.bootstrap(T0 + DELTA)
        _pump(c, client, client_inbox, T0 + DELTA)
        _pump(c, client, client_inbox, T0 + 2 * DELTA)
        self.assertTrue(client.bootstrapped())

        # Move cluster far ahead so client's trusted head is stale.
        for i in range(6):
            c.pump(T0 + (3 + i) * DELTA)

        rid = client.request_get(
            store_id=ops.STORE_DATA,
            name=b"anything",
            peer=c.nodes[0].me.public,
            now=T0 + 20 * DELTA,
        )
        _pump(c, client, client_inbox, T0 + 20 * DELTA)

        result = client.poll(rid)
        self.assertIsInstance(result, Failed)
        assert isinstance(result, Failed)
        self.assertEqual(result.reason, "stale-client")
        # Client dropped trusted state; re-bootstrap needed.
        self.assertIs(client.state, State.UNBOOTSTRAPPED)


if __name__ == "__main__":
    unittest.main()
