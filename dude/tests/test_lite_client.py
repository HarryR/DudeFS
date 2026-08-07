# End-to-end: LightClient through the InProc stack against a real Cluster.
#
# Bootstrap (RT1 + f+1 corroboration) + steady-state GET_PROOF, all wire-real. The
# module-scope InProc registry does the routing; both sides are real Postmen with real
# mailboxes; the light client's state machine drives the whole thing.

from __future__ import annotations

import unittest
from dataclasses import replace

from dude.consensus.bootstrap import intervene
from dude.core import crypto
from dude.net.address import Endpoint, Scheme
from dude.net.envelope import Envelope, Frame, SignedEnvelope, Verb
from dude.net.postman import Postman
from dude.net.transports import InProcDialer, InProcListener, address_of, name_of
from dude.store import ops
from dude.store.management import Cert, Management, Role
from dude.sync.lite_adapter import ProofReply
from dude.sync.lite_client import PENDING, Failed, GetResult, LightClient, State

from .cluster import DELTA, T0, Cluster


def _build_light_client(c: Cluster, kp: crypto.Keypair) -> tuple[LightClient, InProcListener]:
    """Same shape as production: construct the listener + client explicitly, attach the
    client to the LightClient's Postman, register bootstrap peers. Returns both so the
    test pump can drain the listener via `.drain()`."""
    listener = InProcListener(name_of(kp.public))
    postman = Postman(kp)
    postman.attach_transport(Scheme.INPROC, InProcDialer(me=name_of(kp.public)))
    client = LightClient(me=kp, anchor=c.mgr.public, postman=postman)
    for node in c.nodes:
        client.add_bootstrap_peer(node.me.public, (Endpoint(address_of(node.me.public)),))
    return client, listener


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
    ).sign(c.mgr, T0)
    for node in c.nodes:
        intervene(node.store, c.mgr, bodies=(grant_tx,), bucket=444)


def _mutate_frame_to_client(
    frame: Frame,
    client_kp: crypto.Keypair,
    server_kp: crypto.Keypair,
    mutate_proof_reply,
    now: int,
) -> Frame:
    """Unseal a frame addressed to `client_kp`, decode the envelope; if the verb is
    `PROOF_REPLY`, apply `mutate_proof_reply(reply) -> ProofReply` to the decoded
    ProofReply and re-emit the frame with a fresh envelope signed by `server_kp` and
    re-sealed to the client. Non-PROOF_REPLY frames pass through unchanged.

    Used to simulate a byzantine responder: the envelope signature and the frame's
    sealed structure are honest (a real server signed it), but the ProofReply's payload
    has been swapped for something the SMT proof no longer verifies against."""
    raw = client_kp.open_sealed_raw(frame.sealed)
    signed = SignedEnvelope.decode(raw)
    if signed.env.verb is not Verb.PROOF_REPLY:
        return frame
    reply = ProofReply._decode(signed.env.body)
    mutated = mutate_proof_reply(reply)
    verb, body = mutated.encode()
    new_env = Envelope(
        to=signed.env.to,
        verb=verb,
        mid=signed.env.mid,
        body=body,
        reply_to=signed.env.reply_to,
        reply_ts=signed.env.reply_ts,
    )
    return new_env.sign(server_kp, now).seal()


def _pump(
    c: Cluster,
    client: LightClient,
    client_listener: InProcListener,
    now: int,
    rounds: int = 5,
) -> None:
    """Drive the wire: reconcile each node's peers against the current membership
    (`_reconcile_peers` -- so the client's P_GRANT-declared endpoint becomes a
    dial-able peer), flush outbound on every side, and drain each listener back into
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
        # Deliver each side's listener via the public drain() API.
        delivered = 0
        for node in c.nodes:
            for inbound in c.listeners[node.me.public].drain():
                node.receive(inbound.frame, now, session=inbound.session)
                delivered += 1
        for inbound in client_listener.drain():
            client.receive(inbound.frame, now, session=inbound.session)
            delivered += 1
        if delivered == 0:
            return


class TestLightClientBootstrap(unittest.TestCase):
    def test_bootstrap_reaches_ready(self):
        c = Cluster()
        client_kp = crypto.Keypair.generate()
        _provision_client(c, client_kp)

        # Build the LightClient. `_build_light_client` constructs the InProcDialer +
        # InProcListener explicitly and attaches the client to the Postman -- same
        # shape as production. The reverse direction (nodes dialling this client) is
        # set up by each node's `_reconcile_peers` on tick, using the endpoints baked
        # into the P_GRANT row.
        client, client_listener = _build_light_client(c, client_kp)

        # Kick off bootstrap.
        client.bootstrap(T0 + DELTA)
        _pump(c, client, client_listener, T0 + DELTA)
        _pump(c, client, client_listener, T0 + 2 * DELTA)

        self.assertTrue(client.bootstrapped(), f"state {client.state.name}")
        ts = client.trusted_state
        assert ts is not None
        self.assertEqual(len(ts.roster), 3)
        self.assertEqual(len(ts.managers), 1)
        self.assertGreater(ts.head.block_num, 0)


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

        client, client_listener = _build_light_client(c, client_kp)

        client.bootstrap(T0 + 2 * DELTA)
        _pump(c, client, client_listener, T0 + 2 * DELTA)
        _pump(c, client, client_listener, T0 + 3 * DELTA)
        self.assertTrue(client.bootstrapped())

        # Now do a read.
        rid = client.request_get(
            store_id=ops.STORE_DATA,
            name=key,
            peer=c.nodes[0].me.public,
            now=T0 + 4 * DELTA,
        )
        _pump(c, client, client_listener, T0 + 4 * DELTA)

        result = client.poll(rid)
        self.assertNotIsInstance(result, type(PENDING), "read still pending")
        self.assertIsInstance(result, GetResult, f"got {result!r}")
        assert isinstance(result, GetResult)
        self.assertFalse(result.absent)
        self.assertEqual(result.value, b"present")

    def test_byzantine_value_fails_proof_verify(self):
        """A responder signs an honest envelope (real settle_sigs, real head, real SMT
        proof for the ACTUAL live value) but swaps the value it claims. The SMT commits
        to `leaf_hash(path, h(value), h(cred))`; recomputing that with the swapped
        value produces a different terminal, and the fold to root fails.

        Load-bearing for #light-client-nonmembership: back when `serve_get_proof` shipped
        `proof: bytes = b""` and the client's `_on_read_reply` just trusted the value,
        this exact test would have passed with the swapped value -- the whole point of
        that trap was that verification WASN'T happening. If this test ever passes with
        an empty/placeholder proof pipeline, verification has been silently disabled again."""
        c = Cluster()
        key = crypto.h(b"lite-client-byz")
        tx = ops.writes(ops.Set(ops.STORE_DATA, key, b"present")).sign(c.mgr, T0)
        c.submit(c.mgr, tx, to=0, now=T0)
        c.pump(T0)
        c.pump(T0 + DELTA)

        client_kp = crypto.Keypair.generate()
        _provision_client(c, client_kp)

        client, client_listener = _build_light_client(c, client_kp)

        client.bootstrap(T0 + 2 * DELTA)
        _pump(c, client, client_listener, T0 + 2 * DELTA)
        _pump(c, client, client_listener, T0 + 3 * DELTA)
        self.assertTrue(client.bootstrapped())

        rid = client.request_get(
            store_id=ops.STORE_DATA,
            name=key,
            peer=c.nodes[0].me.public,
            now=T0 + 4 * DELTA,
        )

        # Custom pump: intercept the client's listener and swap the value on any PROOF_REPLY.
        # Everything else (bootstrap replies, sync noise) passes through untouched.
        server_kp = c.nodes[0].me
        now = T0 + 4 * DELTA
        rounds = 5

        def mutate(reply):
            return replace(reply, value=b"NOT-THE-REAL-VALUE")

        for _ in range(rounds):
            for node in c.nodes:
                node._reconcile_peers(now)
            client.tick(now)
            for node in c.nodes:
                node.postman.tick(now)
            delivered = 0
            for node in c.nodes:
                for inbound in c.listeners[node.me.public].drain():
                    node.receive(inbound.frame, now, session=inbound.session)
                    delivered += 1
            for inbound in client_listener.drain():
                mutated_frame = _mutate_frame_to_client(
                    inbound.frame, client_kp, server_kp, mutate, now
                )
                client.receive(mutated_frame, now, session=inbound.session)
                delivered += 1
            if delivered == 0:
                break

        result = client.poll(rid)
        self.assertIsInstance(result, Failed, f"got {result!r}")
        assert isinstance(result, Failed)
        self.assertEqual(result.reason, "proof-verify-failed")

    def test_stale_client_gets_refusal_and_drops_trusted_state(self):
        c = Cluster()
        client_kp = crypto.Keypair.generate()
        _provision_client(c, client_kp)

        client, client_listener = _build_light_client(c, client_kp)

        client.bootstrap(T0 + DELTA)
        _pump(c, client, client_listener, T0 + DELTA)
        _pump(c, client, client_listener, T0 + 2 * DELTA)
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
        _pump(c, client, client_listener, T0 + 20 * DELTA)

        result = client.poll(rid)
        self.assertIsInstance(result, Failed)
        assert isinstance(result, Failed)
        self.assertEqual(result.reason, "stale-client")
        # Client dropped trusted state; re-bootstrap needed.
        self.assertIs(client.state, State.UNBOOTSTRAPPED)


if __name__ == "__main__":
    unittest.main()
