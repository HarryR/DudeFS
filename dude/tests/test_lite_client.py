# End-to-end: LightClient through the InProc stack against a real Cluster.
#
# Bootstrap (RT1 + f+1 corroboration) + steady-state GET_PROOF, all wire-real. The
# module-scope InProc registry does the routing; both sides are real Postmen with real
# mailboxes; the light client's state machine drives the whole thing.

from __future__ import annotations

import unittest
from dataclasses import replace
from unittest import mock

from dude.consensus.bootstrap import intervene
from dude.consensus.settle_round import SettledBlock
from dude.core import codec, crypto
from dude.core.errors import DudeError
from dude.net.address import Address, Endpoint, Scheme
from dude.net.envelope import Envelope, Frame, SignedEnvelope, Verb
from dude.net.postman import Postman
from dude.net.transports import InProcListener, address_of, name_of
from dude.store import ops
from dude.store.management import Cert, Grant, MgmtWriter, NodeRecord, Role
from dude.sync import chain
from dude.sync.lite_adapter import LiteMsg, RosterBundle
from dude.sync.lite_client import PENDING, Failed, GetResult, LightClient, State

from .cluster import DELTA, T0, TUNABLES, Cluster


def _build_light_client(c: Cluster, kp: crypto.Keypair) -> tuple[LightClient, InProcListener]:
    """Same shape as production: construct the listener explicitly (a bind address is the
    deployment's to know), let Postman build its own send-side carrier, register bootstrap
    peers. Returns both so the test pump can drain the listener via `.drain()`."""
    listener = InProcListener(name_of(kp.public))
    postman = Postman(kp)
    client = LightClient(me=kp, anchor=c.mgr.public, postman=postman, tunables=TUNABLES)
    for node in c.nodes:
        client.add_bootstrap_peer(node.me.public, (Endpoint(address_of(node.me.public)),))
    return client, listener


def _one_bucket_after_head(c: Cluster) -> int:
    """A wall-clock reading consistent with the last block the cluster actually settled."""
    head_num = c.nodes[0].store.head_block_num()
    assert head_num is not None
    raw = c.nodes[0].store.settled_at(head_num)
    assert raw is not None
    head_bucket = SettledBlock.decode(raw).block.bucket
    return TUNABLES.mempool.bucket_start(head_bucket + 1)


def _provision_client(c: Cluster, kp: crypto.Keypair) -> None:
    """Grant Role.CLIENT_RW via intervene on every store, with the client's InProc endpoint
    baked into the P_GRANT row so nodes can dial back via `_reconcile_peers`
    (#roster-drives-peers)."""
    mgmt = MgmtWriter(c.nodes[0].store)
    grant_tx = mgmt.authorise(
        kp.public,
        Role.CLIENT_RW,
        stores=frozenset({ops.STORE_DATA}),  # scoped: reads are refused outside it
        pop=kp.prove_possession(),
        cert=Cert.sign_grant(c.mgr, kp.public, Role.CLIENT_RW),
    ).sign(c.mgr, T0)
    for node in c.nodes:
        intervene(node.store, c.mgr, bodies=(grant_tx,), bucket=TUNABLES.mempool.bucket(c.clock))


def _mutate_frame_to_client(  # noqa: PLR0913, PLR0917 -- a byzantine-responder harness needs both identities, the verb it targets, the swap, and the clock; bundling any of them hides what the attack changes
    frame: Frame,
    client_kp: crypto.Keypair,
    server_kp: crypto.Keypair,
    target: Verb,
    mutate,
    now: int,
) -> Frame:
    """Unseal a frame addressed to `client_kp`, decode the envelope; if the verb is
    `target`, apply `mutate(msg) -> LiteMsg` to the decoded message and re-emit the frame
    with a fresh envelope signed by `server_kp` and re-sealed to the client. Frames of any
    other verb pass through unchanged.

    Used to simulate a byzantine responder: the envelope signature and the frame's sealed
    structure are honest (a real server signed it), but the payload inside has been swapped
    for something the client's own verification must reject. Verb-generic because both
    halves of what a light client verifies -- the SMT proof on a `PROOF_REPLY` and the
    quorum proof on an `ANCHORS_REPLY` head -- need attacking, and only the first one was."""
    raw = client_kp.open_sealed_raw(frame.sealed)
    signed = SignedEnvelope.decode(raw)
    if signed.env.verb is not target:
        return frame
    verb, body = mutate(LiteMsg.decode(signed.env.verb, signed.env.body)).encode()
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

        # Build the LightClient. `_build_light_client` constructs the InProcListener
        # explicitly; the send side is Postman's own (#postman-owns-dialling) -- same
        # shape as production. The reverse direction (nodes dialling this client) is
        # set up by each node's `_reconcile_peers` on tick, using the endpoints baked
        # into the P_GRANT row.
        client, client_listener = _build_light_client(c, client_kp)

        # Kick off bootstrap.
        client.bootstrap(c.clock + DELTA)
        _pump(c, client, client_listener, c.clock + DELTA)
        _pump(c, client, client_listener, c.clock + DELTA)

        self.assertTrue(client.bootstrapped(), f"state {client.state.name}")
        ts = client.trusted_state
        assert ts is not None
        self.assertEqual(len(ts.roster), 3)
        self.assertEqual(len(ts.managers), 1)
        self.assertGreater(ts.head.block_num, 0)

    def test_forged_quorum_proof_does_not_reach_ready(self):
        """The head's quorum proof is checked, and the client refuses on failure.

        THE HALF THIS FILE NEVER ATTACKED. `test_byzantine_value_fails_proof_verify` forges
        the VALUE and leans on the SMT fold, explicitly leaving the settle sigs honest -- so
        the client's authorisation check had happy-path coverage only. It was a second
        implementation of `MgmtWriter.authorises`' rule, and gutting it to `return True`
        would not have failed a single test. `Authorization` is now the one implementation;
        this is what holds it.

        The bundle is untouched and verifies, the envelope is honestly signed by a real
        node, the roster is the real roster -- only the signatures over
        `(slice_hash, anchors)` are replaced with well-formed garbage. A bitmap of the same
        width and a sig list of the same length, so nothing short-circuits on shape: the
        refusal has to come from verifying the signatures themselves."""
        c = Cluster()
        client_kp = crypto.Keypair.generate()
        _provision_client(c, client_kp)
        client, client_listener = _build_light_client(c, client_kp)

        def forge(msg):
            head = msg.head
            return replace(
                msg,
                head=SettledBlock(
                    block=head.block,
                    anchors=head.anchors,
                    multisig=crypto.MultiSig(
                        head.multisig.bitmap,
                        tuple(crypto.Signature(bytes(64)) for _ in head.multisig.sigs),
                    ),
                ),
            )

        client.bootstrap(c.clock + DELTA)
        for now in (c.clock + DELTA, c.clock + DELTA):
            for _ in range(5):
                for node in c.nodes:
                    node._reconcile_peers(now)
                client.tick(now)
                for node in c.nodes:
                    node.postman.tick(now)
                for node in c.nodes:
                    for inbound in c.listeners[node.me.public].drain():
                        node.receive(inbound.frame, now, session=inbound.session)
                for inbound in client_listener.drain():
                    client.receive(
                        _mutate_frame_to_client(
                            inbound.frame,
                            client_kp,
                            c.nodes[0].me,
                            Verb.ANCHORS_REPLY,
                            forge,
                            now,
                        ),
                        now,
                        session=inbound.session,
                    )

        self.assertFalse(client.bootstrapped(), "forged quorum proof was accepted")
        self.assertIsNone(client.trusted_state)


class TestLightClientRead(unittest.TestCase):
    def test_get_proof_returns_head_value(self):
        c = Cluster()
        # Land a value.
        key = crypto.h(b"lite-client-e2e")
        tx = ops.writes(ops.Set(ops.STORE_DATA, key, b"present")).sign(c.mgr, T0)
        c.submit(c.mgr, tx, to=0, now=T0)
        c.pump(T0)
        c.pump(c.clock + DELTA)

        client_kp = crypto.Keypair.generate()
        _provision_client(c, client_kp)

        client, client_listener = _build_light_client(c, client_kp)

        client.bootstrap(c.clock + DELTA)
        _pump(c, client, client_listener, c.clock + DELTA)
        _pump(c, client, client_listener, c.clock + DELTA)
        self.assertTrue(client.bootstrapped())

        # Now do a read.
        rid = client.request_get(
            store_id=ops.STORE_DATA,
            name=key,
            peer=c.nodes[0].me.public,
            now=c.clock + DELTA,
        )
        _pump(c, client, client_listener, c.clock + DELTA)

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
        c.pump(c.clock + DELTA)

        client_kp = crypto.Keypair.generate()
        _provision_client(c, client_kp)

        client, client_listener = _build_light_client(c, client_kp)

        client.bootstrap(c.clock + DELTA)
        _pump(c, client, client_listener, c.clock + DELTA)
        _pump(c, client, client_listener, c.clock + DELTA)
        self.assertTrue(client.bootstrapped())

        rid = client.request_get(
            store_id=ops.STORE_DATA,
            name=key,
            peer=c.nodes[0].me.public,
            now=c.clock + DELTA,
        )

        # Custom pump: intercept the client's listener and swap the value on any PROOF_REPLY.
        # Everything else (bootstrap replies, sync noise) passes through untouched.
        server_kp = c.nodes[0].me
        now = c.clock + DELTA
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
                    inbound.frame, client_kp, server_kp, Verb.PROOF_REPLY, mutate, now
                )
                client.receive(mutated_frame, now, session=inbound.session)
                delivered += 1
            if delivered == 0:
                break

        result = client.poll(rid)
        self.assertIsInstance(result, Failed, f"got {result!r}")
        assert isinstance(result, Failed)
        self.assertEqual(result.reason, "proof-verify-failed")

    def test_a_far_behind_client_walks_up_instead_of_being_refused(self):
        """The server used to refuse a lagging client -- STALE_CLIENT, then TOO_OLD after that
        one went -- and tell it to re-bootstrap. Both refusals were emitted ABOVE the line that
        builds the headers, so the client had no way to stop lagging; against a live cluster,
        whose head moves every bucket, a light client could not complete a read at all.

        It now gets answered at the responder's head with the headers to reach it, capped per
        reply, and walks up over as many round trips as the gap needs."""
        c = Cluster()
        key = crypto.h(b"lite-client-catchup")
        tx = ops.writes(ops.Set(ops.STORE_DATA, key, b"present")).sign(c.mgr, T0)
        c.submit(c.mgr, tx, to=0, now=T0)
        c.pump(T0)

        client_kp = crypto.Keypair.generate()
        _provision_client(c, client_kp)
        client, client_listener = _build_light_client(c, client_kp)

        client.bootstrap(c.clock + DELTA)
        _pump(c, client, client_listener, c.clock + DELTA)
        _pump(c, client, client_listener, c.clock + DELTA)
        self.assertTrue(client.bootstrapped())

        # Floor above the client's last `_pump`: `receive` advances a node's round, so the
        # cluster's own `clock` trails the nodes and pumping from it ticks time backwards.
        c.pump(c.clock + 2 * DELTA)  # the cluster runs on; the client falls behind
        assert client.trusted_state is not None
        started_at = client.trusted_state.head.block_num
        head_num = c.nodes[0].store.head_block_num() or 0
        self.assertGreater(head_num - started_at, TUNABLES.light_client.liveness_window)

        heads = [started_at]
        result = None
        for _ in range(30):
            # The clock the CLUSTER is on, not one the test invented: a `now` that runs past the
            # last block produced makes the head legitimately stale, which is a different failure
            # wearing this test's name.
            now = _one_bucket_after_head(c)
            rid = client.request_get(
                store_id=ops.STORE_DATA, name=key, peer=c.nodes[0].me.public, now=now
            )
            _pump(c, client, client_listener, now)
            result = client.poll(rid)
            assert client.trusted_state is not None
            heads.append(client.trusted_state.head.block_num)
            if not isinstance(result, Failed):
                break
            self.assertEqual(
                result.reason,
                "behind the responder; retry",
                f"heads={heads} server={c.nodes[0].store.head_block_num()} "
                f"head_bucket={client.trusted_state.head.bucket} "
                f"now_bucket={TUNABLES.mempool.bucket(now)}",
            )
            self.assertIs(client.state, State.READY, "a lagging client must not lose its roster")

        self.assertEqual(heads, sorted(heads), f"the head went backwards: {heads}")
        self.assertGreater(heads[1], heads[0], "one reply advanced the client by nothing")
        self.assertIsInstance(result, GetResult, f"never caught up: heads={heads}")
        assert isinstance(result, GetResult)
        self.assertEqual(result.value, b"present")


class TestRevokedManagerCannotForgeARoster(unittest.TestCase):
    """A manager that WAS authorised and has since been revoked must not be able to hand a
    light client a roster of its own choosing.

    WHY THIS IS NOT COVERED BY THE CERT CHAIN. A #cert carries no serial: "the row is either
    present (attestation valid) or absent (revoked)". Currency for a cert therefore comes only
    from observing its grant ROW in the log — the one thing a light client does not have. So a
    revoked manager's anchor-signed grant cert verifies forever on the client side, and the
    bundle is the single artefact in a light client's diet whose validity is not self-evident
    from its own signatures. Blocks are fine (settle_sigs are a quorum multi-sig, chain-linked);
    values are fine (SMT proof under signed anchors); both survive an arbitrary relay. The
    bundle does not.

    AND STEADY STATE HAS NO CORROBORATION. Bootstrap is covered by `f+1` agreement on
    `roster_fingerprint`, so a forged roster there needs `f+1` colluding peers. But
    `_on_read_reply` adopts a fresh bundle from ONE responder, and a responder may attach one
    whenever it likes. #absence-is-revocation names the intended defence — "the state root's
    non-inclusion proof over the grant path is the client's evidence" — and the client never
    asks for one.

    Asserts the CORRECT behaviour: the client's trusted roster is unchanged. It fails today."""

    def test_forged_bundle_from_a_revoked_manager_is_not_adopted(self):
        c = Cluster()
        client_kp = crypto.Keypair.generate()
        _provision_client(c, client_kp)

        # A warm manager is granted, then revoked -- BEFORE the client bootstraps, so the
        # client is at the responders' head when it reads. (A lagging client's GET_PROOF is
        # refused TOO_OLD, since the no-compaction SMT only exists at head; that refusal made
        # a first draft of this test pass without the forged bundle ever being delivered.)
        # The grant cert stays a genuine anchor-signed artefact; only the ROW is gone, which
        # is precisely what a light client cannot observe.
        warm = crypto.Keypair.generate()
        warm_cert = Cert.sign_grant(c.mgr, warm.public, Role.MANAGER)
        for node in c.nodes:
            mgmt = MgmtWriter(node.store)
            grant = mgmt.authorise(
                warm.public, Role.MANAGER, pop=warm.prove_possession(), cert=warm_cert
            )
            at = TUNABLES.mempool.bucket(c.clock)
            intervene(node.store, c.mgr, bodies=(grant.sign(c.mgr, T0),), bucket=at)
            revoke = mgmt.revoke(warm.public, reissue_signer=c.mgr)
            intervene(node.store, c.mgr, bodies=(revoke.sign(c.mgr, T0),), bucket=at + 1)
            self.assertIsNone(MgmtWriter(node.store).grant_of(warm.public), "revocation failed")

        client, client_listener = _build_light_client(c, client_kp)

        # Bootstrap honestly: f+1 corroboration on the real roster.
        client.bootstrap(c.clock + DELTA)
        _pump(c, client, client_listener, c.clock + DELTA)
        _pump(c, client, client_listener, c.clock + DELTA)
        self.assertTrue(client.bootstrapped())
        ts = client.trusted_state
        assert ts is not None
        honest_roster = ts.roster

        # The revoked manager forges an entire roster of keys it controls.
        attacker_nodes = [crypto.Keypair.generate() for _ in range(3)]
        entries = tuple(
            NodeRecord(
                kp.public,
                (Endpoint(Address(Scheme.INPROC, f"attacker{i}")),),
                Cert.sign_roster(warm, kp.public),
                frozenset(),
            )
            for i, kp in enumerate(attacker_nodes)
        )
        members = tuple(sorted(kp.public for kp in attacker_nodes))
        state_fingerprint = crypto.h(
            codec.encode(
                [
                    [
                        bytes(r.identity),
                        sorted(ep.encode() for ep in r.endpoints),
                        sorted(r.domains),
                    ]
                    for r in sorted(entries, key=lambda r: bytes(r.identity))
                ]
            )
        )
        content = codec.encode([99, sorted(bytes(m) for m in members), state_fingerprint])
        forged = RosterBundle(
            commitment_serial=99,
            commitment_members=members,
            commitment_cert=Cert.sign_roster_commitment(warm, content),
            entries=entries,
            managers=(Grant(warm.public, Role.MANAGER, frozenset(), frozenset(), warm_cert),),
        )

        # Steady state: one responder attaches the forged bundle to an ordinary read reply.
        rid = client.request_get(
            store_id=ops.STORE_DATA,
            name=crypto.h(b"anything"),
            peer=c.nodes[0].me.public,
            now=c.clock + DELTA,
        )
        self.assertIsNotNone(rid)

        def swap(msg):
            return replace(
                msg, bundle=forged, roster_fingerprint=crypto.Digest(forged.commitment_cert.subject)
            )

        now = c.clock + DELTA
        for _ in range(5):
            for node in c.nodes:
                node._reconcile_peers(now)
            client.tick(now)
            for node in c.nodes:
                node.postman.tick(now)
            for node in c.nodes:
                for inbound in c.listeners[node.me.public].drain():
                    node.receive(inbound.frame, now, session=inbound.session)
            for inbound in client_listener.drain():
                client.receive(
                    _mutate_frame_to_client(
                        inbound.frame, client_kp, c.nodes[0].me, Verb.PROOF_REPLY, swap, now
                    ),
                    now,
                    session=inbound.session,
                )

        # The contract: the forged roster is never adopted. A moved fingerprint means this
        # client's cached trust no longer holds, so it drops that trust and re-bootstraps --
        # which is where `f+1` corroboration lives. It does NOT take a replacement roster
        # from whoever happened to answer.
        after = client.trusted_state
        attacker_roster = tuple(sorted(kp.public for kp in attacker_nodes))
        if after is not None:
            self.assertNotEqual(after.roster, attacker_roster, "forged roster was adopted")
            self.assertEqual(after.roster, honest_roster, "trusted roster changed")
        self.assertIsNone(after, "client kept trusting a roster it can no longer verify")
        self.assertIs(client.state, State.UNBOOTSTRAPPED)
        self.assertEqual(client.poll(rid), Failed(reason="roster changed; re-bootstrap"))


class TestAByzantineResponderCannotKillTheClient(unittest.TestCase):
    """A responder is not trusted, so nothing it sends may raise past the frame boundary. A
    multisig bitmap of the wrong width for the roster was enough: `MultiSig.verify` raised
    `CryptoError` out of `Authorization.verify`, `chain.advance`, `_advance_head` and
    `_on_read_reply`, and `_run` catches only `queue.Empty` -- the thread died while the listener
    kept accepting into an inbox nobody drained, so the client looked alive and every read hung
    for ever. `SettledBlock.decode` wraps whatever bitmap bytes arrive, so it comes off the wire."""

    def test_a_wrong_width_signer_bitmap_fails_the_read_and_nothing_else(self):
        c = Cluster()
        key = crypto.h(b"byz-bitmap")
        tx = ops.writes(ops.Set(ops.STORE_DATA, key, b"present")).sign(c.mgr, T0)
        c.submit(c.mgr, tx, to=0, now=T0)
        c.pump(T0)

        client_kp = crypto.Keypair.generate()
        _provision_client(c, client_kp)
        client, client_listener = _build_light_client(c, client_kp)
        client.bootstrap(c.clock + DELTA)
        _pump(c, client, client_listener, c.clock + DELTA)
        _pump(c, client, client_listener, c.clock + DELTA)
        self.assertTrue(client.bootstrapped())

        # ONE block on, so the reply carries the responder's head as a link we must WALK. At our
        # own head `_advance_head` returns early and never checks the head's multisig at all --
        # correctly, since the proof is verified against the root we already walked to -- and the
        # mutation below is then a no-op. Written without this the test passed 1 run in 3.
        c.pump(c.clock + 2 * DELTA, rounds=1)
        assert client.trusted_state is not None
        gap = (c.nodes[0].store.head_block_num() or 0) - client.trusted_state.head.block_num
        self.assertTrue(
            0 < gap <= TUNABLES.light_client.liveness_window,
            f"gap is {gap}: at 0 the head is not walked, past the cap it is not offered",
        )

        now = _one_bucket_after_head(c)
        rid = client.request_get(
            store_id=ops.STORE_DATA, name=key, peer=c.nodes[0].me.public, now=now
        )

        def widen(reply):
            head = reply.head
            wrecked = replace(
                head, multisig=replace(head.multisig, bitmap=crypto.SignerBitmap(bytes(5)))
            )
            return replace(reply, head=wrecked)

        server_kp = c.nodes[0].me
        for _ in range(5):
            for node in c.nodes:
                node._reconcile_peers(now)
            client.tick(now)
            for node in c.nodes:
                node.postman.tick(now)
            for node in c.nodes:
                for inbound in c.listeners[node.me.public].drain():
                    node.receive(inbound.frame, now, session=inbound.session)
            for inbound in client_listener.drain():
                client.receive(  # must not raise
                    _mutate_frame_to_client(
                        inbound.frame, client_kp, server_kp, Verb.PROOF_REPLY, widen, now
                    ),
                    now,
                    session=inbound.session,
                )

        result = client.poll(rid)
        self.assertIsInstance(result, Failed, f"got {result!r}")
        assert isinstance(result, Failed)
        self.assertIn(
            "verify failed",
            result.reason,
            "the read failed for some other reason; this proves nothing about the bitmap",
        )
        self.assertIs(client.state, State.READY, "one bad reply tore down the trusted state")
        self.assertIsNotNone(client.trusted_state)

    def test_any_dude_error_from_a_reply_resolves_the_read_instead_of_unwinding(self):
        """The BOUNDARY, not the bitmap. With the primitive refusing rather than raising, the
        test above no longer reaches this guard -- and a boundary that only holds for the failures
        we have already fixed is not a boundary. A read left PENDING is as bad as a dead thread,
        because nothing times a pending read out."""
        c = Cluster()
        client_kp = crypto.Keypair.generate()
        _provision_client(c, client_kp)
        client, client_listener = _build_light_client(c, client_kp)
        client.bootstrap(c.clock + DELTA)
        _pump(c, client, client_listener, c.clock + DELTA)
        _pump(c, client, client_listener, c.clock + DELTA)
        self.assertTrue(client.bootstrapped())

        # The cluster runs on, so the reply carries headers and `_advance_head` actually walks --
        # at our own head it returns early and `chain.advance` is never reached.
        c.pump(c.clock + 2 * DELTA)
        now = _one_bucket_after_head(c)
        rid = client.request_get(
            store_id=ops.STORE_DATA, name=b"anything", peer=c.nodes[0].me.public, now=now
        )
        with mock.patch.object(chain, "advance", side_effect=DudeError("header check exploded")):
            _pump(c, client, client_listener, now)

        result = client.poll(rid)
        self.assertIsInstance(result, Failed, f"read left unresolved: {result!r}")
        assert isinstance(result, Failed)
        self.assertIn("header check exploded", result.reason)
        self.assertIs(client.state, State.READY)


if __name__ == "__main__":
    unittest.main()
