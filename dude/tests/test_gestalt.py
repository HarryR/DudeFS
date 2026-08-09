# The gestalt: every layer, joined, in one process.
#
# Each part below has its own tests and passes them in isolation. THIS file exists to answer the
# different question — whether isolation was the right decomposition — by making a transaction go
# the whole way: client -> envelope -> seal -> transport -> postman -> mempool -> propose ->
# quorum -> settle -> log, on three nodes at once.
#
# The harness is `cluster.py`; the subjects that grew their own suites are `test_sync.py`,
# `test_collection.py` and `test_angel.py`.

from __future__ import annotations

import time
import unittest
from collections.abc import Callable
from dataclasses import replace

from ..consensus.bootstrap import bootstrap
from ..core import codec, crypto
from ..core.errors import DudeError, InvariantError
from ..core.units import now_ms
from ..net import Verb
from ..net.address import Endpoint
from ..net.envelope import Envelope, Frame
from ..net.postman import Postman
from ..net.transports.tcp import TCPDialer, TCPListener
from ..node import (
    _DISPATCH,
    HANDLED,
    REPLIES,
    Node,
)
from ..store import Store, management, ops
from ..store.management import Cert, MgmtWriter, NodeRecord, Role
from ..store.store import StoreError
from ..sync.lite_client import LightClient
from ..tunables import SyncTunables, Tunables
from .cluster import DELTA, T0, TUNABLES, Cluster, D


class TestGestalt(unittest.TestCase):
    def setUp(self):
        self.c = Cluster()
        self.client = self.c.mgr  # the manager is already authorised to write the data store

    def test_one_transaction_reaches_every_log(self):
        """The whole system, end to end. Submitted to node 0 only; settled on all three."""
        key = crypto.h(b"hello")
        tx = ops.writes(ops.Set(D, key, b"world")).sign(self.client, T0)

        self.c.submit(self.client, tx, to=0, now=T0)
        self.c.pump(T0)  # disseminate within the bucket
        self.c.pump(T0 + DELTA)  # the bucket closes: propose, endorse, settle

        for i, node in enumerate(self.c.nodes):
            got = node.store.get(D, key)
            assert got is not None, f"node {i} did not settle it"
            self.assertEqual(got.value, b"world", f"node {i} settled the wrong value")

    def test_every_node_settles_the_same_log(self):
        """Not merely "all have the value" — the same operations at the same indices, which is what
        the accumulator is for. Two nodes agreeing on a value while disagreeing on history is the
        failure this catches and a value check does not."""
        for n in range(3):
            tx = ops.writes(ops.Set(D, crypto.h(f"k{n}".encode()), f"v{n}".encode())).sign(
                self.client, T0 + n
            )
            self.c.submit(self.client, tx, to=n, now=T0)
        self.c.pump(T0)
        self.c.pump(T0 + DELTA)

        accs = {node.store.accumulator() for node in self.c.nodes}
        heads = {node.store.head() for node in self.c.nodes}
        self.assertEqual(len(accs), 1, "nodes disagree on state")
        self.assertEqual(len(heads), 1, "nodes disagree on log length")

    def test_a_partitioned_node_still_settles_through_the_others(self):
        """Node 2 cannot hear node 0 directly. It must still learn the transaction, because the
        client needs a link to ONE node and the rest is the cluster's problem.

        The partition is modelled by removing each side from the OTHER's `postman.peers` --
        symmetric partition, per #partitions-are-test-only. That IS what a partition looks
        like to the protocol: the sender has no live route to the target."""
        a_pk = self.c.keys[0].public
        c_pk = self.c.keys[2].public
        self.c.nodes[0].postman.peers.pop(c_pk, None)
        self.c.nodes[2].postman.peers.pop(a_pk, None)

        key = crypto.h(b"partitioned")
        tx = ops.writes(ops.Set(D, key, b"relayed")).sign(self.client, T0)
        self.c.submit(self.client, tx, to=0, now=T0)
        self.c.pump(T0)
        self.c.pump(T0 + DELTA)

        got = self.c.nodes[2].store.get(D, key)
        self.assertIsNotNone(got, "the partitioned node never learned it")

    def test_an_unauthorised_client_is_refused_everywhere(self):
        """Authority is log state, so a stranger is refused by every node without any of them
        conferring about it."""
        stranger = crypto.Keypair.generate()
        key = crypto.h(b"nope")
        tx = ops.writes(ops.Set(D, key, b"x")).sign(stranger, T0)
        self.c.submit(stranger, tx, to=0, now=T0)
        self.c.pump(T0)
        self.c.pump(T0 + DELTA)

        for i, node in enumerate(self.c.nodes):
            self.assertIsNone(node.store.get(D, key), f"node {i} settled an unauthorised write")

    def test_garbage_costs_a_frame_and_nothing_else(self):
        """The crash-only boundary: hostile bytes are an expected outcome at a decode boundary, so
        a peer sending rubbish loses its frame while the node keeps serving."""
        node = self.c.nodes[0]
        junk = Frame(crypto.screen_tag(node.me.public, b"junk"), crypto.SealedBlob(b"junk"))
        node.receive(junk, T0)  # must not raise

        key = crypto.h(b"after-junk")
        tx = ops.writes(ops.Set(D, key, b"still-alive")).sign(self.client, T0)
        self.c.submit(self.client, tx, to=0, now=T0)
        self.c.pump(T0)
        self.c.pump(T0 + DELTA)
        self.assertIsNotNone(node.store.get(D, key), "the node stopped working after junk")

    def test_a_garbage_body_costs_a_frame_too_not_the_process(self):
        """The frame-level test above passed while this one would have killed the node, because the
        catch only covered `deliver` and a handler's first act is to DECODE a peer-supplied body.

        A STRANGER -- no grant, no roster seat, signature proving only *who* -- sends `SUBMIT` with
        twelve bytes of non-bencode. With `crashonly` installed, the escaping `CodecError` is
        `os._exit`: the unauthenticated remote kill switch that crashonly.py names as the one thing
        its typed-parsing precondition exists to prevent."""
        node = self.c.nodes[0]
        stranger = crypto.Keypair.generate()
        for body in (b"\xff\x00not-bencode", codec.encode([1, 2, 3])):  # bad tag, then bad arity
            env = Envelope(node.me.public, Verb.SUBMIT, b"c" * 16, body).sign(stranger, T0)
            node.receive(env.seal(), T0)  # must not raise

        key = crypto.h(b"after-garbage-body")
        tx = ops.writes(ops.Set(D, key, b"still-alive")).sign(self.client, T0)
        self.c.submit(self.client, tx, to=0, now=T0)
        self.c.pump(T0)
        self.c.pump(T0 + DELTA)
        self.assertIsNotNone(node.store.get(D, key), "the node stopped working after a bad body")

    def test_our_error_is_structurally_not_their_error(self):
        """The boundary catches `DudeError` and nothing else, so the ONLY thing keeping our own
        broken invariants from being swallowed as "hostile input" is that they are not in that tree.

        Pinned as a type relationship rather than trusted as a convention `[H]`: if someone makes
        `InvariantError` a `DudeError` for convenience, every `except DudeError` in the codebase
        silently becomes a place where "our fold is wrong" is discarded — which is the failure the
        two-tree split exists to make unconstructible (core/errors.py)."""
        self.assertTrue(issubclass(StoreError, DudeError))
        self.assertFalse(
            issubclass(InvariantError, DudeError), "our error became catchable as theirs"
        )


class TestBucketDrift(unittest.TestCase):
    """The bucket a Round runs for MUST be `floor(now/delta)`, so two nodes derive the same one
    for the same instant. It was a counter incremented once per opened Round: a node that missed
    six buckets opened its next Round six behind its peers, who dropped its HELD/SIG as "no
    matching Round", and it fell further behind on every cycle -- while its Follower kept its
    store current, so it looked healthy from every angle."""

    def test_nodes_that_sat_out_buckets_rejoin_the_quorum(self):
        # n=4 so quorum is 3: with two nodes away the remaining two CANNOT settle, so no head
        # moves while 2 and 3 are out and nothing has to be synced afterwards. What is left
        # under test is purely which bucket each node comes back on.
        c = Cluster(size=4)
        now = c.pump(T0, rounds=4)

        stalled = c.nodes[0].store.head_block_num() or 0
        now = c.pump_without(now, away={2, 3}, rounds=6)
        self.assertEqual(
            [n.store.head_block_num() or 0 for n in c.nodes],
            [stalled] * 4,
            "no quorum was available, so no block should have settled",
        )

        now = c.pump(now, rounds=6)
        self.assertGreater(
            c.nodes[0].store.head_block_num() or 0,
            stalled,
            "nodes 2 and 3 came back on a stale bucket, so no three nodes shared a Round",
        )
        self.assertEqual(
            len({n.store.head_block_hash() for n in c.nodes}),
            1,
            "the cluster settled but did not converge on one chain",
        )


class TestSubmitDoesNotCascade(unittest.TestCase):
    """A client's SUBMIT goes to the nodes the client chooses and stops there. Re-flooding it to
    the roster, and re-flooding again on receipt, is ~100 transmissions of every transaction on an
    11-node cluster. Phase 2 moves each body once, to the nodes that lack it."""

    def setUp(self):
        self.c = Cluster()

    def test_no_node_rebroadcasts_a_submission(self):
        tx = ops.writes(ops.Set(D, crypto.h(b"no-cascade"), b"v")).sign(self.c.mgr, T0)
        self.c.submit(self.c.mgr, tx, to=0, now=T0)

        queued = [
            p.envelope.env.verb
            for node in self.c.nodes
            for p in node.postman.mailbox.pending.values()
            if p.envelope is not None
        ]
        self.assertNotIn(Verb.SUBMIT, queued, "a node re-flooded the submission")

    def test_it_still_reaches_every_log_by_being_gossiped(self):
        key = crypto.h(b"gossiped")
        tx = ops.writes(ops.Set(D, key, b"v")).sign(self.c.mgr, T0)
        self.c.submit(self.c.mgr, tx, to=0, now=T0)
        self.c.pump(T0)
        self.c.pump(T0 + DELTA)

        for i, node in enumerate(self.c.nodes):
            got = node.store.get(D, key)
            assert got is not None, f"node {i} never got it -- phase 2 did not carry it"
            self.assertEqual(got.value, b"v")


class TestVerbCoverage(unittest.TestCase):
    """What the node does and does not answer, pinned.

    A test rather than a comment because the interesting property is that the set does not drift:
    add a `Verb` and it belongs to one of the two buckets or this fails, instead of falling
    through a default branch and being discovered when a peer sends it."""

    def test_every_verb_is_either_handled_or_a_reply(self):
        """TWO buckets, no third. A bucket for not-done-yet is where dead verbs and
        fully-working ones both go to stop being asked about."""
        self.assertEqual(HANDLED | REPLIES, frozenset(Verb))
        self.assertFalse(HANDLED & REPLIES)

    def test_every_handled_verb_has_a_handler(self):
        """Derived, not listed: `_DISPATCH` is built from `HANDLED`, so a verb claimed as handled
        with no `_on_<verb>` fails at import rather than falling into a silent default."""
        self.assertEqual(set(_DISPATCH), HANDLED)

    def test_a_verb_we_do_not_know_is_refused_at_decode(self):
        """A number outside the enum is refused by `Envelope.decode` and costs its frame."""
        node, other = self.c.nodes[0], self.c.nodes[1]
        body = codec.encode([node.me.public, 20, b"z" * 16, b"", b"", 0])  # 20: not in the enum
        signed = codec.encode([other.me.public, T0, body])
        raw = codec.encode([signed, other.me.sign(signed)])
        node.receive(Frame(crypto.screen_tag(node.me.public, raw), node.me.public.seal(raw)), T0)

        key = crypto.h(b"after-unknown-verb")
        tx = ops.writes(ops.Set(D, key, b"fine")).sign(self.client, T0)
        self.c.submit(self.client, tx, to=0, now=T0)
        self.c.pump(T0)
        self.c.pump(T0 + DELTA)
        self.assertIsNotNone(node.store.get(D, key))

    def setUp(self):
        self.c = Cluster()
        self.client = self.c.mgr


# --------------------------------------------------------------------------------------------- #
# The scenario: everything, running at once, on real threads and real sockets.                  #
# --------------------------------------------------------------------------------------------- #


# Tightened timing for the scenario: default rtt_max=300ms + skew=250ms puts the delta
# floor at 850ms, which makes a multi-phase test take tens of seconds. Loopback RTT is
# microseconds, so a much tighter rtt/skew is honest here. The invariants
# (`Tunables.__post_init__`) still verify at construction, so nothing is skipped -- just
# faster ceremonies.
_FAST = replace(TUNABLES, sync=SyncTunables(poll_interval=500))


def _genesis(
    mgr: crypto.Keypair,
    keys: list[crypto.Keypair],
    listeners: list[TCPListener],
) -> tuple[ops.SignedTransaction, ...]:
    """Mint the genesis tx that authorises `mgr` as MANAGER + establishes the initial
    roster. Same shape as `Cluster._genesis`, but the roster addresses come from
    `listeners[i].bound_address` because we're on real TCP."""
    scratch = Store()
    scratch.provision(mgr.public)
    mgmt = MgmtWriter(scratch)
    mgr_cert = Cert.sign_grant(mgr, mgr.public, Role.MANAGER)
    tx = mgmt.authorise(
        mgr.public,
        Role.MANAGER,
        frozenset({ops.STORE_MANAGEMENT, ops.STORE_DATA}),
        frozenset(),
        pop=mgr.prove_possession(),
        cert=mgr_cert,
    )
    tx = tx + mgmt.change_roster(
        commitment_signer=mgr,
        add=tuple(
            management.NodeRecord(
                kp.public,
                (Endpoint(listeners[i].bound_address),),
                Cert.sign_roster(mgr, kp.public),
                frozenset(),
            )
            for i, kp in enumerate(keys)
        ),
    )
    return (tx.sign(mgr, T0),)


def _build_node(
    kp: crypto.Keypair,
    mgr: crypto.Keypair,
    genesis: tuple[ops.SignedTransaction, ...],
    tunables: Tunables,
) -> Node:
    """Build a Node on the given genesis. The listener is constructed and passed
    separately by the caller (needed before genesis for its bound_address); the dial
    side is the Postman's own (#postman-owns-dialling)."""
    store = Store()
    store.provision(mgr.public)
    bootstrap(store, mgr, genesis, bucket=_FAST.mempool.bucket(T0))
    return Node(kp, store, tunables=tunables)


def _wait_until(pred, timeout_sec: float, interval_sec: float = 0.02) -> bool:
    """Poll `pred()` until truthy or timeout. Used for "eventually" assertions when real
    threads are driving progress."""
    deadline = time.monotonic() + timeout_sec
    while time.monotonic() < deadline:
        if pred():
            return True
        time.sleep(interval_sec)
    return pred()


def _submit_and_wait(  # noqa: PLR0913, PLR0917 -- one helper with all the parameters is more readable than shuffling them into a params object
    client: TCPDialer,
    nodes: list[Node],
    to: int,
    tx: ops.SignedTransaction,
    sender: crypto.Keypair,
    observed: Callable[[], bool],
    *,
    delta_ms: int,
    max_bucket_attempts: int = 40,
) -> bool:
    """Submit `tx` to `nodes[to]` and RETRY every bucket until `observed()` is true or
    `max_bucket_attempts` runs out. Returns whether the observation happened.

    In production a client tracking the SUBMIT via mailbox reissues on timeout; in tests
    we do the same explicitly. Idempotent by op_hash so multiple landings all dedup to
    one mempool entry, and the retry is a cheap defensive backstop for any transient
    wire hiccup the scenario cannot rehearse -- the actual reason a single submit reliably
    settles now is `Coordinator.on_round_msg` / `on_settle_msg` invoking `Coordinator.tick(now)`
    before dispatch, so a peer's HELD/SIG arriving before our scheduled tick finds consensus
    state already advanced to `now`."""
    target = nodes[to]
    rec = target.mgmt.nodes()[target.me.public]
    import contextlib  # noqa: PLC0415 -- local; only used here

    for _ in range(max_bucket_attempts):
        env = Envelope(target.me.public, Verb.SUBMIT, crypto.random_bytes(16), tx.raw).sign(
            sender, now_ms()
        )
        # Best-effort send: transient TCP hiccups are recovered by the next retry.
        # The `observed` predicate is authoritative.
        with contextlib.suppress(Exception):
            client.send(rec.endpoints[0].address, env.seal())
        # One bucket between resubmissions -- next Round has a chance to pick it up.
        time.sleep(delta_ms / 1000)
        if observed():
            return True
    return observed()


class TestScenario(unittest.TestCase):
    """One long scenario, on real threads with real sockets, exercising every subsystem in
    combination. Each phase names what it proves; a failure in phase N tells you which
    interaction broke rather than which unit did.

    Runs against tightened `_FAST` tunables (delta=100 ms) so the whole thing finishes in
    a few seconds. Everything above still runs against its own invariants -- nothing is
    skipped for speed."""

    def test_the_whole_product(self):  # noqa: C901, PLR0912 -- scenario is intentionally sequential
        mgr = crypto.Keypair.generate()
        keys = [crypto.Keypair.generate() for _ in range(3)]
        listeners = [TCPListener() for _ in keys]

        genesis = _genesis(mgr, keys, listeners)

        nodes = [_build_node(kp, mgr, genesis, _FAST) for kp in keys]

        # Test's own outbound client, used for external SUBMITs. The ONE carrier this
        # test constructs for sending: it is playing an external party at the raw
        # transport level, below any Postman.
        test_client = TCPDialer()

        # LightClient built later; keep names in scope so the finally block can stop them.
        lc: LightClient | None = None

        # Fourth-node placeholders for phase 4/5.
        n4: Node | None = None
        n4_listener: TCPListener | None = None

        try:
            # --- PHASE 0: managed-mode start; every node produces empty blocks -------- #
            # `start` takes the listener (accepts inbound) and starts the Postman, which
            # starts the dial side. The dialer is a Listener too from Wave 2 -- its
            # reader-thread feeds the inbox with `Inbound(frame, session)` just like the
            # listener does. Without it, outbound sockets never get their replies read
            # and consensus stalls; that is exactly why starting it cannot be something
            # a caller has to remember (#postman-owns-dialling).
            for node, listener in zip(nodes, listeners, strict=True):
                node.start(listener)
            # Every node should get past block 1 within a few buckets (Coordinator ticks
            # each bucket boundary; empty rounds ratify on quorum trivially at n=3).
            budget = 5 * (_FAST.mempool.delta / 1000)
            self.assertTrue(
                _wait_until(
                    lambda: all((n.store.head_block_num() or 0) >= 2 for n in nodes),
                    timeout_sec=budget,
                ),
                f"phase 0: heads did not advance past 1 in {budget}s: "
                f"{[n.store.head_block_num() for n in nodes]}",
            )

            # --- PHASE 1: external client SUBMITs a tx; it settles on every node ------ #
            key = crypto.h(b"scenario/phase-1")
            tx = ops.writes(ops.Set(D, key, b"phase-one-value")).sign(mgr, now_ms())
            self.assertTrue(
                _submit_and_wait(
                    test_client,
                    nodes,
                    0,
                    tx,
                    mgr,
                    observed=lambda: all(n.store.get(D, key) is not None for n in nodes),
                    delta_ms=_FAST.mempool.delta,
                ),
                "phase 1: tx did not settle on every node",
            )
            for i, n in enumerate(nodes):
                held = n.store.get(D, key)
                assert held is not None
                self.assertEqual(
                    held.value, b"phase-one-value", f"phase 1: wrong value on node {i}"
                )

            # --- PHASE 2: a LightClient bootstraps + reads via TCP -------------------- #
            # Provision the client as CLIENT via a manager-signed authorise, submitted
            # through the wire like any other tx. The endpoint carried in the P_GRANT
            # row is what nodes will reconcile into their postmans on tick.
            lc_kp = crypto.Keypair.generate()
            # Snapshot-scoped tx composition: MgmtWriter's reads are pinned to a
            # consistent moment so the composed cert can't reference a mid-flight
            # writer commit (that's Bug A -- MgmtWriter's docstring names it). No cast:
            # a StoreReader IS a `management.Source`.
            with nodes[0].store.snapshot() as r:
                grant_tx = (
                    MgmtWriter(r)
                    .authorise(
                        lc_kp.public,
                        Role.CLIENT_RW,
                        stores=frozenset({ops.STORE_DATA}),  # scoped: reads are refused outside it
                        pop=lc_kp.prove_possession(),
                        cert=Cert.sign_grant(mgr, lc_kp.public, Role.CLIENT_RW),
                    )
                    .sign(mgr, now_ms())
                )
            self.assertTrue(
                _submit_and_wait(
                    test_client,
                    nodes,
                    0,
                    grant_tx,
                    mgr,
                    observed=lambda: all(n.mgmt.grant_of(lc_kp.public) is not None for n in nodes),
                    delta_ms=_FAST.mempool.delta,
                ),
                "phase 2: CLIENT grant did not settle on every node",
            )
            # No wait-for-reconcile: nodes don't dial back to clients anymore. The client
            # dials nodes and replies flow back on the sessions it opened (SessionLink);
            # a node learns about a client only when the client's first frame arrives on
            # a session it accepted, at which point Postman.register_session runs.
            lc = LightClient(me=lc_kp, anchor=mgr.public, postman=Postman(lc_kp), tunables=_FAST)
            for i, listener in enumerate(listeners):
                lc.add_bootstrap_peer(nodes[i].me.public, (Endpoint(listener.bound_address),))
            # NO LISTENER AT ALL, and this is the point of the shape: a light client never
            # binds an address. `start()` with no arguments starts its Postman, whose
            # dialer reads every reply back on the socket the client itself opened, per
            # #session-first-reply. Before #postman-owns-dialling this line needed a
            # carrier the test had constructed and passed twice.
            lc.start()
            lc.bootstrap(now_ms())
            self.assertTrue(
                _wait_until(lc.bootstrapped, timeout_sec=2.0),
                "phase 2: LightClient did not reach READY",
            )
            # NOTE: `lc.request_get` uses `trusted_state.head[0]` as `block_num`. In a
            # LIVE cluster with real-time empty blocks firing every δ, the trusted head
            # goes stale within one bucket -- `serve_get_proof` then returns TOO_OLD
            # because it only serves at `head_num` (the live SMT). The read path is
            # covered by `test_lite_client.test_get_proof_returns_head_value` on a
            # static cluster. A `LightClient.refresh_head()` (or auto-refresh via a
            # scheduled GET_ANCHORS on tick) would close this gap; that's future work
            # the scenario just surfaced. Here we assert only that bootstrap wired the
            # client end-to-end.

            # --- PHASE 3: add a 4th node via the real change_roster path -------------- #
            n4_kp = crypto.Keypair.generate()
            n4_listener = TCPListener()
            assert n4_listener is not None  # type-narrow for the composition below
            # Snapshot-scoped composition, same reason as phase 2's grant tx.
            with nodes[0].store.snapshot() as r:
                add_tx = (
                    MgmtWriter(r)
                    .change_roster(
                        commitment_signer=mgr,
                        add=(
                            NodeRecord(
                                n4_kp.public,
                                (Endpoint(n4_listener.bound_address),),
                                Cert.sign_roster(mgr, n4_kp.public),
                                frozenset(),
                            ),
                        ),
                    )
                    .sign(mgr, now_ms())
                )
            ok_phase3 = _submit_and_wait(
                test_client,
                nodes,
                0,
                add_tx,
                mgr,
                observed=lambda: all(n4_kp.public in n.mgmt.roster() for n in nodes),
                delta_ms=_FAST.mempool.delta,
            )
            if not ok_phase3:
                # Small diagnostic: the two smoking guns for consensus stalls in this
                # scenario are (a) `add_in_pool` differing across nodes (dissemination
                # gap) and (b) `peers_reporting=0` while `round_local_has_add=True`
                # (HELDs are silently dropped -- the bug fixed by "tick before every
                # frame" in `Node._run`). Keep both fields when adding assertions.
                diag_lines = ["phase 3: change_roster(add) did not settle on every existing node"]
                for i, n in enumerate(nodes):
                    coord = n.coordinator
                    r = coord.current_round
                    in_pool = any(add_tx.op_hash in b for b in coord.mempool.pending.values())
                    r_local = (
                        r is not None
                        and r._local_bodies is not None
                        and add_tx.op_hash in r._local_bodies
                    )
                    r_peers = len(r._peer_holds) if r else 0
                    diag_lines.append(
                        f"  node{i}: head={n.store.head_block_num()} "
                        f"round_bucket={r.bucket() if r else None} "
                        f"n4_in_roster={n4_kp.public in n.mgmt.roster()} "
                        f"add_in_pool={in_pool} round_local_has_add={r_local} "
                        f"peers_reporting={r_peers}"
                    )
                raise AssertionError("\n".join(diag_lines))
            # Bring node 4 up: it needs its store bootstrapped with the SAME genesis
            # as the others so it can chain-verify from block 1.
            n4_store = Store()
            n4_store.provision(mgr.public)
            bootstrap(n4_store, mgr, genesis, bucket=_FAST.mempool.bucket(T0))
            n4 = Node(n4_kp, n4_store, tunables=_FAST)
            # Manual bootstrap peer wiring (joiner not yet in its own roster's postman;
            # reconciliation will do the rest on tick). This `add_peer` is what builds
            # n4's dialer -- BEFORE `start`, which is the ordering `Postman.start` has to
            # cope with (it starts carriers already built as well as later ones).
            n4.postman.add_peer(nodes[0].me.public, (Endpoint(listeners[0].bound_address),))
            n4.follower.add_peer(nodes[0].me.public, now=now_ms())
            n4.start(n4_listener)
            # Catch up: joiner's head reaches the existing cluster's head.
            self.assertTrue(
                _wait_until(
                    lambda: (
                        (n4_store.head_block_num() or 0) >= (nodes[0].store.head_block_num() or 0)
                    ),
                    timeout_sec=20 * (_FAST.mempool.delta / 1000),
                ),
                f"phase 3: joiner did not catch up (n4={n4_store.head_block_num()} "
                f"vs cluster={nodes[0].store.head_block_num()})",
            )

            # --- PHASE 4: clean shutdown of everything -------------------------------- #
            # (Removing n4 via change_roster + verifying partition/heal both deserve
            # their own focused tests. Under managed threading with n=4 the round
            # cadence gets sensitive to individual peer latency in a way that inline
            # scenario timing is a poor place to reason about.)
            if lc is not None:
                start = time.monotonic()
                lc.stop(timeout=2.0)
                self.assertLess(time.monotonic() - start, 2.0, "phase 4: lc.stop took too long")
            if n4 is not None:
                start = time.monotonic()
                n4.stop(timeout=2.0)
                self.assertLess(time.monotonic() - start, 2.0, "phase 4: n4.stop took too long")
            for i, node in enumerate(nodes):
                start = time.monotonic()
                node.stop(timeout=2.0)
                self.assertLess(
                    time.monotonic() - start, 2.0, f"phase 4: node[{i}].stop took too long"
                )
        finally:
            # Best-effort cleanup so a mid-scenario failure doesn't leak sockets/threads.
            # Suppress every exception -- we're already unwinding, and none of these can
            # escalate to anything the test surfaces.
            import contextlib  # noqa: PLC0415 -- local; only used here

            if lc is not None:
                with contextlib.suppress(Exception):
                    lc.stop(timeout=1.0)
            if n4 is not None:
                with contextlib.suppress(Exception):
                    n4.stop(timeout=1.0)
            if n4_listener is not None:
                n4_listener.stop()
            for node in nodes:
                with contextlib.suppress(Exception):
                    node.stop(timeout=1.0)
            for lst in listeners:
                lst.stop()
            test_client.close()


if __name__ == "__main__":
    unittest.main()
