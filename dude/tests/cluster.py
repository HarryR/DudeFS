# The cluster harness: three nodes and the module-scope InProc registry, no I/O at all.
#
# Shared by every end-to-end suite, which is why it lives here rather than in one of them. `now` is
# an integer the test advances, so a cluster's round is deterministic — no sockets, no threads, no
# sleeping. Partitions are simulated by `postman.remove_peer(pubkey)` (see
# #partitions-are-test-only) rather than by a switchboard-level cut/heal.
#
# EACH NODE OWNS AN InProcListener (receive side, drained by `_quiesce`), constructed here
# because a listen address is the one thing a deployment knows and an endpoint does not. The
# SEND side is not constructed here at all: per #postman-owns-dialling, Postman builds its own
# carrier on first dial, so this harness is the same shape a production main() has with TCP.

from __future__ import annotations

from ..client import Client, Keys, mint_first_keyepoch
from ..consensus.bootstrap import bootstrap
from ..core import crypto
from ..net import Verb
from ..net.address import Endpoint
from ..net.envelope import Envelope
from ..net.transports import InProcListener, address_of, name_of
from ..net.transports.inproc import _reset_for_tests
from ..node import Node
from ..store import Store, management, ops
from ..store.management import Cert, MgmtWriter, Role
from ..tunables import Tunables

D = ops.STORE_DATA
M = ops.STORE_MANAGEMENT
T0 = 1_700_000_000_000

TUNABLES = Tunables(rtt_max=30, clock_skew=25, held_convergence_max=2)
"""A fast deployment. Everything else derives from these three exactly as in production."""

DELTA = TUNABLES.block_time
CUT_RESERVE = TUNABLES.cut_reserve


class Cluster:
    """Three nodes and their listeners. Deliberately not a fixture helper with options — a cluster
    you can configure is a cluster whose test failures need debugging first."""

    def __init__(self, size: int = 3):
        # Reset the module-scope InProc registry, so a prior test's residual entries do not
        # collide with ours. (#inproc-is-a-loopback: the registry is process-wide, so tests
        # that construct clusters back-to-back share it and MUST manage their own hygiene.)
        _reset_for_tests()

        self.mgr = crypto.Keypair.generate()
        self.keys = [crypto.Keypair.generate() for _ in range(size)]
        self.nodes: list[Node] = []
        # Public dict of every node's listener, keyed by pubkey. `_quiesce` drains via
        # `listener.drain()` -- a public API, no cast, no reach into Postman internals.
        self.listeners: dict[crypto.PublicKey, InProcListener] = {}

        # Every node starts with the SAME block 1 -- a manager-signed genesis block that
        # establishes the initial roster (#manager-sig-overrides-quorum). Every node's store
        # therefore agrees byte-for-byte on the chain from block 1 onward, and a fresh joiner
        # arriving later can pull block 1 from any peer and chain-verify it against the
        # manager pubkey alone.
        self._genesis_bodies = self._genesis()
        """COMPUTED ONCE. It mints the first keyepoch, which is random, so calling it again for a
        joiner handed that joiner a different block 1 -- a chain nobody else was on, and a sync
        that could never converge."""
        genesis = self._genesis_bodies
        for kp in self.keys:
            store = Store()
            # PROVISIONED with the manager key before anything else: it is the axiom the rest of
            # the chain hangs from, and `adopt` refuses a checkpoint from a log it does not
            # authorise.
            store.provision(self.mgr.public)
            # Manager signs block 1 containing the roster grants (bootstrap runs once per node
            # at init; every node produces byte-equal block 1 because the inputs are identical).
            bootstrap(store, self.mgr, genesis, bucket=TUNABLES.bucket(T0))
            node = Node(kp, store, TUNABLES)
            # Listener registers this identity in the module-scope InProc registry so other
            # nodes' dialers can find us.
            listener = InProcListener(name_of(kp.public))
            self.listeners[kp.public] = listener
            self.nodes.append(node)
        # No explicit peer wiring here (#roster-drives-peers). Each Node's first `tick`
        # runs `_reconcile_peers`, which reads `mgmt.roster()` + `mgmt.nodes()` from the
        # store the bootstrap block already populated and calls `postman.add_peer` for
        # every other roster member. The listener is already registered, so peers can
        # reach us the moment we advertise our address.
        for node in self.nodes:
            node.tick(T0)
        self._clock: int = T0
        """Monotone. `pump(now)` treats `now` as a floor so a follow-up `pump(T0 + DELTA)`
        continues from wherever the previous pump ended, not from a time already in the past."""

    def _genesis(self) -> tuple[ops.SignedTransaction, ...]:
        # Provision the scratch store with the anchor pubkey so `verify_cert` (called by
        # `authorise` and `change_roster` at construction time) has an anchor to resolve
        # signer-authority against. The mutations composed here are applied to the real
        # per-node stores later; this scratch instance is purely a factory for the tx.
        scratch = Store()
        scratch.provision(self.mgr.public)
        mgmt = MgmtWriter(scratch)
        # Anchor-signed cert attesting the mgr identity as MANAGER (#cert). In this test
        # setup the anchor and the manager are the same key, so this is self-attesting
        # via the anchor's authority — cluster.py is not modelling a distinct manager.
        mgr_cert = Cert.sign_grant(self.mgr, self.mgr.public, Role.MANAGER)
        tx = mgmt.authorise(
            self.mgr.public,
            Role.MANAGER,
            frozenset({M, D}),
            frozenset(),
            pop=self.mgr.prove_possession(),
            cert=mgr_cert,
        )
        # The first keyepoch, composed HERE so every node's block 1 is byte-equal. Minted inside
        # `bootstrap` it was random per node, so no two nodes agreed what their round followed.
        keyepoch, _ = mint_first_keyepoch(mgmt, self.mgr)
        tx = tx + keyepoch
        # Nodes are not authors (#nodes-are-not-authors) — no P_GRANT for them. The
        # roster entries below establish them as consensus signers via P_NODE, each with
        # an anchor-signed roster #cert.
        tx = tx + mgmt.change_roster(
            commitment_signer=self.mgr,
            add=tuple(
                management.NodeRecord(
                    kp.public,
                    (Endpoint(address_of(kp.public)),),
                    Cert.sign_roster(self.mgr, kp.public),
                    frozenset(),
                )
                for kp in self.keys
            ),
        )
        return (tx.sign(self.mgr, T0),)

    def provisioned(self) -> Store:
        """A store as a JOINER really arrives: provisioned with the manager key, holding block 1.

        The anchor is the axiom of the bootstrap chain, so a store without one verifies nothing
        and `Store.adopt` refuses it a floor. Tests that hand-built a bare `Store()` relied on
        that check not existing."""
        s = Store()
        s.provision(self.mgr.public)
        bootstrap(s, self.mgr, self._genesis_bodies, bucket=TUNABLES.bucket(T0))
        return s

    @property
    def clock(self) -> int:
        """How far the cluster's own time has actually run. `pump` advances it `rounds * delta`
        per call and treats its argument as a floor, so a test that keeps its own `T0 + k*delta`
        counter drifts buckets behind the blocks it is reading -- and freshness is bucket
        arithmetic."""
        return self._clock

    def pump(self, now: int, rounds: int = 10) -> int:
        """Advance every node `rounds` times, ADVANCING TIME by δ per outer round, and
        QUIESCING dissemination at each `now` before advancing. Returns the final `now`.

        `now` is a FLOOR, not an authoritative time -- if the cluster's own clock is already
        past it, we continue from there.

        Quiescing inside each outer round is the important half: in production a SUBMIT
        re-flood chains A -> B -> C in less than δ (the SPEC bucket-width floor). A naive
        one-hop-per-iteration pump lets each hop consume a full δ, so a 2-hop chain can cross
        a bucket boundary on the far end -- the tx lands in a different bucket on C than on
        A, and neither node's Round opens with a quorum of holders. `_quiesce` lets every
        hop that fits inside one moment happen inside one moment."""
        return self.pump_without(now, away=set(), rounds=rounds)

    def pump_without(self, now: int, away: set[int], rounds: int = 10) -> int:
        """`pump`, with some nodes switched OFF -- their traffic lost, not queued (backlog is
        not what catches a node up). Ticks at a bucket's two decision points -- boundary and
        cut_by; on boundaries alone `_finalize` and `_abandon` fire in the same tick and
        nothing ratifies. `now` snapped to the next bucket boundary so the offsets land at
        those decision points regardless of `T0`'s alignment against `block_time`."""
        now = max(now, self._clock)
        remainder = now % DELTA
        if remainder:
            now += DELTA - remainder
        for _ in range(rounds):
            for offset in (0, DELTA - CUT_RESERVE):
                at = now + offset
                for i, node in enumerate(self.nodes):
                    if i not in away:
                        node.tick(at)
                self._quiesce(at, away)
            now += DELTA
        self._clock = now
        return now

    def _quiesce(self, now: int, away: set[int]) -> None:
        """Deliver until no more frames are in flight, at `now` fixed. Dissemination chains
        (SUBMIT re-flood, HELD/SIG relays) happen inside one bucket in production; the harness
        preserves that shape here.

        Frames are pulled from each node's own listener via `.drain()` -- a public API on
        the `Listener` protocol, identical to what a production main loop would call in
        the tick between `_run` iterations. A partitioned node's listener still holds any
        frames delivered before the partition — for `pump_without`, those queued frames
        stay queued and are drained normally when the node comes back."""
        for _ in range(len(self.nodes) + 1):
            for i, node in enumerate(self.nodes):
                if i not in away:
                    node.postman.tick(now)
            delivered = 0
            for i, node in enumerate(self.nodes):
                if i in away:
                    continue
                for inbound in self.listeners[node.me.public].drain():
                    node.receive(inbound.frame, now, session=inbound.session)
                    delivered += 1
            if delivered == 0:
                return

    def client(self, kp: crypto.Keypair | None = None) -> Client:
        """A data client for `kp`, default the manager, with its keys unwrapped from this
        cluster's own management rows -- which is where they live. Bootstrap seals epoch 1 to the
        anchor, so the manager is a working client from block 1 with nothing else to arrange."""
        who = self.mgr if kp is None else kp
        return Client(Keys.unwrap(self.nodes[0].store, who))

    def token(self, name: str, kp: crypto.Keypair | None = None) -> crypto.NameToken:
        """Where a name lands in the store. A test that wrote through `put` reads back through
        this -- the row is at a blinded token, not at the name."""
        return self.client(kp).token(name)

    def put(
        self,
        name: str,
        value: bytes,
        *,
        kp: crypto.Keypair | None = None,
        to: int = 0,
        now: int = T0,
    ) -> ops.SignedTransaction:
        """Write the way a client does: blind the name, seal the value under the current keyepoch,
        sign, hand to ONE node. A test about consensus or sync has no business composing an
        `ops.Set` by hand -- that is how fifty-one of them came to know what a keyepoch is."""
        who = self.mgr if kp is None else kp
        tx = self.client(who).put(name, value).sign(who, now)
        self.submit(who, tx, to=to, now=now)
        return tx

    def submit(self, client: crypto.Keypair, tx: ops.SignedTransaction, to: int, now: int) -> None:
        """A client hands a transaction to ONE node — the whole point of the protocol being that it
        needs a link to one node, not to all of them."""
        node = self.nodes[to]
        env = Envelope(node.me.public, Verb.SUBMIT, b"c" * 16, tx.raw).sign(client, now)
        node.receive(env.seal(), now)


def gaps_in_the_retained_log(store: Store) -> tuple[int, ...]:
    """Indices missing from `[1, head]` -- in the no-compaction world the log is complete from
    genesis to head, so any gap is a lost entry rather than a legitimate absence."""
    have = {e.idx for e in store.entries()}
    return tuple(i for i in range(1, store.head() + 1) if i not in have)
