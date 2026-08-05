# The cluster harness: three nodes, one switchboard, and no I/O at all.
#
# Shared by every end-to-end suite, which is why it lives here rather than in one of them. `now` is
# an integer the test advances, so a cluster's round is deterministic and a partition is a value —
# no sockets, no threads, no sleeping.

from __future__ import annotations

from ..consensus.bootstrap import bootstrap
from ..core import crypto
from ..net import Verb
from ..net.envelope import Envelope
from ..net.transports import InProc, Switchboard, address_of, name_of
from ..node import Node
from ..store import Store, management, ops
from ..store.management import Cert, Management, Role
from ..tunables import DEFAULT

D = ops.STORE_DATA
M = ops.STORE_MANAGEMENT
T0 = 1_700_000_000_000
DELTA = DEFAULT.mempool.delta


class Cluster:
    """Three nodes and a switchboard. Deliberately not a fixture helper with options — a cluster you
    can configure is a cluster whose test failures need debugging first."""

    def __init__(self, size: int = 3):
        self.board = Switchboard()
        self.mgr = crypto.Keypair.generate()
        self.keys = [crypto.Keypair.generate() for _ in range(size)]
        self.nodes: list[Node] = []

        # Every node starts with the SAME block 1 -- a manager-signed genesis block that
        # establishes the initial roster (#manager-sig-overrides-quorum). Every node's store
        # therefore agrees byte-for-byte on the chain from block 1 onward, and a fresh joiner
        # arriving later can pull block 1 from any peer and chain-verify it against the
        # manager pubkey alone.
        genesis = self._genesis()
        for kp in self.keys:
            store = Store()
            # PROVISIONED with the manager key before anything else: it is the axiom the rest of
            # the chain hangs from, and `adopt` refuses a checkpoint from a log it does not
            # authorise.
            store.provision(self.mgr.public)
            # Manager signs block 1 containing the roster grants (bootstrap runs once per node
            # at init; every node produces byte-equal block 1 because the inputs are identical).
            bootstrap(store, self.mgr, genesis)
            node = Node(kp, store)
            self.board.bind(name_of(kp.public))
            self.nodes.append(node)
        for node in self.nodes:
            for other in self.keys:
                if other.public != node.me.public:
                    node.connect(other.public, InProc(name_of(node.me.public), self.board))
        self._clock: int = T0
        """The cluster's own monotone clock. `pump(now)` treats its `now` argument as a floor:
        if a test calls `pump(T0)` then `pump(T0 + DELTA)`, the second pump continues from
        wherever the first left off rather than trying to run at a time already in the past.
        This lets the old test pattern -- fixed timestamps spaced by DELTA -- work with the new
        pump, which advances time internally so Round has room to finalize."""

    def _genesis(self) -> tuple[ops.SignedTransaction, ...]:
        # Provision the scratch store with the anchor pubkey so `verify_cert` (called by
        # `authorise` and `change_roster` at construction time) has an anchor to resolve
        # signer-authority against. The mutations composed here are applied to the real
        # per-node stores later; this scratch instance is purely a factory for the tx.
        scratch = Store()
        scratch.provision(self.mgr.public)
        mgmt = Management(scratch)
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
        # Nodes are not authors (#nodes-are-not-authors) — no P_GRANT for them. The
        # roster entries below establish them as consensus signers via P_NODE, each with
        # an anchor-signed roster #cert.
        tx = tx + mgmt.change_roster(
            add=tuple(
                management.NodeRecord(
                    kp.public,
                    (address_of(kp.public).encode(),),
                    Cert.sign_roster(self.mgr, kp.public),
                    frozenset(),
                )
                for kp in self.keys
            )
        )
        return (tx.sign(self.mgr, T0),)

    def provisioned(self) -> Store:
        """A store as a JOINER really arrives: provisioned with the manager key, holding block 1.

        The anchor is the axiom of the bootstrap chain, so a store without one verifies nothing
        and `Store.adopt` refuses it a floor. Tests that hand-built a bare `Store()` relied on
        that check not existing."""
        s = Store()
        s.provision(self.mgr.public)
        bootstrap(s, self.mgr, self._genesis())
        return s

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
        now = max(now, self._clock)
        for _ in range(rounds):
            for node in self.nodes:
                node.tick(now)
            self._quiesce(now, away=set())
            now += DELTA
        self._clock = now
        return now

    def pump_without(self, now: int, away: set[int], rounds: int = 10) -> int:
        """`pump`, with some nodes switched OFF — not ticked, and their traffic lost rather than
        queued. A node that was down did not receive what was sent to it while it was down, and
        letting the switchboard hold it would make the backlog do the catching up."""
        now = max(now, self._clock)
        for _ in range(rounds):
            for i, node in enumerate(self.nodes):
                if i not in away:
                    node.tick(now)
            self._quiesce(now, away)
            now += DELTA
        self._clock = now
        return now

    def _quiesce(self, now: int, away: set[int]) -> None:
        """Deliver until no more frames are in flight, at `now` fixed. Dissemination chains
        (SUBMIT re-flood, HELD/SIG relays) happen inside one bucket in production; the harness
        preserves that shape here."""
        for _ in range(len(self.nodes) + 1):
            for i, node in enumerate(self.nodes):
                if i not in away:
                    node.postman.tick(now)
            delivered = 0
            for i, node in enumerate(self.nodes):
                frames = self.board.drain(name_of(node.me.public))
                if i in away:
                    continue
                for frame in frames:
                    node.receive(frame, now)
                    delivered += 1
            if delivered == 0:
                return

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
