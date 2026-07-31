# The cluster harness: three nodes, one switchboard, and no I/O at all.
#
# Shared by every end-to-end suite, which is why it lives here rather than in one of them. `now` is
# an integer the test advances, so a cluster's round is deterministic and a partition is a value —
# no sockets, no threads, no sleeping.

from __future__ import annotations

from ..core import crypto
from ..net import Verb
from ..net.envelope import Envelope, seal
from ..net.transports import InProc, Switchboard, address_of, name_of
from ..node import Node
from ..store import Store, ops
from ..store.management import Management, Role
from ..tunables import DEFAULT

WINDOW = DEFAULT.attest.fresh_within

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

        # One genesis log, replayed into each node's store, so every node starts from the SAME
        # roster and the same manager grant — membership is log state, not configuration.
        genesis = self._genesis()
        for kp in self.keys:
            store = Store()
            # PROVISIONED with the manager key before anything else: it is the axiom the rest of the
            # chain hangs from, and `adopt` refuses a checkpoint from a log it does not authorise.
            store.provision(self.mgr.public)
            # The manager's own grant has to precede the authority that checks it.
            store.apply(genesis, auth=None)
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
        mgmt = Management(Store())
        tx = mgmt.authorise(
            self.mgr.public,
            Role.MANAGER,
            frozenset({M, D}),
            frozenset(),
            self.mgr.prove_possession(),
        )
        for kp in self.keys:
            tx = tx + mgmt.authorise(
                kp.public, Role.NODE, frozenset({D}), frozenset(), kp.prove_possession()
            )
            tx = tx + mgmt.add_node(kp.public, (address_of(kp.public).encode(),))
        # STEP 7: membership is stated ONCE, in the same transaction that creates the rows. A
        # `node/` row set with no commitment cannot be checked for completeness, so a verifier
        # refuses the log -- `#roster-change-is-atomic` is why both land together or neither does.
        tx = tx + mgmt.set_roster([kp.public for kp in self.keys], serial=1)
        return (tx.sign(self.mgr, T0),)

    def provisioned(self) -> Store:
        """A store as a JOINER really arrives: provisioned with the manager key, holding genesis.

        The anchor is the axiom of the bootstrap chain, so a store without one verifies nothing and
        `Store.adopt` refuses it a floor. Tests that hand-built a bare `Store()` relied on that
        check not existing."""
        s = Store()
        s.provision(self.mgr.public)
        s.apply(self._genesis(), auth=None)
        return s

    def pump(self, now: int, rounds: int = 10) -> int:
        """Advance every node, then deliver everything in flight, `rounds` times, ADVANCING TIME
        by δ per iteration. Returns the final `now`.

        `now` is a FLOOR, not an authoritative time -- if the cluster's own clock is already past
        it, we continue from there. Round's `close_by` needs actual time to pass for finalize to
        trigger, and old tests wrote fixed `pump(T0); pump(T0 + DELTA)` sequences that assumed
        time-standing-still-within-a-pump. Treating `now` as a floor lets those patterns keep
        working while giving Round the room it needs."""
        now = max(now, self._clock)
        for _ in range(rounds):
            for node in self.nodes:
                node.tick(now)
            for node in self.nodes:
                for frame in self.board.drain(name_of(node.me.public)):
                    node.receive(frame, now)
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
            for i, node in enumerate(self.nodes):
                frames = self.board.drain(name_of(node.me.public))
                if i in away:
                    continue
                for frame in frames:
                    node.receive(frame, now)
            now += DELTA
        self._clock = now
        return now

    def submit(self, client: crypto.Keypair, tx: ops.SignedTransaction, to: int, now: int) -> None:
        """A client hands a transaction to ONE node — the whole point of the protocol being that it
        needs a link to one node, not to all of them."""
        node = self.nodes[to]
        env = Envelope(node.me.public, Verb.SUBMIT, b"c" * 16, tx.raw).sign(client, now)
        node.receive(seal(env), now)


def gaps_in_the_retained_log(store: Store) -> tuple[int, ...]:
    """Indices missing from `[1, head]` -- in the no-compaction world the log is complete from
    genesis to head, so any gap is a lost entry rather than a legitimate absence."""
    have = {e.idx for e in store.entries()}
    return tuple(i for i in range(1, store.head() + 1) if i not in have)
