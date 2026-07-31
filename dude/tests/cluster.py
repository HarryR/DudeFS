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

    def pump(self, now: int, rounds: int = 6) -> None:
        """Advance every node, then deliver everything in flight, `rounds` times.

        Delivery is explicit rather than a side effect of sending: the switchboard queues, so
        nothing recurses and the call stack never becomes the scheduler."""
        for _ in range(rounds):
            for node in self.nodes:
                node.tick(now)
            for node in self.nodes:
                for frame in self.board.drain(name_of(node.me.public)):
                    node.receive(frame, now)

    def pump_without(self, now: int, away: set[int], rounds: int = 6) -> None:
        """`pump`, with some nodes switched OFF — not ticked, and their traffic lost rather than
        queued. A node that was down did not receive what was sent to it while it was down, and
        letting the switchboard hold it would make the backlog do the catching up."""
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

    def submit(self, client: crypto.Keypair, tx: ops.SignedTransaction, to: int, now: int) -> None:
        """A client hands a transaction to ONE node — the whole point of the protocol being that it
        needs a link to one node, not to all of them."""
        node = self.nodes[to]
        env = Envelope(node.me.public, Verb.SUBMIT, b"c" * 16, tx.raw).sign(client, now)
        node.receive(seal(env), now)


def gaps_in_the_retained_log(store: Store) -> tuple[int, ...]:
    """Indices missing from `[retained_from, head]` — the part of the log that must be COMPLETE.

    "No holes" is the wrong invariant: collection deletes whole segments, so a compacted log is
    *supposed* to have gaps. What separates a legitimate gap from a lost entry is the HORIZON, the
    frontier of collection named by the one ratified marker the node retains. Below it absence is
    accounted for; at or above it every index is owed.

    This used the floor, which is the wrong quantity: the floor is the head at the moment of
    collecting, so it sits far ABOVE the indices that were actually forgotten. Collection being
    oldest-first is what makes a single frontier sufficient."""
    have = {e.idx for e in store.entries()}
    return tuple(i for i in range(store.retained_from(), store.head() + 1) if i not in have)
