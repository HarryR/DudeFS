"""End-to-end sync test, run over REAL TCP sockets.

Parallel to `test_sync_e2e.py`, which drives the same scenario over InProc. The point
here is to exercise the whole stack (Node dispatch, Postman mailbox correlation,
Follower verify-and-commit) with actual bytes on 127.0.0.1 sockets, actual length-
prefix framing, and actual OS-level connect/accept timing -- the failure modes InProc
hides by construction (synchronous drain, atomic frame delivery, no port state).

API weirdness this conversion surfaced, all named where it bites in setup below:

  1. TCP transports must be constructed BEFORE the genesis roster, because roster
     entries need each node's listen address, and the OS assigns it at bind() time.
     The InProc identity->address mapping makes this trivial (`address_of(pubkey)`);
     TCP has no such shortcut -- it's a real port, not a derived string.

  2. `Postman.attach_transport(scheme, transport)` -- new method. The `Dialler`
     contract assumes the endpoint tells the transport how to construct itself, which
     is true for InProc and false for TCP (the endpoint says where a peer listens, not
     where we listen). Callers pre-construct the TCP and attach it before any
     `add_peer` runs.

  3. Delivery is asynchronous. With InProc, `send()` puts a frame in the target's
     deque before returning, so a single drain loop catches everything in flight. With
     TCP, `send()` is `sendall()` -- bytes leave, kernel routes, receiver's socket
     eventually reads -- and `receive()` polls the selector with timeout 0. A drain
     loop that expects instant delivery will exit before frames arrive on the wire.
     The pump here sleeps briefly between drain rounds.
"""

from __future__ import annotations

import time
import unittest

from dude.consensus.bootstrap import bootstrap
from dude.consensus.settle_round import SettledBlock
from dude.core import crypto
from dude.net import Verb
from dude.net.address import Endpoint, Scheme
from dude.net.envelope import Envelope
from dude.net.transports.tcp import TCP
from dude.node import Node
from dude.store import Store, management, ops
from dude.store.management import Cert, Management, Role
from dude.tunables import DEFAULT

D = ops.STORE_DATA
M = ops.STORE_MANAGEMENT
T0 = 1_700_000_000_000
DELTA = DEFAULT.mempool.delta


def _build_cluster(size: int) -> tuple[crypto.Keypair, list[Node], list[TCP]]:
    """Build `size` nodes wired over real TCP. Returns `(manager_kp, nodes, tcps)`.

    Order matters: TCPs bind() first so their `bound_address` is known, THEN the genesis
    roster is built using those addresses, THEN nodes get the TCPs attached to their
    Postmen. Reversing any of these three steps produces a stillborn cluster --
    reconciliation reads addresses from the roster, so the addresses have to exist
    before the roster is minted."""
    mgr = crypto.Keypair.generate()
    keys = [crypto.Keypair.generate() for _ in range(size)]
    tcps = [TCP() for _ in keys]

    # Genesis roster with TCP endpoints. This is the second point of API weirdness:
    # NodeRecord.endpoints is a `tuple[Endpoint, ...]`, and Endpoint.address is where
    # this node LISTENS. For InProc that's derivable from the pubkey; for TCP we had
    # to bind() a socket to find out.
    scratch = Store()
    scratch.provision(mgr.public)
    mgmt = Management(scratch)
    mgr_cert = Cert.sign_grant(mgr, mgr.public, Role.MANAGER)
    tx = mgmt.authorise(
        mgr.public,
        Role.MANAGER,
        frozenset({M, D}),
        frozenset(),
        pop=mgr.prove_possession(),
        cert=mgr_cert,
    )
    tx = tx + mgmt.change_roster(
        commitment_signer=mgr,
        add=tuple(
            management.NodeRecord(
                kp.public,
                (Endpoint(tcps[i].bound_address),),
                Cert.sign_roster(mgr, kp.public),
                frozenset(),
            )
            for i, kp in enumerate(keys)
        ),
    )
    genesis = (tx.sign(mgr, T0),)

    nodes: list[Node] = []
    for kp, tcp in zip(keys, tcps, strict=True):
        store = Store()
        store.provision(mgr.public)
        bootstrap(store, mgr, genesis)
        node = Node(kp, store)
        # attach_transport is the load-bearing bit: without it, Node's first tick
        # would call the module-scope TCP dialler and get a fresh TCP bound to some
        # OTHER port, and the roster addresses would point nowhere reachable.
        node.postman.attach_transport(Scheme.TCP, tcp)
        nodes.append(node)

    # One tick to trigger reconciliation (each node dials every other roster member).
    for node in nodes:
        node.tick(T0)

    return mgr, nodes, tcps


def _pump_all(
    nodes: list[Node],
    tcps: dict[crypto.PublicKey, TCP],
    now: int,
    rounds: int = 30,
) -> None:
    """Drive tick + drain across every node until nothing's moved for a round.

    Sleeps between drain rounds because TCP delivery is asynchronous. On loopback the
    round-trip is well under 1 ms, but even a single-digit-microsecond gap between
    `sendall()` returning and the receiving socket becoming readable is enough for
    `selector.select(timeout=0)` to see nothing. Without the sleep the pump exits early
    and the tests flake."""
    for _ in range(rounds):
        for node in nodes:
            node.tick(now)
        delivered = 0
        # A few micro-drain iterations per tick to catch chained request/reply.
        for _ in range(10):
            for node in nodes:
                node.postman.tick(now)
            time.sleep(0.002)
            round_delivered = 0
            for node in nodes:
                for frame in tcps[node.me.public].receive():
                    node.receive(frame, now)
                    round_delivered += 1
            delivered += round_delivered
            if round_delivered == 0:
                break


def _submit(node: Node, tx: ops.SignedTransaction, client: crypto.Keypair, now: int) -> None:
    """Hand a signed transaction to `node` via SUBMIT -- same shape as `Cluster.submit`."""
    env = Envelope(node.me.public, Verb.SUBMIT, b"c" * 16, tx.raw).sign(client, now)
    node.receive(env.seal(), now)


def _produce_blocks(
    nodes: list[Node], tcps: dict[crypto.PublicKey, TCP], mgr: crypto.Keypair, want: int
) -> int:
    """Submit transactions and pump until every node holds at least `want` blocks.
    Returns the final `now`."""
    now = T0
    submissions = 0
    while any((n.store.head_block_num() or 0) < want for n in nodes):
        key = crypto.h(f"tcp-e2e-{submissions}".encode())
        tx = ops.writes(ops.Set(D, key, b"v")).sign(mgr, now)
        _submit(nodes[0], tx, mgr, now)
        _pump_all(nodes, tcps, now)
        submissions += 1
        now += DELTA
        if submissions > 30:
            raise AssertionError(f"cluster failed to produce {want} blocks")
    return now


class TestJoinerCatchesUpOverTCP(unittest.TestCase):
    def test_joiner_catches_up_via_the_wire(self):
        mgr, nodes, tcps_list = _build_cluster(3)
        tcps = {n.me.public: t for n, t in zip(nodes, tcps_list, strict=True)}

        try:
            _produce_blocks(nodes, tcps, mgr, 3)
            producer_head = nodes[0].store.head_block_num()
            assert producer_head is not None and producer_head >= 3

            joiner_kp = crypto.Keypair.generate()
            joiner_store = Store()
            joiner_store.provision(mgr.public)
            joiner_tcp = TCP()
            joiner = Node(joiner_kp, joiner_store)
            joiner.postman.attach_transport(Scheme.TCP, joiner_tcp)

            # Bootstrap-outside-roster wiring, same shape as the InProc test but with
            # TCP endpoints instead of address_of(pubkey). The joiner needs to know
            # node[0]'s listen address; node[0] needs to know the joiner's.
            joiner.postman.add_peer(nodes[0].me.public, (Endpoint(tcps_list[0].bound_address),))
            joiner.follower.add_peer(nodes[0].me.public, now=0)
            nodes[0].postman.add_peer(joiner_kp.public, (Endpoint(joiner_tcp.bound_address),))

            all_nodes = [*nodes, joiner]
            all_tcps = {**tcps, joiner_kp.public: joiner_tcp}

            now = T0 + DELTA * 10
            for _ in range(20):
                _pump_all(all_nodes, all_tcps, now)
                if (joiner_store.head_block_num() or 0) >= producer_head:
                    break
                now += DELTA

            joiner_head = joiner_store.head_block_num() or 0
            self.assertGreaterEqual(
                joiner_head,
                producer_head,
                f"joiner did not catch up over TCP: joiner={joiner_head} producer={producer_head}",
            )
            overlap = min(joiner_head, nodes[0].store.head_block_num() or 0)
            self.assertGreater(overlap, 0, "no overlap between joiner and node 0 heads")
            for n in range(1, overlap + 1):
                j_bytes = joiner_store.settled_at(n)
                p_bytes = nodes[0].store.settled_at(n)
                assert j_bytes is not None and p_bytes is not None
                self.assertEqual(
                    SettledBlock.decode(j_bytes).block_hash,
                    SettledBlock.decode(p_bytes).block_hash,
                    f"chain diverged at block_num={n}",
                )
            self.assertEqual(
                set(joiner_store.mgmt.roster()),
                set(nodes[0].store.mgmt.roster()),
            )

            joiner_tcp.close()
        finally:
            for tcp in tcps_list:
                tcp.close()


if __name__ == "__main__":
    unittest.main()
