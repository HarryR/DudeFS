"""End-to-end sync test, run over REAL TCP sockets.

Parallel to `test_sync_e2e.py`, which drives the same scenario over InProc. The point
here is to exercise the whole stack (Node dispatch, Postman mailbox correlation,
Follower verify-and-commit) with actual bytes on 127.0.0.1 sockets, actual length-
prefix framing, and actual OS-level connect/accept timing -- the failure modes InProc
hides by construction (synchronous drain, atomic frame delivery, no port state).

CLIENT/LISTENER SPLIT: every node owns a `TCPDialer` (built by its own Postman for
send, and drained by the test pump for the replies that come back on it) and a
`TCPListener` (built HERE, and drained by the pump for receive). Only the listener is
the test's to construct: its `bound_address` is what peers dial, and it's known ONLY
after bind, which is why listeners get built before the genesis roster.
"""

from __future__ import annotations

import time
import unittest

from dude.consensus.bootstrap import bootstrap
from dude.consensus.settle_round import SettledBlock
from dude.core import crypto
from dude.net import Verb
from dude.net.address import Endpoint
from dude.net.envelope import Envelope
from dude.net.transports.tcp import TCPListener
from dude.node import Node
from dude.store import Store, management, ops
from dude.store.management import Cert, MgmtWriter, Role
from dude.tunables import DEFAULT

D = ops.STORE_DATA
M = ops.STORE_MANAGEMENT
T0 = 1_700_000_000_000
DELTA = DEFAULT.mempool.delta


def _build_cluster(
    size: int,
) -> tuple[crypto.Keypair, list[Node], list[TCPListener]]:
    """Build `size` nodes wired over real TCP. Returns `(manager_kp, nodes, listeners)`.

    Order matters: LISTENERS bind first so their `bound_address` is known, THEN the
    genesis roster is minted with those addresses. Reversing the two produces a
    stillborn cluster -- reconciliation reads addresses from the roster, so the
    addresses have to exist before the roster is minted. The dial side has no ordering
    constraint at all, because nothing outside the Postman ever holds it."""
    mgr = crypto.Keypair.generate()
    keys = [crypto.Keypair.generate() for _ in range(size)]
    listeners = [TCPListener() for _ in keys]  # bind first

    # Genesis roster with TCP endpoints -- each node's listener.bound_address.
    scratch = Store()
    scratch.provision(mgr.public)
    mgmt = MgmtWriter(scratch)
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
                (Endpoint(listeners[i].bound_address),),
                Cert.sign_roster(mgr, kp.public),
                frozenset(),
            )
            for i, kp in enumerate(keys)
        ),
    )
    genesis = (tx.sign(mgr, T0),)

    nodes: list[Node] = []
    for kp in keys:
        store = Store()
        store.provision(mgr.public)
        bootstrap(store, mgr, genesis, bucket=DEFAULT.mempool.bucket(T0))
        nodes.append(Node(kp, store))

    # One tick to trigger reconciliation (each node dials every other roster member).
    # This is also what builds each Postman's TCPDialer -- no `node.start()` call, since
    # this is the deterministic path, so nothing is reading a thread; `postman.drain()`
    # is what the pump uses instead.
    for node in nodes:
        node.tick(T0)

    return mgr, nodes, listeners


def _pump_all(
    nodes: list[Node],
    listeners: dict[crypto.PublicKey, TCPListener],
    now: int,
    rounds: int = 30,
) -> None:
    """Drive tick + drain across every node until nothing's moved for a round.

    Sleeps between drain rounds because TCP delivery is asynchronous. On loopback the
    round-trip is well under 1 ms, but even a single-digit-microsecond gap between
    `sendall()` returning and the receiving socket becoming readable is enough for
    `selector.select(timeout=0)` to see nothing. Without the sleep the pump exits early
    and the tests flake.

    Wave 2: `TCPDialer` reads replies on its outbound sockets (session-Link path). The
    deterministic pump drains BOTH the listener (accept-side sessions) AND the node's
    own Postman (dial-side sessions) so no reply is stranded in an un-read socket
    buffer. `postman.drain()` is the dial-side twin of `listener.drain()` -- the test
    never sees a carrier object, only the two doors."""
    for _ in range(rounds):
        for node in nodes:
            node.tick(now)
        # A few micro-drain iterations per tick to catch chained request/reply.
        for _ in range(10):
            for node in nodes:
                node.postman.tick(now)
            time.sleep(0.002)
            round_delivered = 0
            for node in nodes:
                inbounds = (*listeners[node.me.public].drain(), *node.postman.drain())
                for inbound in inbounds:
                    node.receive(inbound.frame, now, session=inbound.session)
                    round_delivered += 1
            if round_delivered == 0:
                break


def _submit(node: Node, tx: ops.SignedTransaction, client: crypto.Keypair, now: int) -> None:
    """Hand a signed transaction to `node` via SUBMIT -- same shape as `Cluster.submit`."""
    env = Envelope(node.me.public, Verb.SUBMIT, b"c" * 16, tx.raw).sign(client, now)
    node.receive(env.seal(), now)


def _produce_blocks(
    nodes: list[Node],
    listeners: dict[crypto.PublicKey, TCPListener],
    mgr: crypto.Keypair,
    want: int,
) -> int:
    """Submit transactions and pump until every node holds at least `want` blocks.
    Returns the final `now`."""
    now = T0
    submissions = 0
    while any((n.store.head_block_num() or 0) < want for n in nodes):
        key = crypto.h(f"tcp-e2e-{submissions}".encode())
        tx = ops.writes(ops.Set(D, key, b"v")).sign(mgr, now)
        _submit(nodes[0], tx, mgr, now)
        # Twice per bucket, as a real node ticks: a Round's HELD wave and the SIG wave that
        # answers it both belong to its own bucket (see `Cluster.pump_without`).
        _pump_all(nodes, listeners, now)
        _pump_all(nodes, listeners, now + DELTA // 2)
        submissions += 1
        now += DELTA
        if submissions > 30:
            raise AssertionError(f"cluster failed to produce {want} blocks")
    return now


class TestJoinerCatchesUpOverTCP(unittest.TestCase):
    def test_joiner_catches_up_via_the_wire(self):
        mgr, nodes, listener_list = _build_cluster(3)
        listeners = {n.me.public: t for n, t in zip(nodes, listener_list, strict=True)}

        try:
            _produce_blocks(nodes, listeners, mgr, 3)
            producer_head = nodes[0].store.head_block_num()
            assert producer_head is not None and producer_head >= 3

            joiner_kp = crypto.Keypair.generate()
            joiner_store = Store()
            joiner_store.provision(mgr.public)
            joiner_listener = TCPListener()
            joiner = Node(joiner_kp, joiner_store)

            # Bootstrap-outside-roster wiring: the joiner isn't in the roster yet, so
            # reconciliation won't wire it. Manual bootstrap peer both directions.
            joiner.postman.add_peer(nodes[0].me.public, (Endpoint(listener_list[0].bound_address),))
            joiner.follower.add_peer(nodes[0].me.public, now=0)
            nodes[0].postman.add_peer(joiner_kp.public, (Endpoint(joiner_listener.bound_address),))

            all_nodes = [*nodes, joiner]
            all_listeners = {**listeners, joiner_kp.public: joiner_listener}

            now = T0 + DELTA * 10
            for _ in range(20):
                _pump_all(all_nodes, all_listeners, now)
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

            joiner.postman.stop()
            joiner_listener.stop()
        finally:
            for n in nodes:
                n.postman.stop()
            for lst in listener_list:
                lst.stop()


if __name__ == "__main__":
    unittest.main()
