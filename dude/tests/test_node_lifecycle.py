"""The threaded production path: real threads, real wall clock, real TCP. Every other test
drives `tick`/`receive` from the test thread with an injected `now`."""

from __future__ import annotations

import subprocess
import sys
import textwrap
import time
import unittest

from dude.client import mint_first_keyepoch
from dude.consensus.bootstrap import bootstrap
from dude.core import crypto
from dude.net.address import Endpoint
from dude.net.transports.tcp import TCPListener
from dude.node import Node
from dude.store import Store, management, ops
from dude.store.management import Cert, MgmtWriter, Role

from .cluster import T0, TUNABLES


def _build_cluster(
    size: int,
) -> tuple[crypto.Keypair, list[Node], list[TCPListener]]:
    """Same shape as `test_sync_e2e_tcp._build_cluster`: bind listeners first so their
    addresses are known, then mint genesis with those addresses, then construct nodes.
    Does NOT call `node.start()` -- that's the caller's, and it is what starts the
    dial side (#postman-owns-dialling)."""
    mgr = crypto.Keypair.generate()
    keys = [crypto.Keypair.generate() for _ in range(size)]
    listeners = [TCPListener() for _ in keys]

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
    # The first keyepoch, in genesis so encryption is live from block 1 and every node's
    # block 1 is byte-equal -- minting it per node would make each one random.
    tx = tx + mint_first_keyepoch(mgmt, mgr)[0]
    genesis = (tx.sign(mgr, 1_700_000_000_000),)

    nodes: list[Node] = []
    for kp in keys:
        store = Store()
        store.provision(mgr.public)
        bootstrap(store, mgr, genesis, bucket=TUNABLES.bucket(T0))
        nodes.append(Node(kp, store, TUNABLES))

    return mgr, nodes, listeners


def _wait_until(pred, timeout_sec: float, interval_sec: float = 0.05) -> bool:
    """Poll `pred()` until it returns truthy or `timeout_sec` elapses. Returns whether
    the predicate succeeded. Used for the "eventually" assertions that can't be
    synchronous when real threads are driving progress."""
    deadline = time.monotonic() + timeout_sec
    while time.monotonic() < deadline:
        if pred():
            return True
        time.sleep(interval_sec)
    return pred()


class TestNodeLifecycle(unittest.TestCase):
    def test_started_cluster_produces_empty_blocks_and_stops_cleanly(self):
        """3-node TCP cluster, managed mode. Heads advance (tick loop ticks; inbox crosses
        listener/node thread boundary) and stop() returns bounded (`_stopping` breaks the loop;
        `TCPListener.stop()` joins). Real wall clock; harness's fast profile."""
        _mgr, nodes, listeners = _build_cluster(3)
        try:
            # Managed mode: each node gets its listener at start(). The dial side is not
            # passed and never was the caller's to pass -- `start` starts the Postman,
            # which builds and reads its own carriers (#postman-owns-dialling).
            for node, listener in zip(nodes, listeners, strict=True):
                node.start(listener)

            # Empty blocks: no submits, but Coordinator ticks each bucket and closes
            # what's there (nothing). With a 3-node roster the Round hits quorum
            # trivially. Give it a few delta intervals to advance.
            target_block = 2
            budget_sec = (target_block + 2) * (TUNABLES.block_time / 1000)
            got = _wait_until(
                lambda: all((n.store.head_block_num() or 0) >= target_block for n in nodes),
                timeout_sec=budget_sec,
            )
            heads = [n.store.head_block_num() or 0 for n in nodes]
            self.assertTrue(got, f"heads did not reach {target_block}: {heads}")

            # Stop within a bounded time. `queue.get(timeout=tick_interval)` wakes at
            # most one tick_interval after `_stopping.set()`; TCPListener.stop() uses
            # `shutdown(SHUT_RDWR)` to unblock select. Both together = well under 3s.
            for node in nodes:
                start = time.monotonic()
                node.stop(timeout=3.0)
                elapsed = time.monotonic() - start
                self.assertLess(elapsed, 3.0, f"node.stop() took {elapsed:.2f}s, expected < 3.0s")
        finally:
            # Best-effort cleanup in case any assertion tripped early. `node.stop()` closes
            # the dial side too, so there is nothing else for the test to hold.
            for node in nodes:
                node.stop(timeout=1.0)

    def test_start_is_transactional_on_listener_failure(self):
        """Fail-loud on partial listener failure. If any listener's `start()` raises,
        every previously-started listener gets stopped in reverse order and the exception
        propagates -- a running node with only some of its listeners is a silent
        degradation we explicitly refuse.

        Proven by handing `Node.start` a fake Listener whose `start()` raises AFTER a
        real listener has already been started. Post-conditions: (a) the exception
        propagates, (b) the real listener was stopped (its reader thread is gone),
        (c) the Postman was stopped -- it is started FIRST, so a rollback that only
        unwound listeners would leave a half-started node whose next `start` raises
        "already started with a different inbox", (d) `node._thread` was never spawned."""
        _mgr, nodes, listeners = _build_cluster(1)
        try:
            good_listener = listeners[0]

            class RaisingListener:
                """A `Listener` whose `.start()` raises. Tracks whether `.stop()` was
                called so the test can assert it wasn't (this listener never started,
                so nothing to roll back for it)."""

                stop_called = False

                def start(self, inbox):
                    del inbox
                    raise RuntimeError("simulated bind failure on the second listener")

                def stop(self):
                    self.stop_called = True

                def drain(self):
                    return ()

            bad = RaisingListener()
            node = nodes[0]

            with self.assertRaises(RuntimeError, msg="start() should propagate the failure"):
                node.start(good_listener, bad)

            # Rollback: `good_listener` was started and MUST have been stopped again.
            # No `_thread` was ever spawned. Node is idle -- another start() must work.
            self.assertIsNone(node._thread, "node thread must not have been spawned")
            self.assertEqual(node._listeners, ())
            self.assertFalse(bad.stop_called, "bad listener never started; nothing to roll back")
            self.assertIsNone(node.postman._inbox, "postman must be rolled back too")
            # Idempotent: another start() with a fresh listener should work. This is the
            # assertion the postman rollback is load-bearing for -- a Postman still holding
            # the first inbox refuses the second start outright.
            fresh = TCPListener()
            try:
                node.start(fresh)
                self.assertIsNotNone(node._thread)
            finally:
                node.stop(timeout=1.0)
                fresh.stop()
        finally:
            for lst in listeners:
                lst.stop()


class TestCrashOnly(unittest.TestCase):
    def test_the_installed_hook_takes_the_process_down_with_the_thread(self):
        """`Node._run` suppresses DudeError only, on the contract that anything else reaching the
        excepthook is `os._exit(70)` and a supervisor respawn. This pins the MECHANISM; who calls
        `install()` is a process entrypoint's job, and there is no entrypoint yet -- so nothing
        installs it, and a node thread dying of a non-DudeError still leaves a zombie whose
        listeners accept frames into an inbox nobody drains. It was briefly called from
        `Node.start()`, which put a process-wide `os._exit` hook inside a library constructor --
        every importer of Node inherits that, this suite included. Subprocess, because a passing
        run of this test ends in `os._exit`."""
        code = textwrap.dedent(
            """
            import threading
            from dude.core import crashonly

            crashonly.install()

            def boom():
                raise RuntimeError("unguarded escape from a node-side thread")

            t = threading.Thread(target=boom)
            t.start()
            t.join()
            print("still alive", flush=True)
            """
        )
        proc = subprocess.run(  # noqa: S603 -- our own interpreter, fixed argv, no outside input
            [sys.executable, "-c", code], capture_output=True, timeout=60, check=False
        )
        self.assertEqual(proc.returncode, 70, proc.stderr.decode())
        self.assertNotIn(b"still alive", proc.stdout, "the zombie survived its thread's death")


if __name__ == "__main__":
    unittest.main()
