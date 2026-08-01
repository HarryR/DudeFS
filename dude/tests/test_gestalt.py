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

import unittest

from ..core import codec, crypto
from ..core.errors import DudeError, InvariantError
from ..net import Verb
from ..net.envelope import Envelope, Frame, seal
from ..net.transports import name_of
from ..node import (
    _DISPATCH,
    HANDLED,
    REPLIES,
    UNIMPLEMENTED,
)
from ..store import ops
from ..store.store import StoreError
from .cluster import DELTA, T0, Cluster, D


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
        client needs a link to ONE node and the rest is the cluster's problem."""
        a, c = name_of(self.c.keys[0].public), name_of(self.c.keys[2].public)
        self.c.board.cut(a, c)
        self.c.board.cut(c, a)

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
        its typed-parsing precondition exists to prevent. `SOLICITED` is no help, since `SUBMIT` is
        not an answer to anything."""
        node = self.c.nodes[0]
        stranger = crypto.Keypair.generate()
        for body in (b"\xff\x00not-bencode", codec.encode([1, 2, 3])):  # bad tag, then bad arity
            env = Envelope(node.me.public, Verb.SUBMIT, b"c" * 16, body).sign(stranger, T0)
            node.receive(seal(env), T0)  # must not raise

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


class TestVerbCoverage(unittest.TestCase):
    """What the node does and does not answer, pinned.

    A test rather than a comment because the interesting property is that the set does not drift:
    add a `Verb` and it lands in `UNIMPLEMENTED` and this fails, instead of falling through a
    default branch and being discovered when a peer sends it."""

    def test_every_verb_is_accounted_for(self):
        self.assertEqual(HANDLED | REPLIES | UNIMPLEMENTED, frozenset(Verb))
        self.assertFalse(HANDLED & REPLIES)

    def test_the_unimplemented_set_is_exactly_the_known_todo(self):
        """`PROPOSE`/`ENDORSE` were the placeholder round's verbs. `Node` no longer dispatches
        them -- Round's own `HELD`/`SIG` do the job now (SPECv2 #round-lifecycle). They stay in
        the enum's retired range so a stale peer sending one is unimplemented-and-ignored rather
        than crashing on an unknown verb; the enum entries should be moved to a retired section
        in a follow-up cleanup."""
        self.assertEqual(UNIMPLEMENTED, {Verb.PROPOSE, Verb.ENDORSE})

    def test_every_handled_verb_has_a_handler(self):
        """Derived, not listed: `_DISPATCH` is built from `HANDLED`, so a verb claimed as handled
        with no `_on_<verb>` fails at import rather than falling into a silent default."""
        self.assertEqual(set(_DISPATCH), HANDLED)

    def test_an_unimplemented_verb_is_ignored_not_fatal(self):
        """A peer sending a verb we have not built must cost its message and nothing more."""
        node, other = self.c.nodes[0], self.c.nodes[1]
        env = Envelope(node.me.public, Verb.PROPOSE, b"z" * 16).sign(other.me, T0)
        node.receive(seal(env), T0)  # must not raise

        key = crypto.h(b"after-unimplemented")
        tx = ops.writes(ops.Set(D, key, b"fine")).sign(self.client, T0)
        self.c.submit(self.client, tx, to=0, now=T0)
        self.c.pump(T0)
        self.c.pump(T0 + DELTA)
        self.assertIsNotNone(node.store.get(D, key))

    def setUp(self):
        self.c = Cluster()
        self.client = self.c.mgr


if __name__ == "__main__":
    unittest.main()
