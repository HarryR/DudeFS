"""Layer as a View: projected roots match a from-scratch rebuild with the same mutations.

The differential invariant is the whole point of computing roots through the overlay: if
`Layer(base=store).accumulator()` disagrees with `store.rebuild().apply(muts).accumulator()`,
then two nodes could ratify a slice and diverge on the settled anchors. Same for `state_root`.

Random topologies are the honest test -- the enumerated cases (empty overlay, single set,
single del, set-then-del, del-of-absent) exist to pin the specific shapes, but the property
tests exist because the enumeration cannot cover the space where compression edges bite.
"""

from __future__ import annotations

import random
import unittest
from collections.abc import Sequence

from ..core import crypto
from ..store import Layer, LayerError, Store, ops

D = ops.STORE_DATA


def _writes(kp: crypto.Keypair, muts: Sequence[ops.Mutation], ts: int = 1) -> ops.SignedTransaction:
    """Assemble an unguarded transaction from a list of mutations; sign it."""
    return ops.writes(*muts).sign(kp, ts)


def _seed_store(kp: crypto.Keypair, count: int) -> Store:
    """A Store with `count` seed rows, so overlays land against a non-trivial base."""
    s = Store()
    if count:
        s.apply(
            (_writes(kp, [ops.Set(D, crypto.h(f"seed{i}".encode()), b"v") for i in range(count)]),)
        )
    return s


class TestLayerLifecycle(unittest.TestCase):
    """OPEN/FROZEN state machine, and the frozen-base rule at construction."""

    def setUp(self):
        self.kp = crypto.Keypair.generate()
        self.store = _seed_store(self.kp, 4)

    def test_a_fresh_layer_is_open(self):
        layer = Layer(self.store)
        self.assertFalse(layer.is_frozen)

    def test_freeze_is_one_way_and_idempotent(self):
        layer = Layer(self.store)
        layer.freeze()
        self.assertTrue(layer.is_frozen)
        layer.freeze()  # no error
        self.assertTrue(layer.is_frozen)

    def test_apply_on_a_frozen_layer_refuses(self):
        layer = Layer(self.store)
        layer.freeze()
        with self.assertRaises(LayerError):
            layer.apply(ops.Set(D, crypto.h(b"k"), b"v"), b"cred")

    def test_a_layer_over_an_open_layer_refuses(self):
        """The invariant: Layer(base=X) requires X.is_frozen."""
        inner = Layer(self.store)
        # inner is OPEN; stacking on it is a bug
        with self.assertRaises(LayerError):
            Layer(inner)

    def test_a_layer_over_a_frozen_layer_is_allowed(self):
        inner = Layer(self.store)
        inner.apply(ops.Set(D, crypto.h(b"k"), b"v"), b"cred")
        inner.freeze()
        outer = Layer(inner)  # no error
        self.assertFalse(outer.is_frozen)

    def test_speculative_layer_has_no_frozen_requirement(self):
        """settle.evaluate's use case: the base is an open Layer that will absorb survivors."""
        inner = Layer(self.store)  # OPEN
        speculative = Layer.speculative(inner)
        # No frozen check; construction succeeds.
        speculative.apply(ops.Set(D, crypto.h(b"k"), b"v"), b"cred")


class TestAccumulatorProjection(unittest.TestCase):
    """Layer.accumulator == what Store.accumulator would be after applying the same mutations."""

    def setUp(self):
        self.kp = crypto.Keypair.generate()

    def _committed(self, seed: int, muts: Sequence[ops.Mutation]) -> crypto.Accumulator:
        """The reference: seed the Store, apply the mutations, read A_state."""
        s = _seed_store(self.kp, seed)
        s.apply((_writes(self.kp, muts, ts=2),))
        return s.accumulator()

    def _projected(self, seed: int, muts: Sequence[ops.Mutation]) -> crypto.Accumulator:
        """The overlay: seed the Store, project A_state via a Layer without committing."""
        s = _seed_store(self.kp, seed)
        layer = Layer(s)
        cred = _writes(self.kp, muts, ts=2).raw
        for m in muts:
            layer.apply(m, cred)
        return layer.accumulator()

    def test_empty_overlay(self):
        s = _seed_store(self.kp, 4)
        self.assertEqual(Layer(s).accumulator(), s.accumulator())

    def test_single_set_of_new_key(self):
        muts = [ops.Set(D, crypto.h(b"new"), b"v")]
        self.assertEqual(self._projected(3, muts), self._committed(3, muts))

    def test_set_then_del_returns_to_base(self):
        s = _seed_store(self.kp, 3)
        layer = Layer(s)
        cred = b"cred"
        k = crypto.h(b"transient")
        layer.apply(ops.Set(D, k, b"v"), cred)
        layer.apply(ops.Del(D, k), cred)
        self.assertEqual(layer.accumulator(), s.accumulator())

    def test_overwrite_of_seed(self):
        muts = [ops.Set(D, crypto.h(b"seed1"), b"changed")]
        self.assertEqual(self._projected(4, muts), self._committed(4, muts))

    def test_del_of_seed(self):
        muts = [ops.Del(D, crypto.h(b"seed2"))]
        self.assertEqual(self._projected(4, muts), self._committed(4, muts))

    def test_property_random_topologies_agree(self):
        """Seeded random: build a random base + random overlay; commit path and project path
        must agree on A_state. If they don't, two nodes would sign different anchors."""
        for seed in range(10):
            rng = random.Random(seed)
            base_size = rng.randint(0, 12)
            muts: list[ops.Mutation] = []
            for _ in range(rng.randint(1, 8)):
                k = crypto.h(f"k{rng.randint(0, 20)}".encode())
                if rng.random() < 0.3:
                    muts.append(ops.Del(D, k))
                else:
                    muts.append(ops.Set(D, k, bytes([rng.randrange(256)])))
            with self.subTest(seed=seed):
                self.assertEqual(
                    self._projected(base_size, muts),
                    self._committed(base_size, muts),
                    f"seed={seed} base={base_size} muts={muts}",
                )


class TestStateRootProjection(unittest.TestCase):
    """Layer.state_root == what Store.state_root would be after applying the same mutations.

    THE HARDER ROOT. `A_state` is trivial (add/sub arithmetic). `state_root` is the SMT root
    over live rows, which depends on tree topology and compression -- a subtree with exactly
    one leaf hashes as that leaf, not as branch_hash of empty+leaf. Projection has to reproduce
    that shape."""

    def setUp(self):
        self.kp = crypto.Keypair.generate()

    def _committed(self, seed: int, muts: Sequence[ops.Mutation]) -> crypto.Digest:
        s = _seed_store(self.kp, seed)
        s.apply((_writes(self.kp, muts, ts=2),))
        return s.state_root()

    def _projected(self, seed: int, muts: Sequence[ops.Mutation]) -> crypto.Digest:
        s = _seed_store(self.kp, seed)
        layer = Layer(s)
        cred = _writes(self.kp, muts, ts=2).raw
        for m in muts:
            layer.apply(m, cred)
        return layer.state_root()

    def test_empty_overlay(self):
        s = _seed_store(self.kp, 4)
        self.assertEqual(Layer(s).state_root(), s.state_root())

    def test_single_new_key(self):
        muts = [ops.Set(D, crypto.h(b"new"), b"v")]
        self.assertEqual(self._projected(3, muts), self._committed(3, muts))

    def test_overwrite_of_seed(self):
        muts = [ops.Set(D, crypto.h(b"seed1"), b"changed")]
        self.assertEqual(self._projected(4, muts), self._committed(4, muts))

    def test_del_of_seed(self):
        muts = [ops.Del(D, crypto.h(b"seed2"))]
        self.assertEqual(self._projected(4, muts), self._committed(4, muts))

    def test_del_of_absent_is_no_op(self):
        s = _seed_store(self.kp, 4)
        layer = Layer(s)
        layer.apply(ops.Del(D, crypto.h(b"never-existed")), b"cred")
        self.assertEqual(layer.state_root(), s.state_root())

    def test_set_then_del_returns_to_base(self):
        s = _seed_store(self.kp, 3)
        layer = Layer(s)
        cred = b"cred"
        k = crypto.h(b"transient")
        layer.apply(ops.Set(D, k, b"v"), cred)
        layer.apply(ops.Del(D, k), cred)
        # The delta has an entry (Set→None) even for a transient. The final effective view
        # matches base, so state_root should agree.
        self.assertEqual(layer.state_root(), s.state_root())

    def test_property_random_topologies_agree(self):
        """Seeded random: build a random base + random overlay; commit path and project path
        must agree on state_root. This is the load-bearing test -- if it fails, two nodes
        would sign different state roots for the same slice."""
        for seed in range(15):
            rng = random.Random(seed)
            base_size = rng.randint(0, 10)
            muts: list[ops.Mutation] = []
            for _ in range(rng.randint(1, 6)):
                k = crypto.h(f"k{rng.randint(0, 15)}".encode())
                if rng.random() < 0.3:
                    muts.append(ops.Del(D, k))
                else:
                    muts.append(ops.Set(D, k, bytes([rng.randrange(256)])))
            with self.subTest(seed=seed):
                self.assertEqual(
                    self._projected(base_size, muts),
                    self._committed(base_size, muts),
                    f"seed={seed} base={base_size} muts={muts}",
                )


class TestFrozenLayerAsBase(unittest.TestCase):
    """Once a Layer is frozen, another Layer can stack on it and compute roots as if the base
    Layer were part of the persistent store."""

    def setUp(self):
        self.kp = crypto.Keypair.generate()

    def test_stacked_layers_project_to_the_same_root_as_flat_commit(self):
        """Layer1 sets A; Layer2 sets B. state_root(Layer2) should equal state_root of
        applying (A, B) directly to the store.

        Store's _commit uses `tx.raw` as the credential; Layer must be handed the same, or
        the SMT leaves differ and roots diverge. Ordinary usage (settle.evaluate driving
        Layer.apply) satisfies this because settle passes `tx.raw` -- the test mirrors that."""
        s = _seed_store(self.kp, 2)
        muts_a = [ops.Set(D, crypto.h(b"a"), b"va")]
        muts_b = [ops.Set(D, crypto.h(b"b"), b"vb")]

        # Reference: commit A and B as one flat transaction
        ref = _seed_store(self.kp, 2)
        ref_tx = _writes(self.kp, muts_a + muts_b, ts=2)
        ref.apply((ref_tx,))

        # Overlay: same transaction, split across two stacked Layers, same tx.raw as credential
        inner = Layer(s)
        for m in muts_a:
            inner.apply(m, ref_tx.raw)
        inner.freeze()

        outer = Layer(inner)
        for m in muts_b:
            outer.apply(m, ref_tx.raw)

        self.assertEqual(outer.state_root(), ref.state_root())
        self.assertEqual(outer.accumulator(), ref.accumulator())


if __name__ == "__main__":
    unittest.main()
