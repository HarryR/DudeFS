"""The conveyor: re-encrypt forward, then let the old key die (#conveyor).

This is where forward secrecy stops being a claim. `#secrecy-by-key-death` says secrecy comes from
keys dying rather than from erasing ciphertext — and until this step no key had ever died, because
nothing could say which epoch a value was under and therefore nothing could tell when one was
finished with.

The asymmetry that shapes every test below: retiring an epoch one value too early makes that value
unreadable by everyone, forever. A conveyor that runs late is slow. A conveyor that runs early has
destroyed committed state.
"""

import unittest

from dude.core import crypto
from dude.store import layer, management, ops, store
from dude.tests.test_store import tx

D = ops.STORE_DATA
M = ops.STORE_MANAGEMENT


class _Fixture(unittest.TestCase):
    def setUp(self):
        self.s = store.Store()
        self.kp = crypto.Keypair.generate()
        self.mgmt = management.Management(self.s)

    def write(self, name: bytes, value: bytes, epoch: int) -> None:
        self.s.apply((tx(self.kp, muts=(ops.Set(D, name, value, epoch),)),), auth=None)

    def send(self, txn: ops.Transaction) -> tuple[tuple[int, crypto.Digest], ...]:
        """Returns what SETTLED, so a test can assert that a refused retirement settled nothing."""
        return self.s.apply((txn.sign(self.kp, 1),), auth=None).settled


class TestTheBacklog(_Fixture):
    """Counting is the prerequisite. Everything else is a consequence of being able to ask "is this
    epoch finished with" and get an answer no one has to be trusted about."""

    def test_a_value_carries_its_epoch(self):
        self.write(b"k", b"ciphertext", 3)
        held = self.s.get(D, b"k")
        assert held is not None
        self.assertEqual(held.epoch, 3)

    def test_the_epoch_survives_the_log(self):
        """It is carried in the mutation, not attached to the row, so a replay reconstructs it. If
        it were only a column, a rebuilt node could not count and could not convey."""
        self.write(b"k", b"ciphertext", 3)
        self.assertEqual(self.s.rebuild().epoch_live(3), 1)

    def test_the_backlog_is_counted_by_epoch(self):
        for i in range(5):
            self.write(f"a{i}".encode(), b"v", 1)
        for i in range(2):
            self.write(f"b{i}".encode(), b"v", 2)
        self.assertEqual(self.s.epochs(), {1: 5, 2: 2})

    def test_management_rows_are_in_no_epoch(self):
        """Roster and grant rows are not encrypted under a value key, so they hold no epoch alive
        and can never block a retirement. That matters because they are permanent stragglers."""
        self.write(b"k", b"v", ops.EPOCH_NONE)
        self.assertEqual(self.s.epochs(), {}, "a keyless row entered the conveyor's work queue")
        with self.assertRaises(ValueError):
            self.mgmt.retire(ops.EPOCH_NONE)

    def test_overwriting_moves_a_value_between_epochs(self):
        """The conveyance mechanic in its smallest form: one key, rewritten under a newer epoch.
        The old count falls, the new one rises, and nothing else moves."""
        self.write(b"k", b"old ciphertext", 1)
        self.assertEqual(self.s.epochs(), {1: 1})
        self.write(b"k", b"new ciphertext", 2)
        self.assertEqual(self.s.epochs(), {2: 1})

    def test_deleting_drains_too(self):
        """A value that goes away releases its epoch as surely as one that is conveyed. Deletion is
        conveyance's cheaper cousin, and the register-overwritten workload produces a lot of it."""
        self.write(b"k", b"v", 1)
        self.s.apply((tx(self.kp, muts=(ops.Del(D, b"k"),)),), auth=None)
        self.assertEqual(self.s.epoch_live(1), 0)


class TestRetirement(_Fixture):
    """`Drained` is the one predicate that ranges over all keys, because it answers the one question
    that has to."""

    def test_a_drained_epoch_retires(self):
        self.write(b"k", b"v", 1)
        self.send(self.mgmt.distribute(1, {self.kp.public: crypto.SealedBlob(b"sealed master")}))
        self.assertIsNotNone(self.mgmt.wrapped_master(1, self.kp.public))

        self.write(b"k", b"v", 2)  # conveyed forward: epoch 1 now holds nothing
        self.assertEqual(self.s.epoch_live(1), 0)
        self.send(self.mgmt.retire(1))

        self.assertIsNone(self.mgmt.wrapped_master(1, self.kp.public), "the key did not die")

    def test_an_epoch_still_in_use_cannot_be_retired(self):
        """THE test. One live value under epoch 1, and the retirement must not settle -- because
        the alternative is that value being unreadable by everyone for the rest of time."""
        self.write(b"k", b"v", 1)
        self.send(self.mgmt.distribute(1, {self.kp.public: crypto.SealedBlob(b"sealed master")}))

        dropped = self.send(self.mgmt.retire(1))
        self.assertEqual(dropped, (), "an early retirement settled")
        self.assertIsNotNone(
            self.mgmt.wrapped_master(1, self.kp.public), "a key died with a value still under it"
        )

    def test_retirement_is_refused_for_one_straggler_among_many(self):
        """The realistic near-miss: the conveyor did almost all of it. Almost is not drained."""
        for i in range(20):
            self.write(f"k{i}".encode(), b"v", 1)
        self.send(self.mgmt.distribute(1, {self.kp.public: crypto.SealedBlob(b"m")}))
        for i in range(19):
            self.write(f"k{i}".encode(), b"v", 2)

        self.assertEqual(self.s.epoch_live(1), 1)
        self.assertEqual(self.send(self.mgmt.retire(1)), ())
        self.assertIsNotNone(self.mgmt.wrapped_master(1, self.kp.public))

        self.write(b"k19", b"v", 2)  # the last one conveyed
        self.assertNotEqual(self.send(self.mgmt.retire(1)), ())
        self.assertIsNone(self.mgmt.wrapped_master(1, self.kp.public))

    def test_every_holder_loses_it_together(self):
        """Distribution is atomic and so is retirement: no holder is left with a key to data that
        others can no longer read, and none is left able to read what others cannot."""
        holders = [crypto.Keypair.generate() for _ in range(4)]
        self.send(
            self.mgmt.distribute(
                1, {kp.public: crypto.SealedBlob(f"m{i}".encode()) for i, kp in enumerate(holders)}
            )
        )
        self.assertEqual(len(self.mgmt.wraps_of(1)), 4)
        self.send(self.mgmt.retire(1))
        self.assertEqual(self.mgmt.wraps_of(1), ())

    def test_retiring_one_epoch_leaves_the_others_alone(self):
        self.send(self.mgmt.distribute(1, {self.kp.public: crypto.SealedBlob(b"m1")}))
        self.send(self.mgmt.distribute(2, {self.kp.public: crypto.SealedBlob(b"m2")}))
        self.write(b"k", b"v", 2)
        self.send(self.mgmt.retire(1))
        self.assertIsNone(self.mgmt.wrapped_master(1, self.kp.public))
        self.assertIsNotNone(self.mgmt.wrapped_master(2, self.kp.public))

    def test_the_guard_survives_the_wire(self):
        """`Drained` has to decode as itself. A predicate that quietly decoded as something else
        would be a guard that stops guarding, which is the worst failure a guard has."""
        txn = self.mgmt.retire(7)
        back = ops.SignedTransaction.decode(txn.sign(self.kp, 1).raw)
        self.assertEqual(back.txn, txn)


class TestTheGuardSeesUncommittedWork(_Fixture):
    """A guard is evaluated against the evolving state of its own batch, and `Drained` must be no
    exception -- otherwise a transaction could retire an epoch it is itself writing under."""

    def test_a_write_in_the_same_layer_blocks_the_retirement(self):
        base = store.Store()
        lay = layer.Layer(base)
        self.assertEqual(lay.epoch_live(4), 0)
        lay.apply(ops.Set(D, b"k", b"v", 4), b"cred")
        self.assertEqual(lay.epoch_live(4), 1, "the layer did not see its own write")
        self.assertFalse(layer.holds(lay, ops.Drained(4)))

    def test_a_delete_in_the_same_layer_releases_it(self):
        base = store.Store()
        base.apply((tx(self.kp, muts=(ops.Set(D, b"k", b"v", 4),)),), auth=None)
        lay = layer.Layer(base)
        self.assertFalse(layer.holds(lay, ops.Drained(4)))
        lay.apply(ops.Del(D, b"k"), b"cred")
        self.assertTrue(layer.holds(lay, ops.Drained(4)), "the layer did not see its own delete")

    def test_a_conveyance_in_the_same_layer_releases_it(self):
        base = store.Store()
        base.apply((tx(self.kp, muts=(ops.Set(D, b"k", b"old", 4),)),), auth=None)
        lay = layer.Layer(base)
        lay.apply(ops.Set(D, b"k", b"new", 5), b"cred")
        self.assertTrue(layer.holds(lay, ops.Drained(4)))
        self.assertFalse(layer.holds(lay, ops.Drained(5)))


class TestTheBeltMoves(_Fixture):
    """Conveying drains the old epoch. Segment vacation was the compaction-era half; it went
    with rip 2/3."""

    def test_conveying_drains_the_epoch(self):
        for i in range(6):
            self.write(f"k{i}".encode(), b"v", 1)
        self.assertEqual(self.s.epoch_live(1), 6)

        for i in range(6):
            self.write(f"k{i}".encode(), b"conveyed", 2)

        self.assertEqual(self.s.epoch_live(1), 0, "the epoch did not drain")

    def test_the_oldest_epoch_is_the_one_closest_to_dying(self):
        """`epochs()` is the conveyor's work queue, oldest first -- which is the order that
        retires a key soonest, and a basic-but-honest pressure signal."""
        for i in range(3):
            self.write(f"a{i}".encode(), b"v", 5)
        for i in range(9):
            self.write(f"b{i}".encode(), b"v", 3)
        self.assertEqual(list(self.s.epochs()), [3, 5])


if __name__ == "__main__":
    unittest.main()
