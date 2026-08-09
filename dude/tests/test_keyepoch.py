"""The keyepoch lifecycle: minting, rotating, and who can read what afterwards."""

from __future__ import annotations

import unittest

from dude.client import Client, Keys, mint_first_keyepoch
from dude.consensus.bootstrap import bootstrap, intervene
from dude.core import codec, crypto
from dude.core.errors import DudeError
from dude.store import Store, ops, settle
from dude.store.management import P_EPOCH, Cert, MgmtReader, MgmtWriter, Role

from .cluster import Cluster

T0 = 1_700_000_000_000


def _cluster_of_one() -> tuple[Store, crypto.Keypair, MgmtWriter]:
    """An anchor, a manager grant and epoch 1: genesis as a deployment composes it."""
    mgr = crypto.Keypair.generate()
    s = Store()
    s.provision(mgr.public)
    w = MgmtWriter(s)
    tx = w.authorise(
        mgr.public,
        Role.MANAGER,
        frozenset({ops.STORE_MANAGEMENT, ops.STORE_DATA}),
        frozenset(),
        pop=mgr.prove_possession(),
        cert=Cert.sign_grant(mgr, mgr.public, Role.MANAGER),
    )
    tx = tx + mint_first_keyepoch(w, mgr)[0]
    bootstrap(s, mgr, (tx.sign(mgr, T0),), bucket=0)
    return s, mgr, MgmtWriter(s)


def _rotate(s: Store, mgr: crypto.Keypair, who: list[crypto.PublicKey]) -> ops.Transaction:
    """A fresh master for the next epoch, sealed to everyone named."""
    keys = Keys.unwrap(s, mgr)
    master = crypto.Master(crypto.random_bytes(crypto.Master.WIDTH))
    return MgmtWriter(s).rotate(keys.current, {p: p.seal(master) for p in who})


class TestRotationIsOneAllOrNothingStep(unittest.TestCase):
    def test_two_managers_rotating_at_once_do_not_both_win(self):
        """Serialised by the forward-only rule, which is why `rotate` carries no guard: a
        `Holds(P_EPOCH, from_epoch)` says exactly what `target == current + 1` says, since the
        target is derived from `from_epoch`. The loser's target is no longer next, so it drops
        rather than overwriting the winner's epoch and stranding every wrap it just wrote."""
        s, mgr, _ = _cluster_of_one()
        first = _rotate(s, mgr, [mgr.public]).sign(mgr, T0 + 1)
        second = _rotate(s, mgr, [mgr.public]).sign(mgr, T0 + 2)

        got = s.apply((first, second), auth=MgmtReader(s))
        self.assertEqual(len(got.settled), 1, "both rotations landed")
        self.assertEqual([d.why for d in got.dropped], [settle.Reason.EPOCH_JUMP])
        self.assertEqual(MgmtReader(s).current_epoch(), 2)

    def test_the_bump_and_the_wraps_are_one_transaction(self):
        """There must never be a live epoch nobody holds the master for. `evaluate` verdicts a
        whole transaction, so a rotation whose wraps are refused takes the bump down with it."""
        s, mgr, _ = _cluster_of_one()
        tx = _rotate(s, mgr, [mgr.public])
        self.assertGreater(len(tx.steps), 1, "a rotation is a bump AND at least one wrap")
        self.assertEqual(
            {st.mutation.store for st in tx.steps}, {ops.STORE_MANAGEMENT}, "one store, one step"
        )

    def test_an_epoch_may_only_move_forward_one_at_a_time(self):
        """The guard proves the author knew the old value; it does not stop them naming one five
        behind it. A keyepoch that goes backwards asks every client to encrypt under a key readers
        have already moved off."""
        s, mgr, _ = _cluster_of_one()
        for bad in (0, 1, 3, 99):
            tx = ops.writes(ops.Set(ops.STORE_MANAGEMENT, P_EPOCH, codec.encode(bad))).sign(
                mgr, T0 + 3
            )
            got = s.apply((tx,), auth=MgmtReader(s))
            self.assertEqual(
                [d.why for d in got.dropped],
                [settle.Reason.EPOCH_JUMP],
                f"epoch {bad} was accepted over current {MgmtReader(s).current_epoch()}",
            )
        self.assertEqual(MgmtReader(s).current_epoch(), 1, "the row moved anyway")


class TestWhatANodeHolds(unittest.TestCase):
    def test_the_stored_row_is_neither_the_name_nor_the_value(self):
        s, mgr, _ = _cluster_of_one()
        c = Client(Keys.unwrap(s, mgr))
        tx = c.put("accounts/alice", b"balance=42")
        m = tx.steps[0].mutation
        assert isinstance(m, ops.Set)

        self.assertNotIn(b"accounts", m.name)
        self.assertEqual(len(m.name), crypto.DIGEST_SIZE)
        self.assertNotIn(b"balance", m.value)
        self.assertEqual(m.epoch, 1)
        self.assertEqual(c.open("accounts/alice", m.value, m.epoch), b"balance=42")

    def test_the_same_plaintext_seals_differently_every_time(self):
        """Which is why compare-and-swap guards on the STORED bytes: no guard can be computed
        from a plaintext that seals to something new on every call."""
        s, mgr, _ = _cluster_of_one()
        c = Client(Keys.unwrap(s, mgr))
        one = c.put("k", b"v").steps[0].mutation
        two = c.put("k", b"v").steps[0].mutation
        assert isinstance(one, ops.Set) and isinstance(two, ops.Set)
        self.assertEqual(one.name, two.name, "the token must be stable")
        self.assertNotEqual(one.value, two.value, "sealing is not randomised")


class TestACiphertextOpensOnlyWhereItWasSealed(unittest.TestCase):
    """WHAT HOLDS WHAT, because a first draft of this credited the wrong mechanism and passed with
    the AAD gutted. The item key is derived from `(value_key(epoch), name_token)`, so a wrong name
    or a wrong epoch is already a wrong KEY -- the AAD is not what refuses those. What the AAD
    alone binds is the store, which the key derivation does not mention."""

    def setUp(self):
        self.s, self.mgr, _ = _cluster_of_one()
        self.keys = Keys.unwrap(self.s, self.mgr)
        self.c = Client(self.keys)
        m = self.c.put("real/name", b"secret").steps[0].mutation
        assert isinstance(m, ops.Set)
        self.sealed, self.epoch = m.value, m.epoch

    def test_another_name_derives_another_item_key(self):
        with self.assertRaises(DudeError):
            self.c.open("other/name", self.sealed, self.epoch)

    def test_another_epoch_derives_another_item_key(self):
        intervene(
            self.s,
            self.mgr,
            bodies=(_rotate(self.s, self.mgr, [self.mgr.public]).sign(self.mgr, T0 + 1),),
            bucket=1,
        )
        rolled = Client(Keys.unwrap(self.s, self.mgr))
        self.assertEqual(rolled.keys.current, 2)
        with self.assertRaises(DudeError):
            rolled.open("real/name", self.sealed, 2)
        self.assertEqual(
            rolled.open("real/name", self.sealed, self.epoch),
            b"secret",
            "the epoch it was SEALED under must still open it",
        )

    def test_the_store_is_bound_by_the_aad_and_by_nothing_else(self):
        """Same token, same epoch, same item key -- only the AAD differs. Drop the store from it
        and this row opens as though it had been written in another store."""
        elsewhere = Client(self.keys, store_id=ops.STORE_DATA + 1)
        self.assertEqual(
            elsewhere.token("real/name"), self.c.token("real/name"), "same key, same token"
        )
        with self.assertRaises(DudeError):
            elsewhere.open("real/name", self.sealed, self.epoch)


class TestAReaderMintedLaterStillReadsHistory(unittest.TestCase):
    def test_a_client_admitted_after_three_rotations_reads_the_first_epoch(self):
        """The manager can do this because it is in every wrap set: it recovers each master by
        unsealing its OWN row, so the cluster is its key store and nothing durable is kept
        outside it. An epoch minted without a manager could never be granted to anybody new."""
        s, mgr, _ = _cluster_of_one()
        first = Client(Keys.unwrap(s, mgr))
        m = first.put("old/secret", b"written-under-epoch-1").steps[0].mutation
        assert isinstance(m, ops.Set)
        intervene(s, mgr, bodies=(ops.writes(m).sign(mgr, T0),), bucket=1)

        for i in range(3):
            tx = _rotate(s, mgr, [mgr.public]).sign(mgr, T0 + 10 + i)
            intervene(s, mgr, bodies=(tx,), bucket=2 + i)
        self.assertEqual(MgmtReader(s).current_epoch(), 4)

        newcomer = crypto.Keypair.generate()
        wraps, blinding = Keys.unwrap(s, mgr).wraps_for(newcomer.public)
        self.assertEqual(sorted(wraps), [1, 2, 3, 4], "not every outstanding epoch was re-sealed")
        w = MgmtWriter(s)
        admit = (
            w.authorise(
                newcomer.public,
                Role.CLIENT_RO,
                stores=frozenset({ops.STORE_DATA}),
                pop=newcomer.prove_possession(),
                cert=Cert.sign_grant(mgr, newcomer.public, Role.CLIENT_RO),
            )
            + w.admit_reader(newcomer.public, wraps, blinding)
        ).sign(mgr, T0 + 20)
        intervene(s, mgr, bodies=(admit,), bucket=9)

        reader = Client(Keys.unwrap(s, newcomer))
        row = s.get(ops.STORE_DATA, reader.token("old/secret"))
        assert row is not None, "the newcomer derives a different token"
        self.assertEqual(reader.open("old/secret", row.value, row.epoch), b"written-under-epoch-1")


class TestGenesisIsByteEqualOnEveryNode(unittest.TestCase):
    """Minting is RANDOM, so where it happens decides whether a cluster can form at all.

    Done inside `bootstrap` -- which runs once per node -- every node sealed different secrets,
    so every node's block 1 hashed differently, so no two nodes agreed what their round followed
    and nothing ever ratified. It looked exactly like a consensus bug. The mint belongs with the
    genesis bodies, composed once and handed to every node, and a joiner must be handed the SAME
    bodies rather than freshly composed ones or it lands on a chain of its own."""

    def test_every_node_and_a_later_joiner_share_block_one(self):
        c = Cluster()
        blocks = {n.store.settled_at(1) for n in c.nodes}
        self.assertEqual(len(blocks), 1, "nodes disagree on block 1")
        joiner = c.provisioned()
        self.assertIn(joiner.settled_at(1), blocks, "a joiner was bootstrapped onto its own chain")

    def test_the_cluster_actually_settles_a_block(self):
        """The control: byte-equal genesis is only interesting because rounds converge on it."""
        c = Cluster()
        c.put("probe", b"v", now=T0)
        c.pump(T0)
        heads = {n.store.head_block_num() or 0 for n in c.nodes}
        self.assertEqual(len(heads), 1, f"nodes disagree on the head: {heads}")
        self.assertGreater(heads.pop(), 1, "no block was produced")


if __name__ == "__main__":
    unittest.main()
