"""The keyepoch lifecycle: minting, rotating, and who can read what afterwards."""

from __future__ import annotations

import unittest

from dude.consensus.bootstrap import bootstrap, intervene, mint_first_keyepoch
from dude.core import codec, crypto
from dude.core.errors import DudeError
from dude.session import KeyCache, SessionRW, Substrate
from dude.store import Store, ops, settle
from dude.store.layer import Held, Settled
from dude.store.management import Cert, MgmtWriter, Role, epoch_key

from .cluster import Cluster

T0 = 1_700_000_000_000


def _cluster_of_one() -> tuple[Store, crypto.Keypair, MgmtWriter]:
    mgr = crypto.Keypair.generate()
    s = Store()
    s.provision(mgr.public)
    w = s.mgmt_writer
    tx = w.authorise(
        mgr.public,
        Role.MANAGER,
        frozenset({ops.STORE_MANAGEMENT, ops.STORE_DATA}),
        frozenset(),
        pop=mgr.prove_possession(),
        cert=Cert.sign_grant(mgr, mgr.public, Role.MANAGER),
    )
    tx = tx + mint_first_keyepoch(w, mgr)
    bootstrap(s, mgr, (tx.sign(mgr, T0),), bucket=0)
    return s, mgr, s.mgmt_writer


class _StoreSubstrate(Substrate):
    __slots__ = ("_store", "_cache")

    def __init__(self, store: Store, kp: crypto.Keypair) -> None:
        self._store = store
        self._cache = KeyCache(kp, store)

    def anchor(self) -> crypto.PublicKey:
        return self._store.anchor()

    def get(self, store: int, name: bytes) -> Held | None:
        return self._store.get(store, name)

    def token(self, store_id: int, name: str) -> bytes:
        return self._cache.token(store_id, name)

    def seal(self, store_id: int, name: str, value: bytes) -> tuple[bytes, bytes, int]:
        return self._cache.seal(store_id, name, value)

    def decrypt(self, store_id: int, name: str, ciphertext: bytes, epoch: int) -> bytes:
        return self._cache.decrypt(store_id, name, ciphertext, epoch)

    def submit(self, tx: ops.Transaction) -> ...:
        raise NotImplementedError

    def settled(self, op_hash: crypto.Digest) -> Settled | None:
        raise NotImplementedError

    def evict_after_sec(self) -> float:
        raise NotImplementedError

    def wait_for_commit(self, timeout: float) -> None:
        raise NotImplementedError


def _data_session(s: Store, kp: crypto.Keypair) -> SessionRW:
    return SessionRW(_StoreSubstrate(s, kp), ops.STORE_DATA)


def _rotate(s: Store, mgr: crypto.Keypair, who: list[crypto.PublicKey]) -> ops.Transaction:
    cur = s.mgmt_reader.current_epoch(ops.STORE_DATA)
    master = crypto.Master(crypto.random_bytes(crypto.Master.WIDTH))
    return s.mgmt_writer.rotate(ops.STORE_DATA, cur, {p: p.seal(master) for p in who})


class TestRotationIsOneAllOrNothingStep(unittest.TestCase):
    def test_two_managers_rotating_at_once_do_not_both_win(self):
        s, mgr, _ = _cluster_of_one()
        first = _rotate(s, mgr, [mgr.public]).sign(mgr, T0 + 1)
        second = _rotate(s, mgr, [mgr.public]).sign(mgr, T0 + 2)

        got = s.apply((first, second), auth=s.mgmt_reader)
        self.assertEqual(len(got.settled), 1, "both rotations landed")
        self.assertEqual([d.why for d in got.dropped], [settle.Reason.EPOCH_JUMP])
        self.assertEqual(s.mgmt_reader.current_epoch(ops.STORE_DATA), 2)

    def test_the_bump_and_the_wraps_are_one_transaction(self):
        s, mgr, _ = _cluster_of_one()
        tx = _rotate(s, mgr, [mgr.public])
        self.assertGreater(len(tx.steps), 1, "a rotation is a bump AND at least one wrap")
        self.assertEqual(
            {st.mutation.store for st in tx.steps}, {ops.STORE_MANAGEMENT}, "one store, one step"
        )

    def test_an_epoch_may_only_move_forward_one_at_a_time(self):
        s, mgr, _ = _cluster_of_one()
        for bad in (0, 1, 3, 99):
            tx = ops.writes(
                ops.Set(ops.STORE_MANAGEMENT, epoch_key(ops.STORE_DATA), codec.encode(bad))
            ).sign(mgr, T0 + 3)
            got = s.apply((tx,), auth=s.mgmt_reader)
            self.assertEqual(
                [d.why for d in got.dropped],
                [settle.Reason.EPOCH_JUMP],
                f"epoch {bad} accepted over {s.mgmt_reader.current_epoch(ops.STORE_DATA)}",
            )
        self.assertEqual(s.mgmt_reader.current_epoch(ops.STORE_DATA), 1, "the row moved anyway")


class TestWhatANodeHolds(unittest.TestCase):
    def test_the_stored_row_is_neither_the_name_nor_the_value(self):
        s, mgr, _ = _cluster_of_one()
        ds = _data_session(s, mgr)
        token, sealed, epoch = ds.seal("accounts/alice", b"balance=42")

        self.assertNotIn(b"accounts", token)
        self.assertEqual(len(token), crypto.DIGEST_SIZE)
        self.assertNotIn(b"balance", sealed)
        self.assertEqual(epoch, 1)
        rec = ds.get("accounts/alice")
        if not rec.absent:
            self.assertEqual(rec.value, b"balance=42")

    def test_the_same_plaintext_seals_differently_every_time(self):
        s, mgr, _ = _cluster_of_one()
        ds = _data_session(s, mgr)
        tok1, sealed1, _ = ds.seal("k", b"v")
        tok2, sealed2, _ = ds.seal("k", b"v")
        self.assertEqual(tok1, tok2, "the token must be stable")
        self.assertNotEqual(sealed1, sealed2, "sealing is not randomised")


class TestACiphertextOpensOnlyWhereItWasSealed(unittest.TestCase):

    def setUp(self):
        self.s, self.mgr, _ = _cluster_of_one()
        self.ds = _data_session(self.s, self.mgr)
        self.token, self.sealed, self.epoch = self.ds.seal("real/name", b"secret")
        m = ops.Set(ops.STORE_DATA, self.token, self.sealed, self.epoch)
        intervene(self.s, self.mgr, bodies=(ops.writes(m).sign(self.mgr, T0),), bucket=1)

    def test_another_name_derives_another_item_key(self):
        with self.assertRaises(DudeError):
            self.ds._decrypt("other/name", self.sealed, self.epoch)

    def test_another_epoch_derives_another_item_key(self):
        intervene(
            self.s,
            self.mgr,
            bodies=(_rotate(self.s, self.mgr, [self.mgr.public]).sign(self.mgr, T0 + 1),),
            bucket=2,
        )
        rolled = _data_session(self.s, self.mgr)
        self.assertEqual(self.s.mgmt_reader.current_epoch(ops.STORE_DATA), 2)
        with self.assertRaises(DudeError):
            rolled._decrypt("real/name", self.sealed, 2)
        self.assertEqual(
            rolled._decrypt("real/name", self.sealed, self.epoch),
            b"secret",
        )

    def test_a_grant_for_another_store_cannot_open_this_one(self):
        other = ops.STORE_DATA + 1
        mint = mint_first_keyepoch(self.s.mgmt_writer, self.mgr, other)
        intervene(self.s, self.mgr, bodies=(mint.sign(self.mgr, T0 + 5),), bucket=5)

        store2 = _data_session(self.s, self.mgr)
        store2._store_id = other
        self.assertNotEqual(
            store2.token("real/name"),
            self.ds.token("real/name"),
            "both stores blinded with the same secret",
        )
        with self.assertRaises(DudeError):
            store2._decrypt("real/name", self.sealed, self.epoch)

        again = _data_session(self.s, self.mgr)
        self.assertEqual(
            again.token("real/name"),
            self.ds.token("real/name"),
            "minting store 2 moved store 1's rows",
        )
        self.assertEqual(again._decrypt("real/name", self.sealed, self.epoch), b"secret")


class TestGenesisIsByteEqualOnEveryNode(unittest.TestCase):

    def test_every_node_and_a_later_joiner_share_block_one(self):
        c = Cluster(nodes=3, mgmt=1)
        blocks = {n.store.settled_at(1) for n in c.nodes}
        self.assertEqual(len(blocks), 1, "nodes disagree on block 1")
        joiner = c.provisioned()
        self.assertIn(joiner.settled_at(1), blocks, "a joiner was bootstrapped onto its own chain")
        c.close()

    def test_the_cluster_actually_settles_a_block(self):
        c = Cluster(nodes=3, mgmt=1)
        s = c.replicas[0].session()
        result = c.wait_settled(s.put("probe", b"v").wait())
        self.assertGreater(result.block_num, 0, "put did not land in a post-genesis block")
        c.close()


if __name__ == "__main__":
    unittest.main()
