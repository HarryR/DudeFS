"""The state root (#state-root).

Two things are being tested here and they matter for different reasons. The PROOFS are what a client
relies on — most of all the absence proofs, since absence is the revocation. CANONICITY is what the
cluster relies on: two nodes holding the same live state must produce the same root no matter how
they got there, or the root is a divergence detector that fires on honest nodes.
"""

import sqlite3
import unittest

from dude.core import crypto
from dude.store import ops, smt, store
from dude.tests.test_store import tx

D = ops.STORE_DATA
M = ops.STORE_MANAGEMENT


def _bare() -> sqlite3.Connection:
    """Just the leaf table and the memo, so the tree can be exercised without settlement, roles or
    signatures in the way."""
    db = sqlite3.connect(":memory:", isolation_level=None)
    db.executescript(
        "CREATE TABLE live (store INTEGER, name BLOB, head INTEGER, value BLOB, path BLOB,"
        " cred BLOB NOT NULL, PRIMARY KEY (store, name));"
        "CREATE UNIQUE INDEX live_by_path ON live(path);"
        "CREATE TABLE smt_memo (depth INTEGER, prefix BLOB, hash BLOB,"
        " PRIMARY KEY (depth, prefix));"
    )
    return db


class _Fixture(unittest.TestCase):
    def setUp(self):
        self.db = _bare()
        self.t = smt.Tree(self.db)

    def cred(self, name: bytes, st: int = D) -> bytes:
        """Stand-in for the transaction that authorised a row.

        DISTINCT PER KEY, because the leaf commits to it: a fixture writing one shared blob
        everywhere would let a leaf that ignored the credential pass every test here."""
        return b"cred:" + bytes([st]) + name

    def held(self, name: bytes, value: bytes, st: int = D) -> tuple[bytes, bytes]:
        """What `verify` asks about — a value and the credential that authorised it, never one
        without the other."""
        return value, self.cred(name, st)

    def put(self, name: bytes, value: bytes, st: int = D, cred: bytes | None = None) -> None:
        path = smt.path_of(st, name)
        self.t.invalidate(path)
        self.db.execute(
            "INSERT OR REPLACE INTO live (store, name, head, value, path, cred)"
            " VALUES (?,?,0,?,?,?)",
            (st, name, value, path, self.cred(name, st) if cred is None else cred),
        )

    def drop(self, name: bytes, st: int = D) -> None:
        self.t.invalidate(smt.path_of(st, name))
        self.db.execute("DELETE FROM live WHERE store=? AND name=?", (st, name))


class TestProofs(_Fixture):
    def test_an_empty_tree_is_the_empty_constant(self):
        self.assertEqual(self.t.root(), smt.EMPTY)

    def test_a_present_key_proves_present(self):
        self.put(b"k", b"v")
        self.assertTrue(
            smt.verify(self.t.root(), D, b"k", self.held(b"k", b"v"), self.t.prove(D, b"k"))
        )

    def test_a_present_key_proves_present_among_many(self):
        """Depth is what makes this different from the one-key case: the fold has to take the right
        turn at every branch, and a wrong turn still produces A root, just not this one."""
        for i in range(200):
            self.put(f"k{i}".encode(), f"v{i}".encode())
        root = self.t.root()
        for i in (0, 7, 99, 199):
            k = f"k{i}".encode()
            self.assertTrue(
                smt.verify(root, D, k, self.held(k, f"v{i}".encode()), self.t.prove(D, k))
            )

    def test_the_wrong_value_does_not_verify(self):
        self.put(b"k", b"v")
        self.assertFalse(
            smt.verify(self.t.root(), D, b"k", self.held(b"k", b"other"), self.t.prove(D, b"k"))
        )

    def test_an_absent_key_proves_absent_in_an_empty_tree(self):
        self.assertTrue(smt.verify(self.t.root(), D, b"nope", None, self.t.prove(D, b"nope")))

    def test_an_absent_key_proves_absent_among_many(self):
        """A walk for a missing key ends one of two ways — on emptiness, or on somebody ELSE's leaf
        occupying the slot ours would have had. Both are proofs of absence and both must verify, so
        the test finds one of each rather than assuming which a given name happens to hit."""
        for i in range(200):
            self.put(f"k{i}".encode(), f"v{i}".encode())
        root = self.t.root()

        empty_case = neighbour_case = None
        for i in range(200):
            name = f"absent{i}".encode()
            proof = self.t.prove(D, name)
            if proof.occupant is None:
                empty_case = empty_case or (name, proof)
            else:
                neighbour_case = neighbour_case or (name, proof)
        assert empty_case is not None and neighbour_case is not None, "one terminal never occurred"

        for name, proof in (empty_case, neighbour_case):
            self.assertTrue(smt.verify(root, D, name, None, proof))
            self.assertFalse(smt.verify(root, D, name, self.held(name, b"anything"), proof))

    def test_a_deleted_key_proves_absent(self):
        """The one that makes #absence-is-revocation checkable rather than asserted."""
        for i in range(50):
            self.put(f"k{i}".encode(), b"v")
        self.drop(b"k7")
        self.assertTrue(smt.verify(self.t.root(), D, b"k7", None, self.t.prove(D, b"k7")))
        self.assertFalse(
            smt.verify(self.t.root(), D, b"k7", self.held(b"k7", b"v"), self.t.prove(D, b"k7"))
        )

    def test_a_present_key_cannot_be_proved_absent(self):
        for i in range(50):
            self.put(f"k{i}".encode(), b"v")
        self.assertFalse(smt.verify(self.t.root(), D, b"k7", None, self.t.prove(D, b"k7")))

    def test_the_same_name_in_two_stores_is_two_keys(self):
        """A key's identity includes its store, so a management value and a data value of the same
        name occupy different leaves -- the same rule the `live` primary key encodes."""
        self.put(b"n", b"data", st=D)
        self.put(b"n", b"mgmt", st=M)
        root = self.t.root()
        self.assertTrue(smt.verify(root, D, b"n", self.held(b"n", b"data"), self.t.prove(D, b"n")))
        self.assertTrue(
            smt.verify(root, M, b"n", self.held(b"n", b"mgmt", st=M), self.t.prove(M, b"n"))
        )
        self.assertFalse(smt.verify(root, D, b"n", self.held(b"n", b"mgmt"), self.t.prove(D, b"n")))

    def test_a_proof_round_trips(self):
        for i in range(20):
            self.put(f"k{i}".encode(), b"v")
        proof = self.t.prove(D, b"k3")
        self.assertEqual(smt.Proof.decode(proof.encode()), proof)
        self.assertTrue(
            smt.verify(
                self.t.root(), D, b"k3", self.held(b"k3", b"v"), smt.Proof.decode(proof.encode())
            )
        )

    def test_an_absence_proof_round_trips(self):
        for i in range(20):
            self.put(f"k{i}".encode(), b"v")
        proof = self.t.prove(D, b"gone")
        self.assertEqual(smt.Proof.decode(proof.encode()), proof)


class TestForgery(_Fixture):
    """A proof is only worth what it refuses."""

    def setUp(self):
        super().setUp()
        for i in range(200):
            self.put(f"k{i}".encode(), f"v{i}".encode())
        self.root = self.t.root()

    def test_a_neighbours_proof_does_not_prove_our_key(self):
        self.assertFalse(
            smt.verify(self.root, D, b"k1", self.held(b"k1", b"v2"), self.t.prove(D, b"k2"))
        )

    def test_a_leaf_cannot_be_replayed_at_another_position(self):
        """The leaf hash binds its own path, so lifting a valid leaf into a slot where a different
        key would have gone does not fold to the root."""
        mine = self.t.prove(D, b"k5")
        stolen = self.t.prove(D, b"k6")
        assert mine.occupant is not None
        forged = smt.Proof(stolen.siblings, mine.occupant)
        self.assertFalse(smt.verify(self.root, D, b"k6", self.held(b"k6", b"v6"), forged))

    def test_an_unrelated_occupant_does_not_prove_absence(self):
        """The occupant has to sit where OUR key would have gone. Someone else's leaf from a
        different part of the tree proves nothing about ours."""
        elsewhere = self.t.prove(D, b"k9")
        proof = self.t.prove(D, b"absent")
        assert elsewhere.occupant is not None
        forged = smt.Proof(proof.siblings, elsewhere.occupant)
        self.assertFalse(smt.verify(self.root, D, b"absent", None, forged))

    def test_a_truncated_proof_does_not_verify(self):
        proof = self.t.prove(D, b"k5")
        self.assertFalse(
            smt.verify(
                self.root,
                D,
                b"k5",
                self.held(b"k5", b"v5"),
                smt.Proof(proof.siblings[:-1], proof.occupant),
            )
        )

    def test_a_proof_against_the_wrong_root_does_not_verify(self):
        proof = self.t.prove(D, b"k5")
        self.put(b"k5", b"changed")
        self.assertFalse(smt.verify(self.t.root(), D, b"k5", self.held(b"k5", b"v5"), proof))


class TestCanonicity(_Fixture):
    """The root must be a function of the live SET, never of the history that produced it. If it is
    not, two honest nodes diverge and every downstream check fires on them."""

    def _other(self) -> smt.Tree:
        self.db2 = _bare()
        return smt.Tree(self.db2)

    def _put_into(self, t: smt.Tree, db, name: bytes, value: bytes) -> None:
        path = smt.path_of(D, name)
        t.invalidate(path)
        db.execute(
            "INSERT OR REPLACE INTO live (store, name, head, value, path, cred)"
            " VALUES (?,?,0,?,?,?)",
            (D, name, value, path, self.cred(name)),
        )

    def test_insert_order_does_not_change_the_root(self):
        other = self._other()
        keys = [(f"k{i}".encode(), f"v{i}".encode()) for i in range(60)]
        for k, v in keys:
            self.put(k, v)
        for k, v in reversed(keys):
            self._put_into(other, self.db2, k, v)
        self.assertEqual(self.t.root(), other.root())

    def test_insert_then_delete_equals_never_inserted(self):
        """No history in the root. A store that held a key and dropped it is indistinguishable from
        one that never saw it, which is exactly what makes a deletion a real deletion."""
        other = self._other()
        for i in range(40):
            self.put(f"k{i}".encode(), b"v")
            self._put_into(other, self.db2, f"k{i}".encode(), b"v")
        self.put(b"transient", b"x")
        self.drop(b"transient")
        self.assertEqual(self.t.root(), other.root())

    def test_the_memo_is_only_a_cache(self):
        """Every internal node is recomputable from the leaves alone, so truncating the memo table
        costs time and cannot cost correctness -- it is why there is no split/merge code here."""
        for i in range(120):
            self.put(f"k{i}".encode(), f"v{i}".encode())
        warm = self.t.root()
        proof = self.t.prove(D, b"k42")
        self.db.execute("DELETE FROM smt_memo")
        self.assertEqual(self.t.root(), warm, "the root depended on its own cache")
        self.assertEqual(self.t.prove(D, b"k42"), proof)

    def test_a_changed_value_changes_the_root(self):
        for i in range(30):
            self.put(f"k{i}".encode(), b"v")
        before = self.t.root()
        self.put(b"k3", b"different")
        self.assertNotEqual(self.t.root(), before)

    def test_depth_stays_logarithmic(self):
        """Path compression, measured rather than asserted. A sorted-leaf tree was retracted for
        being O(n) on insert; this must stay near log2(n) or the ~768 B proof claim is fiction."""
        for i in range(1000):
            self.put(f"k{i}".encode(), b"v")
        deepest = max(len(self.t.prove(D, f"k{i}".encode()).siblings) for i in range(1000))
        self.assertLess(deepest, 32, f"depth {deepest} at 1000 keys is not logarithmic")


class TestThroughTheStore(unittest.TestCase):
    """The production path: settlement maintains the root, nobody has to remember to."""

    def setUp(self):
        self.s = store.Store()
        self.kp = crypto.Keypair.generate()

    def _write(self, name: bytes, value: bytes) -> None:
        self.s.apply((tx(self.kp, muts=(ops.Set(D, name, value),)),), auth=None)

    def test_settlement_maintains_the_root(self):
        self.assertEqual(self.s.state_root(), smt.EMPTY)
        self._write(b"k", b"v")
        self.assertTrue(
            smt.verify(
                self.s.state_root(),
                D,
                b"k",
                (b"v", self.s.credential(D, b"k")),
                self.s.prove(D, b"k"),
            )
        )

    def test_a_rebuilt_store_agrees_on_the_root(self):
        """The store's standing invariant -- incremental application equals replay -- extended to
        the root. If it held for the accumulator and not for the tree there would be two truths."""
        for i in range(30):
            self._write(f"k{i}".encode(), f"v{i}".encode())
        fresh = self.s.rebuild()
        self.assertEqual(fresh.state_root(), self.s.state_root())
        self.assertEqual(fresh.accumulator(), self.s.accumulator())


if __name__ == "__main__":
    unittest.main()


class TestDomains(unittest.TestCase):
    """Domain separation, since the three hashes here are three functions and not one function over
    three tagged messages (#state-root)."""

    def test_a_domain_changes_the_function(self):
        same = b"identical bytes"
        self.assertNotEqual(crypto.h_domain(b"one", same), crypto.h_domain(b"two", same))
        self.assertNotEqual(crypto.h_domain(b"one", same), crypto.h(same))

    def test_an_over_long_domain_is_refused(self):
        """Domains are module constants, so this fails at import rather than at the first hash."""
        with self.assertRaises(ValueError):
            crypto.h_domain(b"x" * (crypto.PERSON_SIZE + 1), b"")

    def test_a_node_is_bound_to_where_it_sits(self):
        """Same depth, same children, different prefix -- different hash. Without the position, an
        internal node's hash would be reusable anywhere the same two children appear."""
        kids = (crypto.h(b"l"), crypto.h(b"r"))
        here = smt.branch_hash(3, smt.bounds(crypto.h(b"a"), 3)[0], *kids)
        there = smt.branch_hash(3, smt.bounds(crypto.h(b"b"), 3)[0], *kids)
        self.assertNotEqual(here, there)

    def test_a_node_is_bound_to_its_depth(self):
        """And the depth is needed as well as the prefix: a padded prefix at depth 3 and at depth 4
        with a zero next bit are the same bytes."""
        path = bytes(32)
        self.assertEqual(smt.bounds(path, 3)[0], smt.bounds(path, 4)[0])
        kids = (crypto.h(b"l"), crypto.h(b"r"))
        self.assertNotEqual(
            smt.branch_hash(3, smt.bounds(path, 3)[0], *kids),
            smt.branch_hash(4, smt.bounds(path, 4)[0], *kids),
        )


class TestTheCredentialIsInTheLeaf(_Fixture):
    """`[H]` *"why not just put it in all leaves? It's an authenticated data store."*

    The root commits to WHO WAS PERMITTED to write each value, not only to the value. Without this,
    the sole thing authenticating a data row is that a quorum committed it — so a quorum at or above
    threshold could assert arbitrary state and every proof would still verify."""

    def test_the_same_value_under_a_different_credential_is_a_different_root(self):
        """The property everything else here depends on. If the root ignored the credential, the
        two stores below would be indistinguishable and a peer could swap one for the other."""
        self.put(b"k", b"v", cred=b"signed-by-alice")
        alice = self.t.root()
        self.put(b"k", b"v", cred=b"signed-by-mallory")

        self.assertNotEqual(self.t.root(), alice, "the root does not commit to the credential")

    def test_a_proof_with_the_wrong_credential_does_not_verify(self):
        """A peer serving a real value with a credential of its choosing. The value is genuine and
        the fold still refuses it, which is the whole point: authorisation travels with the row."""
        for i in range(50):
            self.put(f"k{i}".encode(), f"v{i}".encode())
        proof = self.t.prove(D, b"k7")

        self.assertTrue(smt.verify(self.t.root(), D, b"k7", self.held(b"k7", b"v7"), proof))
        self.assertFalse(
            smt.verify(self.t.root(), D, b"k7", (b"v7", self.cred(b"k9")), proof),
            "another key's valid credential vouched for this row",
        )
        self.assertFalse(smt.verify(self.t.root(), D, b"k7", (b"v7", b""), proof))

    def test_a_neighbours_credential_is_not_disclosed_by_an_absence_proof(self):
        """The occupant quotes a LEAF HASH, so proving our key absent tells the asker where someone
        else's leaf sits and nothing about what authorised it."""
        for i in range(200):
            self.put(f"k{i}".encode(), f"v{i}".encode())
        occupied = [
            p for p in (self.t.prove(D, f"absent{i}".encode()) for i in range(200)) if p.occupant
        ]
        assert occupied, "no absence proof ended on a neighbour"
        for proof in occupied:
            assert proof.occupant is not None
            self.assertNotIn(b"cred:", proof.occupant[1])
