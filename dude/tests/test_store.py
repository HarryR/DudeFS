"""Store tests. The load-bearing ones are the differential checks at the bottom: they compare the
incremental view against a from-scratch replay, so they can fail for reasons nobody enumerated."""

import functools
import random
import unittest

from dude import quorum
from dude.core import codec, crypto
from dude.core.errors import DudeError
from dude.net.address import Address, Endpoint, Scheme
from dude.store import management, ops, settle, store

D = ops.STORE_DATA


def tx(kp, preds=(), muts=(), st=ops.STORE_DATA, ts=1):
    """A signed single-store transaction. `st` is now only a default for the mutations built here —
    a Transaction itself is store-agnostic (#last-write-wins)."""
    steps = tuple(ops.Step((), _at(st, m)) for m in muts)
    if preds:
        # hang the guards on the FIRST step; with no mutations, on a guard-only step. A guard-only
        # transaction has to be expressible: "check this, write nothing" is a legitimate probe.
        if steps:
            steps = (ops.Step(tuple(preds), steps[0].mutation), *steps[1:])
        else:
            steps = (ops.Step(tuple(preds), ops.Del(st, b"\x00probe")),)
    return ops.Transaction(steps).sign(kp, ts)


def _at(st, m):
    """Re-home a mutation written without a store onto `st`.

    Carries the epoch through. It did not, and every conveyor test silently wrote `EPOCH_NONE` --
    a builder that quietly drops a field tests something other than what it says."""
    return ops.Set(st, m.name, m.value, m.epoch) if isinstance(m, ops.Set) else ops.Del(st, m.name)


def provisioned(kp: crypto.Keypair) -> tuple[store.Store, management.MgmtReader]:
    """A fresh Store provisioned with `kp` as the manager anchor, plus its MgmtReader. Tests
    that authored transactions under the pre-`auth=None`-removal shape use this so the
    anchor-is-always-authorised rule handles their writes without invoking a bypass."""
    s = store.Store()
    s.provision(kp.public)
    return s, management.MgmtReader(s)


class TestSettlement(unittest.TestCase):
    def setUp(self):
        self.kp = crypto.Keypair.generate()
        self.s, self.mgmt = provisioned(self.kp)
        self.K = crypto.NameToken(crypto.h(b"K"))
        self.J = crypto.NameToken(crypto.h(b"J"))

    def test_set_get_and_provenance(self):
        r = self.s.apply((tx(self.kp, (), (ops.Set(0, self.K, b"v1"),)),), auth=self.mgmt)
        self.assertEqual(len(r.settled), 1)
        idx, _ = r.settled[0]
        held = self.s.get(ops.STORE_DATA, self.K)
        assert held is not None
        self.assertEqual((held.provenance, held.value, held.epoch), (idx, b"v1", ops.EPOCH_NONE))
        self.assertTrue(held.cred, "a settled row kept no record of what authorised it")
        self.assertEqual(self.s.head(), idx)

    def test_absent_is_not_empty_bytes(self):
        self.s.apply((tx(self.kp, (), (ops.Set(0, self.K, b""),)),), auth=self.mgmt)
        # holds empty bytes -> present. #one-write-vocabulary: these are different facts.
        self.assertTrue(self.s.holds(ops.Holds(D, self.K, ops.value_digest(b""))))
        self.assertFalse(self.s.holds(ops.Absent(D, self.K)))

    def test_del_makes_absent(self):
        self.s.apply((tx(self.kp, (), (ops.Set(0, self.K, b"v"),)),), auth=self.mgmt)
        self.s.apply((tx(self.kp, (), (ops.Del(0, self.K),)),), auth=self.mgmt)
        self.assertIsNone(self.s.get(ops.STORE_DATA, self.K))
        self.assertTrue(self.s.holds(ops.Absent(D, self.K)))

    def test_failed_predicate_is_dropped_not_stored(self):
        bad = tx(self.kp, (ops.Holds(D, self.K, crypto.h(b"nope")),), (ops.Set(0, self.K, b"x"),))
        r = self.s.apply((bad,), auth=self.mgmt)
        self.assertEqual(r.settled, ())
        self.assertEqual(r.dropped, ((bad.op_hash, settle.Reason.GUARD),))
        self.assertEqual(self.s.head(), 0)  # nothing entered the log (#predicates)
        self.assertIsNone(self.s.get(ops.STORE_DATA, self.K))

    def test_bad_signature_is_dropped(self):
        good = tx(self.kp, (), (ops.Set(0, self.K, b"v"),))
        forged = ops.SignedTransaction(good.author, good.ts + 5, good.txn, good.sig)
        r = self.s.apply((forged,), auth=self.mgmt)
        self.assertEqual(r.dropped, ((forged.op_hash, settle.Reason.SIGNATURE),))

    def test_cas_race_first_wins_second_drops(self):
        self.s.apply((tx(self.kp, (), (ops.Set(0, self.K, b"old"),)),), auth=self.mgmt)
        d = ops.value_digest(b"old")
        a = tx(self.kp, (ops.Holds(D, self.K, d),), (ops.Set(0, self.K, b"A"),))
        b = tx(self.kp, (ops.Holds(D, self.K, d),), (ops.Set(0, self.K, b"B"),))
        r = self.s.apply((a, b), auth=self.mgmt)  # already ordered by the layer above
        self.assertEqual(len(r.settled), 1)
        self.assertEqual(len(r.dropped), 1)
        cur = self.s.get(ops.STORE_DATA, self.K)
        assert cur is not None
        self.assertEqual(cur[1], b"A")

    def test_both_unconditional_writes_settle(self):
        """#settlement: no predicates, so nothing is invalidated — both apply, last wins."""
        a = tx(self.kp, (), (ops.Set(0, self.K, b"A"),))
        b = tx(self.kp, (), (ops.Set(0, self.K, b"B"),))
        r = self.s.apply((a, b), auth=self.mgmt)
        self.assertEqual(len(r.settled), 2)
        cur = self.s.get(ops.STORE_DATA, self.K)
        assert cur is not None
        self.assertEqual(cur[1], b"B")

    def test_atomicity_within_a_transaction(self):
        """Last write wins inside one transaction (#last-write-wins)."""
        r = self.s.apply(
            (tx(self.kp, (), (ops.Set(0, self.K, b"1"), ops.Set(0, self.K, b"2"))),), auth=self.mgmt
        )
        self.assertEqual(len(r.settled), 1)
        cur = self.s.get(ops.STORE_DATA, self.K)
        assert cur is not None
        self.assertEqual(cur[1], b"2")


class TestAccumulator(unittest.TestCase):
    def setUp(self):
        self.kp = crypto.Keypair.generate()
        self.s, self.mgmt = provisioned(self.kp)

    def test_empty_state_is_identity(self):
        self.assertEqual(self.s.accumulator(), crypto.ACC_IDENTITY)

    def test_set_then_del_returns_to_identity(self):
        k = crypto.NameToken(crypto.h(b"K"))
        self.s.apply((tx(self.kp, (), (ops.Set(0, k, b"v"),)),), auth=self.mgmt)
        self.assertNotEqual(self.s.accumulator(), crypto.ACC_IDENTITY)
        self.s.apply((tx(self.kp, (), (ops.Del(0, k),)),), auth=self.mgmt)
        self.assertEqual(
            self.s.accumulator(),
            crypto.ACC_IDENTITY,
            "net-effect-nothing must fingerprint as nothing (#collect-whole-segment)",
        )

    def test_order_independence(self):
        """Two stores reaching the same live state agree on the accumulator regardless of the
        order they got there (#accumulators)."""
        names = [crypto.NameToken(crypto.h(bytes([i]))) for i in range(6)]
        vals = [b"v%d" % i for i in range(6)]
        a, b = provisioned(self.kp)[0], provisioned(self.kp)[0]
        for st, order in ((a, range(6)), (b, reversed(range(6)))):
            m = management.MgmtReader(st)
            for i in order:
                st.apply((tx(self.kp, (), (ops.Set(0, names[i], vals[i]),)),), auth=m)
        self.assertEqual(a.accumulator(), b.accumulator())

    def test_accumulator_matches_recomputation_from_live(self):
        """The maintained value must equal one folded from scratch over the live rows."""
        for i in range(12):
            n = crypto.NameToken(crypto.h(bytes([i % 5])))
            self.s.apply((tx(self.kp, (), (ops.Set(0, n, b"v%d" % i),)),), auth=self.mgmt)
        rows = self.s.db.execute("SELECT store, name, value FROM live").fetchall()
        want = functools.reduce(
            crypto.acc_add,
            (store.element(st, crypto.NameToken(n), v) for st, n, v in rows),
            crypto.ACC_IDENTITY,
        )
        self.assertEqual(self.s.accumulator(), want)


class TestReplayEquivalence(unittest.TestCase):
    """The invariant the whole design rests on: incremental == from scratch. These fail for reasons
    nobody enumerated, which is the point (#content-address, 8.6)."""

    def _randomised(self, seed):
        rng = random.Random(seed)
        # One anchor keypair drives all writes -- the test cares about state convergence
        # under random writes, not about multi-author authority. Cheaper than granting
        # authority to N keys and equally valid for the invariant being tested.
        kp = crypto.Keypair.from_seed(crypto.Seed(bytes([1] * 32)))
        s, mgmt = provisioned(kp)
        names = [crypto.NameToken(crypto.h(bytes([i]))) for i in range(5)]
        for _ in range(120):
            n = rng.choice(names)
            preds, muts = (), ()
            roll = rng.random()
            if roll < 0.25:  # CAS against what is really there
                cur = s.get(ops.STORE_DATA, n)
                d = ops.value_digest(cur[1]) if cur else crypto.h(b"absent")
                preds = (ops.Holds(D, n, d),) if cur else (ops.Absent(D, n),)
                muts = (ops.Set(0, n, bytes([rng.randrange(256)])),)
            elif roll < 0.40:  # CAS that should fail
                preds, muts = (ops.Holds(D, n, crypto.h(b"wrong")),), (ops.Set(0, n, b"z"),)
            elif roll < 0.55:
                muts = (ops.Del(0, n),)
            elif roll < 0.70:  # multi-key transaction
                m = rng.choice(names)
                muts = (ops.Set(0, n, b"a"), ops.Set(0, m, b"b"))
            else:
                muts = (ops.Set(0, n, bytes([rng.randrange(256)])),)
            s.apply((tx(kp, preds, muts, ts=rng.randrange(1, 10**6)),), auth=mgmt)
        return s

    def test_rebuild_matches_incremental(self):
        for seed in range(6):
            with self.subTest(seed=seed):
                s = self._randomised(seed)
                fresh = s.rebuild()
                self.assertEqual(s.head(), fresh.head())
                self.assertEqual(s.accumulator(), fresh.accumulator())
                self.assertEqual(
                    s.db.execute(
                        "SELECT store, name, head, value FROM live ORDER BY store, name"
                    ).fetchall(),
                    fresh.db.execute(
                        "SELECT store, name, head, value FROM live ORDER BY store, name"
                    ).fetchall(),
                )

    def test_negative_control_a_broken_fold_is_caught(self):
        """If the incremental accumulator were wrong, the differential test must notice. Prove the
        test can fail rather than trusting that it would."""
        s = self._randomised(0)
        with s.write() as w:
            w._set_meta("acc", crypto.ACC_IDENTITY)  # corrupt the cache only
        fresh = s.rebuild()
        self.assertNotEqual(s.accumulator(), fresh.accumulator())


if __name__ == "__main__":
    unittest.main()


class TestStoreIsolation(unittest.TestCase):
    """A key's identity includes its store. Keying `live` by name alone let a data write clobber a
    management value — an ACL bypass by name collision. A regression test, not a nicety."""

    def setUp(self):
        self.kp = crypto.Keypair.generate()
        self.s, self.mgmt = provisioned(self.kp)
        self.name = crypto.NameToken(crypto.h(b"config/thing"))  # ONE token, used in two stores

    def test_same_name_in_two_stores_does_not_collide(self):
        self.s.apply(
            (tx(self.kp, (), (ops.Set(0, self.name, b"mgmt"),), st=ops.STORE_MANAGEMENT),),
            auth=self.mgmt,
        )
        self.s.apply(
            (tx(self.kp, (), (ops.Set(0, self.name, b"data"),), st=ops.STORE_DATA),), auth=self.mgmt
        )
        mgmt = self.s.get(ops.STORE_MANAGEMENT, self.name)
        data = self.s.get(ops.STORE_DATA, self.name)
        assert mgmt is not None and data is not None
        self.assertEqual(mgmt[1], b"mgmt")
        self.assertEqual(data[1], b"data")
        self.assertEqual(self.s.db.execute("SELECT COUNT(*) FROM live").fetchone()[0], 2)

    def test_predicates_are_scoped_to_their_store(self):
        self.s.apply(
            (tx(self.kp, (), (ops.Set(0, self.name, b"mgmt"),), st=ops.STORE_MANAGEMENT),),
            auth=self.mgmt,
        )
        # absent in the DATA store even though present in management
        self.assertTrue(self.s.holds(ops.Absent(D, self.name)))
        self.assertFalse(self.s.holds(ops.Absent(ops.STORE_MANAGEMENT, self.name)))
        # so a data CAS on `absent` settles, and does not disturb management
        r = self.s.apply(
            (
                tx(
                    self.kp,
                    (ops.Absent(D, self.name),),
                    (ops.Set(0, self.name, b"d"),),
                    st=ops.STORE_DATA,
                ),
            ),
            auth=self.mgmt,
        )
        self.assertEqual(len(r.settled), 1)
        mgmt = self.s.get(ops.STORE_MANAGEMENT, self.name)
        assert mgmt is not None
        self.assertEqual(mgmt[1], b"mgmt")

    def test_accumulator_distinguishes_the_stores(self):
        """Two states differing only in WHICH store holds a value must not fingerprint alike."""
        a, ma = provisioned(self.kp)
        b, mb = provisioned(self.kp)
        a.apply(
            (tx(self.kp, (), (ops.Set(0, self.name, b"v"),), st=ops.STORE_MANAGEMENT),),
            auth=ma,
        )
        b.apply(
            (tx(self.kp, (), (ops.Set(0, self.name, b"v"),), st=ops.STORE_DATA),),
            auth=mb,
        )
        self.assertNotEqual(a.accumulator(), b.accumulator())


class TestCrossStorePredicates(unittest.TestCase):
    """A predicate carries its own store, so a transaction may read one store while writing
    another — e.g. a data write conditional on management state. Reads are open; the ACL governs
    writes (#coarse-acl)."""

    def setUp(self):
        self.kp = crypto.Keypair.generate()
        self.s, self.mgmt = provisioned(self.kp)
        self.flag = crypto.NameToken(crypto.h(b"mgmt/flag"))
        self.K = crypto.NameToken(crypto.h(b"data/K"))

    def test_data_write_gated_on_management_state(self):
        self.s.apply(
            (tx(self.kp, (), (ops.Set(0, self.flag, b"on"),), st=ops.STORE_MANAGEMENT),),
            auth=self.mgmt,
        )
        # settles: the management predicate holds
        good = tx(
            self.kp,
            (ops.Holds(ops.STORE_MANAGEMENT, self.flag, ops.value_digest(b"on")),),
            (ops.Set(0, self.K, b"v"),),
            st=D,
        )
        self.assertEqual(len(self.s.apply((good,), auth=self.mgmt).settled), 1)
        # drops: same shape, wrong expectation about the OTHER store
        bad = tx(
            self.kp,
            (ops.Holds(ops.STORE_MANAGEMENT, self.flag, ops.value_digest(b"off")),),
            (ops.Set(0, self.K, b"w"),),
            st=D,
        )
        r = self.s.apply((bad,), auth=self.mgmt)
        self.assertEqual(r.dropped, ((bad.op_hash, settle.Reason.GUARD),))

    def test_predicate_store_survives_encoding(self):
        t = tx(
            self.kp,
            (ops.Absent(7, self.K), ops.Holds(9, self.flag, crypto.h(b"z"))),
            (ops.Set(0, self.K, b"v"),),
            st=D,
        )
        back = ops.SignedTransaction.decode(t.raw)
        self.assertEqual(back, t)
        self.assertEqual([p.store for p in back.txn.guards], [7, 9])
        self.assertTrue(back.verify())


class TestFailureDomains(unittest.TestCase):
    """Rack-aware placement, generalised. `experiments/32-failure-domains.py`.

    The invariant is one line — no domain may hold more than `rule.max_domain(n)` nodes — and it is
    sufficient on its own, because that bound is below the quorum size, so no quorum can be drawn
    from a single domain."""

    def setUp(self):
        self.mgr = crypto.Keypair.generate()
        self.store = store.Store()
        self.store.provision(self.mgr.public)
        self.mgmt = management.MgmtWriter(self.store)
        self.store.apply(
            (
                self.mgmt.authorise(
                    self.mgr.public,
                    management.Role.MANAGER,
                    frozenset({ops.STORE_MANAGEMENT, ops.STORE_DATA}),
                    frozenset(),
                    pop=self.mgr.prove_possession(),
                    cert=management.Cert.sign_grant(
                        self.mgr, self.mgr.public, management.Role.MANAGER
                    ),
                ).sign(self.mgr, 1),
            ),
            auth=self.mgmt,
        )

    def _add(self, n, domains):
        kp = crypto.Keypair.generate()
        tx = self.mgmt.add_node(
            kp.public,
            (Endpoint(Address(Scheme.INPROC, f"n{n}")),),
            management.Cert.sign_roster(self.mgr, kp.public),
            commitment_signer=self.mgr,
            domains=frozenset(domains),
        )
        self.store.apply((tx.sign(self.mgr, 1),), auth=self.mgmt)
        return kp

    def test_availability_binds_not_safety(self):
        """At n=11 two-thirds gives spare=3 and tolerates=4. Seizure removes AVAILABILITY, so the
        smaller bound is the real one — the two move in opposite directions (see `spare`)."""
        self.assertEqual(quorum.spare(11), 3)
        self.assertEqual(quorum.tolerates(11), 4)
        self.assertEqual(quorum.max_domain(11), 3)

    def test_a_sound_spread_is_advisory_clean(self):
        """3-3-3-2 across four providers is sound at n=11: max_domain(11) is 3. `domain_advisory`
        returns empty (no over-count domains)."""
        counts = {b"p:a": 3, b"p:b": 3, b"p:c": 3, b"p:d": 2}
        self.assertEqual(quorum.domain_advisory(counts, 11), {})

    def test_concentrated_spread_shows_up_in_advisory_only(self):
        """A 4-4-3 spread at n=11 has two provider-groups over the max_domain(11)=3 bound.
        `domain_advisory` reports them; `change_roster` does NOT refuse on this (composition
        is advisory only, #quorum-gate). Rack-awareness that severely interferes with routine
        operation is worse than none -- enforcing this at the authoring boundary blocks
        legitimate incremental improvements to a concentrated cluster."""
        counts = {b"p:a": 4, b"p:b": 4, b"p:c": 3}
        self.assertEqual(quorum.domain_advisory(counts, 11), {b"p:a": 4, b"p:b": 4})

    def test_add_node_no_longer_refuses_on_composition(self):
        """The old strict-refusal was blocking legitimate growth (single-provider first steps,
        dilution of a concentrated cluster). `change_roster` refuses only on `would_brick`;
        composition remains advisory via `check_domains`."""
        # Add multiple nodes into the same provider without any raise -- would have failed the
        # old strict `add_node`.
        self._add(0, {b"p:a"})
        self._add(1, {b"p:a"})
        self._add(2, {b"p:a"})
        self._add(3, {b"p:a"})  # would have hit "n=4, max_domain=1" refusal previously
        # And the advisory picks up the concentration as guidance for the operator.
        adv = self.mgmt.check_domains()
        # At n=4, max_domain(4)=1, so p:a with 4 nodes is over the bound.
        self.assertIn(b"p:a", adv)
        self.assertEqual(adv[b"p:a"], 4)

    def test_max_domain_arithmetic(self):
        """The advisory ceiling is `min(spare, tolerates)`. At small n both are tiny; grows
        slowly. This drives what the operator SEES in `check_domains`, not what they can DO."""
        self.assertEqual(quorum.max_domain(1), 0)  # nothing tolerable
        self.assertEqual(quorum.max_domain(4), 1)
        self.assertEqual(quorum.max_domain(5), 1)
        self.assertEqual(quorum.max_domain(7), 2)
        self.assertEqual(quorum.max_domain(11), 3)

    def test_domains_are_opaque(self):
        """Nothing parses a label. `rack:` and `psu:` need no schema change, and a nonsense label is
        counted like any other rather than rejected."""
        kp = self._add(0, {b"rack:7", b"psu:left", b"\xff\x00not-utf8"})
        rec = self.mgmt.nodes()[kp.public]
        self.assertIn(b"\xff\x00not-utf8", rec.domains)
        self.assertEqual(len(rec.domains), 3)

    def test_domain_groups_and_roundtrip(self):
        a = self._add(0, {b"p:x", b"c:de"})
        b = self._add(1, {b"p:x", b"c:fr"})
        groups = self.mgmt.domain_groups()
        self.assertEqual(groups[b"p:x"], frozenset({a.public, b.public}))
        self.assertEqual(groups[b"c:de"], frozenset({a.public}))
        self.assertEqual(
            self.mgmt.nodes()[a.public].endpoints,
            (Endpoint(Address(Scheme.INPROC, "n0")),),
        )


class TestMultiSigRoundTrip(unittest.TestCase):
    """A regression for a bug that shipped silently: splitting `_ed25519_verify` into typed errors
    made it RAISE and return None, so `if not _ed25519_verify(...)` was vacuously true and every
    multisig verification returned False. Nothing exercised the path, so nothing caught it."""

    def setUp(self):
        self.kps = [crypto.Keypair.generate() for _ in range(5)]
        self.roster = sorted(k.public for k in self.kps)

    def _sign(self, msg, who):
        shares = {self.roster.index(k.public): crypto.sign_share(k._seed, msg) for k in who}
        return crypto.MultiSig.combine(shares, len(self.roster))

    def test_a_genuine_multisig_verifies(self):
        ms = self._sign(b"claim", self.kps[:4])
        self.assertTrue(ms.verify(b"claim", self.roster))

    def test_a_different_message_does_not(self):
        ms = self._sign(b"claim", self.kps[:4])
        self.assertFalse(ms.verify(b"other", self.roster))

    def test_a_signature_from_outside_the_roster_does_not(self):
        stranger = crypto.Keypair.generate()
        ms = self._sign(b"claim", self.kps[:3])
        forged = list(ms.sigs)
        forged[0] = crypto.sign_share(stranger._seed, b"claim")
        self.assertFalse(crypto.MultiSig(ms.bitmap, tuple(forged)).verify(b"claim", self.roster))

    def test_the_bitmap_names_who_signed(self):
        ms = self._sign(b"claim", [self.kps[0], self.kps[2]])
        self.assertEqual(
            sorted(ms.indices(len(self.roster))),
            sorted([self.roster.index(self.kps[0].public), self.roster.index(self.kps[2].public)]),
        )
        self.assertEqual(ms.count(len(self.roster)), 2)


class TestTransferAndSettlementRace(unittest.TestCase):
    """A transaction can now reach a node by two roads — settlement through the quorum, and log
    transfer from a peer that got there first. A node catching up mid-bucket sees both."""

    def setUp(self):
        self.s = store.Store()
        self.kp = crypto.Keypair.generate()
        # Provision the test key as the anchor so its writes pass authority via the anchor-
        # is-always-authorised rule -- the shape that replaced `auth=None` (Path (a)).
        self.s.provision(self.kp.public)
        self.mgmt = management.MgmtReader(self.s)

    def test_a_transaction_already_in_the_log_is_dropped_not_raised(self):
        """`entry.op_hash UNIQUE` is what makes a settled transaction unrepeatable, and it used to
        enforce that by throwing out of a frame handler — a routine race reported as corruption."""
        t = tx(self.kp, muts=(ops.Set(ops.STORE_DATA, b"k", b"v"),))
        first = self.s.apply((t,), auth=self.mgmt)
        self.assertEqual(len(first.settled), 1)

        again = self.s.apply((t,), auth=self.mgmt)  # must not raise
        self.assertEqual(again.settled, ())
        self.assertEqual([d.why for d in again.dropped], [settle.Reason.SETTLED])
        self.assertEqual(self.s.head(), 1, "the duplicate took a log position")

    def test_a_duplicate_within_one_batch_is_dropped_not_raised(self):
        """The cross-batch case above is held by the pre-loop settled_hashes snapshot; a duplicate
        WITHIN one block's batch is not in that snapshot, and acceptors cannot screen bodies, so a
        Byzantine proposer's ratified block used to crash every honest applier identically with
        sqlite3.IntegrityError through commit_block -- and again after restart, since the block
        re-arrives on sync. Driven through commit_block because that is the boundary it escaped."""
        t = tx(self.kp, muts=(ops.Set(ops.STORE_DATA, b"k", b"v"),))
        got = self.s.commit_block(
            1,
            first_height=1,
            block_bytes=b"b1",
            block_hash=crypto.h(b"b1"),
            batch=(t, t),
            auth=self.mgmt,
        )
        self.assertEqual(len(got.settled), 1)
        self.assertEqual([d.why for d in got.dropped], [settle.Reason.SETTLED])
        self.assertEqual(self.s.head(), 1, "the duplicate must not take a log position")

    def test_the_survivors_of_a_mixed_batch_still_land(self):
        """One duplicate must not take the batch down with it."""
        old = tx(self.kp, muts=(ops.Set(ops.STORE_DATA, b"k", b"v"),))
        self.s.apply((old,), auth=self.mgmt)
        fresh = tx(self.kp, muts=(ops.Set(ops.STORE_DATA, b"j", b"w"),), ts=2)

        got = self.s.apply((old, fresh), auth=self.mgmt)
        self.assertEqual(len(got.settled), 1)
        self.assertEqual([d.why for d in got.dropped], [settle.Reason.SETTLED])
        self.assertIsNotNone(self.s.get(ops.STORE_DATA, b"j"))


class TestTransactionEncoding(unittest.TestCase):
    """`op_hash` is `h(raw)` and `raw` is REBUILT from the decoded fields, so the content address
    of a relayed transaction is only stable if decode-then-encode is the identity. That rests on
    the codec being canonical; this pins the dependency rather than assuming it."""

    def setUp(self):
        self.kp = crypto.Keypair.generate()

    def test_decode_then_encode_reproduces_the_received_bytes(self):
        signed = tx(
            self.kp,
            muts=(ops.Set(ops.STORE_DATA, b"k", b"v", 7), ops.Del(ops.STORE_DATA, b"j")),
            preds=(ops.Absent(ops.STORE_DATA, b"j"),),
        )
        raw = signed.raw
        self.assertEqual(ops.SignedTransaction.decode(raw).raw, raw)
        self.assertEqual(ops.SignedTransaction.decode(raw).op_hash, signed.op_hash)

    def test_a_non_canonical_re_encoding_is_refused_rather_than_normalised(self):
        """A liberal decoder would accept these and silently re-address the transaction."""
        signed = tx(self.kp, muts=(ops.Set(ops.STORE_DATA, b"k", b"v"),))
        for bad in (signed.raw + b"e", b"li00ee", b"l" + signed.raw):
            with self.assertRaises(DudeError):
                ops.SignedTransaction.decode(bad)

    def test_wrong_field_count_raises_at_both_nesting_levels(self):
        """2 outer fields wrapping a 3-field body. A field added to one half without the other
        changes what is signed or what is hashed, in silence (CLAUDE.md trap 1)."""
        for wrong in (1, 3):
            with self.assertRaises(DudeError):
                ops.SignedTransaction.decode(codec.encode([b""] * wrong))
        for wrong in (2, 4):
            body = codec.encode([b""] * wrong)
            with self.assertRaises(DudeError):
                ops.SignedTransaction.decode(codec.encode([body, b"\x00" * 64]))
