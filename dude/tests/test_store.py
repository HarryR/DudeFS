"""Store tests. The load-bearing ones are the differential checks at the bottom: they compare the
incremental view against a from-scratch replay, so they can fail for reasons nobody enumerated."""

import functools
import random
import unittest

from dude import quorum
from dude.core import codec, crypto
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
    """Re-home a mutation written without a store onto `st`."""
    return ops.Set(st, m.name, m.value) if isinstance(m, ops.Set) else ops.Del(st, m.name)


class TestSettlement(unittest.TestCase):
    def setUp(self):
        self.s = store.Store()
        self.kp = crypto.Keypair.generate()
        self.K = crypto.NameToken(crypto.h(b"K"))
        self.J = crypto.NameToken(crypto.h(b"J"))

    def test_set_get_and_provenance(self):
        r = self.s.apply((tx(self.kp, (), (ops.Set(0, self.K, b"v1"),)),))
        self.assertEqual(len(r.settled), 1)
        idx, _ = r.settled[0]
        self.assertEqual(self.s.get(ops.STORE_DATA, self.K), (idx, b"v1"))
        self.assertEqual(self.s.head(), idx)

    def test_absent_is_not_empty_bytes(self):
        self.s.apply((tx(self.kp, (), (ops.Set(0, self.K, b""),)),))
        # holds empty bytes -> present. #one-write-vocabulary: these are different facts.
        self.assertTrue(self.s.holds(ops.Holds(D, self.K, ops.value_digest(b""))))
        self.assertFalse(self.s.holds(ops.Absent(D, self.K)))

    def test_del_makes_absent(self):
        self.s.apply((tx(self.kp, (), (ops.Set(0, self.K, b"v"),)),))
        self.s.apply((tx(self.kp, (), (ops.Del(0, self.K),)),))
        self.assertIsNone(self.s.get(ops.STORE_DATA, self.K))
        self.assertTrue(self.s.holds(ops.Absent(D, self.K)))

    def test_failed_predicate_is_dropped_not_stored(self):
        bad = tx(self.kp, (ops.Holds(D, self.K, crypto.h(b"nope")),), (ops.Set(0, self.K, b"x"),))
        r = self.s.apply((bad,))
        self.assertEqual(r.settled, ())
        self.assertEqual(r.dropped, ((bad.op_hash, settle.Reason.GUARD),))
        self.assertEqual(self.s.head(), 0)  # nothing entered the log (#predicates)
        self.assertIsNone(self.s.get(ops.STORE_DATA, self.K))

    def test_bad_signature_is_dropped(self):
        good = tx(self.kp, (), (ops.Set(0, self.K, b"v"),))
        forged = ops.SignedTransaction(good.author, good.ts + 5, good.txn, good.sig)
        r = self.s.apply((forged,))
        self.assertEqual(r.dropped, ((forged.op_hash, settle.Reason.SIGNATURE),))

    def test_cas_race_first_wins_second_drops(self):
        self.s.apply((tx(self.kp, (), (ops.Set(0, self.K, b"old"),)),))
        d = ops.value_digest(b"old")
        a = tx(self.kp, (ops.Holds(D, self.K, d),), (ops.Set(0, self.K, b"A"),))
        b = tx(self.kp, (ops.Holds(D, self.K, d),), (ops.Set(0, self.K, b"B"),))
        r = self.s.apply((a, b))  # already ordered by the layer above
        self.assertEqual(len(r.settled), 1)
        self.assertEqual(len(r.dropped), 1)
        cur = self.s.get(ops.STORE_DATA, self.K)
        assert cur is not None
        self.assertEqual(cur[1], b"A")

    def test_both_unconditional_writes_settle(self):
        """#settlement: no predicates, so nothing is invalidated — both apply, last wins."""
        a = tx(self.kp, (), (ops.Set(0, self.K, b"A"),))
        b = tx(self.kp, (), (ops.Set(0, self.K, b"B"),))
        r = self.s.apply((a, b))
        self.assertEqual(len(r.settled), 2)
        cur = self.s.get(ops.STORE_DATA, self.K)
        assert cur is not None
        self.assertEqual(cur[1], b"B")

    def test_atomicity_within_a_transaction(self):
        """Last write wins inside one transaction (#last-write-wins)."""
        r = self.s.apply((tx(self.kp, (), (ops.Set(0, self.K, b"1"), ops.Set(0, self.K, b"2"))),))
        self.assertEqual(len(r.settled), 1)
        cur = self.s.get(ops.STORE_DATA, self.K)
        assert cur is not None
        self.assertEqual(cur[1], b"2")


class TestAccumulator(unittest.TestCase):
    def setUp(self):
        self.s = store.Store()
        self.kp = crypto.Keypair.generate()

    def test_empty_state_is_identity(self):
        self.assertEqual(self.s.accumulator(), crypto.ACC_IDENTITY)

    def test_set_then_del_returns_to_identity(self):
        k = crypto.NameToken(crypto.h(b"K"))
        self.s.apply((tx(self.kp, (), (ops.Set(0, k, b"v"),)),))
        self.assertNotEqual(self.s.accumulator(), crypto.ACC_IDENTITY)
        self.s.apply((tx(self.kp, (), (ops.Del(0, k),)),))
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
        a, b = store.Store(), store.Store()
        for st, order in ((a, range(6)), (b, reversed(range(6)))):
            for i in order:
                st.apply((tx(self.kp, (), (ops.Set(0, names[i], vals[i]),)),))
        self.assertEqual(a.accumulator(), b.accumulator())

    def test_accumulator_matches_recomputation_from_live(self):
        """The maintained value must equal one folded from scratch over the live rows."""
        for i in range(12):
            n = crypto.NameToken(crypto.h(bytes([i % 5])))
            self.s.apply((tx(self.kp, (), (ops.Set(0, n, b"v%d" % i),)),))
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
        s = store.Store()
        kps = [crypto.Keypair.from_seed(crypto.Seed(bytes([i] * 32))) for i in range(1, 4)]
        names = [crypto.NameToken(crypto.h(bytes([i]))) for i in range(5)]
        for _ in range(120):
            kp = rng.choice(kps)
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
            s.apply((tx(kp, preds, muts, ts=rng.randrange(1, 10**6)),))
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
                # Segments replaced the `touch` chain: a rebuilt store must land every entry in
                # the same segment, since the id is derived arithmetically from the settled index
                # and never negotiated.
                self.assertEqual(
                    s.db.execute("SELECT idx, segment FROM entry ORDER BY idx").fetchall(),
                    fresh.db.execute("SELECT idx, segment FROM entry ORDER BY idx").fetchall(),
                )
                self.assertEqual(
                    s.db.execute("SELECT id, acc FROM segment ORDER BY id").fetchall(),
                    fresh.db.execute("SELECT id, acc FROM segment ORDER BY id").fetchall(),
                )

    def test_negative_control_a_broken_fold_is_caught(self):
        """If the incremental accumulator were wrong, the differential test must notice. Prove the
        test can fail rather than trusting that it would."""
        s = self._randomised(0)
        s._set_meta("acc", crypto.ACC_IDENTITY)  # corrupt the cache only
        fresh = s.rebuild()
        self.assertNotEqual(s.accumulator(), fresh.accumulator())


if __name__ == "__main__":
    unittest.main()


class TestStoreIsolation(unittest.TestCase):
    """A key's identity includes its store. Keying `live` by name alone let a data write clobber a
    management value — an ACL bypass by name collision. A regression test, not a nicety."""

    def setUp(self):
        self.s = store.Store()
        self.kp = crypto.Keypair.generate()
        self.name = crypto.NameToken(crypto.h(b"config/thing"))  # ONE token, used in two stores

    def test_same_name_in_two_stores_does_not_collide(self):
        self.s.apply((tx(self.kp, (), (ops.Set(0, self.name, b"mgmt"),), st=ops.STORE_MANAGEMENT),))
        self.s.apply((tx(self.kp, (), (ops.Set(0, self.name, b"data"),), st=ops.STORE_DATA),))
        mgmt = self.s.get(ops.STORE_MANAGEMENT, self.name)
        data = self.s.get(ops.STORE_DATA, self.name)
        assert mgmt is not None and data is not None
        self.assertEqual(mgmt[1], b"mgmt")
        self.assertEqual(data[1], b"data")
        self.assertEqual(self.s.db.execute("SELECT COUNT(*) FROM live").fetchone()[0], 2)

    def test_predicates_are_scoped_to_their_store(self):
        self.s.apply((tx(self.kp, (), (ops.Set(0, self.name, b"mgmt"),), st=ops.STORE_MANAGEMENT),))
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
            )
        )
        self.assertEqual(len(r.settled), 1)
        mgmt = self.s.get(ops.STORE_MANAGEMENT, self.name)
        assert mgmt is not None
        self.assertEqual(mgmt[1], b"mgmt")

    def test_accumulator_distinguishes_the_stores(self):
        """Two states differing only in WHICH store holds a value must not fingerprint alike."""
        a, b = store.Store(), store.Store()
        a.apply((tx(self.kp, (), (ops.Set(0, self.name, b"v"),), st=ops.STORE_MANAGEMENT),))
        b.apply((tx(self.kp, (), (ops.Set(0, self.name, b"v"),), st=ops.STORE_DATA),))
        self.assertNotEqual(a.accumulator(), b.accumulator())


class TestCrossStorePredicates(unittest.TestCase):
    """A predicate carries its own store, so a transaction may read one store while writing
    another — e.g. a data write conditional on management state. Reads are open; the ACL governs
    writes (#coarse-acl)."""

    def setUp(self):
        self.s = store.Store()
        self.kp = crypto.Keypair.generate()
        self.flag = crypto.NameToken(crypto.h(b"mgmt/flag"))
        self.K = crypto.NameToken(crypto.h(b"data/K"))

    def test_data_write_gated_on_management_state(self):
        self.s.apply((tx(self.kp, (), (ops.Set(0, self.flag, b"on"),), st=ops.STORE_MANAGEMENT),))
        # settles: the management predicate holds
        good = tx(
            self.kp,
            (ops.Holds(ops.STORE_MANAGEMENT, self.flag, ops.value_digest(b"on")),),
            (ops.Set(0, self.K, b"v"),),
            st=D,
        )
        self.assertEqual(len(self.s.apply((good,)).settled), 1)
        # drops: same shape, wrong expectation about the OTHER store
        bad = tx(
            self.kp,
            (ops.Holds(ops.STORE_MANAGEMENT, self.flag, ops.value_digest(b"off")),),
            (ops.Set(0, self.K, b"w"),),
            st=D,
        )
        r = self.s.apply((bad,))
        self.assertEqual(r.dropped, ((bad.op_hash, settle.Reason.GUARD),))

    def test_conflict_is_per_store_pair(self):
        """The same name in two stores is two keys, so one cannot falsify the other."""
        writer_mgmt = tx(self.kp, (), (ops.Set(0, self.flag, b"x"),), st=ops.STORE_MANAGEMENT)
        reader_data = tx(self.kp, (ops.Holds(D, self.flag, ops.value_digest(b"y")),), (), st=D)
        self.assertFalse(ops.conflicts(writer_mgmt, reader_data))
        # ...but the same store DOES conflict
        reader_mgmt = tx(
            self.kp,
            (ops.Holds(ops.STORE_MANAGEMENT, self.flag, ops.value_digest(b"y")),),
            (),
            st=ops.STORE_MANAGEMENT,
        )
        self.assertTrue(ops.conflicts(writer_mgmt, reader_mgmt))

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
        self.mgmt = management.Management(self.store)
        self.store.apply(
            (
                self.mgmt.authorise(
                    self.mgr.public,
                    management.Role.MANAGER,
                    frozenset({ops.STORE_MANAGEMENT, ops.STORE_DATA}),
                    frozenset(),
                    self.mgr.prove_possession(),
                ).sign(self.mgr, 1),
            )
        )

    def _add(self, n, domains):
        kp = crypto.Keypair.generate()
        tx = self.mgmt.add_node(kp.public, (f"inproc:{n}".encode(),), frozenset(domains))
        self.store.apply((tx.sign(self.mgr, 1),), auth=self.mgmt)
        return kp

    def test_availability_binds_not_safety(self):
        """At n=11 two-thirds gives spare=3 and tolerates=4. Seizure removes AVAILABILITY, so the
        smaller bound is the real one — the two move in opposite directions (see `spare`)."""
        rule = quorum.TWO_THIRDS
        self.assertEqual(rule.spare(11), 3)
        self.assertEqual(rule.tolerates(11), 4)
        self.assertEqual(rule.max_domain(11), 3)

    def test_a_sound_spread_passes_the_check_at_its_target_size(self):
        """3-3-3-2 across four providers is sound at n=11: max_domain(11) is 3."""
        recs = {}
        for prov in ["p:a"] * 3 + ["p:b"] * 3 + ["p:c"] * 3 + ["p:d"] * 2:
            kp = crypto.Keypair.generate()
            recs[kp.public] = management.NodeRecord(kp.public, (b"x",), frozenset({prov.encode()}))
        self.assertEqual(management._violations(recs, quorum.TWO_THIRDS), {})

    def test_a_sound_roster_may_be_unreachable_one_node_at_a_time(self):
        """The growth constraint, found by implementing the check.

        The bound TIGHTENS as `n` falls, so an arrangement valid at the target size can be
        refused on
        the way there: 3-3-3-2 is fine at n=11, but at n=4 the bound is 1. A target roster must be
        reached by a BATCHED change, not by repeated `add_node`."""
        self.assertEqual(quorum.TWO_THIRDS.max_domain(11), 3)  # 3 per provider is fine at target
        self.assertEqual(quorum.TWO_THIRDS.max_domain(4), 1)  # ...but only 1 on the way there
        self._add(0, {b"p:x"})
        self._add(1, {b"p:y"})
        self._add(2, {b"p:a"})
        with self.assertRaises(management.ManagementError):
            self._add(3, {b"p:a"})  # the SECOND p:a, at n=4 where the bound is 1

    def test_a_concentrated_spread_is_refused(self):
        """Refused at the point it would break, not discovered later by an operator reading a
        spreadsheet of eleven country names."""
        recs = {}
        for prov in ["p:a"] * 4 + ["p:b"] * 4 + ["p:c"] * 3:
            kp = crypto.Keypair.generate()
            recs[kp.public] = management.NodeRecord(kp.public, (b"x",), frozenset({prov.encode()}))
        bad = management._violations(recs, quorum.TWO_THIRDS)
        self.assertEqual(bad, {b"p:a": 4, b"p:b": 4})  # 4-4-3 at n=11: two groups over the bound

    def test_the_bound_is_vacuous_while_the_roster_is_too_small(self):
        """`max_domain` is 0 below n=4, because no placement makes a 1-node roster survivable.
        Enforcing it there would forbid the FIRST node and make bootstrap impossible."""
        self.assertEqual(quorum.TWO_THIRDS.max_domain(1), 0)
        self._add(0, {b"p:a"})  # must not raise
        self.assertEqual(self.mgmt.check_domains(), {})

    def test_adding_a_node_can_reduce_tolerance(self):
        """The counter-intuitive case, and the reason the check runs on every roster change: `f`
        falls out of `n`, so growing the roster can shrink what any one domain may hold."""
        self.assertEqual(quorum.TWO_THIRDS.max_domain(4), 1)
        self.assertEqual(quorum.TWO_THIRDS.max_domain(5), 1)
        self.assertEqual(quorum.TWO_THIRDS.max_domain(7), 2)

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
        self.assertEqual(self.mgmt.nodes()[a.public].addresses, (b"inproc:0",))

    def test_a_record_without_domains_still_reads(self):
        """The pre-domains shape is a shorter well-defined form, not a malformed one."""
        kp = crypto.Keypair.generate()
        raw = codec.encode([b"inproc:legacy"])
        self.store.apply(
            (
                ops.writes(ops.Set(ops.STORE_MANAGEMENT, management.P_NODE + kp.public, raw)).sign(
                    self.mgr, 1
                ),
            ),
            auth=self.mgmt,
        )
        rec = self.mgmt.nodes()[kp.public]
        self.assertEqual(rec.addresses, (b"inproc:legacy",))
        self.assertEqual(rec.domains, frozenset())


class TestSegments(unittest.TestCase):
    """Segments replace entry-level compaction. A segment is a PHYSICAL slice of the one logical
    log, collected WHOLE — so there is no scattered drop set, no chain to splice, and no run-length
    problem, because a segment IS a run by construction."""

    def setUp(self):
        self.kp = crypto.Keypair.generate()
        self.s = store.Store()
        self.s.SEGMENT_WIDTH = 4  # small, so a test can cross a boundary in a few writes
        self.K = crypto.h(b"K")

    def _set(self, val, key=None):
        tx = ops.writes(ops.Set(ops.STORE_DATA, key or self.K, val)).sign(self.kp, 1)
        return self.s.apply((tx,))

    def test_segment_id_is_derived_from_the_settled_index(self):
        """Arithmetic on the SETTLED index, never the author's clock. Computed, never negotiated —
        so two nodes assign the same segment with no communication, and a late transaction cannot
        land in a segment that has already been collected."""
        for i in range(9):
            self._set(f"v{i}".encode())
        rows = self.s.db.execute("SELECT idx, segment FROM entry ORDER BY idx").fetchall()
        self.assertEqual([seg for _, seg in rows], [0, 0, 0, 1, 1, 1, 1, 2, 2])
        self.assertEqual(self.s.segment_of(4), 1)

    def test_collection_is_refused_while_a_segment_holds_live_data(self):
        """The refusal IS the safety property: a segment that silently collected live values would
        lose committed state, which is the one failure this system exists to prevent."""
        self._set(b"v0")
        for i in range(5):  # move the head past segment 0 so the current-segment guard is not hit
            self._set(f"x{i}".encode(), key=crypto.h(f"o{i}".encode()))
        self.assertTrue(self.s.stragglers(0))
        with self.assertRaises(store.StoreError) as cm:
            self.s.collect(0)
        self.assertIn("live value", str(cm.exception))

    def test_a_segment_whose_writes_were_all_superseded_collects_whole(self):
        """The ordinary case: later writes supersede earlier ones, so the old segment goes."""
        for i in range(8):
            self._set(f"v{i}".encode())
        self.assertEqual(self.s.stragglers(0), ())  # everything in segment 0 was superseded
        before_state, before_head = self.s.accumulator(), self.s.head()
        self.s.collect(0)
        self.assertNotIn(0, self.s.segments())
        self.assertEqual(self.s.accumulator(), before_state, "state must survive collection")
        self.assertGreater(self.s.head(), before_head, "the collection is itself an entry")
        held = self.s.get(ops.STORE_DATA, self.K)
        assert held is not None
        self.assertEqual(held.value, b"v7")

    def test_migration_is_what_makes_segment_zero_collectable(self):
        """Genesis-shaped data is live for the life of the log, so without migration the first
        segment can NEVER be collected. This is the floor Fable's review predicted."""
        self._set(b"only")
        for i in range(5):  # push the head into a later segment; segment 0 is now drainable
            self._set(f"x{i}".encode(), key=crypto.h(f"other{i}".encode()))
        pinned = self.s.stragglers(0)
        self.assertTrue(pinned, "segment 0 still pins live values")
        before = self.s.accumulator()
        moved = self.s.migrate(0, self.kp, now=2)
        self.assertEqual(len(moved), len(pinned))
        self.assertEqual(self.s.accumulator(), before, "same-value migration is A_state-invariant")
        self.assertEqual(self.s.stragglers(0), ())
        self.s.collect(0)  # now possible
        self.assertNotIn(0, self.s.segments())
        held = self.s.get(ops.STORE_DATA, self.K)
        assert held is not None
        self.assertEqual(held.value, b"only")

    def test_the_current_segment_cannot_be_collected(self):
        """Draining a segment into ITSELF is a no-op: migration writes at the head, so the straggler
        reappears at a later index in the same segment. Only a segment the log has moved past can be
        drained at all."""
        self._set(b"v0")
        with self.assertRaises(store.StoreError) as cm:
            self.s.collect(self.s.segment_of(self.s.head()))
        self.assertIn("still current", str(cm.exception))

    def test_the_log_accumulator_loses_exactly_the_collected_segment(self):
        """ONE subtraction, not a per-entry fold. That is what a segment buys."""
        for i in range(8):
            self._set(f"v{i}".encode())
        seg_acc = crypto.Accumulator(
            self.s.db.execute("SELECT acc FROM segment WHERE id=0").fetchone()[0]
        )
        before = self.s.log_accumulator()
        self.s.collect(0)
        expected = crypto.acc_sub(before, seg_acc)
        # the collection entry is itself logged, so add its own element back
        collected_at = self.s.head()
        oh = self.s.db.execute("SELECT op_hash FROM entry WHERE idx=?", (collected_at,)).fetchone()
        expected = crypto.acc_add(expected, store.log_element(collected_at, crypto.Digest(oh[0])))
        self.assertEqual(self.s.log_accumulator(), expected)

    def test_a_collected_log_replays_to_the_same_state(self):
        """A joiner replaying the surviving entries reaches the identical fold — the property the
        whole scheme rests on."""
        for i in range(8):
            self._set(f"v{i}".encode())
        self._set(b"other", key=crypto.h(b"J"))
        self.s.collect(0)
        fresh = self.s.rebuild()
        self.assertEqual(fresh.accumulator(), self.s.accumulator())
        held = fresh.get(ops.STORE_DATA, self.K)
        assert held is not None
        self.assertEqual(held.value, b"v7")
        held = fresh.get(ops.STORE_DATA, crypto.h(b"J"))
        assert held is not None
        self.assertEqual(held.value, b"other")


class TestCollectionIsRatified(unittest.TestCase):
    """S1: collection deletes the joiner's only other verification path, so the collect entry must
    carry a quorum-ratified `(height, A_state)`. An unratified collection is one nobody checks."""

    def setUp(self):
        self.mgr = crypto.Keypair.generate()
        self.nodes = [crypto.Keypair.generate() for _ in range(3)]
        self.s = store.Store()
        self.s.SEGMENT_WIDTH = 4
        self.mgmt = management.Management(self.s)
        tx = self.mgmt.authorise(
            self.mgr.public,
            management.Role.MANAGER,
            frozenset({ops.STORE_MANAGEMENT, ops.STORE_DATA}),
            frozenset(),
            self.mgr.prove_possession(),
        )
        self.s.apply((tx.sign(self.mgr, 1),))
        for i, kp in enumerate(self.nodes):
            self.s.apply(
                (self.mgmt.add_node(kp.public, (f"inproc:{i}".encode(),)).sign(self.mgr, 1),),
                auth=self.mgmt,
            )
        for i in range(8):
            self.s.apply(
                (
                    ops.writes(ops.Set(ops.STORE_DATA, crypto.h(b"K"), f"v{i}".encode())).sign(
                        self.mgr, 1
                    ),
                )
            )

    def _ratified(self, seg, signers=None):
        roster = list(self.s.roster())
        claim = ops.Compaction(seg, self.s.head(), self.s.accumulator())
        chosen = signers if signers is not None else self.nodes
        shares = {
            roster.index(kp.public): crypto.Ed25519ListMultiSig.sign_share(
                kp._seed, claim.attest_bytes()
            )
            for kp in chosen
        }
        bitmap, sigs = crypto.Ed25519ListMultiSig.combine(shares, len(roster))
        return ops.Compaction(seg, claim.height, claim.acc_state, bitmap, tuple(sigs))

    def test_an_unratified_collection_is_refused_with_a_plain_complaint(self):
        """The complaint a log line can carry, rather than an obscure failure further downstream."""
        self.s.migrate(0, self.mgr, now=2)
        with self.assertRaises(store.StoreError) as cm:
            self.s.collect(0)
        self.assertIn("no signature", str(cm.exception))

    def test_a_ratified_collection_proceeds(self):
        self.s.migrate(0, self.mgr, now=2)
        self.s.collect(0, self._ratified(0))
        self.assertNotIn(0, self.s.segments())

    def test_a_signature_over_a_different_claim_is_refused(self):
        """The attestation binds SEGMENT, HEIGHT and FOLD together; signing one claim and then
        presenting another must not verify."""
        self.s.migrate(0, self.mgr, now=2)
        good = self._ratified(0)
        forged = ops.Compaction(0, good.height + 99, good.acc_state, good.signers, good.sigs)
        with self.assertRaises(store.StoreError) as cm:
            self.s.collect(0, forged)
        self.assertIn("does not match", str(cm.exception))

    def test_an_attestation_naming_another_segment_is_refused(self):
        self.s.migrate(0, self.mgr, now=2)
        with self.assertRaises(store.StoreError) as cm:
            self.s.collect(0, self._ratified(1))
        self.assertIn("different segment", str(cm.exception))


class TestMultiSigRoundTrip(unittest.TestCase):
    """A regression for a bug that shipped silently: splitting `_ed25519_verify` into typed errors
    made it RAISE and return None, so `if not _ed25519_verify(...)` was vacuously true and every
    multisig verification returned False. Nothing exercised the path, so nothing caught it."""

    def setUp(self):
        self.kps = [crypto.Keypair.generate() for _ in range(5)]
        self.roster = sorted(k.public for k in self.kps)

    def _sign(self, msg, who):
        shares = {
            self.roster.index(k.public): crypto.Ed25519ListMultiSig.sign_share(k._seed, msg)
            for k in who
        }
        return crypto.Ed25519ListMultiSig.combine(shares, len(self.roster))

    def test_a_genuine_multisig_verifies(self):
        bm, sigs = self._sign(b"claim", self.kps[:4])
        self.assertTrue(crypto.Ed25519ListMultiSig.verify(bm, sigs, b"claim", self.roster))

    def test_a_different_message_does_not(self):
        bm, sigs = self._sign(b"claim", self.kps[:4])
        self.assertFalse(crypto.Ed25519ListMultiSig.verify(bm, sigs, b"other", self.roster))

    def test_a_signature_from_outside_the_roster_does_not(self):
        stranger = crypto.Keypair.generate()
        bm, sigs = self._sign(b"claim", self.kps[:3])
        forged = list(sigs)
        forged[0] = crypto.Ed25519ListMultiSig.sign_share(stranger._seed, b"claim")
        self.assertFalse(crypto.Ed25519ListMultiSig.verify(bm, forged, b"claim", self.roster))

    def test_the_bitmap_names_who_signed(self):
        bm, _sigs = self._sign(b"claim", [self.kps[0], self.kps[2]])
        idx = crypto.bitmap_indices(bm, len(self.roster))
        self.assertEqual(
            sorted(idx),
            sorted([self.roster.index(self.kps[0].public), self.roster.index(self.kps[2].public)]),
        )
        self.assertEqual(crypto.bitmap_count(bm, len(self.roster)), 2)


class TestDedupFloor(unittest.TestCase):
    """A collected segment forgets its `op_hash` values, and those are what make a settled
    transaction unrepeatable. Collecting one the mempool would still admit from makes its
    transactions replayable — so a segment must age past the admission window before it goes."""

    def setUp(self):
        self.kp = crypto.Keypair.generate()
        self.s = store.Store()
        self.s.SEGMENT_WIDTH = 4
        for i in range(8):
            tx = ops.writes(ops.Set(ops.STORE_DATA, crypto.h(b"K"), f"v{i}".encode())).sign(
                self.kp, 1_000_000 + i
            )
            self.s.apply((tx,))

    def test_a_young_segment_is_refused(self):
        with self.assertRaises(store.StoreError) as cm:
            self.s.collect(0, now=1_000_100, dedup_window=30_000)
        self.assertIn("dedup window", str(cm.exception))
        self.assertIn("replayable", str(cm.exception))

    def test_an_aged_segment_passes_the_floor(self):
        """Past the window, the transactions can no longer be admitted, so forgetting their hashes
        costs nothing."""
        self.s.collect(0, now=1_000_000 + 60_000, dedup_window=30_000)
        self.assertNotIn(0, self.s.segments())

    def test_the_floor_is_an_age_not_a_width(self):
        """A width is a COUNT of entries; the window is a DURATION. Comparing them needs an assumed
        arrival rate nobody has — the newest entry's own timestamp answers it directly."""
        self.assertEqual(self.s.SEGMENT_WIDTH, 4)  # width says nothing about time
        with self.assertRaises(store.StoreError):
            self.s.collect(0, now=1_000_010, dedup_window=30_000)
        self.s.collect(0, now=1_000_100 + 30_000, dedup_window=30_000)  # aged past it
