"""Tests for dude.store.management -- the anchor axiom, Role.MANAGER grants, and the
emergency-intervention path.

Two distinct "manager" concepts (#anchor-is-the-axiom + #role-manager-grant):
  * The **anchor** — one immutable pubkey per store, provisioned at `store.provision()`.
    `may_write` and `may_send` return True unconditionally for it. Holds bitmap slot N in
    `Management.authorization` for the block-level override.
  * A **Role.MANAGER grant** — any number of runtime-granted identities. Blanket authorship
    via `may_write`/`may_send`. Does NOT get the block override.

The asymmetry is load-bearing (#trust-tiers): the anchor is cold and unrotatable; Role.MANAGER
identities are its warm-online delegates.
"""

from __future__ import annotations

import unittest

from ..consensus.bootstrap import bootstrap, intervene
from ..consensus.settle_round import _settle_payload
from ..core import crypto
from ..core.errors import InvariantError
from ..net.address import Address, Endpoint, Scheme
from ..store import Store, ops
from ..store.management import Cert, Management, ManagementError, NodeRecord, Role

T0 = 1_700_000_000_000


def _sign(kp: crypto.Keypair, tx: ops.Transaction) -> ops.SignedTransaction:
    return tx.sign(kp, T0)


def _provisioned(anchor_kp: crypto.Keypair) -> tuple[Store, Management]:
    s = Store()
    s.provision(anchor_kp.public)
    return s, Management(s)


# --------------------------------------------------------------------------------------------- #
# The anchor axiom: always authorised regardless of grants.                                     #
# --------------------------------------------------------------------------------------------- #


class TestAnchorIsAlwaysAuthorised(unittest.TestCase):
    """The anchor short-circuits `may_write` and `may_send` to True without any grant record
    (#anchor-is-the-axiom). Checking the anchor against a log the anchor itself authorises
    would be circular; treating them as always-may-write is what makes bootstrap a manager-
    signed block rather than a special-cased evaluator bypass."""

    def test_anchor_may_write_any_store_with_no_grant(self):
        anchor = crypto.Keypair.generate()
        s, mgmt = _provisioned(anchor)
        # Anchor has no grant record; `grant_of` returns None.
        self.assertIsNone(mgmt.grant_of(anchor.public))
        # Nevertheless, may_write returns True for any store id.
        self.assertTrue(mgmt.may_write(s, anchor.public, ops.STORE_DATA))
        self.assertTrue(mgmt.may_write(s, anchor.public, ops.STORE_MANAGEMENT))
        self.assertTrue(mgmt.may_write(s, anchor.public, 99))  # any invented store id

    def test_anchor_may_send_any_kind_with_no_grant(self):
        """Consistency with `may_write` (#anchor-is-the-axiom): the anchor's may_send is
        also unconditional. Previously `may_send` looked up the grant and returned False
        for the anchor -- an inconsistency between the two auth checks that would surface
        as "the anchor can write but cannot use the has-no-store grant KINDS (e.g., a
        compaction op)". Fixed as part of the anchor-vs-Role.MANAGER audit."""
        anchor = crypto.Keypair.generate()
        _s, mgmt = _provisioned(anchor)
        self.assertIsNone(mgmt.grant_of(anchor.public))
        # Anchor may send any operation kind.
        for kind in (0, 1, 42, 999):
            self.assertTrue(mgmt.may_send(anchor.public, kind), f"kind {kind}")

    def test_non_anchor_with_no_grant_may_not_write(self):
        anchor = crypto.Keypair.generate()
        stranger = crypto.Keypair.generate()
        s, mgmt = _provisioned(anchor)
        self.assertFalse(mgmt.may_write(s, stranger.public, ops.STORE_DATA))
        self.assertFalse(mgmt.may_send(stranger.public, 0))


# --------------------------------------------------------------------------------------------- #
# Role.MANAGER grants: blanket authorship, no block override.                                   #
# --------------------------------------------------------------------------------------------- #


class TestRoleManagerGrant(unittest.TestCase):
    """A Role.MANAGER grant confers blanket authorship (#role-manager-grant): `may_write`
    True for any store, `may_send` True for any kind. Does NOT confer the anchor's block
    override -- that stays with the axiomatic identity."""

    def test_role_manager_grant_writes_any_store(self):
        anchor = crypto.Keypair.generate()
        warm_mgr = crypto.Keypair.generate()
        s, mgmt = _provisioned(anchor)

        # Anchor grants Role.MANAGER to warm_mgr. Requires possession proof.
        pop = warm_mgr.prove_possession()
        grant = mgmt.authorise(
            warm_mgr.public,
            Role.MANAGER,
            pop=pop,
            cert=Cert.sign_grant(anchor, warm_mgr.public, Role.MANAGER),
        )
        s.apply((_sign(anchor, grant),), auth=mgmt)

        # warm_mgr may write any store, including one not named in `stores`.
        self.assertTrue(mgmt.may_write(s, warm_mgr.public, ops.STORE_DATA))
        self.assertTrue(mgmt.may_write(s, warm_mgr.public, ops.STORE_MANAGEMENT))
        self.assertTrue(mgmt.may_write(s, warm_mgr.public, 12345))
        # And send any kind.
        self.assertTrue(mgmt.may_send(warm_mgr.public, 0))
        self.assertTrue(mgmt.may_send(warm_mgr.public, 999))

    def test_non_manager_role_is_store_scoped(self):
        """A non-MANAGER role (CLIENT, NODE, COMPACTOR) is scoped to `g.stores` -- not
        blanket. This is what makes Role.MANAGER load-bearing: without the blanket, ordinary
        grants are per-store, per-kind."""
        anchor = crypto.Keypair.generate()
        client = crypto.Keypair.generate()
        s, mgmt = _provisioned(anchor)

        pop = client.prove_possession()
        grant = mgmt.authorise(
            client.public,
            Role.CLIENT,
            stores=frozenset({ops.STORE_DATA}),
            pop=pop,
            cert=Cert.sign_grant(anchor, client.public, Role.CLIENT),
        )
        s.apply((_sign(anchor, grant),), auth=mgmt)

        # Scoped: STORE_DATA yes, STORE_MANAGEMENT no.
        self.assertTrue(mgmt.may_write(s, client.public, ops.STORE_DATA))
        self.assertFalse(mgmt.may_write(s, client.public, ops.STORE_MANAGEMENT))
        self.assertFalse(mgmt.may_write(s, client.public, 999))

    def test_role_manager_does_not_get_block_override(self):
        """A Role.MANAGER grant may author operations blanket, but its signature does NOT
        satisfy `Management.authorization`'s manager-slot -- that slot is anchor-only
        (#anchor-is-the-axiom). Wire this by fabricating a bitmap that names the manager
        slot with a warm-manager sig; authorization returns False."""
        anchor = crypto.Keypair.generate()
        warm_mgr = crypto.Keypair.generate()
        s, mgmt = _provisioned(anchor)
        pop = warm_mgr.prove_possession()
        grant = mgmt.authorise(
            warm_mgr.public,
            Role.MANAGER,
            pop=pop,
            cert=Cert.sign_grant(anchor, warm_mgr.public, Role.MANAGER),
        )
        s.apply((_sign(anchor, grant),), auth=mgmt)
        # Roster is empty (warm_mgr is granted MANAGER but not added to the roster). N = 1;
        # the manager slot is position 0. Sign the payload with warm_mgr and try to occupy
        # the manager slot with warm_mgr's sig.
        payload = b"any payload"
        warm_sig = warm_mgr.sign(payload)
        signers, sigs = crypto.Ed25519ListMultiSig.combine({0: warm_sig}, 1)
        # authorization checks the anchor slot against `store.anchor()`, which is anchor's
        # pubkey -- NOT warm_mgr's. warm_sig doesn't verify against anchor's pubkey.
        self.assertFalse(mgmt.authorization(signers, tuple(sigs), payload))
        # And the anchor's own sig at the same slot DOES verify.
        anchor_sig = anchor.sign(payload)
        signers, sigs = crypto.Ed25519ListMultiSig.combine({0: anchor_sig}, 1)
        self.assertTrue(mgmt.authorization(signers, tuple(sigs), payload))


class TestRoleManagerRotation(unittest.TestCase):
    """Role.MANAGER identities rotate via ordinary authorise/revoke (#role-manager-grant).
    A cluster may have zero, one, or many at any moment. Revocation is forward-only
    (#absence-is-revocation)."""

    def test_authorise_then_revoke_removes_the_grant(self):
        anchor = crypto.Keypair.generate()
        warm_mgr = crypto.Keypair.generate()
        s, mgmt = _provisioned(anchor)
        pop = warm_mgr.prove_possession()

        # Grant.
        grant = mgmt.authorise(
            warm_mgr.public,
            Role.MANAGER,
            pop=pop,
            cert=Cert.sign_grant(anchor, warm_mgr.public, Role.MANAGER),
        )
        s.apply((_sign(anchor, grant),), auth=mgmt)
        self.assertIsNotNone(mgmt.grant_of(warm_mgr.public))
        self.assertTrue(mgmt.may_write(s, warm_mgr.public, ops.STORE_DATA))

        # Revoke.
        s.apply((_sign(anchor, mgmt.revoke(warm_mgr.public)),), auth=mgmt)
        self.assertIsNone(mgmt.grant_of(warm_mgr.public))
        self.assertFalse(mgmt.may_write(s, warm_mgr.public, ops.STORE_DATA))
        self.assertFalse(mgmt.may_send(warm_mgr.public, 0))

    def test_multiple_role_manager_identities_coexist(self):
        anchor = crypto.Keypair.generate()
        m1 = crypto.Keypair.generate()
        m2 = crypto.Keypair.generate()
        s, mgmt = _provisioned(anchor)

        for m in (m1, m2):
            pop = m.prove_possession()
            grant = mgmt.authorise(
                m.public,
                Role.MANAGER,
                pop=pop,
                cert=Cert.sign_grant(anchor, m.public, Role.MANAGER),
            )
            s.apply((_sign(anchor, grant),), auth=mgmt)
        self.assertTrue(mgmt.may_write(s, m1.public, ops.STORE_DATA))
        self.assertTrue(mgmt.may_write(s, m2.public, ops.STORE_DATA))
        # Neither reaches the block override -- that stays anchor-only.
        payload = b"payload"
        m1_sig = m1.sign(payload)
        signers, sigs = crypto.Ed25519ListMultiSig.combine({0: m1_sig}, 1)
        self.assertFalse(mgmt.authorization(signers, tuple(sigs), payload))


# --------------------------------------------------------------------------------------------- #
# Emergency intervention: manager-signed block post-bootstrap.                                  #
# --------------------------------------------------------------------------------------------- #


class TestEmergencyIntervention(unittest.TestCase):
    """`intervene()` produces a manager-signed block that chains onto the existing head
    (#manager-sig-overrides-quorum's "emergency intervention" case, #anchor-is-the-axiom's
    shared code path). Same construction as bootstrap; only the store state differs."""

    def test_intervene_chains_onto_head_and_authorises(self):
        anchor = crypto.Keypair.generate()
        s, mgmt = _provisioned(anchor)
        # Bootstrap first with an empty body set.
        bootstrap(s, anchor, bodies=())
        self.assertEqual(s.head_block_num(), 1)
        pre_head_hash = s.head_block_hash()
        assert pre_head_hash is not None

        # Now intervene with a manager-authored op. Grant a Role.CLIENT to some identity.
        client = crypto.Keypair.generate()
        pop = client.prove_possession()
        grant = mgmt.authorise(
            client.public,
            Role.CLIENT,
            stores=frozenset({ops.STORE_DATA}),
            pop=pop,
            cert=Cert.sign_grant(anchor, client.public, Role.CLIENT),
        )
        grant_tx = _sign(anchor, grant)
        sbwb = intervene(s, anchor, bodies=(grant_tx,), bucket=1)

        # Block 2 chained onto block 1.
        self.assertEqual(s.head_block_num(), 2)
        self.assertEqual(sbwb.block.anchors.block_num, 2)
        self.assertEqual(sbwb.block.anchors.prev_block, pre_head_hash)

        # Verifies via the same Management.authorization path as any other block.
        self.assertTrue(
            mgmt.authorization(
                sbwb.block.signers,
                sbwb.block.settle_sigs,
                _settle_payload(sbwb.block.block.slice_hash, sbwb.block.anchors),
            )
        )

        # The grant landed via the intervention.
        self.assertIsNotNone(mgmt.grant_of(client.public))

    def test_intervene_refuses_pre_bootstrap_store(self):
        anchor = crypto.Keypair.generate()
        s, _mgmt = _provisioned(anchor)
        with self.assertRaises(InvariantError):
            intervene(s, anchor, bodies=(), bucket=0)

    def test_intervene_refuses_wrong_manager_key(self):
        anchor = crypto.Keypair.generate()
        wrong = crypto.Keypair.generate()
        s, _mgmt = _provisioned(anchor)
        bootstrap(s, anchor, bodies=())
        with self.assertRaises(InvariantError):
            intervene(s, wrong, bodies=(), bucket=1)

    def test_intervene_and_bootstrap_share_wire_shape(self):
        """The bitmap layout, signed payload, and SettledBlock shape are IDENTICAL between
        bootstrap and intervene -- there is no separate emergency wire form
        (#anchor-is-the-axiom's shared code path). Assert by checking that both blocks
        verify via the same `Management.authorization` call with the same construction."""
        anchor = crypto.Keypair.generate()
        s, mgmt = _provisioned(anchor)
        bs = bootstrap(s, anchor, bodies=())
        iv = intervene(s, anchor, bodies=(), bucket=1)

        for sbwb in (bs, iv):
            payload = _settle_payload(sbwb.block.block.slice_hash, sbwb.block.anchors)
            self.assertTrue(
                mgmt.authorization(sbwb.block.signers, sbwb.block.settle_sigs, payload),
                f"block {sbwb.block.anchors.block_num} failed uniform authorization",
            )
        # Both have the manager slot set at bitmap position N (the last).
        for sbwb in (bs, iv):
            n = len(mgmt.roster()) + 1
            indices = crypto.bitmap_indices(sbwb.block.signers, n)
            self.assertIn(n - 1, indices, "manager slot not set")


# --------------------------------------------------------------------------------------------- #
# Anchor immutability: no rotation, one-shot provisioning.                                      #
# --------------------------------------------------------------------------------------------- #


class TestAnchorImmutable(unittest.TestCase):
    """`Store.provision` is one-shot; there is no anchor rotation mechanism
    (#anchor-is-the-axiom, deferred). The anchor is fixed at cluster creation and cannot
    change afterwards -- loss of the anchor cold-key ends emergency-intervention capability."""

    def test_provision_is_one_shot(self):
        anchor = crypto.Keypair.generate()
        s = Store()
        s.provision(anchor.public)
        # Re-provisioning with the same or a different key must refuse.
        other = crypto.Keypair.generate()
        with self.assertRaises(InvariantError):
            s.provision(other.public)
        # Anchor unchanged.
        self.assertEqual(s.anchor(), anchor.public)


# --------------------------------------------------------------------------------------------- #
# change_roster: batched atomic add+remove, brick-refuse only, advisory composition.            #
# --------------------------------------------------------------------------------------------- #


def _endpoint(n: int) -> Endpoint:
    """A stub endpoint for tests. `NodeRecord.endpoints` is a tuple of full `Endpoint`s
    (address + options) per #peer-endpoint-in-log; wrapping the address in an Endpoint
    with empty options is the minimum a caller has to do."""
    return Endpoint(Address(Scheme.INPROC, f"n{n}"))


def _seed_cluster(mgmt: Management, anchor: crypto.Keypair, size: int) -> list[crypto.Keypair]:
    """Bootstrap a cluster of `size` nodes via one atomic change_roster call, applied to the
    store. Returns the node keypairs."""
    kps = [crypto.Keypair.generate() for _ in range(size)]
    tx = mgmt.change_roster(
        commitment_signer=anchor,
        add=tuple(
            NodeRecord(kp.public, (_endpoint(i),), Cert.sign_roster(anchor, kp.public), frozenset())
            for i, kp in enumerate(kps)
        ),
    )
    mgmt.store.apply((tx.sign(anchor, T0),), auth=mgmt)
    return kps


class TestChangeRosterBatched(unittest.TestCase):
    """`change_roster` composes add + remove atomically. Batching sidesteps the one-at-a-time
    growth trap that made the old strict `add_node` refuse legitimate cluster construction."""

    def test_atomic_batch_add_from_zero_reaches_target(self):
        """From empty (n=0) to n=3 in one atomic change_roster: works even though the
        intermediate n<3 states would would_brick if inspected."""
        anchor = crypto.Keypair.generate()
        _s, mgmt = _provisioned(anchor)
        kps = _seed_cluster(mgmt, anchor, 3)
        self.assertEqual(len(mgmt.nodes()), 3)
        for kp in kps:
            self.assertIn(kp.public, mgmt.nodes())

    def test_batch_atomic_writes_p_node_p_pop_and_p_roster_together(self):
        """The one atomic tx must include the roster commitment update
        (#roster-change-is-atomic). Prove by checking `roster_commitment` reflects the
        post-state after apply."""
        anchor = crypto.Keypair.generate()
        _s, mgmt = _provisioned(anchor)
        kps = _seed_cluster(mgmt, anchor, 3)
        commit = mgmt.roster_commitment()
        assert commit is not None
        serial, members = commit
        self.assertEqual(serial, 1)  # first commitment after provisioning
        self.assertEqual(set(members), {kp.public for kp in kps})


class TestChangeRosterBrickRefusal(unittest.TestCase):
    """Only one refusal path: `quorum.would_brick(n_after) AND NOT quorum.would_brick(n_before)`.
    Shrinking a safe cluster into a bricked state is refused; growth into or through bricked
    states is allowed (bootstrap starts at n=0)."""

    def test_shrink_from_safe_to_bricked_is_refused(self):
        anchor = crypto.Keypair.generate()
        _s, mgmt = _provisioned(anchor)
        kps = _seed_cluster(mgmt, anchor, 3)
        # Now try to remove 2 nodes: n=3 (safe) -> n=1 (bricked). Refused.
        with self.assertRaises(ManagementError):
            mgmt.change_roster(commitment_signer=anchor, remove=(kps[0].public, kps[1].public))

    def test_shrink_within_bricked_range_is_allowed(self):
        """If n_before is already bricked (n<3), any shrink that doesn't make it worse is
        allowed. This preserves growth-from-zero and any legitimate remove-only ops in an
        already-degraded cluster."""
        anchor = crypto.Keypair.generate()
        _s, mgmt = _provisioned(anchor)
        # Grow to n=2 via a batched change (still bricked).
        kps = _seed_cluster(mgmt, anchor, 2)
        # Remove one, going 2 -> 1. n_before is already bricked, so no refusal.
        tx = mgmt.change_roster(commitment_signer=anchor, remove=(kps[0].public,))
        # Must not raise; apply and verify.
        mgmt.store.apply((tx.sign(anchor, T0),), auth=mgmt)
        self.assertEqual(len(mgmt.nodes()), 1)

    def test_growth_through_bricked_states_is_allowed(self):
        """Bootstrap starts at n=0 and grows through n=1, n=2 before hitting n=3. Under the
        would-brick rule, growing INTO a bricked state is fine; only shrinking into brick is
        refused. The batch abstraction means intermediate n values never exist externally."""
        anchor = crypto.Keypair.generate()
        _s, mgmt = _provisioned(anchor)
        # add=1 from n=0: n_after=1, bricked, but n_before also bricked -- allowed.
        kp1 = crypto.Keypair.generate()
        tx = mgmt.change_roster(
            commitment_signer=anchor,
            add=(
                NodeRecord(
                    kp1.public, (_endpoint(1),), Cert.sign_roster(anchor, kp1.public), frozenset()
                ),
            ),
        )
        mgmt.store.apply((tx.sign(anchor, T0),), auth=mgmt)
        self.assertEqual(len(mgmt.nodes()), 1)


class TestChangeRosterAdvisoryComposition(unittest.TestCase):
    """Domain concentration is ADVISORY, not enforcement (#quorum-gate). `change_roster`
    does NOT refuse on `domain_advisory` returning non-empty -- the operator sees the
    concentration via `check_domains` and decides."""

    def test_concentrating_all_nodes_in_one_domain_is_allowed(self):
        """A cluster whose entire roster shares one domain would lose quorum when that
        domain fails, but `change_roster` allows it. Enforcing at authoring blocked the
        legitimate case of building a small cluster on one provider before diversifying;
        it also blocked incremental dilution of a concentrated cluster."""
        anchor = crypto.Keypair.generate()
        _s, mgmt = _provisioned(anchor)
        # Four nodes, all in provider "hetzner". At n=4 max_domain(4)=1, so this is 3 over.
        # The old add_node refused this; change_roster allows it.
        kps = [crypto.Keypair.generate() for _ in range(4)]
        tx = mgmt.change_roster(
            commitment_signer=anchor,
            add=tuple(
                NodeRecord(
                    kp.public,
                    (_endpoint(i),),
                    Cert.sign_roster(anchor, kp.public),
                    frozenset({b"provider:hetzner"}),
                )
                for i, kp in enumerate(kps)
            ),
        )
        mgmt.store.apply((tx.sign(anchor, T0),), auth=mgmt)
        # The advisory reports the concentration.
        adv = mgmt.check_domains()
        self.assertEqual(adv, {b"provider:hetzner": 4})

    def test_add_node_wrapper_composes_via_change_roster(self):
        """`add_node` becomes a wrapper on `change_roster(add=[...])`. Same brick-refuse
        semantics, same commitment update. Verify by adding a node into an existing safe
        cluster and observing the commitment serial advances."""
        anchor = crypto.Keypair.generate()
        _s, mgmt = _provisioned(anchor)
        _seed_cluster(mgmt, anchor, 3)
        commit_before = mgmt.roster_commitment()
        assert commit_before is not None

        kp_new = crypto.Keypair.generate()
        tx = mgmt.add_node(
            kp_new.public,
            (_endpoint(9),),
            Cert.sign_roster(anchor, kp_new.public),
            commitment_signer=anchor,
        )
        mgmt.store.apply((tx.sign(anchor, T0),), auth=mgmt)

        commit_after = mgmt.roster_commitment()
        assert commit_after is not None
        self.assertEqual(commit_after[0], commit_before[0] + 1)
        self.assertIn(kp_new.public, commit_after[1])
        self.assertEqual(len(mgmt.nodes()), 4)

    def test_remove_node_wrapper_updates_commitment(self):
        """`remove_node` becomes a wrapper on `change_roster(remove=[...])`, fixing its
        previous violation of #roster-change-is-atomic (used to emit a bare Del P_NODE with
        no commitment update)."""
        anchor = crypto.Keypair.generate()
        _s, mgmt = _provisioned(anchor)
        kps = _seed_cluster(mgmt, anchor, 4)  # start at n=4 so remove takes us to n=3, safe

        commit_before = mgmt.roster_commitment()
        assert commit_before is not None
        tx = mgmt.remove_node(kps[0].public, commitment_signer=anchor)
        mgmt.store.apply((tx.sign(anchor, T0),), auth=mgmt)

        commit_after = mgmt.roster_commitment()
        assert commit_after is not None
        self.assertEqual(commit_after[0], commit_before[0] + 1)
        self.assertNotIn(kps[0].public, commit_after[1])
        self.assertEqual(len(mgmt.nodes()), 3)


if __name__ == "__main__":
    unittest.main()
