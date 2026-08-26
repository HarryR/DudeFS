"""Tests for the anchor axiom, Role.MANAGER grants, and the emergency-intervention path."""

from __future__ import annotations

import unittest

from ..consensus.bootstrap import bootstrap, intervene
from ..consensus.settle_round import _settle_payload
from ..core import codec, crypto
from ..core.errors import DudeError, InvariantError
from ..net.address import Address, Endpoint, Scheme
from ..store import Store, ops, settle
from ..store.management import (
    P_POP,
    P_ROSTER,
    Authorization,
    Cert,
    Grant,
    ManagementError,
    MgmtReader,
    MgmtWriter,
    NodeRecord,
    Role,
    RosterCommitment,
)
from .cluster import TUNABLES, Cluster

T0 = 1_700_000_000_000
DK = crypto.NameToken(crypto.h(b"k"))
DJ = crypto.NameToken(crypto.h(b"j"))
"""Data-store names are 32-byte tokens: a node must not be able to read a key name, and
`evaluate` refuses any other width."""


def unauthorised_certs(mgmt: MgmtWriter) -> str | None:
    for who, rec in mgmt.nodes().items():
        if not mgmt.verify_cert(rec.cert):
            return f"node row {who.hex()[:8]} carries a cert signed by {rec.cert.signer.hex()[:8]}"
    for who in mgmt._grants.keys():
        who_pk = crypto.PublicKey(who)
        grant = mgmt.grant_of(who_pk)
        if grant is None:
            return f"grant row {who_pk.hex()[:8]} will not decode"
        if not mgmt.verify_cert(grant.cert):
            return f"grant row {who_pk.hex()[:8]} carries a cert signed by {grant.cert.signer.hex()[:8]}"
    rc = mgmt.roster_commitment()
    if rc is not None and not mgmt.verify_cert(rc.cert):
        return f"the roster commitment is attested by {rc.cert.signer.hex()[:8]}"
    return None


def log_authorises_proof(mgmt: MgmtWriter, multisig: crypto.MultiSig, payload: bytes) -> bool:
    return Authorization(multisig, payload, mgmt.roster(), mgmt.anchor).verify()


def _sign(kp: crypto.Keypair, tx: ops.Transaction) -> ops.SignedTransaction:
    return tx.sign(kp, T0)


def _provisioned(anchor_kp: crypto.Keypair) -> tuple[Store, MgmtWriter]:
    s = Store()
    s.provision(anchor_kp.public)
    return s, s.mgmt_writer


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
            Role.CLIENT_RW,
            stores=frozenset({ops.STORE_DATA}),
            pop=pop,
            cert=Cert.sign_grant(anchor, client.public, Role.CLIENT_RW),
        )
        s.apply((_sign(anchor, grant),), auth=mgmt)

        # Scoped: STORE_DATA yes, STORE_MANAGEMENT no.
        self.assertTrue(mgmt.may_write(s, client.public, ops.STORE_DATA))
        self.assertFalse(mgmt.may_write(s, client.public, ops.STORE_MANAGEMENT))
        self.assertFalse(mgmt.may_write(s, client.public, 999))

    def test_role_manager_does_not_get_block_override(self):
        """A Role.MANAGER grant may author operations blanket, but its signature does NOT
        satisfy `Authorization.verify`'s manager slot -- that slot is anchor-only
        (#anchor-is-the-axiom). Wire this by fabricating a bitmap that names the manager
        slot with a warm-manager sig; the check returns False."""
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
        # The check tests the anchor slot against `store.anchor()`, which is anchor's
        # pubkey -- NOT warm_mgr's. warm_sig doesn't verify against anchor's pubkey.
        self.assertFalse(
            log_authorises_proof(mgmt, crypto.MultiSig.combine({0: warm_sig}, 1), payload)
        )
        # And the anchor's own sig at the same slot DOES verify.
        anchor_sig = anchor.sign(payload)
        self.assertTrue(
            log_authorises_proof(mgmt, crypto.MultiSig.combine({0: anchor_sig}, 1), payload)
        )


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

        # Revoke. Anchor re-issues, though this manager attested nothing.
        s.apply(
            (_sign(anchor, mgmt.revoke(warm_mgr.public, reissue_signer=anchor)),),
            auth=mgmt,
        )
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
        self.assertFalse(
            log_authorises_proof(mgmt, crypto.MultiSig.combine({0: m1_sig}, 1), payload)
        )


# --------------------------------------------------------------------------------------------- #
# Emergency intervention: manager-signed block post-bootstrap.                                  #
# --------------------------------------------------------------------------------------------- #


class TestRevocationIsCompound(unittest.TestCase):
    """Revoking an identity MUST re-issue every #cert it signed, in the same transaction --
    otherwise `verify_cert`'s "signer authorised NOW" check silently un-attests every row that
    identity signed. A cluster in that state sits out consensus and looks like a network fault."""

    def _cluster_admitted_by_a_warm_manager(self, size=3):
        """Anchor grants MANAGER to `warm`; `warm` -- not the anchor -- admits `size` nodes,
        signing both the entry certs and the roster commitment. The ordinary warm-manager
        operational path, and the one that breaks."""
        anchor = crypto.Keypair.generate()
        warm = crypto.Keypair.generate()
        s, mgmt = _provisioned(anchor)
        s.apply(
            (
                _sign(
                    anchor,
                    mgmt.authorise(
                        warm.public,
                        Role.MANAGER,
                        pop=warm.prove_possession(),
                        cert=Cert.sign_grant(anchor, warm.public, Role.MANAGER),
                    ),
                ),
            ),
            auth=mgmt,
        )
        kps = [crypto.Keypair.generate() for _ in range(size)]
        add = mgmt.change_roster(
            commitment_signer=warm,
            add=tuple(
                NodeRecord(
                    kp.public,
                    (_endpoint(i),),
                    Cert.sign_roster(warm, kp.public),
                    frozenset(),
                )
                for i, kp in enumerate(kps)
            ),
        )
        s.apply((add.sign(warm, T0),), auth=mgmt)
        return anchor, warm, s, mgmt, kps

    def test_revoking_the_manager_that_admitted_them_keeps_the_roster(self):
        anchor, warm, s, mgmt, _kps = self._cluster_admitted_by_a_warm_manager()
        before = mgmt.roster()
        self.assertEqual(len(before), 3)

        s.apply((_sign(anchor, mgmt.revoke(warm.public, reissue_signer=anchor)),), auth=mgmt)

        self.assertIsNone(mgmt.grant_of(warm.public), "grant survived revocation")
        self.assertEqual(mgmt.roster(), before, "revoking the attesting manager dropped nodes")
        self.assertIsNotNone(mgmt.roster_commitment(), "roster commitment stopped verifying")

    def test_the_invariant_holds_across_revocation(self):
        """`unauthorised_certs` is the quantified form of the per-row check the read side
        already runs. It reports the violation the roster silently absorbed."""
        anchor, warm, s, mgmt, _kps = self._cluster_admitted_by_a_warm_manager()
        self.assertIsNone(unauthorised_certs(mgmt))

        s.apply((_sign(anchor, mgmt.revoke(warm.public, reissue_signer=anchor)),), auth=mgmt)
        self.assertIsNone(unauthorised_certs(mgmt), unauthorised_certs(mgmt))

    def test_a_bare_del_leaves_the_invariant_violated(self):
        """The accepted intermediate state (#typed-management-ops-owed): a caller who bypasses
        the API and composes the deletion by hand still reaches an un-attested roster. The
        invariant REPORTS it -- which is the whole point of naming it -- but nothing refuses
        the write until management operations become typed opcodes."""
        anchor, warm, s, mgmt, _kps = self._cluster_admitted_by_a_warm_manager()
        bare = ops.writes(
            ops.Del(ops.STORE_MANAGEMENT, mgmt._grants.entry_name(warm.public)),
            ops.Del(ops.STORE_MANAGEMENT, P_POP + warm.public),
        )
        s.apply((_sign(anchor, bare),), auth=mgmt)

        self.assertEqual(mgmt.roster(), (), "the roster-collapse precondition changed")
        self.assertIsNotNone(unauthorised_certs(mgmt), "invariant did not report the violation")

    def test_only_the_anchor_may_revoke_a_manager(self):
        """#role-manager-grant: "Only the anchor grants or revokes Role.MANAGER." Refused at
        AUTHORING; the log-boundary refusal is owed with the typed opcodes."""
        _anchor, warm, _s, mgmt, _kps = self._cluster_admitted_by_a_warm_manager()
        with self.assertRaises(ManagementError):
            mgmt.revoke(warm.public, reissue_signer=warm)

    def test_reissue_does_not_bump_the_serial_or_the_fingerprint(self):
        """A re-issue is not a roster change and MUST NOT look like one: membership, endpoints
        and domains are untouched, so `cert.subject` -- which IS `roster_fingerprint` -- stays
        put. Otherwise every revocation would churn light-client bundles and trip
        `Node._reconcile_peers`' serial gate for no state change."""
        anchor, warm, s, mgmt, _kps = self._cluster_admitted_by_a_warm_manager()
        before = mgmt.roster_commitment()
        assert before is not None

        s.apply((_sign(anchor, mgmt.revoke(warm.public, reissue_signer=anchor)),), auth=mgmt)

        after = mgmt.roster_commitment()
        assert after is not None
        self.assertEqual(after.serial, before.serial, "serial bumped on a re-issue")
        self.assertEqual(
            after.state_fingerprint, before.state_fingerprint, "state_fingerprint moved"
        )
        self.assertEqual(after.cert.subject, before.cert.subject, "roster_fingerprint moved")
        self.assertEqual(after.cert.signer, anchor.public, "cert was not re-signed by the anchor")


class TestEmergencyIntervention(unittest.TestCase):
    """`intervene()` produces a manager-signed block that chains onto the existing head
    (#manager-sig-overrides-quorum's "emergency intervention" case, #anchor-is-the-axiom's
    shared code path). Same construction as bootstrap; only the store state differs."""

    def test_intervene_chains_onto_head_and_authorises(self):
        anchor = crypto.Keypair.generate()
        s, mgmt = _provisioned(anchor)
        # Bootstrap first with an empty body set.
        bootstrap(s, anchor, bodies=(), bucket=0)
        self.assertEqual(s.head_block_num(), 0)
        pre_head_hash = s.head_block_hash()
        assert pre_head_hash is not None

        # Now intervene with a manager-authored op. Grant a Role.CLIENT_RW to some identity.
        client = crypto.Keypair.generate()
        pop = client.prove_possession()
        grant = mgmt.authorise(
            client.public,
            Role.CLIENT_RW,
            stores=frozenset({ops.STORE_DATA}),
            pop=pop,
            cert=Cert.sign_grant(anchor, client.public, Role.CLIENT_RW),
        )
        grant_tx = _sign(anchor, grant)
        sbwb = intervene(s, anchor, bodies=(grant_tx,), bucket=1)

        self.assertEqual(s.head_block_num(), 1)
        self.assertEqual(sbwb.block.anchors.block_num, 1)
        self.assertEqual(sbwb.block.anchors.prev_block, pre_head_hash)

        # Verifies via the same quorum-proof rule as any other block.
        self.assertTrue(
            log_authorises_proof(
                mgmt,
                sbwb.block.multisig,
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
        bootstrap(s, anchor, bodies=(), bucket=0)
        with self.assertRaises(InvariantError):
            intervene(s, wrong, bodies=(), bucket=1)

    def test_intervene_and_bootstrap_share_wire_shape(self):
        """The bitmap layout, signed payload, and SettledBlock shape are IDENTICAL between
        bootstrap and intervene -- there is no separate emergency wire form
        (#anchor-is-the-axiom's shared code path). Assert by checking that both blocks
        verify via the same quorum-proof rule with the same construction."""
        anchor = crypto.Keypair.generate()
        s, mgmt = _provisioned(anchor)
        bs = bootstrap(s, anchor, bodies=(), bucket=0)
        iv = intervene(s, anchor, bodies=(), bucket=1)

        for sbwb in (bs, iv):
            payload = _settle_payload(sbwb.block.block.slice_hash, sbwb.block.anchors)
            self.assertTrue(
                log_authorises_proof(mgmt, sbwb.block.multisig, payload),
                f"block {sbwb.block.anchors.block_num} failed uniform authorization",
            )
        # Both have the manager slot set at bitmap position N (the last).
        for sbwb in (bs, iv):
            n = len(mgmt.roster()) + 1
            self.assertIn(n - 1, sbwb.block.multisig.indices(n), "manager slot not set")


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


def _seed_cluster(
    s: Store, mgmt: MgmtWriter, anchor: crypto.Keypair, size: int
) -> list[crypto.Keypair]:
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
    s.apply((tx.sign(anchor, T0),), auth=mgmt)
    return kps


class TestChangeRosterBatched(unittest.TestCase):
    """`change_roster` composes add + remove atomically. Batching sidesteps the one-at-a-time
    growth trap that made the old strict `add_node` refuse legitimate cluster construction."""

    def test_atomic_batch_add_from_zero_reaches_target(self):
        """From empty (n=0) to n=3 in one atomic change_roster: works even though the
        intermediate n<3 states would would_brick if inspected."""
        anchor = crypto.Keypair.generate()
        s, mgmt = _provisioned(anchor)
        kps = _seed_cluster(s, mgmt, anchor, 3)
        self.assertEqual(len(mgmt.nodes()), 3)
        for kp in kps:
            self.assertIn(kp.public, mgmt.nodes())

    def test_batch_atomic_writes_p_node_p_pop_and_p_roster_together(self):
        """The one atomic tx must include the roster commitment update
        (#roster-change-is-atomic). Prove by checking `roster_commitment` reflects the
        post-state after apply."""
        anchor = crypto.Keypair.generate()
        s, mgmt = _provisioned(anchor)
        kps = _seed_cluster(s, mgmt, anchor, 3)
        commit = mgmt.roster_commitment()
        assert commit is not None
        self.assertEqual(commit.serial, 1)  # first commitment after provisioning
        self.assertEqual(set(commit.members), {kp.public for kp in kps})


class TestChangeRosterBrickRefusal(unittest.TestCase):
    """Only one refusal path: `quorum.would_brick(n_after) AND NOT quorum.would_brick(n_before)`.
    Shrinking a safe cluster into a bricked state is refused; growth into or through bricked
    states is allowed (bootstrap starts at n=0)."""

    def test_shrink_from_safe_to_bricked_is_refused(self):
        anchor = crypto.Keypair.generate()
        s, mgmt = _provisioned(anchor)
        kps = _seed_cluster(s, mgmt, anchor, 3)
        # Now try to remove 2 nodes: n=3 (safe) -> n=1 (bricked). Refused.
        with self.assertRaises(ManagementError):
            mgmt.change_roster(commitment_signer=anchor, remove=(kps[0].public, kps[1].public))

    def test_shrink_within_bricked_range_is_allowed(self):
        """If n_before is already bricked (n<3), any shrink that doesn't make it worse is
        allowed. This preserves growth-from-zero and any legitimate remove-only ops in an
        already-degraded cluster."""
        anchor = crypto.Keypair.generate()
        s, mgmt = _provisioned(anchor)
        # Grow to n=2 via a batched change (still bricked).
        kps = _seed_cluster(s, mgmt, anchor, 2)
        # Remove one, going 2 -> 1. n_before is already bricked, so no refusal.
        tx = mgmt.change_roster(commitment_signer=anchor, remove=(kps[0].public,))
        # Must not raise; apply and verify.
        s.apply((tx.sign(anchor, T0),), auth=mgmt)
        self.assertEqual(len(mgmt.nodes()), 1)

    def test_growth_through_bricked_states_is_allowed(self):
        """Bootstrap starts at n=0 and grows through n=1, n=2 before hitting n=3. Under the
        would-brick rule, growing INTO a bricked state is fine; only shrinking into brick is
        refused. The batch abstraction means intermediate n values never exist externally."""
        anchor = crypto.Keypair.generate()
        s, mgmt = _provisioned(anchor)
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
        s.apply((tx.sign(anchor, T0),), auth=mgmt)
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
        s, mgmt = _provisioned(anchor)
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
        s.apply((tx.sign(anchor, T0),), auth=mgmt)
        # The advisory reports the concentration.
        adv = mgmt.check_domains()
        self.assertEqual(adv, {b"provider:hetzner": 4})

    def test_add_node_wrapper_composes_via_change_roster(self):
        """`add_node` becomes a wrapper on `change_roster(add=[...])`. Same brick-refuse
        semantics, same commitment update. Verify by adding a node into an existing safe
        cluster and observing the commitment serial advances."""
        anchor = crypto.Keypair.generate()
        s, mgmt = _provisioned(anchor)
        _seed_cluster(s, mgmt, anchor, 3)
        commit_before = mgmt.roster_commitment()
        assert commit_before is not None

        kp_new = crypto.Keypair.generate()
        tx = mgmt.add_node(
            kp_new.public,
            (_endpoint(9),),
            Cert.sign_roster(anchor, kp_new.public),
            commitment_signer=anchor,
        )
        s.apply((tx.sign(anchor, T0),), auth=mgmt)

        commit_after = mgmt.roster_commitment()
        assert commit_after is not None
        self.assertEqual(commit_after.serial, commit_before.serial + 1)
        self.assertIn(kp_new.public, commit_after.members)
        self.assertEqual(len(mgmt.nodes()), 4)

    def test_remove_node_wrapper_updates_commitment(self):
        """`remove_node` becomes a wrapper on `change_roster(remove=[...])`, fixing its
        previous violation of #roster-change-is-atomic (used to emit a bare Del P_NODE with
        no commitment update)."""
        anchor = crypto.Keypair.generate()
        s, mgmt = _provisioned(anchor)
        kps = _seed_cluster(s, mgmt, anchor, 4)  # start at n=4 so remove takes us to n=3, safe

        commit_before = mgmt.roster_commitment()
        assert commit_before is not None
        tx = mgmt.remove_node(kps[0].public, commitment_signer=anchor)
        s.apply((tx.sign(anchor, T0),), auth=mgmt)

        commit_after = mgmt.roster_commitment()
        assert commit_after is not None
        self.assertEqual(commit_after.serial, commit_before.serial + 1)
        self.assertNotIn(kps[0].public, commit_after.members)
        self.assertEqual(len(mgmt.nodes()), 3)


# --------------------------------------------------------------------------------------------- #
# Encoding: guard against wire vs disk drift. CLAUDE.md trap #1 -- both halves are self-        #
# consistent in isolation, so only field-count pins catch a silent divergence.                  #
# --------------------------------------------------------------------------------------------- #


class TestNodeRecordEncoding(unittest.TestCase):
    """Wire form (4 fields) and disk form (3 fields) both live on `NodeRecord`, both must
    refuse a wrong-count payload. Round-trip separately proves consistency; the count
    refusals catch a field added to encode but not decode (or vice versa)."""

    def setUp(self):
        kp = crypto.Keypair.generate()
        manager = crypto.Keypair.generate()
        addr = Address(Scheme.TCP, "127.0.0.1:7001")
        cert = Cert.sign_roster(manager, kp.public)
        self.rec = NodeRecord(
            identity=kp.public,
            endpoints=(Endpoint(addr),),
            cert=cert,
            domains=frozenset({b"provider:x"}),
        )

    def test_wire_form_round_trips(self):
        self.assertEqual(NodeRecord.decode(self.rec.encode()), self.rec)

    def test_row_form_round_trips(self):
        self.assertEqual(NodeRecord.decode_row(self.rec.identity, self.rec.encode_row()), self.rec)

    def test_wire_form_wrong_field_count_raises(self):
        """`NodeRecord.encode` emits 4 fields; anything else must be a hard decode refusal.
        Trap #1: a field added to encode without matching decode `as_seq(..., N)` would silently
        drop; this test pins the count so the drop can't happen unnoticed."""
        for wrong in (3, 5):
            malformed = codec.encode([b""] * wrong)
            with self.assertRaises(DudeError):
                NodeRecord.decode(malformed)

    def test_row_form_wrong_field_count_raises(self):
        """Same trap, for the disk form (3 fields, identity from key)."""
        for wrong in (2, 4):
            malformed = codec.encode([b""] * wrong)
            with self.assertRaises(DudeError):
                NodeRecord.decode_row(self.rec.identity, malformed)


class TestAuthorityIsResolvedOverOneView(unittest.TestCase):
    """`may_write` reads the author's grant from the view it is handed and MUST resolve that
    grant's SIGNER against the same view. It read the row from the settlement overlay and the
    signer's authority from the durable Store, so no authority chain established inside a single
    block could be used inside it -- a manager granted at step 1 could not admit a client at
    step 2, and the refusal looked like an ordinary AUTHORITY verdict."""

    def test_a_manager_granted_in_the_same_batch_can_authorise_a_client(self):
        anchor = crypto.Keypair.generate()
        mgr = crypto.Keypair.generate()
        client = crypto.Keypair.generate()

        # The manager composes offline against a store where its own grant has landed -- the
        # authoring path a warm delegate really has.
        scratch, scratch_mgmt = _provisioned(anchor)
        tx1 = _sign(
            anchor,
            scratch_mgmt.authorise(
                mgr.public,
                Role.MANAGER,
                pop=mgr.prove_possession(),
                cert=Cert.sign_grant(anchor, mgr.public, Role.MANAGER),
            ),
        )
        scratch.apply((tx1,), auth=scratch_mgmt)
        tx2 = _sign(
            mgr,
            scratch_mgmt.authorise(
                client.public,
                Role.CLIENT_RW,
                frozenset({ops.STORE_DATA}),
                pop=client.prove_possession(),
                cert=Cert.sign_grant(mgr, client.public, Role.CLIENT_RW),
            ),
        )
        tx3 = ops.writes(ops.Set(ops.STORE_DATA, DK, b"v")).sign(client, T0)

        s, mgmt = _provisioned(anchor)
        screened = settle.would_apply(s, (tx1, tx2, tx3), mgmt)
        self.assertEqual(
            [(r.verdict.why, r.verdict.step) for r in screened.rejects],
            [],
            "an authority chain established inside the batch was not visible inside it",
        )


class TestAuthorityRowEncoding(unittest.TestCase):
    """The remaining authority-carrying layouts. `NodeRecord` was pinned and these were not, so
    a field added to one half of a Cert, a Grant or the roster commitment would have gone in
    silently -- the halves stay self-consistent alone, which is what defeats round-trip tests."""

    def setUp(self):
        self.anchor = crypto.Keypair.generate()
        self.who = crypto.Keypair.generate().public

    def test_cert_wrong_field_count_raises(self):
        cert = Cert.sign_grant(self.anchor, self.who, Role.CLIENT_RW)
        self.assertEqual(Cert.decode(cert.encode()), cert)
        for wrong in (3, 5):
            with self.assertRaises(ManagementError):
                Cert.decode(codec.encode([b""] * wrong))

    def test_grant_wrong_field_count_raises_on_both_forms(self):
        grant = Grant(
            self.who,
            Role.CLIENT_RW,
            frozenset({1}),
            frozenset({2}),
            Cert.sign_grant(self.anchor, self.who, Role.CLIENT_RW),
        )
        self.assertEqual(Grant.decode(grant.encode()), grant)
        self.assertEqual(Grant.decode_row(self.who, grant.encode_row()), grant)
        for wrong in (4, 6):
            with self.assertRaises(DudeError):
                Grant.decode(codec.encode([b""] * wrong))
        for wrong in (3, 5):
            with self.assertRaises(DudeError):
                Grant.decode_row(self.who, codec.encode([b""] * wrong))

    def test_roster_commitment_wrong_field_count_raises(self):
        rc = RosterCommitment(
            serial=1,
            members=(self.who,),
            state_fingerprint=crypto.h(b"fp"),
            cert=Cert.sign_roster_commitment(self.anchor, b"content"),
        )
        self.assertEqual(RosterCommitment.decode_row(rc.encode_row()), rc)
        for wrong in (3, 5):
            with self.assertRaises(ManagementError):
                RosterCommitment.decode_row(codec.encode([b""] * wrong))


class TestMalformedRowsDoNotPoison(unittest.TestCase):
    """A store-0 row that doesn't parse MUST read as "identity absent". Settlement never checks
    parseability, so garbage lands legitimately; a raise poisons every roster()/may_write on the
    hot path, and repair needs a consensus round that can no longer run."""

    def setUp(self):
        self.anchor = crypto.Keypair.generate()
        self.s, self.mgmt = _provisioned(self.anchor)
        self.kps = _seed_cluster(self.s, self.mgmt, self.anchor, 3)

    def _settle_garbage(self, name: bytes) -> None:
        t = ops.writes(ops.Set(ops.STORE_MANAGEMENT, name, b"\x00not-bencode"))
        applied = self.s.apply((t.sign(self.anchor, T0 + 1),), auth=self.mgmt)
        self.assertEqual(len(applied.settled), 1, "the garbage row must land for the test to bite")

    def test_garbage_node_row_reads_as_absent_and_roster_survives(self):
        stranger = crypto.Keypair.generate().public
        self._settle_garbage(self.mgmt._nodes.entry_name(stranger))
        self.assertEqual(set(self.mgmt.roster()), {kp.public for kp in self.kps})
        self.assertNotIn(stranger, self.mgmt.nodes())
        self.assertIsNotNone(self.mgmt.roster_commitment())
        after = self.s.apply(
            (ops.writes(ops.Set(ops.STORE_DATA, DK, b"v")).sign(self.anchor, T0 + 2),),
            auth=self.mgmt,
        )
        self.assertEqual(len(after.settled), 1, "settlement itself must survive the garbage row")

    def test_garbage_grant_row_refuses_authority_not_raising(self):
        writer = crypto.Keypair.generate()
        self._settle_garbage(self.mgmt._grants.entry_name(writer.public))
        self.assertIsNone(self.mgmt.grant_of(writer.public))
        attempt = ops.writes(ops.Set(ops.STORE_DATA, DK, b"v")).sign(writer, T0 + 2)
        applied = self.s.apply((attempt,), auth=self.mgmt)
        self.assertEqual(applied.settled, ())
        self.assertEqual([d.why for d in applied.dropped], [settle.Reason.AUTHORITY])


class TestIsMemberAndRosterCannotDisagree(unittest.TestCase):
    """`is_member` reads ONE row and verifies ONE signature; `roster()` does it per member. Two
    implementations of who is in the cluster is the shape that has cost this codebase most, so
    they SHARE the per-row predicate rather than restating it -- this pins that they answer alike
    on real cluster state, and `_seats` is why they cannot come apart."""

    def test_they_agree_on_every_member_and_on_a_stranger(self):
        c = Cluster(nodes=3)
        s = c.provisioned()
        c.close()
        mgmt = s.mgmt_reader
        roster = mgmt.roster()
        self.assertTrue(roster, "no roster to compare against")
        for who in roster:
            self.assertTrue(mgmt.is_member(who), "a seat roster() grants, is_member refuses")
        self.assertFalse(mgmt.is_member(crypto.Keypair.generate().public))

    def test_a_row_that_is_not_a_seat_is_refused_by_both(self):
        c = Cluster(nodes=4)
        s = c.provisioned()
        c.close()
        node_keys = [n.me.public for n in c.nodes]
        victim = node_keys[3]
        entry = s.mgmt_reader._nodes.entry(victim)
        assert entry is not None
        rec = NodeRecord.decode_row(victim, entry.value)
        forged = NodeRecord(
            identity=rec.identity,
            endpoints=rec.endpoints,
            cert=Cert(
                rec.cert.signer, rec.cert.subject, rec.cert.purpose, crypto.Signature(bytes(64))
            ),
            domains=rec.domains,
        )
        from ..store.managed import MapEntry
        plant = ops.writes(
            ops.Set(ops.STORE_MANAGEMENT, s.mgmt_reader._nodes.entry_name(victim),
                    MapEntry.encode(entry.index, forged.encode_row()))
        ).sign(c.anchor, T0)
        intervene(s, c.anchor, bodies=(plant,), bucket=TUNABLES.bucket(T0))

        mgmt = s.mgmt_reader
        self.assertIsNotNone(s.mgmt_reader._nodes.entry(victim), "the row must exist")
        self.assertNotIn(victim, mgmt.roster())
        self.assertFalse(mgmt.is_member(victim), "is_member took a row's existence for a seat")

    def test_a_removed_node_stops_being_a_member_by_both_readings(self):
        c = Cluster(nodes=4)
        s = c.provisioned()
        c.close()
        node_keys = [n.me.public for n in c.nodes]
        victim = node_keys[3]
        self.assertTrue(s.mgmt_reader.is_member(victim))
        remove = (
            s.mgmt_writer.change_roster(commitment_signer=c.anchor, remove=(victim,)).sign(c.anchor, T0)
        )
        intervene(s, c.anchor, bodies=(remove,), bucket=TUNABLES.bucket(T0))
        self.assertNotIn(victim, s.mgmt_reader.roster())
        self.assertFalse(s.mgmt_reader.is_member(victim))


class TestAuthorizationRefusesRatherThanRaises(unittest.TestCase):
    """Every field of a multisig arrives from a peer, so a shape we cannot make sense of is that
    peer's claim being wrong -- a refusal. Raised instead, it escapes as OUR error: `CryptoError`
    from an unindexable bitmap and `QuorumError` from `quorum.size(0)` both unwound through
    `chain.advance` into the light client, which catches neither on its read path."""

    def test_a_bitmap_of_the_wrong_width_is_refused(self):
        anchor = crypto.Keypair.generate()
        roster = tuple(crypto.Keypair.generate().public for _ in range(3))
        wrong = crypto.MultiSig(crypto.SignerBitmap(bytes(5)), (crypto.Signature(bytes(64)),))
        self.assertFalse(Authorization(wrong, b"payload", roster, anchor.public).verify())

    def test_an_empty_roster_without_the_anchor_is_refused(self):
        """No roster is no quorum. Reached verifying a claim about block 1."""
        anchor = crypto.Keypair.generate()
        none_set = crypto.MultiSig(crypto.SignerBitmap(bytes(1)), ())
        self.assertFalse(Authorization(none_set, b"payload", (), anchor.public).verify())

    def test_the_anchor_still_overrides_an_empty_roster(self):
        """The control: refusing an empty roster must not refuse the bootstrap block itself."""
        anchor = crypto.Keypair.generate()
        payload = b"block-one"
        sig = crypto.MultiSig.combine({0: anchor.sign(payload)}, 1)
        self.assertTrue(Authorization(sig, payload, (), anchor.public).verify())


class TestReadAndWriteAreScopedTheSameWay(unittest.TestCase):
    """`stores` is the set a grant covers; the ROLE says what may be done to it. Before the split
    there was one CLIENT role and reads consulted neither -- any grant read any store."""

    def _granted(self, role: Role, stores: frozenset[int]) -> tuple[Store, crypto.Keypair]:
        anchor = crypto.Keypair.generate()
        s = Store()
        s.provision(anchor.public)
        who = crypto.Keypair.generate()
        tx = s.mgmt_writer.authorise(
            who.public,
            role,
            stores=stores,
            pop=who.prove_possession(),
            cert=Cert.sign_grant(anchor, who.public, role),
        )
        bootstrap(s, anchor, bodies=(tx.sign(anchor, T0),), bucket=0)
        return s, who

    def test_a_read_only_grant_reads_its_store_and_writes_nothing(self):
        s, who = self._granted(Role.CLIENT_RO, frozenset({ops.STORE_DATA}))
        m = s.mgmt_reader
        self.assertTrue(m.may_read(s, who.public, ops.STORE_DATA))
        self.assertFalse(m.may_write(s, who.public, ops.STORE_DATA), "CLIENT_RO wrote")

    def test_a_grant_for_one_store_does_not_reach_another(self):
        s, who = self._granted(Role.CLIENT_RW, frozenset({ops.STORE_DATA}))
        m = s.mgmt_reader
        self.assertTrue(m.may_write(s, who.public, ops.STORE_DATA))
        self.assertFalse(m.may_read(s, who.public, ops.STORE_DATA + 1), "read another store")
        self.assertFalse(m.may_write(s, who.public, ops.STORE_DATA + 1))

    def test_the_management_store_is_readable_by_any_principal(self):
        """It IS the trust chain -- roster, node records, grants, commitment certs -- and a light
        client cannot verify a quorum proof without it. `RosterBundle` already ships the roster and
        every manager grant to anyone who bootstraps. Its wraps are sealed boxes, so they are
        encrypted rather than withheld. Scoping it withheld nothing and broke the thing it exists
        for: a client could not fetch the keys its own grant depends on."""
        s, who = self._granted(Role.CLIENT_RO, frozenset({ops.STORE_DATA}))
        m = s.mgmt_reader
        self.assertTrue(
            m.may_read(s, who.public, ops.STORE_MANAGEMENT),
            "a granted client was refused the trust chain",
        )
        self.assertFalse(
            m.may_write(s, who.public, ops.STORE_MANAGEMENT), "readable is not writable"
        )
        self.assertFalse(
            m.may_read(s, crypto.Keypair.generate().public, ops.STORE_MANAGEMENT),
            "a stranger with no standing is still refused",
        )

    def test_a_compactor_reads_its_store_and_writes_nothing(self):
        """It authorises nothing more until compaction returns with its own verbs."""
        s, who = self._granted(Role.COMPACTOR, frozenset({ops.STORE_DATA}))
        m = s.mgmt_reader
        self.assertTrue(m.may_read(s, who.public, ops.STORE_DATA))
        self.assertFalse(m.may_write(s, who.public, ops.STORE_DATA))

    def test_a_grant_whose_signer_holds_no_grant_is_refused_for_reads_too(self):
        """#revocation-is-compound. `revoke` re-issues what a key attested, so it never orphans a
        chain -- but a row planted around `authorise` can, which is exactly what
        `TestRevokedManagerCannotForgeARoster` models: the cert stays a genuine artefact and only
        the signer's own grant is gone. `may_write` re-walked the chain and the read path did not,
        so such a grant kept reading after it had stopped writing."""
        anchor = crypto.Keypair.generate()
        s = Store()
        s.provision(anchor.public)
        bootstrap(s, anchor, bodies=(), bucket=0)

        stranger = crypto.Keypair.generate()  # never held a MANAGER grant
        who = crypto.Keypair.generate()
        forged = Grant(
            identity=who.public,
            role=Role.CLIENT_RW,
            stores=frozenset({ops.STORE_DATA}),
            kinds=frozenset(),
            cert=Cert.sign_grant(stranger, who.public, Role.CLIENT_RW),
        )
        from ..store.managed import MapEntry
        plant = ops.writes(
            ops.Set(ops.STORE_MANAGEMENT, s.mgmt_reader._grants.entry_name(who.public),
                    MapEntry.encode(0, forged.encode_row()))
        ).sign(anchor, T0)
        intervene(s, anchor, bodies=(plant,), bucket=1)

        m = s.mgmt_reader
        self.assertIsNotNone(m.grant_of(who.public), "the row must exist, or this is vacuous")
        self.assertFalse(m.may_write(s, who.public, ops.STORE_DATA))
        self.assertFalse(m.may_read(s, who.public, ops.STORE_DATA), "unchained grant still read")


if __name__ == "__main__":
    unittest.main()
