# dude.store.management — the management store, as an API. See SPEC.md (#management-is-cleartext).
#
# Two halves, and the split is the whole point:
#
#   READS   derive from the store by replay. No secrets, no I/O, no network.
#   WRITES  RETURN AN UNSIGNED `Transaction`. They never apply anything, and never sign.
#
# Because a write returns an unsigned transaction rather than performing anything, several compose
# with `+` into ONE atomic unit — which is how #roster-change-is-atomic's "one transaction, not a
# sequence" gets
# enforced by the shape of the API instead of by remembering. A caller composes the mutations from
# several helpers with `+`, signs the union ONCE, and applies that — so a partial removal
# (a node out of the roster but still holding a live master) is not a state the API can reach.
#
# and it satisfies #one-write-vocabulary: there is no compound `remove_node` OPERATION, only a
# helper emitting `set` and `del`. Nothing here is a new opcode.
#
# KEYS ARE CLEARTEXT PATHS, not derived tokens. #management-is-cleartext makes control operations
# readable to
# nodes — they must be, since a node needs the node set and the ACL to function — and it must
# ENUMERATE node records, which opaque fixed-width digests cannot support. So the management
# store is a plain prefixed keyspace and `Store.prefix` is how it is read.

from __future__ import annotations

from collections.abc import Iterable
from dataclasses import dataclass
from enum import Enum
from typing import Protocol

from .. import quorum
from ..core import codec, crypto
from ..core.errors import DudeError
from ..net.address import Endpoint
from . import ops
from .layer import Reader


class ManagementError(DudeError):
    """A management record that is absent, malformed, or contradicts itself."""


class Role(Enum):
    """Who someone is, when they are an AUTHOR. Coarse, per #coarse-acl — the grant is by
    store or by operation kind, never by path prefix, because a node must check it without
    reading a key (#management-is-cleartext).

    STORAGE NODES ARE NOT AUTHORS (#nodes-are-not-authors). A node's identity does not have
    a Role — being a node means having a P_NODE row (with a #cert). Nodes arbitrate the
    log; they do not author transactions on their own key's authority."""

    MANAGER = b"manager"
    CLIENT = b"client"
    COMPACTOR = b"compactor"


type Domain = bytes
"""A failure-domain label, e.g. `b"provider:hetzner"`, `b"country:de"`, `b"asn:24940"`.

**OPAQUE.** Nothing in this package parses one — the prefix convention is for humans, and the code
only
ever COUNTS. That is what lets a deployment add axes (`rack:`, `psu:`, `cable:`) later without a
schema
change or a version bump."""

_CERT_DOMAIN = b"dude.management.cert:"
_CERT_PURPOSE_ROSTER = b"roster"
_CERT_PURPOSE_ROSTER_COMMITMENT = b"roster_commitment"


@dataclass(frozen=True, slots=True)
class Cert:
    """One authorisation cert shape, applied on every authority-carrying row (#cert).

    `subject` is `bytes` rather than `PublicKey` because the shape covers TWO kinds of
    attestation:
      * Identity attestations (P_GRANT, P_NODE): `subject` is the identity's pubkey bytes.
      * Content-commitment attestations (P_ROSTER commitment): `subject` is `crypto.h(content)`.
    Since `PublicKey` is a `bytes` subclass, comparing `cert.subject == pubkey` still works
    structurally for identity certs.

    Purpose values in use:
      * `role.value` (`b"manager"` / `b"client"` / `b"compactor"`) — P_GRANT identity cert
      * `b"roster"` — P_NODE identity cert
      * `b"roster_commitment"` — P_ROSTER content-commitment cert (subject is `H(serial ‖ members)`)

    The domain tag plus purpose binding is what stops an anchor-signed CLIENT cert from
    being repurposed into a MANAGER row: different bytes get signed for different purposes,
    so the sig doesn't verify when carried across.

    `verify()` is signature-only. Whether the signer is authorised for the purpose (anchor
    only for MANAGER/COMPACTOR; anchor OR valid manager for CLIENT/ROSTER/ROSTER_COMMITMENT)
    is `MgmtReader.verify_cert`, which reads state to answer."""

    signer: crypto.PublicKey
    subject: bytes
    purpose: bytes
    sig: crypto.Signature

    @classmethod
    def sign(cls, signer: crypto.Keypair, subject: bytes, purpose: bytes) -> Cert:
        return cls(
            signer.public,
            subject,
            purpose,
            signer.sign(_CERT_DOMAIN + purpose + b":" + subject),
        )

    @classmethod
    def sign_grant(cls, signer: crypto.Keypair, subject: crypto.PublicKey, role: Role) -> Cert:
        """Build a #cert attesting a grant of `role` to `subject`. Purpose is `role.value`."""
        return cls.sign(signer, bytes(subject), role.value)

    @classmethod
    def sign_roster(cls, signer: crypto.Keypair, subject: crypto.PublicKey) -> Cert:
        """Build a #cert attesting `subject`'s presence in the roster. Purpose is
        `_CERT_PURPOSE_ROSTER` (`b"roster"`)."""
        return cls.sign(signer, bytes(subject), _CERT_PURPOSE_ROSTER)

    @classmethod
    def sign_roster_commitment(cls, signer: crypto.Keypair, commitment_bytes: bytes) -> Cert:
        """Build a #cert attesting the roster commitment (#roster-commitment-cert).
        `commitment_bytes` is `codec.encode([serial, sorted_members, state_fingerprint])`
        -- the three fields the cert binds together. The cert's subject is
        `crypto.h(commitment_bytes)`, so ANY change to membership, endpoints, or domains
        produces a different hash and the cert fails to verify against it."""
        return cls.sign(signer, crypto.h(commitment_bytes), _CERT_PURPOSE_ROSTER_COMMITMENT)

    def verify(self) -> bool:
        """True if the signature matches `self.signer` over `(purpose, subject)`. Does not
        check whether the signer is currently authorised — see `MgmtReader.verify_cert`."""
        return self.signer.verify(_CERT_DOMAIN + self.purpose + b":" + self.subject, self.sig)

    def encode(self) -> bytes:
        return codec.encode([self.signer, self.subject, self.purpose, self.sig])

    @classmethod
    def decode(cls, raw: bytes) -> Cert:
        try:
            p = codec.as_seq(codec.decode(raw), 4)
            return cls(
                signer=crypto.PublicKey(codec.as_bytes(p[0])),
                subject=codec.as_bytes(p[1]),
                purpose=codec.as_bytes(p[2]),
                sig=crypto.Signature(codec.as_bytes(p[3])),
            )
        except DudeError as e:
            raise ManagementError(f"malformed Cert: {e}") from e


@dataclass(frozen=True, slots=True)
class Authorization:
    """May this payload be treated as authorised? (#manager-sig-overrides-quorum)

    ONE SHAPE, TWO WAYS TO BUILD IT, AND THAT IS THE POINT. A node reads `roster` and `anchor`
    from its own log and asks via `MgmtReader.authorises`; a light client holds them from a
    cert-verified `RosterBundle` and constructs this directly. Both then run the SAME `verify`.
    The rule lived in two places for one release -- `MgmtReader.authorization` and the light
    client's own `_verify_multisig` -- and the light-client copy was never asked to refuse
    anything, so the pair could have drifted arbitrarily far without a test noticing. An
    authorisation rule with two implementations has no implementation.

    BITMAP LAYOUT: `len(roster) + 1` positions. `0..N-1` are roster members in `roster` order;
    position `N` is the manager override, verified against the anchor. The `+1` is why the
    manager is not a roster member: putting it in the roster would move quorum arithmetic every
    time the cluster grew.

    TRUE if EITHER the manager slot signed (authorises alone) OR a quorum of roster slots did.
    FALSE if the multisig itself does not verify, or only sub-quorum roster slots signed with no
    override. Raises `CryptoError` (a `DudeError`) if the bitmap is the wrong width for the
    signer set -- it arrives off the wire, so a typed refusal rather than an IndexError."""

    multisig: crypto.MultiSig
    payload: bytes
    roster: tuple[crypto.PublicKey, ...]
    anchor: crypto.PublicKey

    def verify(self) -> bool:
        signers = (*self.roster, self.anchor)
        if not self.multisig.verify(self.payload, signers):
            return False
        manager_slot = len(self.roster)
        set_indices = self.multisig.indices(len(signers))
        if manager_slot in set_indices:
            return True  # manager override -- authorises alone
        roster_signers = sum(1 for i in set_indices if i < manager_slot)
        return roster_signers >= quorum.size(len(self.roster))


@dataclass(frozen=True, slots=True)
class NodeRecord:
    """A node's membership record. Its PRESENCE is membership (#presence-is-membership);
    deletion is removal.

    Carries a #cert with `purpose=b"roster"` attesting the entry from anchor or a valid
    manager. `nodes()` returns every row in the P_NODE keyspace; `roster()` filters out any
    row whose cert fails the authority check.

    ENDPOINTS, NOT BARE ADDRESSES (#peer-endpoint-in-log). Each entry is a full `Endpoint`
    (address + options). Per-endpoint transport config (TLS material, mixnet profile,
    concurrency limits) travels with the identity through the log; the cert covers row
    content so a hostile responder cannot fake options without a manager key.

    TWO ENCODING FORMS, both owned here so the layouts cannot drift (CLAUDE.md trap #1):
      * `encode()` / `decode(raw)` -- WIRE form, 4 fields including `identity` (used by
        light-client `RosterBundle` and anywhere else a NodeRecord travels standalone).
      * `encode_row()` / `decode_row(identity, raw)` -- DISK form, 3 fields without
        `identity` (P_NODE row body; identity is the key suffix). The asymmetry is real,
        not a bug: identity is the row key on disk, so storing it twice would just be
        redundancy waiting to disagree with itself.
    Drift-guard: `test_node_record_wire_and_row_agree_on_field_count` pins both counts."""

    identity: crypto.PublicKey
    endpoints: tuple[Endpoint, ...]
    cert: Cert
    domains: frozenset[Domain] = frozenset()
    """Which failure domains this node shares with others. Rack-aware placement, generalised:
    when one
    rack burns, you do not want the replacement in the rack beside it."""

    def encode(self) -> bytes:
        """Wire form: `[identity, endpoints, domains, cert]`, endpoints/domains sorted by
        encoded bytes for deterministic on-wire ordering."""
        return codec.encode(
            [
                self.identity,
                sorted(ep.encode() for ep in self.endpoints),
                sorted(self.domains),
                self.cert.encode(),
            ]
        )

    @classmethod
    def decode(cls, raw: bytes) -> NodeRecord:
        """Parse the wire form. Raises `DudeError` (via codec) on shape mismatch."""
        f = codec.as_seq(codec.decode(raw), 4)
        identity = crypto.PublicKey(codec.as_bytes(f[0]))
        endpoints = tuple(Endpoint.parse(codec.as_bytes(e)) for e in codec.as_seq(f[1]))
        domains = frozenset(codec.as_bytes(d) for d in codec.as_seq(f[2]))
        cert = Cert.decode(codec.as_bytes(f[3]))
        return cls(identity, endpoints, cert, domains)

    def encode_row(self) -> bytes:
        """Disk form (P_NODE row body): `[endpoints, domains, cert]`. Identity is the key
        suffix on disk (`P_NODE + identity`), so it's absent from the value."""
        return codec.encode(
            [
                sorted(ep.encode() for ep in self.endpoints),
                sorted(self.domains),
                self.cert.encode(),
            ]
        )

    @classmethod
    def decode_row(cls, identity: crypto.PublicKey, raw: bytes) -> NodeRecord:
        """Parse the disk form, given `identity` from the P_NODE row key."""
        f = codec.as_seq(codec.decode(raw), 3)
        endpoints = tuple(Endpoint.parse(codec.as_bytes(e)) for e in codec.as_seq(f[0]))
        domains = frozenset(codec.as_bytes(d) for d in codec.as_seq(f[1]))
        cert = Cert.decode(codec.as_bytes(f[2]))
        return cls(identity, endpoints, cert, domains)


@dataclass(frozen=True, slots=True)
class Grant:
    """What an identity may write. Pure authority -- `stores` is the set of store ids; `kinds`
    the operation kinds (the compactor's grant is a KIND, not a store -- there is no compaction
    store, #coarse-acl).

    `cert` is required (#cert) -- `purpose == role.value`. `may_write` / `may_send` refuse a
    grant whose cert does not verify or whose signer is not authorised for the role.

    NO ENDPOINTS. Nodes never dial clients back -- clients are ephemeral, may be behind NAT,
    connection may drop and reconnect. Replies flow back on the session the client opened (see
    `SessionLink` in `dude.net.link`). Where an identity CAN be reached is a discovery
    concern, not an authority concern; grants stay pure. Roster members (nodes) carry their
    addresses in `NodeRecord.endpoints` because nodes ARE dialable at stable addresses; that
    asymmetry with clients is what the split makes honest.

    TWO ENCODING FORMS, both owned here (parallels `NodeRecord`):
      * `encode()` / `decode(raw)` -- WIRE form (5 fields with identity), used by
        light-client `RosterBundle` and anywhere else a Grant travels standalone.
      * `encode_row()` / `decode_row(identity, raw)` -- DISK form (4 fields without
        identity; identity is the P_GRANT row key suffix)."""

    identity: crypto.PublicKey
    role: Role
    stores: frozenset[int]
    kinds: frozenset[int]
    cert: Cert

    def encode(self) -> bytes:
        """Wire form: `[identity, role.value, sorted_stores, sorted_kinds, cert]`."""
        return codec.encode(
            [
                self.identity,
                self.role.value,
                sorted(self.stores),
                sorted(self.kinds),
                self.cert.encode(),
            ]
        )

    @classmethod
    def decode(cls, raw: bytes) -> Grant:
        """Parse the wire form. Raises `DudeError` on shape mismatch; `ManagementError` on
        an unknown role value (semantic, not codec)."""
        f = codec.as_seq(codec.decode(raw), 5)
        identity = crypto.PublicKey(codec.as_bytes(f[0]))
        role_bytes = codec.as_bytes(f[1])
        try:
            role = Role(role_bytes)
        except ValueError as e:
            raise ManagementError(f"unknown role in Grant: {role_bytes!r}") from e
        stores = frozenset(codec.as_int(x) for x in codec.as_seq(f[2]))
        kinds = frozenset(codec.as_int(x) for x in codec.as_seq(f[3]))
        cert = Cert.decode(codec.as_bytes(f[4]))
        return cls(identity, role, stores, kinds, cert)

    def encode_row(self) -> bytes:
        """Disk form (P_GRANT row body): `[role.value, sorted_stores, sorted_kinds, cert]`.
        Identity is the key suffix on disk."""
        return codec.encode(
            [
                self.role.value,
                sorted(self.stores),
                sorted(self.kinds),
                self.cert.encode(),
            ]
        )

    @classmethod
    def decode_row(cls, identity: crypto.PublicKey, raw: bytes) -> Grant:
        """Parse the disk form, given `identity` from the P_GRANT row key."""
        f = codec.as_seq(codec.decode(raw), 4)
        role_bytes = codec.as_bytes(f[0])
        try:
            role = Role(role_bytes)
        except ValueError as e:
            raise ManagementError(f"unknown role for {identity.hex()[:8]}") from e
        stores = frozenset(codec.as_int(x) for x in codec.as_seq(f[1]))
        kinds = frozenset(codec.as_int(x) for x in codec.as_seq(f[2]))
        cert = Cert.decode(codec.as_bytes(f[3]))
        return cls(identity, role, stores, kinds, cert)


# --------------------------------------------------------------------------- #
# Key layout. One prefix per record type, so each is a range scan.             #
# --------------------------------------------------------------------------- #

P_NODE = b"node/"  # + identity          -> [addr, ...]
P_GRANT = b"grant/"  # + identity        -> [role, [store...], [kind...]]
P_POP = b"pop/"  # + identity            -> possession proof, from issuance (#possession-proof)
P_WRAP = b"wrap/"  # + epoch + identity  -> sealed master (#wrapped-masters)
P_ROSTER = b"roster"  # one key      -> [serial, [member, ...]] (#bootstrap-anchor step 7)


def _wrap_key(epoch: int, who: crypto.PublicKey) -> bytes:
    # epoch is fixed-width big-endian so the keyspace sorts by epoch, making "every wrap for epoch
    # N" a prefix scan rather than a filter.
    return P_WRAP + epoch.to_bytes(8, "big") + who


class Source(Reader, Protocol):
    """What a management view reads FROM: `Reader`'s rows, plus the anchor they are judged
    against.

    Rows alone are not enough -- #anchor-is-the-axiom means every authority question bottoms
    out at the provisioned anchor, so a management view that could not ask for it would have to
    be handed one by each caller, and a caller that supplies an anchor is a caller that can
    supply the wrong one. `Store` and the `StoreReader` a `store.snapshot()` yields both satisfy
    this; a `Layer` does NOT, which is correct -- an overlay has rows but no provisioning.

    Narrower than `Store` on purpose. The previous shape annotated the constructor as `Store`
    while using only these three methods, so every snapshot-scoped caller had to `cast` a
    `StoreReader` it already held into a `Store` it did not have."""

    def anchor(self) -> crypto.PublicKey | None: ...


class MgmtReader:
    """The management store's READ surface -- every query that returns pure data (bool,
    dict, Grant, NodeRecord, ...). Used by:

      * `settle.evaluate`'s auth check, with a Layer-Reader passed to `may_write`.
      * External observation (`node.mgmt.roster()`, `store.mgmt.grant_of(...)`) via
        the Store's convenience wrappers.
      * Composed read snapshots (`with store.snapshot() as r: MgmtReader(r).nodes()`)
        when a caller needs a coherent moment across multiple reads.

    Self-contained: a caller that holds this needs no other knowledge of how membership,
    authorisation, or key distribution are encoded."""

    def __init__(self, src: Source, store_id: int = ops.STORE_MANAGEMENT):
        self.src = src
        self.store_id = store_id

    # -- reads ---------------------------------------------------------------- #

    def nodes(self) -> dict[crypto.PublicKey, NodeRecord]:
        """Every node currently in the P_NODE keyspace. A prefix scan
        (#presence-is-membership: presence is membership).

        RETURNS EVERY ENTRY — including any with an invalid #cert. Callers that want "who
        is actually authorised" use `roster()`, which filters. Callers that want "what rows
        are in the P_NODE keyspace" (introspection, tests) use this."""
        out: dict[crypto.PublicKey, NodeRecord] = {}
        for name, _prov, value, _ep in self.src.prefix(self.store_id, P_NODE):
            who = crypto.PublicKey(name[len(P_NODE) :])
            out[who] = NodeRecord.decode_row(who, value)
        return out

    def roster(self) -> tuple[crypto.PublicKey, ...]:
        """The roster as a sorted tuple of currently-authorised nodes — sorted because a
        signer bitmap indexes into it, and two implementations must agree on the order.
        Never rely on mapping iteration order for this: Go randomises it, so an unsorted
        roster would produce different bitmaps per language.

        FILTERS INVALIDLY-ATTESTED ENTRIES. Each entry's #cert must verify AND its signer
        must be authorised for the roster purpose (anchor or a currently-valid manager).
        Rows that fail this check appear in `nodes()` for introspection but are absent from
        the roster used for authorisation and quorum arithmetic.

        Also refuses entries whose cert `subject` or `purpose` do not match the row — a
        cert-substitution attempt where an anchor-signed cert for X is stuffed into Y's
        row fails at the subject check.

        THIS IS THE ONE ROSTER SOURCE. `Store.roster()` used to delegate here; deleted. Anyone
        needing the roster asks Management (which is what owns authority questions in general)."""
        out: list[crypto.PublicKey] = []
        for who, rec in self.nodes().items():
            if rec.cert.subject != who:
                continue
            if rec.cert.purpose != _CERT_PURPOSE_ROSTER:
                continue
            if not self.verify_cert(rec.cert):
                continue
            out.append(who)
        return tuple(sorted(out))

    def verify_cert(self, cert: Cert) -> bool:  # noqa: PLR0911 -- each early-return names a distinct refusal reason; collapsing them into one `and`-chain hides which check failed
        """True iff `cert` is signature-valid AND its signer is authorised for its
        `purpose` (#cert):

          * `purpose == b"manager"` or `b"compactor"`: signer MUST be the store's anchor.
          * `purpose == b"client"` or `b"roster"`: signer MUST be the store's anchor OR
            an identity currently holding a valid Role.MANAGER grant.

        Signature-only check for the manager-cert-to-anchor hop; the manager's grant-row
        presence is checked implicitly via `_read_grant`, which returns None if the row
        has been deleted (#absence-is-revocation).

        Returns False on an unprovisioned store — no anchor means no authority."""
        anchor = self.src.anchor()
        if anchor is None:
            return False
        if not cert.verify():
            return False
        anchor_only_purposes = (Role.MANAGER.value, Role.COMPACTOR.value)
        anchor_or_manager_purposes = (
            Role.CLIENT.value,
            _CERT_PURPOSE_ROSTER,
            _CERT_PURPOSE_ROSTER_COMMITMENT,
        )
        if cert.purpose in anchor_only_purposes:
            return cert.signer == anchor
        if cert.purpose in anchor_or_manager_purposes:
            if cert.signer == anchor:
                return True
            grant = self._read_grant(self.src, cert.signer)
            if grant is None or grant.role is not Role.MANAGER:
                return False
            return (
                grant.cert.subject == cert.signer
                and grant.cert.purpose == Role.MANAGER.value
                and grant.cert.verify()
                and grant.cert.signer == anchor
            )
        return False

    def manager_grants(self) -> tuple[Grant, ...]:
        """Every currently-attested Role.MANAGER grant. Prefix scan over P_GRANT,
        filtered to `role is Role.MANAGER` and cert-valid. Used by the light-client
        bundle: the manager set is what verifies roster-entry certs whose signer isn't
        the anchor directly (#light-client-cert-chain)."""
        out: list[Grant] = []
        for name, _prov, _value, _ep in self.src.prefix(self.store_id, P_GRANT):
            who = crypto.PublicKey(name[len(P_GRANT) :])
            grant = self._read_grant(self.src, who)
            if grant is None or grant.role is not Role.MANAGER:
                continue
            if not self._grant_cert_ok(grant):
                continue
            out.append(grant)
        # Sort by identity for deterministic bundle content.
        out.sort(key=lambda g: bytes(g.identity))
        return tuple(out)

    def roster_commitment_full(  # noqa: PLR0911 -- each early-return names a distinct refusal reason; collapsing hides which check failed
        self,
    ) -> tuple[int, tuple[crypto.PublicKey, ...], crypto.Digest, Cert] | None:
        """Same shape as `roster_commitment()` but also returns the state_fingerprint and
        the commitment cert -- what the light-client bundle needs to ship the full
        signed commitment (#roster-commitment-cert, #light-client-cert-chain).

        Runs the same cross-checks as `roster_commitment()` and returns None on any
        failure, so a caller that trusts a non-None result trusts the commitment fully."""
        raw = self.src.get(self.store_id, P_ROSTER)
        if raw is None:
            return None
        try:
            f = codec.as_seq(codec.decode(raw[1]), 4)
            serial = codec.as_int(f[0])
            members_seq = codec.as_seq(f[1])
            members = tuple(crypto.PublicKey(codec.as_bytes(m)) for m in members_seq)
            state_fingerprint = crypto.Digest(codec.as_bytes(f[2]))
            cert = Cert.decode(codec.as_bytes(f[3]))
        except DudeError:
            return None
        content_bytes = codec.encode([serial, sorted(bytes(m) for m in members), state_fingerprint])
        if cert.subject != crypto.h(content_bytes):
            return None
        if cert.purpose != _CERT_PURPOSE_ROSTER_COMMITMENT:
            return None
        if not self.verify_cert(cert):
            return None
        # Reuse the state-cross-check from roster_commitment(): the commitment attests a
        # state that MUST match the P_NODE rows on hand.
        member_set = set(members)
        current_nodes = self.nodes()
        expected_state = crypto.h(
            codec.encode(
                [
                    [
                        bytes(rec.identity),
                        sorted(ep.encode() for ep in rec.endpoints),
                        sorted(rec.domains),
                    ]
                    for rec in sorted(current_nodes.values(), key=lambda r: bytes(r.identity))
                    if rec.identity in member_set
                ]
            )
        )
        if expected_state != state_fingerprint:
            return None
        return serial, members, state_fingerprint, cert

    def endpoints_of(self, who: crypto.PublicKey) -> tuple[Endpoint, ...]:
        """Where `who` can be reached, and with what per-endpoint options
        (#peer-endpoint-in-log). A node may be multi-homed; `dude.net` chooses among them.

        Returns full `Endpoint`s (address + options), not bare addresses -- Postman needs
        the options to dial correctly. See #peer-options-are-endpoint-options."""
        rec = self.nodes().get(who)
        return rec.endpoints if rec else ()

    def roster_commitment(self) -> tuple[int, tuple[crypto.PublicKey, ...]] | None:
        """The manager's signed statement of WHO THE MEMBERS ARE, and which revision it is.

        STEP 7 OF THE CHAIN (#bootstrap-anchor). Enumerating `node/` rows tells a holder of state
        who the members are; it cannot tell a party HANDED some rows that it received all of
        them, and a subset is a smaller roster, which is a smaller quorum. One value the manager
        signed closes that: a subset of a list is not that list.

        THE SERIAL MAKES A STALE ROSTER DETECTABLE, by the argument the floor rests on: an adversary
        can withhold a newer commitment but cannot forge a higher serial without the manager's key,
        so believing the highest one you can verify is correct rather than credulous. Without it a
        genuine-but-superseded roster — members since removed, whose keys an adversary may still
        hold — verifies perfectly.

        CERT-CHECKED (#roster-commitment-cert). Row content is
        `[serial, sorted_members, state_fingerprint, cert.encode()]`. Cert's subject MUST equal
        `crypto.h(codec.encode([serial, sorted_members, state_fingerprint]))` -- any tamper
        with any of the three (member set, endpoints, domains) produces a different hash and
        the cert fails to verify. Signer MUST be anchor or a currently-valid manager. Returns
        None on any check failure, so a caller that trusts a non-None result trusts the
        commitment fully.

        RECOMPUTES `state_fingerprint` from the current P_NODE rows and checks it matches the
        stored fingerprint. If not, the commitment attests a different state than the log
        holds -- a mismatch that should not occur in practice (the same tx that writes the
        commitment writes the P_NODE rows), and if it does, treat the commitment as invalid."""
        raw = self.src.get(self.store_id, P_ROSTER)
        if raw is None:
            return None
        f = codec.as_seq(codec.decode(raw[1]), 4)
        serial = codec.as_int(f[0])
        members_seq = codec.as_seq(f[1])
        members = tuple(crypto.PublicKey(codec.as_bytes(m)) for m in members_seq)
        state_fingerprint = crypto.Digest(codec.as_bytes(f[2]))
        cert = Cert.decode(codec.as_bytes(f[3]))
        # Recompute the commitment binding and verify.
        content_bytes = codec.encode([serial, sorted(bytes(m) for m in members), state_fingerprint])
        if cert.subject != crypto.h(content_bytes):
            return None
        if cert.purpose != _CERT_PURPOSE_ROSTER_COMMITMENT:
            return None
        if not self.verify_cert(cert):
            return None
        # Cross-check the state_fingerprint against the actual P_NODE rows. Mismatch means
        # the commitment attests a state different from what the log holds; refuse.
        member_set = set(members)
        current_nodes = self.nodes()
        expected_state = crypto.h(
            codec.encode(
                [
                    [
                        bytes(rec.identity),
                        sorted(ep.encode() for ep in rec.endpoints),
                        sorted(rec.domains),
                    ]
                    for rec in sorted(current_nodes.values(), key=lambda r: bytes(r.identity))
                    if rec.identity in member_set
                ]
            )
        )
        if expected_state != state_fingerprint:
            return None
        return serial, members

    def _read_grant(self, reader: Reader, who: crypto.PublicKey) -> Grant | None:
        """The primitive grant lookup. Reads from `reader` (typically `self.src`, but the
        transaction's own layer during evaluation) so a grant made by an earlier step is
        visible to a later step's check.

        Row body is 4 fields: role, stores, kinds, cert-bytes (identity from key). Decoded
        via `Grant.decode_row` so the layout stays owned by the dataclass."""
        raw = reader.get(self.store_id, P_GRANT + who)
        if raw is None:
            return None
        return Grant.decode_row(who, raw[1])

    def grant_of(self, who: crypto.PublicKey) -> Grant | None:
        """The default-reader convenience: look up a grant against `self.src`. Same shape as
        `_read_grant(self.src, who)`."""
        return self._read_grant(self.src, who)

    def may_write(self, reader: Reader, who: crypto.PublicKey, store_id: int) -> bool:
        """`#coarse-acl`'s check: may `who` write `store_id`? The one authority question a node
        can answer blind, because the store id is cleartext in every operation.

        THE ANCHOR IS ALWAYS AUTHORISED. The anchor pubkey (`store.anchor()`, provisioned
        out-of-band) is the axiom the whole authority chain hangs from -- its grants are
        what create the rest of the roster's authority in the first place. Checking its
        authority against a log it itself authorises would be circular; treating it as
        always-may-write is what makes bootstrap a manager-signed block rather than a special-
        cased evaluator bypass (`auth=None`, deleted).

        GRANTS ARE CERT-CHECKED. Every grant carries a #cert; the grant is honoured only
        if the cert's subject matches the row key, its purpose matches the row's role, its
        signature verifies, and its signer is authorised for that role. A row that fails
        any of those is treated as absent, closing the direct-write bypass at read-time
        even before eval-time enforcement lands.

        Takes `reader` per call so a grant made by an earlier step in a transaction is visible
        to a later step's check (authorise -> use -> revoke, in one atomic transaction)."""
        if who == self.src.anchor():
            return True
        g = self._read_grant(reader, who)
        if g is None or not self._grant_cert_ok(g):
            return False
        if g.role is Role.MANAGER:
            return True
        return store_id in g.stores

    def may_send(self, who: crypto.PublicKey, kind: int) -> bool:
        """Whether `who` may author an operation of this kind — the grant that has no store, e.g. a
        compaction (#coarse-acl).

        THE ANCHOR IS ALWAYS AUTHORISED (#anchor-is-the-axiom), same rule as `may_write` --
        applied consistently here so `may_write` and `may_send` do not disagree about the
        axiomatic identity. Grants are cert-checked (#cert), same rule as `may_write`."""
        if who == self.src.anchor():
            return True
        g = self.grant_of(who)
        if g is None or not self._grant_cert_ok(g):
            return False
        if g.role is Role.MANAGER:
            return True
        return kind in g.kinds

    def _grant_cert_ok(self, g: Grant) -> bool:
        """The cert-consistency check every grant-honouring path runs. Cert `subject` must
        match the grant identity, `purpose` must match `role.value`, signature must verify,
        and signer must be authorised for the role. See `verify_cert` for the signer rule."""
        if g.cert.subject != g.identity:
            return False
        if g.cert.purpose != g.role.value:
            return False
        return self.verify_cert(g.cert)

    def authorises(self, multisig: crypto.MultiSig, payload: bytes) -> bool:
        """Is this block-shape proof authorised against OUR roster and anchor
        (SPECv2 #manager-sig-overrides-quorum)?

        The roster and the anchor are not parameters: this object reads them from the log it
        already holds. A caller that had to supply them could supply the wrong ones, and the
        one caller that legitimately holds its own -- a light client, whose roster came from a
        cert-verified bundle rather than from a log -- builds an `Authorization` directly.
        Both run the same `verify`.

        Raises `ManagementError` if the store is not provisioned: there is no anchor to check
        the override slot against, which is a misconfiguration, not a routine failure."""
        anchor = self.src.anchor()
        if anchor is None:
            raise ManagementError("cannot authorize: store has no manager anchor")
        return Authorization(multisig, payload, self.roster(), anchor).verify()

    def possession_proof(self, who: crypto.PublicKey) -> crypto.Signature | None:
        raw = self.src.get(self.store_id, P_POP + who)
        return crypto.Signature(raw[1]) if raw else None

    def wrapped_master(self, epoch: int, who: crypto.PublicKey) -> crypto.SealedBlob | None:
        """`who`'s sealed copy of the epoch master (#wrapped-masters). Opening it is the
        holder's business;
        this layer never sees a secret."""
        raw = self.src.get(self.store_id, _wrap_key(epoch, who))
        return crypto.SealedBlob(raw[1]) if raw else None

    def domain_groups(self) -> dict[Domain, frozenset[crypto.PublicKey]]:
        """Which nodes share each label. A pure fold over the roster."""
        groups: dict[Domain, set[crypto.PublicKey]] = {}
        for rec in self.nodes().values():
            for d in rec.domains:
                groups.setdefault(d, set()).add(rec.identity)
        return {d: frozenset(m) for d, m in groups.items()}

    def check_domains(self) -> dict[Domain, int]:
        """Domains over the advisory `max_domain(n)` bound. Empty when composition is sound.

        ADVISORY, NOT ENFORCEMENT. `change_roster` does NOT refuse on this -- callers use it
        for operator inspection (#quorum-gate, `quorum.domain_advisory`). In production this
        IS the failure mode that bites (single-provider concentration → provider outage →
        cluster loses quorum until recovery), which is why it is worth reporting; it stays
        advisory because hard refusal blocks legitimate incremental improvements."""
        counts: dict[Domain, int] = {}
        for rec in self.nodes().values():
            for d in rec.domains:
                counts[d] = counts.get(d, 0) + 1
        return quorum.domain_advisory(counts, len(self.nodes()))


class MgmtWriter(MgmtReader):
    """The management store's TRANSACTION-COMPOSING surface. Every method here READS the
    store (inherited from MgmtReader) to compose an unsigned `ops.Transaction`; the tx
    then gets signed and submitted through consensus. Nothing here writes to the store
    directly -- that's `Store.commit_block`'s job at settle time.

    Snapshot consistency matters here: a composed tx's cert can reference the roster,
    the anchor, and the current commitment; if those reads race a writer's commit, the
    tx's eval-time check will fail. Callers should wrap in a snapshot scope:

        with store.snapshot() as r:
            tx = MgmtWriter(r).change_roster(commitment_signer=..., add=...)
        tx.sign(mgr, now).submit(...)

    Store's convenience `store.mgmt.change_roster(...)` bypass exists for one-shot
    read-consistent-enough cases (a quiet cluster) but is not safe under a concurrent
    writer -- use the snapshot form for any operator-authored change_roster."""

    # -- writes: emit mutations, apply nothing -------------------------------- #

    def change_roster(
        self,
        *,
        commitment_signer: crypto.Keypair,
        add: Iterable[NodeRecord] = (),
        remove: Iterable[crypto.PublicKey] = (),
    ) -> ops.Transaction:
        """Batched atomic roster change: add nodes, remove nodes, and update the
        commitment-cert-carrying P_ROSTER row in ONE transaction (#roster-change-is-atomic,
        #roster-commitment-cert).

        `commitment_signer` is the keypair that signs the P_ROSTER commitment cert. Must be
        the anchor OR an identity currently holding a valid Role.MANAGER grant. Passed
        keyword-only so it is impossible to forget alongside the add / remove positionals.

        HARD BRICK REFUSAL. Refuses if the post-state has `quorum.would_brick(n_after)` --
        equivalently, `n_after < 3`, where any single node reboot leaves quorum unreachable.
        That is the only refusal path: composition (domain concentration) is ADVISORY only,
        per `quorum.domain_advisory` (#quorum-gate). Rack-awareness that severely interferes
        with routine operation is worse than none; legitimate improvement moves to a
        concentrated cluster frequently pass through composition-violating intermediate
        states, and refusing them one-at-a-time turned a growth mechanism into a footgun.
        The operator inspects `check_domains()` and acts.

        BATCHING. Adds and removes commit atomically. Intermediate states do not exist
        externally, so a roster change reaches its target composition in one step -- the
        one-at-a-time growth constraint noted in the earlier `add_node` docstring
        (3-3-3-2 across four providers not reachable node-by-node) is dissolved by this API.

        THE ESCAPE HATCH. `intervene()` (#anchor-is-the-axiom) lets the anchor sign arbitrary
        mutation ops, bypassing this composition-agnostic path entirely. Use when a routine
        `change_roster` cannot reach a safe post-state in one batch."""
        add = tuple(add)
        remove = tuple(remove)
        before = self.nodes()
        after: dict[crypto.PublicKey, NodeRecord] = dict(before)
        for who in remove:
            after.pop(who, None)
        for rec in add:
            after[rec.identity] = rec
        n_before = len(before)
        n_after = len(after)
        # THE ONLY REFUSAL: you cannot ENTER a bricked state from a safe one. Growth through
        # n<3 is allowed (bootstrap starts at n=0), same-size or larger transitions are always
        # allowed. Shrinking a safe cluster (n>=3) down to n<3 is refused, because that turns a
        # working cluster into one that a single reboot bricks. Use intervene() for anchor
        # rescue if a shrink into brick is truly deliberate.
        if not quorum.would_brick(n_before) and quorum.would_brick(n_after):
            raise ManagementError(
                f"change_roster would shrink from n={n_before} (safe) to n={n_after} "
                f"(would_brick); refused. Use intervene() for anchor rescue if deliberate."
            )
        # Validate every added entry's #cert at construction time. Cert must attest the
        # roster purpose, target the entry's identity, verify, and be signed by an
        # authorised signer (anchor or currently-valid manager). Eval-time refusal of a
        # raw `Set P_NODE` bypassing this is OWED.
        for rec in add:
            if rec.cert.subject != rec.identity:
                raise ManagementError(
                    f"cert.subject {rec.cert.subject.hex()[:8]} does not match node "
                    f"identity {rec.identity.hex()[:8]}"
                )
            if rec.cert.purpose != _CERT_PURPOSE_ROSTER:
                raise ManagementError(
                    f"cert.purpose {rec.cert.purpose!r} is not the roster purpose"
                )
            if not self.verify_cert(rec.cert):
                raise ManagementError(
                    f"cert for node {rec.identity.hex()[:8]} does not verify or signer "
                    f"is not authorised"
                )
        # Compose one atomic Transaction. Order:
        #   1. Remove: Del P_NODE + Del P_POP for each removed identity
        #   2. Add:    Set P_NODE for each added record (addresses + domains + cert)
        #   3. Commit: Set P_ROSTER with fresh commitment (serial = current + 1)
        # PoPs for added nodes are the caller's business (they come via `authorise`, which is
        # a separate step composed onto this transaction).
        steps: list[ops.Mutation] = []
        for who in remove:
            steps.append(ops.Del(self.store_id, P_NODE + who))
            steps.append(ops.Del(self.store_id, P_POP + who))
        # Row body via NodeRecord.encode_row -- layout owned by the dataclass so wire and
        # disk cannot silently drift (CLAUDE.md trap #1).
        steps.extend(ops.Set(self.store_id, P_NODE + rec.identity, rec.encode_row()) for rec in add)
        # Roster commitment (#roster-commitment-cert). Payload binds THREE fields:
        #   1. serial            -- monotone, bumps per change
        #   2. sorted_members    -- pubkeys only (membership fingerprint)
        #   3. state_fingerprint -- H over per-member (pubkey, endpoints, domains)
        # The cert covers all three atomically. A change to ANY of them (membership,
        # endpoints, options, domains) produces a different subject and requires a fresh
        # cert. Signer is anchor or a currently-valid manager.
        current = self.roster_commitment()
        next_serial = (current[0] + 1) if current is not None else 1
        sorted_members = sorted(bytes(m) for m in after)
        # state_fingerprint captures the FULL per-member state so light clients and node
        # reconciliation can detect endpoint / option / domain changes with a single hash
        # compare (#light-client-piggyback, #roster-drives-peers). Members sorted by
        # pubkey so the hash is deterministic across implementations.
        state_content = codec.encode(
            [
                [
                    bytes(rec.identity),
                    sorted(ep.encode() for ep in rec.endpoints),
                    sorted(rec.domains),
                ]
                for rec in sorted(after.values(), key=lambda r: bytes(r.identity))
            ]
        )
        state_fingerprint = crypto.h(state_content)
        commitment_content = codec.encode([next_serial, sorted_members, state_fingerprint])
        commitment_cert = Cert.sign_roster_commitment(commitment_signer, commitment_content)
        if not self.verify_cert(commitment_cert):
            raise ManagementError(
                f"commitment_signer {commitment_signer.public.hex()[:8]} is not authorised "
                f"to sign the roster commitment (must be anchor or a valid manager)"
            )
        commitment_row = codec.encode(
            [next_serial, sorted_members, state_fingerprint, commitment_cert.encode()]
        )
        steps.append(ops.Set(self.store_id, P_ROSTER, commitment_row))
        return ops.writes(*steps)

    def add_node(
        self,
        who: crypto.PublicKey,
        endpoints: tuple[Endpoint, ...],
        cert: Cert,
        *,
        commitment_signer: crypto.Keypair,
        domains: frozenset[Domain] = frozenset(),
    ) -> ops.Transaction:
        """Convenience wrapper on `change_roster`: single-node add. See `change_roster` for
        the full semantics (batched, brick-refuse only, advisory composition, cert-checked).

        `endpoints` are full `Endpoint`s (address + per-endpoint options), not bare
        addresses -- see #peer-endpoint-in-log."""
        return self.change_roster(
            commitment_signer=commitment_signer,
            add=(NodeRecord(who, endpoints, cert, domains),),
        )

    def remove_node(
        self, who: crypto.PublicKey, *, commitment_signer: crypto.Keypair
    ) -> ops.Transaction:
        """Convenience wrapper on `change_roster`: single-node remove. See `change_roster`
        for the full semantics.

        NOTE: previously this emitted a bare `Del P_NODE` without the roster-commitment
        update, silently violating #roster-change-is-atomic. Now delegates to `change_roster`
        which composes the commitment update, PoP deletion, and node deletion atomically."""
        return self.change_roster(commitment_signer=commitment_signer, remove=(who,))

    def authorise(  # noqa: PLR0913, PLR0917 -- every arg is a distinct required piece of a grant; collapsing them hides intent and forces callers to build dicts
        self,
        who: crypto.PublicKey,
        role: Role,
        stores: frozenset[int] = frozenset(),
        kinds: frozenset[int] = frozenset(),
        pop: crypto.Signature | None = None,
        cert: Cert | None = None,
    ) -> ops.Transaction:
        """Authorise an identity (#role-manager-grant, #cert).

        `pop` is the subject's proof that it holds the secret half — the anchor/manager
        never certifies a key it did not see proven (#possession-proof).

        `cert` is the #cert attesting the grant. It is validated here rather than trusted:
          * `cert.subject` MUST equal `who`.
          * `cert.purpose` MUST equal `role.value`.
          * `cert.verify()` MUST hold (signature-only).
          * `cert.signer` MUST be authorised for the role: anchor-only for MANAGER and
            COMPACTOR, anchor-or-currently-valid-manager for CLIENT.

        NO `endpoints` PARAMETER. Grants are pure authority; location is a discovery concern.
        Nodes never dial back to clients -- clients reach nodes by dialing them, and replies
        flow back on the session the client opened (`SessionLink`). Roster members carry
        their own addresses in `NodeRecord.endpoints`; that asymmetry is honest because
        nodes ARE dialable at stable addresses and clients are not.

        Refuses at construction time on any missing / invalid input. This is the API-side
        check; eval-time refusal of a raw `Set P_GRANT` bypassing this method is OWED (see
        the enforcement table for #cert)."""
        if pop is None or not who.verify_possession(pop):
            raise ManagementError(f"no valid possession proof for {who.hex()[:8]}")
        if cert is None:
            raise ManagementError(f"authorise requires a #cert (role={role.name})")
        if cert.subject != who:
            raise ManagementError(
                f"cert.subject {cert.subject.hex()[:8]} does not match grant subject "
                f"{who.hex()[:8]}"
            )
        if cert.purpose != role.value:
            raise ManagementError(f"cert.purpose {cert.purpose!r} does not match role {role.name}")
        if not self.verify_cert(cert):
            raise ManagementError(
                f"cert does not verify or signer is not authorised for role {role.name}"
            )
        record = Grant(who, role, stores, kinds, cert).encode_row()
        return ops.writes(
            ops.Set(self.store_id, P_GRANT + who, record),
            ops.Set(self.store_id, P_POP + who, pop),
        )

    def revoke(self, who: crypto.PublicKey) -> ops.Transaction:
        """Forward-only (#absence-is-revocation): operations this identity already authored
        stay valid, because
        validity is relative to the position at which they were authorised."""
        return ops.writes(
            ops.Del(self.store_id, P_GRANT + who),
            ops.Del(self.store_id, P_POP + who),
        )

    def distribute(
        self, epoch: int, wraps: dict[crypto.PublicKey, crypto.SealedBlob]
    ) -> ops.Transaction:
        """One wrapped master per authorised holder, for one keyepoch (#wrapped-masters).

        Atomicity is the point: every holder gains the secret together or none does, so no client is
        left holding data it cannot read. Sorted so two implementations emit identical mutations."""
        return ops.writes(
            *(ops.Set(self.store_id, _wrap_key(epoch, who), wraps[who]) for who in sorted(wraps))
        )
