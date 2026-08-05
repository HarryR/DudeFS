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
from typing import TYPE_CHECKING

from .. import quorum
from ..core import codec, crypto
from ..core.errors import DudeError
from . import ops
from .layer import Reader

if TYPE_CHECKING:
    from .store import Store

# A transport locator, opaque here on purpose: the management store records WHERE a node can be
# reached as a string, and `dude.net` owns what the string means. Keeping the parse out of the store
# is what stops carrier vocabulary leaking into the log (#transport-adds-no-trust — transport adds
# no trust).
type Address = bytes


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


@dataclass(frozen=True, slots=True)
class Cert:
    """One authorisation cert shape, applied on every authority-carrying row (#cert).

    On a P_GRANT row: `purpose = role.value` (e.g. `b"manager"`). On a P_NODE row:
    `purpose = _CERT_PURPOSE_ROSTER` (`b"roster"`).

    The domain tag plus purpose binding is what stops an anchor-signed CLIENT cert from
    being repurposed into a MANAGER row: different bytes get signed for different purposes,
    so the sig doesn't verify when carried across.

    `verify()` is signature-only. Whether the signer is authorised for the purpose (anchor
    only for MANAGER/COMPACTOR; anchor OR valid manager for CLIENT/ROSTER) is
    `Management.verify_cert`, which reads state to answer."""

    signer: crypto.PublicKey
    subject: crypto.PublicKey
    purpose: bytes
    sig: crypto.Signature

    @classmethod
    def sign(cls, signer: crypto.Keypair, subject: crypto.PublicKey, purpose: bytes) -> Cert:
        return cls(
            signer.public,
            subject,
            purpose,
            signer.sign(_CERT_DOMAIN + purpose + b":" + subject),
        )

    @classmethod
    def sign_grant(cls, signer: crypto.Keypair, subject: crypto.PublicKey, role: Role) -> Cert:
        """Build a #cert attesting a grant of `role` to `subject`. Purpose is `role.value`."""
        return cls.sign(signer, subject, role.value)

    @classmethod
    def sign_roster(cls, signer: crypto.Keypair, subject: crypto.PublicKey) -> Cert:
        """Build a #cert attesting `subject`'s presence in the roster. Purpose is
        `_CERT_PURPOSE_ROSTER` (`b"roster"`)."""
        return cls.sign(signer, subject, _CERT_PURPOSE_ROSTER)

    def verify(self) -> bool:
        """True if the signature matches `self.signer` over `(purpose, subject)`. Does not
        check whether the signer is currently authorised — see `Management.verify_cert`."""
        return self.signer.verify(_CERT_DOMAIN + self.purpose + b":" + self.subject, self.sig)

    def encode(self) -> bytes:
        return codec.encode([self.signer, self.subject, self.purpose, self.sig])

    @classmethod
    def decode(cls, raw: bytes) -> Cert:
        try:
            p = codec.as_seq(codec.decode(raw), 4)
            return cls(
                signer=crypto.PublicKey(codec.as_bytes(p[0])),
                subject=crypto.PublicKey(codec.as_bytes(p[1])),
                purpose=codec.as_bytes(p[2]),
                sig=crypto.Signature(codec.as_bytes(p[3])),
            )
        except DudeError as e:
            raise ManagementError(f"malformed Cert: {e}") from e


@dataclass(frozen=True, slots=True)
class NodeRecord:
    """A node's membership record. Its PRESENCE is membership (#presence-is-membership);
    deletion is removal.

    Carries a #cert with `purpose=b"roster"` attesting the entry from anchor or a valid
    manager. `nodes()` returns every row in the P_NODE keyspace; `roster()` filters out any
    row whose cert fails the authority check."""

    identity: crypto.PublicKey
    addresses: tuple[Address, ...]
    cert: Cert
    domains: frozenset[Domain] = frozenset()
    """Which failure domains this node shares with others. Rack-aware placement, generalised:
    when one
    rack burns, you do not want the replacement in the rack beside it."""


@dataclass(frozen=True, slots=True)
class Grant:
    """What an identity may write. `stores` is the set of store ids; `kinds` the operation kinds
    (the compactor's grant is a KIND, not a store — there is no compaction store, #coarse-acl).

    `cert` is required (#cert) — `purpose == role.value`. `may_write` / `may_send` refuse
    a grant whose cert does not verify or whose signer is not authorised for the role."""

    identity: crypto.PublicKey
    role: Role
    stores: frozenset[int]
    kinds: frozenset[int]
    cert: Cert


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


class Management:
    """The management store, read and written through one place.

    Self-contained by design: a caller that holds this needs no other knowledge of how membership,
    authorisation or key distribution are encoded."""

    def __init__(self, store: Store, store_id: int = ops.STORE_MANAGEMENT):
        self.store = store
        self.store_id = store_id

    # -- reads ---------------------------------------------------------------- #

    def nodes(self) -> dict[crypto.PublicKey, NodeRecord]:
        """Every node currently in the P_NODE keyspace. A prefix scan
        (#presence-is-membership: presence is membership).

        RETURNS EVERY ENTRY — including any with an invalid #cert. Callers that want "who
        is actually authorised" use `roster()`, which filters. Callers that want "what rows
        are in the P_NODE keyspace" (introspection, tests) use this."""
        out: dict[crypto.PublicKey, NodeRecord] = {}
        for name, _prov, value, _ep in self.store.prefix(self.store_id, P_NODE):
            who = crypto.PublicKey(name[len(P_NODE) :])
            f = codec.as_seq(codec.decode(value), 3)
            addrs = tuple(codec.as_bytes(a) for a in codec.as_seq(f[0]))
            doms = frozenset(codec.as_bytes(d) for d in codec.as_seq(f[1]))
            cert = Cert.decode(codec.as_bytes(f[2]))
            out[who] = NodeRecord(who, addrs, cert, doms)
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
        anchor = self.store.anchor()
        if anchor is None:
            return False
        if not cert.verify():
            return False
        anchor_only_purposes = (Role.MANAGER.value, Role.COMPACTOR.value)
        anchor_or_manager_purposes = (Role.CLIENT.value, _CERT_PURPOSE_ROSTER)
        if cert.purpose in anchor_only_purposes:
            return cert.signer == anchor
        if cert.purpose in anchor_or_manager_purposes:
            if cert.signer == anchor:
                return True
            grant = self._read_grant(self.store, cert.signer)
            if grant is None or grant.role is not Role.MANAGER:
                return False
            return (
                grant.cert.subject == cert.signer
                and grant.cert.purpose == Role.MANAGER.value
                and grant.cert.verify()
                and grant.cert.signer == anchor
            )
        return False

    def addresses_of(self, who: crypto.PublicKey) -> tuple[Address, ...]:
        """Where `who` can be reached. A node may be multi-homed; `dude.net` chooses among them."""
        rec = self.nodes().get(who)
        return rec.addresses if rec else ()

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
        hold — verifies perfectly."""
        raw = self.store.get(self.store_id, P_ROSTER)
        if raw is None:
            return None
        f = codec.as_seq(codec.decode(raw[1]), 2)
        members = tuple(crypto.PublicKey(codec.as_bytes(m)) for m in codec.as_seq(f[1]))
        return codec.as_int(f[0]), members

    def set_roster(self, members: Iterable[crypto.PublicKey], serial: int) -> ops.Transaction:
        """Emit the commitment for a membership set. SORTED, because the value is compared byte for
        byte against an enumeration and two orderings of one set must not be two commitments."""
        record = codec.encode([serial, sorted(bytes(m) for m in members)])
        return ops.writes(ops.Set(self.store_id, P_ROSTER, record))

    def _read_grant(self, reader: Reader, who: crypto.PublicKey) -> Grant | None:
        """The primitive grant lookup. Reads from `reader` (typically `self.store`, but the
        transaction's own layer during evaluation) so a grant made by an earlier step is
        visible to a later step's check.

        Row content is always 4 fields: role, stores, kinds, cert-bytes. A grant on-log
        always carries a #cert (`authorise` refuses to build a grant without one)."""
        raw = reader.get(self.store_id, P_GRANT + who)
        if raw is None:
            return None
        f = codec.as_seq(codec.decode(raw[1]), 4)
        try:
            role = Role(codec.as_bytes(f[0]))
        except ValueError as e:
            raise ManagementError(f"unknown role for {who.hex()[:8]}") from e
        cert = Cert.decode(codec.as_bytes(f[3]))
        return Grant(
            who,
            role,
            frozenset(codec.as_int(x) for x in codec.as_seq(f[1])),
            frozenset(codec.as_int(x) for x in codec.as_seq(f[2])),
            cert,
        )

    def grant_of(self, who: crypto.PublicKey) -> Grant | None:
        """The default-reader convenience: look up a grant against `self.store`. Same shape as
        `_read_grant(self.store, who)`."""
        return self._read_grant(self.store, who)

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
        if who == self.store.anchor():
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
        if who == self.store.anchor():
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

    def authorization(
        self,
        bitmap: crypto.SignerBitmap,
        sigs: tuple[crypto.Signature, ...],
        payload: bytes,
    ) -> bool:
        """Verify a block-shape multisig against the current roster + anchor
        (SPECv2 #manager-sig-overrides-quorum).

        BITMAP LAYOUT: `len(roster) + 1` positions. Indices `0..N-1` are roster members;
        index `N` is the manager slot, verified against `self.store.anchor()`. Delegates to
        `Ed25519ListMultiSig.verify` with `[*roster, anchor]` as the effective signer set --
        the roster-append composition is encapsulated here so no caller needs to know about
        the manager slot's position.

        TRUE if EITHER:
          - the manager slot signed (anchor override) -- authorizes alone; OR
          - a quorum of roster slots signed (ordinary consensus path).

        FALSE if the multisig itself failed to verify (bad sig, wrong signer, bitmap/sig
        length mismatch) OR if only sub-quorum roster slots signed with no manager override.

        Raises `ManagementError` if the store is not provisioned (no anchor to verify the
        override slot against) -- a Management being asked to authorize with no manager
        anchor is a misconfiguration, not a routine failure."""
        anchor = self.store.anchor()
        if anchor is None:
            raise ManagementError("cannot authorize: store has no manager anchor")
        roster = self.roster()
        n = len(roster) + 1  # +1 for the manager override slot
        if not crypto.Ed25519ListMultiSig.verify(bitmap, list(sigs), payload, [*roster, anchor]):
            return False
        set_indices = crypto.bitmap_indices(bitmap, n)
        manager_slot = n - 1
        if manager_slot in set_indices:
            return True  # manager override -- authorizes alone
        roster_signer_count = sum(1 for i in set_indices if i < manager_slot)
        return roster_signer_count >= quorum.size(len(roster))

    def possession_proof(self, who: crypto.PublicKey) -> crypto.Signature | None:
        raw = self.store.get(self.store_id, P_POP + who)
        return crypto.Signature(raw[1]) if raw else None

    def wrapped_master(self, epoch: int, who: crypto.PublicKey) -> crypto.SealedBlob | None:
        """`who`'s sealed copy of the epoch master (#wrapped-masters). Opening it is the
        holder's business;
        this layer never sees a secret."""
        raw = self.store.get(self.store_id, _wrap_key(epoch, who))
        return crypto.SealedBlob(raw[1]) if raw else None

    # -- writes: emit mutations, apply nothing -------------------------------- #

    def change_roster(
        self,
        add: Iterable[NodeRecord] = (),
        remove: Iterable[crypto.PublicKey] = (),
    ) -> ops.Transaction:
        """Batched atomic roster change: add nodes, remove nodes, and update the manager-signed
        commitment in ONE transaction (#roster-change-is-atomic).

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
        steps.extend(
            ops.Set(
                self.store_id,
                P_NODE + rec.identity,
                codec.encode([list(rec.addresses), sorted(rec.domains), rec.cert.encode()]),
            )
            for rec in add
        )
        # Roster commitment: sorted members of the post-state, next serial.
        current = self.roster_commitment()
        next_serial = (current[0] + 1) if current is not None else 1
        commitment = codec.encode([next_serial, sorted(bytes(m) for m in after)])
        steps.append(ops.Set(self.store_id, P_ROSTER, commitment))
        return ops.writes(*steps)

    def add_node(
        self,
        who: crypto.PublicKey,
        addresses: tuple[Address, ...],
        cert: Cert,
        domains: frozenset[Domain] = frozenset(),
    ) -> ops.Transaction:
        """Convenience wrapper on `change_roster`: single-node add. See `change_roster` for
        the full semantics (batched, brick-refuse only, advisory composition, cert-checked)."""
        return self.change_roster(add=(NodeRecord(who, addresses, cert, domains),))

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

    def remove_node(self, who: crypto.PublicKey) -> ops.Transaction:
        """Convenience wrapper on `change_roster`: single-node remove. See `change_roster`
        for the full semantics.

        NOTE: previously this emitted a bare `Del P_NODE` without the roster-commitment
        update, silently violating #roster-change-is-atomic. Now delegates to `change_roster`
        which composes the commitment update, PoP deletion, and node deletion atomically."""
        return self.change_roster(remove=(who,))

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
        record = codec.encode([role.value, sorted(stores), sorted(kinds), cert.encode()])
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
