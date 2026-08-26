from __future__ import annotations

from collections.abc import Iterable
from dataclasses import dataclass, replace
from enum import Enum
from typing import TYPE_CHECKING

from .. import quorum
from ..core import codec, crypto
from ..core.errors import DudeError
from ..net.address import Endpoint
from . import ops
from .errors import StoreError
from .layer import Reader
from .managed import ManagedMap, MapEntry

if TYPE_CHECKING:
    from ..session import Session


class ManagementError(StoreError): ...


class Role(Enum):
    MANAGER = b"manager"
    CLIENT_RO = b"client_ro"
    CLIENT_RW = b"client_rw"
    COMPACTOR = b"compactor"

    @property
    def isolated(self) -> bool:
        return self is Role.COMPACTOR


type Domain = bytes

_CERT_DOMAIN = b"dude.management.cert:"
CERT_PURPOSE_ROSTER = b"roster"
CERT_PURPOSE_ROSTER_COMMITMENT = b"roster_commitment"


@dataclass(frozen=True, slots=True)
class Cert:
    signer: crypto.PublicKey
    subject: bytes
    purpose: bytes
    sig: crypto.Signature

    @classmethod
    def sign(cls, signer: crypto.Keypair, subject: bytes, purpose: bytes) -> "Cert":
        return cls(
            signer.public,
            subject,
            purpose,
            signer.sign(_CERT_DOMAIN + purpose + b":" + subject),
        )

    @classmethod
    def sign_grant(cls, signer: crypto.Keypair, subject: crypto.PublicKey, role: Role) -> "Cert":
        return cls.sign(signer, bytes(subject), role.value)

    @classmethod
    def sign_roster(cls, signer: crypto.Keypair, subject: crypto.PublicKey) -> "Cert":
        return cls.sign(signer, bytes(subject), CERT_PURPOSE_ROSTER)

    @classmethod
    def sign_roster_commitment(cls, signer: crypto.Keypair, commitment_bytes: bytes) -> "Cert":
        return cls.sign(signer, crypto.h(commitment_bytes), CERT_PURPOSE_ROSTER_COMMITMENT)

    def verify(self) -> bool:
        return self.signer.verify(_CERT_DOMAIN + self.purpose + b":" + self.subject, self.sig)

    def encode(self) -> bytes:
        return codec.encode([self.signer, self.subject, self.purpose, self.sig])

    @classmethod
    def decode(cls, raw: bytes) -> "Cert":
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
            return True
        if not self.roster:
            # No roster is no quorum. Reached while verifying a claim about block 1, where the
            # anchor override above is the only authorisation there can be -- `quorum.size(0)`
            # raises, and that raise is a peer's malformed claim escaping as our error.
            return False
        roster_signers = sum(1 for i in set_indices if i < manager_slot)
        return roster_signers >= quorum.size(len(self.roster))


@dataclass(frozen=True, slots=True)
class NodeRecord:
    identity: crypto.PublicKey
    endpoints: tuple[Endpoint, ...]
    cert: Cert
    domains: frozenset[Domain] = frozenset()

    def encode(self) -> bytes:
        return codec.encode(
            [
                self.identity,
                sorted(ep.encode() for ep in self.endpoints),
                sorted(self.domains),
                self.cert.encode(),
            ]
        )

    @classmethod
    def decode(cls, raw: bytes) -> "NodeRecord":
        f = codec.as_seq(codec.decode(raw), 4)
        identity = crypto.PublicKey(codec.as_bytes(f[0]))
        endpoints = tuple(Endpoint.parse(codec.as_bytes(e)) for e in codec.as_seq(f[1]))
        domains = frozenset(codec.as_bytes(d) for d in codec.as_seq(f[2]))
        cert = Cert.decode(codec.as_bytes(f[3]))
        return cls(identity, endpoints, cert, domains)

    def encode_row(self) -> bytes:
        return codec.encode(
            [
                sorted(ep.encode() for ep in self.endpoints),
                sorted(self.domains),
                self.cert.encode(),
            ]
        )

    @classmethod
    def decode_row(cls, identity: crypto.PublicKey, raw: bytes) -> "NodeRecord":
        f = codec.as_seq(codec.decode(raw), 3)
        endpoints = tuple(Endpoint.parse(codec.as_bytes(e)) for e in codec.as_seq(f[0]))
        domains = frozenset(codec.as_bytes(d) for d in codec.as_seq(f[1]))
        cert = Cert.decode(codec.as_bytes(f[2]))
        return cls(identity, endpoints, cert, domains)


@dataclass(frozen=True, slots=True)
class RosterCommitment:
    """The P_ROSTER row: its layout and the fingerprints derived from it, in one place. Hand-
    decoded at each call site instead, the read and write halves drifted into disagreeing about
    whether a malformed row raises or reads as absent."""

    serial: int
    members: tuple[crypto.PublicKey, ...]
    state_fingerprint: crypto.Digest
    cert: Cert

    @staticmethod
    def fingerprint(records: Iterable[NodeRecord]) -> crypto.Digest:
        return crypto.h(
            codec.encode(
                [
                    [
                        bytes(rec.identity),
                        sorted(ep.encode() for ep in rec.endpoints),
                        sorted(rec.domains),
                    ]
                    for rec in sorted(records, key=lambda r: bytes(r.identity))
                ]
            )
        )

    @staticmethod
    def content(
        serial: int, members: Iterable[crypto.PublicKey], state_fingerprint: crypto.Digest
    ) -> bytes:
        return codec.encode([serial, sorted(bytes(m) for m in members), state_fingerprint])

    @property
    def subject(self) -> crypto.Digest:
        return crypto.h(self.content(self.serial, self.members, self.state_fingerprint))

    def attests(self) -> bool:
        return self.cert.purpose == CERT_PURPOSE_ROSTER_COMMITMENT and self.cert.subject == (
            self.subject
        )

    def encode_row(self) -> bytes:
        return codec.encode(
            [
                self.serial,
                sorted(bytes(m) for m in self.members),
                self.state_fingerprint,
                self.cert.encode(),
            ]
        )

    @classmethod
    def decode_row(cls, raw: bytes) -> "RosterCommitment":
        try:
            f = codec.as_seq(codec.decode(raw), 4)
            return cls(
                serial=codec.as_int(f[0]),
                members=tuple(crypto.PublicKey(codec.as_bytes(m)) for m in codec.as_seq(f[1])),
                state_fingerprint=crypto.Digest(codec.as_bytes(f[2])),
                cert=Cert.decode(codec.as_bytes(f[3])),
            )
        except DudeError as e:
            raise ManagementError(f"malformed RosterCommitment: {e}") from e


@dataclass(frozen=True, slots=True)
class Grant:
    identity: crypto.PublicKey
    role: Role
    stores: frozenset[int]
    kinds: frozenset[int]
    cert: Cert

    def encode(self) -> bytes:
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
    def decode(cls, raw: bytes) -> "Grant":
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
        return codec.encode(
            [
                self.role.value,
                sorted(self.stores),
                sorted(self.kinds),
                self.cert.encode(),
            ]
        )

    @classmethod
    def decode_row(cls, identity: crypto.PublicKey, raw: bytes) -> "Grant":
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


P_NODE = b"node/"
P_GRANT = b"grant/"
P_POP = b"pop/"
P_WRAP = b"wrap/"
P_BLIND = b"blind/"
"""Per-grant wrap of a store's blinding secret. ITS OWN PREFIX, not `P_WRAP` at a reserved epoch:
a blinding secret never rotates -- name tokens are SMT paths, and rotating one would relocate
every row in its store -- so filing it under an epoch sentinel would read fine and mislead later."""
P_COMPACT = b"compact"
P_ROSTER = b"roster"
P_EPOCH = b"epoch/"
"""Per store, not one counter. EVERY KEY IS PER-STORE: a grant naming store 2 mints that store's
blinding secret and its epoch masters and nothing else, so a client with no grant for a store
cannot read it even holding its bytes. Cluster-wide keys would make `stores` an access rule
standing in for a key boundary -- the weaker of the two, and the one a stale replica ignores.

Each store therefore rotates independently: re-keying store 2 does not re-wrap everyone on
store 1."""


def _store_key(store_id: int) -> bytes:
    return store_id.to_bytes(8, "big")


def epoch_key(store_id: int) -> bytes:
    return P_EPOCH + _store_key(store_id)


def blind_key(store_id: int, who: crypto.PublicKey) -> bytes:
    return P_BLIND + _store_key(store_id) + who


def wrap_key(store_id: int, epoch: int, who: crypto.PublicKey) -> bytes:
    return P_WRAP + _store_key(store_id) + epoch.to_bytes(8, "big") + who



@dataclass(frozen=True, slots=True)
class Attestation:
    key: bytes
    purpose: bytes
    subject: bytes


def attestations_by(  # noqa: C901
    session: Session, signer: crypto.PublicKey,
) -> tuple[Attestation, ...]:
    nodes_map = ManagedMap(P_NODE, session)
    grants_map = ManagedMap(P_GRANT, session)
    out: list[Attestation] = []
    for key in nodes_map.keys():
        who = crypto.PublicKey(key)
        entry = nodes_map.entry(key)
        if entry is None:
            continue
        try:
            rec = NodeRecord.decode_row(who, entry.value)
        except DudeError:
            continue
        if rec.cert.signer == signer:
            out.append(Attestation(nodes_map.entry_name(key), CERT_PURPOSE_ROSTER, bytes(who)))
    for key in grants_map.keys():
        who = crypto.PublicKey(key)
        entry = grants_map.entry(key)
        if entry is None:
            continue
        try:
            grant = Grant.decode_row(who, entry.value)
        except DudeError:
            continue
        if grant.cert.signer == signer:
            out.append(Attestation(grants_map.entry_name(key), grant.role.value, bytes(who)))
    rec = session.get(P_ROSTER)
    if not rec.absent:
        try:
            rc = RosterCommitment.decode_row(rec.value)
        except DudeError:
            return tuple(sorted(out, key=lambda a: a.key))
        if rc.cert.signer == signer:
            out.append(Attestation(P_ROSTER, CERT_PURPOSE_ROSTER_COMMITMENT, rc.subject))
    return tuple(sorted(out, key=lambda a: a.key))


class MgmtReader:
    def __init__(self, session: Session) -> None:
        self._session = session
        self._anchor = session.anchor
        self._nodes = ManagedMap(P_NODE, session)
        self._grants = ManagedMap(P_GRANT, session)

    @property
    def anchor(self) -> crypto.PublicKey:
        return self._anchor

    def nodes(self) -> dict[crypto.PublicKey, NodeRecord]:
        out: dict[crypto.PublicKey, NodeRecord] = {}
        for key in self._nodes.keys():
            who = crypto.PublicKey(key)
            entry = self._nodes.entry(key)
            if entry is None:
                continue
            try:
                out[who] = NodeRecord.decode_row(who, entry.value)
            except DudeError:
                continue
        return out

    def _seats(self, who: crypto.PublicKey, rec: NodeRecord) -> bool:
        return (
            rec.cert.subject == who
            and rec.cert.purpose == CERT_PURPOSE_ROSTER
            and self.verify_cert(rec.cert)
        )

    def roster(self) -> tuple[crypto.PublicKey, ...]:
        return tuple(sorted(who for who, rec in self.nodes().items() if self._seats(who, rec)))

    def is_member(self, who: crypto.PublicKey) -> bool:
        entry = self._nodes.entry(who)
        if entry is None:
            return False
        try:
            rec = NodeRecord.decode_row(who, entry.value)
        except DudeError:
            return False
        return self._seats(who, rec)

    def verify_cert(self, cert: Cert, reader: Reader | None = None) -> bool:  # noqa: PLR0911 -- each early-return names a distinct refusal reason; collapsing them into one `and`-chain hides which check failed
        if not cert.verify():
            return False
        anchor_only_purposes = (Role.MANAGER.value, Role.COMPACTOR.value)
        anchor_or_manager_purposes = (
            Role.CLIENT_RO.value,
            Role.CLIENT_RW.value,
            CERT_PURPOSE_ROSTER,
            CERT_PURPOSE_ROSTER_COMMITMENT,
        )
        if cert.purpose in anchor_only_purposes:
            return cert.signer == self._anchor
        if cert.purpose in anchor_or_manager_purposes:
            if cert.signer == self._anchor:
                return True
            grant = self._read_grant(cert.signer, reader)
            if grant is None or grant.role is not Role.MANAGER:
                return False
            return (
                grant.cert.subject == cert.signer
                and grant.cert.purpose == Role.MANAGER.value
                and grant.cert.verify()
                and grant.cert.signer == self._anchor
            )
        return False

    def authorized_identities(self) -> frozenset[crypto.PublicKey]:
        out: set[crypto.PublicKey] = {self._anchor}
        for key in self._grants.keys():
            who = crypto.PublicKey(key)
            if self.valid_grant(who) is not None:
                out.add(who)
        return frozenset(out)

    def manager_grants(self) -> tuple[Grant, ...]:
        out: list[Grant] = []
        for key in self._grants.keys():
            who = crypto.PublicKey(key)
            grant = self._read_grant(who)
            if grant is None or grant.role is not Role.MANAGER:
                continue
            if not self._grant_cert_ok(grant):
                continue
            out.append(grant)
        out.sort(key=lambda g: bytes(g.identity))
        return tuple(out)

    def roster_commitment(self) -> RosterCommitment | None:
        rec = self._session.get(P_ROSTER)
        if rec.absent:
            return None
        try:
            rc = RosterCommitment.decode_row(rec.value)
        except DudeError:
            return None
        if not rc.attests():
            return None
        if not self.verify_cert(rc.cert):
            return None
        member_set = set(rc.members)
        held = [r for r in self.nodes().values() if r.identity in member_set]
        if RosterCommitment.fingerprint(held) != rc.state_fingerprint:
            return None
        return rc

    def endpoints_of(self, who: crypto.PublicKey) -> tuple[Endpoint, ...]:
        rec = self.nodes().get(who)
        return rec.endpoints if rec else ()

    def _read_grant(self, who: crypto.PublicKey, reader: Reader | None = None) -> Grant | None:
        if reader is not None:
            held = reader.get(ops.STORE_MANAGEMENT, self._grants.entry_name(who))
            if held is None:
                return None
            try:
                return Grant.decode_row(who, MapEntry.decode(held.value).value)
            except (DudeError, ValueError, IndexError):
                return None
        entry = self._grants.entry(who)
        if entry is None:
            return None
        try:
            return Grant.decode_row(who, entry.value)
        except DudeError:
            return None

    def grant_of(self, who: crypto.PublicKey) -> Grant | None:
        return self._read_grant(who)

    def valid_grant(self, who: crypto.PublicKey, reader: Reader | None = None) -> Grant | None:
        g = self._read_grant(who, reader)
        if g is None or not self._grant_cert_ok(g, reader):
            return None
        return g

    def may_write(self, reader: Reader, who: crypto.PublicKey, store_id: int) -> bool:
        if who == self._anchor:
            return True
        g = self.valid_grant(who, reader)
        if g is None:
            return False
        if g.role is Role.MANAGER:
            return True
        if g.role is Role.COMPACTOR:
            return store_id == ops.STORE_MANAGEMENT
        return g.role is Role.CLIENT_RW and store_id in g.stores

    def may_read(self, reader: Reader, who: crypto.PublicKey, store_id: int) -> bool:
        if store_id == ops.STORE_MANAGEMENT:
            return self.has_standing(reader, who)
        if who == self._anchor:
            return True
        if self.is_member(who):
            return True
        g = self.valid_grant(who, reader)
        if g is None:
            return False
        if g.role is Role.MANAGER:
            return True
        return store_id in g.stores

    def has_standing(self, reader: Reader, who: crypto.PublicKey) -> bool:
        return (
            who == self._anchor
            or self.is_member(who)
            or self.valid_grant(who, reader) is not None
        )

    def may_send(self, who: crypto.PublicKey, kind: int) -> bool:
        if who == self._anchor:
            return True
        g = self.valid_grant(who)
        if g is None:
            return False
        if g.role is Role.MANAGER:
            return True
        return kind in g.kinds

    def _grant_cert_ok(self, g: Grant, reader: Reader | None = None) -> bool:
        if g.cert.subject != g.identity:
            return False
        if g.cert.purpose != g.role.value:
            return False
        return self.verify_cert(g.cert, reader)

    def possession_proof(self, who: crypto.PublicKey) -> crypto.Signature | None:
        rec = self._session.get(P_POP + who)
        return crypto.Signature(rec.value) if not rec.absent else None

    def epoch_target(self, name: bytes) -> int | None:
        """Which store's keyepoch this management row carries, or None if it carries none. Lets
        `settle.evaluate` recognise a rotation without importing this module."""
        if not name.startswith(P_EPOCH) or len(name) != len(P_EPOCH) + 8:
            return None
        return int.from_bytes(name[len(P_EPOCH) :], "big")

    def current_epoch(self, store_id: int, reader: Reader | None = None) -> int:
        if reader is not None:
            raw = reader.get(ops.STORE_MANAGEMENT, epoch_key(store_id))
            return codec.as_int(codec.decode(raw.value)) if raw else ops.EPOCH_NONE
        rec = self._session.get(epoch_key(store_id))
        return codec.as_int(codec.decode(rec.value)) if not rec.absent else ops.EPOCH_NONE

    def wraps_for(self, store_id: int, who: crypto.PublicKey) -> dict[int, crypto.SealedBlob]:
        cur = self.current_epoch(store_id)
        out: dict[int, crypto.SealedBlob] = {}
        for epoch in range(1, cur + 1):
            rec = self._session.get(wrap_key(store_id, epoch, who))
            if not rec.absent:
                out[epoch] = crypto.SealedBlob(rec.value)
        return out

    def blinding_wrap(self, store_id: int, who: crypto.PublicKey) -> crypto.SealedBlob | None:
        rec = self._session.get(blind_key(store_id, who))
        return crypto.SealedBlob(rec.value) if not rec.absent else None

    def domain_groups(self) -> dict[Domain, frozenset[crypto.PublicKey]]:
        groups: dict[Domain, set[crypto.PublicKey]] = {}
        for rec in self.nodes().values():
            for d in rec.domains:
                groups.setdefault(d, set()).add(rec.identity)
        return {d: frozenset(m) for d, m in groups.items()}

    def check_domains(self) -> dict[Domain, int]:
        counts: dict[Domain, int] = {}
        for rec in self.nodes().values():
            for d in rec.domains:
                counts[d] = counts.get(d, 0) + 1
        return quorum.domain_advisory(counts, len(self.nodes()))


class MgmtWriter(MgmtReader):
    def change_roster(  # noqa: C901
        self,
        *,
        commitment_signer: crypto.Keypair,
        add: Iterable[NodeRecord] = (),
        remove: Iterable[crypto.PublicKey] = (),
    ) -> ops.Transaction:
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
        if not quorum.would_brick(n_before) and quorum.would_brick(n_after):
            raise ManagementError(
                f"change_roster would shrink from n={n_before} (safe) to n={n_after} "
                f"(would_brick); refused. Use intervene() for anchor rescue if deliberate."
            )
        for rec in add:
            if rec.cert.subject != rec.identity:
                raise ManagementError(
                    f"cert.subject {rec.cert.subject.hex()[:8]} does not match node "
                    f"identity {rec.identity.hex()[:8]}"
                )
            if rec.cert.purpose != CERT_PURPOSE_ROSTER:
                raise ManagementError(
                    f"cert.purpose {rec.cert.purpose!r} is not the roster purpose"
                )
            if not self.verify_cert(rec.cert):
                raise ManagementError(
                    f"cert for node {rec.identity.hex()[:8]} does not verify or signer "
                    f"is not authorised"
                )
        tx = ops.Transaction(())
        for who in remove:
            tx = tx + self._nodes.remove(who)
            tx = tx + ops.writes(ops.Del(self._session.store_id, P_POP + who))
        if add:
            tx = tx + self._nodes.batch_add(
                tuple((bytes(rec.identity), rec.encode_row()) for rec in add),
            )
        current = self.roster_commitment()
        next_serial = (current.serial + 1) if current is not None else 1
        members = tuple(after)
        state_fingerprint = RosterCommitment.fingerprint(after.values())
        commitment_cert = Cert.sign_roster_commitment(
            commitment_signer, RosterCommitment.content(next_serial, members, state_fingerprint)
        )
        if not self.verify_cert(commitment_cert):
            raise ManagementError(
                f"commitment_signer {commitment_signer.public.hex()[:8]} is not authorised "
                f"to sign the roster commitment (must be anchor or a valid manager)"
            )
        commitment = RosterCommitment(next_serial, members, state_fingerprint, commitment_cert)
        return tx + ops.writes(ops.Set(self._session.store_id, P_ROSTER, commitment.encode_row()))

    def add_node(
        self,
        who: crypto.PublicKey,
        endpoints: tuple[Endpoint, ...],
        cert: Cert,
        *,
        commitment_signer: crypto.Keypair,
        domains: frozenset[Domain] = frozenset(),
    ) -> ops.Transaction:
        return self.change_roster(
            commitment_signer=commitment_signer,
            add=(NodeRecord(who, endpoints, cert, domains),),
        )

    def remove_node(
        self, who: crypto.PublicKey, *, commitment_signer: crypto.Keypair
    ) -> ops.Transaction:
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
        return (
            self._grants.add(who, record)
            + ops.writes(ops.Set(self._session.store_id, P_POP + who, pop))
        )

    def revoke(self, who: crypto.PublicKey, *, reissue_signer: crypto.Keypair) -> ops.Transaction:
        """Revocation MUST re-issue everything the key attested, in the same transaction. A #cert
        says an identity WAS authorised, never that it still is, so a bare delete took `roster()`
        to ZERO with every P_NODE row intact and nothing raised -- the node then sat out consensus
        and looked like a network fault.

        `reissue_signer` has no default even when nothing needs re-issuing: a default here is a
        caller silently leaving live rows attested by a signer that is no longer authorised."""
        anchor = self._anchor
        if anchor is None:
            raise ManagementError("cannot revoke: store has no manager anchor")
        target = self.grant_of(who)
        if (
            target is not None
            and target.role in (Role.MANAGER, Role.COMPACTOR)
            and reissue_signer.public != anchor
        ):
            raise ManagementError(
                f"only the anchor may revoke a {target.role.name} grant (#role-manager-grant); "
                f"reissue_signer {reissue_signer.public.hex()[:8]} is not the anchor"
            )
        attested = attestations_by(self._session, who)
        tx = ops.Transaction(())
        for att in attested:
            tx = tx + self._reissue(att, reissue_signer)
        tx = tx + self._grants.remove(who)
        return tx + ops.writes(ops.Del(self._session.store_id, P_POP + who))

    def _reissue(self, att: Attestation, signer: crypto.Keypair) -> ops.Transaction:
        if att.key == P_ROSTER:
            rec = self._session.get(P_ROSTER)
            if rec.absent:
                raise ManagementError("roster row vanished while composing a revocation")
            rc = RosterCommitment.decode_row(rec.value)
            cert = Cert.sign_roster_commitment(
                signer, RosterCommitment.content(rc.serial, rc.members, rc.state_fingerprint)
            )
            self._require_signer(cert)
            return ops.writes(ops.Set(self._session.store_id, P_ROSTER, replace(rc, cert=cert).encode_row()))
        identity = crypto.PublicKey(att.subject)
        is_node = att.key == self._nodes.entry_name(identity)
        target_map = self._nodes if is_node else self._grants
        entry = target_map.entry(identity)
        if entry is None:
            raise ManagementError(f"row {att.key!r} vanished while composing a revocation")
        if is_node:
            rec = NodeRecord.decode_row(identity, entry.value)
            cert = Cert.sign_roster(signer, identity)
            self._require_signer(cert)
            new_value = replace(rec, cert=cert).encode_row()
        else:
            grant = Grant.decode_row(identity, entry.value)
            cert = Cert.sign_grant(signer, identity, grant.role)
            self._require_signer(cert)
            new_value = replace(grant, cert=cert).encode_row()
        return target_map.tx_update(identity, new_value, entry)

    def _require_signer(self, cert: Cert) -> None:
        if not self.verify_cert(cert):
            raise ManagementError(
                f"reissue_signer {cert.signer.hex()[:8]} is not authorised to sign a "
                f"{cert.purpose!r} cert (must be anchor or a currently-valid manager)"
            )

    def admit_reader(
        self,
        who: crypto.PublicKey,
        store_id: int,
        wraps: dict[int, crypto.SealedBlob],
        blinding: crypto.SealedBlob,
    ) -> ops.Transaction:
        """The key half of admitting a reader TO ONE STORE. Composes with `authorise` (`a + b`) so
        a grant and the keys that make it useful land in ONE transaction -- granted without keys,
        an identity can address rows it cannot read, which looks like corruption rather than a
        missing step. A grant naming several stores needs one of these per store, which is the
        point: the keys and the grant say the same thing."""
        return ops.writes(
            ops.Set(self._session.store_id, blind_key(store_id, who), blinding),
            *(ops.Set(self._session.store_id, wrap_key(store_id, e, who), wraps[e]) for e in sorted(wraps)),
        )

    def rotate(
        self,
        store_id: int,
        from_epoch: int,
        wraps: dict[crypto.PublicKey, crypto.SealedBlob],
        blinding: dict[crypto.PublicKey, crypto.SealedBlob] | None = None,
    ) -> ops.Transaction:
        """ONE transaction: bump and every wrap, or neither -- otherwise a live epoch has no
        master. ONE STORE: re-keying store 2 must not re-wrap store 1. NO GUARD on the epoch
        row: `evaluate`'s forward-only rule binds every writer, whereas a `Holds` would only
        bind txs this method built. A manager MUST be among `wraps` -- managers recover masters
        by unwrapping their own copy, so an epoch minted without one is un-rewrappable for a
        newcomer. `blinding` is written at first mint only; rotating it would relocate every row
        in the store."""
        to = from_epoch + 1
        steps = [ops.Step((), ops.Set(self._session.store_id, epoch_key(store_id), codec.encode(to)))]
        steps += [
            ops.Step((), ops.Set(self._session.store_id, wrap_key(store_id, to, who), wraps[who]))
            for who in sorted(wraps)
        ]
        blind = blinding or {}
        steps += [
            ops.Step((), ops.Set(self._session.store_id, blind_key(store_id, who), blind[who]))
            for who in sorted(blind)
        ]
        return ops.Transaction(tuple(steps))

    def compact(self, block_num: int) -> ops.Transaction:
        s = self._session.store_id
        rec = self._session.get(P_COMPACT)
        if rec.absent:
            guard: ops.Predicate = ops.Absent(s, P_COMPACT)
        else:
            guard = ops.Holds(s, P_COMPACT, ops.value_digest(rec.value))
        value = block_num.to_bytes(8, "big")
        return ops.Transaction((ops.Step((guard,), ops.Set(s, P_COMPACT, value)),))
