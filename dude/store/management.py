from __future__ import annotations

from collections.abc import Iterable
from dataclasses import dataclass, replace
from enum import Enum
from typing import Protocol

from .. import quorum
from ..core import codec, crypto
from ..core.errors import DudeError
from ..net.address import Endpoint
from . import ops
from .layer import Reader


class ManagementError(DudeError): ...


class Role(Enum):
    MANAGER = b"manager"
    CLIENT_RO = b"client_ro"
    CLIENT_RW = b"client_rw"
    COMPACTOR = b"compactor"
    """COMPACTOR reads and nothing else until compaction returns. Its own verbs land with it."""


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
    def sign(cls, signer: crypto.Keypair, subject: bytes, purpose: bytes) -> Cert:
        return cls(
            signer.public,
            subject,
            purpose,
            signer.sign(_CERT_DOMAIN + purpose + b":" + subject),
        )

    @classmethod
    def sign_grant(cls, signer: crypto.Keypair, subject: crypto.PublicKey, role: Role) -> Cert:
        return cls.sign(signer, bytes(subject), role.value)

    @classmethod
    def sign_roster(cls, signer: crypto.Keypair, subject: crypto.PublicKey) -> Cert:
        return cls.sign(signer, bytes(subject), CERT_PURPOSE_ROSTER)

    @classmethod
    def sign_roster_commitment(cls, signer: crypto.Keypair, commitment_bytes: bytes) -> Cert:
        return cls.sign(signer, crypto.h(commitment_bytes), CERT_PURPOSE_ROSTER_COMMITMENT)

    def verify(self) -> bool:
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
    def decode(cls, raw: bytes) -> NodeRecord:
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
    def decode_row(cls, identity: crypto.PublicKey, raw: bytes) -> NodeRecord:
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
    def decode_row(cls, raw: bytes) -> RosterCommitment:
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
    def decode(cls, raw: bytes) -> Grant:
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
    def decode_row(cls, identity: crypto.PublicKey, raw: bytes) -> Grant:
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
"""Per-grant wrap of the blinding secret. ITS OWN PREFIX, not `P_WRAP` at a reserved epoch: the
blinding secret never rotates -- name tokens are SMT paths, and rotating it would relocate every
row in the store -- so filing it under an epoch sentinel would read fine and mislead later."""
P_ROSTER = b"roster"
P_EPOCH = b"epoch"
"""Singleton: the keyepoch data writes must currently carry. Lives in state rather than the block
header, which would restate what state already decides."""


def _wrap_key(epoch: int, who: crypto.PublicKey) -> bytes:
    return P_WRAP + epoch.to_bytes(8, "big") + who


class Source(Reader, Protocol):
    def anchor(self) -> crypto.PublicKey | None: ...


@dataclass(frozen=True, slots=True)
class Attestation:
    key: bytes
    purpose: bytes
    subject: bytes


def attestations_by(
    src: Reader, signer: crypto.PublicKey, store_id: int = ops.STORE_MANAGEMENT
) -> tuple[Attestation, ...]:
    out: list[Attestation] = []
    for name, _prov, value, _ep in src.prefix(store_id, P_NODE):
        who = crypto.PublicKey(name[len(P_NODE) :])
        try:
            rec = NodeRecord.decode_row(who, value)
        except DudeError:
            continue
        if rec.cert.signer == signer:
            out.append(Attestation(name, CERT_PURPOSE_ROSTER, bytes(who)))
    for name, _prov, value, _ep in src.prefix(store_id, P_GRANT):
        who = crypto.PublicKey(name[len(P_GRANT) :])
        try:
            grant = Grant.decode_row(who, value)
        except DudeError:
            continue
        if grant.cert.signer == signer:
            out.append(Attestation(name, grant.role.value, bytes(who)))
    raw = src.get(store_id, P_ROSTER)
    if raw is not None:
        try:
            rc = RosterCommitment.decode_row(raw[1])
        except DudeError:
            return tuple(sorted(out, key=lambda a: a.key))
        if rc.cert.signer == signer:
            out.append(Attestation(P_ROSTER, CERT_PURPOSE_ROSTER_COMMITMENT, rc.subject))
    return tuple(sorted(out, key=lambda a: a.key))


class MgmtReader:
    def __init__(self, src: Source, store_id: int = ops.STORE_MANAGEMENT):
        self.src = src
        self.store_id = store_id

    def nodes(self) -> dict[crypto.PublicKey, NodeRecord]:
        """A row that will not decode is a row this reader does not have. Raising here instead
        made one garbage settled row a poison pill: every roster() caller -- coordinator,
        follower, peer reconcile -- raised on every read, restart replayed the row, and the
        repair needed the consensus it had killed."""
        out: dict[crypto.PublicKey, NodeRecord] = {}
        for name, _prov, value, _ep in self.src.prefix(self.store_id, P_NODE):
            who = crypto.PublicKey(name[len(P_NODE) :])
            try:
                out[who] = NodeRecord.decode_row(who, value)
            except DudeError:
                continue
        return out

    def _seats(self, who: crypto.PublicKey, rec: NodeRecord) -> bool:
        """Whether one row is a roster seat. PER-ROW, with no cross-member condition, which is
        what lets `is_member` answer from a single read -- and ONE implementation, so it and
        `roster()` cannot come to disagree about who is in the cluster."""
        return (
            rec.cert.subject == who
            and rec.cert.purpose == CERT_PURPOSE_ROSTER
            and self.verify_cert(rec.cert, self.src)
        )

    def roster(self) -> tuple[crypto.PublicKey, ...]:
        return tuple(sorted(who for who, rec in self.nodes().items() if self._seats(who, rec)))

    def is_member(self, who: crypto.PublicKey) -> bool:
        """One row read and ONE signature verified, against `roster()`'s one per member. This
        runs on the submit path for every transaction a client offers, where walking the whole
        roster made each submission cost a verification per node."""
        raw = self.src.get(self.store_id, P_NODE + who)
        if raw is None:
            return False
        try:
            rec = NodeRecord.decode_row(who, raw.value)
        except DudeError:
            return False
        return self._seats(who, rec)

    def verify_cert(self, cert: Cert, reader: Reader) -> bool:  # noqa: PLR0911 -- each early-return names a distinct refusal reason; collapsing them into one `and`-chain hides which check failed
        """The signer's grant MUST resolve against the SAME `reader` as the row it attests.
        Split across two views, no authority chain established inside a block works inside it."""
        anchor = self.src.anchor()
        if anchor is None:
            return False
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
            return cert.signer == anchor
        if cert.purpose in anchor_or_manager_purposes:
            if cert.signer == anchor:
                return True
            grant = self._read_grant(reader, cert.signer)
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
        out: list[Grant] = []
        for name, _prov, _value, _ep in self.src.prefix(self.store_id, P_GRANT):
            who = crypto.PublicKey(name[len(P_GRANT) :])
            grant = self._read_grant(self.src, who)
            if grant is None or grant.role is not Role.MANAGER:
                continue
            if not self._grant_cert_ok(grant, self.src):
                continue
            out.append(grant)
        out.sort(key=lambda g: bytes(g.identity))
        return tuple(out)

    def roster_commitment(self) -> RosterCommitment | None:
        raw = self.src.get(self.store_id, P_ROSTER)
        if raw is None:
            return None
        try:
            rc = RosterCommitment.decode_row(raw[1])
        except DudeError:
            return None
        if not rc.attests():
            return None
        if not self.verify_cert(rc.cert, self.src):
            return None
        member_set = set(rc.members)
        held = [rec for rec in self.nodes().values() if rec.identity in member_set]
        if RosterCommitment.fingerprint(held) != rc.state_fingerprint:
            return None
        return rc

    def endpoints_of(self, who: crypto.PublicKey) -> tuple[Endpoint, ...]:
        rec = self.nodes().get(who)
        return rec.endpoints if rec else ()

    def _read_grant(self, reader: Reader, who: crypto.PublicKey) -> Grant | None:
        raw = reader.get(self.store_id, P_GRANT + who)
        if raw is None:
            return None
        try:
            return Grant.decode_row(who, raw[1])
        except DudeError:
            # A garbage grant row must read as "no grant" (AUTHORITY refusal), not raise out of
            # `may_write` mid-settlement and take commit_block down with it.
            return None

    def grant_of(self, who: crypto.PublicKey) -> Grant | None:
        return self._read_grant(self.src, who)

    def valid_grant(self, reader: Reader, who: crypto.PublicKey) -> Grant | None:
        """A grant whose cert still traces to an authorised signer. Read on EVERY request against
        current state: a grant issued by a manager since revoked has no standing, and caching it
        at connect time is how a revoked identity keeps working."""
        g = self._read_grant(reader, who)
        if g is None or not self._grant_cert_ok(g, reader):
            return None
        return g

    def may_write(self, reader: Reader, who: crypto.PublicKey, store_id: int) -> bool:
        if who == self.src.anchor():
            return True
        g = self.valid_grant(reader, who)
        if g is None:
            return False
        if g.role is Role.MANAGER:
            return True
        # CLIENT_RO and COMPACTOR hold `stores` for READING. Before the roles were split, any
        # grant naming a store could write it.
        return g.role is Role.CLIENT_RW and store_id in g.stores

    def may_read(self, reader: Reader, who: crypto.PublicKey, store_id: int) -> bool:
        """Scoped the same way writing is. The lite read path asked only whether a grant EXISTED,
        so a grant for one store read every store -- including store 0, which holds grants, roster
        rows, possession proofs and wrapped keys -- and a grant from a revoked manager kept reading
        after it had stopped writing."""
        if who == self.src.anchor():
            return True
        if self.is_member(who):
            return True  # a node holds every block already
        g = self.valid_grant(reader, who)
        if g is None:
            return False
        if g.role is Role.MANAGER:
            return True
        return store_id in g.stores

    def may_send(self, who: crypto.PublicKey, kind: int) -> bool:
        if who == self.src.anchor():
            return True
        g = self.valid_grant(self.src, who)
        if g is None:
            return False
        if g.role is Role.MANAGER:
            return True
        return kind in g.kinds

    def _grant_cert_ok(self, g: Grant, reader: Reader) -> bool:
        if g.cert.subject != g.identity:
            return False
        if g.cert.purpose != g.role.value:
            return False
        return self.verify_cert(g.cert, reader)

    def possession_proof(self, who: crypto.PublicKey) -> crypto.Signature | None:
        raw = self.src.get(self.store_id, P_POP + who)
        return crypto.Signature(raw[1]) if raw else None

    def epoch_row(self) -> tuple[int, bytes]:
        """Which row carries the current keyepoch, so `settle.evaluate` can recognise a write to
        it without importing the management module."""
        return self.store_id, P_EPOCH

    def current_epoch(self, reader: Reader | None = None) -> int:
        """`EPOCH_NONE` until a manager mints the first one, which is what makes plaintext the
        default rather than a special case. Read against the SAME reader the write is evaluated
        against, or a rotation landing inside a block would be invisible to the rows in it."""
        src = self.src if reader is None else reader
        raw = src.get(self.store_id, P_EPOCH)
        return codec.as_int(codec.decode(raw.value)) if raw else ops.EPOCH_NONE

    def wraps_for(self, who: crypto.PublicKey) -> dict[int, crypto.SealedBlob]:
        """Every keyepoch this identity was minted a wrap for. Scans by prefix and filters on the
        trailing pubkey, because the row key is `P_WRAP + epoch + who` -- epoch first, so one
        epoch's wraps for every holder sit together and a rotation writes a contiguous run."""
        out: dict[int, crypto.SealedBlob] = {}
        for row in self.src.prefix(self.store_id, P_WRAP):
            body = row.name[len(P_WRAP) :]
            if len(body) != 8 + len(who) or body[8:] != who:
                continue
            out[int.from_bytes(body[:8], "big")] = crypto.SealedBlob(row.value)
        return out

    def blinding_wrap(self, who: crypto.PublicKey) -> crypto.SealedBlob | None:
        raw = self.src.get(self.store_id, P_BLIND + who)
        return crypto.SealedBlob(raw.value) if raw else None

    def wrapped_master(self, epoch: int, who: crypto.PublicKey) -> crypto.SealedBlob | None:
        raw = self.src.get(self.store_id, _wrap_key(epoch, who))
        return crypto.SealedBlob(raw[1]) if raw else None

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
    def change_roster(
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
            if not self.verify_cert(rec.cert, self.src):
                raise ManagementError(
                    f"cert for node {rec.identity.hex()[:8]} does not verify or signer "
                    f"is not authorised"
                )
        steps: list[ops.Mutation] = []
        for who in remove:
            steps.append(ops.Del(self.store_id, P_NODE + who))
            steps.append(ops.Del(self.store_id, P_POP + who))
        steps.extend(ops.Set(self.store_id, P_NODE + rec.identity, rec.encode_row()) for rec in add)
        current = self.roster_commitment()
        next_serial = (current.serial + 1) if current is not None else 1
        members = tuple(after)
        state_fingerprint = RosterCommitment.fingerprint(after.values())
        commitment_cert = Cert.sign_roster_commitment(
            commitment_signer, RosterCommitment.content(next_serial, members, state_fingerprint)
        )
        if not self.verify_cert(commitment_cert, self.src):
            raise ManagementError(
                f"commitment_signer {commitment_signer.public.hex()[:8]} is not authorised "
                f"to sign the roster commitment (must be anchor or a valid manager)"
            )
        commitment = RosterCommitment(next_serial, members, state_fingerprint, commitment_cert)
        steps.append(ops.Set(self.store_id, P_ROSTER, commitment.encode_row()))
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
        if not self.verify_cert(cert, self.src):
            raise ManagementError(
                f"cert does not verify or signer is not authorised for role {role.name}"
            )
        record = Grant(who, role, stores, kinds, cert).encode_row()
        return ops.writes(
            ops.Set(self.store_id, P_GRANT + who, record),
            ops.Set(self.store_id, P_POP + who, pop),
        )

    def revoke(self, who: crypto.PublicKey, *, reissue_signer: crypto.Keypair) -> ops.Transaction:
        """Revocation MUST re-issue everything the key attested, in the same transaction. A #cert
        says an identity WAS authorised, never that it still is, so a bare delete took `roster()`
        to ZERO with every P_NODE row intact and nothing raised -- the node then sat out consensus
        and looked like a network fault.

        `reissue_signer` has no default even when nothing needs re-issuing: a default here is a
        caller silently leaving live rows attested by a signer that is no longer authorised."""
        anchor = self.src.anchor()
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
        attested = attestations_by(self.src, who, self.store_id)
        steps: list[ops.Mutation] = [self._reissue(att, reissue_signer) for att in attested]
        steps.append(ops.Del(self.store_id, P_GRANT + who))
        steps.append(ops.Del(self.store_id, P_POP + who))
        return ops.writes(*steps)

    def _reissue(self, att: Attestation, signer: crypto.Keypair) -> ops.Mutation:
        raw = self.src.get(self.store_id, att.key)
        if raw is None:
            raise ManagementError(f"row {att.key!r} vanished while composing a revocation")
        if att.key == P_ROSTER:
            rc = RosterCommitment.decode_row(raw[1])
            cert = Cert.sign_roster_commitment(
                signer, RosterCommitment.content(rc.serial, rc.members, rc.state_fingerprint)
            )
            self._require_signer(cert)
            return ops.Set(self.store_id, P_ROSTER, replace(rc, cert=cert).encode_row())
        identity = crypto.PublicKey(att.subject)
        if att.key.startswith(P_NODE):
            rec = NodeRecord.decode_row(identity, raw[1])
            cert = Cert.sign_roster(signer, identity)
            self._require_signer(cert)
            return ops.Set(self.store_id, att.key, replace(rec, cert=cert).encode_row())
        grant = Grant.decode_row(identity, raw[1])
        cert = Cert.sign_grant(signer, identity, grant.role)
        self._require_signer(cert)
        return ops.Set(self.store_id, att.key, replace(grant, cert=cert).encode_row())

    def _require_signer(self, cert: Cert) -> None:
        if not self.verify_cert(cert, self.src):
            raise ManagementError(
                f"reissue_signer {cert.signer.hex()[:8]} is not authorised to sign a "
                f"{cert.purpose!r} cert (must be anchor or a currently-valid manager)"
            )

    def admit_reader(
        self,
        who: crypto.PublicKey,
        wraps: dict[int, crypto.SealedBlob],
        blinding: crypto.SealedBlob,
    ) -> ops.Transaction:
        """The key half of admitting a reader. Composes with `authorise` (`a + b`) so a grant and
        the keys that make it useful land in ONE transaction -- granted without keys, an identity
        can address rows it cannot read, which looks like corruption rather than a missing step."""
        return ops.writes(
            ops.Set(self.store_id, P_BLIND + who, blinding),
            *(ops.Set(self.store_id, _wrap_key(e, who), wraps[e]) for e in sorted(wraps)),
        )

    def rotate(
        self,
        from_epoch: int,
        wraps: dict[crypto.PublicKey, crypto.SealedBlob],
        blinding: dict[crypto.PublicKey, crypto.SealedBlob] | None = None,
    ) -> ops.Transaction:
        """ONE transaction: the bump and every wrap, or neither. `evaluate` verdicts a whole
        transaction, so there is never a live epoch nobody holds the master for.

        NO GUARD. A `Holds(P_EPOCH, from_epoch)` was equivalent to the forward-only rule
        `evaluate` already applies -- both say `from_epoch == current`, since the target is derived
        from `from_epoch` too -- and the evaluator's version is strictly stronger, because it binds
        every writer rather than only transactions this method built. Two managers rotating at once
        are serialised by it: the loser's target is no longer `current + 1` and drops as
        EPOCH_JUMP.

        A manager MUST be among `wraps`: managers recover any master by unwrapping their own copy
        from the cluster, so an epoch minted without one can never be re-wrapped for a newcomer.
        `blinding` is written at the first mint only -- the blinding secret never rotates, since
        name tokens are SMT paths."""
        to = from_epoch + 1
        steps = [ops.Step((), ops.Set(self.store_id, P_EPOCH, codec.encode(to)))]
        steps += [
            ops.Step((), ops.Set(self.store_id, _wrap_key(to, who), wraps[who]))
            for who in sorted(wraps)
        ]
        blind = blinding or {}
        steps += [
            ops.Step((), ops.Set(self.store_id, P_BLIND + who, blind[who])) for who in sorted(blind)
        ]
        return ops.Transaction(tuple(steps))
