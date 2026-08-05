# dude.sync.lite_adapter -- typed messages and wire encoding for the light-client verbs.
#
# STATELESS. The four `LiteMsg` subclasses cover the whole protocol vocabulary:
#
#     GetAnchors      -- (fingerprint | None,), verb GET_ANCHORS
#     AnchorsReply    -- (anchors, sigs, fingerprint, bundle | None), verb ANCHORS_REPLY
#     GetProof        -- (store_id, name, block_num), verb GET_PROOF
#     ProofReply      -- (value | ABSENT, proof, state_root), verb PROOF_REPLY
#     LiteRefused     -- (LiteRefusal,), verb LITE_REFUSED
#
# Same shape as `dude.sync.adapter` for `SyncMsg`: each subclass declares its own
# `verb: ClassVar[Verb]` and its `_encode(self) -> bytes`. Adding a subclass to
# `_LITE_MSG_CLASSES` wires it into `_DECODERS` automatically.
#
# WHAT THIS MODULE OWNS. The message types, the closed enum of refusal reasons, and the
# thin bundle types (`RosterBundle`) that shuttle identity-chain material to the client.
#
# WHAT IT DOES NOT OWN. The `LightClient` state machine (`dude.sync.lite`), the server-
# side handlers (`serve_get_anchors`, `serve_get_proof` in `lite.py`), or the SMT proof
# verifier (that lives with `smt.py` when Slice 2 lands).

from __future__ import annotations

from abc import ABC, abstractmethod
from collections.abc import Callable
from dataclasses import dataclass
from enum import Enum
from typing import ClassVar

from ..consensus.settle_round import Anchors, SettledBlock
from ..core import codec, crypto
from ..core.errors import DudeError
from ..net.address import Endpoint
from ..net.envelope import Verb
from ..store.management import Cert, Grant, NodeRecord, Role


class LiteAdapterError(DudeError):
    """A wire message that names a lite-client verb but is not one -- malformed body,
    wrong shape. Not for a `PROOF_REPLY` whose proof does not verify (that is the
    client's own concern); not for `GET_PROOF` naming a `block_num` the responder does
    not hold (that is a `LiteRefused`). For messages that could not have come from an
    honest peer using the same protocol at all."""


class LiteRefusal(Enum):
    """Why a light-client request cannot be served (#light-client-get,
    #light-client-nonmembership). Closed set, same discipline as `SyncRefusal`.

    Wire form is the enum's string value, sent as the `LiteRefused` body."""

    INVALID = "invalid"
    """RESERVED, never returned. Declared FIRST so a zero-valued struct field in a Go
    port lands on a named invalid rather than a real one."""

    NO_STATE = "no-state"
    """The responder holds no SETTLED block yet (a fresh joiner still catching up).
    Retry against another responder."""

    NOT_YET_SETTLED = "not-yet-settled"
    """`GET_PROOF` asks for a `block_num` higher than the responder's head. Retry with
    a lower block_num or against a further-ahead responder."""

    TOO_OLD = "too-old"
    """`GET_PROOF` asks for a `block_num` below the responder's compaction floor.
    Post-#compaction; not currently reachable in the no-compaction path."""

    UNKNOWN_STORE = "unknown-store"
    """`GET_PROOF` names a `store_id` the responder has no state for. Configuration
    drift or a client bug -- reporting distinguishes it from "key not found" (which is
    a first-class non-membership proof, not a refusal)."""

    MALFORMED_QUERY = "malformed-query"
    """The request decoded but was semantically invalid (empty name, out-of-range
    store_id shape, etc.). Client bug; retry after fixing."""

    STALE_CLIENT = "stale-client"
    """The client's `known_trusted_block` is more than `liveness_window` blocks behind
    the responder's head (#light-client-liveness, #light-client-stale). The client MUST
    discard trusted state and re-bootstrap. Walking forward across many blocks is not
    supported -- the light client contract is that clients stay live within the cadence."""

    FORK_DETECTED = "fork-detected"
    """The client's `known_trusted_block=(N, H)` names a block_num the responder holds
    but at a DIFFERENT block_hash. The client is on a chain the responder does not
    (#light-client-fork-detected). Client MUST re-bootstrap; their previous corroboration
    was against responders on a different chain (or the current responder is Byzantine)."""

    INTERNAL = "internal"
    """The responder hit its own defect while assembling the reply. Should never
    happen in practice; here so the enum is total and the caller's branch is
    exhaustive."""


# --------------------------------------------------------------------------------------------- #
# Bundle types                                                                                  #
# --------------------------------------------------------------------------------------------- #


@dataclass(frozen=True, slots=True)
class RosterBundle:
    """The identity chain shipped to a light client on first-bootstrap or fingerprint-
    mismatch. Everything a light client needs to verify the roster from the anchor alone,
    without touching state_root.

    `commitment_*` is the P_ROSTER row: `(serial, sorted_members, cert)`. The cert's
    subject binds `H(codec.encode([serial, sorted_members]))` so a subset fails to
    verify (#roster-commitment-cert).

    `entries` are the P_NODE rows -- addresses + roster #cert per member. The certs prove
    provenance from anchor (each is either anchor-signed or manager-signed with the
    signing manager appearing in `managers`).

    `managers` are the P_GRANT MANAGER rows -- each with its anchor-signed #cert. These
    let the client chain-verify roster entries whose signer is a manager rather than the
    anchor directly."""

    commitment_serial: int
    commitment_members: tuple[crypto.PublicKey, ...]
    commitment_cert: Cert
    entries: tuple[NodeRecord, ...]
    managers: tuple[Grant, ...]

    def _encode(self) -> bytes:
        return codec.encode(
            [
                self.commitment_serial,
                sorted(bytes(m) for m in self.commitment_members),
                self.commitment_cert.encode(),
                [_encode_node_record(rec) for rec in self.entries],
                [_encode_grant(g) for g in self.managers],
            ]
        )

    @classmethod
    def _decode(cls, raw: bytes) -> RosterBundle:
        try:
            p = codec.as_seq(codec.decode(raw), 5)
            serial = codec.as_int(p[0])
            members = tuple(crypto.PublicKey(codec.as_bytes(m)) for m in codec.as_seq(p[1]))
            commitment_cert = Cert.decode(codec.as_bytes(p[2]))
            entries = tuple(_decode_node_record(codec.as_bytes(e)) for e in codec.as_seq(p[3]))
            managers = tuple(_decode_grant(codec.as_bytes(g)) for g in codec.as_seq(p[4]))
        except DudeError as e:
            raise LiteAdapterError(f"malformed RosterBundle: {e}") from e
        return cls(serial, members, commitment_cert, entries, managers)


def _encode_node_record(rec: NodeRecord) -> bytes:
    """Wire form of a P_NODE row content, shipped in a RosterBundle. Same layout as the
    P_NODE row itself: `[encoded_endpoints, sorted_domains, cert]`, plus the identity
    pubkey so the client doesn't have to key-match to reconstruct. Endpoints carry
    per-endpoint options via `Endpoint.encode` (#peer-endpoint-in-log)."""
    return codec.encode(
        [
            rec.identity,
            sorted(ep.encode() for ep in rec.endpoints),
            sorted(rec.domains),
            rec.cert.encode(),
        ]
    )


def _decode_node_record(raw: bytes) -> NodeRecord:
    p = codec.as_seq(codec.decode(raw), 4)
    identity = crypto.PublicKey(codec.as_bytes(p[0]))
    endpoints = tuple(Endpoint.parse(codec.as_bytes(e)) for e in codec.as_seq(p[1]))
    domains = frozenset(codec.as_bytes(d) for d in codec.as_seq(p[2]))
    cert = Cert.decode(codec.as_bytes(p[3]))
    return NodeRecord(identity, endpoints, cert, domains)


def _encode_grant(g: Grant) -> bytes:
    """Wire form of a P_GRANT row content, shipped in a RosterBundle. Layout mirrors the
    P_GRANT row: `[identity, role.value, sorted_stores, sorted_kinds, cert]`."""
    return codec.encode(
        [
            g.identity,
            g.role.value,
            sorted(g.stores),
            sorted(g.kinds),
            g.cert.encode(),
        ]
    )


def _decode_grant(raw: bytes) -> Grant:
    p = codec.as_seq(codec.decode(raw), 5)
    identity = crypto.PublicKey(codec.as_bytes(p[0]))
    role_bytes = codec.as_bytes(p[1])
    try:
        role = Role(role_bytes)
    except ValueError as e:
        raise LiteAdapterError(f"unknown role in Grant: {role_bytes!r}") from e
    stores = frozenset(codec.as_int(x) for x in codec.as_seq(p[2]))
    kinds = frozenset(codec.as_int(x) for x in codec.as_seq(p[3]))
    cert = Cert.decode(codec.as_bytes(p[4]))
    return Grant(identity, role, stores, kinds, cert)


# --------------------------------------------------------------------------------------------- #
# Messages                                                                                      #
# --------------------------------------------------------------------------------------------- #


class LiteMsg(ABC):
    """Base of the lite-client protocol vocabulary. Same shape as `SyncMsg`."""

    verb: ClassVar[Verb]

    @abstractmethod
    def _encode(self) -> bytes: ...

    def encode(self) -> tuple[Verb, bytes]:
        """The wire form: `(verb, body_bytes)`."""
        return self.verb, self._encode()

    @classmethod
    def decode(cls, verb: Verb, body: bytes) -> LiteMsg:
        try:
            handler = _DECODERS[verb]
        except KeyError as e:
            raise LiteAdapterError(f"not a lite-client verb: {verb.name}") from e
        return handler(body)


type TrustedBlock = tuple[int, crypto.Digest]
"""`(block_num, block_hash)` -- what a light client remembers about its last-verified
block. Carried in every light-client request so the responder can piggyback headers to
catch the client up (#light-client-piggyback). `None` at bootstrap or after re-bootstrap."""


def _encode_trusted_block(tb: TrustedBlock | None) -> bytes:
    """Wire form for the optional `TrustedBlock`. Empty bytes when absent; two-tuple
    `[block_num, block_hash]` when present. Encoded within the request payload."""
    if tb is None:
        return b""
    return codec.encode([tb[0], tb[1]])


def _decode_trusted_block(raw: bytes) -> TrustedBlock | None:
    if not raw:
        return None
    p = codec.as_seq(codec.decode(raw), 2)
    return codec.as_int(p[0]), crypto.Digest(codec.as_bytes(p[1]))


@dataclass(frozen=True, slots=True)
class GetAnchors(LiteMsg):
    """A light client asks: what is your current head, and (piggybacked) enough state to
    catch me up if I'm behind (#light-client-piggyback)?

    `known_roster_fingerprint=None` on first bootstrap or when the client wants a fresh
    bundle. `known_trusted_block=None` similarly -- no prior trusted head to advance from.

    Both fields let the responder ship only the delta: bundle iff fingerprint changed,
    headers iff `known_trusted_block` lags the responder's head (up to `liveness_window`
    per #light-client-liveness). Farther behind is refused with `STALE_CLIENT`
    (#light-client-stale); mismatched block_hash is refused with `FORK_DETECTED`
    (#light-client-fork-detected)."""

    verb: ClassVar[Verb] = Verb.GET_ANCHORS

    known_roster_fingerprint: crypto.Digest | None
    known_trusted_block: TrustedBlock | None

    def _encode(self) -> bytes:
        return codec.encode(
            [
                self.known_roster_fingerprint or b"",
                _encode_trusted_block(self.known_trusted_block),
            ]
        )

    @classmethod
    def _decode(cls, body: bytes) -> GetAnchors:
        try:
            p = codec.as_seq(codec.decode(body), 2)
            fp_raw = codec.as_bytes(p[0])
            trusted = _decode_trusted_block(codec.as_bytes(p[1]))
        except DudeError as e:
            raise LiteAdapterError(f"malformed GET_ANCHORS body: {e}") from e
        return cls(
            known_roster_fingerprint=crypto.Digest(fp_raw) if fp_raw else None,
            known_trusted_block=trusted,
        )


@dataclass(frozen=True, slots=True)
class AnchorsReply(LiteMsg):
    """The responder's current SETTLED head anchors + settle_sigs, plus the roster
    fingerprint and (optionally) the full identity bundle and piggybacked headers.

    Client uses this in two ways:
      1. **Bootstrap** (first call, fingerprint=None, trusted_block=None): decode
         `bundle`, verify the cert chain from the anchor, cache the roster, then fan out
         to `f+1` roster members to corroborate `roster_fingerprint`.
      2. **Steady state** (bundle omitted iff fingerprint matches): use `headers[]` to
         chain-verify from the client's trusted_block up to the responder's head
         (#light-client-header-chain), and use `anchors + settle_sigs` as the new
         trusted head."""

    verb: ClassVar[Verb] = Verb.ANCHORS_REPLY

    anchors: Anchors
    signers: crypto.SignerBitmap
    settle_sigs: tuple[crypto.Signature, ...]
    roster_fingerprint: crypto.Digest
    bundle: RosterBundle | None
    headers: tuple[SettledBlock, ...]

    def _encode(self) -> bytes:
        a = self.anchors
        return codec.encode(
            [
                a.block_num,
                a.height,
                a.prev_block,
                a.state_root,
                a.acc_state,
                a.acc_log,
                self.signers,
                list(self.settle_sigs),
                self.roster_fingerprint,
                self.bundle._encode() if self.bundle is not None else b"",  # noqa: SLF001
                [h.encode() for h in self.headers],
            ]
        )

    @classmethod
    def _decode(cls, body: bytes) -> AnchorsReply:
        try:
            p = codec.as_seq(codec.decode(body), 11)
            anchors = Anchors(
                block_num=codec.as_int(p[0]),
                height=codec.as_int(p[1]),
                prev_block=crypto.Digest(codec.as_bytes(p[2])),
                state_root=crypto.Digest(codec.as_bytes(p[3])),
                acc_state=crypto.Accumulator(codec.as_bytes(p[4])),
                acc_log=crypto.Accumulator(codec.as_bytes(p[5])),
            )
            signers = crypto.SignerBitmap(codec.as_bytes(p[6]))
            settle_sigs = tuple(crypto.Signature(codec.as_bytes(s)) for s in codec.as_seq(p[7]))
            roster_fingerprint = crypto.Digest(codec.as_bytes(p[8]))
            bundle_bytes = codec.as_bytes(p[9])
            bundle = RosterBundle._decode(bundle_bytes) if bundle_bytes else None  # noqa: SLF001
            headers = tuple(SettledBlock.decode(codec.as_bytes(h)) for h in codec.as_seq(p[10]))
        except DudeError as e:
            raise LiteAdapterError(f"malformed ANCHORS_REPLY body: {e}") from e
        return cls(anchors, signers, settle_sigs, roster_fingerprint, bundle, headers)


@dataclass(frozen=True, slots=True)
class GetProof(LiteMsg):
    """A light client asks for a value + SMT proof for `(store_id, name)` at
    `block_num`. Responder must hold the state at that block_num to serve. Reply is
    `ProofReply` (value present or absent, both proof-carrying) or `LiteRefused`.

    Piggyback fields (#light-client-piggyback): `known_roster_fingerprint` and
    `known_trusted_block` let the responder ship any bundle refresh or catch-up headers
    in the SAME reply. Cadence-normal reads become one RT that both reads AND advances
    the client's trusted head."""

    verb: ClassVar[Verb] = Verb.GET_PROOF

    store_id: int
    name: bytes
    block_num: int
    known_roster_fingerprint: crypto.Digest | None
    known_trusted_block: TrustedBlock | None

    def _encode(self) -> bytes:
        return codec.encode(
            [
                self.store_id,
                self.name,
                self.block_num,
                self.known_roster_fingerprint or b"",
                _encode_trusted_block(self.known_trusted_block),
            ]
        )

    @classmethod
    def _decode(cls, body: bytes) -> GetProof:
        try:
            p = codec.as_seq(codec.decode(body), 5)
            fp_raw = codec.as_bytes(p[3])
            trusted = _decode_trusted_block(codec.as_bytes(p[4]))
            return cls(
                store_id=codec.as_int(p[0]),
                name=codec.as_bytes(p[1]),
                block_num=codec.as_int(p[2]),
                known_roster_fingerprint=crypto.Digest(fp_raw) if fp_raw else None,
                known_trusted_block=trusted,
            )
        except DudeError as e:
            raise LiteAdapterError(f"malformed GET_PROOF body: {e}") from e


# Sentinel for "no value" in a ProofReply. Distinct from empty-bytes-as-value because a
# real value CAN legitimately be `b""` (an empty ciphertext, an empty roster slot). The
# sentinel is a marker outside the value-bytes namespace.
ABSENT_MARKER = b""


@dataclass(frozen=True, slots=True)
class ProofReply(LiteMsg):
    """Value or non-membership proof for a `GET_PROOF` request, piggybacked with any
    catch-up info the client needs (headers + optional bundle refresh).

    - `value/absent/proof/state_root` -- the requested proof at `block_num`. Client
      verifies against a trusted state_root at that height.
    - `anchors/signers/settle_sigs/roster_fingerprint` -- the responder's CURRENT head,
      used to advance client's trusted head via #light-client-header-chain.
    - `bundle` -- a fresh RosterBundle iff the client's cached fingerprint doesn't match
      the responder's current fingerprint (#light-client-roster-change-in-window).
    - `headers[]` -- 0 to `liveness_window` SettledBlocks between the client's
      `known_trusted_block` and the responder's head. Empty when caught up.

    Slice 1 places `proof: bytes` as an opaque wire field -- the SMT proof shape pins
    when the client-side verifier lands."""

    verb: ClassVar[Verb] = Verb.PROOF_REPLY

    value: bytes  # ABSENT_MARKER for non-membership; opaque bytes otherwise
    absent: bool
    proof: bytes
    state_root: crypto.Digest
    anchors: Anchors
    signers: crypto.SignerBitmap
    settle_sigs: tuple[crypto.Signature, ...]
    roster_fingerprint: crypto.Digest
    bundle: RosterBundle | None
    headers: tuple[SettledBlock, ...]

    def _encode(self) -> bytes:
        a = self.anchors
        return codec.encode(
            [
                self.value,
                1 if self.absent else 0,
                self.proof,
                self.state_root,
                a.block_num,
                a.height,
                a.prev_block,
                a.state_root,
                a.acc_state,
                a.acc_log,
                self.signers,
                list(self.settle_sigs),
                self.roster_fingerprint,
                self.bundle._encode() if self.bundle is not None else b"",  # noqa: SLF001
                [h.encode() for h in self.headers],
            ]
        )

    @classmethod
    def _decode(cls, body: bytes) -> ProofReply:
        try:
            p = codec.as_seq(codec.decode(body), 15)
            anchors = Anchors(
                block_num=codec.as_int(p[4]),
                height=codec.as_int(p[5]),
                prev_block=crypto.Digest(codec.as_bytes(p[6])),
                state_root=crypto.Digest(codec.as_bytes(p[7])),
                acc_state=crypto.Accumulator(codec.as_bytes(p[8])),
                acc_log=crypto.Accumulator(codec.as_bytes(p[9])),
            )
            signers = crypto.SignerBitmap(codec.as_bytes(p[10]))
            settle_sigs = tuple(crypto.Signature(codec.as_bytes(s)) for s in codec.as_seq(p[11]))
            roster_fingerprint = crypto.Digest(codec.as_bytes(p[12]))
            bundle_bytes = codec.as_bytes(p[13])
            bundle = RosterBundle._decode(bundle_bytes) if bundle_bytes else None  # noqa: SLF001
            headers = tuple(SettledBlock.decode(codec.as_bytes(h)) for h in codec.as_seq(p[14]))
            return cls(
                value=codec.as_bytes(p[0]),
                absent=codec.as_int(p[1]) == 1,
                proof=codec.as_bytes(p[2]),
                state_root=crypto.Digest(codec.as_bytes(p[3])),
                anchors=anchors,
                signers=signers,
                settle_sigs=settle_sigs,
                roster_fingerprint=roster_fingerprint,
                bundle=bundle,
                headers=headers,
            )
        except DudeError as e:
            raise LiteAdapterError(f"malformed PROOF_REPLY body: {e}") from e


@dataclass(frozen=True, slots=True)
class LiteRefused(LiteMsg):
    """A refusal to serve a light-client request. Uniform reply-shape whether the
    request was `GET_ANCHORS` or `GET_PROOF`; the client's retry logic is the same for
    both (try another responder, or fail after enough retries)."""

    verb: ClassVar[Verb] = Verb.LITE_REFUSED

    reason: LiteRefusal

    def _encode(self) -> bytes:
        return self.reason.value.encode()

    @classmethod
    def _decode(cls, body: bytes) -> LiteRefused:
        try:
            reason = LiteRefusal(body.decode("utf-8"))
        except (ValueError, UnicodeDecodeError) as e:
            raise LiteAdapterError(f"unknown LITE_REFUSED reason: {body!r}") from e
        return cls(reason=reason)


_LITE_MSG_CLASSES: tuple[type[LiteMsg], ...] = (
    GetAnchors,
    AnchorsReply,
    GetProof,
    ProofReply,
    LiteRefused,
)
"""The closed set of lite-client message subclasses. `_DECODERS` derives from this;
adding a new verb requires exactly two edits: define the subclass, add it here."""


_DECODERS: dict[Verb, Callable[[bytes], LiteMsg]] = {
    c.verb: c._decode  # noqa: SLF001 -- same-module dispatch table
    for c in _LITE_MSG_CLASSES
}


__all__ = [
    "ABSENT_MARKER",
    "AnchorsReply",
    "GetAnchors",
    "GetProof",
    "LiteAdapterError",
    "LiteMsg",
    "LiteRefusal",
    "LiteRefused",
    "ProofReply",
    "RosterBundle",
]
