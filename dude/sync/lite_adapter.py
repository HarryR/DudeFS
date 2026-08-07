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

from ..consensus.settle_round import SettledBlock
from ..core import codec, crypto
from ..core.errors import DudeError
from ..net.envelope import Verb
from ..store.management import Cert, Grant, NodeRecord


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
                [rec.encode() for rec in self.entries],
                [g.encode() for g in self.managers],
            ]
        )

    @classmethod
    def _decode(cls, raw: bytes) -> RosterBundle:
        try:
            p = codec.as_seq(codec.decode(raw), 5)
            serial = codec.as_int(p[0])
            members = tuple(crypto.PublicKey(codec.as_bytes(m)) for m in codec.as_seq(p[1]))
            commitment_cert = Cert.decode(codec.as_bytes(p[2]))
            entries = tuple(NodeRecord.decode(codec.as_bytes(e)) for e in codec.as_seq(p[3]))
            managers = tuple(Grant.decode(codec.as_bytes(g)) for g in codec.as_seq(p[4]))
        except DudeError as e:
            raise LiteAdapterError(f"malformed RosterBundle: {e}") from e
        return cls(serial, members, commitment_cert, entries, managers)


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


@dataclass(frozen=True, slots=True)
class TrustedBlock:
    """What a light client remembers about its last-verified block. Carried in every light-
    client request so the responder can piggyback headers to catch the client up
    (#light-client-piggyback). `None` (via `encode_optional`/`decode_optional`) at bootstrap
    or after re-bootstrap -- the request field is nullable, absence-on-wire is empty bytes."""

    block_num: int
    block_hash: crypto.Digest

    def encode(self) -> bytes:
        """Present form: `[block_num, block_hash]`. Absence uses `encode_optional`."""
        return codec.encode([self.block_num, self.block_hash])

    @classmethod
    def decode(cls, raw: bytes) -> TrustedBlock:
        """Parse the present form. Raises `DudeError` on shape mismatch. For the nullable
        field, use `decode_optional`."""
        p = codec.as_seq(codec.decode(raw), 2)
        return cls(codec.as_int(p[0]), crypto.Digest(codec.as_bytes(p[1])))

    @classmethod
    def encode_optional(cls, tb: TrustedBlock | None) -> bytes:
        """Nullable wire form: empty bytes when absent, `encode()` when present. Used as a
        request field so the responder can distinguish 'first bootstrap' from 'catch me up
        from here' -- the two mean different things (full bundle vs headers)."""
        return b"" if tb is None else tb.encode()

    @classmethod
    def decode_optional(cls, raw: bytes) -> TrustedBlock | None:
        """Inverse of `encode_optional`. Empty bytes -> None."""
        return None if not raw else cls.decode(raw)


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
                TrustedBlock.encode_optional(self.known_trusted_block),
            ]
        )

    @classmethod
    def _decode(cls, body: bytes) -> GetAnchors:
        try:
            p = codec.as_seq(codec.decode(body), 2)
            fp_raw = codec.as_bytes(p[0])
            trusted = TrustedBlock.decode_optional(codec.as_bytes(p[1]))
        except DudeError as e:
            raise LiteAdapterError(f"malformed GET_ANCHORS body: {e}") from e
        return cls(
            known_roster_fingerprint=crypto.Digest(fp_raw) if fp_raw else None,
            known_trusted_block=trusted,
        )


@dataclass(frozen=True, slots=True)
class AnchorsReply(LiteMsg):
    """The responder's current SETTLED head as a full `SettledBlock` (slice + anchors +
    quorum multisig), plus the roster fingerprint and (optionally) the full identity
    bundle and piggybacked headers.

    Why the whole `SettledBlock`, not just anchors + settle_sigs: `settle_sigs` cover
    `_settle_payload(slice_hash, anchors)`, and `slice_hash` derives from the slice
    (bucket + sorted hashes). Without the slice content the client cannot verify the
    signatures. Shipping the full `SettledBlock` costs bytes proportional to the slice
    size but is the only shape that lets the client verify independently.

    Client uses this in two ways:
      1. **Bootstrap** (first call, fingerprint=None, trusted_block=None): decode
         `bundle`, verify the cert chain from the anchor, cache the roster, then fan
         out to `f+1` roster members to corroborate `roster_fingerprint`.
      2. **Steady state** (bundle omitted iff fingerprint matches): use `headers[]` to
         chain-verify from the client's trusted_block up to the responder's head
         (#light-client-header-chain), and use `head` as the new trusted head."""

    verb: ClassVar[Verb] = Verb.ANCHORS_REPLY

    head: SettledBlock
    roster_fingerprint: crypto.Digest
    bundle: RosterBundle | None
    headers: tuple[SettledBlock, ...]

    def _encode(self) -> bytes:
        return codec.encode(
            [
                self.head.encode(),
                self.roster_fingerprint,
                self.bundle._encode() if self.bundle is not None else b"",  # noqa: SLF001
                [h.encode() for h in self.headers],
            ]
        )

    @classmethod
    def _decode(cls, body: bytes) -> AnchorsReply:
        try:
            p = codec.as_seq(codec.decode(body), 4)
            head = SettledBlock.decode(codec.as_bytes(p[0]))
            roster_fingerprint = crypto.Digest(codec.as_bytes(p[1]))
            bundle_bytes = codec.as_bytes(p[2])
            bundle = RosterBundle._decode(bundle_bytes) if bundle_bytes else None  # noqa: SLF001
            headers = tuple(SettledBlock.decode(codec.as_bytes(h)) for h in codec.as_seq(p[3]))
        except DudeError as e:
            raise LiteAdapterError(f"malformed ANCHORS_REPLY body: {e}") from e
        return cls(head, roster_fingerprint, bundle, headers)


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
                TrustedBlock.encode_optional(self.known_trusted_block),
            ]
        )

    @classmethod
    def _decode(cls, body: bytes) -> GetProof:
        try:
            p = codec.as_seq(codec.decode(body), 5)
            fp_raw = codec.as_bytes(p[3])
            trusted = TrustedBlock.decode_optional(codec.as_bytes(p[4]))
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
    """Value + credential + SMT proof for a `GET_PROOF` request, piggybacked with any
    catch-up info the client needs (headers + optional bundle refresh).

    - `value / credential / absent / proof` -- the SMT proof-emitting pair at
      `block_num`. The client verifies `smt.verify(head.anchors.state_root, store_id,
      name, (value, credential) or None, Proof.decode(proof))`; the SMT leaf commits to
      BOTH value and credential (#light-client-nonmembership), so both are required to
      reconstruct the terminal.
    - `head` -- the responder's CURRENT head, a full `SettledBlock`. Client uses it to
      advance trusted head via #light-client-header-chain; its `anchors.state_root` is
      the root the proof verifies against.
    - `roster_fingerprint` / `bundle` -- fresh RosterBundle iff the client's cached
      fingerprint doesn't match the responder's (#light-client-roster-change-in-window).
    - `headers[]` -- 0 to `liveness_window` SettledBlocks between the client's
      `known_trusted_block` and the responder's head. Empty when caught up.

    There is DELIBERATELY no separate `state_root` field: `head.anchors.state_root` is
    the one authoritative source and duplicating it invites two-field-must-agree traps."""

    verb: ClassVar[Verb] = Verb.PROOF_REPLY

    value: bytes  # ABSENT_MARKER for non-membership; opaque bytes otherwise
    credential: bytes  # b"" for non-membership; opaque bytes otherwise
    absent: bool
    proof: bytes  # `smt.Proof.encode()`; `smt.Proof.decode()` at the client
    head: SettledBlock
    roster_fingerprint: crypto.Digest
    bundle: RosterBundle | None
    headers: tuple[SettledBlock, ...]

    def _encode(self) -> bytes:
        return codec.encode(
            [
                self.value,
                self.credential,
                1 if self.absent else 0,
                self.proof,
                self.head.encode(),
                self.roster_fingerprint,
                self.bundle._encode() if self.bundle is not None else b"",  # noqa: SLF001
                [h.encode() for h in self.headers],
            ]
        )

    @classmethod
    def _decode(cls, body: bytes) -> ProofReply:
        try:
            p = codec.as_seq(codec.decode(body), 8)
            head = SettledBlock.decode(codec.as_bytes(p[4]))
            roster_fingerprint = crypto.Digest(codec.as_bytes(p[5]))
            bundle_bytes = codec.as_bytes(p[6])
            bundle = RosterBundle._decode(bundle_bytes) if bundle_bytes else None  # noqa: SLF001
            headers = tuple(SettledBlock.decode(codec.as_bytes(h)) for h in codec.as_seq(p[7]))
            return cls(
                value=codec.as_bytes(p[0]),
                credential=codec.as_bytes(p[1]),
                absent=codec.as_int(p[2]) == 1,
                proof=codec.as_bytes(p[3]),
                head=head,
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


# --------------------------------------------------------------------------------------------- #
# The adapter                                                                                   #
# --------------------------------------------------------------------------------------------- #


class LiteAdapter:
    """Send lite-client messages via a Postman. Parallels `SyncAdapter` for `SyncMsg`.

    Node uses `reply(env, msg, now)` to answer inbound `GET_ANCHORS` / `GET_PROOF`.
    LightClient (when built) uses `send(peer, msg, now, await_reply=True)` for outbound
    requests."""

    def __init__(self, me: crypto.Keypair, postman, ttl):
        self.me = me
        self.postman = postman
        self.ttl = ttl

    def send(self, to: crypto.PublicKey, msg: LiteMsg, now) -> bytes:
        """Post a directed request. Returns the message-id, which the caller can
        correlate with the eventual reply if it tracks its own outstanding requests.
        All light-client verbs are request-reply, so `await_reply=True` is implicit."""
        from ..net.envelope import Envelope, new_message_id  # noqa: PLC0415

        verb, body = msg.encode()
        mid = new_message_id()
        env = Envelope(to, verb, mid, body).sign(self.me, now)
        self.postman.mailbox.post(env, now, self.ttl, await_reply=True)
        return mid

    def reply(self, to, msg: LiteMsg, now):
        """Answer an inbound request. Uses `env.answer(verb, body)` so `reply_to` echoes
        the original's MessageId -- what the requester's mailbox uses to correlate."""
        verb, body = msg.encode()
        self.postman.mailbox.post(
            to.answer(verb, body).sign(self.me, now), now, self.ttl, await_reply=False
        )


__all__ = [
    "ABSENT_MARKER",
    "AnchorsReply",
    "GetAnchors",
    "GetProof",
    "LiteAdapter",
    "LiteAdapterError",
    "LiteMsg",
    "LiteRefusal",
    "LiteRefused",
    "ProofReply",
    "RosterBundle",
]
