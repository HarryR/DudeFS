# L_msg — the authenticated (± sealed) request/reply envelope (TRANSPORT.md, the
# NOTES 58/59 substrate). The cluster wire's PEER-IDENTITY layer: every envelope
# carries a `from`, so the request gate can refuse non-members at the door on ANY
# carrier. All authentication and confidentiality live in the MESSAGE, never the
# channel — Noise/TLS is the wrong layer for our message-oriented, sessionless,
# intermediated carriers (TRANSPORT §0). Reuses L0 primitives only: SIGNER
# (Ed25519), sbx1 sealed box, and the keyed-BLAKE2 screening tag.
from __future__ import annotations

import dataclasses
import enum
import hmac
from collections.abc import Callable
from dataclasses import dataclass

from . import codec
from . import crypto as C

# domain-separates an envelope signature from an op signature / a PoP — a signed
# envelope must never be mistakable for any other signed artifact.
_SIG_PREFIX = b"dude.msg:"


@dataclass(frozen=True)
class Envelope:
    """An authenticated L_msg request or reply (TRANSPORT §2). `frm` is the design's
    `from` (a reserved word in Python). The SAME signed struct is sent plain or as
    the sealed inner. `to` binds the message to one recipient INSIDE the seal — the
    anti-reflection field, without which a signed request to A is replayable to B."""

    frm: bytes
    to: bytes
    epoch: int
    ts: int
    nonce: bytes
    verb: bytes
    body: bytes
    sig: bytes = b""

    def _signed_bytes(self) -> bytes:
        # canon(...) = the existing canonical bencode (⟦F⟧, TRANSPORT §2) — injective
        # and golden-pinned; the sig covers everything but itself.
        return _SIG_PREFIX + codec.encode(
            [self.frm, self.to, self.epoch, self.ts, self.nonce, self.verb, self.body]
        )

    def verify_sig(self) -> bool:
        return bool(self.sig) and C.SIGNER.verify(self.frm, self._signed_bytes(), self.sig)

    def encode(self) -> bytes:
        return codec.encode(
            [self.frm, self.to, self.epoch, self.ts, self.nonce, self.verb, self.body, self.sig]
        )

    @staticmethod
    def decode(raw: bytes) -> Envelope:
        f = codec.as_seq(codec.decode(raw), length=8)
        return Envelope(
            frm=codec.as_bytes(f[0]),
            to=codec.as_bytes(f[1]),
            epoch=codec.as_int(f[2]),
            ts=codec.as_int(f[3]),
            nonce=codec.as_bytes(f[4]),
            verb=codec.as_bytes(f[5]),
            body=codec.as_bytes(f[6]),
            sig=codec.as_bytes(f[7]),
        )


def author(
    sk: bytes, to: bytes, verb: bytes, body: bytes, *, epoch: int, ts: int, nonce: bytes = b""
) -> Envelope:
    """Build + sign a plain envelope. `frm` is DERIVED from `sk` (never passed
    separately — the signature can never outrun the identity that made it)."""
    unsigned = Envelope(C.SIGNER.public(sk), to, int(epoch), int(ts), nonce, verb, body)
    return dataclasses.replace(unsigned, sig=C.SIGNER.sign(sk, unsigned._signed_bytes()))


# --------------------------------------------------------------------------- #
# Sealed mode (auth + confidentiality) — sign-then-seal via sbx1 (TRANSPORT §2). #
# The intermediary sees only `to_hint` + ciphertext: "a message, to someone".    #
# --------------------------------------------------------------------------- #


def seal_request(env: Envelope, to_pub: bytes, reply_key: bytes, *, hinted: bool) -> bytes:
    """Seal a fully-signed `env` (+ a REQUIRED fresh ephemeral reply-key) to `to_pub`.
    `reply_key` is the requester's ephemeral PUBLIC key; the node seals its reply back
    to it (confidential both ways, still no session). Required in sealed mode — an
    optional reply-key is a downgrade lever (⟦F⟧). `hinted` emits the screening tag
    for a MULTIPLEXED carrier (§3); a direct carrier passes hinted=False (empty tag,
    `to` stays inside the seal). The outer wire is [to_hint, sealed]."""
    if not reply_key:
        raise ValueError("sealed mode requires a reply-key (no downgrade lever, TRANSPORT §2)")
    inner = codec.encode([env.encode(), reply_key])
    sealed = C.seal_to(to_pub, inner)
    tag = C.screen_tag(to_pub, sealed) if hinted else b""
    return codec.encode([tag, sealed])


def matches_tag(self_pub: bytes, outer: bytes) -> bool:
    """Screen an inbound sealed message off a MULTIPLEXED carrier WITHOUT unsealing
    (TRANSPORT §3): an empty tag means 'not hinted' — a direct carrier, always mine to
    trial-open; a present tag is mine iff it keys under MY identity. A never-member
    cannot forge the tag, so its noise free-drops here before any ECDH (§4)."""
    try:
        parts = codec.as_seq(codec.decode(outer), length=2)
        tag, sealed = codec.as_bytes(parts[0]), codec.as_bytes(parts[1])
    except (ValueError, IndexError, codec.CodecError):
        return False  # malformed -> not mine, screen out
    if not tag:
        return True
    return hmac.compare_digest(tag, C.screen_tag(self_pub, sealed))


def unseal_request(sk: bytes, outer: bytes) -> tuple[Envelope, bytes] | None:
    """Open a sealed request with `sk`; return (inner envelope, reply_key), or None if
    it wasn't sealed to me / is malformed. Does NOT verify the sig or gate — the
    AEAD tag already proves it was sealed to my key; the caller runs `gate` next."""
    try:
        parts = codec.as_seq(codec.decode(outer), length=2)
        opened = C.open_sealed(sk, codec.as_bytes(parts[1]))
        if opened is None:
            return None
        inner = codec.as_seq(codec.decode(opened), length=2)
        return Envelope.decode(codec.as_bytes(inner[0])), codec.as_bytes(inner[1])
    except (ValueError, IndexError, codec.CodecError):
        return None  # malformed -> a non-match, never a crash


def seal_reply(env: Envelope, reply_key: bytes) -> bytes:
    """Seal a node's signed reply back to the requester's ephemeral `reply_key`."""
    return C.seal_to(reply_key, env.encode())


def unseal_reply(reply_sk: bytes, sealed: bytes) -> Envelope | None:
    """Open a sealed reply with the requester's ephemeral reply secret."""
    opened = C.open_sealed(reply_sk, sealed)
    return Envelope.decode(opened) if opened is not None else None


# --------------------------------------------------------------------------- #
# The request gate — L_msg's first consumer (TRANSPORT §5).                       #
# --------------------------------------------------------------------------- #


class Gate(enum.Enum):
    OK = b"ok"
    BAD_SIG = b"bad_sig"
    WRONG_RECIPIENT = b"wrong_recipient"  # anti-reflection: not addressed to me
    STALE = b"stale"  # outside the δ freshness window (DoS hygiene)
    NOT_A_MEMBER = b"not_a_member"  # the gate proper — revoked / non-member


def gate(
    env: Envelope, *, self_pub: bytes, now: int, delta: int, authorized: Callable[[bytes], bool]
) -> Gate:
    """The request gate over an ALREADY-unsealed envelope (TRANSPORT §5). Cheap door
    checks first, membership last. **Check ORDER is load-bearing** (`classify_inbound`
    relies on it): sig THEN recipient come first, so a BAD_SIG / WRONG_RECIPIENT verdict
    marks a sender that has NOT proven it holds our identity — those are classified
    `Dropped` (no reply) so a signed 'no' never leaks our pubkey (TRANSPORT §3/§4).
    `epoch` is DIAGNOSTIC and deliberately NOT gated
    (⟦F⟧): a roster bridge always has an activated party talking to a not-yet-activated
    one, so a hard `epoch == current` refusal is the R1 over-strict-gate class — the
    artifact layer already enforces epoch where it is load-bearing (receipts, QCs,
    RERECEIPT). `authorized(from) -> bool` is the live control-plane view (current
    roster member / un-revoked cert). `ts` is DoS hygiene, not correctness: verbs are
    idempotent + replay-protected, so a re-sent message is inert."""
    if not env.verify_sig():
        return Gate.BAD_SIG
    if env.to != self_pub:
        return Gate.WRONG_RECIPIENT
    if abs(now - env.ts) > delta:
        return Gate.STALE
    if not authorized(env.frm):
        return Gate.NOT_A_MEMBER
    return Gate.OK


# --------------------------------------------------------------------------- #
# Typed outcomes — the encoding layer CLASSIFIES; the transport renders. No I/O,   #
# no blocking, no None: an inbound frame maps to exactly one of these, and the      #
# transport (socket / XMPP / HTTP) decides how to carry each (send a reply, or its  #
# carrier-native silence — a closed frame, no stanza, a 404).                       #
# --------------------------------------------------------------------------- #


@dataclass(frozen=True)
class Gated:
    """The requester passed the gate: authentic, addressed to us, fresh, authorized.
    The transport dispatches `env.body` and seals a reply back to `env.frm`."""

    env: Envelope


@dataclass(frozen=True)
class Refused:
    """Authentic AND addressed to us (so the sender already holds our identity), but
    failed freshness/membership. The transport MAY reply with a signed refusal — it
    leaks nothing new. `reason` is STALE or NOT_A_MEMBER."""

    env: Envelope
    reason: Gate


@dataclass(frozen=True)
class Dropped:
    """The sender did NOT prove it holds our identity (malformed, bad sig, or a probe
    addressed to a pubkey it doesn't hold). The transport renders carrier-native
    SILENCE — no reply — so we never leak our pubkey. `reason` is for the node's own
    logs only; it is never emitted (else it becomes a pubkey-guess oracle)."""

    reason: str


type Inbound = Gated | Refused | Dropped


def classify_inbound(
    data: bytes, *, self_pub: bytes, now: int, delta: int, authorized: Callable[[bytes], bool]
) -> Inbound:
    """Decode + gate one inbound request frame into a typed outcome — PURE, no I/O.
    The transport matches on the result and renders it (reply / silence)."""
    try:
        env = Envelope.decode(data)
    except (codec.CodecError, ValueError, IndexError):
        return Dropped("malformed")
    verdict = gate(env, self_pub=self_pub, now=now, delta=delta, authorized=authorized)
    if verdict is Gate.OK:
        return Gated(env)
    if verdict in (Gate.BAD_SIG, Gate.WRONG_RECIPIENT):
        return Dropped(verdict.name.lower())  # unproven identity -> reveal nothing
    return Refused(env, verdict)  # STALE / NOT_A_MEMBER -> authenticated 'no' is safe


@dataclass(frozen=True)
class Reply:
    """A verified reply from the peer we addressed. `env.body` is the response payload
    — a Receipt, a Rejected(reason), etc.: the node's OWN 'why' rides inside it."""

    env: Envelope


@dataclass(frozen=True)
class NoReply:
    """The peer returned nothing — a silent drop (we weren't proven) or an unreachable
    peer. Indistinguishable at this layer; the cause is simply 'no reply came back'."""


@dataclass(frozen=True)
class MalformedReply:
    """Bytes came back, but not a verifiable signed envelope (corrupt or injected)."""


@dataclass(frozen=True)
class WrongPeer:
    """A valid envelope, but signed by someone OTHER than the peer we addressed — a
    reflection or a misdelivery, never our reply. `frm` is who actually signed it."""

    frm: bytes


# Named per cause (say WHY, not "unusable"): the caller can log exactly what went
# wrong, and a driver can act on it (an authenticated refusal ≠ an unreachable peer).
type ReplyOutcome = Reply | NoReply | MalformedReply | WrongPeer


def classify_reply(data: bytes, *, expect_from: bytes, expect_to: bytes) -> ReplyOutcome:
    """Validate an inbound REPLY frame against the peer we addressed — PURE, no I/O.
    Returns a cause-named outcome; a reply not signed by `expect_from` back to
    `expect_to` is not our reply."""
    if not data:
        return NoReply()
    try:
        env = Envelope.decode(data)
    except (codec.CodecError, ValueError, IndexError):
        return MalformedReply()
    if not env.verify_sig():
        return MalformedReply()  # unsigned / tampered -> not a verifiable reply
    if env.frm != expect_from or env.to != expect_to:
        return WrongPeer(env.frm)
    return Reply(env)
