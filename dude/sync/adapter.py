# dude.sync.adapter -- the wire encoding for the four sync verbs.
#
# STATELESS. Encoders and decoders for HEIGHT, HEIGHT_REPLY, GETBLOCK, SETTLED_BLOCK, and the
# REFUSED-with-reason bodies sync returns for unservable GETBLOCK requests. The `SyncAdapter`
# class holds a keypair + Postman for send/deliver -- mirrors `RoundAdapter` / `SettleAdapter`
# in shape, so the same "adapter is the seam between sans-I/O logic and the wire" discipline
# applies (#sync-in-its-own-module).
#
# WHAT THIS MODULE OWNS. Bytes-in, bytes-out for sync's own verbs; the closed enum of refusal
# reasons; a small class that ties the two together with the Postman.
#
# WHAT IT DOES NOT OWN. The Follower state machine (that is `dude.sync.follower`, Stage 3), the
# actual block-serve lookup (that is `Store.settled_at` on the answering side, called by whoever
# handles `GETBLOCK` -- Node in Stage 4).

from __future__ import annotations

from enum import Enum

from ..consensus.settle_round import SettledBlockWithBodies
from ..core import codec, crypto
from ..core.errors import DudeError
from ..core.units import Millis
from ..net.envelope import Envelope, SignedEnvelope, Verb, new_message_id
from ..net.postman import Postman


class SyncAdapterError(DudeError):
    """A wire message that names a sync verb but is not one -- malformed body, wrong shape.

    Not for a `GETBLOCK n` where `n` is out of range (that is a REFUSED reply, not a parse
    failure) and not for a `SETTLED_BLOCK` whose sigs do not verify (that is the Follower's
    own concern). For messages that could not have come from an honest peer using the same
    protocol at all."""


class SyncRefusal(Enum):
    """Why a `GETBLOCK n` cannot be served (#getblock-refuses-with-reason).

    Closed set, same discipline as `mempool.Refusal`: the caller must be able to branch
    exhaustively (e.g., "peer is behind me" vs "peer has compacted this away" needs different
    follow-up), and a stringly-typed reason would drift silently across implementations.

    Wire form is the enum's string value, sent as the REFUSED body."""

    INVALID = "invalid"
    """RESERVED, never returned. Declared FIRST so a Go/Rust port's zero-valued struct field
    lands on a named invalid rather than a real one (same reason `mempool.Refusal.INVALID`
    exists). Receiving it MUST be treated as a decode fault."""

    NOT_YET_SETTLED = "not-yet-settled"
    """The peer's own head is below `n`. Common during a joiner's initial catch-up if the
    peer just came online too, or if the requester picked a peer that turned out to be
    behind. The requester should try another peer."""

    UNKNOWN = "unknown"
    """The peer does not hold `n` for a reason that isn't captured by another member.
    Placeholder for future refusal reasons (compaction, corruption) added by their own
    named members as they land."""


# --------------------------------------------------------------------------------------------- #
# Per-verb encoders / decoders                                                                  #
# --------------------------------------------------------------------------------------------- #


def encode_height() -> tuple[Verb, bytes]:
    """The poll. No body -- the request IS the question."""
    return Verb.HEIGHT, b""


def encode_height_reply(block_num: int, tip_hash: crypto.Digest) -> tuple[Verb, bytes]:
    """`(block_num, tip_hash)` -- the peer's current SETTLED head, plus its identity hash so
    the requester can fork-detect at poll time (#poll-detects-divergent-tips).

    UNSIGNED body. The envelope's own signature binds the reply to this peer and correlates it
    to the specific request; no additional signature is needed inside the body."""
    return Verb.HEIGHT_REPLY, codec.encode([block_num, tip_hash])


def decode_height_reply(body: bytes) -> tuple[int, crypto.Digest]:
    """The inverse of `encode_height_reply`. Raises `SyncAdapterError` on malformed body."""
    try:
        p = codec.as_seq(codec.decode(body), 2)
        return codec.as_int(p[0]), crypto.Digest(codec.as_bytes(p[1]))
    except DudeError as e:
        raise SyncAdapterError(f"malformed HEIGHT_REPLY body: {e}") from e


def encode_getblock(n: int) -> tuple[Verb, bytes]:
    """`GETBLOCK n` -- fetch the SETTLED block at block_num `n`. Body is just the integer."""
    return Verb.GETBLOCK, codec.encode(n)


def decode_getblock(body: bytes) -> int:
    """The inverse of `encode_getblock`. Raises `SyncAdapterError` on malformed body."""
    try:
        return codec.as_int(codec.decode(body))
    except DudeError as e:
        raise SyncAdapterError(f"malformed GETBLOCK body: {e}") from e


def encode_settled_block(sbwb: SettledBlockWithBodies) -> tuple[Verb, bytes]:
    """The reply body is the wire form of `SettledBlockWithBodies`: block bytes (identity +
    proof) plus tx bodies. The Node's answering handler assembles the wrapper from
    `store.settled_at(n)` + `store.bodies_of_block(n)` and passes it here."""
    return Verb.SETTLED_BLOCK, sbwb.encode()


def decode_settled_block(body: bytes) -> SettledBlockWithBodies:
    """The inverse of `encode_settled_block`. Raises `SettleError` (a `DudeError`) on malformed
    bytes; the caller is expected to be inside the crash-only boundary that catches
    `DudeError`."""
    return SettledBlockWithBodies.decode(body)


def encode_refusal(reason: SyncRefusal) -> tuple[Verb, bytes]:
    """A REFUSED reply for a sync request. Reason is the enum's string value."""
    return Verb.REFUSED, reason.value.encode()


def decode_refusal(body: bytes) -> SyncRefusal:
    """The inverse of `encode_refusal`. Raises `SyncAdapterError` on an unknown reason value
    -- unrecognized reasons are a protocol mismatch, not a routine drop."""
    try:
        return SyncRefusal(body.decode("utf-8"))
    except (ValueError, UnicodeDecodeError) as e:
        raise SyncAdapterError(f"unknown REFUSED reason: {body!r}") from e


# --------------------------------------------------------------------------------------------- #
# The adapter                                                                                   #
# --------------------------------------------------------------------------------------------- #


class SyncAdapter:
    """Send sync messages via a Postman; expose small helpers for the caller (Follower or Node)
    to build outbound envelopes.

    NOT a Follower. This class holds no sync state -- no known-heights, no in-flight pulls. It
    is the wire boundary only: given a verb and body, wrap it in an envelope and post it. The
    Follower (Stage 3) is what decides WHEN to send and WHAT TO ASK; the Node (Stage 4) is what
    decides how to ANSWER an inbound request."""

    def __init__(self, me: crypto.Keypair, postman: Postman, ttl: Millis) -> None:
        self.me = me
        self.postman = postman
        self.ttl = ttl

    def send(
        self, to: crypto.PublicKey, verb: Verb, body: bytes, now: Millis, *, await_reply: bool
    ) -> None:
        """Post one directed envelope. HEIGHT and GETBLOCK are the request half (await_reply=True
        so the mailbox correlates the answer); HEIGHT_REPLY, SETTLED_BLOCK, REFUSED are the
        answer half (await_reply=False)."""
        env = Envelope(to, verb, new_message_id(), body).sign(self.me, now)
        self.postman.mailbox.post(env, now, self.ttl, await_reply=await_reply)

    def reply(self, to: SignedEnvelope, verb: Verb, body: bytes, now: Millis) -> None:
        """Answer an inbound request. `answer` produces an Envelope whose `reply_to` echoes the
        original's MessageId -- what the requester's mailbox uses to correlate."""
        self.postman.mailbox.post(
            to.answer(verb, body).sign(self.me, now), now, self.ttl, await_reply=False
        )


__all__ = [
    "SyncAdapter",
    "SyncAdapterError",
    "SyncRefusal",
    "decode_getblock",
    "decode_height_reply",
    "decode_refusal",
    "decode_settled_block",
    "encode_getblock",
    "encode_height",
    "encode_height_reply",
    "encode_refusal",
    "encode_settled_block",
]
