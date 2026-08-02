# dude.sync.adapter -- typed messages and the wire encoding for the four sync verbs.
#
# STATELESS. The five `SyncMsg` subclasses cover the whole protocol vocabulary:
#
#     HeightAsk           -- bodyless poll, verb HEIGHT
#     HeightReply         -- (block_num, tip_hash), verb HEIGHT_REPLY
#     GetBlock            -- (n,), verb GETBLOCK
#     SettledBlockReply   -- (SettledBlockWithBodies,), verb SETTLED_BLOCK
#     Refused             -- (SyncRefusal,), verb REFUSED
#
# Each subclass declares its own `verb: ClassVar[Verb]` and implements `_encode(self) -> bytes`
# for the body. The base class's concrete `encode(self)` bundles `(verb, body)`.
# `SyncMsg.decode(verb, body)` dispatches via `_DECODERS`, which is DERIVED from an explicit
# class list -- adding a subclass to that list wires it into decode automatically.
#
# WHAT THIS MODULE OWNS. The message types, the closed enum of refusal reasons, and the small
# class that pairs the encoder with a Postman.
#
# WHAT IT DOES NOT OWN. The Follower state machine (`dude.sync.follower`), the block-serve
# lookup (`serve_getblock` in follower.py -- takes a `GetBlock` and returns a `SyncMsg`).

from __future__ import annotations

from abc import ABC, abstractmethod
from collections.abc import Callable
from dataclasses import dataclass
from enum import Enum
from typing import ClassVar

from ..consensus.settle_round import SettledBlockWithBodies
from ..core import codec, crypto
from ..core.errors import DudeError
from ..core.units import Millis
from ..net.envelope import Envelope, SignedEnvelope, Verb, new_message_id
from ..net.postman import Postman


class SyncAdapterError(DudeError):
    """A wire message that names a sync verb but is not one -- malformed body, wrong shape.

    Not for a `GETBLOCK n` where `n` is out of range (that is a `Refused` reply, not a parse
    failure) and not for a `SETTLED_BLOCK` whose sigs do not verify (that is the Follower's
    own concern). For messages that could not have come from an honest peer using the same
    protocol at all."""


class SyncRefusal(Enum):
    """Why a `GETBLOCK n` cannot be served (#getblock-refuses-with-reason).

    Closed set, same discipline as `mempool.Refusal`: the caller must be able to branch
    exhaustively (e.g., "peer is behind me" vs "peer has compacted this away" needs different
    follow-up), and a stringly-typed reason would drift silently across implementations.

    Wire form is the enum's string value, sent as the `Refused` body."""

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
# Messages                                                                                      #
# --------------------------------------------------------------------------------------------- #


class SyncMsg(ABC):
    """Base of the sync protocol vocabulary. Every subclass:

      * is a frozen dataclass;
      * declares `verb: ClassVar[Verb]` -- its wire tag;
      * implements `_encode(self) -> bytes` -- its body-only wire form;
      * implements classmethod `_decode(cls, body: bytes) -> Self` -- the body inverse;
      * appears in `_SYNC_MSG_CLASSES` so `_DECODERS` sees it.

    Instantiating `SyncMsg` directly is not meaningful -- `_encode` is abstract, so ABC guards
    that at construction time. Use `msg.encode()` for the wire form (bundles verb + body) and
    `SyncMsg.decode(verb, body)` for inbound wire frames."""

    verb: ClassVar[Verb]
    """Wire tag for this message type. Each concrete subclass MUST assign a distinct `Verb`."""

    @abstractmethod
    def _encode(self) -> bytes:
        """The BODY bytes for this message. Subclass owns the layout; `encode()` wraps in the
        verb. Deterministic and byte-canonical -- two nodes with identical `msg` values MUST
        produce identical output."""

    def encode(self) -> tuple[Verb, bytes]:
        """The wire form of this message: `(verb, body_bytes)`. Composed from the class's
        `verb` attribute and `_encode()`."""
        return self.verb, self._encode()

    @classmethod
    def decode(cls, verb: Verb, body: bytes) -> SyncMsg:
        """The inverse of `encode`: given a wire verb + body, dispatch to the matching
        subclass's decoder. Raises `SyncAdapterError` on unknown verb or malformed body; a
        `SETTLED_BLOCK` with unparsable bytes propagates `SettleError` from
        `SettledBlockWithBodies.decode` -- both are `DudeError`, the caller sits inside a
        crash-only boundary that catches it."""
        try:
            handler = _DECODERS[verb]
        except KeyError as e:
            raise SyncAdapterError(f"not a sync verb: {verb.name}") from e
        return handler(body)


@dataclass(frozen=True, slots=True)
class HeightAsk(SyncMsg):
    """The poll. Bodyless -- the request IS the question. An empty dataclass rather than a
    sentinel so the type discipline matches the other four verbs uniformly."""

    verb: ClassVar[Verb] = Verb.HEIGHT

    def _encode(self) -> bytes:
        return b""

    @classmethod
    def _decode(cls, body: bytes) -> HeightAsk:
        if body != b"":
            raise SyncAdapterError(f"HEIGHT body must be empty, got {body!r}")
        return cls()


@dataclass(frozen=True, slots=True)
class HeightReply(SyncMsg):
    """The peer's current SETTLED head plus its identity hash. `tip_hash` lets the requester
    fork-detect at poll time (#poll-detects-divergent-tips) before spending a GETBLOCK.

    UNSIGNED at the message layer -- the envelope's own signature binds this to a peer and to
    a specific request via `reply_to`; no additional signature is needed inside the body."""

    verb: ClassVar[Verb] = Verb.HEIGHT_REPLY

    block_num: int
    tip_hash: crypto.Digest

    def _encode(self) -> bytes:
        return codec.encode([self.block_num, self.tip_hash])

    @classmethod
    def _decode(cls, body: bytes) -> HeightReply:
        try:
            p = codec.as_seq(codec.decode(body), 2)
            return cls(
                block_num=codec.as_int(p[0]),
                tip_hash=crypto.Digest(codec.as_bytes(p[1])),
            )
        except DudeError as e:
            raise SyncAdapterError(f"malformed HEIGHT_REPLY body: {e}") from e


@dataclass(frozen=True, slots=True)
class GetBlock(SyncMsg):
    """Fetch the SETTLED block at block_num `n`."""

    verb: ClassVar[Verb] = Verb.GETBLOCK

    n: int

    def _encode(self) -> bytes:
        return codec.encode(self.n)

    @classmethod
    def _decode(cls, body: bytes) -> GetBlock:
        try:
            return cls(n=codec.as_int(codec.decode(body)))
        except DudeError as e:
            raise SyncAdapterError(f"malformed GETBLOCK body: {e}") from e


@dataclass(frozen=True, slots=True)
class SettledBlockReply(SyncMsg):
    """A pulled block plus the tx bodies a joiner needs for replay. The producer's answer to
    `GetBlock(n)`. `payload.block` bytes are byte-canonical so the joiner recomputes the same
    `block_hash` (#block-shape-settled)."""

    verb: ClassVar[Verb] = Verb.SETTLED_BLOCK

    payload: SettledBlockWithBodies

    def _encode(self) -> bytes:
        return self.payload.encode()

    @classmethod
    def _decode(cls, body: bytes) -> SettledBlockReply:
        # SettledBlockWithBodies.decode raises SettleError (a DudeError) on bad bytes; let it
        # propagate -- the caller's crash-only boundary catches DudeError.
        return cls(payload=SettledBlockWithBodies.decode(body))


@dataclass(frozen=True, slots=True)
class Refused(SyncMsg):
    """A refusal to serve a `GetBlock` -- see `SyncRefusal` for the reason enum. Also used by
    the answering side when a `GetBlock` body doesn't decode (`Refused(UNKNOWN)`), so the
    requester's next-peer path is uniform regardless of failure mode."""

    verb: ClassVar[Verb] = Verb.REFUSED

    reason: SyncRefusal

    def _encode(self) -> bytes:
        return self.reason.value.encode()

    @classmethod
    def _decode(cls, body: bytes) -> Refused:
        try:
            reason = SyncRefusal(body.decode("utf-8"))
        except (ValueError, UnicodeDecodeError) as e:
            raise SyncAdapterError(f"unknown REFUSED reason: {body!r}") from e
        return cls(reason=reason)


_SYNC_MSG_CLASSES: tuple[type[SyncMsg], ...] = (
    HeightAsk,
    HeightReply,
    GetBlock,
    SettledBlockReply,
    Refused,
)
"""The closed set of sync message subclasses. `_DECODERS` is derived from this; adding a new
verb requires exactly two edits: define the subclass, add it here."""


_DECODERS: dict[Verb, Callable[[bytes], SyncMsg]] = {
    c.verb: c._decode  # noqa: SLF001 -- same-module dispatch table
    for c in _SYNC_MSG_CLASSES
}


# --------------------------------------------------------------------------------------------- #
# The adapter                                                                                   #
# --------------------------------------------------------------------------------------------- #


class SyncAdapter:
    """Send sync messages via a Postman.

    NOT a Follower. This class holds no sync state -- no known-heights, no in-flight pulls.
    It is the wire boundary only: given a `SyncMsg`, encode via its own `encode()` method and
    post. The Follower (`dude.sync.follower`) decides WHEN to send and WHAT TO ASK; the
    Node's dispatcher decides how to ANSWER an inbound request."""

    def __init__(self, me: crypto.Keypair, postman: Postman, ttl: Millis) -> None:
        self.me = me
        self.postman = postman
        self.ttl = ttl

    def send(self, to: crypto.PublicKey, msg: SyncMsg, now: Millis, *, await_reply: bool) -> None:
        """Post one directed envelope. `HeightAsk` and `GetBlock` are the request half
        (await_reply=True so the mailbox correlates the answer); `HeightReply`,
        `SettledBlockReply`, `Refused` are the answer half (await_reply=False)."""
        verb, body = msg.encode()
        env = Envelope(to, verb, new_message_id(), body).sign(self.me, now)
        self.postman.mailbox.post(env, now, self.ttl, await_reply=await_reply)

    def reply(self, to: SignedEnvelope, msg: SyncMsg, now: Millis) -> None:
        """Answer an inbound request. `answer` produces an Envelope whose `reply_to` echoes
        the original's MessageId -- what the requester's mailbox uses to correlate."""
        verb, body = msg.encode()
        self.postman.mailbox.post(
            to.answer(verb, body).sign(self.me, now), now, self.ttl, await_reply=False
        )


__all__ = [
    "GetBlock",
    "HeightAsk",
    "HeightReply",
    "Refused",
    "SettledBlockReply",
    "SyncAdapter",
    "SyncAdapterError",
    "SyncMsg",
    "SyncRefusal",
]
