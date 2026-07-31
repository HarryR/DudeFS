# dude.net.envelope — point-to-point message framing. See SPEC.md (#sign-then-seal).
#
# THREE LAYERS, and keeping them apart is the whole design [H]:
#
#   inner     a signed transaction (or any authenticated artifact). Authenticates its AUTHOR.
#             DISTRIBUTABLE — anyone may forward it, anyone may verify it.
#   envelope  "this node (me) sends a message to that node (you), with a distinct message id."
#             Authenticates the SENDER of this hop. NOT distributable: it is a conversation
#             artifact, and forwarding its contents means RE-ENVELOPING them.
#   sealing   transport confidentiality, and literally nothing else. Authenticates nobody.
#
# The envelope DOES NOT KNOW what it carries. `body` is opaque bytes here. A client submitting a
# transaction signs the transaction, then signs the envelope that submits it — two signatures at two
# layers answering two different questions, which is why the request gate authorises the envelope's
# `frm` (the requester) and NEVER the artifact's author.
#
# THE TIMESTAMP IS GATED, AND THAT IS ITS PURPOSE [H]. Not a pre-signature DoS rung — that argument
# fails, since an unauthenticated `ts` is forgeable and an authenticated one is read after the
# crypto is already paid for. It is a PARTICIPATION gate: a node whose clock is outside the window
# literally cannot hold a conversation, and because both ends check, it self-partitions
# symmetrically. The door closes on defect. No accommodation exists for a broken clock, by decision
# -- see #timing.
#
# SIGN-THEN-SEAL, never the reverse: sealing after signing means an observer sees no identity at
# all. Signing a ciphertext would leave the sender's key in the clear and leak the social graph.

from __future__ import annotations

from dataclasses import dataclass
from enum import IntEnum
from typing import Self

from ..core import codec, crypto
from ..core.errors import DudeError


class EnvelopeError(DudeError):
    """A frame that is malformed, misaddressed, stale, or not signed by whom it claims."""


class Verb(IntEnum):
    """What this message ASKS FOR — a closed enumeration, and one of exactly two in the protocol.

    THE OTHER ONE IS NOT THIS ONE. Operation kinds (what an identity may *author* into the log,
    `management.Grant.kinds`) are a different axis from request verbs (what an identity may *ask a
    node to do*). They live at different layers, are gated by different signatures, and conflating
    them would let "may write the data store" imply "may demand a state transfer". Two enumerations,
    deliberately **[H]**.

    Closed rather than an open byte string for three reasons: the request gate must be able to
    enumerate its domain to be auditable; a Rust or Go port gets exhaustive matching instead of a
    default branch, and default branches are where two implementations quietly diverge; and it is a
    small int on every message.

    ADDING A VERB COSTS A CODE CHANGE AND NOTHING ELSE, at present `[H]`: *"there are no versions
    yet, this is version -1."* There is no deployed peer to stay compatible with, so a new verb is
    not a migration and needs no ceremony. Once there is one it becomes a version bump, which for a
    permissioned system with a key-issuing manager is the correct cost — but pricing that in now
    buys nothing, and has already made one decision look more expensive than it was.

    The SHAPE still deserves care, for the reason above rather than for compatibility: a verb is a
    closed enumeration two implementations must agree on exhaustively."""

    # -- liveness ------------------------------------------------------------------------------- #
    PING = 1
    PONG = 2

    # -- mempool dissemination (#mempool) -------------------------------------------------- #
    SUBMIT = 10
    """A client offers a transaction. The only verb a client needs to write."""
    ANNOUNCE = 11
    """"I hold these transaction ids for this bucket", plus the bucket accumulator."""
    FETCH = 12
    """"Send me these bodies." The pull half of pull-not-push."""
    BODIES = 13

    # -- slice agreement (#buckets) -------------------------------------------------------- #
    PROPOSE = 20
    ENDORSE = 21
    HELD = 22
    """"I hold these transaction hashes for this bucket" -- Round's advertisement (SPECv2
    #gossip-by-hash). The Round protocol's own vocabulary, distinct from `SUBMIT`'s "here is a
    body for you to admit"."""
    SIG = 23
    """A signature over the slice this node believes this bucket ratifies -- Round's second
    message (SPECv2 #slice-meta-agreement). A quorum of matching `SIG`s is what turns a
    candidate slice into a ratified block."""

    # -- collection (#collection-is-driven-by-any-node) ----------------------------------------- #
    COLLECT = 40
    """"Segment S is collectable, and the fold after collecting is X." Any node may say it."""
    RATIFY = 41
    """A signature over that claim, from a node that recomputed the fold and agrees."""

    # -- log transfer (#replication) -------------------------------------------------------- #
    FRONTIER = 30
    """"Where are you now?" Carries nothing: the question has no parameters."""
    STANDING = 33
    """The answer — own attestation, plus the latest heard of every peer (#cross-attestation).
    A reply that DOES need a handler, unlike those in `REPLIES`: the sightings it carries are the
    evidence channel, so dropping it on the floor would discard the whole point of asking."""
    PULL = 31
    ENTRIES = 32

    # -- diagnostics ---------------------------------------------------------------------------- #
    REFUSED = 90
    """A refusal, carrying a reason. Never silence: a client can only correct a clock fault if it is
    told which way it is wrong (#mempool)."""


type MessageId = bytes
MESSAGE_ID_SIZE = 16


def new_message_id() -> MessageId:
    """A fresh correlation id.

    THIS EXISTS FOR A BUG, not for tidiness. Without a request-response binding there is no
    relationship between an answer and the question it claims to answer, which is message-order
    malleability: an attacker reorders replies and a client attributes one request's answer to
    another. A reply MUST echo the id it answers."""
    return crypto.random_bytes(MESSAGE_ID_SIZE)


@dataclass(frozen=True, slots=True)
class Envelope:
    """What the author DECIDED, before anyone signed it. No `frm`, and no `ts`.

    Those two live on `SignedEnvelope`, because authorship and time arrive WITH the signature. Not
    tidiness: while `frm` sat here, an envelope could be attributed to anyone and `sign()` had to
    check the attribution matched the key, raising if not. The check is gone because the state it
    guarded is gone — you cannot claim to be someone else if there is nowhere to write the claim.
    `Transaction` / `SignedTransaction` in `dude.store.ops` is the same split; this now matches it.

    POINT-TO-POINT, always. There is no broadcast address and no multicast form, because the
    carrier may be broadcast while the *message* never is — a transport that reaches many is still
    delivering a message to one named recipient (#transport-adds-no-trust). `to` is that
    recipient's identity."""

    to: crypto.PublicKey
    verb: Verb
    mid: MessageId
    body: bytes = b""
    """Opaque. This layer never parses it: it may hold a signed transaction, a batch of ids, or
    nothing. Keeping it opaque is what stops carrier vocabulary leaking into the log."""

    reply_to: MessageId = b""
    """The id this answers, empty for a request. A reply that fails to echo is not a reply."""

    reply_ts: int = 0
    """The `ts` of the ATTEMPT this answers — TCP's Timestamps option (RFC 7323) in one field.

    Without it, Karn's rule (#rtt-attribution) discards the RTT sample from anything sent more than
    once,
    which under multi-homing is most traffic: a reply arriving after attempts on two links tells you
    nothing about either. Echoing the attempt's `ts` matches the reply to exactly ONE transmission,
    and since each attempt went out on a known link, that recovers **both** the sample and the link.

    So this is what stops R7 being a measurement blind spot — without it, the more paths you use the
    less you know about any of them.

    Note it lives HERE and not in the header: a value the author chose to carry, an echo of the
    other party's stamp, not a claim about this hop."""

    def encode(self) -> bytes:
        """The envelope proper, as it appears inside the signed body."""
        return codec.encode(
            [self.to, int(self.verb), self.mid, self.body, self.reply_to, self.reply_ts]
        )

    @classmethod
    def decode(cls, raw: bytes) -> Envelope:
        f = codec.as_seq(codec.decode(raw), 6)
        try:
            verb = Verb(codec.as_int(f[1]))
        except ValueError as exc:
            raise EnvelopeError(f"unknown verb {codec.as_int(f[1])}") from exc
        return cls(
            crypto.PublicKey(codec.as_bytes(f[0])),
            verb,
            codec.as_bytes(f[2]),
            codec.as_bytes(f[3]),
            codec.as_bytes(f[4]),
            codec.as_int(f[5]),
        )

    def sign(self, kp: crypto.Keypair, ts: int) -> SignedEnvelope:
        """Author this envelope, now. Authorship and time arrive together, so there is no window in
        which an envelope has one but not the other.

        A RETRANSMIT IS A NEW MESSAGE: sign the same envelope again with a later `ts` and the frame
        is freshly stamped and freshly signed. That is why the conversation window need never
        stretch to cover retries — and why each attempt carries a DISTINCT `ts`, which is exactly
        what lets a reply's `reply_ts` name one of them. It also replaces the old `at()`, which
        existed only because `ts` used to sit on the unsigned half."""
        return SignedEnvelope(kp.public, ts, self, kp.sign(_body(kp.public, ts, self)))


def _body(frm: crypto.PublicKey, ts: int, env: Envelope) -> bytes:
    """The canonical bytes a sender signs. Mirrors `ops._body(author, ts, steps)` deliberately.

    NESTED, so the two levels are visible on the wire as well as in the types: the header is this
    hop's claim, the inner list is the envelope the author decided.

    Everything here is signed, and that is load-bearing. `to` under the signature stops a valid
    envelope being lifted and re-delivered to a different recipient, who would otherwise see a
    correctly-signed message never addressed to them; the same argument covers `verb` and
    `reply_to` — anything an unsigned copy would let an attacker change for free."""
    return codec.encode([frm, ts, env.encode()])


@dataclass(frozen=True, slots=True)
class SignedEnvelope:
    """The authenticated header — who sent this hop, when — plus the envelope it carries.

    A separate type from `Envelope` so that "maybe signed" is not an ambiguous `None`, the same
    reason `SignedTransaction` is distinct. `frm` and `ts` live here rather than on `Envelope`
    because they are claims this signature makes; an unsigned envelope has no author and no time."""

    frm: crypto.PublicKey
    ts: int
    env: Envelope
    sig: crypto.Signature

    @property
    def raw(self) -> bytes:
        return codec.encode([_body(self.frm, self.ts, self.env), self.sig])

    def verify(self) -> bool:
        return self.frm.verify(_body(self.frm, self.ts, self.env), self.sig)

    def fresh(self, now: int, window: int) -> bool:
        """Is this envelope inside the conversation window?

        Measures *"are we in sync right now"*, not *"how old is the content"* — the stamp is fresh
        per message, so this window is tight while a transaction's admission window is loose. The
        two are independent, and neither substitutes for the other."""
        return abs(now - self.ts) <= window

    def answer(self, verb: Verb, body: bytes = b"") -> Envelope:
        """The reply to this message: addresses reverse, `reply_to` and `reply_ts` echo.

        Lives on the SIGNED half because it needs both — `frm` to address the reply back, and `ts`
        for the echo — and both are claims of this hop. Returns an unsigned `Envelope`, so the
        reply's own time arrives when the caller signs it. There is no `ts` to inherit or forget,
        which is what retires the zero-sentinel trap the old version needed."""
        return Envelope(self.frm, verb, new_message_id(), body, self.env.mid, self.ts)

    def accept(
        self, me: crypto.PublicKey, now: int, window: int, in_reply_to: MessageId | None = None
    ) -> None:
        """Every check a receiver owes, in one place, raising on the first failure.

        ORDER IS DELIBERATE — addressing and freshness before the signature, so a misdelivered or
        stale frame costs no verification. That is not the argument *for* the timestamp (see the
        module header) but it is a free consequence of having it.

        A caller that wants only some of these should not exist: forgetting one is precisely how the
        previous package shipped an unbound request id."""
        if self.env.to != me:
            raise EnvelopeError(f"addressed to {self.env.to.hex()[:8]}, not us")
        if not self.fresh(now, window):
            raise EnvelopeError(
                f"outside the {window}ms conversation window (ts={self.ts}, now={now})"
            )
        if not self.verify():
            raise EnvelopeError(f"signature does not match sender {self.frm.hex()[:8]}")
        if in_reply_to is not None and self.env.reply_to != in_reply_to:
            raise EnvelopeError("reply does not echo the request id it claims to answer")

    @classmethod
    def decode(cls, raw: bytes) -> Self:
        """Decode and TYPE-CHECK. Signature verification is the caller's, via `accept`: a malformed
        frame and a forged one are different failures."""
        outer = codec.as_seq(codec.decode(raw), 2)
        f = codec.as_seq(codec.decode(codec.as_bytes(outer[0])), 3)
        return cls(
            crypto.PublicKey(codec.as_bytes(f[0])),
            codec.as_int(f[1]),
            Envelope.decode(codec.as_bytes(f[2])),
            crypto.Signature(codec.as_bytes(outer[1])),
        )


def request(
    kp: crypto.Keypair, to: crypto.PublicKey, verb: Verb, ts: int, body: bytes = b""
) -> SignedEnvelope:
    """Author a request. The message id is generated here so it cannot be forgotten."""
    return Envelope(to, verb, new_message_id(), body).sign(kp, ts)


# --------------------------------------------------------------------------------------------- #
# Sealing — transport confidentiality, and nothing else.                                        #
# --------------------------------------------------------------------------------------------- #


@dataclass(frozen=True, slots=True)
class Frame:
    """What actually goes on the wire: a screen tag and a sealed envelope.

    The tag lets a recipient on a MULTIPLEXED carrier recognise its own traffic without trial
    decryption. It is `HMAC(key = destination identity, message = sealed bytes)` — and including the
    sealed bytes is essential, not incidental: keyed only on the identity it would be a constant,
    i.e. a permanent per-node fingerprint an observer could use to link every frame ever sent to
    that node. Per-message input makes it unlinkable to anyone without the key."""

    tag: crypto.ScreenTag
    sealed: crypto.SealedBlob

    @property
    def raw(self) -> bytes:
        return codec.encode([self.tag, self.sealed])

    @classmethod
    def decode(cls, raw: bytes) -> Self:
        f = codec.as_seq(codec.decode(raw), 2)
        return cls(crypto.ScreenTag(codec.as_bytes(f[0])), crypto.SealedBlob(codec.as_bytes(f[1])))

    def addressed_to(self, me: crypto.PublicKey) -> bool:
        """Cheap pre-filter on a shared carrier: recompute the tag and compare.

        A HINT, NEVER A DECISION. A match means the frame is probably ours; everything that matters
        is still established by `SignedEnvelope.accept` after unsealing. Using this to authorise
        anything would be trusting an unauthenticated field."""
        return crypto.screen_tag(me, self.sealed) == self.tag


def seal(env: SignedEnvelope) -> Frame:
    """Sign-then-seal (the envelope arrives already signed) and tag for the recipient.

    Note what is NOT here: no epoch, no version, no sender hint, no length prefix beyond the
    codec's. Every one of those would be an unauthenticated field outside the sealed box, and an
    unauthenticated field on the wire is either ignorable or forgeable."""
    sealed = env.env.to.seal(env.raw)
    return Frame(crypto.screen_tag(env.env.to, sealed), sealed)


def unseal(frame: Frame, kp: crypto.Keypair) -> SignedEnvelope:
    """Open a frame and decode the envelope inside. Verification is `accept`'s job.

    Raises `EnvelopeError` for a box that will not open — a frame not meant for us and a tampered
    one are indistinguishable by design in an anonymous sealed box, so they are one error."""
    try:
        raw = kp.open_sealed_raw(frame.sealed)
    except crypto.SealedBoxError as e:
        raise EnvelopeError("frame would not unseal (not ours, or tampered)") from e
    return SignedEnvelope.decode(raw)
