# dude.settle_round — the settlement protocol as a sans-I/O state machine. See SPECv2 anchors
# ratified-is-not-settled, settlement-signs-post-anchors, settlement-quorum-on-anchors.
#
# WHAT ONE SETTLE-ROUND DOES. Handles one ratified Block. Given the Coordinator's locally-
# computed post-apply anchors, immediately signs them and emits a SettleSig for peers. Collects
# peer SettleSigs; when a quorum of matching sigs converges, transitions to SETTLED and produces
# a SettledBlock the Coordinator commits.
#
# WHAT IT DOES NOT DO. Compute anchors (that is the Coordinator's Layer projection). Touch the
# Store. Do wire encoding (that is `dude.net.settle_adapter`). Time out (indefinite hang is
# noted in SPECv2 anchor settlement-may-hang and deferred).
#
# WHY IT LOOKS LIKE ROUND BUT SMALLER. Round has three phases (COLLECT holdings, FINALIZE via
# meta-agreement, GONE) because it discovers which slice to ratify. SettleRound has the ratified
# slice as input -- everyone already knows what they are signing -- so it is one phase of
# signature collection. Two states: COLLECTING -> SETTLED. GONE is not modelled; the Coordinator
# drops the SettleRound when SETTLED, and a hang leaves it COLLECTING indefinitely.
#
# DIVERGENCE IS ROUTINE, NOT INVARIANT. A peer SettleSig with anchors that do not match ours is
# dropped from quorum counting and recorded as evidence via `divergences()`. It is NEVER cause
# to raise or terminate the process: byzantine peers exist, buggy peers exist, and the two are
# operationally indistinguishable from the receiver's perspective. If enough peers disagree with
# us that we cannot reach a quorum, we simply do not settle this block on this node -- the honest
# quorum may have formed around anchors matching among themselves without us (fine, we fall
# behind and re-sync), or nobody has formed one at all (the hang case). Neither warrants a
# self-crash. See CLAUDE.md trap #3.

from __future__ import annotations

from collections.abc import Iterable
from dataclasses import dataclass
from enum import Enum, auto
from typing import ClassVar

from .. import quorum
from ..core import codec, crypto
from ..core.errors import DudeError
from ..core.units import Millis
from ..net.envelope import Verb
from ..net.postman import Recipient, Target
from ..store.layer import Index
from ..store.ops import SignedTransaction
from .round import Block


class SettleAdapterError(DudeError):
    """A wire message that names SETTLE_SIG but is not one -- malformed body, wrong shape.

    Not for a `SettleSig` whose signature does not verify (that is SettleRound's own concern),
    and not for a foreign-slice sig (SettleRound drops those silently). For messages that could
    not have come from an honest peer using the same protocol at all."""


_ANCHORS_DOMAIN = b"dude.settle_round.anchors"


class SettleError(DudeError):
    """A misuse of the SettleRound API: called out of order, contradictory input. Not for peer
    misbehaviour -- that is a silent drop. Not for internal postcondition violation -- that is
    `InvariantError`, and this module raises it only if the Coordinator hands us anchors whose
    payload cannot be constructed at all (impossible in practice)."""


@dataclass(frozen=True, slots=True)
class Anchors:
    """The post-apply commitments a SettleRound signs and quorum-agrees on
    (SPECv2 #settlement-signs-post-anchors).

    `block_num` is the MONOTONE block counter: increments by one per SETTLED block regardless of
    whether the block committed any transactions. This is what a `GETBLOCK n` request names and
    what the chain is indexed by. Empty ratifications (#empty-bucket-still-settles) still get a
    distinct block_num, so chain-continuity holds even across empties.

    `height` is the log `Index` of the last transaction this block committed. Same underlying
    type as `store.head` and `Entry.idx`. Distinct from `block_num`: an empty block has
    `height == prev_block.height` (no txs committed), but `block_num == prev.block_num + 1`.
    Both are signed so a joiner can verify chain position (block_num) and log alignment
    (height) independently.

    `prev_block` is `H(prev_settled_block.encode())` -- the chain link (#block-shape-settled,
    #genesis-stamp-anchors-the-chain). At `block_num == 1`, this is the genesis stamp
    `H("dude.genesis:" || manager_pubkey)`, computable by anyone holding the manager pubkey. The
    settlement signature covers `prev_block`, so a peer cannot lie about which chain their block
    belongs to without invalidating the sig.

    All six fields are what a replayer or a light client checks against. Equal `Anchors` between
    two nodes at the same slice means byte-identical post-apply state; anything else is a
    divergence."""

    block_num: Index
    height: Index
    prev_block: crypto.Digest
    state_root: crypto.Digest
    acc_state: crypto.Accumulator
    acc_log: crypto.Accumulator


@dataclass(frozen=True, slots=True)
class SettleSig:
    """A peer's signed statement that they computed these `anchors` after applying the block
    with `slice_hash`. Constructed via `SettleSig.sign(kp, slice_hash, anchors)`; verified via
    `msg.verify(pk)`.

    `slice_hash` is `block.slice_hash`, exactly as Round computes it, so the sig binds this
    signature to the ratified block and cannot be replayed against any other slice or bucket.
    Domain-tagged so a SettleSig cannot be replayed as a Round Sig or vice versa; slice-bound so
    it cannot be replayed across blocks; anchors-bound so a peer changing its mind about the
    outcome is detectable rather than silent."""

    verb: ClassVar[Verb] = Verb.SETTLE_SIG
    """Wire tag for this message type. Same shape as `SyncMsg.verb`, `RoundMsg.verb`; there is
    only one SettleRound message so no dispatch table is needed, but the attribute is present
    so `msg.verb` is a legal query regardless of protocol."""

    slice_hash: crypto.Digest
    anchors: Anchors
    sig: crypto.Signature

    @classmethod
    def sign(cls, kp: crypto.Keypair, slice_hash: crypto.Digest, anchors: Anchors) -> SettleSig:
        """Build a SettleSig for `(slice_hash, anchors)` signed by `kp`."""
        return cls(slice_hash, anchors, kp.sign(_settle_payload(slice_hash, anchors)))

    def verify(self, pk: crypto.PublicKey) -> bool:
        """True if this SettleSig's signature is a valid signature by `pk` over what it claims to
        cover. The caller decides what to do with a False -- SettleRound drops, tests assert."""
        return pk.verify(_settle_payload(self.slice_hash, self.anchors), self.sig)

    def _encode(self) -> bytes:
        """The BODY bytes for this message. slice_hash comes first so `SettleSig.slice_hash_of`
        reads only that field to route the message without a full decode."""
        a = self.anchors
        return codec.encode(
            [
                self.slice_hash,
                a.block_num,
                a.height,
                a.prev_block,
                a.state_root,
                a.acc_state,
                a.acc_log,
                self.sig,
            ]
        )

    def encode(self) -> tuple[Verb, bytes]:
        """The wire form of this message: `(verb, body_bytes)`."""
        return self.verb, self._encode()

    @classmethod
    def decode(cls, verb: Verb, body: bytes) -> SettleSig:
        """The inverse of `encode`. Raises `SettleAdapterError` on the wrong verb or a malformed
        body; the caller sits inside a crash-only boundary that catches `DudeError`."""
        if verb is not cls.verb:
            raise SettleAdapterError(f"not a SettleRound verb: {verb.name}")
        try:
            p = codec.as_seq(codec.decode(body), 8)
            return cls(
                slice_hash=crypto.Digest(codec.as_bytes(p[0])),
                anchors=Anchors(
                    block_num=codec.as_int(p[1]),
                    height=codec.as_int(p[2]),
                    prev_block=crypto.Digest(codec.as_bytes(p[3])),
                    state_root=crypto.Digest(codec.as_bytes(p[4])),
                    acc_state=crypto.Accumulator(codec.as_bytes(p[5])),
                    acc_log=crypto.Accumulator(codec.as_bytes(p[6])),
                ),
                sig=crypto.Signature(codec.as_bytes(p[7])),
            )
        except DudeError as e:
            raise SettleAdapterError(f"malformed SETTLE_SIG body: {e}") from e

    @classmethod
    def slice_hash_of(cls, body: bytes) -> crypto.Digest:
        """The slice_hash named in a SETTLE_SIG body, extracted without fully decoding. Used by
        the Coordinator to route the message to the right SettleRound instance before full
        validation."""
        try:
            p = codec.as_seq(codec.decode(body))
            return crypto.Digest(codec.as_bytes(p[0]))
        except DudeError as e:
            raise SettleAdapterError(f"cannot read slice_hash from body: {e}") from e


def _settle_payload(slice_hash: crypto.Digest, anchors: Anchors) -> bytes:
    """The bytes a SettleSig's signature covers. Shared between `sign` (before the message
    exists) and `verify` (after) so the shape lives in exactly one place."""
    return codec.encode(
        [
            _ANCHORS_DOMAIN,
            slice_hash,
            anchors.block_num,
            anchors.height,
            anchors.prev_block,
            anchors.state_root,
            anchors.acc_state,
            anchors.acc_log,
        ]
    )


@dataclass(frozen=True, slots=True)
class SettledBlock:
    """The block that has SETTLED: a ratified slice plus a quorum's agreed-upon post-apply
    anchors and the signatures over them.

    Persists as the record of "the cluster applied this slice at this height and agreed on these
    roots." A replayer receiving this block verifies the settle_sigs against the roster at
    `height` (#roster-at-ratification) and, on a fresh apply of the same slice, reproduces the
    same anchors -- else divergence.

    RATIFY SIGS ARE NOT ENCODED. Per #block-shape-settled, "what proves the block to a replayer
    is the settle_sigs alone: a quorum agreed on the outcome, and `slice_hash` inside that
    payload pins which slice they were agreeing about." Round's `signers`/`sigs` on the wrapped
    `Block` are transient consensus infrastructure -- the record of HOW the quorum agreed on the
    slice, not the record THAT they did. `encode()` therefore omits them; `decode()` returns a
    SettledBlock whose wrapped Block has empty ratify credentials."""

    block: Block
    anchors: Anchors
    signers: crypto.SignerBitmap
    settle_sigs: tuple[crypto.Signature, ...]

    @property
    def block_hash(self) -> crypto.Digest:
        """Chain identity -- `H(identity_bytes)`, over the block's slice + anchors + block_num.
        A successor's `Anchors.prev_block` names THIS.

        SIG-INDEPENDENT. The signer bitmap and `settle_sigs` are a QUORUM PROOF, variable per
        node: any quorum-sized subset of matching sigs is a valid proof, and which subset a node
        holds at the moment `_try_settle` fires depends on message-arrival timing. Two nodes with
        the same slice + same anchors MUST compute the same `block_hash` regardless of which
        subset of sigs they persist -- else `prev_block` diverges per node and the chain forks.
        (Discovered while implementing L5 close-out: nodes' `encode()` bytes differed because of
        this exact race, breaking chain agreement.)"""
        return crypto.h(self._identity_bytes())

    def _identity_bytes(self) -> bytes:
        """The chain-identity portion of the block: slice + anchors, no sigs. Hashed for
        `block_hash`; embedded verbatim in `encode` so a joiner receives both identity and
        proof without re-hashing to know which was signed."""
        return codec.encode(
            [
                self.block.bucket,
                sorted(self.block.hashes),
                self.anchors.block_num,
                self.anchors.height,
                self.anchors.prev_block,
                self.anchors.state_root,
                self.anchors.acc_state,
                self.anchors.acc_log,
            ]
        )

    def encode(self) -> bytes:
        """Wire form (#block-shape-settled). What a peer sends on `SETTLED_BLOCK`, what a
        producer persists on SETTLED. Layout: `[identity_bytes, signers, settle_sigs]` -- the
        identity portion comes first because chain-verify hashes only it (`block_hash`), and a
        joiner can peek without re-decoding the sig section."""
        return codec.encode(
            [
                self._identity_bytes(),
                self.signers,
                list(self.settle_sigs),
            ]
        )

    @classmethod
    def decode(cls, raw: bytes) -> SettledBlock:
        """The inverse of `encode`. Raises `SettleError` on malformed bytes."""
        try:
            outer = codec.as_seq(codec.decode(raw), 3)
            identity = codec.as_seq(codec.decode(codec.as_bytes(outer[0])), 8)
            bucket = codec.as_int(identity[0])
            hashes = tuple(crypto.Digest(codec.as_bytes(h)) for h in codec.as_seq(identity[1]))
            anchors = Anchors(
                block_num=codec.as_int(identity[2]),
                height=codec.as_int(identity[3]),
                prev_block=crypto.Digest(codec.as_bytes(identity[4])),
                state_root=crypto.Digest(codec.as_bytes(identity[5])),
                acc_state=crypto.Accumulator(codec.as_bytes(identity[6])),
                acc_log=crypto.Accumulator(codec.as_bytes(identity[7])),
            )
            signers = crypto.SignerBitmap(codec.as_bytes(outer[1]))
            settle_sigs = tuple(crypto.Signature(codec.as_bytes(s)) for s in codec.as_seq(outer[2]))
        except DudeError as e:
            raise SettleError(f"malformed SettledBlock: {e}") from e
        # Ratify sigs are not on the wire -- reconstruct a Block with empty ratify credentials.
        # A replayer needs `bucket` and `hashes` for `slice_hash` and for applying the slice;
        # the ratify sigs were Round's transient consensus record and never persist.
        block = Block(
            bucket=bucket,
            hashes=hashes,
            signers=crypto.SignerBitmap(b""),
            sigs=(),
        )
        return cls(block=block, anchors=anchors, signers=signers, settle_sigs=settle_sigs)


@dataclass(frozen=True, slots=True)
class SettledBlockWithBodies:
    """A SettledBlock plus the tx bodies needed to replay it -- the wire form a joiner receives
    on `SETTLED_BLOCK` and what a replayer needs to actually apply the block.

    TWO-TYPE SPLIT (#block-shape-settled): `SettledBlock` alone is identity + proof (persists,
    chains, verifies). `SettledBlockWithBodies` is identity + proof + payload (transmits,
    replays). Kept as separate types so the CHAIN concern (block_hash, prev_block linking) never
    accidentally depends on the PAYLOAD concern (which txs make it up) -- their shapes differ,
    their durability differs (proof persists in the block table; bodies come from the entry
    table), and conflating them was the source of the sig-inclusion race Stage 1 caught.

    `bodies` correspond to the APPLIED set on the producer -- the subset of `block.hashes` that
    actually made it through the evaluator (some may have fallen through per
    #fall-through-through-the-door). A joiner verifies bodies re-apply cleanly against its own
    state at that height, produces matching anchors, and only then commits."""

    block: SettledBlock
    bodies: tuple[SignedTransaction, ...]

    def encode(self) -> bytes:
        """Wire form: `[SettledBlock.encode(), [tx.raw, ...]]`. The block-bytes come first so a
        peer serving `SETTLED_BLOCK` can pass `store.settled_at(n)` through verbatim without
        re-serialising the identity/proof portion."""
        return codec.encode(
            [
                self.block.encode(),
                [tx.raw for tx in self.bodies],
            ]
        )

    @classmethod
    def decode(cls, raw: bytes) -> SettledBlockWithBodies:
        """The inverse of `encode`. Raises `SettleError` on malformed bytes."""
        try:
            p = codec.as_seq(codec.decode(raw), 2)
            block = SettledBlock.decode(codec.as_bytes(p[0]))
            bodies = tuple(SignedTransaction.decode(codec.as_bytes(b)) for b in codec.as_seq(p[1]))
        except DudeError as e:
            raise SettleError(f"malformed SettledBlockWithBodies: {e}") from e
        return cls(block=block, bodies=bodies)


_GENESIS_DOMAIN = b"dude.genesis:"


def genesis_stamp(manager: crypto.PublicKey) -> crypto.Digest:
    """The `prev_block` value for the SettledBlock at height 1 (#genesis-stamp-anchors-the-chain).
    A joiner starting from the out-of-band manager pubkey computes this locally; every node
    producing block 1 computes the same thing from its own `store.anchor()`. Two clusters started
    from different manager keys have byte-different genesis stamps by construction, so a block
    from cluster A cannot chain-verify against cluster B's history."""
    return crypto.h(_GENESIS_DOMAIN + bytes(manager))


class SettleState(Enum):
    """Two states, one direction (#ratified-is-not-settled).

    Ordinal 0 is INVALID by convention (#no-exceptions-for-control-flow), so a Go port's
    zero-valued struct field lands on a named invalid rather than on a real state."""

    INVALID = 0
    COLLECTING = auto()
    """Awaiting peer SettleSigs. Own sig is already in the outbox."""
    SETTLED = auto()
    """A quorum of matching sigs converged; `settled()` returns the SettledBlock."""


class SettleRound:
    """One block's settlement. Constructed after Round ratifies, when the Coordinator has
    computed post-apply anchors from a Layer over Store.

    Emits our own SettleSig on construction. Handles incoming SettleSigs via `receive`. On
    convergence transitions to SETTLED; `settled()` yields the block for the Coordinator to
    commit."""

    def __init__(
        self,
        block: Block,
        me: crypto.Keypair,
        roster: tuple[crypto.PublicKey, ...],
        anchors: Anchors,
        now: Millis,  # noqa: ARG002 -- reserved for hang-detection when #settlement-may-hang lands
    ):
        if me.public not in roster:
            raise SettleError(f"me ({me.public.hex()[:8]}) is not in the roster")
        self._block = block
        self._me = me
        self._roster = roster
        self._quorum = quorum.size(len(roster))
        self._anchors = anchors
        self._slice_hash = block.slice_hash
        # Pre-verified sigs, keyed by signer. Only sigs whose anchors match ours land here.
        self._sigs: dict[crypto.PublicKey, crypto.Signature] = {}
        # Peer sigs whose anchors did NOT match. Kept for observability, never counted.
        self._divergences: list[tuple[crypto.PublicKey, Anchors]] = []
        self._outbox: list[tuple[Target, SettleSig]] = []
        self._state = SettleState.COLLECTING
        self._settled: SettledBlock | None = None

        # Sign our own anchors immediately and broadcast.
        my_msg = SettleSig.sign(me, self._slice_hash, anchors)
        self._sigs[me.public] = my_msg.sig
        self._outbox.append((Recipient.ALL, my_msg))
        self._try_settle()

    # -- inbound ----------------------------------------------------------------------------- #

    def receive(self, msg: SettleSig, from_: crypto.PublicKey, now: Millis) -> None:  # noqa: ARG002 -- `now` reserved
        """Consume one peer's SettleSig for this block.

        Verifies the signature, checks the slice binding, and either counts the sig toward the
        quorum (anchors match ours) or records it as a divergence (they do not). Divergent sigs
        are silently dropped from quorum counting; they never raise, never terminate, and never
        block progress. A peer signing under someone else's key, or over a different slice, is
        the same shape -- drop.

        DIVERGENCE RECORDING SURVIVES SETTLED. Same principle as Round's
        #evidence-outlives-ratification: a peer whose signed anchors differ from ours is
        evidence about that peer, and that evidence is worth preserving even if we have already
        moved on. Only the quorum-counting side is gated on state -- once SETTLED, further
        matching sigs are ignored (nothing to add) but divergent ones are still recorded."""
        if from_ not in self._roster:
            return  # not our concern
        if from_ == self._me.public:
            return  # our own sig already counted
        if msg.slice_hash != self._slice_hash:
            return  # wrong block
        if not msg.verify(from_):
            return  # invalid signature; drop
        if msg.anchors != self._anchors:
            # Divergence: peer computed different anchors from the same slice. Their bug, their
            # malice, or ours -- we cannot tell locally, and the only safe action is to drop
            # the sig from quorum counting. Recorded as evidence regardless of our own state,
            # per SPECv2 #settlement-quorum-on-anchors and #evidence-outlives-ratification.
            self._divergences.append((from_, msg.anchors))
            return
        if self._state is not SettleState.COLLECTING:
            return  # matching sig arrived after SETTLED; nothing to add
        # Match: count toward quorum.
        self._sigs[from_] = msg.sig
        self._try_settle()

    # -- outbound ---------------------------------------------------------------------------- #

    def outbox(self) -> Iterable[tuple[Target, SettleSig]]:
        """Drain queued outbound messages. Called by the Coordinator after each tick / receive."""
        drained = tuple(self._outbox)
        self._outbox.clear()
        return drained

    def tick(self, _now: Millis) -> None:
        """No-op today. Hang detection lands with #settlement-may-hang."""

    # -- terminal ---------------------------------------------------------------------------- #

    def state(self) -> SettleState:
        return self._state

    def settled(self) -> SettledBlock | None:
        """The settled block once a quorum has converged, else None."""
        return self._settled

    def divergences(self) -> tuple[tuple[crypto.PublicKey, Anchors], ...]:
        """Peer SettleSigs whose anchors disagreed with ours. Evidence for the observability
        layer to act on; empty tuple in the honest case (SPECv2 #settlement-quorum-on-anchors)."""
        return tuple(self._divergences)

    # -- internal ---------------------------------------------------------------------------- #

    def _try_settle(self) -> None:
        if self._state is not SettleState.COLLECTING:
            return
        if len(self._sigs) < self._quorum:
            return
        # Ratified. Build the SettledBlock with a bitmap of signers plus a reserved manager slot
        # at position `len(roster)` (#manager-sig-overrides-quorum). The manager bit stays 0 in
        # the ordinary quorum path -- bootstrap and emergency-intervention blocks set it via
        # `SettledBlock.sign_by_manager` instead. Sig list is parallel to set bits, same as
        # Round's Block (SPECv2 #ratification-counts).
        n = len(self._roster) + 1  # +1 for the manager override slot
        shares = {i: self._sigs[m] for i, m in enumerate(self._roster) if m in self._sigs}
        signers, sigs = crypto.Ed25519ListMultiSig.combine(shares, n)
        self._settled = SettledBlock(
            block=self._block,
            anchors=self._anchors,
            signers=signers,
            settle_sigs=tuple(sigs),
        )
        self._state = SettleState.SETTLED
