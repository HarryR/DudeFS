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

from .. import quorum
from ..core import codec, crypto
from ..core.errors import DudeError
from .round import Block, NodeId, Recipient, Target

type Height = int
type Millis = int

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

    `height` is the log position this block will occupy once SETTLED. Assigned by the
    Coordinator in block order (#pipelining), not derivable from the block itself -- so it lives
    here rather than on `Block`.

    All four fields are what a replayer or a light client checks against. Equal `Anchors` between
    two nodes at the same slice means byte-identical post-apply state; anything else is a
    divergence."""

    height: Height
    state_root: crypto.Digest
    acc_state: crypto.Accumulator
    acc_log: crypto.Accumulator


@dataclass(frozen=True, slots=True)
class SettleSig:
    """A peer's signed statement that they computed these `anchors` after applying the block
    with `slice_hash`. The signature covers `_payload(slice_hash, anchors)`.

    `slice_hash` is `dude.round._slice_id(bucket, hashes)`, exactly as Round computes it, so
    the sig binds this signature to the ratified block and cannot be replayed against any
    other slice or bucket."""

    slice_hash: crypto.Digest
    anchors: Anchors
    sig: crypto.Signature


type SettleMsg = SettleSig


@dataclass(frozen=True, slots=True)
class SettledBlock:
    """The block that has SETTLED: a ratified slice plus a quorum's agreed-upon post-apply
    anchors and the signatures over them.

    Persists as the record of "the cluster applied this slice at this height and agreed on these
    roots." A replayer receiving this block verifies the settle_sigs against the roster at
    `height` (#roster-at-ratification) and, on a fresh apply of the same slice, reproduces the
    same anchors -- else divergence."""

    block: Block
    anchors: Anchors
    signers: crypto.SignerBitmap
    settle_sigs: tuple[crypto.Signature, ...]


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
        roster: tuple[NodeId, ...],
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
        self._slice_hash = _slice_id_of(block)
        # Pre-verified sigs, keyed by signer. Only sigs whose anchors match ours land here.
        self._sigs: dict[NodeId, crypto.Signature] = {}
        # Peer sigs whose anchors did NOT match. Kept for observability, never counted.
        self._divergences: list[tuple[NodeId, Anchors]] = []
        self._outbox: list[tuple[Target, SettleMsg]] = []
        self._state = SettleState.COLLECTING
        self._settled: SettledBlock | None = None

        # Sign our own anchors immediately and broadcast.
        my_sig = me.sign(_payload(self._slice_hash, anchors))
        self._sigs[me.public] = my_sig
        self._outbox.append((Recipient.ALL, SettleSig(self._slice_hash, anchors, my_sig)))
        self._try_settle()

    # -- inbound ----------------------------------------------------------------------------- #

    def receive(self, msg: SettleSig, from_: NodeId, now: Millis) -> None:  # noqa: ARG002 -- `now` reserved
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
        payload = _payload(msg.slice_hash, msg.anchors)
        if not from_.verify(payload, msg.sig):
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

    def outbox(self) -> Iterable[tuple[Target, SettleMsg]]:
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

    def divergences(self) -> tuple[tuple[NodeId, Anchors], ...]:
        """Peer SettleSigs whose anchors disagreed with ours. Evidence for the observability
        layer to act on; empty tuple in the honest case (SPECv2 #settlement-quorum-on-anchors)."""
        return tuple(self._divergences)

    # -- internal ---------------------------------------------------------------------------- #

    def _try_settle(self) -> None:
        if self._state is not SettleState.COLLECTING:
            return
        if len(self._sigs) < self._quorum:
            return
        # Ratified. Build the SettledBlock with a roster-ordered bitmap of signers and their
        # parallel signatures -- the same shape as Round's Block (SPECv2 #ratification-counts).
        bits = bytearray(crypto.bitmap_size(len(self._roster)))
        sigs: list[crypto.Signature] = []
        for i, member in enumerate(self._roster):
            if member in self._sigs:
                bits[i // 8] |= 1 << (7 - i % 8)
                sigs.append(self._sigs[member])
        self._settled = SettledBlock(
            block=self._block,
            anchors=self._anchors,
            signers=crypto.SignerBitmap(bytes(bits)),
            settle_sigs=tuple(sigs),
        )
        self._state = SettleState.SETTLED


# ------------------------------------------------------------------------------------------- #
# Signature payload and slice-hash derivation                                                 #
# ------------------------------------------------------------------------------------------- #


def _payload(slice_hash: crypto.Digest, anchors: Anchors) -> bytes:
    """The bytes a peer signs to endorse post-apply anchors for a slice. Domain-tagged so a
    SettleSig cannot be replayed as a Round Sig or vice versa; slice-bound so it cannot be
    replayed across blocks; anchors-bound so a peer changing its mind about the outcome is
    detectable rather than silent."""
    return codec.encode(
        [
            _ANCHORS_DOMAIN,
            slice_hash,
            anchors.height,
            anchors.state_root,
            anchors.acc_state,
            anchors.acc_log,
        ]
    )


def _slice_id_of(block: Block) -> crypto.Digest:
    """The block's slice_hash, computed as `dude.round._slice_id(bucket, hashes)` would -- same
    domain, same shape, so SettleSig binds to exactly the identity Round's Sig ratified."""
    return crypto.h(codec.encode([block.bucket, list(block.hashes)]))
