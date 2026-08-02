# dude.round — the consensus protocol as a sans-I/O state machine. See SPECv2 (#round-lifecycle).
#
# WHAT ONE ROUND DOES. Handles one bucket. It takes what this node holds (from Mempool at bucket
# close), gossips with peers about what they hold, converges on the largest intersection over a
# quorum, and produces a Block when a quorum of peers sign the same slice. No sockets, no storage,
# no system clock -- `now` is a parameter, driven by tests or by the Coordinator.
#
# WHAT ROUND OWNS. Its own protocol messages (`Held`, `Sig`), its state machine, its ratification
# rule. The message set may grow to three during implementation if meta-agreement needs an
# observability step, or shrink if two suffice; any change is a proposal for SPECv2 (#mempool /
# L4) to ratify. What Round does NOT own: envelopes, seals, mailboxes, links, storage, the log,
# admission (Mempool), the wire encoding (`RoundAdapter`), and lifecycle across buckets
# (`Coordinator`).
#
# WHY THE INTERFACE IS HERE FIRST, WITH NO IMPLEMENTATION. The whole reason this module exists is
# that the previous round mechanism was placeholder code with a comment admitting it was
# placeholder. Writing the interface header first, with the tests driving the implementation into
# it, makes it obvious when a scenario reveals a gap -- rather than a comment claiming a gap.
# See `dude/tests/test_round.py`.

from __future__ import annotations

from abc import ABC, abstractmethod
from collections.abc import Callable, Iterable
from dataclasses import dataclass
from enum import Enum, auto
from itertools import combinations
from typing import ClassVar

from .. import quorum
from ..core import codec, crypto
from ..core.errors import DudeError
from ..core.units import Millis
from ..net.envelope import Verb
from ..net.postman import Recipient, Target
from .mempool import Bucket

_SLICE_DOMAIN = b"dude.round.slice"


class RoundError(DudeError):
    """A misuse of the Round API: called out of order, given contradictory input, or handed a
    clock that went backwards. Not for peer misbehaviour -- that is a silent drop with an `#XXX:`
    comment. Not for genuine invariant violation -- that is `InvariantError`, and Round has none
    at the moment because there is nothing here whose arithmetic could go wrong internally."""


# --------------------------------------------------------------------------------------------- #
# Protocol messages                                                                             #
#                                                                                                #
# Round OWNS these. They are the abstract shape the state machine operates on. Each subclass    #
# also carries its own wire encoding (`encode()` + classmethod `_decode(body)`); dispatch by     #
# verb is on the `RoundMsg` base via `RoundMsg.decode(verb, body)`. `RoundAdapter` is a thin    #
# Postman binding around those methods (see round_adapter.py).                                   #
# --------------------------------------------------------------------------------------------- #


class RoundAdapterError(DudeError):
    """A wire message that names a Round verb but is not one -- malformed body, wrong shape.

    Not for a `Sig` whose signature does not verify (that is Round's own concern, checked in
    `Round.receive`), and not for a foreign-bucket message (Round drops those silently). This is
    for messages that could not have come from an honest peer using the same protocol at all."""


class RoundMsg(ABC):
    """Base of Round's protocol vocabulary. Every subclass:

      * is a frozen dataclass whose leading field is `bucket: Bucket`;
      * declares `verb: ClassVar[Verb]` -- its wire tag;
      * implements `_encode(self) -> bytes` -- its body-only wire form;
      * implements classmethod `_decode(cls, body) -> Self` -- the body inverse;
      * appears in `_ROUND_MSG_CLASSES` so `_DECODERS` sees it.

    Instantiating `RoundMsg` directly is not meaningful -- `_encode` is abstract, so ABC guards
    that at construction time. Use `msg.encode()` for the wire form (bundles verb + body),
    `RoundMsg.decode(verb, body)` for inbound wire frames, and `RoundMsg.bucket_of(body)` for
    the "peek without full decode" the Coordinator needs to route to the right Round instance.
    """

    verb: ClassVar[Verb]
    """Wire tag for this message type. Each concrete subclass MUST assign a distinct `Verb`."""

    bucket: Bucket
    """Every Round message names its bucket in its FIRST wire field so `bucket_of` can read
    it without fully decoding. Enforced by convention (every subclass's `_encode` places bucket
    first) plus `bucket_of` reading only field zero."""

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
    def decode(cls, verb: Verb, body: bytes) -> RoundMsg:
        """The inverse of `encode`: given a wire verb + body, dispatch to the matching
        subclass's decoder. Raises `RoundAdapterError` on unknown verb or malformed body; the
        caller sits inside a crash-only boundary that catches `DudeError`."""
        try:
            handler = _DECODERS[verb]
        except KeyError as e:
            raise RoundAdapterError(f"not a Round verb: {verb.name}") from e
        return handler(body)

    @classmethod
    def bucket_of(cls, body: bytes) -> Bucket:
        """The bucket named in a Round-verb body, extracted without fully decoding. The `HELD`
        and `SIG` shapes both start with an int bucket. Used by the Coordinator to route the
        message to the right Round instance before doing full validation."""
        try:
            p = codec.as_seq(codec.decode(body))
            return codec.as_int(p[0])
        except DudeError as e:
            raise RoundAdapterError(f"cannot read bucket from body: {e}") from e


@dataclass(frozen=True, slots=True)
class Held(RoundMsg):
    """Advertisement: I hold these transaction hashes in my bucket for `bucket`.

    Encoding is per-hash for now; a future optimisation MAY compress via ECMH or set-reconciliation
    (minisketch), which is a wire concern that does not change Round's semantics.

    A node MAY re-advertise the same or a superset (holdings only grow within a round -- there is
    no `unheld`). Peers accumulate; the latest advertisement wins per (peer, bucket)."""

    verb: ClassVar[Verb] = Verb.HELD

    bucket: Bucket
    hashes: frozenset[crypto.Digest]

    def _encode(self) -> bytes:
        return codec.encode([self.bucket, sorted(self.hashes)])

    @classmethod
    def _decode(cls, body: bytes) -> Held:
        try:
            p = codec.as_seq(codec.decode(body), 2)
            hashes = frozenset(crypto.Digest(codec.as_bytes(h)) for h in codec.as_seq(p[1]))
            return cls(bucket=codec.as_int(p[0]), hashes=hashes)
        except DudeError as e:
            raise RoundAdapterError(f"malformed HELD body: {e}") from e


@dataclass(frozen=True, slots=True)
class Sig(RoundMsg):
    """My signature over the slice I believe this bucket ratifies. Constructed via
    `Sig.sign(kp, bucket, slice_hash)`; verified via `msg.verify(pk)`.

    `slice_hash` is `H(bucket, sorted_tuple_of_hashes)` -- exactly what would appear as the
    slice's identity on the wire. A peer holding the same set of `Held` messages computes the
    same `slice_hash` (#slice-is-intersection, #slice-tie-break). Once a quorum of `Sig` messages
    arrive for the same `slice_hash`, the Round is ratified (#slice-meta-agreement).

    Bucket-bound, so a signature over one bucket's slice cannot be replayed against another
    bucket."""

    verb: ClassVar[Verb] = Verb.SIG

    bucket: Bucket
    slice_hash: crypto.Digest
    sig: crypto.Signature

    @classmethod
    def sign(cls, kp: crypto.Keypair, bucket: Bucket, slice_hash: crypto.Digest) -> Sig:
        """Build a Sig over `(bucket, slice_hash)` signed by `kp`."""
        return cls(bucket, slice_hash, kp.sign(_sig_payload(bucket, slice_hash)))

    def verify(self, pk: crypto.PublicKey) -> bool:
        """True if this Sig's signature is a valid signature by `pk` over what it claims to
        cover. The caller decides what to do with a False -- Round drops, tests assert."""
        return pk.verify(_sig_payload(self.bucket, self.slice_hash), self.sig)

    def _encode(self) -> bytes:
        return codec.encode([self.bucket, self.slice_hash, self.sig])

    @classmethod
    def _decode(cls, body: bytes) -> Sig:
        try:
            p = codec.as_seq(codec.decode(body), 3)
            return cls(
                bucket=codec.as_int(p[0]),
                slice_hash=crypto.Digest(codec.as_bytes(p[1])),
                sig=crypto.Signature(codec.as_bytes(p[2])),
            )
        except DudeError as e:
            raise RoundAdapterError(f"malformed SIG body: {e}") from e


def _sig_payload(bucket: Bucket, slice_hash: crypto.Digest) -> bytes:
    """The bytes a Sig's signature covers. Shared between `sign` (before the message exists) and
    `verify` (after) so the shape lives in exactly one place."""
    return codec.encode([_SLICE_DOMAIN, bucket, slice_hash])


_ROUND_MSG_CLASSES: tuple[type[RoundMsg], ...] = (Held, Sig)
"""The closed set of Round message subclasses. `_DECODERS` is derived from this; adding a new
verb requires exactly two edits: define the subclass, add it here."""


_DECODERS: dict[Verb, Callable[[bytes], RoundMsg]] = {
    c.verb: c._decode  # noqa: SLF001 -- same-module dispatch table
    for c in _ROUND_MSG_CLASSES
}


@dataclass(frozen=True, slots=True)
class Block:
    """A ratified slice: the Round's terminal output.

    Settlement adds `height`, `prev_block`, and the on-log positioning when this is applied to the
    store. Round produces only what a Round can produce -- the ordered slice plus its quorum
    signature. The distinction matters: a Round does not know log heights, and inventing one here
    would couple Round to Settlement it does not need."""

    bucket: Bucket
    hashes: tuple[crypto.Digest, ...]
    """The slice, sorted deterministically (`sorted(hashes)`), so `slice_hash` is a pure function
    of the set and any two nodes computing it independently agree."""

    signers: crypto.SignerBitmap
    sigs: tuple[crypto.Signature, ...]
    """The quorum's ratification, per #ratification-counts. The bitmap indexes the roster; each
    named signer's signature is over `slice_hash`."""

    @property
    def slice_hash(self) -> crypto.Digest:
        """`H(bucket, sorted(hashes))` -- the canonical identity two nodes computing the same
        slice agree on. Bucket-bound so identical slices in different buckets have different ids.
        Used by SettleRound to bind post-apply anchors to this specific block."""
        return _slice_hash(self.bucket, self.hashes)


def _slice_hash(
    bucket: Bucket, hashes: tuple[crypto.Digest, ...] | frozenset[crypto.Digest]
) -> crypto.Digest:
    """The slice-identity computation, shared between `Block.slice_hash` (post-ratification)
    and `Round._finalize` (pre-Block, working with the not-yet-Block set)."""
    return crypto.h(codec.encode([bucket, sorted(hashes)]))


# --------------------------------------------------------------------------------------------- #
# The Round itself                                                                              #
# --------------------------------------------------------------------------------------------- #


class State(Enum):
    """The three states of a Round's lifecycle (#round-lifecycle).

    A Round transitions COLLECT -> FINALIZE exactly once (when local holdings are handed over),
    and FINALIZE -> GONE exactly once (when a quorum signs the same slice). No other transitions
    exist; a Round cannot regress."""

    COLLECT = auto()
    FINALIZE = auto()
    GONE = auto()


class Round:
    """One consensus round for one bucket. Sans-I/O.

    Instantiated per bucket by the Coordinator (or directly by tests). Drive it with `receive`,
    `tick`, and `add_local`; drain effects with `outbox`; read terminal state with `ratified` /
    `surviving`.

    ONE BUCKET, ONE ROUND. A message for a different bucket is not this Round's concern -- the
    Coordinator dispatches to the right instance. Round rejects foreign-bucket messages silently
    rather than raising, because a stray message is a routine outcome under gossip and reordering.
    """

    def __init__(
        self,
        bucket: Bucket,
        me: crypto.Keypair,
        roster: tuple[crypto.PublicKey, ...],
        now: Millis,
        close_by: Millis,
    ) -> None:
        """Construct a Round for `bucket`.

        `me` is this node's keypair; used to sign this node's `Sig` messages and to identify
        this node in the roster.

        `roster` is the ordered tuple of node public keys that may participate. Determines the
        quorum size, the signer-bitmap width, and who Round will accept `Sig` messages from.
        Round does NOT own how the roster is chosen -- that is management state (L2).

        `close_by` is the wall time at which collection ends and finalize begins. It is a
        parameter rather than a mode change signalled later, so tests hand it in as data and the
        Coordinator computes it from the bucket boundary + propagation margin. Every node in the
        cluster is expected to be given roughly the same `close_by` -- honest clock skew is
        absorbed by the propagation margin, and if two nodes finalize at slightly different times
        they still compute the same slice because their evidence has stopped changing."""
        if me.public not in roster:
            raise RoundError("my public key is not in the roster")
        if close_by <= now:
            raise RoundError(f"close_by={close_by} is not in the future (now={now})")
        self._bucket = bucket
        self._me = me
        self._roster = roster
        self._quorum = quorum.DEFAULT.size(len(roster))
        self._state = State.COLLECT
        self._now = now
        self._close_by = close_by
        self._local: frozenset[crypto.Digest] | None = None
        self._peer_holds: dict[crypto.PublicKey, frozenset[crypto.Digest]] = {}
        self._peer_sigs: dict[crypto.PublicKey, Sig] = {}
        self._my_sig: Sig | None = None
        self._equivocations: list[tuple[crypto.PublicKey, Sig, Sig]] = []
        self._ratified: Block | None = None
        self._surviving: tuple[crypto.Digest, ...] = ()
        self._outbox: list[tuple[Target, RoundMsg]] = []
        self._pending_slice_hashes: frozenset[crypto.Digest] = frozenset()

    # -- inputs ------------------------------------------------------------------------------- #

    def add_local(self, hashes: frozenset[crypto.Digest]) -> None:
        """The Mempool has closed and hands over what this node held for this bucket.

        MUST be called exactly once, and MUST be called before Round can transition out of
        COLLECT. Calling twice raises `RoundError` -- the local holdings are what they are,
        and any "second thought" is a bug.

        This is the ONLY input that determines this node's initial contribution; further changes
        to this node's holdings (a late tx admitted after bucket close) are not this Round's
        concern -- they go to the next Round via Mempool re-admission (#rejects-through-same-door).
        """
        if self._local is not None:
            raise RoundError("add_local called twice; local holdings are set once")
        if self._state is not State.COLLECT:
            raise RoundError(f"add_local in state {self._state.name}; expected COLLECT")
        self._local = hashes
        # Advertise what I hold. Peers combine my Held with theirs to compute the same slice I
        # will compute; convergence is by shared observation, not by delegation.
        self._outbox.append((Recipient.ALL, Held(self._bucket, hashes)))

    def receive(self, msg: RoundMsg, from_: crypto.PublicKey, now: Millis) -> None:
        """A message arrived from a peer. VERIFY, THEN INCORPORATE OR DROP.

        A bad-signature `Sig` MUST be verified and dropped. Nothing about a message with an
        invalid signature affects Round's state -- not the count of `Held` observations, not
        the ratification tally, not equivocation tracking. A dropped message is a null-op.
        Every drop site MUST carry an `#XXX:` comment naming what was dropped and why, so the
        rejection is visible in code rather than implicit in a bare return.

        Rejected by verification (dropped, no state change):
          * `Sig` whose signature does not verify against `from_`'s roster entry
          * `Held` (or `Sig`) whose `from_` is not in the roster at all
          * any message for a bucket other than this Round's -- it belongs to another Round
            instance, and the Coordinator will have dispatched to the right one

        Malformed by structure (raises `DudeError`, the crash-only boundary catches):
          * codec failures, unknown fields, wrong types -- these are what typed extractors
            (#no-exceptions-for-control-flow) catch at decode time

        Accepted after verification:
          * `Held` with a valid roster member: latest wins per (peer, bucket)
          * `Sig` with a valid roster signature and matching `slice_hash` to an earlier `Sig`
            from the same peer: idempotent re-send, counted once
          * `Sig` with a valid roster signature and a `slice_hash` differing from an earlier
            `Sig` from the same peer: EQUIVOCATION -- both signatures are genuine, but they
            contradict each other. Round keeps the first, drops the second, and exposes the
            pair via `equivocations()`. That is DISTINCT from a bad signature: equivocation is
            two valid signatures over contradictory content, which is proof against the peer's
            own key; a bad signature is proof against nothing (anyone could have crafted it,
            since the sender field is unauthenticated on that particular attempt)."""
        if now < self._now:
            raise RoundError(f"receive with now={now} < last={self._now}")
        self._now = now
        if msg.bucket != self._bucket:
            # XXX: dropped -- foreign bucket. Belongs to another Round; Coordinator dispatches.
            return
        if from_ not in self._roster:
            # XXX: dropped -- sender not in the roster. Round only heeds authorised peers.
            return
        if isinstance(msg, Held):
            self._on_held(msg, from_)
        elif isinstance(msg, Sig):
            self._on_sig(msg, from_)

    def _on_held(self, msg: Held, from_: crypto.PublicKey) -> None:
        if self._state is State.GONE:
            # XXX: dropped -- Round has ratified. A Held is evidence for slice computation and
            # that computation is now settled; further Helds do not affect anything.
            return
        # Latest wins per peer. Round does NOT recompute a slice here -- finalize is time-driven
        # (see `tick`), so late-arriving Held enriches evidence up until close_by and is ignored
        # afterwards. This is what makes convergence possible: all nodes sign based on the same
        # stable snapshot at close_by, not on whoever they happened to hear from before quorum.
        self._peer_holds[from_] = msg.hashes

    def _on_sig(self, msg: Sig, from_: crypto.PublicKey) -> None:
        if not msg.verify(from_):
            # XXX: dropped -- bad signature. Not evidence: anyone could craft a bad Sig with any
            # `from_` field on the wire, so this proves nothing about `from_`.
            return
        prior = self._peer_sigs.get(from_)
        if prior is not None and prior.slice_hash != msg.slice_hash:
            # XXX: dropped -- equivocation. Two valid signatures over contradictory slices IS
            # proof against `from_`'s key. We keep the first (which any counter-party might
            # already be counting toward ratification), record the pair for observability, and
            # drop this second one so it never enters the tally.
            #
            # DETECTED EVEN IN GONE. Ratification's own state is settled, but a byzantine peer's
            # contradiction is evidence that outlives any one Round -- shunning and eviction act
            # on it later, wherever this pair is carried. Silently dropping it just because we
            # ratified early throws away that evidence.
            self._equivocations.append((from_, prior, msg))
            return
        if self._state is State.GONE:
            # XXX: dropped -- Round has ratified. New (non-equivocating) Sigs no longer change
            # anything; ratification is already recorded and its signer set is complete.
            return
        self._peer_sigs[from_] = msg
        self._try_ratify()

    def tick(self, now: Millis) -> None:
        """Advance time. May transition state, may emit messages, may ratify.

        `now` is monotone by contract; a tick with `now` less than the last observed time raises
        `RoundError`. Round has no other clock."""
        if now < self._now:
            raise RoundError(f"tick with now={now} < last={self._now}")
        self._now = now
        # Time-driven finalize (#round-lifecycle): at close_by we stop accepting new evidence and
        # sign whatever holdings we have observed. This is the load-bearing property for
        # convergence -- if nodes finalized on quorum-many holdings instead, different nodes
        # would sign based on different observation orders and their sigs would not match.
        if self._state is State.COLLECT and self._local is not None and now >= self._close_by:
            self._finalize()

    # -- outputs ------------------------------------------------------------------------------ #

    def outbox(self) -> tuple[tuple[Target, RoundMsg], ...]:
        """Drain and return messages queued to send since the last call.

        Empty tuple if nothing new. Idempotent given no intervening `tick`/`receive` -- the
        second call returns nothing.

        Round emits at-most-once from its perspective; the wire is at-least-once, so the adapter
        may retransmit. Round does not track what has been sent -- that is the adapter's job."""
        drained = tuple(self._outbox)
        self._outbox.clear()
        return drained

    def ratified(self) -> Block | None:
        """The ratified Block for this bucket, or `None` if the Round has not converged.

        Once non-None, stable for the remainder of the Round's life. When non-None, Round is in
        state GONE and no further processing occurs on `receive` or `tick`.

        `surviving()` is meaningful only after this returns non-None."""
        return self._ratified

    def surviving(self) -> Iterable[crypto.Digest]:
        """Transaction hashes this node held but that did not make the ratified slice.

        Available only when `ratified()` is non-None; calling before raises `RoundError`.
        The Coordinator hands these back to the current-collecting Mempool via its one
        admission door -- some may re-enter, some may be rejected against the newly-updated
        state, and both outcomes are correct (#rejects-through-same-door)."""
        if self._ratified is None:
            raise RoundError("surviving() called before ratified()")
        return self._surviving

    def equivocations(self) -> Iterable[tuple[crypto.PublicKey, Sig, Sig]]:
        """Pairs of `Sig` messages from one peer that name different slices for this bucket.

        Round does not itself act on these -- shunning and eviction from the roster are separate
        concerns (`attest.contradiction`, management operations). Round exposes the raw pair so
        the observability layer can produce evidence.

        Empty until at least one equivocation is observed; monotone thereafter."""
        return tuple(self._equivocations)

    def state(self) -> State:
        """Current lifecycle state, for tests and observability."""
        return self._state

    # -- internals ---------------------------------------------------------------------------- #

    def _all_holdings(self) -> dict[crypto.PublicKey, frozenset[crypto.Digest]]:
        """Every set of holdings observed for this bucket: this node's plus every peer's.

        Includes the local set only after `add_local` has been called."""
        got: dict[crypto.PublicKey, frozenset[crypto.Digest]] = dict(self._peer_holds)
        if self._local is not None:
            got[self._me.public] = self._local
        return got

    def _compute_slice(self, local: frozenset[crypto.Digest]) -> frozenset[crypto.Digest]:
        """The largest set held (as a set) by at least `self._quorum` peers AND by us
        (#slice-is-intersection), with ties broken by a bucket-keyed deterministic sort
        (#slice-tie-break).

        Enumerates quorum-sized subsets of the observed peers and picks the largest intersection.
        For N ~ 11 and quorum ~ 8, C(11,8) = 165 subsets -- fast. For much larger rosters this is
        not the algorithm to use, but 11 is the ceiling this design targets (#no-token-economics).

        RESTRICTED TO ⊆ `local`. A node MUST NOT sign a slice containing transactions it does not
        hold: it cannot check them, cannot produce their bodies for settlement, and (worst) is
        attesting to something it hasn't verified. Filtering candidates to those subsets of `local`
        means every slice this node signs is fully backed by evidence it holds. If the quorum-held
        intersection over some subset of peers contains a tx we lack, we simply don't include that
        tx in our own view -- other nodes that DO hold it may reach quorum without us, which is
        correct.

        Ties: several distinct maximal intersections. The block MUST be chosen by a deterministic
        randomised sort keyed by the bucket, so (a) every honest node picks the same one and (b) an
        adversary cannot pre-mine transactions to guarantee winning in every future round -- the
        sort's ordering changes with `bucket`. `H(bucket, sorted(candidate))` is the sort key; the
        smallest such digest wins."""
        holdings = self._all_holdings()
        if len(holdings) < self._quorum:
            return frozenset()
        peers = sorted(holdings)
        candidates: set[frozenset[crypto.Digest]] = set()
        max_size = 0
        for combo in combinations(peers, self._quorum):
            it = iter(combo)
            inter = holdings[next(it)]
            for p in it:
                inter = inter & holdings[p]
                if not inter:
                    break
            inter = inter & local  # restrict to what we can back
            if len(inter) < max_size:
                continue
            if len(inter) > max_size:
                max_size = len(inter)
                candidates = {inter}
            else:
                candidates.add(inter)
        if not candidates:
            return frozenset()
        if len(candidates) == 1:
            return next(iter(candidates))
        return min(candidates, key=lambda c: _slice_hash(self._bucket, c))

    def _finalize(self) -> None:
        """Called by `tick` when `close_by` has passed. Compute the slice from whatever holdings
        we have accumulated, sign it, transition to FINALIZE.

        Precondition (checked by caller): `state is COLLECT` and `local is not None`. Late-
        arriving Helds after this point still update `peer_holds`, but do not change the slice
        this node signed -- convergence rests on all nodes signing based on their observed
        evidence AT CLOSE_BY, not on continually revising."""
        local = self._local
        if local is None:  # unreachable given tick's guard, but the narrower makes ty happy
            return
        slice_hashes = self._compute_slice(local)
        my_sig = Sig.sign(self._me, self._bucket, _slice_hash(self._bucket, slice_hashes))
        self._my_sig = my_sig
        self._peer_sigs[self._me.public] = my_sig  # my own vote counts toward my own ratification
        self._surviving = tuple(sorted(h for h in local if h not in slice_hashes))
        self._pending_slice_hashes = slice_hashes
        self._state = State.FINALIZE
        self._outbox.append((Recipient.ALL, my_sig))
        self._try_ratify()

    def _try_ratify(self) -> None:
        """If a quorum of Sig messages agree on the same slice_hash, ratify."""
        if self._state is not State.FINALIZE:
            return
        if self._my_sig is None:  # unreachable given state, but the narrower makes ty happy
            return
        want = self._my_sig.slice_hash
        agreeing = {peer: sig for peer, sig in self._peer_sigs.items() if sig.slice_hash == want}
        if len(agreeing) < self._quorum:
            return
        # Ratified. Build the Block: the roster-ordered bitmap + parallel signatures, via
        # the same `combine` primitive `Ed25519ListMultiSig.verify` will read on the other side.
        shares = {i: agreeing[m].sig for i, m in enumerate(self._roster) if m in agreeing}
        signers, sigs = crypto.Ed25519ListMultiSig.combine(shares, len(self._roster))
        self._ratified = Block(
            bucket=self._bucket,
            hashes=tuple(sorted(self._pending_slice_hashes)),
            signers=signers,
            sigs=tuple(sigs),
        )
        self._state = State.GONE
