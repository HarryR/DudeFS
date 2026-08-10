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
from ..store.ops import SignedTransaction
from .canonical import CanonicalBatch, bodies_canonical, hashes_canonical
from .mempool import Bucket

_SLICE_DOMAIN = b"dude.round.slice"


class RoundError(DudeError): ...


class RoundAdapterError(DudeError): ...


class RoundMsg(ABC):
    verb: ClassVar[Verb]

    bucket: Bucket
    prev_block: crypto.Digest
    """The block this round builds on. Carried on EVERY round message: without it, nodes at
    different heights ratify together and only find out two stages later, at the anchors."""

    @abstractmethod
    def _encode(self) -> bytes: ...

    def encode(self) -> tuple[Verb, bytes]:
        return self.verb, self._encode()

    @classmethod
    def decode(cls, verb: Verb, body: bytes) -> RoundMsg:
        try:
            handler = _DECODERS[verb]
        except KeyError as e:
            raise RoundAdapterError(f"not a Round verb: {verb.name}") from e
        return handler(body)

    @classmethod
    def bucket_of(cls, body: bytes) -> Bucket:
        try:
            p = codec.as_seq(codec.decode(body))
            return codec.as_int(p[0])
        except DudeError as e:
            raise RoundAdapterError(f"cannot read bucket from body: {e}") from e


@dataclass(frozen=True, slots=True)
class Held(RoundMsg):
    verb: ClassVar[Verb] = Verb.HELD

    bucket: Bucket
    prev_block: crypto.Digest
    hashes: frozenset[crypto.Digest]

    def _encode(self) -> bytes:
        return codec.encode([self.bucket, self.prev_block, hashes_canonical(self.hashes)])

    @classmethod
    def _decode(cls, body: bytes) -> Held:
        try:
            p = codec.as_seq(codec.decode(body), 3)
            hashes = frozenset(crypto.Digest(codec.as_bytes(h)) for h in codec.as_seq(p[2]))
            return cls(
                bucket=codec.as_int(p[0]),
                prev_block=crypto.Digest(codec.as_bytes(p[1])),
                hashes=hashes,
            )
        except DudeError as e:
            raise RoundAdapterError(f"malformed HELD body: {e}") from e


@dataclass(frozen=True, slots=True)
class Sig(RoundMsg):
    verb: ClassVar[Verb] = Verb.SIG

    bucket: Bucket
    prev_block: crypto.Digest
    slice_hash: crypto.Digest
    sig: crypto.Signature

    @classmethod
    def sign(
        cls,
        kp: crypto.Keypair,
        bucket: Bucket,
        prev_block: crypto.Digest,
        slice_hash: crypto.Digest,
    ) -> Sig:
        return cls(
            bucket, prev_block, slice_hash, kp.sign(_sig_payload(bucket, prev_block, slice_hash))
        )

    def verify(self, pk: crypto.PublicKey) -> bool:
        return pk.verify(_sig_payload(self.bucket, self.prev_block, self.slice_hash), self.sig)

    def _encode(self) -> bytes:
        return codec.encode([self.bucket, self.prev_block, self.slice_hash, self.sig])

    @classmethod
    def _decode(cls, body: bytes) -> Sig:
        try:
            p = codec.as_seq(codec.decode(body), 4)
            return cls(
                bucket=codec.as_int(p[0]),
                prev_block=crypto.Digest(codec.as_bytes(p[1])),
                slice_hash=crypto.Digest(codec.as_bytes(p[2])),
                sig=crypto.Signature(codec.as_bytes(p[3])),
            )
        except DudeError as e:
            raise RoundAdapterError(f"malformed SIG body: {e}") from e


def _sig_payload(bucket: Bucket, prev_block: crypto.Digest, slice_hash: crypto.Digest) -> bytes:
    return codec.encode([_SLICE_DOMAIN, bucket, prev_block, slice_hash])


@dataclass(frozen=True, slots=True)
class Bodies(RoundMsg):
    """Phase 2. Bodies a peer's advertisement showed it was missing."""

    verb: ClassVar[Verb] = Verb.BODIES

    bucket: Bucket
    prev_block: crypto.Digest
    txs: tuple[SignedTransaction, ...]

    def _encode(self) -> bytes:
        return codec.encode([self.bucket, self.prev_block, [tx.raw for tx in self.txs]])

    @classmethod
    def _decode(cls, body: bytes) -> Bodies:
        try:
            p = codec.as_seq(codec.decode(body), 3)
            txs = tuple(SignedTransaction.decode(codec.as_bytes(raw)) for raw in codec.as_seq(p[2]))
            return cls(
                bucket=codec.as_int(p[0]),
                prev_block=crypto.Digest(codec.as_bytes(p[1])),
                txs=txs,
            )
        except DudeError as e:
            raise RoundAdapterError(f"malformed BODIES body: {e}") from e


_ROUND_MSG_CLASSES: tuple[type[RoundMsg], ...] = (Held, Sig, Bodies)


_DECODERS: dict[Verb, Callable[[bytes], RoundMsg]] = {
    c.verb: c._decode  # noqa: SLF001 -- same-module dispatch table
    for c in _ROUND_MSG_CLASSES
}


@dataclass(frozen=True, slots=True)
class Block:
    bucket: Bucket
    hashes: tuple[crypto.Digest, ...]
    """Screened before the slice was signed, so this is exactly what the block applied -- not a
    superset of it. Everything downstream that treats membership as application depends on it."""

    # No ratify multisig here. One used to sit beside `hashes`: never encoded, never verified,
    # and combined one bitmap slot too narrow for `Authorization`'s (*roster, anchor) -- wrong
    # the moment anybody actually checked it. The settle multisig signs `slice_hash`, so it
    # already attests to this exact set; a second proof of the same fact is one to drift.

    @property
    def slice_hash(self) -> crypto.Digest:
        return _slice_hash(self.bucket, self.hashes)


def _slice_hash(
    bucket: Bucket, hashes: tuple[crypto.Digest, ...] | frozenset[crypto.Digest]
) -> crypto.Digest:
    return crypto.h(codec.encode([bucket, hashes_canonical(hashes)]))


class State(Enum):
    COLLECT = auto()
    FINALIZE = auto()
    GONE = auto()
    ABANDONED = auto()


class Round:
    def __init__(  # noqa: PLR0913, PLR0917 -- cadence + identity are all required, no defaults
        self,
        bucket: Bucket,
        me: crypto.Keypair,
        roster: tuple[crypto.PublicKey, ...],
        prev_block: crypto.Digest,
        now: Millis,
        close_by: Millis,
        abandon_by: Millis,
        *,
        screen: Callable[[CanonicalBatch], frozenset[crypto.Digest]],
    ) -> None:
        """`screen` decides WHICH op_hashes of a canonical candidate stay -- membership only, not
        bodies. Round applies the membership to the candidate via `CanonicalBatch.filter`, so
        "narrow" and "in apply order" are structural: extras in the frozenset name hashes not in
        the candidate and are dropped by filter, and order comes from the candidate's canonical
        sort. Nothing to assert, nothing for a screen to widen or shuffle.

        REQUIRED, never defaulted: the only available default is `batch.op_hashes` -- identity --
        which is precisely the defect. A block would name transactions it did not apply."""
        if me.public not in roster:
            raise RoundError("my public key is not in the roster")
        if close_by <= now:
            raise RoundError(f"close_by={close_by} is not in the future (now={now})")
        if abandon_by <= close_by:
            raise RoundError(f"abandon_by={abandon_by} must be > close_by={close_by}")
        self._bucket = bucket
        self._me = me
        self._roster = roster
        self._prev_block = prev_block
        self._screen = screen
        self._quorum = quorum.size(len(roster))
        self._state = State.COLLECT
        self._now = now
        self._close_by = close_by
        self._abandon_by: Millis = abandon_by
        self._local_bodies: dict[crypto.Digest, SignedTransaction] | None = None
        self._peer_holds: dict[crypto.PublicKey, frozenset[crypto.Digest]] = {}
        self._peer_sigs: dict[crypto.PublicKey, Sig] = {}
        self._my_sig: Sig | None = None
        self._equivocations: list[tuple[crypto.PublicKey, Sig, Sig]] = []
        self._divergences: list[tuple[crypto.PublicKey, crypto.Digest]] = []
        self._gap_attempts: dict[tuple[crypto.PublicKey, crypto.Digest], int] = {}
        self._ratified: Block | None = None
        self._slice_bodies: tuple[SignedTransaction, ...] = ()
        self._surviving: tuple[SignedTransaction, ...] = ()
        self._outbox: list[tuple[Target, RoundMsg]] = []
        self._pending_slice_hashes: frozenset[crypto.Digest] = frozenset()

    def add_local(self, bodies: Iterable[SignedTransaction]) -> None:
        if self._local_bodies is not None:
            raise RoundError("add_local called twice; local holdings are set once")
        if self._state is not State.COLLECT:
            raise RoundError(f"add_local in state {self._state.name}; expected COLLECT")
        self._local_bodies = {tx.op_hash: tx for tx in bodies}
        self._outbox.append(
            (Recipient.ALL, Held(self._bucket, self._prev_block, frozenset(self._local_bodies)))
        )
        self._close_if_converged()  # peers' HELD may already be in, if we opened last

    def receive(self, msg: RoundMsg, from_: crypto.PublicKey, now: Millis) -> None:
        if now < self._now:
            raise RoundError(f"receive with now={now} < last={self._now}")
        self._now = now
        if msg.bucket != self._bucket:
            return
        if from_ not in self._roster:
            return
        if msg.prev_block != self._prev_block:
            # Recorded, not silently dropped: this is how a node behind the cluster finds out.
            self._divergences.append((from_, msg.prev_block))
            return
        if isinstance(msg, Held):
            self._on_held(msg, from_)
        elif isinstance(msg, Sig):
            self._on_sig(msg, from_)

    def _on_held(self, msg: Held, from_: crypto.PublicKey) -> None:
        if self._state is State.GONE:
            return
        self._peer_holds[from_] = msg.hashes
        self._push_missing(from_, msg.hashes)
        self._close_if_converged()

    def _push_missing(self, to: crypto.PublicKey, theirs: frozenset[crypto.Digest]) -> None:
        bodies = self._local_bodies
        if bodies is None or self._state is not State.COLLECT:
            return
        send = [bodies[h] for h in sorted(set(bodies) - theirs) if self._elected(h, to)]
        if send:
            self._outbox.append((to, Bodies(self._bucket, self._prev_block, tuple(send))))

    def _elected(self, h: crypto.Digest, to: crypto.PublicKey) -> bool:
        """One holder per gap, or a node rejoining after a partition gets n copies of everything.
        Attempt-indexed because the winner may have no path to them: a repeat sighting elects a
        different holder, so an unreachable winner costs a cycle rather than the transaction."""
        key = (to, h)
        attempt = self._gap_attempts.get(key, 0)
        self._gap_attempts[key] = attempt + 1
        holders = {self._me.public} | {p for p, hs in self._peer_holds.items() if h in hs}
        return self._me.public == min(
            holders, key=lambda p: crypto.h(codec.encode([self._bucket, h, to, attempt, p]))
        )

    def absorb(
        self,
        msg: Bodies,
        from_: crypto.PublicKey,
        validated: tuple[SignedTransaction, ...],
    ) -> None:
        """`validated` has already been through the admission door. Round holds no reader and no
        authoriser: what it can apply is a question it asks `screen` at the cut, and never one it
        answers here about a body arriving mid-collection."""
        if msg.bucket != self._bucket or from_ not in self._roster:
            return
        if msg.prev_block != self._prev_block:
            self._divergences.append((from_, msg.prev_block))
            return
        bodies = self._local_bodies
        if bodies is None or self._state is not State.COLLECT:
            return
        fresh = {tx.op_hash: tx for tx in validated if tx.op_hash not in bodies}
        if not fresh:
            return
        bodies.update(fresh)
        # Re-advertising IS the iteration: it makes peers recompute their gaps against what we
        # now hold.
        self._outbox.append(
            (Recipient.ALL, Held(self._bucket, self._prev_block, frozenset(bodies)))
        )
        self._close_if_converged()

    def _close_if_converged(self) -> None:
        """Cut early only when EVERY member has advertised the same set -- the deadline is a
        timeout for the absent, not a schedule. Never on a quorum: `_compute_slice` maximises over
        any quorum subset, so another peer's holdings can only enlarge the slice."""
        if self._state is not State.COLLECT or self._local_bodies is None:
            return
        if len(self._peer_holds) != len(self._roster) - 1:
            return
        mine = frozenset(self._local_bodies)
        if any(held != mine for held in self._peer_holds.values()):
            return
        self._finalize()

    def _on_sig(self, msg: Sig, from_: crypto.PublicKey) -> None:
        if not msg.verify(from_):
            return
        prior = self._peer_sigs.get(from_)
        if prior is not None and prior.slice_hash != msg.slice_hash:
            self._equivocations.append((from_, prior, msg))
            return
        if self._state is State.GONE:
            return
        self._peer_sigs[from_] = msg
        self._try_ratify()

    def tick(self, now: Millis) -> None:
        if now < self._now:
            raise RoundError(f"tick with now={now} < last={self._now}")
        self._now = now
        if (
            self._state is State.COLLECT
            and self._local_bodies is not None
            and now >= self._close_by
        ):
            self._finalize()
        if self._state is State.FINALIZE and now >= self._abandon_by:
            self._abandon()

    def outbox(self) -> tuple[tuple[Target, RoundMsg], ...]:
        drained = tuple(self._outbox)
        self._outbox.clear()
        return drained

    def ratified(self) -> Block | None:
        return self._ratified

    def abandoned(self) -> bool:
        return self._state is State.ABANDONED

    def surviving(self) -> tuple[SignedTransaction, ...]:
        if self._state not in (State.GONE, State.ABANDONED):
            raise RoundError(f"surviving() called in state {self._state.name}")
        return self._surviving

    def slice_bodies(self) -> tuple[SignedTransaction, ...]:
        if self._ratified is None:
            raise RoundError("slice_bodies() called before ratified()")
        return self._slice_bodies

    def equivocations(self) -> Iterable[tuple[crypto.PublicKey, Sig, Sig]]:
        return tuple(self._equivocations)

    def divergences(self) -> tuple[tuple[crypto.PublicKey, crypto.Digest], ...]:
        """Roster members whose round messages chain to a block we do not hold."""
        return tuple(self._divergences)

    def state(self) -> State:
        return self._state

    def bucket(self) -> Bucket:
        return self._bucket

    def prev_block(self) -> crypto.Digest:
        """The base this round's slice was screened against. The anchors MUST be computed over
        the same one -- see `Coordinator._promote_to_settling`."""
        return self._prev_block

    def roster(self) -> tuple[crypto.PublicKey, ...]:
        return self._roster

    def _all_holdings(self) -> dict[crypto.PublicKey, frozenset[crypto.Digest]]:
        got: dict[crypto.PublicKey, frozenset[crypto.Digest]] = dict(self._peer_holds)
        if self._local_bodies is not None:
            got[self._me.public] = frozenset(self._local_bodies)
        return got

    def _compute_slice(self, local: frozenset[crypto.Digest]) -> frozenset[crypto.Digest]:
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
            inter = inter & local
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
        bodies = self._local_bodies
        if bodies is None:
            return
        candidate = bodies_canonical(bodies[h] for h in self._compute_slice(frozenset(bodies)))
        # THE CUT. Screen before signing, so what the quorum ratifies is what it applies. Screened
        # after, a block named transactions that never touched state: they got no log entry, so
        # `has_settled` stayed false and they were re-admitted and could settle again later -- the
        # same op_hash legitimately in two blocks, and inclusion proving nothing to anyone.
        applicable = candidate.filter(self._screen(candidate))
        self._slice_bodies = applicable.txs
        slice_hashes = applicable.op_hashes
        my_sig = Sig.sign(
            self._me, self._bucket, self._prev_block, _slice_hash(self._bucket, slice_hashes)
        )
        self._my_sig = my_sig
        self._peer_sigs[self._me.public] = my_sig
        self._surviving = bodies_canonical(
            tx for tx in bodies.values() if tx.op_hash not in slice_hashes
        ).txs
        self._pending_slice_hashes = slice_hashes
        self._state = State.FINALIZE
        self._outbox.append((Recipient.ALL, my_sig))
        self._try_ratify()

    def _try_ratify(self) -> None:
        if self._state is not State.FINALIZE:
            return
        if self._my_sig is None:
            return
        want = self._my_sig.slice_hash
        agreeing = {peer: sig for peer, sig in self._peer_sigs.items() if sig.slice_hash == want}
        if len(agreeing) < self._quorum:
            return
        self._ratified = Block(
            bucket=self._bucket,
            hashes=hashes_canonical(self._pending_slice_hashes),
        )
        self._state = State.GONE

    def _abandon(self) -> None:
        bodies = self._local_bodies
        if bodies is None:
            return
        self._surviving = bodies_canonical(bodies.values()).txs
        self._state = State.ABANDONED
