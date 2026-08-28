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
from ..net.postman import Encodable, Recipient, Target
from ..store.layer import Index
from ..store.ops import SignedTransaction
from .canonical import hashes_canonical
from .round import Block


class SettleAdapterError(DudeError): ...


_ANCHORS_DOMAIN = b"dude.settle_round.anchors"


class SettleError(DudeError): ...


@dataclass(frozen=True, slots=True)
class Anchors:
    block_num: Index
    height: Index
    prev_block: crypto.Digest
    state_root: crypto.Digest
    acc_state: crypto.Accumulator
    acc_log: crypto.Accumulator


@dataclass(frozen=True, slots=True)
class SettleSig(Encodable):
    verb: ClassVar[Verb] = Verb.SETTLE_SIG

    slice_hash: crypto.Digest
    anchors: Anchors
    sig: crypto.Signature

    @classmethod
    def sign(cls, kp: crypto.Keypair, slice_hash: crypto.Digest, anchors: Anchors) -> SettleSig:
        return cls(slice_hash, anchors, kp.sign(_settle_payload(slice_hash, anchors)))

    def verify(self, pk: crypto.PublicKey) -> bool:
        return pk.verify(_settle_payload(self.slice_hash, self.anchors), self.sig)

    def _encode(self) -> bytes:
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
        return self.verb, self._encode()

    @classmethod
    def decode(cls, verb: Verb, body: bytes) -> SettleSig:
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
        try:
            p = codec.as_seq(codec.decode(body))
            return crypto.Digest(codec.as_bytes(p[0]))
        except DudeError as e:
            raise SettleAdapterError(f"cannot read slice_hash from body: {e}") from e


def _settle_payload(slice_hash: crypto.Digest, anchors: Anchors) -> bytes:
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
    block: Block
    anchors: Anchors
    multisig: crypto.MultiSig

    @property
    def block_hash(self) -> crypto.Digest:
        return crypto.h(self._identity_bytes())

    def _identity_bytes(self) -> bytes:
        return codec.encode(
            [
                self.block.bucket,
                hashes_canonical(self.block.hashes),
                self.anchors.block_num,
                self.anchors.height,
                self.anchors.prev_block,
                self.anchors.state_root,
                self.anchors.acc_state,
                self.anchors.acc_log,
            ]
        )

    def encode(self) -> bytes:
        return codec.encode(
            [
                self._identity_bytes(),
                self.multisig.bitmap,
                list(self.multisig.sigs),
            ]
        )

    @classmethod
    def decode(cls, raw: bytes) -> SettledBlock:
        try:
            outer = codec.as_seq(codec.decode(raw), 3)
            identity = codec.as_seq(codec.decode(codec.as_bytes(outer[0])), 8)
            bucket = codec.as_int(identity[0])
            # Canonicalise on the way in too, so `.hashes` on a decoded Block always equals
            # `hashes_canonical(.hashes)`. `_identity_bytes` canonicalises on the way out.
            hashes = hashes_canonical(
                crypto.Digest(codec.as_bytes(h)) for h in codec.as_seq(identity[1])
            )
            anchors = Anchors(
                block_num=codec.as_int(identity[2]),
                height=codec.as_int(identity[3]),
                prev_block=crypto.Digest(codec.as_bytes(identity[4])),
                state_root=crypto.Digest(codec.as_bytes(identity[5])),
                acc_state=crypto.Accumulator(codec.as_bytes(identity[6])),
                acc_log=crypto.Accumulator(codec.as_bytes(identity[7])),
            )
            multisig = crypto.MultiSig(
                crypto.SignerBitmap(codec.as_bytes(outer[1])),
                tuple(crypto.Signature(codec.as_bytes(s)) for s in codec.as_seq(outer[2])),
            )
        except DudeError as e:
            raise SettleError(f"malformed SettledBlock: {e}") from e
        block = Block(bucket=bucket, hashes=hashes)
        return cls(block=block, anchors=anchors, multisig=multisig)


@dataclass(frozen=True, slots=True)
class SettledBlockWithBodies:
    block: SettledBlock
    bodies: tuple[SignedTransaction, ...]

    def encode(self) -> bytes:
        return codec.encode(
            [
                self.block.encode(),
                [tx.raw for tx in self.bodies],
            ]
        )

    @classmethod
    def decode(cls, raw: bytes) -> SettledBlockWithBodies:
        try:
            p = codec.as_seq(codec.decode(raw), 2)
            block = SettledBlock.decode(codec.as_bytes(p[0]))
            bodies = tuple(SignedTransaction.decode(codec.as_bytes(b)) for b in codec.as_seq(p[1]))
        except DudeError as e:
            raise SettleError(f"malformed SettledBlockWithBodies: {e}") from e
        return cls(block=block, bodies=bodies)


_GENESIS_DOMAIN = b"dude.genesis:"


def genesis_stamp(manager: crypto.PublicKey) -> crypto.Digest:
    return crypto.h(_GENESIS_DOMAIN + bytes(manager))


class SettleState(Enum):
    INVALID = 0
    COLLECTING = auto()
    SETTLED = auto()
    ABANDONED = auto()


class SettleRound:
    def __init__(  # noqa: PLR0913, PLR0917 -- construction inputs, all required
        self,
        block: Block,
        me: crypto.Keypair,
        roster: tuple[crypto.PublicKey, ...],
        anchors: Anchors,
        now: Millis,  # noqa: ARG002 -- reserved for telemetry
        abandon_by: Millis,
    ):
        if me.public not in roster:
            raise SettleError(f"me ({me.public.hex()[:8]}) is not in the roster")
        self._block = block
        self._me = me
        self._roster = roster
        self._quorum = quorum.size(len(roster))
        self._anchors = anchors
        self._slice_hash = block.slice_hash
        self._abandon_by = abandon_by
        self._sigs: dict[crypto.PublicKey, crypto.Signature] = {}
        self._divergences: list[tuple[crypto.PublicKey, Anchors]] = []
        self._outbox: list[tuple[Target, SettleSig]] = []
        self._state = SettleState.COLLECTING
        self._settled: SettledBlock | None = None

        my_msg = SettleSig.sign(me, self._slice_hash, anchors)
        self._sigs[me.public] = my_msg.sig
        self._outbox.append((Recipient.ALL, my_msg))
        self._try_settle()

    def receive(self, msg: SettleSig, from_: crypto.PublicKey, now: Millis) -> None:  # noqa: ARG002 -- `now` reserved
        if from_ not in self._roster:
            return
        if from_ == self._me.public:
            return
        if msg.slice_hash != self._slice_hash:
            return
        if not msg.verify(from_):
            return
        if msg.anchors != self._anchors:
            self._divergences.append((from_, msg.anchors))
            return
        if self._state is not SettleState.COLLECTING:
            return
        self._sigs[from_] = msg.sig
        self._try_settle()

    def outbox(self) -> Iterable[tuple[Target, SettleSig]]:
        drained = tuple(self._outbox)
        self._outbox.clear()
        return drained

    def tick(self, now: Millis) -> None:
        if self._state is SettleState.COLLECTING and now >= self._abandon_by:
            self._state = SettleState.ABANDONED

    def state(self) -> SettleState:
        return self._state

    def roster(self) -> tuple[crypto.PublicKey, ...]:
        return self._roster

    def settled(self) -> SettledBlock | None:
        return self._settled

    def abandoned(self) -> bool:
        return self._state is SettleState.ABANDONED

    def divergences(self) -> tuple[tuple[crypto.PublicKey, Anchors], ...]:
        return tuple(self._divergences)

    def _try_settle(self) -> None:
        if self._state is not SettleState.COLLECTING:
            return
        if len(self._sigs) < self._quorum:
            return
        n = len(self._roster) + 1
        shares = {i: self._sigs[m] for i, m in enumerate(self._roster) if m in self._sigs}
        self._settled = SettledBlock(
            block=self._block,
            anchors=self._anchors,
            multisig=crypto.MultiSig.combine(shares, n),
        )
        self._state = SettleState.SETTLED
