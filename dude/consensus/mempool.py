from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum

from ..core import crypto
from ..core.units import Bucket, Millis
from ..store import ops, settle
from ..store.layer import Ledger
from ..tunables import Tunables


class Refusal(Enum):
    INVALID = "invalid"

    TOO_OLD = "ts-too-old"
    TOO_NEW = "ts-too-new"
    DUPLICATE = "duplicate"
    UNSIGNED = "signature"
    CANNOT_APPLY = "cannot-apply"
    NOT_IN_ROSTER = "not-in-roster"
    REPEATED_OP = "repeated-op"


TOO_OLD = Refusal.TOO_OLD
TOO_NEW = Refusal.TOO_NEW
DUPLICATE = Refusal.DUPLICATE
UNSIGNED = Refusal.UNSIGNED
CANNOT_APPLY = Refusal.CANNOT_APPLY


@dataclass(slots=True)
class Mempool:
    tunables: Tunables = field(default_factory=Tunables)
    pending: dict[Bucket, dict[crypto.Digest, ops.SignedTransaction]] = field(default_factory=dict)

    def valid(  # noqa: PLR0911 -- each early-return names a distinct refusal a client can act
        # on; collapsing them hides which door it was turned away at.
        # THE CLOCK MAY CHOOSE, IT MAY NOT JUDGE: `now` is read here and in `propose`,
        # never in verifying a proposal. A clock read anywhere else turns skew from a throughput
        # cost into a liveness or safety failure.
        self,
        tx: ops.SignedTransaction,
        now: Millis,
        reader: Ledger,
        auth: settle.Authoriser,
    ) -> Refusal | None:
        t = self.tunables
        if now - tx.ts > t.w_admit:
            return Refusal.TOO_OLD
        if tx.ts - now > t.w_admit:
            return Refusal.TOO_NEW
        if not tx.verify():
            return Refusal.UNSIGNED
        # One operation, once. A tx carrying the same mutation twice applies it twice in the
        # preview that computes a block's anchors and once in the store, which is a log position
        # of disagreement between what a block is signed for and what it settles. `apply_to` and
        # `_apply_within` both dedup now, so this is not what holds that -- it refuses the shape
        # at the door instead of letting every later stage carry the question.
        mutations = [step.mutation for step in tx.steps]
        if len(set(mutations)) != len(mutations):
            return Refusal.REPEATED_OP
        # A settled tx MUST NOT re-enter (#dedup-content-address). This is why the parameter is
        # `Ledger` and not `Reader`: an overlay has no log, so admitting against one cannot compile.
        if reader.has_settled(tx.op_hash):
            return Refusal.DUPLICATE
        if settle.would_apply(reader, (tx,), auth).rejects:
            return Refusal.CANNOT_APPLY
        return None

    def valid_for_bucket(
        self,
        tx: ops.SignedTransaction,
        bucket: Bucket,
        reader: Ledger,
        auth: settle.Authoriser,
    ) -> Refusal | None:
        t = self.tunables
        earliest = t.bucket_start(bucket) - t.w_admit - t.clock_skew
        latest = t.bucket_start(bucket + 1) + t.w_admit + t.clock_skew
        if tx.ts < earliest:
            return Refusal.TOO_OLD
        if tx.ts > latest:
            return Refusal.TOO_NEW
        if not tx.verify():
            return Refusal.UNSIGNED
        mutations = [step.mutation for step in tx.steps]
        if len(set(mutations)) != len(mutations):
            return Refusal.REPEATED_OP
        if reader.has_settled(tx.op_hash):
            return Refusal.DUPLICATE
        if settle.would_apply(reader, (tx,), auth).rejects:
            return Refusal.CANNOT_APPLY
        return None

    def admit(
        self,
        tx: ops.SignedTransaction,
        now: Millis,
        reader: Ledger,
        auth: settle.Authoriser,
    ) -> Refusal | None:
        if any(tx.op_hash in held for held in self.pending.values()):
            return Refusal.DUPLICATE
        if (why := self.valid(tx, now, reader, auth)) is not None:
            return why
        t = self.tunables
        landed = max(t.bucket(tx.ts), t.bucket(now))
        self.pending.setdefault(landed, {})[tx.op_hash] = tx
        return None

    def buckets(self) -> tuple[Bucket, ...]:
        return tuple(sorted(b for b, held in self.pending.items() if held))

    def all_hashes(self) -> frozenset[crypto.Digest]:
        return frozenset(op_hash for txs in self.pending.values() for op_hash in txs)

    def all_bodies(self) -> dict[crypto.Digest, ops.SignedTransaction]:
        return {tx.op_hash: tx for txs in self.pending.values() for tx in txs.values()}

    def snapshot(self) -> Mempool:
        return Mempool(
            tunables=self.tunables,
            pending={b: dict(txs) for b, txs in self.pending.items() if txs},
        )

    def evict_settled(self, reader: Ledger) -> None:
        for bucket_txs in self.pending.values():
            for h in list(bucket_txs):
                if reader.has_settled(h):
                    del bucket_txs[h]
        self.pending = {b: txs for b, txs in self.pending.items() if txs}

    def __len__(self) -> int:
        return sum(len(held) for held in self.pending.values())
