from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum
from typing import Protocol

from ..core import crypto
from ..core.units import Millis
from ..store import ops, settle
from ..store.layer import Reader

type Bucket = int


@dataclass(frozen=True, slots=True)
class Tunables:
    delta: Millis = 30_000
    """THE BLOCK TIME: how long a client waits before it can prove its write is final. The only
    operating dial in the timing surface -- everything else derives from it and the measurements.
    It is not a floor to be parked on; the floors are what `Tunables.__post_init__` checks."""

    w_admit: Millis = 30_000

    w_valid_margin: Millis = 60_250

    @property
    def w_valid(self) -> Millis:
        return self.w_admit + self.w_valid_margin

    @property
    def evict_after(self) -> Millis:
        return self.w_valid

    def bucket(self, ts: Millis) -> Bucket:
        return ts // self.delta

    def bucket_start(self, b: Bucket) -> Millis:
        return b * self.delta


class Refusal(Enum):
    INVALID = "invalid"

    TOO_OLD = "ts-too-old"
    TOO_NEW = "ts-too-new"
    DUPLICATE = "duplicate"
    UNSIGNED = "signature"
    CANNOT_APPLY = "cannot-apply"


TOO_OLD = Refusal.TOO_OLD
TOO_NEW = Refusal.TOO_NEW
DUPLICATE = Refusal.DUPLICATE
UNSIGNED = Refusal.UNSIGNED
CANNOT_APPLY = Refusal.CANNOT_APPLY


class Ledger(Reader, Protocol):
    def has_settled(self, op_hash: crypto.Digest) -> bool: ...


@dataclass(slots=True)
class Mempool:
    tunables: Tunables = field(default_factory=Tunables)
    pending: dict[Bucket, dict[crypto.Digest, ops.SignedTransaction]] = field(default_factory=dict)

    def valid(  # THE CLOCK MAY CHOOSE, IT MAY NOT JUDGE: `now` is read here and in `propose`,
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
        # A settled tx MUST NOT re-enter (#dedup-content-address). This is why the parameter is
        # `Ledger` and not `Reader`: an overlay has no log, so admitting against one cannot compile.
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

    def __len__(self) -> int:
        return sum(len(held) for held in self.pending.values())
