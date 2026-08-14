from __future__ import annotations

from dataclasses import dataclass
from enum import Enum
from typing import Any, NamedTuple, Protocol

from ..core import codec, crypto
from ..core.errors import DudeError
from . import ops
from .layer import Overlay, Reader, holds


class Authoriser(Protocol):
    def may_write(self, reader: Reader, who: crypto.PublicKey, store_id: int) -> bool: ...

    def current_epoch(self, store_id: int, reader: Reader) -> int: ...

    def epoch_target(self, name: bytes) -> int | None: ...


class Reason(Enum):
    INVALID = "invalid"

    SIGNATURE = "signature"
    AUTHORITY = "authority"
    GUARD = "guard"
    SETTLED = "settled"
    EPOCH = "epoch"
    NAME_SHAPE = "name-shape"
    EPOCH_JUMP = "epoch-jump"


@dataclass(frozen=True, slots=True)
class Verdict:
    why: Reason | None = None
    step: int | None = None

    @property
    def ok(self) -> bool:
        return self.why is None

    def __bool__(self) -> bool:
        return self.ok


OK = Verdict()


def evaluate(
    reader: Reader, tx: ops.SignedTransaction, auth: Authoriser
) -> tuple[Verdict, Overlay[Reader]]:
    layer = Overlay(reader)
    if not tx.verify():
        return Verdict(Reason.SIGNATURE), layer
    for i, step in enumerate(tx.steps):
        m = step.mutation
        if not auth.may_write(layer, tx.author, m.store):
            return Verdict(Reason.AUTHORITY, i), layer
        if (why := _data_row_shape(layer, auth, m)) is not None:
            return Verdict(why, i), layer
        for g in step.guards:
            if not holds(layer, g):
                return Verdict(Reason.GUARD, i), layer
        layer.apply(m, tx.raw)
    return OK, layer


def _data_row_shape(layer: Reader, auth: Authoriser, m: ops.Mutation) -> Reason | None:
    """HERE AND NOWHERE ELSE. `evaluate` serves both the admission door and settlement, so one
    check binds both; a copy in `Mempool.valid` alone is how the two halves came apart over
    duplicate transactions.

    Management rows are exempt from both, and must be: nodes enforce authorisation out of store 0,
    so it is never encrypted and its names are structured (`grant/` + pubkey) rather than blinded.
    The one management row with a rule of its own is a store's epoch counter."""
    if isinstance(m, ops.Del):
        if m.store == ops.STORE_MANAGEMENT and auth.epoch_target(m.name) is not None:
            return Reason.EPOCH_JUMP
        return None
    if m.store == ops.STORE_MANAGEMENT:
        target = auth.epoch_target(m.name)
        return None if target is None else _epoch_step(layer, auth, m, target)
    if len(m.name) != crypto.DIGEST_SIZE:
        # A name a node can read is a name it can correlate. The client API types this as a
        # `NameToken`; the width is what stops a plaintext name arriving by accident.
        return Reason.NAME_SHAPE
    if m.epoch != auth.current_epoch(m.store, layer):
        # Written under a key that is no longer the one readers will reach for. Refused rather
        # than stored, so a stale ciphertext never becomes the current value of a row.
        return Reason.EPOCH
    return None


def _epoch_step(layer: Reader, auth: Authoriser, m: ops.Set, target: int) -> Reason | None:
    """One at a time and forwards only, PER STORE -- `target` is the store whose epoch this row
    carries, so rotating store 2 says nothing about store 1's counter. A keyepoch that goes
    backwards asks every client to encrypt under a key readers have already moved off."""
    try:
        want = codec.as_int(codec.decode(m.value))
    except DudeError:
        return Reason.EPOCH_JUMP
    return None if want == auth.current_epoch(target, layer) + 1 else Reason.EPOCH_JUMP


def vouched(reader: Reader, store: int, name: bytes, credential: bytes) -> crypto.PublicKey | None:
    held = reader.get(store, name)
    if held is None or not credential:
        return None
    try:
        cred = ops.SignedTransaction.decode(credential)
    except DudeError:
        return None
    if not cred.verify():
        return None
    want = ops.value_digest(held.value)
    for step in cred.steps:
        m = step.mutation
        if (
            m.store == store
            and m.name == name
            and isinstance(m, ops.Set)
            and ops.value_digest(m.value) == want
        ):
            return cred.author
    return None


class Reject(NamedTuple):
    tx: ops.SignedTransaction
    verdict: Verdict


class Screened(NamedTuple):
    survivors: tuple[ops.SignedTransaction, ...]
    rejects: tuple[Reject, ...]


def would_apply(
    reader: Reader, batch: tuple[ops.SignedTransaction, ...], auth: Authoriser
) -> Screened:
    return apply_to(Overlay(reader), batch, auth)


def apply_to(
    target: Overlay[Any],
    batch: tuple[ops.SignedTransaction, ...],
    auth: Authoriser,
) -> Screened:
    keep: list[ops.SignedTransaction] = []
    drop: list[Reject] = []
    seen: set[crypto.Digest] = set()
    for tx in batch:
        # SAME DEDUP AS `StoreWriter._apply_within`, and it must stay the same: this half
        # computes the anchors a block is signed with, that half decides what the block actually
        # settles. Dropping a within-batch duplicate in only one of them made the two disagree by
        # a whole log position -- `_expect_anchors` raises InvariantError on the settle path, and
        # the follower's `_adopt` has no such check and would commit a block whose signed height
        # and A_log describe a state no node holds.
        if tx.op_hash in seen:
            drop.append(Reject(tx, Verdict(Reason.SETTLED)))
            continue
        verdict, layer = evaluate(target, tx, auth)
        if verdict:
            target.absorb(layer)
            seen.add(tx.op_hash)
            keep.append(tx)
        else:
            drop.append(Reject(tx, verdict))
    return Screened(tuple(keep), tuple(drop))
