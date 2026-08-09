from __future__ import annotations

from dataclasses import dataclass
from enum import Enum
from typing import Any, NamedTuple, Protocol

from ..core import crypto
from ..core.errors import DudeError
from . import ops
from .layer import Overlay, Reader, holds


class Authoriser(Protocol):
    def may_write(self, reader: Reader, who: crypto.PublicKey, store_id: int) -> bool: ...


class Reason(Enum):
    INVALID = "invalid"

    SIGNATURE = "signature"
    AUTHORITY = "authority"
    GUARD = "guard"
    SETTLED = "settled"


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
        for g in step.guards:
            if not holds(layer, g):
                return Verdict(Reason.GUARD, i), layer
        layer.apply(m, tx.raw)
    return OK, layer


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
