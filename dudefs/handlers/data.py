# DudeFS L6 — the data/txn handler (client-only).
#
# ARCHITECTURE L6 / DESIGN §5, §6, §7.
#
#   decode(op, keyring)      -> Txn | Opaque(reason)     # AEAD open + parse
#   evaluate(txn, view)      -> EvalResult                # guards + mutations + slot preimage
#
# The handler NEVER touches lineage/attribution/ordering — L5 (fold.py) owns
# those (ARCHITECTURE L5). This module only: opens the ciphertext, parses the
# guarded transaction, and evaluates guards against a StateView.

from __future__ import annotations

from enum import Enum, auto
from typing import Protocol

from .. import artifacts as A
from ..artifacts import Op, Txn


class StateReader(Protocol):
    """Structural view of fold state for guard evaluation — decouples the
    handler (L6) from the fold's concrete StateView (L5), no circular import."""

    def get(self, key: bytes) -> tuple[bool, bytes | None, bytes, int]: ...


# keyepoch -> {"data_key": .., "slot_secret": ..} (DESIGN §3).
type Keyring = dict[int, dict[str, bytes]]


class OpaqueReason(Enum):
    """Why a data payload could not be interpreted (diagnostic only — L5
    attributes an Opaque purely by tag-equality, DESIGN §6)."""

    NO_KEY = auto()  # no group key held for the op's keyepoch
    AEAD_OPEN_FAILED = auto()  # authentication failure (⊥)
    MALFORMED_TXN = auto()  # decrypted, but not a well-formed Txn


class Opaque:
    """A payload this handler could not interpret (undecryptable, or malformed
    plaintext). Carries a typed reason for diagnostics only."""

    __slots__ = ("reason",)

    def __init__(self, reason: OpaqueReason):
        self.reason = reason

    def __repr__(self):
        return f"Opaque({self.reason})"


class EvalResult:
    __slots__ = ("guards_ok", "mutations", "slot_preimage")

    def __init__(
        self,
        guards_ok: bool,
        mutations: list[list[bytes]],
        slot_preimage: tuple[bytes, bytes, int] | None,
    ):
        self.guards_ok = guards_ok
        self.mutations = mutations  # list of [op, path, value?]
        self.slot_preimage = slot_preimage  # (key, version, attempt) | None


def decode(op: Op, keyring: Keyring) -> Txn | Opaque:
    """Open a data op's payload and parse the Txn, or return Opaque. keyring:
    {keyepoch: {"data_key":.., "slot_secret":..}} (DESIGN §3). Total over
    arbitrary envelopes: a missing/mistyped keyepoch or payload field is
    Opaque, never a raised KeyError (NOTES item 17)."""
    if not isinstance(op, A.DataOp):
        return Opaque(OpaqueReason.MALFORMED_TXN)  # a control/invalid op carries no data payload
    try:
        ring = keyring.get(op.keyepoch)
        if ring is None:
            return Opaque(OpaqueReason.NO_KEY)
        pt = op.open_payload(ring["data_key"])
    except (KeyError, A.ArtifactError, A.codec.CodecError):
        return Opaque(OpaqueReason.MALFORMED_TXN)  # unreadable envelope fields
    if pt is None:
        return Opaque(OpaqueReason.AEAD_OPEN_FAILED)  # authentication failure (⊥)
    try:
        return A.Txn.decode(pt)
    except Exception:
        return Opaque(OpaqueReason.MALFORMED_TXN)


def evaluate(txn: Txn, view: StateReader) -> EvalResult:
    """Evaluate guards against `view` (state produced by predecessors in total
    order — DESIGN §6, A6). Returns guard result, the mutation list, and the
    restated slot preimage (which L5 checks against the public tag)."""
    guards_ok = all(_eval_guard(g, view) for g in txn.guards)
    return EvalResult(guards_ok, txn.mutations, txn.slot)


def _eval_guard(guard: list[bytes], view: StateReader) -> bool:
    if not (isinstance(guard, list) and len(guard) >= 2):
        return False
    kind, key = guard[0], guard[1]
    present, value, version, _attempt = view.get(key)
    if kind == A.Guard.ABSENT:
        return not present
    if kind == A.Guard.PRESENT:
        return present
    if kind == A.Guard.VALUE_EQ:
        return present and len(guard) >= 3 and value == guard[2]
    if kind == A.Guard.VERSION_EQ:
        # version-CAS: matches a live value OR a tombstone's anchor version.
        return len(guard) >= 3 and version == guard[2] and version != A.VERSION_ABSENT
    return False  # unknown guard predicate -> guard fails (fail-closed)
