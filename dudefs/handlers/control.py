# DudeFS L6 — control-plane handlers (nodes AND clients; no keyring).
#
# ARCHITECTURE L6 / DESIGN §12, §13, §15, §16 / NOTES §M2.5.
#
# Control ops carry PLAINTEXT bodies (the explicit carve-out from
# zero-knowledge, DESIGN §5): roster, cert issue/revoke, key rotation,
# wrap-sets, checkpoints, pver fences. This module decodes AND validates
# bodies per kind (a malformed manager body folds `invalid`, never crashes the
# fold — NOTES item 17) and provides builders; the state machine that applies
# them lives in L5 (fold.ControlState) so both the full profile (clients) and
# the control profile (nodes) share it.

from __future__ import annotations

from collections.abc import Callable, Iterable
from typing import Any

from .. import codec
from ..artifacts import HLC, BytesEnum, Heads, Op

# Body discriminator (a field key, not a value vocabulary).
BK_KIND = b"kind"


class ControlKind(BytesEnum):
    """The kind of a control-op body (DESIGN §12, §13, §15, §16). An unknown
    kind decodes to None -> the op folds `invalid` (fail-closed; new kinds are
    lane-3 gated, DESIGN §16)."""

    CERT_ISSUE = b"cert_issue"
    CERT_REVOKE = b"cert_revoke"
    ROSTER = b"roster"
    ROTATE = b"rotate"
    WRAP_SET = b"wrap_set"
    CHECKPOINT = b"checkpoint"
    PVER_ACTIVATE = b"pver_activate"
    ENDPOINT = b"endpoint"


class Cap(BytesEnum):
    """Capability certs grant (DESIGN §15)."""

    WRITE = b"write"
    STORE = b"store"
    COMPACT = b"compact"
    MANAGE_ROSTER = b"manage-roster"
    ISSUE_REVOKE = b"issue-revoke"


# ---- per-kind body validators (NOTES item 17) ------------------------------ #
# Each takes the raw decoded dict and returns a normalized body (typed field
# values; `cut`/frontiers as Heads) or raises — decode() maps any raise to None.


def _uint(v: codec.Bencodable) -> int:
    n = codec.as_int(v)
    if n < 0:
        raise codec.CodecError("expected a non-negative integer")
    return n


def _heads(v: codec.Bencodable) -> Heads:
    out: Heads = {}
    for author, entry in codec.as_dict(v).items():
        pair = codec.as_seq(entry, 2)
        out[author] = (_uint(pair[0]), codec.as_bytes(pair[1]))
    return out


def _v_cert_issue(b: dict[bytes, codec.Bencodable]) -> dict[bytes, Any]:
    return {
        BK_KIND: ControlKind.CERT_ISSUE,
        b"subject": codec.as_bytes(codec.field(b, b"subject")),
        b"caps": [codec.as_bytes(c) for c in codec.as_seq(codec.field(b, b"caps"))],
        b"epoch": _uint(codec.field(b, b"epoch")),
    }


def _v_cert_revoke(b: dict[bytes, codec.Bencodable]) -> dict[bytes, Any]:
    return {
        BK_KIND: ControlKind.CERT_REVOKE,
        b"subject": codec.as_bytes(codec.field(b, b"subject")),
    }


def _v_roster(b: dict[bytes, codec.Bencodable]) -> dict[bytes, Any]:
    roster = [codec.as_bytes(p) for p in codec.as_seq(codec.field(b, b"roster"))]
    # DESIGN §13: roster size is always odd — even voting-member counts are
    # rejected by validation (they enlarge quorums without adding tolerance).
    if len(roster) == 0 or len(roster) % 2 == 0:
        raise codec.CodecError("roster must have an odd, non-zero voting-member count")
    return {
        BK_KIND: ControlKind.ROSTER,
        b"from_epoch": _uint(codec.field(b, b"from_epoch")),
        b"roster": roster,
        b"sync_frontier": _heads(codec.field(b, b"sync_frontier")),
    }


def _v_rotate(b: dict[bytes, codec.Bencodable]) -> dict[bytes, Any]:
    return {BK_KIND: ControlKind.ROTATE, b"keyepoch": _uint(codec.field(b, b"keyepoch"))}


def _v_wrap_set(b: dict[bytes, codec.Bencodable]) -> dict[bytes, Any]:
    wraps = {k: codec.as_bytes(v) for k, v in codec.as_dict(codec.field(b, b"wraps")).items()}
    return {
        BK_KIND: ControlKind.WRAP_SET,
        b"keyepoch": _uint(codec.field(b, b"keyepoch")),
        b"wraps": wraps,
    }


def _retained(v: codec.Bencodable) -> dict[bytes, tuple[int, bytes]]:
    """Per-author retained-set commitment: {author: (count, digest)} (DESIGN §12
    rev 6, NOTES 29c). Plaintext — op-hashes are public metadata."""
    out: dict[bytes, tuple[int, bytes]] = {}
    for author, entry in codec.as_dict(v).items():
        pair = codec.as_seq(entry, 2)
        out[author] = (_uint(pair[0]), codec.as_bytes(pair[1]))
    return out


def _v_checkpoint(b: dict[bytes, codec.Bencodable]) -> dict[bytes, Any]:
    # rev 6 (DESIGN §12): log-compaction — no snapshot blob. `dead` is the
    # incremental GC delta; `retained` commits to the FULL retained set ≤ cut;
    # `attempts` is the encrypted nonzero-attempt sidecar.
    return {
        BK_KIND: ControlKind.CHECKPOINT,
        b"cut": _heads(codec.field(b, b"cut")),
        b"state_root": codec.as_bytes(codec.field(b, b"state_root")),
        b"dead": [codec.as_bytes(h) for h in codec.as_seq(codec.field(b, b"dead"))],
        b"retained": _retained(codec.field(b, b"retained")),
        b"attempts": codec.as_bytes(codec.field(b, b"attempts")),
        b"keyepoch": _uint(codec.field(b, b"keyepoch")),
        # the finality frontier F the cut was sealed at (§9): every op ≤ cut has
        # hlc ≤ F. THE horizon value for §8's void/below-horizon guards (WP1.5).
        b"horizon": HLC.decode(codec.field(b, b"horizon")),
    }


def _v_pver(b: dict[bytes, codec.Bencodable]) -> dict[bytes, Any]:
    return {BK_KIND: ControlKind.PVER_ACTIVATE, b"pver": _uint(codec.field(b, b"pver"))}


def _v_endpoint(_b: dict[bytes, codec.Bencodable]) -> dict[bytes, Any]:
    # Schema open until M5 (PROTOCOL §7.1); accepted as an inert body.
    return {BK_KIND: ControlKind.ENDPOINT}


_VALIDATORS: dict[ControlKind, Callable[[dict[bytes, codec.Bencodable]], dict[bytes, Any]]] = {
    ControlKind.CERT_ISSUE: _v_cert_issue,
    ControlKind.CERT_REVOKE: _v_cert_revoke,
    ControlKind.ROSTER: _v_roster,
    ControlKind.ROTATE: _v_rotate,
    ControlKind.WRAP_SET: _v_wrap_set,
    ControlKind.CHECKPOINT: _v_checkpoint,
    ControlKind.PVER_ACTIVATE: _v_pver,
    ControlKind.ENDPOINT: _v_endpoint,
}


def decode(op: Op) -> dict[bytes, Any] | None:
    """Parse AND validate a control op's plaintext body. Returns a normalized
    body dict (known `kind`, per-kind schema checked, `cut`/frontier fields as
    Heads) or None if malformed or unknown — the op then folds `invalid`.
    Total: never raises on wire input (NOTES item 17)."""
    if not op.is_control:
        return None
    try:
        body = codec.decode(op.payload)
    except Exception:
        return None
    if not isinstance(body, dict) or BK_KIND not in body:
        return None
    try:
        kind = ControlKind(body[BK_KIND])
    except ValueError:
        return None  # unknown kind — fail-closed (lane-3 gates new kinds)
    try:
        return _VALIDATORS[kind](body)
    except (codec.CodecError, KeyError, TypeError):
        return None


# --------------------------------------------------------------------------- #
# Body builders (used by the manager/tests; PROTOCOL §3)                       #
# --------------------------------------------------------------------------- #


def cert_issue_body(subject_pub: bytes, caps: Iterable[bytes], epoch: int) -> bytes:
    return codec.encode(
        {
            BK_KIND: ControlKind.CERT_ISSUE,
            b"subject": subject_pub,
            b"caps": [bytes(c) for c in caps],
            b"epoch": int(epoch),
        }
    )


def cert_revoke_body(subject_pub: bytes) -> bytes:
    return codec.encode({BK_KIND: ControlKind.CERT_REVOKE, b"subject": subject_pub})


def roster_body(from_epoch: int, roster_pubs: list[bytes], sync_frontier: Heads) -> bytes:
    sf = {a: [s, h] for a, (s, h) in sync_frontier.items()}
    return codec.encode(
        {
            BK_KIND: ControlKind.ROSTER,
            b"from_epoch": int(from_epoch),
            b"roster": [bytes(p) for p in roster_pubs],
            b"sync_frontier": sf,
        }
    )


def rotate_body(keyepoch: int) -> bytes:
    return codec.encode({BK_KIND: ControlKind.ROTATE, b"keyepoch": int(keyepoch)})


def wrap_set_body(keyepoch: int, wraps: dict[bytes, bytes]) -> bytes:
    return codec.encode(
        {
            BK_KIND: ControlKind.WRAP_SET,
            b"keyepoch": int(keyepoch),
            b"wraps": dict(wraps),
        }
    )


def checkpoint_body(
    cut: Heads,
    state_root: bytes,
    dead: list[bytes],
    retained: dict[bytes, tuple[int, bytes]],
    attempts: bytes,
    keyepoch: int,
    horizon: HLC,
) -> bytes:
    """A rev-6 checkpoint (DESIGN §12): the pinned `cut`, the `state_root` audit
    anchor, the incremental `dead` delta, the per-author `retained` commitment,
    the encrypted `attempts` sidecar, and the `horizon` finality frontier F the
    cut was sealed at (the void / below-horizon guard value, §8). No snapshot."""
    cut_enc = {a: [s, h] for a, (s, h) in cut.items()}
    retained_enc = {a: [c, d] for a, (c, d) in retained.items()}
    return codec.encode(
        {
            BK_KIND: ControlKind.CHECKPOINT,
            b"cut": cut_enc,
            b"state_root": state_root,
            b"dead": list(dead),
            b"retained": retained_enc,
            b"attempts": attempts,
            b"keyepoch": int(keyepoch),
            b"horizon": list(horizon.encode()),
        }
    )


def pver_body(pver: int) -> bytes:
    return codec.encode({BK_KIND: ControlKind.PVER_ACTIVATE, b"pver": int(pver)})
