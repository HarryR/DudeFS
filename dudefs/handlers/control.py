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

from collections.abc import Callable, Iterable, Mapping
from dataclasses import dataclass
from typing import Any, ClassVar

from .. import codec, crypto
from ..artifacts import HLC, BytesEnum, Heads, Op, RetainedEntry

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


# ---- the decoded control body — a tagged union, one frozen dataclass per kind #
# `decode()` parses the plaintext bencode into exactly one of these (or None). The
# TYPE is the discriminant (was a `dict[bytes, Any]` keyed by `BK_KIND` — a
# string-keyed map faking a struct); consumers `match`/`isinstance` and read `.field`.
# Each carries a `KIND` ClassVar so a generic consumer can recover the wire kind.


@dataclass(frozen=True)
class CertIssue:
    KIND: ClassVar[ControlKind] = ControlKind.CERT_ISSUE
    subject: bytes
    caps: list[bytes]
    epoch: int


@dataclass(frozen=True)
class CertRevoke:
    KIND: ClassVar[ControlKind] = ControlKind.CERT_REVOKE
    subject: bytes


@dataclass(frozen=True)
class Roster:
    KIND: ClassVar[ControlKind] = ControlKind.ROSTER
    from_epoch: int
    roster: list[bytes]
    sync_frontier: Heads
    recovery: bytes | None  # NOTES 36a: an op_hash = the fiat recovery pairing; None = normal


@dataclass(frozen=True)
class Rotate:
    KIND: ClassVar[ControlKind] = ControlKind.ROTATE
    keyepoch: int


@dataclass(frozen=True)
class WrapSet:
    KIND: ClassVar[ControlKind] = ControlKind.WRAP_SET
    keyepoch: int
    wraps: dict[bytes, bytes]  # member_pub -> sealed group key


@dataclass(frozen=True)
class Checkpoint:
    KIND: ClassVar[ControlKind] = ControlKind.CHECKPOINT
    cut: Heads
    state_acc: bytes
    dead: list[bytes]
    retained: dict[bytes, RetainedEntry]  # author -> (count, digest)
    attempts: bytes
    keyepoch: int
    horizon: HLC  # the finality frontier F the cut was sealed at (§9)
    seq: int = 0  # monotone checkpoint sequence; the public slot it contends (WP-F(c))


@dataclass(frozen=True)
class PverActivate:
    KIND: ClassVar[ControlKind] = ControlKind.PVER_ACTIVATE
    pver: int


@dataclass(frozen=True)
class EndpointRecord:
    KIND: ClassVar[ControlKind] = ControlKind.ENDPOINT
    subject: bytes
    addrs: list[tuple[bytes, bytes, dict[bytes, bytes]]]  # (transport, uri, opts); empty = removal


type ControlBody = (
    CertIssue | CertRevoke | Roster | Rotate | WrapSet | Checkpoint | PverActivate | EndpointRecord
)


# ---- per-kind body validators (NOTES item 17) ------------------------------ #
# Each takes the raw decoded bencode dict and returns the typed body, or raises —
# decode() maps any raise to None (the op folds `invalid`).


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


def _v_cert_issue(b: dict[bytes, codec.Bencodable]) -> CertIssue:
    return CertIssue(
        subject=codec.as_bytes(codec.field(b, b"subject")),
        caps=[codec.as_bytes(c) for c in codec.as_seq(codec.field(b, b"caps"))],
        epoch=_uint(codec.field(b, b"epoch")),
    )


def _v_cert_revoke(b: dict[bytes, codec.Bencodable]) -> CertRevoke:
    return CertRevoke(subject=codec.as_bytes(codec.field(b, b"subject")))


def _v_roster(b: dict[bytes, codec.Bencodable]) -> Roster:
    roster = [codec.as_bytes(p) for p in codec.as_seq(codec.field(b, b"roster"))]
    # DESIGN §13: roster size is always odd — even voting-member counts are
    # rejected by validation (they enlarge quorums without adding tolerance).
    if len(roster) == 0 or len(roster) % 2 == 0:
        raise codec.CodecError("roster must have an odd, non-zero voting-member count")
    recovery = b.get(b"recovery")  # present => the fiat recovery trigger (root-only)
    return Roster(
        from_epoch=_uint(codec.field(b, b"from_epoch")),
        roster=roster,
        sync_frontier=_heads(codec.field(b, b"sync_frontier")),
        recovery=codec.as_bytes(recovery) if recovery is not None else None,
    )


def _v_rotate(b: dict[bytes, codec.Bencodable]) -> Rotate:
    return Rotate(keyepoch=_uint(codec.field(b, b"keyepoch")))


def _v_wrap_set(b: dict[bytes, codec.Bencodable]) -> WrapSet:
    return WrapSet(
        keyepoch=_uint(codec.field(b, b"keyepoch")),
        wraps={k: codec.as_bytes(v) for k, v in codec.as_dict(codec.field(b, b"wraps")).items()},
    )


def _retained(v: codec.Bencodable) -> dict[bytes, RetainedEntry]:
    """Per-author retained-set commitment: {author: (size, digest)} (DESIGN §12
    rev 6, NOTES 29c). Plaintext — op-hashes are public metadata."""
    out: dict[bytes, RetainedEntry] = {}
    for author, entry in codec.as_dict(v).items():
        pair = codec.as_seq(entry, 2)
        out[author] = RetainedEntry(_uint(pair[0]), codec.as_bytes(pair[1]))
    return out


def _v_checkpoint(b: dict[bytes, codec.Bencodable]) -> Checkpoint:
    # rev 6 (DESIGN §12): log-compaction — no snapshot blob. `dead` is the incremental
    # GC delta; `retained` commits the FULL retained set ≤ cut; `attempts` the sidecar.
    return Checkpoint(
        cut=_heads(codec.field(b, b"cut")),
        state_acc=codec.as_bytes(codec.field(b, b"state_acc")),
        dead=[codec.as_bytes(h) for h in codec.as_seq(codec.field(b, b"dead"))],
        retained=_retained(codec.field(b, b"retained")),
        attempts=codec.as_bytes(codec.field(b, b"attempts")),
        keyepoch=_uint(codec.field(b, b"keyepoch")),
        horizon=HLC.decode(codec.field(b, b"horizon")),
        seq=_uint(codec.field(b, b"seq")),
    )


def _v_pver(b: dict[bytes, codec.Bencodable]) -> PverActivate:
    return PverActivate(pver=_uint(codec.field(b, b"pver")))


def _v_endpoint(b: dict[bytes, codec.Bencodable]) -> EndpointRecord:
    # Node reachability (PROTOCOL §7.1, NOTES 58): a root-signed record mapping a
    # node's pubkey -> its access methods. `addrs` is a list of (transport, uri, opts);
    # opts carries the L_msg profile. Latest-wins per subject; EMPTY addrs = removal.
    addrs: list[tuple[bytes, bytes, dict[bytes, bytes]]] = []
    for entry in codec.as_seq(codec.field(b, b"addrs")):
        e = codec.as_seq(entry, 3)
        opts = {k: codec.as_bytes(v) for k, v in codec.as_dict(e[2]).items()}
        addrs.append((codec.as_bytes(e[0]), codec.as_bytes(e[1]), opts))
    return EndpointRecord(subject=codec.as_bytes(codec.field(b, b"subject")), addrs=addrs)


_VALIDATORS: dict[ControlKind, Callable[[dict[bytes, codec.Bencodable]], ControlBody]] = {
    ControlKind.CERT_ISSUE: _v_cert_issue,
    ControlKind.CERT_REVOKE: _v_cert_revoke,
    ControlKind.ROSTER: _v_roster,
    ControlKind.ROTATE: _v_rotate,
    ControlKind.WRAP_SET: _v_wrap_set,
    ControlKind.CHECKPOINT: _v_checkpoint,
    ControlKind.PVER_ACTIVATE: _v_pver,
    ControlKind.ENDPOINT: _v_endpoint,
}


def decode(op: Op) -> ControlBody | None:
    """Parse AND validate a control op's plaintext body into its typed `ControlBody`
    (the TYPE is the kind), or None if malformed or unknown — the op then folds
    `invalid`. Total: never raises on wire input (NOTES item 17)."""
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


def roster_body(
    from_epoch: int,
    roster_pubs: list[bytes],
    sync_frontier: Heads,
    recovery: bytes | None = None,
) -> bytes:
    body: dict[bytes, Any] = {
        BK_KIND: ControlKind.ROSTER,
        b"from_epoch": int(from_epoch),
        b"roster": [bytes(p) for p in roster_pubs],
        b"sync_frontier": {a: [s, h] for a, (s, h) in sync_frontier.items()},
    }
    if recovery is not None:  # the fiat recovery pairing; omit for a normal roster
        body[b"recovery"] = recovery
    return codec.encode(body)


def rotate_body(keyepoch: int) -> bytes:
    return codec.encode({BK_KIND: ControlKind.ROTATE, b"keyepoch": int(keyepoch)})


def endpoint_body(subject: bytes, addrs: list[tuple[bytes, bytes, dict[bytes, bytes]]]) -> bytes:
    """A root-signed node reachability record (PROTOCOL §7.1 / NOTES 58): `subject`
    is the node pubkey, `addrs` a list of (transport, uri, opts) — opts carries the
    L_msg profile. Latest-wins per subject; an EMPTY `addrs` removes the node."""
    return codec.encode(
        {
            BK_KIND: ControlKind.ENDPOINT,
            b"subject": subject,
            b"addrs": [[t, u, dict(o)] for (t, u, o) in addrs],
        }
    )


def wrap_set_body(keyepoch: int, wraps: dict[bytes, bytes]) -> bytes:
    """Low-level encoder: `wraps` maps each member's public key to its already-
    sealed group-key ciphertext. Use `sealed_wrap_set_body` to build `wraps`."""
    return codec.encode(
        {
            BK_KIND: ControlKind.WRAP_SET,
            b"keyepoch": int(keyepoch),
            b"wraps": dict(wraps),
        }
    )


def sealed_wrap_set_body(keyepoch: int, group_key: bytes, members: list[bytes]) -> bytes:
    """Build a WRAP_SET distributing `group_key` (K_epoch) to each member: an
    `sbx1` sealed box per member public key (DESIGN §3 / §15). Only that member's
    secret key opens its wrap; the enclosing control op's signature authenticates
    the distribution. `members` are Ed25519 public keys (roster + client certs)."""
    wraps = {m: crypto.seal_to(m, group_key) for m in members}
    return wrap_set_body(keyepoch, wraps)


def unwrap_group_key(body: WrapSet, member_sk: bytes) -> bytes | None:
    """Member-side: recover K_epoch from a decoded WRAP_SET body, or None if this
    member has no wrap in the set (or it fails to open)."""
    sealed = body.wraps.get(crypto.SIGNER.public(member_sk))
    if sealed is None:
        return None
    return crypto.open_sealed(member_sk, sealed)


def checkpoint_body(
    cut: Heads,
    state_acc: bytes,
    dead: list[bytes],
    retained: Mapping[bytes, tuple[int, bytes]],
    attempts: bytes,
    keyepoch: int,
    horizon: HLC,
    seq: int = 0,
) -> bytes:
    """A rev-6 checkpoint (DESIGN §12): the pinned `cut`, the `state_acc` audit
    anchor, the incremental `dead` delta, the per-author `retained` commitment,
    the encrypted `attempts` sidecar, the `horizon` finality frontier F the cut was
    sealed at (the void / below-horizon guard value, §8), and the monotone `seq` —
    the checkpoint's position in the chain and the public slot it contends (WP-F(c),
    like a roster epoch). No snapshot."""
    cut_enc = {a: [s, h] for a, (s, h) in cut.items()}
    retained_enc = {a: [c, d] for a, (c, d) in retained.items()}
    return codec.encode(
        {
            BK_KIND: ControlKind.CHECKPOINT,
            b"cut": cut_enc,
            b"state_acc": state_acc,
            b"dead": list(dead),
            b"retained": retained_enc,
            b"attempts": attempts,
            b"keyepoch": int(keyepoch),
            b"horizon": list(horizon.encode()),
            b"seq": int(seq),
        }
    )


def pver_body(pver: int) -> bytes:
    return codec.encode({BK_KIND: ControlKind.PVER_ACTIVATE, b"pver": int(pver)})
