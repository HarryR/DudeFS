# DudeFS — the compactor (log-compaction, DESIGN §12 rev 6).
#
# The compactor holds the group key (a `compact`-capability delegate, §15) and
# folds the committed set to a cut, then SELECTS what to retain: every live key's
# winner op stays in place, plus resurrection-mask tombstones and the
# control-plane liveness set; everything else below the cut is `dead`. Nothing is
# materialized or re-encrypted — the retained winners ARE the baseline, in native
# ciphertext-op form. A bootstrap client reconstructs the barrier from them via
# `barrier_state` (mutations-only LWW + the attempts sidecar), and A4 holds:
# retained-bootstrap ≡ full-history fold.
#
# Zero-knowledge forces the oracle upward: a node cannot see supersession, so only
# the compactor (which decrypts) can compute the dead set. Cost ∝ churn.

from __future__ import annotations

from dataclasses import dataclass

from . import artifacts as A
from . import crypto, fold
from .artifacts import VERSION_ABSENT, Heads, Op
from .handlers import data as data_handler
from .handlers.data import Opaque


@dataclass(frozen=True)
class CompactResult:
    """What a checkpoint carries (DESIGN §12): the pinned cut + audit root, the
    incremental `dead` GC delta, the `retained` ops in place, and the `attempts`
    sidecar (cleartext here; the checkpoint body encrypts it)."""

    cut: Heads
    state_root: bytes
    dead: list[bytes]  # newly-dead op hashes ≤ cut (the GC delta)
    retained: list[Op]  # retained ops: winners + resurrection masks + control liveness
    attempts: dict[bytes, int]  # live keys with a nonzero attempt at the cut


def compact(
    committed_ops: list[Op],
    keyring: fold.Keyring,
    genesis: fold.Genesis,
    cut: Heads,
    aead_suite: bytes | None = None,
) -> CompactResult:
    """Fold the covered set to the cut and select the retained set (DESIGN §12)."""
    aead = crypto.AEAD_SUITE if aead_suite is None else aead_suite
    deduped = list({o.op_hash: o for o in committed_ops}.values())
    covered = [o for o in deduped if fold._covered(o, cut)]
    r = fold.fold(covered, keyring, genesis, aead_suite=aead)
    barrier = fold.make_barrier(r)  # live keys -> {value, version, attempt}

    winners = {e["version"] for e in barrier.values()}
    attempts = {k: e["attempt"] for k, e in barrier.items() if e["attempt"] > 0}

    by_hash = {o.op_hash: o for o in covered}
    # resurrection mask (NOTES 29b): a retained multi-key winner replays ALL its
    # mutations at bootstrap; a key it set that was later DELETED below the cut must
    # keep its tombstone, or bootstrap resurrects a key full-history clients hold
    # dead. The killing tombstone's hash IS that key's current `version`.
    masks: set[bytes] = set()
    for wh in winners:
        w = by_hash.get(wh)
        if w is None or w.is_control:
            continue
        d = data_handler.decode(w, keyring, aead)
        if isinstance(d, Opaque):
            continue
        for m in d.mutations:
            meta = r.meta.get(m[1])
            if meta is not None and not meta.present and meta.version != VERSION_ABSENT:
                masks.add(meta.version)

    # control-plane liveness set (NOTES 29e): certs/revocations, wrap-sets, roster,
    # endpoints, checkpoints never GC. POC keeps every control op ≤ cut (tiny).
    control_live = {o.op_hash for o in covered if o.is_control}

    keep = winners | masks | control_live
    retained = [by_hash[h] for h in keep if h in by_hash]
    dead = [o.op_hash for o in covered if o.op_hash not in keep]
    return CompactResult(cut, fold.state_root(r), dead, retained, attempts)


def retained_commitment(retained: list[Op]) -> dict[bytes, tuple[int, bytes]]:
    """The per-author `(count, digest)` over retained op-hashes (DESIGN §12,
    NOTES 29c) — the checkpoint's `retained` field. Plaintext (hashes are public
    metadata). Lets a node verify below-cut completeness locally and localizes an
    omission to a single author, so a sparse below-cut log stays checkable without
    a full state fetch. Self-contained: the digest covers the FULL retained set."""
    by_author: dict[bytes, list[bytes]] = {}
    for op in retained:
        by_author.setdefault(op.author, []).append(op.op_hash)
    return {a: (len(hs), crypto.h(b"".join(sorted(hs)))) for a, hs in by_author.items()}


def barrier_state(
    retained: list[Op],
    attempts: dict[bytes, int],
    keyring: fold.Keyring,
    aead_suite: bytes | None = None,
) -> fold.BarrierState:
    """Reconstruct the barrier from the retained winner ops (DESIGN §12 bootstrap):
    a MUTATIONS-ONLY LWW fold in `(hlc, author, seq, op_hash)` order — NO guard
    re-evaluation (reading settled state, not re-deciding CAS) — then apply the
    attempts sidecar. A4: equals `make_barrier` of the full fold below the cut."""
    aead = crypto.AEAD_SUITE if aead_suite is None else aead_suite
    live: dict[bytes, tuple[bytes, bytes]] = {}  # key -> (value, version)
    for op in sorted((o for o in retained if not o.is_control), key=fold._total_order_key):
        d = data_handler.decode(op, keyring, aead)
        if isinstance(d, Opaque):
            continue
        for m in d.mutations:
            if m[0] == A.Mutation.SET:
                live[m[1]] = (m[2], op.op_hash)
            elif m[0] == A.Mutation.DEL:
                live.pop(m[1], None)
    return {
        k: {"value": v, "version": ver, "attempt": attempts.get(k, 0)}
        for k, (v, ver) in live.items()
    }
