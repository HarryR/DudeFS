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
from . import codec, crypto, fold
from .artifacts import VERSION_ABSENT, Heads, Op
from .errors import DudeFSError
from .handlers import data as data_handler
from .handlers.data import Opaque


class CompactError(DudeFSError):
    """Base for compaction failures (errors.py hierarchy) — e.g. a checkpoint whose
    sealed sidecar will not open (wrong keyepoch / tampered)."""


# The attempts sidecar (DESIGN §12) travels the checkpoint encrypted under the group
# data_key — the same xcs1 AEAD as data payloads — because it maps KEYS (paths, which
# are content) to their CAS attempt counters, and confidentiality covers content +
# structure. `dude.ckpt.attempts` domain-separates it from payload ciphertext.
_ATTEMPTS_AAD = b"dude.ckpt.attempts"


def seal_attempts(attempts: dict[bytes, int], data_key: bytes) -> bytes:
    """Encrypt the attempts sidecar for the checkpoint's `attempts` field. Deterministic
    (SIV), so a reproducible checkpoint reproduces identical bytes. An empty sidecar
    carries nothing (b"")."""
    if not attempts:
        return b""
    return crypto.AEAD.seal(data_key, _ATTEMPTS_AAD, codec.encode(attempts))


def open_attempts(sealed: bytes, data_key: bytes) -> dict[bytes, int]:
    """The bootstrap inverse of `seal_attempts`: b"" -> {} (no sidecar). A failed open
    (wrong keyepoch / tamper) raises CompactError — LOUD, never a silently-empty dict,
    which would zero live keys' attempts and break A4."""
    if not sealed:
        return {}
    pt = crypto.AEAD.open(data_key, _ATTEMPTS_AAD, sealed)
    if pt is None:
        raise CompactError("attempts sidecar failed to open (wrong keyepoch or tampered)")
    return {codec.as_bytes(k): codec.as_int(v) for k, v in codec.as_dict(codec.decode(pt)).items()}


def verify_state_root(claimed: bytes, barrier: fold.BarrierState) -> None:
    """Audit a checkpoint at intake (WP-B / DESIGN §12): the state_root recomputed from
    the barrier a bootstrapping node RECONSTRUCTED from the retained set + sidecar MUST
    equal the checkpoint's claimed `state_root`. A mismatch means a forged or corrupt
    checkpoint — a tampered root, an omitted live winner, or a kept-superseded op that
    perturbs the reconstructed state — so raise loudly (a portable audit failure) and
    never adopt it. The trust surface §12 rests on: a lying compactor is caught by any
    node that recomputes."""
    got = fold.state_root_of_barrier(barrier)
    if got != claimed:
        raise CompactError(
            f"checkpoint state_root mismatch: claimed {claimed.hex()[:16]}… "
            f"but the reconstructed barrier hashes to {got.hex()[:16]}…"
        )


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


def _mut_meta(ops: list[Op], keyring: fold.Keyring) -> dict[bytes, tuple[bool, bytes]]:
    """A MUTATIONS-ONLY meta fold (no guard re-eval): key -> (present, version)
    where `version` is the last mutation's op_hash — a SET's hash for a live key,
    the killing DEL's hash (the tombstone) for a dead one.

    ONLY sound over a RETAINED set, whose ops are all applied (NOTES 34 applied-ops
    lemma). It must NOT be fed an arbitrary committed band: that band contains
    committed-but-REJECTED ops whose mutations never applied, and replaying them
    mutations-only would nominate a rejected write as its key's version and drop
    the real tombstone (finding 13). The compactor feeds it `prev_retained` only,
    then overlays the band's guard-evaluated `r.meta`."""
    meta: dict[bytes, tuple[bool, bytes]] = {}
    for op in sorted((o for o in ops if not o.is_control), key=fold._total_order_key):
        d = data_handler.decode(op, keyring)
        if isinstance(d, Opaque):
            continue
        for m in d.mutations:
            if m[0] == A.Mutation.SET:
                meta[m[1]] = (True, op.op_hash)
            elif m[0] == A.Mutation.DEL:
                meta[m[1]] = (False, op.op_hash)
    return meta


def compact(
    prev_retained: list[Op],
    prev_attempts: dict[bytes, int],
    prev_cut: Heads,
    tail: list[Op],
    keyring: fold.Keyring,
    genesis: fold.Genesis,
    cut: Heads,
) -> CompactResult:
    """INCREMENTAL compaction (DESIGN §12 rev 6, HANDOFF-R3 WP1.4 / Q4). Advance
    the checkpoint from `prev_cut` to `cut`, given the previous checkpoint's
    retained set + attempts sidecar and only the NEWLY-committed `tail`. Cost ∝
    churn since the last checkpoint, never ∝ history. Genesis-first is the
    degenerate `prev = ∅` (see `compact_genesis`).

    `dead` is the incremental GC delta `(prev_retained ∪ covered_tail) ∖
    new_retained` — the ops a node holding the previous baseline + this tail drops
    to reach the new baseline. A4 holds across BOTH the tail fold (winners/state)
    and the successive-checkpoint mask carry-forward (see `_mut_meta`)."""
    # precondition: the cut monotonically advances prev_cut (no author regresses).
    for author, (pseq, _ph) in prev_cut.items():
        entry = cut.get(author)
        if entry is None or entry[0] < pseq:
            raise ValueError("compact: cut must monotonically advance prev_cut")

    prev_data = [o for o in prev_retained if not o.is_control]
    prev_control = [o for o in prev_retained if o.is_control]
    prev_barrier = barrier_state(prev_data, prev_attempts, keyring)

    # the band (prev_cut, cut] — the only ops we re-fold. Sealing the barrier at
    # prev_cut (NOT the new cut) is what keeps these tail ops in the fold instead
    # of skipped as already-in-barrier.
    tail_new = list(
        {
            o.op_hash: o for o in tail if fold._covered(o, cut) and not fold._covered(o, prev_cut)
        }.values()
    )
    r = fold.fold(
        prev_control + tail_new,
        keyring,
        genesis,
        barrier=prev_barrier,
        cut_frontier=(prev_cut or None),
    )
    barrier = fold.make_barrier(r)  # authoritative live keys -> {value, version, attempt}
    winners = {e["version"] for e in barrier.values()}
    attempts = {k: e["attempt"] for k, e in barrier.items() if e["attempt"] > 0}

    # the universe available to retain: the previous baseline + the new band.
    universe = {o.op_hash: o for o in [*prev_retained, *tail_new]}

    # meta for the mask fixpoint (finding 13): mutations-only over prev_retained
    # ONLY — sound there by the applied-ops lemma, and it still carries the
    # tombstone of a key that died below prev_cut (the two-checkpoint carry-
    # forward) — OVERLAID by the band's guard-evaluated r.meta for every key the
    # band actually touched (version != ⊥). Feeding the whole committed band to a
    # mutations-only fold would treat REJECTED ops as applied and drop real
    # tombstones. The ⊥ guard stops a band attempt-only lineage (a rejected create
    # bumps the attempt but leaves version ⊥) from erasing a below-prev_cut tomb.
    meta_mut = _mut_meta(prev_data, keyring)
    for key, m in r.meta.items():
        if m.version != VERSION_ABSENT:
            meta_mut[key] = (m.present, m.version)

    # resurrection mask (NOTES 29b): a retained op replays ALL its mutations at
    # bootstrap; a key it set that is DEAD at the cut must keep its tombstone, or
    # bootstrap resurrects it. FIXPOINT — a mask tombstone can itself set a further
    # dead key, so scan newly-added masks too (else a chain W→X→Z leaks Z).
    masks: set[bytes] = set()
    frontier = set(winners)
    while frontier:
        nxt: set[bytes] = set()
        for wh in frontier:
            w = universe.get(wh)
            if w is None or w.is_control:
                continue
            d = data_handler.decode(w, keyring)
            if isinstance(d, Opaque):
                continue
            for m in d.mutations:
                mm = meta_mut.get(m[1])
                if mm is not None and not mm[0] and mm[1] != VERSION_ABSENT:
                    tomb = mm[1]
                    if tomb not in winners and tomb not in masks:
                        masks.add(tomb)
                        nxt.add(tomb)
        frontier = nxt

    # control-plane liveness (NOTES 29e): never GC. POC keeps every control op.
    control_live = {h for h, o in universe.items() if o.is_control}

    keep = winners | masks | control_live
    retained = [universe[h] for h in keep if h in universe]
    dead = [h for h in universe if h not in keep]  # (prev_retained ∪ tail) ∖ retained
    return CompactResult(cut, fold.state_root(r), dead, retained, attempts)


def compact_genesis(
    committed_ops: list[Op],
    keyring: fold.Keyring,
    genesis: fold.Genesis,
    cut: Heads,
) -> CompactResult:
    """The first checkpoint: the degenerate `prev = ∅` of `compact` — fold the
    whole committed set below `cut` from scratch (DESIGN §12)."""
    return compact([], {}, {}, committed_ops, keyring, genesis, cut)


def barrier_state(
    retained: list[Op],
    attempts: dict[bytes, int],
    keyring: fold.Keyring,
) -> fold.BarrierState:
    """Reconstruct the barrier from the retained winner ops (DESIGN §12 bootstrap):
    a MUTATIONS-ONLY LWW fold in `(hlc, author, seq, op_hash)` order — NO guard
    re-evaluation (reading settled state, not re-deciding CAS) — then apply the
    attempts sidecar. A4: equals `make_barrier` of the full fold below the cut."""
    live: dict[bytes, tuple[bytes, bytes]] = {}  # key -> (value, version)
    for op in sorted((o for o in retained if not o.is_control), key=fold._total_order_key):
        d = data_handler.decode(op, keyring)
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
