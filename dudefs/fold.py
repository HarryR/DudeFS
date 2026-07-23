# DudeFS L5 — the fold (deterministic state derivation).
#
# ARCHITECTURE L5 / DESIGN §6, §7, §12, §15, §16 / FORMAL A1-A7 / NOTES §M2.5.
#
# State is a pure function of the *committed* op-set:
#     fold(committed_ops, keyring, genesis) -> FoldResult(state, verdicts, meta)
#
# Total order: (hlc, author, seq, op_hash) — the op_hash tail keeps the order
# total even against an equivocating author (DESIGN §4). Per-key lineage
# (version, attempt) plus the lineage-advance invariant (DESIGN §6) make every
# consumed slot advance the tag lineage — no wedge (A2). The invariant is
# UNIVERSAL: even an op that folds `invalid` consumes the slot its tag names
# (NOTES item 14) — nodes voted its ballot without seeing fold-positional
# invalidity, so not advancing would wedge the tag.
#
# Checkpoints partition the walk at their pinned *cut* (DESIGN §12): fold the
# covered set, apply the barrier (tombstone death, key-universe reset, pending
# pver activation), fold the tail. The barrier is NOT at the checkpoint op's
# own hlc position (NOTES item 13).
#
# This module (full profile) + the data handler is the FORMAL Lean-oracle
# target: byte-identical across implementations or bust.

from __future__ import annotations

from enum import StrEnum
from typing import NotRequired, TypedDict

from . import artifacts as A
from . import crypto, transports, tunables
from .artifacts import GENESIS_PREV, VERSION_ABSENT, Heads, Op, Txn
from .errors import DudeFSError
from .handlers import control as control_handler
from .handlers import data as data_handler
from .handlers.data import Opaque

# The highest fold-semantics version this build understands (DESIGN §16 lane 2).
# When a control op activates a higher version at a checkpoint barrier, the
# fold HALTS (FoldHalted) — fail-stop read-only at the sealed state, never
# misfold (NOTES item 15).
SUPPORTED_PVER = 0


class BarrierEntry(TypedDict):
    """A live key's state at a checkpoint barrier (DESIGN §12). rev 6: there is no
    snapshot blob — a bootstrap client reconstructs this from the retained winner
    ops + the attempts sidecar; a full-history client derives it. Same shape."""

    value: bytes
    version: bytes
    attempt: int


class Cert(TypedDict):
    """A folded capability cert (DESIGN §15)."""

    caps: set[bytes]
    revoked: bool


class Genesis(TypedDict):
    """Genesis config: the manager root pubkey + optional starting epochs. `roster`
    is the founding (epoch-`epoch`) voting set — the trust anchor a newcomer folds
    forward from to reconstruct roster-per-epoch (issue #3). Absent until the founding
    roster becomes an on-chain manager-signed op (issue #2)."""

    manager_pub: bytes
    epoch: NotRequired[int]
    keyepoch: NotRequired[int]
    pver: NotRequired[int]
    roster: NotRequired[list[bytes]]


# Client-held key material and the checkpoint barrier state (DESIGN §3, §12).
type Keyring = dict[int, dict[str, bytes]]  # keyepoch -> {data_key, slot_secret}
type BarrierState = dict[bytes, BarrierEntry]  # key -> {value, version, attempt}


def keyring_from_masters(masters: dict[int, bytes]) -> Keyring:
    """Build a Keyring by DERIVING each epoch's working keys from its 32-byte master
    K_epoch (finding 21 / CRYPTO.md §2): `data_key` = the `dude.enc` subkey, the
    xcs1 AEAD key; `slot_secret` = the `dude.slot` subkey, the slot-tag PRF key. The
    master is what the wrap-set distributes and escrow holds — a client unwraps ONE
    secret per epoch and derives the rest here (a deterministic view; the dict shape
    is kept so every consumer's `ring["data_key"]` / `ring["slot_secret"]` is
    unchanged)."""
    return {
        e: {
            "data_key": crypto.derive_data_key(k),
            "slot_secret": crypto.derive_slot_secret(k),
        }
        for e, k in masters.items()
    }


class Verdict(StrEnum):
    """Per-op fold outcome (DESIGN §6). Frozen at finality (§9)."""

    APPLIED = "applied"  # slotted op won its slot & guards held; or blind write applied
    REJECTED = "rejected"  # attributed to a slot but did not apply (guard/undecryptable/mismatch)
    STALE = "stale"  # tag matched no current expected tag (cross-version/late/garbage)
    INVALID = "invalid"  # structurally invalid (bad sig/authz/hlc/prev/pver)
    CONTROL = "control"  # a control op the reducer applied


# --------------------------------------------------------------------------- #
# Per-key metadata (DESIGN §6)                                                 #
# --------------------------------------------------------------------------- #


class KeyMeta:
    __slots__ = ("present", "value", "version", "attempt")

    def __init__(self, present: bool, value: bytes | None, version: bytes, attempt: int):
        self.present = present  # live value exists?
        self.value = value  # bytes | None
        self.version = version  # op_hash of last applied mutation, or ⊥
        self.attempt = attempt  # consumed slots at this version

    def copy(self) -> KeyMeta:
        return KeyMeta(self.present, self.value, self.version, self.attempt)


class StateView:
    """Read-only view handed to the data handler for guard evaluation
    (state produced by predecessors in the total order — A6)."""

    __slots__ = ("_keys",)

    def __init__(self, keys: dict[bytes, KeyMeta]):
        self._keys = keys

    def get(self, key: bytes) -> tuple[bool, bytes | None, bytes, int]:
        m = self._keys.get(key)
        if m is None or not m.present:
            ver = m.version if m is not None else VERSION_ABSENT
            att = m.attempt if m is not None else 0
            return (False, None, ver, att)
        return (True, m.value, m.version, m.attempt)


# --------------------------------------------------------------------------- #
# Control state (shared by the full profile and the node control profile)     #
# --------------------------------------------------------------------------- #

# The delegable capability each control kind needs (DESIGN §15). Root authors
# any kind; kinds absent here are root-only (pver/endpoint). Revocation drives
# key rotation, so rotate/wrap-set ride the issue-revoke capability.
_CAP_FOR_KIND: dict[control_handler.ControlKind, control_handler.Cap] = {
    control_handler.ControlKind.CHECKPOINT: control_handler.Cap.COMPACT,
    control_handler.ControlKind.ROSTER: control_handler.Cap.MANAGE_ROSTER,
    control_handler.ControlKind.CERT_ISSUE: control_handler.Cap.ISSUE_REVOKE,
    control_handler.ControlKind.CERT_REVOKE: control_handler.Cap.ISSUE_REVOKE,
    control_handler.ControlKind.ROTATE: control_handler.Cap.ISSUE_REVOKE,
    control_handler.ControlKind.WRAP_SET: control_handler.Cap.ISSUE_REVOKE,
}


def _is_recovery_roster(body: control_handler.ControlBody) -> bool:
    """A ROSTER op carrying a `recovery` field is the fiat recovery trigger
    (NOTES 36a / WP1.7) — root-only, never delegable."""
    return isinstance(body, control_handler.Roster) and body.recovery is not None


class ControlState:
    """Roster / cert / keyepoch / pver state. Reachable without HLC ordering
    for the node profile (activation is by certificate observation and
    everything is idempotent, ARCHITECTURE L5); the full profile walks it in
    total order so revocation is fold-positional (DESIGN §15)."""

    def __init__(
        self,
        manager_pub: bytes,
        epoch: int = 0,
        keyepoch: int = 0,
        pver: int = 0,
        genesis_roster: list[bytes] | None = None,
    ):
        self.manager_pub = manager_pub
        self.epoch = epoch
        self.roster: list[bytes] | None = list(genesis_roster) if genesis_roster else None
        # roster-per-epoch, forward-accumulated as authorized ROSTER ops fold (issue #3):
        # the trust map a client verifies each committed op's QC against. Seeded with the
        # founding roster at the genesis epoch when the anchor is known.
        self.rosters: dict[int, list[bytes]] = (
            {epoch: list(genesis_roster)} if genesis_roster else {}
        )
        self.active_keyepoch = keyepoch
        self.pver = pver  # ACTIVE fold-semantics version (gates op.pver)
        self.pending_pver = pver  # activates at the next checkpoint barrier (§16)
        self.certs: dict[bytes, Cert] = {}  # subject_pub -> {caps, revoked}
        # node reachability (PROTOCOL §7 / NOTES 58): subject_pub -> addrs, latest-
        # wins in the walk; an ENDPOINT with empty addrs removes the node.
        self.endpoints: dict[bytes, list[transports.Endpoint]] = {}

    def is_authorized(self, pub: bytes, cap: bytes) -> bool:
        if pub == self.manager_pub:
            return True
        c = self.certs.get(pub)
        return bool(c and not c["revoked"] and cap in c["caps"])

    def can_author_control(
        self, author: bytes, kind: control_handler.ControlKind, is_recovery: bool = False
    ) -> bool:
        """Control-op authorization (DESIGN §15; upgrades NOTES item 9's M1
        root-only shortcut). The root may author any kind; a delegate needs the
        capability mapped to that kind — a checkpoint signed by a `compact` cert
        is authorized, one signed by a plain client cert is not. Fold-positional:
        `is_authorized` sees a revocation the moment it is applied in the walk, so
        a revoked delegate's later control ops fold `invalid`. Kinds with no
        delegable capability (pver, endpoint) stay root-only.

        `is_recovery` (a ROSTER op carrying a `recovery` field, NOTES 36a): FIAT
        recovery is ROOT-ONLY and never delegable — even a `manage-roster`
        delegate's recovery-marked op folds invalid, because fiat activation
        bypasses the joint-quorum safeguard that makes delegation safe."""
        if is_recovery:
            return author == self.manager_pub
        if author == self.manager_pub:
            return True
        cap = _CAP_FOR_KIND.get(kind)
        return cap is not None and self.is_authorized(author, cap)

    def activate_pending_pver(self) -> None:
        """The lane-2 fence: pending versions become active only at a
        checkpoint barrier (DESIGN §16)."""
        self.pver = max(self.pver, self.pending_pver)

    def apply_control(self, op: Op, body: control_handler.ControlBody) -> None:
        # `body` is the typed, schema-validated control body — match on its kind.
        # WrapSet / Checkpoint have no ControlState effect here (the `_` arm).
        match body:
            case control_handler.CertIssue() as c:
                self.certs[c.subject] = {"caps": set(c.caps), "revoked": False}
            case control_handler.CertRevoke() as c:
                existing = self.certs.get(c.subject)
                if existing:
                    existing["revoked"] = True
                else:
                    self.certs[c.subject] = {"caps": set(), "revoked": True}
            case control_handler.Rotate() as r:
                self.active_keyepoch = r.keyepoch
            case control_handler.Roster() as r:
                self.epoch = r.from_epoch + 1
                self.roster = list(r.roster)
                self.rosters[r.from_epoch + 1] = list(r.roster)  # roster-per-epoch (issue #3)
            case control_handler.PverActivate() as p:
                self.pending_pver = max(self.pending_pver, p.pver)
            case control_handler.EndpointRecord() as e:
                if e.addrs:  # latest-wins; empty addrs = removal (NOTES 58)
                    # decompose the record's (transport, uri, opts) into dial structs here
                    self.endpoints[e.subject] = [
                        transports.Endpoint.from_record(*a) for a in e.addrs
                    ]
                else:
                    self.endpoints.pop(e.subject, None)
            case _:
                pass
        # ControlKind.CHECKPOINT: no control-state change here — its cut places
        # the barrier in the walk (fold) / activates pending pver (reducer).
        # ControlKind.WRAP_SET: no control-state change.


# --------------------------------------------------------------------------- #
# Structural pre-validation (per-author chains)                               #
# --------------------------------------------------------------------------- #

# Signature/structure validity is a pure function of an op's bytes (op_hash
# uniquely determines them), so the result is cacheable — pure-Python Ed25519
# verification is otherwise re-paid on every re-fold. Bounded to avoid unbounded
# growth in a long-lived process.
_SIG_CACHE: dict[bytes, bool] = {}
_SIG_CACHE_MAX = tunables.SIG_CACHE_MAX


def _struct_and_sig_ok(op: Op) -> bool:
    ok = _SIG_CACHE.get(op.op_hash)
    if ok is None:
        ok = op.verify_structure() and op.verify_sig(op.author)
        if len(_SIG_CACHE) < _SIG_CACHE_MAX:
            _SIG_CACHE[op.op_hash] = ok
    return ok


def _prevalidate(ops: list[Op], cut_frontier: Heads | None = None) -> set[bytes]:
    """Key-independent structural validity: signatures, shape, prev-linkage,
    and per-author HLC monotonicity (DESIGN §4). Forks (two ops at one seq) are
    NOT rejected — they fold in op_hash order like any others; determinism
    never waits for punishment (DESIGN §4).

    Sig-invalid ops are excluded from linkage targets and from the HLC
    baseline: a forged (unsigned-by-the-author) op must not be able to
    invalidate an honest author's chain (NOTES item 17).

    `cut_frontier` (the checkpoint's pinned per-author heads, {author: (seq,
    hash)}) lets ops just above a compaction barrier prev-validate against the
    boundary — a bootstrap client folds snapshot ∘ tail without holding the
    compacted history (DESIGN §12)."""
    cut_frontier = cut_frontier or {}
    invalid: set[bytes] = set()
    by_author: dict[bytes, list[Op]] = {}
    for op in ops:
        if not _struct_and_sig_ok(op):
            invalid.add(op.op_hash)
            continue  # never a linkage target, never an HLC baseline contributor
        by_author.setdefault(op.author, []).append(op)
    for author, chain in by_author.items():
        cut = cut_frontier.get(author)  # (cut_seq, cut_hash) | None
        hashes_by_seq: dict[int, set[bytes]] = {}
        for o in chain:
            hashes_by_seq.setdefault(o.seq, set()).add(o.op_hash)
        for o in chain:
            if o.seq == 0:
                if o.prev != GENESIS_PREV:
                    invalid.add(o.op_hash)
            elif o.prev in hashes_by_seq.get(o.seq - 1, set()):
                pass  # normal in-set linkage (to a sig-valid parent)
            elif cut is not None and o.seq == cut[0] + 1 and o.prev == cut[1]:
                pass  # first op above the barrier
            else:
                invalid.add(o.op_hash)
        # HLC strictly increases across distinct seq (equivocation at one seq ok)
        maxh = None
        for seq in sorted(hashes_by_seq):
            ops_at = [o for o in chain if o.seq == seq]
            for o in ops_at:
                if maxh is not None and not (o.hlc.as_tuple() > maxh):
                    invalid.add(o.op_hash)
            maxh_here = max(o.hlc.as_tuple() for o in ops_at)
            maxh = maxh_here if maxh is None else max(maxh, maxh_here)
    return invalid


# --------------------------------------------------------------------------- #
# The fold                                                                     #
# --------------------------------------------------------------------------- #


class FoldResult:
    __slots__ = ("state", "verdicts", "meta", "control")

    def __init__(
        self,
        state: dict[bytes, bytes],
        verdicts: dict[bytes, Verdict],
        meta: dict[bytes, KeyMeta],
        control: ControlState,
    ):
        self.state = state  # {key: value} live keys only (the SEC state)
        self.verdicts = verdicts  # {op_hash: verdict}
        self.meta = meta  # {key: KeyMeta} full lineage
        self.control = control  # ControlState

    def lineage(self, key: bytes) -> tuple[bytes, int]:
        m = self.meta.get(key)
        if m is None:
            return (VERSION_ABSENT, 0)
        return (m.version, m.attempt)


class FoldHalted(DudeFSError):
    """The lane-2 fence tripped (DESIGN §16 / NOTES item 15): a checkpoint
    barrier activated a fold-semantics version above SUPPORTED_PVER. Fail-stop,
    never misfold: `sealed` is the FoldResult at the fence for read-only
    service; `pver` is the version this build does not speak."""

    def __init__(self, pver: int, sealed: FoldResult):
        self.pver = pver
        self.sealed = sealed
        super().__init__(
            f"fold halted at lane-2 fence: active pver {pver} > supported {SUPPORTED_PVER}"
        )


def _total_order_key(op: Op) -> tuple[tuple[int, int], bytes, int, bytes]:
    # Total even over garbage: an op with missing/mistyped envelope fields
    # (struct-invalid, folded `invalid`) still needs a deterministic position.
    try:
        h = op.hlc.as_tuple()
    except (KeyError, DudeFSError):
        h = (-1, -1)
    try:
        author = op.author
    except (KeyError, DudeFSError):
        author = b""
    try:
        seq = op.seq
    except (KeyError, DudeFSError):
        seq = -1
    return (h, author, seq, op.op_hash)


def _covered(op: Op, cut: Heads) -> bool:
    """Is `op` at-or-below the pinned cut? Membership is per-author by seq
    (DESIGN §12); garbage ops with unreadable author/seq are never covered."""
    try:
        entry = cut.get(op.author)
        return entry is not None and op.seq <= entry[0]
    except (KeyError, DudeFSError):
        return False


def _authorized_cuts(ops_sorted: list[Op], invalid: set[bytes], genesis: Genesis) -> list[Heads]:
    """The pinned cuts of every AUTHORIZED checkpoint, in total order (NOTES 37 /
    finding 12). A control-only PRE-WALK: replay control ops in total order against
    a fresh ControlState and record every checkpoint whose author holds the
    `compact` capability at THAT position — the root or a compact-delegate.

    The chicken-and-egg the old routine got wrong: barrier placement runs before
    the main walk, but delegate authorization is fold-positional. It sidestepped it
    by honoring only `author == manager_pub`, so a delegate-minted checkpoint
    folded CONTROL (authorized) yet placed NO barrier — its cut, tombstone deaths,
    attempts, and pver activation all silently dropped. Authorization depends only
    on prior control ops (certs/revocations), never on data or HLC, so this
    pre-walk is self-contained, deterministic, and agrees op-for-op with the main
    walk's CONTROL verdicts.

    It mirrors the main walk's gates so it cannot record a cut the main walk would
    reject (findings 14/15): the lane-2 pver fence (an op above the active pver
    folds INVALID — no state, no barrier; PVER_ACTIVATE pends, and pending
    activates at each recorded cut's barrier position, i.e. when the walk first
    crosses an op that cut does not cover), and the root-only recovery marking
    (`is_recovery`). Stage-order-vs-total-order divergence under a NON-FINAL
    (dishonest) cut is contained, not solved — deterministic for all clients."""
    return _reduce_control(ops_sorted, invalid, genesis)[1]


def _reduce_control(
    ops_sorted: list[Op], invalid: set[bytes], genesis: Genesis
) -> tuple[ControlState, list[Heads]]:
    """The shared control-only reduction: replay control ops in total order against a
    fresh ControlState, authorization fold-positional, yielding the final state (certs,
    keyepoch, pver, roster-per-epoch) and the authorized checkpoint cuts. Data-
    independent (issue #3): both cut-placement and QC-verification roster reconstruction
    read the same replay, so they agree op-for-op with the main walk's CONTROL verdicts."""
    control = ControlState(
        genesis["manager_pub"],
        genesis.get("epoch", 0),
        genesis.get("keyepoch", 0),
        genesis.get("pver", 0),
        genesis.get("roster"),
    )
    cuts: list[Heads] = []
    pending_barrier: Heads | None = None  # a recorded cut whose pver activation is due
    for op in ops_sorted:  # already in _total_order_key order
        # barrier-position pver activation: crossing beyond a recorded cut moves
        # its pending pver active, mirroring the main walk's end-of-stage step.
        if pending_barrier is not None and not _covered(op, pending_barrier):
            control.activate_pending_pver()
            pending_barrier = None
        if op.op_hash in invalid or not op.is_control:
            continue
        if op.pver > control.pver:
            continue  # lane-2 fence: INVALID in the main walk -> no state, no barrier
        body = control_handler.decode(op)
        if body is None or not control.can_author_control(
            op.author, body.KIND, _is_recovery_roster(body)
        ):
            continue  # unauthorized -> folds `invalid` in the main walk; no barrier
        if isinstance(body, control_handler.Checkpoint):
            cuts.append(body.cut)
            pending_barrier = body.cut  # its barrier activates pending downstream
        control.apply_control(op, body)
    return control, cuts


def rosters_by_epoch(ops: list[Op], genesis: Genesis) -> dict[int, list[bytes]]:
    """Reconstruct `epoch -> voting roster` from the held control chain (issue #3):
    the trust map a client verifies each committed op's QC against. Only AUTHORIZED,
    signature-valid ROSTER ops count (a compactor-forged roster op is excluded — it has
    no `MANAGE_ROSTER` cap), so a rogue compactor cannot rewrite roster history. Anchored
    on the genesis roster in `genesis`; forward-accumulated in total order."""
    ops_sorted = sorted(ops, key=_total_order_key)
    invalid = _prevalidate(ops_sorted)
    return _reduce_control(ops_sorted, invalid, genesis)[0].rosters


def fold(
    committed_ops: list[Op],
    keyring: Keyring,
    genesis: Genesis,
    barrier: BarrierState | None = None,
    cut_frontier: Heads | None = None,
) -> FoldResult:
    """Deterministic fold of a *committed* op set (FORMAL A1). Any arrival order
    yields identical (state, verdicts) — the walk sorts internally. Pass
    `barrier` + `cut_frontier` to fold a checkpoint tail above a sealed barrier
    (bootstrap client, DESIGN §12). Raises FoldHalted at a lane-2 fence above
    SUPPORTED_PVER."""
    # The fold is a pure function of the committed *SET* (FORMAL A1): dedupe by
    # op_hash so re-delivery is a no-op (idempotent gossip, DESIGN §8).
    ops = list({op.op_hash: op for op in committed_ops}.values())
    invalid = _prevalidate(ops, cut_frontier)

    control = ControlState(
        genesis["manager_pub"],
        genesis.get("epoch", 0),
        genesis.get("keyepoch", 0),
        genesis.get("pver", 0),
        genesis.get("roster"),
    )
    verdicts: dict[bytes, Verdict] = {}

    # ---- seed state from the sealed barrier (checkpoint bootstrap, §12 / A4) --
    state: dict[bytes, KeyMeta] = {}
    if barrier is not None:
        for key, s in barrier.items():
            state[key] = KeyMeta(True, s["value"], s["version"], s["attempt"])

    ops_sorted = sorted(ops, key=_total_order_key)
    # Bootstrap mode: data ops sealed by the provided cut are already reflected
    # in the snapshot — they are never re-folded (and get no verdict). Control
    # ops below the cut still fold: the snapshot carries data state only, the
    # control chain is retained in full (PROTOCOL §7.2).
    if cut_frontier:
        ops_sorted = [o for o in ops_sorted if o.is_control or not _covered(o, cut_frontier)]

    # ---- cached decodes (every client decrypts the same set, DESIGN §6) ----- #
    decoded: dict[bytes, Txn | Opaque] = {}  # op_hash -> parsed payload
    for op in ops_sorted:
        if not op.is_control:
            decoded[op.op_hash] = data_handler.decode(op, keyring)

    # ---- checkpoint partition: fold covered set, barrier, fold tail (§12) --- #
    stages: list[list[Op]] = []
    remaining = ops_sorted
    for cut in _authorized_cuts(ops_sorted, invalid, genesis):
        stages.append([o for o in remaining if _covered(o, cut)])
        remaining = [o for o in remaining if not _covered(o, cut)]
    stages.append(remaining)

    def _stage_universe(idx: int) -> set[bytes]:
        # Keys attributable in this segment: live at the segment start ∪ named
        # by any decryptable op at-or-above it. The universe RESETS at each
        # barrier (DESIGN §12 / NOTES item 13) — dead sealed keys are
        # unattributable above the cut, identically for snapshot and
        # full-history clients.
        uni = {k for k, m in state.items() if m.present}
        for stage in stages[idx:]:
            for op in stage:
                d = decoded.get(op.op_hash)
                if d is None or isinstance(d, Opaque):
                    continue
                if d.slot is not None:
                    uni.add(d.slot[0])
                for m in d.mutations:
                    if len(m) >= 2:
                        uni.add(m[1])
        return uni

    # ---- the ordered walk ------------------------------------------------- #
    for i, stage in enumerate(stages):
        universe = _stage_universe(i)
        for op in stage:
            if op.op_hash in invalid:
                verdicts[op.op_hash] = Verdict.INVALID
                _consume_invalid_slot(op, keyring, universe, state)
                continue
            # lane-2 fence: gates ALL op classes (DESIGN §16 / NOTES item 15)
            if op.pver > control.pver:
                verdicts[op.op_hash] = Verdict.INVALID
                _consume_invalid_slot(op, keyring, universe, state)
                continue

            if op.is_control:
                body = control_handler.decode(op)
                if body is None or not control.can_author_control(
                    op.author, body.KIND, _is_recovery_roster(body)
                ):
                    verdicts[op.op_hash] = Verdict.INVALID
                    _consume_invalid_slot(op, keyring, universe, state)
                    continue
                control.apply_control(op, body)
                verdicts[op.op_hash] = Verdict.CONTROL
                continue

            # data op --------------------------------------------------------- #
            if not control.is_authorized(op.author, control_handler.Cap.WRITE):
                verdicts[op.op_hash] = Verdict.INVALID
                _consume_invalid_slot(op, keyring, universe, state)
                continue

            d = decoded[op.op_hash]  # every non-control op was decoded in pass 1
            view = StateView(state)

            if op.slot_tag is None:
                # blind write (LWW). Undecryptable blind write cannot apply.
                if isinstance(d, Opaque):
                    verdicts[op.op_hash] = Verdict.REJECTED
                    continue
                ev = data_handler.evaluate(d, view)
                if ev.guards_ok:
                    _apply_mutations(state, ev.mutations, op.op_hash)
                    verdicts[op.op_hash] = Verdict.APPLIED
                else:
                    verdicts[op.op_hash] = Verdict.REJECTED
                continue

            # slotted op: attribute by tag-equality over the key universe ----- #
            ring = keyring.get(op.keyepoch)
            if ring is None:
                verdicts[op.op_hash] = Verdict.STALE  # cannot compute tags for this epoch
                continue
            secret = ring["slot_secret"]
            k = _attribute(op.slot_tag, secret, universe, state)
            if k is None:
                verdicts[op.op_hash] = Verdict.STALE
                continue

            cur = state.get(k)
            cur_ver = cur.version if cur is not None else VERSION_ABSENT
            cur_att = cur.attempt if cur is not None else 0

            applied = False
            if not isinstance(d, Opaque):
                ev = data_handler.evaluate(d, view)
                # the restated preimage must match k's *current* lineage, and guards hold
                if ev.slot_preimage == (k, cur_ver, cur_att) and ev.guards_ok:
                    _apply_mutations(state, ev.mutations, op.op_hash)
                    applied = True
                    mutated = {m[1] for m in ev.mutations if len(m) >= 2}
                    if k not in mutated:
                        _bump_attempt(state, k)  # guard-only slot (lineage-advance)
                    verdicts[op.op_hash] = Verdict.APPLIED

            if not applied:
                # attributed but did not apply: consume the slot (attempt += 1)
                _bump_attempt(state, k)
                verdicts[op.op_hash] = Verdict.REJECTED

        if i < len(stages) - 1:
            _apply_checkpoint_barrier(state)
            control.activate_pending_pver()
            if control.pver > SUPPORTED_PVER:
                sealed = FoldResult(_live(state), verdicts, state, control)
                raise FoldHalted(control.pver, sealed)

    return FoldResult(_live(state), verdicts, state, control)


def _live(state: dict[bytes, KeyMeta]) -> dict[bytes, bytes]:
    # A present key always carries a bytes value (Mutation.SET); the `is not
    # None` narrows for the type checker and is a harmless invariant guard.
    return {k: m.value for k, m in state.items() if m.present and m.value is not None}


def _attribute(
    tag: bytes, secret: bytes, universe: set[bytes], state: dict[bytes, KeyMeta]
) -> bytes | None:
    """Find the unique key whose *current* expected tag equals `tag` under this
    epoch's secret. At most one matches (tags are unique per
    (key, version, attempt); lineages never repeat — A2)."""
    for k in universe:
        m = state.get(k)
        ver = m.version if m is not None else VERSION_ABSENT
        att = m.attempt if m is not None else 0
        if A.compute_slot_tag(secret, k, ver, att) == tag:
            return k
    return None


def _consume_invalid_slot(
    op: Op, keyring: Keyring, universe: set[bytes], state: dict[bytes, KeyMeta]
) -> None:
    """The universal lineage-advance rule (DESIGN §6 / NOTES item 14): an op
    that folds `invalid` still consumes the slot its tag names, if it is
    attributable — its ballot was voted at the acceptor layer, where
    fold-positional invalidity is invisible; leaving the tag expected while its
    slot is decided would be a permanent wedge. Unattributable (garbage tag,
    unreadable envelope, unknown epoch) → no state change, like `stale`."""
    try:
        tag = op.slot_tag
        keyepoch = op.keyepoch
    except (KeyError, DudeFSError):
        return
    if tag is None:
        return
    ring = keyring.get(keyepoch)
    if ring is None:
        return
    k = _attribute(tag, ring["slot_secret"], universe, state)
    if k is not None:
        _bump_attempt(state, k)


def _apply_mutations(
    state: dict[bytes, KeyMeta], mutations: list[list[bytes]], op_hash: bytes
) -> None:
    """All-or-nothing (A6). Every mutated key: version := op_hash, attempt := 0.
    Vocabulary is validated at Txn.decode (unknown kinds are a malformed Txn ->
    Opaque, NOTES item 15) — rows here are known-good."""
    for m in mutations:
        kind, path = m[0], m[1]
        if kind == A.Mutation.SET:
            state[path] = KeyMeta(True, m[2], op_hash, 0)
        elif kind == A.Mutation.DEL:
            state[path] = KeyMeta(False, None, op_hash, 0)  # tombstone


def _bump_attempt(state: dict[bytes, KeyMeta], key: bytes) -> None:
    m = state.get(key)
    if m is None:
        state[key] = KeyMeta(False, None, VERSION_ABSENT, 1)  # absent-key lineage advances
    else:
        m.attempt += 1


def _apply_checkpoint_barrier(state: dict[bytes, KeyMeta]) -> None:
    """Non-live lineages die at the barrier (DESIGN §12): tombstones AND
    attempt-only (⊥, n) entries are dropped, so their lineages restart at
    (⊥, 0) — exactly what the live-keys-only snapshot expresses. Live keys
    keep their (version, attempt)."""
    for key in [k for k, m in state.items() if not m.present]:
        del state[key]


# --------------------------------------------------------------------------- #
# Barrier state (checkpoint bootstrap seed, DESIGN §12 / A4)                   #
# --------------------------------------------------------------------------- #


def make_barrier(result: FoldResult) -> BarrierState:
    """The live-key state at a barrier, each with (value, version, attempt) — what
    a bootstrap client reconstructs from the retained winners + attempts sidecar,
    and a full-history client derives (DESIGN §12; rev 6: no snapshot blob).
    Tombstones are omitted (they die at the barrier)."""
    out: BarrierState = {}
    for key, m in result.meta.items():
        if m.present and m.value is not None:  # present => bytes value (narrows for BarrierEntry)
            out[key] = {"value": m.value, "version": m.version, "attempt": m.attempt}
    return out


def _acc_element(key: bytes, value: object, version: bytes, attempt: int) -> bytes:
    """φ of one live-key element — its ECMH curve point (ACCUMULATOR §3.1). The encoding
    `[key, value, version, attempt]` is the canonical, injective serialization."""
    return crypto.acc_element(A.codec.encode([key, value, version, attempt]))


def state_acc(result: FoldResult) -> bytes:
    """The audit anchor over the live state at a barrier (DESIGN §12 / ACCUMULATOR): the
    ECMH accumulator `Σ φ(key, value, version, attempt)` over live keys — a 32-byte curve
    point, order-independent (no sort), incrementally verifiable. `state_acc_of_barrier`
    recomputes the SAME value from a reconstructed barrier, so a key-holder can audit a
    checkpoint (WP-B); mis-selection is caught in O(Δ) via the transition check."""
    a = crypto.ACC_IDENTITY
    for k, m in result.meta.items():
        if m.present and m.value is not None:
            a = crypto.acc_add(a, _acc_element(k, m.value, m.version, m.attempt))
    return a


def state_acc_of_barrier(barrier: BarrierState) -> bytes:
    """The state accumulator recomputed from a reconstructed barrier — the bootstrap/audit
    inverse of `state_acc`. By A4 (retained bootstrap ≡ full fold) it equals the `state_acc`
    a full-history fold derives, so a mismatch against a checkpoint's claimed value is a
    forged/corrupt checkpoint (WP-B)."""
    a = crypto.ACC_IDENTITY
    for k, e in barrier.items():
        a = crypto.acc_add(a, _acc_element(k, e["value"], e["version"], e["attempt"]))
    return a


# --------------------------------------------------------------------------- #
# Control reducer — the node profile (ARCHITECTURE L5)                         #
# --------------------------------------------------------------------------- #


class ControlReducer:
    """The deliberately-weaker node profile: roster/cert/checkpoint state
    reachable WITHOUT HLC ordering (activation is by certificate observation,
    everything idempotent — DESIGN §12-§13). Nodes never fold data; this
    profile registers no data handler and holds no keyring."""

    def __init__(self, manager_pub: bytes, epoch: int = 0, keyepoch: int = 0, pver: int = 0):
        self.control = ControlState(manager_pub, epoch, keyepoch, pver)

    def observe(self, op: Op) -> bool:
        """Idempotently fold one control op. Returns True if applied. Data ops
        are ignored (bytes to store, never interpreted)."""
        if not op.is_control:
            return False
        if not _struct_and_sig_ok(op):
            return False
        body = control_handler.decode(op)
        if body is None:
            return False
        # best-effort capability filter (DESIGN §15): the node profile is
        # order-independent, so revocation isn't fold-positional here — the full
        # fold is authoritative. Enough to recognize a delegate's control op.
        if not self.control.can_author_control(op.author, body.KIND, _is_recovery_roster(body)):
            return False
        self.control.apply_control(op, body)
        if isinstance(body, control_handler.Checkpoint):
            # observing a committed checkpoint IS the node's barrier (§16);
            # nodes never fold data, so a high pver never halts them.
            self.control.activate_pending_pver()
        return True


def endpoints_of(
    ops: list[Op], manager_pub: bytes, epoch: int = 0
) -> dict[bytes, list[transports.Endpoint]]:
    """Reduce ENDPOINT control ops to `{node_pub: [Endpoint, …]}` (latest-wins in
    manager-chain order — PROTOCOL §7 / NOTES 58). The node and client daemons derive
    their address books from this instead of taking addresses as kwargs."""
    reducer = ControlReducer(manager_pub, epoch)
    for op in sorted(ops, key=lambda o: (o.hlc.as_tuple(), o.op_hash)):
        if op.is_control:
            reducer.observe(op)
    return reducer.control.endpoints
