# HANDOFF-R8 — the `Op` capstone: typed variants over the invariant wire

> **Scope.** One refactor: turn `Op` from a `dict[Field, value]` **field-bag** into a
> **decode-once class hierarchy** — a leaf type PER op kind (`CasOp`, `BlindPutOp`, `CheckpointOp`,
> `RosterOp`, …), each a full concrete type valid in isolation, sharing behavior through a base
> envelope + a `Slotted` mixin. `from_bytes` dispatches on `class` and returns the concrete leaf
> with **everything decoded once** (no lazy property re-parse, no `ctl.decode` re-running per
> touch). This is the last item of the R8 cleanup arc and the highest blast radius (`Op` is *the*
> fundamental type — fold, acceptor, store, gossip, quorum, manager all touch it) and it **is the
> wire** (`op_hash = h(raw)`).
>
> **The shape is SETTLED — see §3/§4. Do not reopen it (views, or a `ControlOp.body` enum, are
> both rejected with reasons in §4).**
>
> **From:** cleanup session (Opus) · **To:** implementer (fresh) ·
> **Baseline:** `59f0427` (347 green) — `authz` and `deps` already ripped, field audit complete.
>
> **Ground rules (proven this session).** Wire changes are cheap when factored — removing a
> signed field was ~11 lines in one file (`artifacts.py`) + mechanical caller cleanup + a
> **deliberate golden regen**. The tests are the net: `make check` green after every stage;
> style/behaviour never mixed; goldens move only on purpose and get reviewed. Accept the wire
> change here — protocol versions exist precisely so a considered wire bump is fine.

---

## 1. Why — the field-bag is the rot generator

`Op` is `Op(raw: bytes, fields: dict[Field, Bencodable])` with a flat accessor per field. Two
distinct *shapes* (data vs control, and 8 control kinds) are smuggled through one struct where
half the fields are "only meaningful sometimes," and `verify_structure` is one `try` block for
everything. That is exactly why `authz` and `deps` rotted **invisibly** — nothing ever forced
the question "what consumes this field, and for which variant?" A typed hierarchy makes that
question **structural**: a `CheckpointOp` requires a slot_tag bound to its seq; a `RotateOp`
forbids a slot_tag; a data op needs a keyepoch; a control op doesn't. The control **body**
dataclasses that exist today (`ctl.ControlBody`, 8 frozen dataclasses w/ per-kind validators) are
the **raw material** — they get PROMOTED into the leaf ops (fields → the op's fields, `_v_*` → the
op's `decode`), not retained as a `.body` object (see §4). What's added is the **envelope** typing,
the **data payload** typing, and decode-once construction that ends the lazy re-parse.

## 2. The completed field audit (the ledger)

Traced every field: who sets it, who **reads** it, for which variant.

| field | verdict |
|---|---|
| `author` · `seq` · `prev` · `hlc` · `pver` · `sig` | **envelope-common** — every op |
| `class` | the **discriminant** — dissolves into the type once variants exist |
| `keyepoch` | **DATA-ONLY.** Read in exactly 3 places (`data.decode`, `fold` data path ×2) to pick the decryption key — load-bearing for data durability. **Never read for control ops** (they carry their own semantic keyepoch in the *body*: `Rotate.keyepoch`, `WrapSet.keyepoch`, `Checkpoint.keyepoch`). A checkpoint op literally sets it **twice** — envelope + body — and only the body copy is consumed. → moves down to the Data variants; **dropped from the control envelope (wire change).** |
| `slot_tag` | **`Slotted` mixin.** Present on exactly `Cas` (data), `Roster` + `Checkpoint` (control); absent (blind) on `BlindPut` + `CertIssue`/`CertRevoke`/`Rotate`/`WrapSet`/`Pver`/`Endpoint`. Its presence is a **per-kind fact** with a per-kind binding (`compute_slot_tag` / `roster_slot_tag(epoch)` / `checkpoint_slot_tag(seq)`). `quorum.Commit` currently enforces it with a runtime `assert op.slot_tag is not None` — that wants to be a type guarantee. |
| `payload` | **polymorphic** — `AEAD.open`→`Txn` for data, `codec.decode`→`ControlBody` for control. Becomes the typed body per variant. |
| ~~`authz`~~ ~~`deps`~~ | **removed** (`2a8a676`, `59f0427`). |

## 3. The design (SETTLED) — a decode-once leaf-per-kind hierarchy

`from_bytes` decodes the envelope once, dispatches on `class`, and returns a **concrete leaf
type** with its body already decoded and validated into typed fields. The `ControlBody` dataclasses
that exist today (`Checkpoint`, `Roster`, … in `handlers/control.py`) are **PROMOTED into the leaf
ops** — their fields become the op's fields, `_v_checkpoint` becomes `CheckpointOp.decode`. There is
**no** separate `.body` object and **no** `ControlBody` union retained on the op; the op hierarchy
*is* the discriminated union.

```
Op (base)          author · seq · prev · hlc · pver · sig · raw · op_hash · verify_sig()
│
├─ DataOp          keyepoch · open(key) -> Txn|None   (sealed payload; client-only open)
│   ├─ CasOp(Slotted)        slot_tag                 binding: compute_slot_tag(...)
│   └─ BlindPutOp                                     (blind)
│
├─ ControlOp       (plaintext, node-folded — DESIGN §5 carve-out)
│   ├─ CasIssue…    CertIssueOp · CertRevokeOp · RotateOp · WrapSetOp · PverActivateOp · EndpointOp
│   ├─ RosterOp(Slotted)     from_epoch · roster · …  binding: roster_slot_tag(from_epoch)
│   └─ CheckpointOp(Slotted) baseline · seq · …       binding: checkpoint_slot_tag(seq)
│
└─ InvalidOp       well-formed envelope, unparseable/unknown-kind body -> folds `invalid`
```

Each leaf owns its own `decode(envelope) -> Self`, `encode() -> bytes`, and validation — testable
in isolation, composable. Data-vs-control still groups cleanly through the `DataOp`/`ControlOp`
intermediates (the outer arm of the union).

**Rust map** (nested enums; shared behavior via traits, since Rust has no struct inheritance —
`Envelope` embedded, `HasEnvelope`/`Slotted` traits):
```rust
struct CheckpointOp { env: Envelope, baseline: Baseline, seq: u64, slot_tag: SlotTag, /* … */ }
impl Slotted for CheckpointOp { fn expected_slot_tag(&self) -> SlotTag { checkpoint_slot_tag(self.seq) } }
enum Control { Roster(RosterOp), Checkpoint(CheckpointOp), Rotate(RotateOp), /* … */ }
enum Data    { Cas(CasOp), BlindPut(BlindPutOp) }
enum Op      { Data(Data), Control(Control), Invalid(InvalidOp) }
```

**Python** (3.12; frozen `slots=True` dataclasses; `op_hash` derived in `__post_init__`):
```python
class ControlOp(Op): ...                     # intermediate
class Slotted:                               # mixin: goes through quorum.Commit
    slot_tag: bytes
    def expected_slot_tag(self) -> bytes: raise NotImplementedError

@dataclass(frozen=True, slots=True)
class CheckpointOp(ControlOp, Slotted):
    baseline: Baseline; state_acc: bytes; attempts: bytes
    keyepoch: int; horizon: HLC; seq: int; slot_tag: bytes
    def expected_slot_tag(self) -> bytes: return checkpoint_slot_tag(self.seq)   # binding OWNED here
```

Notes:
- **`Slotted` is a cross-cut mixin, not a class axis.** `CasOp`, `RosterOp`, `CheckpointOp` share
  the *consensus path* (PREPARE/ACCEPT on their slot); the rest are blind. The mixin carries
  `slot_tag` + `expected_slot_tag()` (the per-kind binding) + the "slot_tag == expected" check,
  validated at construction — replacing the scattered runtime `assert op.slot_tag is not None`
  ([quorum.py:229](dudefs/quorum.py)) and the duplicated binding checks
  ([daemon.py:346](dudefs/daemon.py) + [compactor_daemon.py:82](dudefs/compactor_daemon.py)).
  `quorum.Commit` takes a `Slotted`, a type guarantee not a runtime assert.
- **Invariants are type-local.** `CheckpointOp` holds both `seq` and `slot_tag`, so the binding is
  a self-contained method — no cross-layer relation between an envelope field and a payload field.
- **`InvalidOp` is an explicit variant**, not a `None` sentinel — fold totality (a malformed manager
  body folds `invalid`, never crashes — NOTES 17) becomes a case the fold `isinstance`-matches.
- **Sealed fields are field-level.** All control bodies are plaintext-structured (DESIGN §5). Two
  carry ciphertext *fields*: `WrapSetOp.wraps`, `CheckpointOp.attempts`. Typing those as a `Sealed`
  `bytes` newtype ("opened with key K") is a nice-to-have, not required.

## 4. Rejected alternatives — DO NOT REOPEN

Both were floated during design and explicitly rejected; recorded here so the question stays shut.

- **Typed views over a flat `Op` (a `classify()` layer).** REJECTED. It does not decode once —
  the flat `Op` keeps lazy property re-parse and `ctl.decode` keeps re-parsing the payload per call.
  Nothing forces a variant field onto the right type, so it fails to fix the exact rot (`authz`,
  `deps` dangling on the wrong shape) this refactor exists to kill. A view is a lens, not a type.
- **Two envelope types (`DataOp`/`ControlOp`) + a `ControlBody` enum as `ControlOp.body`.**
  REJECTED. The checkpoint slot binding needs `seq` AND `slot_tag`; here they straddle
  `ControlOp.slot_tag` (envelope) and `body.seq` (payload) — a cross-layer check, the same "a field
  only means something in combination with another field elsewhere" smell that let `authz`/`deps`
  rot. It also forces two-level dispatch everywhere (`isinstance(o, ControlOp) and isinstance(o.body,
  Checkpoint)`) where §3 dispatches once (`isinstance(o, CheckpointOp)`). A `Checkpoint` and a
  `Rotate` would be the *same* `ControlOp` type distinguished only by a tag — not "valid in isolation."

## 5. Staged plan (each a green `make check` commit; style/behaviour never mixed)

1. **`keyepoch` → data-only (wire change, isolated).** Make `Op.build`'s `keyepoch` optional
   (`int | None = None`, set the field only when given); `Op.build_data` still passes it. Drop
   `keyepoch=` from the **control** `build` callers (list in §6). Split `verify_structure`: the
   keyepoch check moves under a data-only branch. **CONFIRMED golden-immovable** — every wire
   golden is a *data* op (`test_wire_goldens._fixtures` builds a single `build_data` op;
   `test_artifacts.GOLDEN_OP_HASH` is data; no control-op hash is pinned anywhere). So this stage
   moves zero goldens.
2. **Envelope base + decode-once + `from_bytes` dispatch (wire-neutral).** Introduce the `Op` base
   with **real decoded slots** (not the lazy `codec.as_int(self.fields[...])` properties);
   `from_bytes` decodes the envelope once and dispatches on `class` → `DataOp` / `ControlOp`.
   `verify_structure` dissolves into construction-time validation. This kills the per-access
   envelope re-parse. (Bodies still go through `ctl.decode` for now — stage 3 kills that.)
3. **Promote control bodies into leaf ops.** `CheckpointOp` · `RosterOp` · `CertIssueOp` ·
   `CertRevokeOp` · `RotateOp` · `WrapSetOp` · `PverActivateOp` · `EndpointOp` — each fuses envelope
   + body and decodes **once** at construction; `InvalidOp` for a malformed/unknown-kind body
   (preserves fold totality, NOTES 17). `_VALIDATORS`/`ctl.decode` retire *into* the leaves' own
   `decode`. Migrate the `ctl.decode(op)` sites (fold ×4, daemon ×4, compactor_daemon ×3, client,
   manager — see census) to `match`/`isinstance` on the concrete leaf — killing the per-call body
   re-decode. This is the bulk of the win.
4. **Data leaves + `Slotted` mixin.** `CasOp` / `BlindPutOp` split (by slot presence, envelope-only).
   `Slotted` mixin owns `slot_tag` + `expected_slot_tag()` + the "slot_tag == expected" check at
   construction; `quorum.Commit` takes a `Slotted` (type guarantee, not runtime assert). Collapse
   the duplicated binding checks ([daemon.py:346](dudefs/daemon.py) +
   [compactor_daemon.py:82](dudefs/compactor_daemon.py)) and the `assert op.slot_tag is not None`
   sites.
5. **(Optional) `Sealed` bytes newtype** for `WrapSetOp.wraps` / `CheckpointOp.attempts` / the data
   payload — makes "this is ciphertext, opened with key K" structural.
6. **Review pass** (Harry: "at the end we can do a review").

## 6. Blast radius — the `Op.build` call sites (from `59f0427`)

`build_data(...)` callers are all DATA → **keep** keyepoch automatically (build_data passes it).
Direct `Op.build(cls_=DATA, …)` (rare) → **keep**. Direct `Op.build(cls_=CONTROL, …)` → **drop**
keyepoch in stage 1:

**CONTROL builds (drop keyepoch):**
`dudefs/manager.py:163` (`build_control`), `dudefs/compactor_daemon.py:105` (`_author_checkpoint`),
`tests/_builders.py:153` (`_mgr_op` — also drop its `keyepoch` param), `tests/test_chaos_compaction.py:95`,
`tests/test_manager.py:316,494`, `tests/test_compaction.py:531`, `tests/test_daemon.py:805,815`,
`tests/test_fold.py:542`, `tests/test_fumbling.py:33,49,59`, `tests/test_hardening.py:201`,
`tests/test_control_plane.py:33,52,422,449`.

**DATA builds via `Op.build` directly (KEEP keyepoch):**
`tests/_builders.py:258` (garbage/undecryptable data op), `tests/test_hardening.py:322` (forged data op).

Safety asymmetry: the tests catch a *data* op wrongly stripped of keyepoch (data `verify_structure`
requires it); a *control* op left with a stray keyepoch is harmless (control validator won't check
it) — so err toward the test-caught side.

## 7. Invariants to preserve (the `deps` lesson)

When deleting/moving, don't silently drop a guarantee. Deleting the `deps` tests was safe **only
after** confirming the layering invariant they touched (acceptance-liveness ≠ fold-validity) lives
independently: `test_acceptor` (`BELOW_FLOOR` + `test_floor_is_monotone`), `test_hardening`
(`UNKNOWN_PREV`), `TestFoldTotalityOverGarbage` (fold total + un-poisonable). Apply the same
check before removing any test in this refactor: *is the invariant it guards covered elsewhere?*

## 8. Context — what this cleanup session already landed (all green, all reviewed)

`fd9bbde` personas → tests/ · `ab1e2d1` gossip sans-io seams (`summary`/`_gossip_reply`/`apply_gossip`)
· `61065a8` gossip de-inverted to `Summary`/`Delta` methods · `c2ebd4a` `dudefs/sim/` **deleted**
(merge/pull_op/pull_baseline → tests) · `6ec14ca`/`a412743`/`cca49b3` **`Baseline`** object
end-to-end (artifacts → checkpoint body → store interface; `verify_baseline` magic-tuple killed;
`covered` home to artifacts; `dead` deterministic-sorted) · `64c05b7` `Summary.request()` (framing
on the object, not a free function) · `2a8a676` **`authz` field removed** (wire) · `59f0427`
**`deps` mechanism removed** (wire + acceptor + tests).

**Deferred, separate passes (not this handoff):** the meta-dict string-key review
(`epoch`/`checkpoint`/`horizon` — `cut*` already typed behind `tx.baseline()`); the `memory`
transport rip-out (avoid touching anything that imports it until it can be removed cleanly — its
retirement is its own effort, along with reforging the `tests/_harness.py` sim to drive real
`NodeDaemon`s over the sans-io gossip seams instead of fake direct-store-merge); the `fold._covered`
→ garbage-tolerant wrapper over `artifacts.covered` (4 lines). Tracking is GitHub issues now
(#1 sidecar, #2 provisioning, #3 client verify-pass, #4 fast-sync, #5 WP-H recovery, #6 WP-J
control compaction, #7 coverage).
