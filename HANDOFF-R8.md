# HANDOFF-R8 — the `Op` capstone: typed variants over the invariant wire

> **Scope.** One refactor: turn `Op` from a `dict[Field, value]` **field-bag** into a **typed
> variant hierarchy** (Envelope + `Slotted` mixin + Data/Control leaf types), with **per-variant
> validators** replacing the one-big `verify_structure`. This is the last item of the R8 cleanup
> arc and the highest blast radius (`Op` is *the* fundamental type — fold, acceptor, store,
> gossip, quorum, manager all touch it) and it **is the wire** (`op_hash = h(raw)`).
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
forbids a slot_tag; a data op needs a keyepoch; a control op doesn't. The control **body** is
*already* a typed union (`ctl.ControlBody`, 8 frozen dataclasses w/ per-kind validators) — half
the hierarchy exists. What's missing is the **envelope** typing and the **data payload** typing.

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

## 3. Target hierarchy

```
Envelope (base / trait):  author · seq · prev · hlc · pver · sig · op_hash · raw
Slotted  (mixin):         slot_tag + per-kind binding + "goes through quorum.Commit"
│
├─ Data
│   ├─ CasOp(Slotted)      payload = Sealed[Txn] · keyepoch     binding: compute_slot_tag
│   └─ BlindPutOp          payload = Sealed[Txn] · keyepoch     (no slot)
│
└─ Control  (payload = a typed ControlBody — the union that ALREADY exists)
    ├─ RosterOp(Slotted)      binding: roster_slot_tag(from_epoch)
    ├─ CheckpointOp(Slotted)  binding: checkpoint_slot_tag(seq)   body.attempts: Sealed[…]
    ├─ CertIssueOp · CertRevokeOp · RotateOp
    ├─ WrapSetOp     body.wraps: dict[pub, Sealed[GroupKey]]
    └─ PverOp · EndpointOp
```

Notes:
- **`Slotted` is a cross-cut, not a class axis.** `CasOp`, `RosterOp`, `CheckpointOp` share the
  *consensus path* (PREPARE/ACCEPT on their slot); the rest are blind-committed. So `Slotted`
  is a **mixin** carrying `slot_tag` + `expected_slot_tag()` (the per-kind binding) + the
  validator "slot_tag == expected". That single mixin replaces the scattered runtime asserts.
- **Sealed fields are field-level, not a body-level split.** All control bodies are
  plaintext-structured (DESIGN §5 ZK carve-out). Two carry ciphertext *fields*: `WrapSet.wraps`,
  `Checkpoint.attempts`. Typing those as `Sealed[T]` (a thin `bytes` newtype that says "opened
  with key K") is a nice-to-have that makes "this is ciphertext" structural. Not required.

## 4. The one design fork — resolve first

**Views vs. subclass replacement.** Two ways to realise the hierarchy over the invariant `raw`:

- **(A) Typed views (lower risk).** `Op` stays the concrete envelope (raw + common accessors +
  `verify_sig`). Add a `classify()` / parse layer → returns the typed variant (`CasOp` wrapping
  the Op, `CheckpointOp` wrapping Op+body, …), each with a `validate()`. Generic code keeps
  using `Op`; code that wants the shape asks for it. Least churn to the ~everywhere `op.author`
  callers.
- **(B) Subclass replacement (Harry's "every ControlOp its own instance").** `Op` abstract;
  `from_bytes` dispatches on `class` → the concrete leaf type; each op instance *is* its variant.
  More honest, more invasive (every `isinstance`/annotation, every constructor).

**Recommendation:** start with **(A)** for the parse/validate layer (it's wire-neutral and
reversible), and let the leaf types be **real dataclasses fused with the envelope** (so
`ctl.decode` returns a `CheckpointOp`, not a bare `Checkpoint` body). If (A) lands clean and the
call sites want it, (B) is a follow-on. Do **not** big-bang (B) — it's the sprawl that this whole
session avoided.

## 5. Staged plan (each a green `make check` commit)

1. **`keyepoch` → data-only (wire change).** Make `Op.build`'s `keyepoch` optional
   (`int | None = None`, set the field only when given); `Op.build_data` still passes it. Drop
   `keyepoch=` from the **control** `build` callers (list in §6). Split `verify_structure`: the
   keyepoch check moves under a data-only branch (the first per-variant validator). **Wire
   moves for control ops only** — and the byte goldens use a *data* op fixture
   (`test_wire_goldens._fixtures`, `test_artifacts.GOLDEN_OP_HASH`), so **check whether any golden
   pins a control op** (likely none → this stage may be golden-immovable). If a control-op hash
   is pinned anywhere, regen it deliberately.
2. **Split `verify_structure` into per-variant validators.** Wire-neutral. Common envelope
   checks + `_validate_data` (keyepoch, payload-is-ciphertext-shaped) + `_validate_control`
   (payload decodes to a known body kind; delegate to the body's own validator). This is the
   seam the field-bag never had.
3. **`Slotted` mixin.** Fold the `slot_tag` presence + per-kind binding into the variant
   validators (`checkpoint_slot_tag(seq)`, `roster_slot_tag(from_epoch)`), and replace
   `quorum.Commit`'s runtime `assert op.slot_tag is not None` with the typed guarantee.
4. **The typed variant layer (fork §4).** `classify()`/parse → the leaf types; `ctl.decode`
   returns the fused `…Op`. Optionally `Sealed[T]` for `wraps`/`attempts`.
5. **Review pass** (Harry: "at the end we can do a review").

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
