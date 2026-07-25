# Fix log — 2026-07-25 review

Each confirmed finding, as it is fixed, with a red-repro test that fails before and passes
after (a genuine regression test, not a re-assertion of the fixed behavior). Workflow per
finding: **red repro → surgical fix → green → annotate here**.

| Finding | Status | Commit | Fix | Regression test |
|---|---|---|---|---|
| **F-2** | ✅ FIXED | `b4d9835` | `compactor.PrevState.of` masks by `tx.cut_dead()` — retained = `covered ∖ dead`, matching `store.baseline_commitment()`. A lazy-GC (adopted, not-yet-dropped) `dead` op no longer pollutes the next checkpoint's winners. | `tests/test_compaction.py::TestF2RetainedExcludesDead` — adopts a checkpoint without `gc_checkpoint`, asserts the dead op is absent from `PrevState.retained`. |
| **C-1** | ✅ FIXED | `9916093` | `acceptor.on_prepare` voids a slot ONLY when the accepted op is present AND below the horizon. Envelope absence keeps the accepted op (a fetch problem) instead of voiding it, so a GC'd-but-live slot can no longer be re-won. Horizon is the sole void authority (DESIGN §8). | `tests/test_acceptor.py::TestC1VoidOnMissingEnvelope` — accepts an op, GCs its envelope with the horizon still at 0, asserts `on_prepare` still reports the decided op. |

## Still open (confirmed, in progress / queued)
- **K-1 + K-2** — roster activation / `on_roster_accept` have no authz on the op author, no
  slot binding, and verify the new half against the op-declared roster. Fix: a roster
  predicate module mirroring `checkpoint.py` (authz + slot_bound + old-roster verify +
  RosterOp type + `from_epoch == current`), plugged uniformly.
- **C-2** — floor gate runs before the idempotent-re-accept exemption ⇒ re-ACCEPT after δ
  deadlocks a checkpoint/roster slot. Fix direction proposed; **Harry not yet decided** on
  the exact fix (write the repro first, then choose).
