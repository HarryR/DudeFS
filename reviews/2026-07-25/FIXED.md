# Fix log — 2026-07-25 review

Each confirmed finding, as it is fixed, with a red-repro test that fails before and passes
after (a genuine regression test, not a re-assertion of the fixed behavior). Workflow per
finding: **red repro → surgical fix → green → annotate here**.

| Finding | Status | Commit | Fix | Regression test |
|---|---|---|---|---|
| **F-2** | ✅ FIXED | `b4d9835` | `compactor.PrevState.of` masks by `tx.cut_dead()` — retained = `covered ∖ dead`, matching `store.baseline_commitment()`. A lazy-GC (adopted, not-yet-dropped) `dead` op no longer pollutes the next checkpoint's winners. | `tests/test_compaction.py::TestF2RetainedExcludesDead` — adopts a checkpoint without `gc_checkpoint`, asserts the dead op is absent from `PrevState.retained`. |

## Still open (confirmed, in progress / queued)

- **C-1** — void rule voids on envelope-absence (`acc is None`), not only below-horizon.
  Root: an ambiguous `tx.get_op() -> None` (Harry: expected conditions need unambiguous
  return types; only truly-unexpected states throw). Fix: void only on the meaningful
  below-horizon condition; a missing envelope is a fetch problem.
- **K-1 + K-2** — roster activation / `on_roster_accept` have no authz on the op author, no
  slot binding, and verify the new half against the op-declared roster. Fix: a roster
  predicate module mirroring `checkpoint.py` (authz + slot_bound + old-roster verify +
  RosterOp type + `from_epoch == current`), plugged uniformly.
- **C-2** — floor gate runs before the idempotent-re-accept exemption ⇒ re-ACCEPT after δ
  deadlocks a checkpoint/roster slot. Fix direction proposed; **Harry not yet decided** on
  the exact fix (write the repro first, then choose).
