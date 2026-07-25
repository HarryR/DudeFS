# Fix log — 2026-07-25 review

Each confirmed finding, as it is fixed, with a red-repro test that fails before and passes
after (a genuine regression test, not a re-assertion of the fixed behavior). Workflow per
finding: **red repro → surgical fix → green → annotate here**.

| Finding | Status | Commit | Fix | Regression test |
|---|---|---|---|---|
| **F-2** | ✅ FIXED | `b4d9835` | `compactor.PrevState.of` masks by `tx.cut_dead()` — retained = `covered ∖ dead`, matching `store.baseline_commitment()`. A lazy-GC (adopted, not-yet-dropped) `dead` op no longer pollutes the next checkpoint's winners. | `tests/test_compaction.py::TestF2RetainedExcludesDead` — adopts a checkpoint without `gc_checkpoint`, asserts the dead op is absent from `PrevState.retained`. |
| **C-1** | ✅ FIXED | `9916093` | `acceptor.on_prepare` voids a slot ONLY when the accepted op is present AND below the horizon. Envelope absence keeps the accepted op (a fetch problem) instead of voiding it, so a GC'd-but-live slot can no longer be re-won. Horizon is the sole void authority (DESIGN §8). | `tests/test_acceptor.py::TestC1VoidOnMissingEnvelope` — accepts an op, GCs its envelope with the horizon still at 0, asserts `on_prepare` still reports the decided op. |
| **K-1 / K-2 / K-12b** | ✅ FIXED | `b0fd1d7` | The roster path gains the checkpoint path's rigor. **K-1** (`daemon._activate_one`): authz gate + slot binding + unique members before seating. **K-2** (`acceptor.on_roster_accept`): trust only the signed op body — reject non-RosterOp, `from_epoch == epoch` (§13), barrier on `op.sync_frontier` not the requester's. **K-12b** (`RosterOp._from_body`): reject duplicate members. | `TestK1RosterEscalation` (a WRITE-certed client cannot seize the roster), `TestK2RosterAcceptGate`. Legit `change_roster` (test_manager) still green. |
| **C-2** | ✅ FIXED | `f49e72c` | `acceptor.on_accept` reads the slot first and skips the future/floor gate for an idempotent re-ACCEPT of the SAME op (mirrors the BELOW_HORIZON same-op exemption). A verbatim re-request (dropped/retried transmit) re-yields its receipt; a DIFFERENT op below the floor is still gated. Clears the checkpoint/roster re-drive deadlock after δ. | `tests/test_acceptor.py::TestC2ReacceptAfterDelta` — accepts an op, lets δ pass, re-ACCEPTs it verbatim, asserts the same receipt (not BELOW_FLOOR). |

All four of Harry's chosen findings (F-2, C-1, K-1/K-2, C-2) are fixed with regression tests.

## Still open (confirmed, queued)
The rest of the review's HIGH/MEDIUM cluster, e.g. **RC-1** unverified-store reads (F-1, F-7,
K-3/4/5), **RC-4** immortal-loop exception scoping (IO-3/11/12), **IO-2** roster-from-bootstrap,
**F-3** compaction wedge, **F-4** non-total cut tie-break, **C-3** unreachable RERECEIPT.
