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

## Wave 2 — the fix review's own findings (uncommitted at time of writing)

Reviewed in [FIX-REVIEW.md](FIX-REVIEW.md); wave 1 above was **1 of 4 fully closed**. Repros
were written FIRST, from the *reported scenario* rather than from the intended patch — the
correction wave 1 earned. Each was verified RED before its fix and green after.

| Finding | Status | Fix | Regression test |
|---|---|---|---|
| **FIX-6** (C-2a self-conviction) | ✅ FIXED | `on_accept`'s floor-gate exemption narrowed from "same op" to **same op AND same ballot** — a verbatim retransmit, which `_issue_receipt` serves from store at its ORIGINAL `issue_seq` and so cannot mint a new artifact. A different ballot idents differently in `reserve_receipt_seq`, mints a fresh seq, and was producing honest-node FLOOR_PERJURY. | `test_acceptor.TestC2aReacceptMustNotSelfConvict` — asserts the **invariant** (`detect_floor_perjury == []`), not the re-ACCEPT's outcome, so it stays valid whichever way the request is answered. |
| **C-1** (properly, via FIX-1) | ✅ FIXED | `slot_state` gains `accepted_wall/accepted_ctr` (native `INTEGER`), `SlotState.accepted_hlc` is set with `accepted_op`, and `on_prepare`'s void rule reads it instead of the envelope. The predicate is now **total**: no undefined "envelope missing" case, so neither failure mode (amnesia ⇒ two QCs; never-void ⇒ NOTES 27 livelock) is reachable. `on_prepare` also lost its `get_op` call and can always report `accepted_hlc`, restoring the `quorum.py:388` client guard. | `test_acceptor.TestC1VoidStillFiresBelowHorizon` — drives the **real** adopt pairing (`adopt_checkpoint` + `gc_checkpoint` in one txn) and asserts the void DOES fire. Paired with the retained `TestC1VoidOnMissingEnvelope`, which pins the other direction (absence alone must never void). |
| **K-8** | ✅ FIXED | `_pull_chain` now requires `fetched.op_hash == h` **and** `verify_sig()` before storing. Closes the K-8 → F-1 chain at the K-8 end (an injected control op could otherwise become a fold barrier). | `test_client.TestK8FetchedOpMustMatchTheRequest` — a typed subclass overrides the fetch seam (no monkeypatch, so `ty` checks the stub). |
| **K-13** | ✅ FIXED | Request→reply binding: `lmsg.request_digest(env)` over the request's signed bytes; the daemon's `_reply` echoes it in the (previously dead) `nonce`; `Link.request` computes it once and passes `expect_nonce`; `_check_reply` compares with `compare_digest` and returns a new cause-named `WrongRequest`. `expect_nonce` is **required**, deliberately — an optional correlator is how the field sat dead for a milestone. | `test_lmsg.TestK13RequestReplyBinding` ×3 — substitution refused, legitimate reply still accepted (no false rejection), digest deterministic and request-separating. |

Plus one **tripwire**, not a fix — `test_personas.TestPersonaMirrorsHonestSlotShape`.
`EquivocatingAcceptor` hand-copies the honest `on_accept` body to drop one guard, so every
field the honest path denormalizes into `SlotState` must be mirrored by hand; `accepted_hlc`
was such a field. A persona writing a different slot *shape* is no longer a faithful
equivocator (the void rule keys on `accepted_hlc`), which weakens every adversarial test built
on it — and the comment asking a human to remember cannot fail CI. The test compares *which
fields are populated* over `SlotState.__slots__`, so it extends to the next denormalized field
without needing an update. **Negative control verified**: green as-is, FAILS with the persona's
mirroring line removed, green on restore.

Gate after wave 2: **ruff + format + `ty` all clean; 366 tests, 1 failure** — `C-2b`, which is
an intentional documented RED (below).

## Wave 3 — the structural directions (uncommitted)

[DIRECTIONS.md](DIRECTIONS.md) **D-A** and **D-B** implemented. **D-C** (Promise demotion)
deferred: it is a wire-format change and wants its own pass.

| Direction | Status | What landed |
|---|---|---|
| **D-A** — RC-1 as a type | ✅ 3 of 5 sites (the other 2 must NOT be gated — see below) | New `dudefs/committed.py`: `CommittedSet.of(ops, qc_for, rosters)` is the one verifying boundary, with the two-arm rule (quorum authority for data ops **and checkpoints**; chain authority for the rest) stated in the type instead of implicit at a call site. Wired into `client._committed_ops` (**closes F-1**), `compactor.CompactorView.of` (**closes the K-5 presence-trap inheritance**), `compactor.PrevState.of` (**closes F-2's reported half**). |
| **D-B** — acceptor named predicates | ✅ done | `on_accept`'s guards became `_verbatim_reaccept` / `_equivocates` / `_below_horizon` — named, pure, individually testable, each documenting the one attack it stops (checkpoint.py's `_RULES` shape). |

### D-A correction: RC-1 over-collected

Implementing it surfaced an error in the original review's grouping. `client._bootstrap_barrier`
and `gossip.Summary.of` operate **below the cut, where per-op QCs are GC'd by design** — gating
them on a verified QC is not merely unnecessary, it is wrong:

- `_bootstrap_barrier` already verifies the *checkpoint's* QC, and the below-cut vouch is
  `state_acc`, not a per-op QC. F-7's client arm is really **IO-14** (no purge path), not RC-1.
- `baseline_digest` is a **possession-comparison** protocol; filtering by *locally available*
  QCs would make two honest nodes advertise different digests and wedge the §13 roster change —
  the same shape as C-5, self-inflicted.

**Rule:** RC-1 applies above the cut, where authority is quorum authority and the QC is present.
Below the cut, authority has transferred to the checkpoint's `state_acc` and its own QC.

### D-B removed the tripwire it was supposed to make redundant

`EquivocatingAcceptor` no longer hand-copies `on_accept`; it overrides `_equivocates` to return
`False` and inherits everything else, so slot-shape divergence is now **unconstructible** rather
than merely detected. `TestPersonaMirrorsHonestSlotShape` was therefore **deleted**: with both
sides running identical code it could no longer fail, and a test that cannot fail is exactly the
tautology class this review flagged (A-15/A-16). Construction beat enumeration, as intended.

Gate after wave 3: **ruff + format + `ty` clean; 365 tests, 1 failure** — `C-2b`, intentional.

## Still open (confirmed, queued)

**Awaiting a ruling, not a patch:**
- **C-2b** — the re-drive deadlock. `TestC2bRedriveNeedsAQuorum` is RED **by design**: with the
  FIX-6 narrowing it now yields **0** receipts rather than 1, because the old exemption was
  helping only the node that didn't need it. Cannot be fixed by relaxing a gate (that is FIX-6);
  the remaining direction is an `attempt` component on `checkpoint_slot_tag`/`roster_slot_tag`,
  which needs the §8/§13 tag ruling and wants **D-1** (unbounded `slot_state`) bounded first.
  ⚠️ Do not "fix" this failing test — it is the acceptance criterion.

**Queued, confirmed:**
- **RC-1** unverified-store reads — the critical path. F-2's *reported* mechanism (the never-QC'd
  op that never enters `dead`) plus F-1, F-7, K-3/4/5. Wants **one** committed-ness predicate
  applied at five sites, not five local patches — F-2's partial fix is the evidence for that.
- **RC-4** immortal-loop exception scoping (IO-3/11/12) · **IO-2** roster-from-bootstrap ·
  **F-3** compaction wedge · **F-4** non-total cut tie-break · **C-3** unreachable RERECEIPT.
- **D-1** `slot_state` never pruned — now a one-liner, since FIX-1 made the hlc an indexed
  `INTEGER`: `DELETE FROM slot_state WHERE accepted_wall < ?`.
- **K-14** the Promise's redundant signature · **C-9** ballot-priority binding · **RC-6** thread
  requester identity into L3 · **FIX-4** `WRONG_EPOCH` · **FIX-5** dead `RosterAcceptReq` fields.
