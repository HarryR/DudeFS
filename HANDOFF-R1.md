# HANDOFF-R1 — implementation hand-off after review wave R1

> **From:** review side (Fable) · **To:** implementation side (Opus) ·
> **Date:** 2026-07-20 · **Baseline:** M0–M4 green (`make check`, 80+ tests)
> at commit `9a6c2c8`; documents at **revision 6**, cross-reviewed for
> internal consistency (independent pass: zero normative contradictions).
>
> The documents are canonical and self-consistent — work from them, not from
> memory of rev 5. NOTES.md items 25–31 are the *rationale record* for the
> rev-6 edits (all RESOLVED); the R1 marker in NOTES.md is the coordination
> line. **If code and documents disagree, the documents win** — raise new
> discrepancies as numbered NOTES items below the R1 marker, never code
> around them.

## What changed at rev 6 (read these before anything else)

1. **DESIGN §12 is rewritten**: compaction is **log-compaction** — live
   winner ops retained **in place**, sparse log below a continuously
   advancing conveyor cut. There is no snapshot blob anywhere anymore.
   Checkpoint schema: `{cut, state_root, dead, retained, attempts,
   keyepoch, hlc, prev, sig}`, minted under the `compact` capability.
2. **DESIGN §8 gained the acceptor void rule** (slot state with
   `accepted_op.hlc` below the checkpoint horizon is void on `prepare`) and
   the ballot/backoff text now matches the M4 code: ballots are
   `(round, priority)`, `priority = h(slot_tag ‖ client_fp)`; deterministic
   jitter + round-timeout escalation.
3. **PROTOCOL**: `PULL` serves sparse retained runs below the cut (no
   receipts/QCs there — the checkpoint vouches); `SUMMARY` carries retained
   digests; `DELTA` intake is not peer-gated (salvage path); §3.2 is the
   conveyor flow; §1.3 has the client-side below-horizon no-accept guard.
4. **RESILIENCE §2.2**: recovery checkpoint = same artifact with a fiat cut
   at the salvage frontier; salvaged-but-uncommitted ops adopted by fiat;
   the roster op's old-quorum half is waived there and only there
   (DESIGN §13 "recovery exception").
5. **FORMAL**: A4 restated in retained-set form; B1 scoped for reborn
   absent-key tags; B7 wording matches the real backoff mechanism.

## Work order

### WP1 — M5, control plane (IMPLEMENTATION §5 M5, as amended)

Certs; fold-positional revocation; roster 1→3→5 with possession barrier +
learner catch-up; the public roster slot (two competing managers → one
activation — **B4 test**); `RERECEIPT` across the epoch bridge (**B5
test**); **delegated capabilities including the `compact` compactor cert**
(this upgrades NOTES item 9's "root-key-only" M1 simplification — control-op
authz must now validate *capability*, not root identity; a checkpoint signed
by a valid `compact` cert is authorized, one signed by a plain client cert
is not).

### WP2 — M6, log-compaction (DESIGN §12 rev 6 + IMPLEMENTATION §5 M6)

Deliverables, in dependency order:

1. **Checkpoint artifact** per the §12 schema (golden vectors; `dead` is the
   incremental delta, `retained` is the *full* per-author `(count, digest)`
   commitment — only the latest checkpoint is ever load-bearing).
2. **Compactor fold**: incremental tail-fold since the previous cut;
   dead-set computation honoring the **resurrection mask** (a tombstone is
   GC-able only if no retained op mutates its key); `attempts` sidecar
   (nonzero live-key attempts only, encrypted); `state_root` unchanged in
   shape (leaf includes `attempt`, domain-separated — NOTES items 10/19).
3. **Node GC**: drop `dead` ops, receipts/QCs ≤ cut, slot state ≤ cut;
   receipt floor at the horizon; keep retained envelopes + latest
   checkpoint + control-plane liveness set (certs, wrap-sets, roster,
   endpoints — these NEVER GC).
4. **Acceptor void rule** + client-side no-accept guard, with the NOTES 27
   scenario as a regression test: delete a key, checkpoint past the
   tombstone, recreate the key against a node that has NOT yet GC'd the
   original creation slot — must converge, not livelock.
5. **Sparse below-cut `PULL`** + `SUMMARY` retained digests + digest
   verification on intake (a node/client can prove below-cut completeness
   per author).
6. **Bootstrap fold**: retained winners' mutations only, in
   `(hlc, author, seq, op_hash)` order, **no guard re-evaluation**, apply
   the sidecar, verify `state_root`, then fold the tail normally.
7. **A4 integration test — retained-bootstrap ≡ full-history fold** —
   including two vectors that MUST fail if their mechanism is removed:
   the **resurrection vector** (multi-key winner writes A+B, B later
   deleted below the cut → without the mask, bootstrap resurrects B) and
   the **sidecar vector** (contended key with nonzero attempt at the cut →
   without the sidecar, bootstrap derives a different expected tag).
8. Housekeeping: rename the fold's `Snapshot` type (`fold.Snapshot`,
   README layout line) to something barrier-flavored (`BarrierState` /
   `FoldState`) — "snapshot" now invites exactly the confusion §12 kills.

### Gotchas (the mistakes a fresh reading is most likely to make)

- **Nothing ever moves.** Retention is in-place; retained ops keep their
  original `(hlc, seq)` and the log goes sparse. There is no "push to the
  head of the conveyor" — only the cut advances.
- **Mask tombstones are not lineage anchors** — the dead key still resets
  to `(⊥, 0)`; the tombstone is retained solely so the bootstrap LWW fold
  yields "absent".
- **The `dead` delta is GC work; the `retained` digest is the commitment.**
  Don't reconstruct the retained set by chaining deltas from old
  checkpoints — each checkpoint's digest is self-contained.
- **Below the cut there are no QCs by design** — do not "fix" a missing QC
  on a retained op; the checkpoint vouches (NOTES 29d ruling).
- **The recovery checkpoint is not new machinery** — same artifact, fiat
  cut precondition, flagged in the op body; do not build a second code
  path (RESILIENCE §2.2).
- **Blind writes can be winners** and multi-key winners are retained whole;
  their superseded side-mutations are corrected by later winners in fold
  order — resist the urge to trim mutations (ops are signed; never
  rewrite).

### Out of scope — do not implement

- The **re-anchor** op (recorded escape hatch in §12 declared costs).
- **NOTES item 32** (parameter governance, root succession, δ_control) —
  raised, awaiting owner ruling; nothing in M5/M6 depends on it.
- M7/M8 material (daemon entropy mixing for backoff is an M7 task —
  NOTES 28).

### Verification bar

`make check` green per milestone; FORMAL ids in test names
(`test_A4_...`, `test_B4_...`, `test_B5_...`); keep the 80-scenario
contention sweep and existing regression seeds green; every new invariant
above gets a test that fails when its mechanism is deliberately broken.
