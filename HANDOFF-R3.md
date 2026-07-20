# HANDOFF-R3 — work order after ruling wave R2

> **From:** designer/reviewer (Fable) · **To:** implementer (Opus) ·
> **Date:** 2026-07-21 · **Baseline:** `ae4005d` (M0–M6 green, 108 tests)
> **plus the R2/R3 ruling edits in the same commit-wave as this file**:
> NOTES items 34–35; DESIGN §8/§12/§13/§15/§18; PROTOCOL §1.1/§2.1/§2.2/§3.2;
> RESILIENCE §2.3/§3-intro; MANAGER §3; FORMAL A4; IMPLEMENTATION §6.4–6.6.
>
> The documents are canonical. Every HANDOFF-R2 question is ruled (NOTES 34);
> the R3 framing — optimization ledger, threat re-weighting, the fumbling
> manager — is ruled in NOTES 35. **If code and documents disagree, the
> documents win** — raise discrepancies as NOTES items below the R3 marker.

## 0. What R2/R3 settled (read first)

1. **NOTES 34** — all five Q-rulings: the cut IS the pin (Q1); baseline
   completeness = `covered ∖ dead` equality (Q2); cert `epoch` is metadata,
   never a fence — no fold change (Q3); the compactor is incremental by
   contract (Q4); `Promise.accepted_hlc` blessed and the checkpoint gains an
   explicit `horizon = F` field (Q5). Fixes 5 and 7 verified correct (7 is
   *complete* — no second retention class exists; the applied-ops lemma in
   NOTES 34). Finding 4 is GO. A new finding 11: `holds_frontier` is a fourth
   cut-unaware gate (post-GC roster change wedges).
2. **DESIGN §18** — the dial ledger: invariants vs dials, the two real
   trilemmas (replication, compaction), the named non-tensions.
3. **RESILIENCE §2.3 + MANAGER §3** — the fumbling manager: mistaken
   recovery is contained by *activation-is-the-park* + QC-vs-manifest
   disclosure; prevention lives in tool interlocks. **Recovery is never
   urgent** is now normative.
4. **RESILIENCE §3 intro** — TEE deployment profile: octopus tentacles on
   storage nodes are the priority threat; client-side personas deprioritized.

---

## WP1 — the correctness wave (gates M7; false-rejection pairs mandatory)

Every gate below gets the IMPLEMENTATION §6.5 treatment: beside each
reject-side test, a boundary-valid-ACCEPTED test. Boundary cases first:
at-the-cut, at-the-horizon (`hlc == F`), first-op-above-the-barrier.

1. **Finding 4 (land first, independent):** `Commit._on_fetch_reply` returns
   `[]` on any reply that is not the awaited op; the round deadline
   escalates. Prefer dispatching on `isinstance(req, FetchOpReq)` in `feed`
   over payload-type sniffing. Regression: a late hedged Promise and a Nack
   arriving mid-FETCH must not abort; the commit still decides.
2. **Cut-aware store (findings 1/2/11, per DESIGN §12 pinned-heads +
   §13 cut-relative barrier):**
   - Persist the active cut in the store on checkpoint adoption (it is in
     the durability domain — must survive crash-restart; test that).
   - `heads()`: anchor at `cut_seq + 1`; report the pin when no tail
     extends it; authors absent from the cut anchor at 0.
   - `append()`: admit iff `pred ∈ store` OR `seq ≤ cut_seq[author] + 1`.
   - `holds_frontier()`: at-or-below the cut, possession = verified
     baseline completeness; per-op check above only. Regression: roster
     change succeeds after full GC with an idle author whose frontier
     entry names a dead envelope.
3. **Retained projection (finding 3, per DESIGN §12 baseline-completeness):**
   `summary()` / `pull_baseline()` / `verify_baseline()` digest over
   `covered ∖ dead`. Regressions: (a) lazy-GC node verifies complete;
   (b) **the oscillation bug** — a GC'd node gossiping with a lazy peer
   must converge, not re-pull dead envelopes every round.
4. **Incremental compactor (Q4, per DESIGN §12):** new contract
   `compact(prev_retained, prev_attempts, prev_cut, tail, …)`; assert the
   precondition; `dead = (prev_retained ∪ covered_tail) ∖ new_retained`;
   genesis-first = degenerate `prev = ∅`. **A4 must hold across two
   successive checkpoints** — new vector: an op retained by checkpoint 1
   (winner or mask) that dies in checkpoint 2's delta.
5. **Horizon carrier (Q5):** checkpoint schema gains `horizon` (HLC);
   golden-vector bump in the same commit; `advance_horizon` and
   `QuorumConfig.horizon` source from the latest committed checkpoint.
   Boundary pair both sides: an accept at exactly `hlc == F` is **not**
   voided (acceptor) and **not** ignored (client); one strictly below is.
6. **A4 property fuzz (IMPLEMENTATION §6.6):** seeded random chains
   (N ops, random multi-key set/del/CAS over K keys), compact at a random
   final cut, assert `fold(full) ≡ bootstrap(retained ∘ tail)` — run it
   also through the WP1.4 two-checkpoint path.
7. **Recovery-fence trigger — activation-is-the-park (DESIGN §13 as
   amended, NOTES 36):** this is protocol behavior and lands HERE, unit-
   tested, before any WP4 persona exercises it. Ruling: it is a
   **restatement of M5's `activate_epoch`, not new machinery** — the same
   monotone epoch switch with a second validated trigger (the root-signed
   recovery pair substitutes for the joint certificate); the park is the
   emergent effect of the `e+1` stamp meeting client-side epoch checks.
   Work: `ROSTER` body gains an optional `recovery` field naming the
   recovery checkpoint; recovery-marked roster ops are **root-only** (a
   delegate's folds invalid — fiat must not be delegable); acceptor gains
   the validate-pair-then-`activate_epoch` step. Unit tests: (a) valid
   root-signed pair activates without a joint QC and old-epoch receipting
   stops; (b) a `manage-roster` delegate's recovery-marked op does NOT
   activate and folds invalid; (c) a replayed fence for an already-passed
   epoch is a no-op (monotone); (d) a normal roster op still requires the
   joint certificate. Distinct from the possession barrier (which gates
   *joining*); the fence parks everyone who sees it.

## WP2 — chaos axes (harness first; all seeded, all replayable)

Extend `transports/memory.py` + `sim/harness.py`. These are *carrier*
features — personas (WP3/4) plug into them; keep the one-seam-per-milestone
discipline.

- **Latency:** per-link base + jitter; heavy-tail spikes (rare 100×);
  **asymmetric** A→B vs B→A. Assertion: hedging masks a slow (not failed)
  node — tail latency bounded by the hedge schedule, and hedges cancel on
  quorum (no blast).
- **Ordering:** per-link reorder windows; duplication; **burst loss**.
  (Uniform loss/dup/reorder exists — add burstiness and per-link asymmetry.)
- **Partitions:** every cut of the roster (minority-with-manager,
  minority-with-compactor included); **flapping**; **one-way links**
  (A hears B, B doesn't hear A). Assertions: minority writes park, majority
  continues, reads continue everywhere, heal converges (gossip fixpoint).
- **Time skew:** per-node clock offset within / at / beyond δ; slow drift;
  **step jumps** (NTP-style, both directions). Assertions: floor
  monotonicity survives a backward jump (attested floor is durable);
  `hlc == floor` accepted, below rejected; future gate at `now + δ`.
- **Crash-restart:** kill at every persistence boundary (RESILIENCE §1.2
  rows) — especially between store COMMIT and signing (must be safe by
  sign-after-fsync) and mid-GC.
- **Continuous assertions** while any of the above runs: B1 (≤1 decided op
  per tag per barrier interval), B2 (committed survives), B3 (nothing new
  commits below an attested quorum frontier), A1 (all clients' folds
  byte-identical at quiescence), B6 (any violation ⇒ evidence exists).

## WP3 — node-side personas (TEE re-weighting: these outrank client personas)

First-class `LocalNode`/acceptor subclasses in the sim (IMPLEMENTATION §6.4).
Each asserts **containment AND evidence**:

1. **Equivocator** — signs two receipts at one `(tag, ballot)` for different
   ops. Requires implementing `EvidenceKind.DOUBLE_VOTE` minting (currently
   a stub): two conflicting receipts = portable proof. Assert: state
   unaffected (lineage collapses duplicates), proof minted at whichever
   party assembles both.
2. **Floor perjurer** — attests a floor, receipts beneath it later.
   Requires `EvidenceKind.FLOOR_PERJURY` (WM + contradicting receipt).
   Assert: state still converges; proof minted.
3. **Withholder / eclipser** — serves a stale-but-signed frontier, withholds
   ops from one client. Assert: staleness never unsafety; one honest
   contact heals; the §7.3 relay-read property holds through it.
4. **Amnesiac node** — wiped, resumes under its old key, double-votes.
   Assert: evidence → identity-retirement flow (revoke + fresh learner).
5. **Mixed-laziness GC population** — not malicious, just wonky: nodes GC at
   wildly different times mid-traffic. Assert: digests stable (WP1.3),
   convergence, no false rejections.
6. **Split-view two-victims test** (RESILIENCE §3.5, now provable): two
   stores fed divergent root-signed chains from one genesis, then merged —
   `FORK` evidence must mint at the divergence seq. This upgrades the §3.5
   detection claim from paper to test.
7. *(Deprioritized, keep as boundary tests only: time-traveller client —
   TEE profile, RESILIENCE §3 intro.)*

## WP4 — the fumbling-manager suite (the most probable real failure)

Honest-but-confused root. Global invariants for every scenario: no silent
divergence; ≤1 roster activation per epoch (B4); committed data survives
**or** surfaces as loud QC-vs-manifest disclosure; evidence where docs claim.

1. **Retry storms:** resubmit the identical roster op / checkpoint N times
   with crashes interleaved — idempotent, one activation.
2. **Crash-at-every-step:** PROTOCOL §3.1's six steps × {die, resume
   verbatim, abandon-then-attempt-a-different-change}. The abandoned flow
   must never half-activate.
3. **Double-press:** two *different* roster ops for the same `from_epoch`
   (crashed-and-retried manager with a new plan). Exactly one activates.
4. **Stale-frontier roster op:** sync frontier below the current cut —
   must compose with the WP1.2 `holds_frontier` fix, not wedge.
5. **Cross-flow interleave:** checkpoint mid-roster-change and vice versa;
   compactor-cert revoke mid-conveyor; rotate mid-write.
6. **Amnesiac manager:** re-authors its own seq without the DESIGN §4
   amnesia procedure → FORK evidence minted, fold stays deterministic;
   with the procedure → no fork. (The MANAGER §3 guard, exercised.)
7. **Mistaken recovery** (RESILIENCE §2.3): manager on the minority side of
   a partition runs the §2.2 flow while the old quorum lives. Exercises
   **WP1.7's fence trigger** — nothing is implemented here, only composed.
   Assert: pre-heal divergence bounded to the partition; on heal the old
   world parks (no racing lineages); over-window commits surface as
   QC-vs-manifest contradictions, attributed to the recovery op.
8. **Button-masher property test:** seeded random sequences of manager
   verbs (roster, checkpoint, cert issue/revoke, rotate, recovery) ×
   crashes × partitions; the global invariants above run continuously.
   This is the test that answers "I hit all the buttons without keeping
   track" with something better than hope.

## Designer-owned (mine, running in parallel)

- **D1:** MANAGER recovery-interlock spec is landed (§3); whether the
  recovery fence carries an explicit `presumed_dead` list is OPEN — decide
  when WP4.7 shows whether the park rule needs it.
- **D2:** DESIGN §18 dial ledger — ratify or amend after Harry reviews.
- **D3:** next review pass targets the WP1 diff (cut-aware store +
  compactor rewrite are the two highest-risk changes in the codebase).

## Sequencing (hard gates, not one push — NOTES 36)

R3 is deliberately three milestones wide; it is NOT executed as one wave:

1. **WP1 (including 1.7) → fully green → STOP.** Hand the diff back for
   the D3 review before anything else starts: the cut-aware store and the
   compactor rewrite are the two highest-risk changes in the codebase, and
   WP1.7 is new acceptor surface. WP1.1 lands immediately; WP1.5's
   golden-vector bump is one commit.
2. **WP2 (harness) alone** — one seam, reviewed on its own.
3. **WP3/WP4 (personas)** plug into the reviewed harness. Within them:
   equivocator and mistaken-recovery first — one is the core
   detect-and-punish claim, the other is the most probable real event.

WP1 gates M7 (findings 1/2/3/11 become live the moment the daemon wires
GC). `make check` stays green at every commit; chaos tests replay from
seed.
