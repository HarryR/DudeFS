# HANDOFF-R6 — Compaction: completing the conveyor, end-to-end

> **From:** reviewer/planner (Opus) · **To:** implementer · **Date:** 2026-07-22 ·
> **Baseline:** `530ad9a` (296 green). Companion to **DESIGN §12** (normative — the conveyor
> cut, retention rule, barrier, GC), **§8** (acceptor/slots + durability & GC), **§9** (finality),
> **§13** (membership/possession-barrier/recovery), **NOTES 27** (void rule) and **NOTES 29**
> (log-compaction rulings: a=sidecar, d=GC-QCs, f=compactor cert, g=cut-lag W).
>
> **Depends on [HANDOFF-R5.md](HANDOFF-R5.md)** (storage foundation — per-connection WAL +
> transactions). This milestone runs heavily multi-threaded over the store and is unsafe until R5
> lands; the data race (#3) is fixed there.
>
> **This is a work order, not documentation.** The design is *complete and ruled* — this
> milestone builds the implementation up to it; it does not reopen the design. Genuine design
> questions become NOTES items (see §7), never workarounds. The CLI work (originally R5, now the
> active **[HANDOFF-R7.md](HANDOFF-R7.md)**) follows this milestone — the CLI is a thin shell over
> already-correct machinery.
>
> **STATUS (2026-07-24).** LANDED + green: WP-0, WP-I, WP-A, WP-B, WP-C, WP-D, WP-E (#9),
> WP-F(b) (checkpoint-QC verify) + the full **client verify-pass** (issue #3, closes #11 and the
> client half of #5/#9), and **WP-G the compactor driver** (`dudefs/compactor_daemon.py`:
> sync → final cut → author Cap.COMPACT checkpoint → commit → nodes adopt), now **INCREMENTAL**
> (band-only, == full recompute A4) with **durable restart-persistence** (adopts its own
> checkpoint: GC + persist cut/horizon; reconstructs prev from the store; state-machine tested
> across restart orderings). **WP-F COMPLETE — checkpoints are now quorum-consensus ops:**
> (a) adoption **validity gate** [cut+horizon dominance] and (c) **sequence-slotting** [DONE]:
> each checkpoint carries a monotone `seq`, is committed on the slotted `Commit` path at
> `checkpoint_slot_tag(seq)` (the blind path is gone), the declared seq **binds** its slot at
> adoption, and nodes adopt **strictly in sequence** (chained catch-up, fixes finding #10). The
> quorum decrees at most ONE checkpoint per seq ⇒ **divergence is impossible by construction**;
> a lagging concurrent compactor **skips rather than wedges** (won't author a cut that fails the
> dominance gate). **Remaining:** WP-H recovery variant (#12); WP-J manager control-plane compaction.

## 1. Why this is a milestone

Compaction is **half-implemented**, and worse than a first pass suggested. A three-axis
design-vs-implementation sweep (bootstrapping, CP/safety, concurrency) found that the fold
*kernel* is sound but the entire **operational layer** around it — establishing cut finality,
bootstrapping a fresh party, serializing compactors, verifying the checkpoint QC, adopting the
recovery variant — is missing, unwired, or **tested only in the sim harness, not the daemon**.

Today it is dormant-but-consistent: no driver authors real checkpoints → no GC → clients fold
full history and it works. **Enabling a compactor breaks correctness**: a fresh node deadlocks
on bootstrap, a non-final cut can seal and GC committed history (safety), the cut can regress,
and the maintenance thread races the serving thread. The compactor, the bootstrap consumer, the
finality gate, and concurrency control are one feature that must land **together**, behind
end-to-end tests **that run against the production daemon**.

## 2. The insidious trait: sim-tested ≠ production-tested

The compaction test suite (`tests/test_compaction.py`, `tests/test_chaos_compaction.py`) drives
`sim/harness.py`, whose `gossip_round` calls `gossip.pull_baseline` and adopts checkpoints
**out of band** (`sim/harness.py:314-321`). The production `NodeDaemon` does **neither** — it
syncs via `apply_delta`→`append` and adopts via `adopt_committed_checkpoints`, and **never calls
`pull_baseline`** (verified: `pull_baseline` appears only in `sim/` and tests). So the green tests
validate code production never runs. This is the root cause of Findings 1, 3, and 10 below, and it
retroactively corrects the earlier claim that node GC / adopt / baseline-sync were "built + tested":
they are built as **pure functions**, sim-tested, and **not wired into the daemon**.

**Consequence for this milestone:** the sim harness was a stopgap from before a real node existed.
Now that `NodeDaemon` exists, its innards must be made **composable and testable the same way the
sim harness is** (inject clock/peers/store, drive `gossip_round`/`adopt` in-process without
sockets), the compaction tests migrated onto that real path, and the sim retired (WP-I). Tests
must exercise what production runs.

## 3. Reconciliation — what's sound vs what's missing

**Genuinely correct** (mechanism, where built): fold math (`compact`, retention rule, resurrection
mask); the horizon *mechanism* — void-on-`prepare` strictness (`<`, acceptor.py:217), receipt-floor
(acceptor.py:269), monotone `advance_horizon` (acceptor.py:231), crash-restore (acceptor.py:114);
barrier placement (fold.py:485, *conditional on cut finality*); cut-aware `append`/`heads` **for an
already-adopted party** (store.py:377-380,438-453); adopt-before-GC ordering (daemon.py:273-275);
`verify_baseline` polarity; adoption idempotency. (Benign deviation: GC keeps retained winners'
below-cut QCs — more conservative than DESIGN.md:343.)

**Known stubs / unwired (first pass):** encrypted `attempts` sidecar is `b""` everywhere, seal/unseal
unbuilt (NOTES 29a MANDATORY → A4 break); `state_acc` computed+carried but **never verified**;
client fold (client.py:492) has no barrier so bootstrap-from-checkpoint is unwired; no production
cut/W selector; no compactor identity/chain; `quorum.Commit` slotted-only so no blind-commit driver.

**Operational-layer divergences found by the sweep** (each verified against code):

| # | Finding | Tag | Evidence | Impact |
|---|---|---|---|---|
| 1 | **Fresh-node bootstrap deadlocks** — daemon never calls `pull_baseline`; `append` rejects sparse below-cut winners as GAP, but the cut-exemption needs an *adopted* cut, and adoption needs the baseline complete. | IMPL-DIFF | pull_baseline sim/tests only; store.py:377-380; daemon.py:268 | wiped/new node can't join a GC'd cluster |
| 2 | **Cut finality never enforced** at mint or adopt. | DOC-UNBUILT | compactor.py:63; daemon.py:250-276 | **safety**: late below-cut commit → bootstrap-vs-full-history divergence |
| 3 | **Data race (live bug now → fixed in R5)** — maintenance thread (`sync_once`→adopt/GC/gossip) touches the shared sqlite connection **without `_lock`** that `serve` holds. Root cause = shared connection + Python lock; see HANDOFF-R5. | UNDOC | daemon.py:115 vs 209/241/357 | torn reads; inconsistent baseline handed to a peer |
| 4 | **Cut can regress** — highest-`hlc`-wins with no cut-dominance guard; `adopt_checkpoint` `INSERT OR REPLACE`s unconditionally; empty-cut recovery checkpoint resets cut to `{}`. | UNDOC | daemon.py:259; store.py:606; manager.py:487 | irreversible GC past a cut that then regresses |
| 5 | **Checkpoint QC adopted unverified (live trust gap)** — only `get_qc is None` checked; never `qc.verify(roster)`, no `config_epoch`; `put_qc` stores anything gossiped. | UNDOC | daemon.py:255 (cf. roster path daemon.py:322 which *does* verify) | forged/stale QC → bogus checkpoint "committed" → GC |
| 6 | **No compactor serialization** — checkpoints unslotted (roster ops are slotted); equal-`hlc` ties resolve by per-node `all_ops()` order (no `ORDER BY`) → nodes adopt different cuts, never reconcile. | UNDOC | control.py:94-103; store.py:455; daemon.py:259 | permanent divergence with >1 compactor |
| 7 | **Client horizon is dead code** — `QuorumConfig.horizon` defaults `HLC(0,0)`, never set in prod; client no-accept guard never fires. | DOC-UNBUILT | quorum.py:46; client.py:226 | reborn-tag **livelock** (NOTES 27 client half) |
| 8 | **`horizon`-covers-`cut` never validated.** | UNDOC | DESIGN.md:315 → no check | reintroduces #2 even with an honest cut |
| 9 | **Client read can't source the retained set** — `_pull_chain` walks `prev` backward, aborts at the first GC'd hole; retained winners have no QC so are dropped. | UNDOC | client.py:434-458,485 | bootstrapped client folds incomplete state even after the fold gap is fixed |
| 10 | **Dead deltas not applied in chain order** — adoption leaps to max-`hlc`; skipped intermediate deltas' ops pollute `baseline_digest` → `verify_baseline` mismatch → **adoption wedges**. | IMPL-DIFF | daemon.py:250-275; gossip.py:184 | a node that skipped a checkpoint can't adopt the next |
| 11 | **Per-retained-op provenance unverified at intake** — baseline winners via `put_op_raw` stored on digest-match only, no author-sig/cert-chain check. | DOC-UNBUILT | gossip.py:166 | §12:347 "verify every retained op" assumed, not done |
| 12 | **Recovery variant unwired + empty** — recovery fence does epoch-switch only (no cut/horizon/GC adoption); recovery checkpoint authored with empty cut/retained (no salvage manifest); `detect_lost_commits` never run by a node. | DOC-UNBUILT | daemon.py:279-291; manager.py:487; daemon.py:341-343 | post-recovery: no horizon protection, no manifest, no disclosure |
| 13 | **Compactor completeness precondition unasserted** — no check the compactor holds the full below-cut set before sealing; only backstop is the unbuilt `state_acc` verify. | DOC-UNBUILT | compactor.py:63-157 | a lagged compactor seals a wrong `dead`/winner, caught by nothing |

**Two are live bugs today, independent of the compactor:** #3 (data race — fires on any maintenance
tick overlapping a request, in the shipped M7 daemon; **fixed in HANDOFF-R5**, the storage
foundation) and #5 (a forged checkpoint+QC gossiped in would be adopted and GC executed; **WP-F(b)**
here). Both are live in the shipped M7 daemon regardless of when the compactor driver ships.

## 4. Work packages

Grouped; ordered so correctness + the finality/bootstrap/concurrency layer land and are tested on
the **daemon path** before the driver that would exercise them in anger. WP-0 and WP-I are enabling.

**Enabling / infrastructure**
- **WP-0 — Manager persistence onto the shared `ChainStore`.** A materialized view is *permitted*
  for the manager (single writer, DESIGN.md:254) and justified (ephemeral, fast-start; it holds
  only the ~100-item control plane, never the 5 GB data). The defect is that the view is
  hand-mutated across two non-atomic files and never reconciled to the log. Fix: derive it via the
  same `ControlState` fold and update log+view in **one SQLite transaction**; persist only secrets
  (`root.key`, `masters`) outside the fold. Manager + compactor co-locate → one shared, well-tested
  storage substrate across every component. Files: `dudefs/manager.py`.
- **WP-I — Composable node + retire the sim harness.** Make `NodeDaemon`'s sync/adopt/gossip innards
  injectable and drivable in-process (no sockets), the way `sim/harness` composes them; migrate the
  compaction tests onto the **real daemon path**; retire `sim/harness.py`. This is what makes every
  test below validate production. Files: `dudefs/daemon.py` (compose seams), `sim/`, tests.

**Correctness core** (drivable in-process with hand-built checkpoints)
- **WP-A — Attempts sidecar seal/unseal.** Codec between `cr.attempts` (cleartext) and the
  checkpoint's encrypted `attempts` field; wire seal into authoring, unseal into bootstrap barrier
  assembly; retire the `b""` stub. Files: `dudefs/handlers/control.py`, `dudefs/compactor.py`.
- **WP-B — `state_acc` derive-and-verify.** Recompute at intake (bootstrap + the compactor/manager
  auditors) and compare; loud, portable audit failure on mismatch. Files: `dudefs/fold.py`, consumer.
- **WP-C — Client/node bootstrap consumer.** Route the client fold through the checkpoint barrier
  (`barrier_state` + unsealed sidecar) instead of the unconditional full-history fold (client.py:492).
  Files: `dudefs/client.py`.

**Finality establishment** (the layer the horizon mechanism assumes — Findings 2,7,8)
- **WP-D — Cut-finality + horizon coherence gate.** Enforce, at **both** mint and adopt: the cut is
  covered by a quorum of watermark floors (final, DESIGN.md:337), and `horizon = F ≥ max hlc below
  cut` (DESIGN.md:315). Adoption verifies quorum watermarks ≥ `horizon` before `advance_horizon`.
  Wire the **client-side horizon** from the latest committed checkpoint into `QuorumConfig`
  (quorum.py:46; client.py:226) so the client no-accept guard actually fires. Files: `dudefs/compactor*`,
  `dudefs/daemon.py`, `dudefs/quorum.py`, `dudefs/client.py`.

**Bootstrap wiring on the daemon path** (Findings 1,9,10,11)
- **WP-E — Fresh-party bootstrap.** Wire `pull_baseline` (or an equivalent contiguity-free intake)
  into the daemon so a fresh node can store sparse below-cut winners **before** it has adopted a cut,
  breaking the deadlock; apply `dead` deltas in **checkpoint-chain order** (or resync-whole on a
  skip) so adoption doesn't wedge; **verify each retained op's author-sig/cert-chain/provenance** at
  intake. Give the client read path a retained-set source (digest-diff / checkpoint-aware read), not
  a `prev`-walk that aborts at the first GC'd hole. Files: `dudefs/daemon.py`, `dudefs/gossip.py`,
  `dudefs/client.py`, `dudefs/store.py`.

**Concurrency control** — compaction-logic only (Findings 4,5,6). *The connection/lock/transaction
model and the data race (#3) are fixed in **HANDOFF-R5** (storage foundation), which this milestone
sits on; the guards below run inside R5's per-connection write transactions.*
- **WP-F — Checkpoints are quorum-consensus operations (Findings 4,5,6). DONE (a)+(b)+(c).**
  A checkpoint is a link in a chain: checkpoint `k+1` advances *from* `k` (its cut dominates,
  its retained set carries `k`'s forward). Treat it exactly like a CAS / a roster change —
  the quorum decrees **one per sequence number**, and only a *valid* advance is adopted. This
  unifies (a) and (c): they are the two halves of one mechanism.

  **Why consensus, not blind + resolve-after (the load-bearing argument).** Two irreversible
  facts make post-hoc divergence resolution impossible, so divergence must be prevented *at
  commit*: (i) the finality **horizon is monotone + crash-durable** (findings 19/20 — it is the
  void-rule/anti-replay value), so a node that adopted checkpoint A (horizon F_A) can NEVER roll
  back to B with F_B < F_A; (ii) **GC is destructive** — a node that deleted its `dead` set can't
  reconstruct a checkpoint that needed those ops. So two compactors each picking a legitimate
  cut in the finality window and both blind-committing = *unrecoverable* wedge. The blind path
  (WP-G's shortcut) is safe ONLY under one honest compactor.

  - **(c) Serialize by a MONOTONIC SEQUENCE — `checkpoint_slot_tag(seq)`, decoupled from the
    cut.** Add a monotonic `seq` to the checkpoint body; the slot tag is a PUBLIC function of
    `seq` (the same shape as `roster_slot_tag(epoch)` — NOT a PRF/ZK tag, NOT the `prev`-hash).
    *The key must be the sequence, not the content:* the finality window admits a RANGE of valid
    cuts, so a content/cut-derived slot lets two both-valid checkpoints win different slots and
    diverge; a sequence collapses "the next checkpoint" to ONE slot regardless of which cut the
    winner chose. The compactor targets `latest_seq + 1`, authors with `slot_tag`, and drives the
    **existing slotted `Commit`** (PREPARE/ACCEPT) instead of `_commit_blind` — **no new verbs**
    (roster ops already prove a slotted *control* op folds + serializes). Concurrent compactors:
    one wins the slot, the other gets `LostSlot` and retries at `seq+1`.
  - **(a) Validity gate at adoption — reject the impossible, as early as possible.** The slot
    decides *one* checkpoint per `seq`; it does not make it *valid*. Adoption must verify the
    decided `k+1`: `seq == adopted_seq + 1` (chains), its cut per-author **dominates** `k`'s
    (#4, no regression), QC verifies, horizon-covers-cut, baseline complete. A checkpoint that
    fails is rejected by every node alike, leaving slot `k+1` open for a good compactor. Prefer
    rejecting BEFORE the log where feasible: the cut is cleartext, so a ZK acceptor *could*
    refuse a regressing checkpoint SUBMIT (never store it) — cheaper than adopt-time, harden
    toward it. **Local-log dump (idea, sharp edges):** a compactor/node that authored/holds a
    LOSING checkpoint attempt may GC it from its own log once it lost the slot — but only if no
    one else holds it, which is hard to prove, and deletion is destructive; default to letting
    the normal retention age it out rather than an eager targeted delete. Flag as a NOTES item.
  - **(b) Verify the checkpoint QC — DONE** (WP-F(b), landed): `qc.config_epoch == epoch and
    qc.verify(roster)` at adoption (daemon.py) + the client verify-pass (issue #3).

  **Staged (fewest footguns, trending valid-by-construction) — BOTH LANDED:**
  1. **Adoption validity gate (a) — LANDED.** `adopt_committed_checkpoints` rejects a checkpoint
     whose cut doesn't per-author dominate the adopted cut, or whose horizon regresses.
  2. **Sequence-slotting (c) — LANDED.** `seq` field in the checkpoint body + `checkpoint_slot_tag`;
     `compact_once` targets the quorum-committed frontier `seq+1` and drives the slotted `Commit`
     (blind path gone); adoption is **strictly sequential** (`seq == adopted+1`, chained catch-up
     — fixes finding #10) and **binds** the declared seq to its slot (`slot_tag ==
     checkpoint_slot_tag(seq)`, no seq-jump). Anti-wedge: a compactor won't author a link whose
     cut fails the dominance gate — a lagging concurrent compactor **skips and retries**, never
     wedges the chain with a decided-but-unadoptable checkpoint. Divergence impossible by
     construction. Tests: `test_daemon.TestAdoptionValidityGate` (dominance, sequential catch-up,
     seq/slot binding), `test_compactor_daemon.TestCheckpointSequencing` (monotone bound seq,
     second-compactor contends next seq). **RESIDUAL:** a TRULY concurrent multi-compactor
     deployment is serialized safely but the loser wastes a pass; the model is single-compactor
     (or manager-run, WP-J) — file an issue if concurrent compaction becomes a real deployment.

  Files (landed): `dudefs/daemon.py`, `dudefs/handlers/control.py` (seq field), `dudefs/artifacts.py`
  (`checkpoint_slot_tag`), `dudefs/compactor_daemon.py` (`_committed_frontier`, slotted commit).

**The driver**
- **WP-G — Compactor identity + author + commit + daemon. DONE.** Cap.COMPACT-signed
  checkpoint on the compactor's own chain; cut selector (F = quorum floor, `cut ≤ F` — W retired,
  ACCUMULATOR §2/DESIGN §12); `compactor run` (continuous) / `once`; keys via wrap-unwrap;
  INCREMENTAL + durable restart-persistence. Commit is now the **sequence-slotted `Commit`**
  (WP-F(c) landed; the blind shortcut is gone). Files: `dudefs/compactor_daemon.py`.

**Recovery variant** (Finding 12)
- **WP-H — Recovery checkpoint carries a real manifest and is adopted.** Author the recovery
  checkpoint with the salvage frontier as `cut` and the salvage manifest as `retained` (not empty);
  drive cut/horizon/GC adoption on the fiat path (not epoch-switch only); run `detect_lost_commits`
  in the node evidence cycle. Files: `dudefs/manager.py`, `dudefs/daemon.py`.

**Manager control-plane compaction**
- **WP-J — post-WP-0**, the manager's control plane checkpoints/compacts via the **same** path as
  any node (no bespoke `control.log` prune). Cut policy differs: control ops are effective-on-author
  (not quorum-final), so "dead" = SUPERSEDED (revoked cert, roster below the latest joint-cert,
  wrap-set below the current keyepoch), not below-a-finality-floor. Retained control set must be a
  SELF-SUFFICIENT live-state snapshot (current roster + activating joint-cert, live certs, current
  wrap-sets, keyepoch, active fences) so a cold backup reconstructs current control state from
  retained-only.

**PREREQUISITE for WP-H + WP-J — the resurrecting far-behind path (RULED, Harry).** Strict sequential
adoption (WP-F(c)) assumes every checkpoint from `adopted+1` forward is present. That holds only
because nothing GCs old checkpoint ops yet; **WP-J is what starts GC-ing them**, which strands any
backup whose next-needed seq is gone. So adoption needs TWO modes:
- **Hot (incremental):** `seq == adopted+1` — apply the incremental `dead` band. (Current code.)
- **Warm/Cold (bootstrap):** direct-adopt-latest — adopt a seq-DISTANT checkpoint whose `retained`
  baseline FULLY verifies, bypassing the sequence gate (the retained commitment is a COMPLETE
  baseline, not a delta), then **reconcile-GC** below the new cut (drop ops not in `retained`).

Ruled properties: **warm, not cold** — keep the store; delta-fill only the CHURN via gossip
(`retained_commitment` is already the anti-entropy diff key — `verify_baseline` returns the per-author
mismatch set to `pull_baseline`); "keep vs discard" is per-op `in retained?`, never a wipe; cost
bounded by churn, never dataset size or seq-distance (cold = the degenerate case that held nothing).
**Dominance gate STAYS on the warm path** — forward-only; a backup ahead of the quorum frontier is
"deeply sus" and refused; the root-signed recovery fence is the SOLE deliberate rewind (its own
`observe_fences` path). Invariant: **absolute finality behind the frontier, `may_flip` flux only
ahead of it** (CLIENT.md §2.1). Same shape for a resurrected backup MANAGER: delta-fill missing
control ops + adopt the current control checkpoint, after author-amnesia (quorum-read chain head,
wait δ) re-anchors its single-author chain — backups are COLD STANDBY (concurrent root authoring
would equivocate the root chain, the same failure as a compactor fresh-store restart).

Testing note: prefer **deterministic seam injection** (fail between named inter-transaction seams:
authored-op → drove-Commit → stored-QC → adopted-own) over `kill -9` — WAL + `synchronous=FULL` makes
every crash land on a consistent store, so kill-9 samples no distinct failure state.

## 5. Testing arc (the gate) — on the daemon path

All lifecycle tests run against `NodeDaemon` (post WP-I), not the sim.
- **T-A sidecar roundtrip** (WP-A) — seal→carry(checkpoint op)→unseal; nonzero-`attempt` key survives.
- **T-B state_acc audit** (WP-B) — tampered `state_acc`/omitted-live/kept-superseded → loud reject.
- **T-C bootstrap consumer** (WP-C/E) — a fresh **daemon** node + client bootstrap a **GC'd** cluster
  and read byte-identically to a full-history client; A4 across a nonzero-`attempt` key; resurrection
  mask holds; reborn-tag CAS folds `stale`. **This is the "starts after compaction, replays to the
  same state" gate — and it must fail before WP-E and pass after (reproduces Finding 1).**
- **T-D finality gate** (WP-D) — sealing/adopting a non-final cut, or `horizon < max-hlc-below-cut`,
  is refused; the client no-accept guard fires on a below-horizon promise (reproduces Finding 7).
- **T-E checkpoint lifecycle** (WP-G) — compactor authors a real **sealed** checkpoint → blind-commit
  to a quorum → gossip → nodes adopt (horizon advances, `dead` GC'd), carrying a nonempty sidecar and
  verifiable `state_acc` (ECMH accumulator, ACCUMULATOR.md).
- **T-F concurrency** (WP-F) — cut cannot
  regress (#4); an unverified/forged QC is rejected (#5); two compactors converge deterministically
  or the non-elected is ignored (#6); dead-delta skip resyncs rather than wedges (#10).
- **T-G recovery** (WP-H) — post-recovery nodes adopt the salvage cut/horizon, GC below it, a new
  learner bootstraps from the manifest, and a surfaced below-fence QC emits LOST_COMMIT (#12).
- **T-H manager** (WP-0/J) — manager view is derived + crash-consistent; its control plane compacts
  via the shared path; a crash mid-verb leaves log and view consistent.
- **T-chaos** (WP-G) — extend to the daemon-driven path: kill the compactor mid-conveyor; lagging
  node resyncs; idempotent re-adoption.

## 6. Sequencing

Prerequisite: **HANDOFF-R5** (storage foundation — per-connection WAL + transactions) lands first;
it fixes the data race (#3) and makes the store safe for the multi-threaded work below.

0. **WP-0** (manager persistence) and **WP-I** (composable node + retire sim) — enabling; do first so
   everything after is tested on the real path.
1. **WP-A/B/C** + **WP-D** + the QC-verify live-bug fix **WP-F(b)** — correctness + finality core,
   in-process with hand-built checkpoints. (+ T-A/B/C/D, the #5 repro)
2. **WP-E** + **WP-F(a),(c)** — daemon bootstrap wiring + concurrency guards. (+ T-C on the daemon, T-F)
3. **WP-G** — the compactor driver + daemon. (+ T-E, T-chaos)
4. **WP-H** — recovery variant. (+ T-G)
5. **WP-J** — manager control-plane compaction. (+ T-H)
6. **Then** HANDOFF-R7 (the CLI) wraps `compactor run/once` + serve verbs for a real cluster.

## 7. Open decisions (need a ruling before the relevant WP)

1. **Concurrent compactors — RULED (Harry, 2026-07-24): SLOT by a monotonic checkpoint
   `seq`.** Checkpoints are quorum-consensus operations, decided one-per-`seq` on a public
   `checkpoint_slot_tag(seq)` (mirrors `roster_slot_tag(epoch)`), with the cut **decoupled** from
   the slot (a `prev`-hash / cut-derived key would let two both-valid checkpoints in the same
   finality window win different slots and diverge — the sequence collapses them to one slot).
   NOT "mandate a single cert" — any number of compactors may run; the slot makes at most one
   win, exactly like racing CAS. Reuse the existing slotted `Commit` (no new verbs). Adoption is
   the validity gate (chain + dominance). See WP-F above for the full spec + staged plan. A
   DESIGN §12/§15 clarification follows ("*the* compactor" → "the compactor ROLE; the sequence
   slot serializes concurrent instances").
2. **Auditors = compactor + manager**, not "resident full-history clients" (DESIGN.md:347 wording) —
   a DESIGN §12 trust-surface reconciliation (NOTES item).
3. **Cut-lag `W` value** — δ-family constant; semantics fixed (NOTES 29g), value open (§17); pick a
   POC default at WP-D.
4. **Recovery horizon = max reachable floor vs quorum floor** (manager.py:469) — the recovery path
   derives `horizon` from the *max* floor, above what a quorum attests; that can refuse still-
   committable ops in `(quorum_floor, max_floor]`. Confirm the max is intended (fiat conservatism) or
   switch to the quorum floor.

## 8. Notes to record (NOTES items)

- The sim-vs-daemon test divergence (§2) — the general anti-pattern (validate the production path,
  not a stopgap harness) plus the specific compaction instance.
- The concurrent-compactor gap (§7.1) and the auditor reframing (§7.2), once ruled.
