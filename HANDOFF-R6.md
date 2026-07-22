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
> questions become NOTES items (see §7), never workarounds. The CLI work (originally R5, now
> parked as **HANDOFF-RX**) follows this milestone — the CLI is a thin shell over already-correct
> machinery.

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
unbuilt (NOTES 29a MANDATORY → A4 break); `state_root` computed+carried but **never verified**;
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
| 13 | **Compactor completeness precondition unasserted** — no check the compactor holds the full below-cut set before sealing; only backstop is the unbuilt `state_root` verify. | DOC-UNBUILT | compactor.py:63-157 | a lagged compactor seals a wrong `dead`/winner, caught by nothing |

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
- **WP-B — `state_root` derive-and-verify.** Recompute at intake (bootstrap + the compactor/manager
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
- **WP-F — Guard adoption.** (a) Cut-**dominance** guard: never adopt a checkpoint whose cut does
  not per-author dominate the currently-adopted cut (#4). (b) **Verify the checkpoint QC**
  (`qc.verify(roster)` + `config_epoch`) at adoption, like the roster path (#5). (c) Resolve
  concurrent compactors — **design decision, §7**: slot checkpoints (like rosters) or mandate a
  single `compact` cert; either way make selection deterministic (`ORDER BY` / tie-break) (#6).
  Files: `dudefs/daemon.py`, `dudefs/store.py`.

**The driver**
- **WP-G — Compactor identity + author + commit + daemon.** Cap.COMPACT-signed checkpoint on the
  compactor's own chain; cut/W selector (F = quorum floor, `cut ≤ F − W`, W a δ-family constant);
  blind-commit of the slotless checkpoint (extract from `client._commit_blind`); `compactor run`
  (continuous) / `once`. Own gossip-synced replica; keys via wrap-unwrap. Files: new
  `dudefs/compactor_daemon.py`.

**Recovery variant** (Finding 12)
- **WP-H — Recovery checkpoint carries a real manifest and is adopted.** Author the recovery
  checkpoint with the salvage frontier as `cut` and the salvage manifest as `retained` (not empty);
  drive cut/horizon/GC adoption on the fiat path (not epoch-switch only); run `detect_lost_commits`
  in the node evidence cycle. Files: `dudefs/manager.py`, `dudefs/daemon.py`.

**Manager control-plane compaction**
- **WP-J — post-WP-0**, the manager's control plane checkpoints/compacts via the **same** path as
  any node (no bespoke `control.log` prune).

## 5. Testing arc (the gate) — on the daemon path

All lifecycle tests run against `NodeDaemon` (post WP-I), not the sim.
- **T-A sidecar roundtrip** (WP-A) — seal→carry(checkpoint op)→unseal; nonzero-`attempt` key survives.
- **T-B state_root audit** (WP-B) — tampered `state_root`/omitted-live/kept-superseded → loud reject.
- **T-C bootstrap consumer** (WP-C/E) — a fresh **daemon** node + client bootstrap a **GC'd** cluster
  and read byte-identically to a full-history client; A4 across a nonzero-`attempt` key; resurrection
  mask holds; reborn-tag CAS folds `stale`. **This is the "starts after compaction, replays to the
  same state" gate — and it must fail before WP-E and pass after (reproduces Finding 1).**
- **T-D finality gate** (WP-D) — sealing/adopting a non-final cut, or `horizon < max-hlc-below-cut`,
  is refused; the client no-accept guard fires on a below-horizon promise (reproduces Finding 7).
- **T-E checkpoint lifecycle** (WP-G) — compactor authors a real **sealed** checkpoint → blind-commit
  to a quorum → gossip → nodes adopt (horizon advances, `dead` GC'd), carrying a nonempty sidecar and
  verifiable `state_root`.
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
6. **Then** HANDOFF-RX (the CLI) wraps `compactor run/once` + serve verbs for a real cluster.

## 7. Open decisions (need a ruling before the relevant WP)

1. **Concurrent compactors (WP-F(d)) — DESIGN decision.** Slot checkpoints like roster ops
   (`H("checkpoint"‖e)` or similar, so at most one activates per interval), **or** mandate a single
   `compact` cert and enforce singularity? DESIGN §12/§15 say "*the* compactor" (singular) but §15
   makes `compact` an ordinary delegable cap and nothing enforces one. This is a real design gap —
   a NOTES item + a DESIGN §12/§15 clarification.
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
