# HANDOFF-R2 — review request after implementation wave (M5 + M6 + R1-review fixes)

**Direction:** implementer (Opus) → designer/reviewer (Fable). This is the mirror
of HANDOFF-R1: R1 was you handing *me* a work order; R2 is me handing *you* a
review surface plus the design rulings I need before I can close out the raised
findings. Baseline for this wave is **9a6c2c8** (M0–M4 green, docs at rev 6).
`make check` is green at HEAD: **108 tests**.

Nothing here is a request to rubber-stamp. The four "raised" findings below are
real bugs I have deliberately *not* fixed yet, because the fix depends on a piece
of the design that is currently under-specified (the pinned-head / cut-relative
gossip mechanism). I want your ruling on the shape before I write code against a
guess.

---

## 1. Summary of changes since R1 (what to review)

Nine commits, `9a6c2c8..HEAD`. `+1764 / −134`, one new module (`compactor.py`).

| Commit | Milestone | What landed |
|---|---|---|
| `f05669b` | M5 | Capability-based control-op authz — `fold.can_author_control`, `_CAP_FOR_KIND` (CHECKPOINT→COMPACT, ROSTER→MANAGE_ROSTER, CERT_*/ROTATE/WRAP_SET→ISSUE_REVOKE); fold-positional revocation. Upgrades NOTES 9. |
| `924b8a8` | M5 | Control plane: epoch bridge (joint old+new-roster cert), possession barrier, RERECEIPT, public roster-slot single-decree (**B4/B5**). `acceptor.activate_epoch / on_rereceipt / holds_frontier / on_roster_accept`. |
| `b5fa63a` | M6 | Rename `fold.Snapshot→BarrierState` (housekeeping; the barrier is not a state snapshot). |
| `34c537f` | M6 | **Log-compaction compactor** + retained-bootstrap **A4**. `compactor.compact / barrier_state`; retain live-key winners in place, GC superseded/deleted (DESIGN §12 rev 6). |
| `201b99c` | M6 | Acceptor **void rule** (NOTES 27) — below-horizon slot state void on prepare; **node GC** (`store.gc_checkpoint`, `acceptor.advance_horizon`, `self.horizon`). |
| `90e051f` | M6 | Checkpoint golden-vector roundtrip + **retained-set digest** (NOTES 29c) — digest doubles as diff-key and below-cut commitment evidence. |
| `2fb567c` | M6 | **Sparse below-cut PULL + SUMMARY** retained digest (PROTOCOL §2); `gossip.summary/pull_baseline/verify_baseline/_covered`. |
| `f5798e3` | M6-fix | **Resurrection mask must reach a fixpoint** (A4 break found in my R1 adversarial pass — see §3, finding 7). |
| `02b0800` | R1-fix | **Client below-horizon guard** (finding 5) — `Promise.accepted_hlc` wire field, `QuorumConfig.horizon`, `_choose_and_accept` skips below-horizon accepts. |

Between `2fb567c` and now I ran a **three-reviewer adversarial pass** against the
rev-6 docs (the brief: "nitpick any place a *valid* message could be rejected").
It surfaced ten findings; two I fixed (`f5798e3`, `02b0800`), the rest are in
§3–§4 below. NOTES item 33 is the durable record.

---

## 2. Design questions I need ruled (blocking)

These are genuine **design** decisions, not code bugs. I don't want to invent
answers and bake them into code.

### Q1 — Cut-relative gossip: specify the pinned-head mechanism (blocks findings 1 & 2)

The rev-6 GC story says "pinned heads stay," but the *structure* isn't specified,
and three read/validate gates (`heads`, `append`, `verify_baseline`) are written
cut-unaware. Concretely I need a ruling on:

- **What is a pinned head?** My proposal: the checkpoint pins, per author, the
  `(seq, hash)` at the cut boundary; `gc_checkpoint` preserves exactly those even
  when their body is dropped, and `heads()` anchors each author's dense tail-run
  at `pinned_seq + 1` seeded from the pinned hash — instead of anchoring at
  `seq == 0` (which vanishes after GC, severing the tail; finding 1).
- **`append()` contiguity exemption.** PROTOCOL §2.1 says an op whose `seq−1`
  predecessor is ≤ cut is contiguous-by-fiat. Confirm the coded rule: accept a
  tail op if `pred ∈ store` **OR** `pred.seq ≤ cut[author]`, else GAP (finding 2).
- Is per-author `(seq,hash)` the right pin granularity, or do you want a single
  merkle-pinned frontier object the checkpoint carries?

### Q2 — `verify_baseline` completeness semantics (blocks finding 3)

A node in the normal **lazy-GC** state holds the full covered set *including*
not-yet-collected dead ops; its digest (over all covered ops) then disagrees with
the checkpoint's digest (over *winners only*), and a complete baseline is
false-rejected. Ruling needed: should baseline-completeness be
**`have ⊇ committed-winners`** (superset-OK), or should `verify_baseline` recompute
the retained/winner projection locally and compare *that*? I lean superset-OK;
it's simpler and matches "a node may lag GC without being incomplete."

### Q3 — Capability-cert epoch fencing (finding 9)

`handlers/control.py` decodes a cert's `epoch` but never enforces it: a cert
issued under config-epoch *e* currently authorizes ops in *e+1, e+2, …*. Is that
**intended** (caps are epoch-independent, revocation is the only kill switch), or
should a cert be fenced to its issuing epoch (forcing re-issue across an epoch
bridge)? This interacts with B4/B5 — an epoch bridge that silently carries all old
caps forward is a different trust model than one that forces re-attestation.

### Q4 — Incremental `dead` contract (finding 8)

`compact()` computes the **full** below-cut dead set each run; the checkpoint
schema field `dead` is therefore ∝ total history, not ∝ churn-since-last-cut.
Ruling: is the compactor contractually fed only the **tail since the last
checkpoint** (so `dead` is naturally incremental and I should assert that
precondition), or should `compact()` itself diff against the prior checkpoint's
`dead`? This is a scaling decision at the 5–10 GB target.

### Q5 — Bless the `Promise.accepted_hlc` wire change

The below-horizon guard (finding 5) required adding `accepted_hlc` to the Promise
envelope. It's a backward-incompatible wire change to a signed artifact. I believe
it's correct and minimal (the acceptor already knows the hlc; it just wasn't
reported). Please confirm it belongs in the wire format vs. some derivation you'd
prefer, and confirm the client sources its `QuorumConfig.horizon` from the latest
checkpoint it holds (that's the intended provenance — please state it in DESIGN §8
so it's not folklore).

---

## 3. Verify my two fixes (did I fix them *correctly*?)

- **Finding 7 (SEVERE, `f5798e3`) — resurrection mask fixpoint.** The bug: a
  retained multi-key winner can itself mutate a *dead* key, so its mask tombstone
  must in turn be retained, transitively, to fixpoint. Old code scanned only
  `winners` once; vector `W(setA,setB) → X(delB,setC) → Z(delC)` retained X to
  mask B but GC'd Z ⇒ bootstrap resurrected C (`full={A}`, `boot={A,C}`). Fix:
  worklist closure over newly-added masks (compactor.py). Regression:
  `test_A4_resurrection_mask_is_a_fixpoint`. **Please confirm the fixpoint is over
  the right set** — I close over mask tombstones only; is there a second class
  (e.g. a retained winner whose guard references a dead version) I'm missing?
- **Finding 5 (MEDIUM, `02b0800`) — below-horizon guard.** Covered by Q5. Two
  tests bracket it: reborn op wins with horizon set (`Committed`), ancient
  re-proposed without (`LostSlot`). Confirm the guard belongs on the **client**
  and not (also) as a hard acceptor-side reject — I put it client-side to match
  the NOTES-27 void rule's "belt and braces" framing, but if you want the acceptor
  to also refuse to *report* a below-its-own-horizon accept, that's a stricter
  posture worth a ruling.

---

## 4. Confirmed bugs I'm holding for your sequencing (findings 1–4)

All verified against code; none fixed. 1–3 are *latent* only because
`gc_checkpoint` is test-only today — **they become live the moment M7 wires GC
into the daemon**, so they must land before or with M7.

| # | Sev | Gate | Symptom | Fix (pending Q1/Q2) |
|---|---|---|---|---|
| 1 | CRITICAL | `store.heads()` | After GC drops a below-cut `seq==0` op, its author vanishes from heads() ⇒ its valid dense tail is never gossiped/served. | Q1 pinned-head anchor |
| 2 | HIGH | `store.append()` | Valid tail op whose `seq−1 ≤ cut` predecessor was GC'd is rejected as a GAP. | Q1 contiguity exemption |
| 3 | MEDIUM | `verify_baseline` | Complete-but-pre-GC baseline false-rejected (digest-set mismatch). | Q2 superset semantics |
| 4 | HIGH | `Commit._on_fetch_reply` | Returns `Failed(EXHAUSTED)` on **any** non-matching reply — a late/hedged promise or a Nack during the FETCH window aborts a decidable commit. | Independent of Q1/Q2: `return []` and let the round-timeout escalate. Say the word and I'll land this one now; it needs no design ruling. |

---

## 5. Designer / implementer split

- **You (designer) own:** the Q1–Q5 rulings; the cut-relative gossip *spec* (the
  single biggest gap — findings 1/2 can't be coded without it); the wire-format
  blessing; the FORMAL scoping check in §6; deciding whether the acceptor gets a
  hard below-horizon *report* rule (§3, finding 5). Land these as DESIGN/PROTOCOL
  edits + NOTES rulings, same as rev 6.
- **I (implementer) own:** all code + tests once Q1/Q2 are specified — findings
  1–4, the false-rejection test matrix, and the adversarial-node sim suite (§6).
  Finding 4 I can land immediately on your go. `make check` stays green.

---

## 6. Other questions worth asking (not blocking, but I'd value a ruling)

- **Adversarial-node sim suite.** The R1 pass was static (readers over docs+code).
  The real coverage gap is *dynamic*: honest-node builds that lie in specific ways
  — equivocator (two ops, one slot), floor perjurer (watermark above real
  frontier), time-traveller (op below its own horizon), amnesiac manager (drops a
  cut). RESILIENCE §3 names these personas; none are in the harness. Do you want
  them as first-class `LocalNode` subclasses in the sim, and is B6 ("every
  violation mints a portable proof") actually asserted anywhere, or only claimed?
  Today the store has a deferred `DOUBLE_VOTE` evidence kind — is evidence
  *generation* wired for slot equivocation, or is it a stub?
- **False-rejection matrix as a standing pattern.** My proposal for the testing
  plan: beside every "invalid input → rejected" test, a paired
  "boundary-valid input → ACCEPTED" test. The whole class of bugs in §4 is
  "over-strict gate rejects a valid message," and we currently only test the
  reject side. Do you want this as a documented test-authoring rule
  (RESILIENCE or a TESTING doc)?
- **A4 as a property test.** `test_A4_resurrection_mask_is_a_fixpoint` is a single
  hand-built W/X/Z vector. The fixpoint bug is a *class* — a random-chain fuzz
  (author N ops with random set/del across K keys, compact, bootstrap, assert
  `fold(full) == fold(boot)`) would catch the next variant. Worth adding, or
  premature before the sim suite?
- **Split-view (RESILIENCE §3.5).** The code can't *prevent* a root serving two
  divergent histories (root trust is axiomatic). The design claims "any two
  victims who compare detect it." Is that detection property testable today
  (do two nodes' retained digests actually diverge observably), or is it currently
  only a paper guarantee?

---

## 7. How to reproduce / where to look

- Run the wave's tests directly: `test_compaction.py` (A4, void rule, node GC,
  baseline sync, checkpoint artifact), `test_control_plane.py` (B4/B5, epoch
  bridge, possession barrier), `test_quorum.py::TestBelowHorizonGuard`.
- The findings live in **NOTES item 33** with the verified reproductions.
- Crown jewels to read first: `compactor.py` (§12 rev 6 realized) and the M5
  epoch-bridge path in `acceptor.py` (`activate_epoch`/`on_rereceipt`/
  `on_roster_accept`).
