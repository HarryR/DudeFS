# PLAN.md — from the current tree to the segmented, attested design

Derived from 32 probes in [experiments/](experiments/). Every step cites the finding that motivates it
and states what it **deletes**, because the net effect of this plan is less code, not more.

Sequencing principle: **replacements before additions.** A replacement is testable against a harness
that already exists ([dude/tests/test_gestalt.py](dude/tests/test_gestalt.py)); an addition is new
surface with no harness. Two of the three biggest wins are deletions.

---

## Rulings made `[H]`

| | ruling |
|---|---|
| **priest vs cold manager** | **Cold manager is a REQUIREMENT** — the budget will not carry the cluster *and* a priest. So there is no priest, and **cold single-link clients are out of scope**: a cold client reaches `f+1`. A returning client with a receipt still works on one link. |
| **conveyor keys** | **Worker bees.** TEE workers convey old data as housekeeping while doing their own jobs — they already hold keys and are already decrypting. Effort scales with **compactor pressure** (backlog/TARGET, clamped by `CAP` so housekeeping cannot crowd out work, P34). The idle case needs only a **heartbeat** — "ensure ≥1 bee runs every T" — not a fallback conveyance path. A bee's blast radius exceeding its own job is an **accepted trade-off**; that is what the TEEs are for. |
| **H / warm bootstrap** | **Re-join as if new.** No separate warm-bootstrap path: a node past H discards and runs the new-node join, which must exist anyway. The join is **chunk-diff**, so cost degrades smoothly with absence (1 day ≈ 2% of state, 1 year ≈ all of it — correct, it *is* a new node). **H is therefore a storage tunable, not a recovery cliff, and no longer gates step 2** (P35). |
| **out-of-band restore** | **Forbid**, or force an identity reset. A restored image regresses the node's monotone height — precisely the fault the angel exists to catch (P25/P29). |

**Still unruled:** F27's formal status — **retracted** or **deferred**? Segments plus P31 appear to
supersede backlinks entirely, but F27 is a ★★ finding and `experiments/SPECv1.md` §1.4/§2 build on it.
Dropping it silently leaves the next reader inheriting a mechanism nobody is building.

## Amendments from `experiments/PLAN-REVIEW-fable.md`

Four sequencing errors, all inside step 2. **[H]** the ordering itself is not a problem — the tree is
largely uncommitted — but these are correctness issues, not just ordering:

- **S1 — step 2 needs a checkpoint.** It deletes the joiner's only verification path (genesis replay via
  `Store.rebuild`) three steps before the replacement lands. **Bind a quorum-ratified `(height, A_state)`
  to the collect entry in step 2**; the compactor's *timestamp* stays in step 5. F34's two signatures
  then land in two separately-testable steps.
- **S2 — the management store guarantees stragglers.** Genesis grants and roster rows are live forever,
  so segment 0 is permanently uncollectable without migration. F46's "entirely dead" was measured on job
  traffic only. **Minimal same-value migration belongs in step 2** (no re-encryption, `A_state`-invariant).
- **S3 — segment id must be the SETTLEMENT bucket, not `entry.ts`.** The author's clock plus the
  mempool's carry-forward can land entries in already-collected segments, recreating F39's scattering.
- **S4 — segment width has floors.** Multiple of δ, and **greater than `w_admit + w_valid`**, because
  `entry.op_hash UNIQUE` is the dedup substrate and collection forgets hashes.

**And the step-2 deletion is differently sized than claimed:** `ChainLink`, `_derive_links` and the
splice go as stated (~120–150 lines), but **"gap-fillers" were never code** — probe-only, so that part
was overstated. Understated elsewhere: the entire **`touch` table, `history()` and per-write chain
maintenance** become dead with no production caller. The real harness is **`test_store.py`** (~180 lines
rewritten), not `test_gestalt.py`, which exercises no compaction path at all.

**Gaps to fold in:** `FRONTIER`/`PULL`/`ENTRIES` appear in no step and no repair path exists in code;
the **new-node join** is now load-bearing (it is the recovery path) and needs its own step; step 1's `f`
is `min(n−q, 2q−n−1)` — **seizure is unavailability**, so the availability bound binds (3 at n=11).

## Step 0 — correct the record (half a day)

`FRAMING.md` still carries the disinterest framing that probe 29 undercut, and `experiments/SPECv1.md`
predates segments. Both will be read as authoritative by whoever picks this up.

- FRAMING: threat model is **failure domains, not incentives** (P29). There is no disinterested party —
  every node is bought and paid for. The angel's job is **accident detection** (snapshot revert,
  restore-from-backup), not adversarial deterrence.
- FRAMING §3.2: correct the over-unification. τ, H and L are **three** parameters, not one.
- SPECv1: supersede §4's entry-level mechanism with segments (F46).

## Step 1 — failure domains (small, self-contained, no dependencies)

**Motivated by:** P29 (`f` is set by the largest correlated group), P32 (one invariant suffices).

- `NodeRecord` gains `domains: frozenset[bytes]` — **opaque labels**, never parsed.
- `management.domain_groups(reader)` and `check_domains(reader, rule)` — pure functions over the
  management store.
- `add_node` / `change_roster` **refuse** a roster that would violate `no domain > f`.

**Test:** a 3-3-3-2 spread across four providers passes; 4-4-3 fails; adding a 12th node to an existing
provider is caught. Note that *adding* a node can *reduce* effective tolerance.

**Deletes:** nothing. ~80 lines.

## Step 2 — segments replace entry-level compaction ★ the big one

**Motivated by:** F46 (time-segmented global log), F36/F37 (wholesale deletion, explicit trigger),
F39 (interleaving destroys run length), F23/F25 (both made unnecessary).

- Log gains a **segment id** = `ts / segment_width`. Segments are *physical slices of the one logical
  log* — **not** stores, not ACL domains (F38 is the trap; F41 explains why it does not arise here).
- Per-segment accumulator, so collection is one subtraction.
- `collect_segment(id)` — wholesale deletion when live fraction falls below a threshold.
- Stragglers migrate forward (the conveyor, step 4).

**Deletes:** `ChainLink`, `_derive_links`, the drop-set machinery, `Compaction.drops`/`links`, and the
gap-filler concept entirely. **This is the largest code removal available** — a segment *is* a run, so
run-length, chain repair and scattered-drop handling all stop existing.

**Test:** extend `test_gestalt.py` — jobs advance, segments age out, state and accumulators identical
across all nodes after collection. The harness already exists.

## Step 3 — the state root (SMT)

**Motivated by:** F7 (compaction-invariant), F15 (640 B proof, 8 µs verify at 10⁶), F17 (non-inclusion),
F19 (the ~4500× startup reduction that makes ephemeral workers viable).

- **Key-indexed sparse tree with path compression** — **not** sorted-leaf. P20: sorted-leaf insert is
  O(n) because positions shift; the tree used in probes 03/06 is read-only and **F16's "O(log S) with a
  cached tree" is retracted**.
- Persisted alongside data (~0.6 GB per 5 GB). Cost is **storage and random IO**, not CPU.
- Root per checkpoint; every node recomputes it to ratify (F34).
- Non-inclusion answered by the empty slot — no adjacency proofs.

**Keeps:** ECMH `A_state` as well. It **supplements**, not replaces (F16): O(1) update for the equality
check nodes perform constantly; the tree is paid only when a proof is served or a checkpoint is cut.

## Step 4 — the conveyor

**Motivated by:** F61 (it is the **forward-secrecy engine**, not a defragmenter — correcting F25),
F62 (secrecy lag is bounded by conveyor rate, not rotation rate), F60 (one straggler pins an epoch key).

- Migrate live values forward, re-encrypting under the current epoch.
- Drives `refcount(epoch) -> 0`, letting wraps be collected and **the old key die**.
- Rate is the forward-secrecy guarantee, statable as a number (**L**).

**Note:** rotating keys faster without conveying faster buys *nothing*.

## Step 5 — the compactor role

**Motivated by:** F33 (a trust tier solves freshness where no cryptography can), F34 (two signatures,
different jobs), F35 (compromise is bounded and degrades to the no-compactor case).

- Proposes `(height, state_root, A_state, A_log, drops)`; signs **with a timestamp**.
- Nodes **ratify** — they hold the data, so they recompute and refuse a wrong fold. A lying compactor is
  caught *at the time*; only later is it unverifiable, which is why later verifiers trust the
  ratification rather than the compactor.

## Step 6 — revocation, and the priest question

**Motivated by:** P31 (**already bound** — the management prefix is in state, so revoking changes the
state root), P30 (the CRL/short-lived-cert trade).

- **No CRL, no never-forget bookkeeping.** *Absence is the revocation* — you do not remember a
  retraction, the grant is simply gone, and the root commits to that.
- Selective withholding becomes impossible: hiding a revocation means serving an older root, i.e. older
  data too.
- **Revocation freshness == data freshness**, so any freshness signal covers both for free.

**The coupling to state plainly:** *manager offline ⟺ no priest ⟺ cold clients need f+1.* One decision,
not three. Recommendation: take the cold manager; a priest that must re-bless every τ for 2–4 years is a
liability designed in. Build the priest only if single-link **cold** clients are required.

## Step 7 — the angel duty (optional, cheap)

Nodes attest a **monotone** height and never regress; clients take the max over f+1. Catches the *actual*
rollback threat in this deployment — snapshot revert, restore-from-backup, operator error (P29) — not a
coordinated adversary. Self-convicting: a regression is a signed contradiction (P25). Needs durable
state, no clock, no TEE.

---

## Not doing, and why

| | |
|---|---|
| the two-plane split (data-free oracles) | **rejected** — breaks ratification (F34), severs commit-implies-possession (the U), and strands epochs (the E). Fable's deliberation, and the 5 GB premise was pre-compaction anyway |
| MMR / Merkle over the log | F6 — a log commits to positions and compaction scatters them |
| SNARKs on the data path | F29/F30 — an old proof is a valid proof; freshness is not computational |
| recurrent PCD at the priest | genuinely sound (F/§3.5) but only if step 6 builds a priest at all |
| per-workflow logs | F44 — work portability requires one global log |

## Verification throughout

`ruff format && ruff check && ty check dude/ && python3 -m unittest discover -s dude/tests -t . -q`
(108 tests green today). Every step extends `test_gestalt.py` rather than adding a parallel harness.
