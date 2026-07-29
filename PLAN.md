# PLAN.md — from the current tree to the segmented, attested design

Derived from 35 probes in [experiments/](experiments/). Every step cites the finding that motivates it
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

## Status

| step | state |
|---|---|
| 0 — correct the record | **mostly done** — stale docs quarantined, `SPEC.md` rewritten with tags, 112 refs repointed. Outstanding: `FRAMING.md`'s two corrections; `MEMPOOL.md` / `LINKS.md` prose predating segments and the no-priest ruling |
| 1 — failure domains | **done**, 7 tests |
| 2 — segments | **done**, 14 tests, all four Fable amendments closed |
| 3 — state root (SMT) | not started |
| 4 — conveyor | **half done** — `Store.migrate` is the same-value half; re-encryption is not written, so no key has ever died |
| 5 — compactor role | **quorum half done** — collection is driven and ratified in a cluster (below); the compactor's *timestamp* is still unwritten, and `FRONTIER`/`PULL`/`ENTRIES` are still `UNIMPLEMENTED` |
| 6 — revocation | **collapsed to nothing** — see below |
| 7 — angel duty | not started |

**130 tests green.** Gate unchanged (bottom of this file).

## Step 0 — correct the record  ✅ mostly

`SPEC.md` is rewritten and **cites by `#tag`, never by section number** — positional refs broke
whenever a section moved, could not be grepped in both directions, and rendered as dead text.
36 tags; a retired tag stays listed with its reason so a stale citation resolves to an explanation.

Old design docs are in `old-and-invalid/` with a README saying *why* each is invalid.

**Outstanding:** `FRAMING.md` still carries the disinterest framing P29 undercut, and its §3.2
over-unifies τ/H/L. `MEMPOOL.md` and `LINKS.md` contain prose predating segments and the no-priest
ruling.

## Step 1 — failure domains  ✅

`NodeRecord.domains` (opaque labels), `domain_groups`, `check_domains`, `Rule.max_domain`,
`add_node` refusing violating rosters. **Two things implementation found:**

- the bound is **vacuous below n=4** — no placement makes a 1-node roster survivable, and enforcing it
  would have forbidden the first node, making bootstrap impossible
- a sound roster can be **unreachable one node at a time** — 3-3-3-2 is fine at n=11 and refused at
  n=4, so a target roster must be reached by a **batched** change

## Step 2 — segments replace entry-level compaction  ✅ ★

`entry.segment`, `segment(id, acc, sealed)`, `segment_of` / `segments` / `segment_live` /
`stragglers` / `migrate` / `collect`. `Compaction` went from `(drops, links)` to
`(segment, height, acc_state, signers, sigs)`.

**Deleted:** the `touch` table, `history()`, `ChainLink`, `_derive_links`, `_compact`, `compact()`,
per-write chain maintenance.

**All four amendments closed** — S1 ratified collect entry, S2 straggler migration, S3 settlement-bucket
id, S4 dedup floor. Two corrections implementation forced:

- **S4 is an AGE, not a width.** A width is a count of entries and the dedup window is a duration;
  comparing them needs an arrival rate nobody has. The newest entry's timestamp answers it directly.
- **A segment cannot be drained into itself.** Migration writes at the head, so `collect` refuses a
  segment the log has not moved past — otherwise the straggler simply reappears.

**Harness:** `test_store.py`, not `test_gestalt.py` — which exercises no compaction path at all.

**Also found here:** every multisig verification was returning `False`, because splitting
`_ed25519_verify` into typed errors made it raise instead of return. Now `VerifyFailure | None`,
matching every other decision type in the codebase (#no-exceptions-for-control-flow), with regression
tests.

## Step 5a — collection in a cluster  ✅ ★

`Store.collect` worked alone; nothing drove it. Now `Node.maybe_collect` proposes, peers ratify by
**recomputing the fold**, and at quorum every node calls the same `Store.collect` — one path, not a
second one. Verbs `COLLECT` / `RATIFY` (#collection-is-driven-by-any-node).

**No distinguished proposer, and the risk the plan flagged did not materialise.** Two nodes noticing
the same segment propose byte-identical claims, because a claim is a function of the segment and the
fold rather than of who spoke first — so their signatures **pool** instead of splitting the quorum.
Shares are therefore keyed by **claim bytes, not by segment**: a node disagreeing about the fold must
not be able to borrow signatures given to a different claim.

**Found by the cluster test:** `attest_bytes` had **no inverse**. `Compaction.decode` reads the
six-field *entry*; a claim is the four-field thing the quorum signs. So every `COLLECT` on the wire
decoded to nothing and was **dropped in silence** — no error, no refusal, the cluster simply never
collected. `Compaction.from_attest_bytes` is the missing half, with round-trip tests pinning that the
two encodings refuse each other's bytes. This is the third time in this plan that a unit-tested
component was wrong only once something else had to talk to it.

**Also found:** migration writes at the HEAD, so a segment narrower than its own straggler count
drains part of itself back into itself. Sizing, not a bug — but it makes `SEGMENT_WIDTH > live rows`
a real floor alongside S4's dedup age.

## Step 3 — the state root (SMT)

**Key-indexed sparse tree with path compression** — **not** sorted-leaf. P20 measured sorted-leaf
insert as O(n) because positions shift, so **F16's "O(log S) cached" is retracted**; the probe-03/06
tree is read-only and must not be lifted into production.

~768 B proof at 10⁷ keys, depth ~24. Cost is **storage and random IO**, not CPU. Keeps `A_state`
alongside — ECMH supplements rather than replaces, being O(1) for the equality check nodes do
constantly.

**Needs a new tag.** `SPEC.md` has no statement about the state root.

## Step 4 — the conveyor  ◐ half

`Store.migrate` rewrites stragglers at the head with the **same value**, `A_state`-invariant. That is
the half that makes segments collectable.

**Not written:** re-encryption under the current epoch, which is what lets an old key epoch die
(#conveyor). Worker bees do it as housekeeping; effort scales with backlog pressure, clamped so it
cannot crowd out work; the idle case needs a heartbeat, not a fallback path.

**Needs tags** for the mechanism — `#conveyor` states the *why*, not the *how*.

## Step 5 — the compactor role

Compactor proposes with a **timestamp**; nodes **ratify** by recomputing. Two signatures, two jobs.
The quorum half exists (#collection-is-ratified); **the timestamp half has no tag and no code**, and it
is what gives a single-link client freshness.

Also: wire `FRONTIER` / `PULL` / `ENTRIES`.

## Step 6 — revocation  ✅ nothing to build

Collapsed. **Absence *is* the revocation** — the grant is simply gone, and the state root commits to
state, so the removal is bound to the data (#absence-is-revocation). No CRL, no retraction record, no
never-forget bookkeeping. Revocation freshness == data freshness.

The priest question is **ruled**: cold manager, no priest, cold single-link clients out of scope.

## Step 7 — the angel duty

Nodes attest a monotone height and never regress; clients take the max over `f+1` (#monotonicity).
Catches the *actual* rollback threat here — snapshot revert, restore, operator error — not a
coordinated adversary. Durable state, no clock, no TEE.

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
