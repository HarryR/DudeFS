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
| 3 — state root (SMT) | **done**, 30 tests — and it is signed, so it proves something |
| 4 — conveyor | **done**, 17 tests — a key can now die |
| 5 — compactor role | **done bar STATE transfer** — `PULL`/`ENTRIES` landed; only the far-behind/wiped path is left — collection is driven and ratified in a cluster; `FRONTIER` landed with step 7; the timestamp role is **struck**, not built (below). Outstanding: `PULL`/`ENTRIES` and join-as-recovery |
| 6 — revocation | **collapsed to nothing** — see below |
| 7 — angel duty | **done**, 49 tests — grew two more halves: cross-attestation and gathered freshness (below) |

**237 tests green.** Gate unchanged (bottom of this file).

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

## Step 3 — the state root  ✅ ★

`dude/store/smt.py`: a binary radix tree over `H(store ‖ name)` in which **a subtree holding exactly
one leaf hashes to that leaf however deep it sits**. That single rule is the whole compression —
nominally 256 deep, actually ~log2(n), so a proof is ~24 hashes rather than 256. Measured, not
asserted: `test_depth_stays_logarithmic`.

**Key-indexed with path compression, as ruled.** Sorted-leaf stays retracted (P20: insert is O(n)
because positions shift; the probe-03/06 tree is read-only).

**What it buys over `A_state`:** a proof about ONE key — and above all a proof of **absence**. That
makes #absence-is-revocation checkable rather than asserted, since a revocation *is* a grant that is
gone. It also restores what collection destroys: a joiner that reconstructs state can check it against
a signed root instead of trusting its own reconstruction. Both commitments are kept — ECMH is O(1) for
the equality nodes ask constantly, the tree is paid when a proof is served or a checkpoint is cut.

**Canonicity is structural, not maintained.** A subtree's hash is defined purely as a function of the
leaves in its range, so there is no insert path and no delete path that could disagree, and
insert-then-delete is byte-identical to never-inserted. That is why there is **no split/merge
machinery**: the leaves ARE the `live` table indexed by path, and `smt_memo` is a memo of a pure
function that can be truncated at any moment (`test_the_memo_is_only_a_cache`).

**Every node is bound to where it sits `[H]`** — a leaf to its path, an internal node to its depth
*and* prefix. Binding the leaf and not the branch was asymmetric for no reason: without position, an
internal node's hash is anchored only by the global argument that the fold must reach the real root,
and that argument has to be re-made for every later use of these hashes. Local binding costs nothing
on the wire, since the verifier derives each prefix from the key it is asking about.

**Domains are BLAKE2b personalisation `[H]`**, not a tag concatenated onto the message — matching
`PERSON_SCREEN` / `PERSON_ENC`, which were already the house idiom. `crypto.h_domain` is the one
entry point; two domains are two different hash functions rather than one function over a message
someone has to prove is prefix-free.

**Signed, or it proves nothing.** `Compaction` and `Attestation` both carry a root: the checkpoint's
is what a **quorum** vouches for, the attestation's is what **one node** stakes its identity on.
Ratification covers it — `_on_collect` recomputes the root with the height and the fold, so a node
claiming a root it did not compute gets no signature.

## Step 5 — the compactor's timestamp: STRUCK  ✅ ★

`[H]` **A timestamp cannot be ratified, only asserted.** Ratification is *recompute, don't trust* —
a peer signs a collection claim because it re-derived the fold — and **nobody can re-derive somebody
else's clock**. The sketched design had ratifiers vouching for something they could not check.

So the compactor's timestamp role is **deleted rather than built**, and freshness rides the
attestation gossip that already exists: `Attestation.at` is the time that node's own clock read.
One less tier, which is the direction the budget has pushed throughout.

**What it buys is a BOUND.** An adversary without `f+1` keys cannot manufacture recent statements —
only replay old ones, and old ones look old. Silent staleness becomes **visible** staleness, and
`attest.staleness` turns "how far behind am I" from an unknown into a number. `[H]` A **diagnostic**;
adversarial liveness is not available here and is not claimed.

**The single-link cold client is back in scope, without a priest.** A relay holds no key but its own,
so one link is enough to *gather* `f+1` signed statements the client verifies itself — which was the
priest's entire job. `#freshness-needs-many`'s strike is lifted.

**Rulings `[H]`:** the window is a **cluster-wide tunable** (`fresh_within`) because two clients
disagreeing about whether one bundle is fresh is a defect; it is **symmetric**, since a future
timestamp would still read as recent when replayed tomorrow; and it **must exceed `probe_every`**, or
a bundle is stale by construction — the same shape as S4's dedup floor. A **clock fault is never
convictable**: an NTP step backwards is a road bump, it degrades what a node contributes and drops it
from the `f+1`, and `contradiction` still never looks at time.

## Step 4 — the conveyor  ✅ ★

**The first time forward secrecy is real.** `#secrecy-by-key-death` said secrecy comes from keys
dying rather than from erasing ciphertext, and until now **no key had ever died** — nothing could say
which epoch a value was under, so nothing could tell when one was finished with.

`ops.Set` carries `epoch` in **cleartext**. Forced, not chosen: a node that cannot decrypt must still
be able to count, so an epoch inside the AEAD makes the refcount underivable and key death impossible.
The leak — which epoch a value sits under, hence roughly when it was last conveyed — goes on §7's
closed list rather than into a footnote.

**Retirement is an ordinary transaction guarded by `ops.Drained`**, a new predicate and the only one
that ranges over all keys, because it answers the one question that must. Every node evaluates it
identically at the same position, replay reproduces it, and the entry records in the log what it was
conditional on — so an early retirement settles nowhere. It is the exact twin of `collect()` refusing
a segment that still holds live values, and it matters for the same reason squared: retire one value
early and that value is unreadable **by everyone, forever**.

`Layer.epoch_live` corrects the base count by its own delta, so a transaction cannot retire an epoch
it is itself writing under — a guard has to see uncommitted work or it is not a guard.

**A stale write cannot resurrect a dead epoch, and needs no rule to stop it `[H]`.** An epoch outlives
a validity window by orders of magnitude, so a client writing under a retired epoch is far outside the
admission window and is refused there. The windows are an implicit liveness contract on both sides;
that coherence is relied on rather than re-earned. *(I had proposed a second guard here; it was
redundant machinery for a case the window already excludes.)*

**What retirement can and cannot do.** Deleting the wraps makes a master unobtainable *from the
record*, and #state-root proves that absence — key death is a revocation, and #absence-is-revocation
finally has a proof. Whether a holder that once had it in memory forgot is provable by nobody: the
accepted TEE trade-off, not a gap this closes.

**One conveyance does two jobs** — drains the old epoch *and* vacates the old segment, since it writes
at the head. The belt moves once, two things fall off the back.

**Found while testing:** the shared `tx` builder dropped the epoch when re-homing a mutation onto a
store, so every conveyor test silently wrote `EPOCH_NONE`. A builder that quietly drops a field tests
something other than what it claims.

**Pressure is deliberately basic** `[H]`: `Store.epochs()` is the work queue, oldest first, since the
oldest epoch is the one closest to dying. Tunable later; the mechanics are what had to be right.

## Step 5 — the compactor's timestamp: STRUCK  ✅ ★

`[H]` **A timestamp cannot be ratified, only asserted.** Ratification is *recompute, don't trust* —
a peer signs a collection claim because it re-derived the fold — and **nobody can re-derive somebody
else's clock**. The sketched design had ratifiers vouching for something they could not check.

So the compactor's timestamp role is **deleted rather than built**, and freshness rides the
attestation gossip that already exists: `Attestation.at` is the time that node's own clock read.
One less tier, which is the direction the budget has pushed throughout.

**What it buys is a BOUND.** An adversary without `f+1` keys cannot manufacture recent statements —
only replay old ones, and old ones look old. Silent staleness becomes **visible** staleness, and
`attest.staleness` turns "how far behind am I" from an unknown into a number. `[H]` A **diagnostic**;
adversarial liveness is not available here and is not claimed.

**The single-link cold client is back in scope, without a priest.** A relay holds no key but its own,
so one link is enough to *gather* `f+1` signed statements the client verifies itself — which was the
priest's entire job. `#freshness-needs-many`'s strike is lifted.

**Rulings `[H]`:** the window is a **cluster-wide tunable** (`fresh_within`) because two clients
disagreeing about whether one bundle is fresh is a defect; it is **symmetric**, since a future
timestamp would still read as recent when replayed tomorrow; and it **must exceed `probe_every`**, or
a bundle is stale by construction — the same shape as S4's dedup floor. A **clock fault is never
convictable**: an NTP step backwards is a road bump, it degrades what a node contributes and drops it
from the `f+1`, and `contradiction` still never looks at time.

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

## Step 7 — the angel duty, and who keeps the evidence  ✅ ★

`dude/store/attest.py`: `Attestation` (durable counter, own head as a **hint**, both accumulators,
and the highest quorum-ratified checkpoint as the **floor**), `SignedAttestation`, `Evidence`,
`Frontier`, and the pure `contradiction` predicate. `FRONTIER` / `STANDING` on the wire.

**The floor carries the quorum whole.** A node's private opinion of its own height is forgeable
*upward* at no cost, so #freshness-needs-many's "withhold, never forge" only holds for something
carrying signatures. The head rides along labelled as a hint and is never a floor.

**The counter is separate from the height**, because ordering two claims by the quantity under
dispute is circular — if the counter *were* the height, a regression would be unorderable and so
unconvictable.

**The interlock is the highest-risk part.** `Store.attestation` bumps and COMMITS the counter inside
one transaction and returns an unsigned claim; only the node signs. Signing over uncommitted state is
therefore unconstructible rather than merely discouraged. It matters because the consequence is
asymmetric: peers keep the evidence and conviction is terminal, so a node that attested a height it
had not made durable would destroy itself on an honest crash. Gaps are free; reuse is fatal.

**Cross-attestation `[H]`** — the plan had this as a small self-contained step and it roughly doubled,
absorbing `FRONTIER` from step 5. Worth it: accountability otherwise rests on a client having happened
to be watching, and the accident this catches is a snapshot restored overnight. Peers are the keepers.
Sightings are **verbatim and peer-signed**, never opinions, so a relay can neither frame a peer nor be
framed by one — the only lie left is silence, which is measurable against the rest of the cluster.

**Found by the cluster test:** sightings alone do **not** make evidence transitive. A peer that
convicts keeps the earlier statement and refuses the later one, so relaying sightings relays only the
*innocent half* — a node cut off from the culprit would keep talking to it forever. `STANDING` carries
convictions too, and the receiver **recomputes** the verdict (`Store.judge`) rather than believing it,
which is C1's ratification principle applied again: a relay's word is worth nothing, its signatures
everything.

**Also found:** the obvious "latest sighting wins by seq" is **wrong** — a regression arrives with the
highest counter and would overwrite the very statement that proves it. `Store.witness` tests the
contradiction *before* storing and keeps both halves forever.

**Rulings `[H]`:** conviction is **terminal for the identity** — recovery is re-join as a new node,
the path a forbidden restore already forces, so no rehabilitation and no un-shun protocol. Shunning is
**proven self-contradiction only**, never silence, staleness or divergence (a partition makes honest
nodes look stalled), and it is a **local read policy**: shunned keys drop before the `f+1` count but
the roster and quorum arithmetic are untouched, so a heavily-shunned cluster **stalls** rather than
proceeding thin.

**What this does not give you:** freshness. A frozen node attests truthfully forever. That is the
compactor's *timestamp*, still unwritten in step 5, and the conflation has cost time twice.

## The relocation wave — three defects and what they cost  ★

Found by review, not by tests. `Store.migrate` authored a `Set` of the same value and settled it
locally with authority checking off, which gave: **nodes writing into the management store
unauthorised**, **the manager's signature over the roster displaced by a node's**, and **three honest
nodes holding byte-different logs at identical indices** — `A_state` and `head` agreeing throughout,
which is exactly why nothing noticed.

`ops.Move` carries no value: it cannot express a change, so it needs no authority and forges nothing.
`[H]` **The credential travels with the row** — a Move over a management row carries the
manager-signed transaction that authorised the value, checked against live state and current
authority. The chain back to the manager key survives any amount of compaction, so a joiner need not
take the roster on the word of the quorum the roster defines.

Two more fell out of fixing it: `_commit` subtracted the element for every mutation and only a `Set`
added one back, so a Move **deleted its own row from `A_state`**; and `Compaction.op_hash` covered the
signature set, so nodes collecting the same segment with different shares produced different entries —
`A_log` diverging for a second, unrelated reason. The op hash is over the **claim** now: the log
commits to what was agreed, not to which shares arrived first.

**The assertion that catches this class is `A_log` across nodes, not `A_state`.** It was one line away
when the divergence shipped, and it caught the second instance within a minute of being added.

## Transfer, and the audit  ★

`PULL`/`ENTRIES` landed and immediately opened a hole: a stranger with no grant and no roster seat
added itself to a catching-up node's roster — its quorum — with one unsolicited frame. Now: `SOLICITED`
gates before dispatch, the sender must be in the roster, and the run is checked against the sender's
**signed** commitment (head, both accumulators, root) and rolled back before commit.

**The audit found the dedup floor was never enforced on the peer-driven path.** `maybe_collect` took
`dedup_window` as a parameter and stashed it on the node for `_try_collect` to read later, so a
peer-driven collection used whatever a local call had left behind — nothing. Collection forgets
`op_hash`, so those collections would have made their transactions replayable. Derived from the
mempool's window now; turning it on broke nine cluster tests, every one of which had been collecting
inside the window.

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
