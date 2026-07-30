---
title: DUDEFS — specification
---

# SPEC

Replaces the numbered spec now in [`old-and-invalid/SPEC.md`](old-and-invalid/SPEC.md). Derived from
the probes in [`experiments/`](experiments/) and the rulings in [`PLAN.md`](PLAN.md).

## How to cite this

**Every normative statement carries a `#tag`.** Code cites the tag, never a section number:

```python
"""Content address — over the bytes as received (#content-address)."""
```

Positional references (`SPEC 11.1`) are brittle by construction — they break whenever a section moves,
they cannot be grepped in both directions, and they render as dead text rather than links. A tag is a
stable identifier, resolves as a pandoc anchor, and `grep -rn '#content-address'` finds both the rule
and everything that depends on it.

**Tags are permanent.** Renaming one is a breaking change; retiring one means marking it
`RETIRED` here, not deleting it, so a stale citation resolves to an explanation rather than nothing.

**Sections are not numbered, so a positional citation cannot be written.** Numbered refs went stale
the moment a section moved, and eleven of them in the code still pointed at the numbering of a spec
that was replaced.

## What this document is

**Requirements, and nothing else.** Every statement here says what an implementation MUST or MUST NOT
do, in a form a reader can check against code.

There are no provenance markers. Who first proposed a requirement does not change the obligation to
meet it, and marking one as *inference not yet ruled on* invited the failure this file was rewritten
to stop: an objection, recorded with its reasoning intact, reads as the more detailed and therefore
more authoritative text, and gets implemented in place of the rule it was arguing against.

Rationale, rejected alternatives, measurements and history are **not** here. `git log` holds them, and
`PLAN.md` records what is not being done and why. Where a requirement would otherwise look arbitrary,
it carries at most one clause naming what goes wrong without it.

**Every requirement that a check can carry appears in the enforcement table with the symbol that
enforces it.** A requirement with no enforcer is not satisfied by prose; it is marked OWED.

Conversion is in progress: **Compaction, Accumulators, Replication, Trust, Timing, the mempool and
the conveyor** are in this form. The remaining sections still carry the old descriptive style and
their markers, and are next.

---

## Design choices

**Read this section before changing anything.** Everything after it is detail; this is the set of
decisions the detail follows from. Each has been re-derived wrongly at least once, and the cost was
days rather than minutes — so they are stated as choices with their reasons, not left implicit.

### What this is for {#the-workload}

`[H]` Coordination for **blockchain intent-space** workflow automation. A job is a **register
overwritten at each checkpoint**: idempotent steps between checkpoints, certainty required at each one
before the job continues.

`[M]` So the log is **near-total death with a tiny live frontier** — ~90% of it is dead the moment a
job advances. This is not key-value churn, and reasoning that assumes churn gets the wrong answer.

### Who is trusted, and who is not {#trust-tiers}

| | | |
|---|---|---|
| **manager** | root of trust | **cold — offline ~99% of the time** |
| **workers** (worker bees) | run in TEEs, hold key material, execute steps | ephemeral, come and go |
| **storage nodes** | ~11 low-spec VPS across jurisdictions | **untrusted; no keys, no trusted component** |

`[H]` **There is no priest.** The budget will not carry the cluster *and* a blessing service. That one
ruling decides three things at once, and they are not separable:

> **manager offline ⟺ no priest ⟺ cold clients need `f+1`.**

A returning client holding a receipt still works on a single link; a **cold** single-link client is
out of scope, and no amount of cryptography changes that (#the-lemma).

### You pay for the infrastructure {#no-token-economics}

`[H]` Every node is bought and paid for on 2–4 year prepaid contracts. **There is no staking, no
incentive layer, no economically rational adversary, and no "paid bulk holders".**

`[M]` The adversary is **failure domains** — seizure, provider bankruptcy, accidental rollback from a
snapshot restore, operator error. Rollback here is overwhelmingly an **accident**, not an attack, which
is why monotonicity is worth having and why accountability suffices where deterrence would not.

Importing blockchain incentive reasoning into this design has produced wrong conclusions twice.

### Workers do the housekeeping {#workers-convey}

`[H]` **Clients — the worker bees — perform routine compaction work.** They already hold the keys and
are already decrypting for their own jobs, so conveying old data forward costs almost nothing extra.

There is no dedicated conveyor service. Effort scales with backlog pressure and is clamped so
housekeeping cannot crowd out real work; the idle case needs only a **heartbeat**, not a fallback
conveyance path. A bee reading data it does not own is an **accepted trade-off** — that is what the
TEEs are for.

### One global log {#one-global-log}

`[H]` A worker must be able to resume **any** job without knowing in advance which. That requires one
log, not per-job logs — those turn resumption into a discovery problem across 11 nodes.

`[M]` The log is divided **physically** into segments for collection (#collect-whole-segment). Segments
are storage generations, **not** stores and not ACL domains.

### Durability over latency {#durability-over-latency}

`[H]` 30-second finality is fine; 1–2 minutes is acceptable. That is the **U** in DUDE.

`[M]` It is also what makes the design tractable: 30 s is ~40 full consensus rounds at
inter-continental RTT, so convergence has room to fail and retry. The binding constraint on job latency
is **checkpoints per job**, not finality — reducing synchronisation points pays, shaving milliseconds
does not.

### Compaction is not an optimisation {#compaction-is-required}

`[M]` The live frontier is megabytes while the raw log is gigabytes per day. On prepaid low-spec VPS
that is the difference between fitting and not. `[H]` *"A car without wheels."*

### Forward secrecy comes from key death {#secrecy-by-key-death}

`[M]` Not from erasing ciphertext — on SSDs, CoW filesystems and rented block storage you cannot assert
the old bytes are gone, and you do not own the layer that would. **Key destruction is the only erasure
you control**, which is why live values must be re-encrypted forward (#conveyor).

### Things that have been re-derived wrongly {#known-churn}

Each was argued into place plausibly and then killed by a model. If you find yourself concluding one
of these, the model that refutes it is in `experiments/`.

| tempting conclusion | why it is wrong |
|---|---|
| split storage from attestation, so nodes hold no data | breaks ratification, severs commit-implies-possession, strands key epochs |
| give each workflow its own log | work portability requires one global log (#one-global-log) |
| a Merkle/MMR tree over the **log** | a log commits to positions and compaction scatters them |
| chunking gives early detection of a lying node | detection is ~S/2 for any chunk size; chunking improves **recovery**, not detection |
| a SNARK can establish that state is current | an old proof is a valid proof — currency is not computational (#the-lemma) |
| storage nodes can witness their own monotonicity | they are the observed party; a common-mode failure is invisible to them |
| aggressive key rotation improves forward secrecy | rotation without conveying creates epochs without retiring them (#conveyor) |

---

## The log

### One write vocabulary {#one-write-vocabulary}

`[H]` There are two mutations — `set(store, name, value)` and `del(store, name)` — and nothing else.
No compound operations, no read-modify-write opcodes. A transaction is an **ordered log of steps**,
each step a mutation carrying its own guards, evaluated in sequence exactly as if applied directly to
the store.

### Last write wins within a transaction {#last-write-wins}

`[H]` If a transaction writes the same key twice, the later step wins. Step *N*'s guards **and** its
authority are evaluated against state as evolved by steps 1..*N*-1 — which is what makes
*authorise → use → revoke* a single atomic transaction rather than three.

### Predicates quote, never recompute {#predicates}

`[H]` A guard is `absent(store, name)` or `holds(store, name, digest)`. `holds` **quotes** a ciphertext
digest; it never recomputes one, so a node needs no key to evaluate it and the value's cardinality
stays unobservable. `absent` is genuinely "no row" — deliberately different from holding empty bytes.

### A content address is over the bytes as received {#content-address}

`op_hash = h(raw)`. Not over a re-encoding: an entry is relayed verbatim, so its identity survives
transport without depending on the canonicaliser agreeing with itself.

### Position is not authored {#position-is-not-authored}

`[H]` A settled index is assigned by settlement and is never part of what an author signs. Reaching
for one at authoring time is a bug — the index does not exist yet.

## Settlement

### Settlement linearises and drops {#settlement}

`[M]` Settlement evaluates a batch in order against a layer and partitions it: survivors commit,
rejects carry a **typed reason**. The reasons are not equally final — a bad signature is permanently
dead, while an authority or guard failure may become satisfiable later.

### Provenance is the last writer {#provenance}

`[H]` A live value records the settled index that last wrote it. `[M]` It is the *current* head only —
after collection the history behind it is gone, which is why nothing re-adjudicates.

### The quorum gate {#quorum-gate}

`[H]` One module decides what is and is not consensus, and nothing else depends on how it decides.
Two-thirds by ruling.

`[M]` **`f` is `min(spare, tolerates)`** — how many may vanish while a quorum can still form, and how
many may lie while safety holds. **Availability binds**: at n=11 two-thirds gives spare=3 and
tolerates=4, so f=3. Seizure, bankruptcy and outage all remove *availability*.

### Failure domains {#failure-domains}

`[M]` A node carries **opaque labels** — `provider:`, `country:`, `asn:`, `billing:`, `rack:`. Nothing
parses them; the system only counts. **No domain may hold more than `f` nodes.** Sufficient on its own:
since that bound is below the quorum size, no quorum can be drawn from a single domain.

Two consequences found by implementing it: the bound is **vacuous below n=4** (no placement makes a
1-node roster survivable, and enforcing it would forbid the first node), and a sound roster may be
**unreachable one node at a time** — 3-3-3-2 is fine at n=11 and refused at n=4, so a target roster
must be reached by a batched change.

### Buckets {#buckets}

`[H]` `bucket = ts / delta`. Boundaries are **computed, never negotiated** — there is no protocol for
agreeing where a bucket starts. Both a convention and a safety rail, for that reason.

## Authority

### Presence is membership {#presence-is-membership}

`[H]` A node is in the roster because its record exists. Deletion is removal; there is no separate
status field to disagree with the record.

### A roster change is one transaction {#roster-change-is-atomic}

`[H]` Removal and the rotation that follows it land together, so a node out of the roster but still
holding a live master is not a reachable state.

### Keys generate where they live {#possession-proof}

`[H]` Only a public half and a proof of possession ever travel. The manager never certifies a key it
did not see proven.

### Coarse ACL {#coarse-acl}

`[H]` A grant names **store ids** and **operation kinds**, never key paths. A node must be able to
check authority without reading a key, and the store id is cleartext in every operation.

### Management is a cleartext prefixed keyspace {#management-is-cleartext}

`[H]` Control records are readable and **enumerable** — a node needs the roster and the ACL to
function, and opaque fixed-width tokens cannot be enumerated.

### Absence is the revocation {#absence-is-revocation}

`[M]` There is no revocation list and no retraction record. Revoking removes the grant; the state root
commits to state, so the removal is bound to the data. **Selective withholding is therefore
impossible** — hiding a revocation means serving an older root, i.e. older data too.

Revocation freshness == data freshness: any freshness signal covers both, free.

### Replay does not re-adjudicate {#replay-does-not-readjudicate}

`[M]` A replayer applies at recorded indices and evaluates **nothing**. Forced, not convenient: after
collection the state a guard referenced is gone, so re-running guards gives *wrong* answers rather
than missing ones.

## Compaction

### Collection is a log entry {#collection-is-a-log-entry}

- A collection MUST be an ordinary settled entry at its own index.
- Replay MUST reproduce a collection exactly as settlement produced it.

### A segment is collected whole {#collect-whole-segment}

- The log MUST be divided into segments.
- A segment id MUST derive from the settled index, never from the author's timestamp (the mempool
  carries late transactions forward, so an author-stamped entry can otherwise land in a segment that
  has already been collected).
- A segment MUST NOT be used as a store id or as an ACL domain.
- Collection MUST delete every entry of the segment and MUST subtract exactly one accumulator.

### Collection is refused while live {#collection-refused-while-live}

Collection MUST be refused when any of these holds:

- the segment still holds a live value;
- the segment is current — it contains, or would contain, `head + 1`;
- the newest entry in the segment is younger than the dedup window. This MUST be measured as an
  **age** against author timestamps, never as a segment width (a width is a count and a window is a
  duration; comparing them requires an arrival rate nobody has).

### Collection is ratified {#collection-is-ratified}

- A collection marker MUST carry `(segment, height, acc_state, acc_log, root)`.
- It MUST carry a quorum signature over all five.
- A marker MUST NOT be applied on **any** path — settlement, replay, or bulk transfer — unless its
  signatures verify against the roster **and** the number of distinct signers satisfies the quorum
  rule (#quorum-gate). Verifying signatures without counting them is not ratification.
- The marker's identity MUST be over the claim alone, never over the signature set, so nodes that
  collect the same segment with different shares produce the same entry.
- A refusal MUST name its reason.

### Any node may drive a collection {#collection-is-driven-by-any-node}

- Any node MAY propose a collection. There MUST be no distinguished proposer.
- A proposal MUST be a function of the segment and the fold alone, never of who proposed it, so two
  nodes proposing the same segment produce byte-identical claims and their signatures pool.
- A peer MUST recompute the claim and MUST sign only if its own computation matches byte for byte.
- Ratification MUST happen while the evidence still exists; a wrong fold is refusable now and never
  again.
- At quorum every node MUST collect using the same ratified marker.

### Migration keeps the fold invariant {#migration-is-state-invariant}

- A migration MUST rewrite a straggler with the value it already holds, changing no state element.
- `A_state` MUST be unchanged by migration and by collection.
- A migration MUST assert nothing about the value, so that it requires no write authority.
- A relocation of a management row MUST carry the credential that authorised the value it moves, and
  that credential's author MUST be authorised at the time of the relocation.
- Migration MUST be agreed by the quorum like any other entry. A node MUST NOT apply its own
  migration locally.

## Accumulators

### The state root {#state-root}

- The state root MUST be a compressed sparse Merkle tree over live state, keyed by `H(store ‖ name)`.
- It MUST support non-inclusion proofs, which are what make #absence-is-revocation checkable.
- It MUST NOT be a sorted-leaf tree.
- The root MUST be a function of the live set alone: insert-then-delete MUST be indistinguishable
  from never-inserted, and no history may enter the root.
- Every leaf MUST be bound to its own path, and every internal node to its depth **and** its prefix,
  so no hash can be quoted out of position.
- Empty subtrees MUST hash to a fixed constant per depth.
- Domain separation MUST use BLAKE2b personalisation, never a tag concatenated onto the message.
- The root and `A_state` MUST both be maintained; neither replaces the other.
- The root MUST be carried in every ratified checkpoint (#collection-is-ratified) and in every
  attestation (#monotonicity).
- **A party that receives state MUST verify what it receives against a quorum-signed root before
  acting on it.** Serving a proof nobody verifies satisfies nothing.

### Two accumulators {#accumulators}

- `A_state` MUST be an ECMH sum over live `(store, name, value)`.
- `A_log` MUST be an ECMH sum over `(index, op_hash)` for the entries currently retained.
- `A_state` MUST be unchanged by collection.
- `A_log` MUST lose exactly the collected segment's accumulator, and nothing else.
- Replay-invariance MUST hold: every node replaying the *current* log agrees on both. Time-invariance
  MUST NOT be expected — the log changes when anything is collected.
- `A_log` cannot be computed by a node that never held the collected entries, so it MUST be adopted
  from a signed commitment rather than derived.

## Replication {#replication}

### A transfer is verified, not believed {#transfer-is-verified}

- A run of entries MUST be applied at the indices it names, without re-adjudicating predicates
  (#replay-does-not-readjudicate).
- A run MUST be contiguous from the recipient's head. A gap, a repeated index and a reordering are
  one failure: an entry that is not at the position owed.
- Every entry's signature MUST be verified before it is applied.
- Where a run reaches a height for which the recipient holds a **quorum-ratified** commitment, it
  MUST reconcile with that commitment. The sender's own attestation MUST NOT be sufficient: a node
  that signs a statement matching the history it invented is self-consistent, not authentic.
- A refusal MUST be returned, never raised (#no-exceptions-for-control-flow). A run that does not
  reconcile is an ordinary outcome of a bounded transfer racing the sender's own progress.
- Bulk state MUST be accepted only from a roster member, and only in answer to a request the
  recipient made.

### The floor authorises the hole {#the-floor-authorises}

- A compacted log is expected to have gaps, so completeness MUST NOT be required of the whole log.
- **Collection MUST proceed oldest segment first.** The retained log is then a contiguous suffix, and
  one ratified marker describes where it starts — the segment it collected, so the next one up is the
  frontier. A collector free to skip a blocked segment leaves interior holes, and an interior hole can
  only be explained by a record per collection, which would be the one structure here that grows
  without bound.
- `[retained_from, head]` MUST be complete, where `retained_from` is that frontier in index terms.
  Below it, absence is accounted for by the ratified collection that removed those indices; at or
  above it, every index MUST be held.
- A node MUST NOT retain a per-collection ledger to explain its holes. A frontier is sufficient and is
  O(1) for ever; a set is not bounded by anything.
- A node MUST NOT adopt a checkpoint whose signatures it cannot verify.
- A node MAY hold a floor above its own head. That is the signed statement *"the cluster has ratified
  state I do not hold"*, and it MUST NOT be refused: it is the condition that requires a bootstrap.
- Catching up MUST fill `(floor, head]`. A node that cannot obtain that range MUST bootstrap instead,
  and MUST NOT accept a partial or discontiguous run in its place.
- A server that no longer holds a requested range MUST NOT answer with what it happens to still hold.
  A run beginning past what was asked for is a hole the requester cannot use and will not revisit.
- A node whose needed range lies below the frontier MUST stop asking for it and bootstrap instead. The
  frontier reaches it on the ratified marker that gossip already carries, so this is decidable without
  a new message.

### Bootstrap has one anchor {#bootstrap-anchor}

The chain below MUST be established in order, and every step MUST be checked against the step before
it. Nothing in it may rest on the word of the cluster being joined.

1. The **manager public key AND `f+1` node addresses** MUST be supplied out of band when a node is
   provisioned, and retained across a re-bootstrap. Reaching `f+1` responders needs `f+1` addresses,
   and an address cannot be obtained by asking, because asking requires one.
   The manager key MUST be retained It is the only value not derived from something else, and it MUST NOT be
   taken from the log: a forged log introduces its own manager and checks out against itself.
2. A node MUST NOT be re-provisioned to a different manager. That would move it between clusters
   while keeping its identity, its attestation history and its monotone height — the one quantity
   #monotonicity says cannot be forged. Changing clusters MUST mean a new identity.
3. The log's own manager grant MUST name that key. A log that does not is a different cluster's and
   MUST be refused, and refused as a whole: a run that fails this MUST leave nothing behind.
4. The check MUST be applied after a run is applied and rolled back on failure, not before. A
   from-scratch replay begins with genesis, so the manager grant does not exist until the run lands;
   checking first would refuse the only run that could establish it.
5. A node with no anchor MUST NOT be treated as verified by default. It holds no axiom, so it MUST
   NOT adopt a floor.
6. Roster membership MUST be verified against **the anchor itself**, not against whichever key the
   log calls a manager: every roster row by the credential that authorised it. `replay` does not
   re-adjudicate authority, so a forged log can hold a `grant` row naming a manager nobody
   authorised, and "signed by a manager in this log" would accept the roster that manager wrote. A
   roster MUST NOT be taken on the word of the quorum it defines.
   Manager rotation therefore requires walking the chain of grants forward from the anchor, and is
   NOT yet supported: a row vouched by a successor key MUST fail this check rather than pass it.
   A party that does not hold the state MUST additionally verify each row's presence under a signed
   root — see step 9, which is where a proof is needed at all.
7. Roster membership MUST be stated in **one manager-signed commitment**, and that commitment MUST
   agree with the rows a node holds. Enumeration cannot detect its own incompleteness, and a subset is
   a smaller roster, hence a smaller quorum — a party handed three rows of eleven would compute a
   quorum of two from individually valid, individually vouched rows.
   The commitment MUST carry a **monotone serial**, and a node MUST NOT accept a roster whose serial
   is older than one it has already accepted. Otherwise a genuine-but-superseded roster — members
   since removed, whose keys an adversary may still hold — verifies perfectly for ever. The same
   withhold-never-forge argument as the floor: a higher serial cannot be forged without the manager.
   A roster change and its commitment MUST land in one transaction (#roster-change-is-atomic): a row
   set with no commitment is unverifiable rather than merely undocumented.
   The high-water serial MUST be durable, or a restart reopens the window it closes.
8. The checkpoint MUST then be verified against that roster (#collection-is-ratified).
9. State MUST then be verified against the checkpoint's root (#state-root), **row by row, on
   arrival**. A transfer checked only at the end cannot say which part was wrong and cannot be taken
   optimistically; a row that folds to the signed root can be kept the moment it lands.
   The walk MUST compare subtree hashes and descend only where they differ, so cost tracks absence
   rather than state size.
   The party doing the verifying MUST choose the depth at which it stops descending and asks for
   rows. A server that decided this would be deciding how much its client takes on one reply, which
   is why hashes and rows are two verbs and not one.
   **Subtree hashes MUST be verified, not believed.** An internal node is a function of its two
   children, so a reply MUST rebuild the hash already expected for that node — seeded by the signed
   root and carried down by each verified reply. Otherwise a peer can echo a walker's own hashes
   back, the walk descends nowhere, and finishing holding nothing is indistinguishable from success.
   A reply MUST name the question it answers. Replies are asynchronous, so pairing by arrival order
   attributes an answer to whatever was asked most recently.
   An unaccepted reply MUST NOT retire the question it failed to answer, or refusing a lie becomes a
   way to delete the question.
   A row MUST arrive with its own proof. Without one a reply cannot be checked in isolation, which is
   the property the whole walk rests on.
   State adopted this way MUST NOT set the head or `A_log`: history is not what is being transferred.
   Those come from the checkpoint and from replaying forward afterwards.

- **`f+1` fresh corroboration MUST come first, before anything else is adopted or walked**
  (#freshness-needs-many). Every other step of this chain establishes AUTHENTICITY; none establishes
  CURRENCY, and a malicious node can serve a perfectly authentic, perfectly stale world, correctly
  signed throughout. The count of fresh independent statements is the only thing that tells the two
  apart.
- `f+1` MUST be computed from what the quorum rule TOLERATES at this `n`, not from the quorum size:
  they answer different questions, and at n=3 two-thirds tolerates zero, so one honest fresh answer
  is `f+1`.
- A node MUST NOT count its own attestation toward that corroboration. Asking whether our view is
  current and answering with our own view decides nothing — and with one peer it would decide it.
- The checkpoint taken MUST be the **maximum** across those responders, since a floor carries the
  quorum's signatures: a responder can withhold a higher one and cannot forge one.

## Trust

### Storage nodes are untrusted {#nodes-are-untrusted}

- A node MUST hold no trusted component and no data keys.
- The adversary MUST be modelled as failure domains — seizure, provider loss, rollback from a
  snapshot restore, operator error — not as a rational actor with a payoff.

### Authenticity is self-verifying; currency is not {#the-lemma}

- Currency MUST NOT be treated as provable. A signature proves who spoke, a hash proves what, a proof
  proves it was computed correctly; nothing proves that nobody has spoken since.
- A signed position MUST be interpreted as *"at `T`, the frontier was at least `F`"*, and MUST NOT be
  interpreted as *"`F` is the frontier now"*.

### Freshness needs f+1; authenticity needs one {#freshness-needs-many}

- A cold client MUST gather `f+1` independently signed statements and MUST check them itself.
- A returning client holding a receipt MAY rely on one responder, since it carries its own floor.
- The floor MUST be the **maximum** over those responders, never a majority vote: an arm can withhold
  a higher checkpoint but cannot forge one.
- Only a floor whose quorum signatures verify may contribute. An unverifiable floor MUST count as
  zero.
- There MUST be no third party that vouches for freshness. No priest.

### Freshness is gathered, never proved {#freshness-is-gathered}

- A node MUST sign the time its **own** clock reads when it attests.
- A timestamp MUST NOT be ratified by anyone: no peer can recompute another's clock.
- A statement outside the freshness window MUST be discarded, in both directions — a future timestamp
  would read as maximally fresh until that time arrived.
- The window MUST be a cluster-wide tunable, and MUST exceed the probe interval.
- A clock fault MUST NOT be convictable. It MUST only drop that node from the `f+1`.

### Monotonicity is a duty {#monotonicity}

- A node MUST attest a monotone height and MUST NOT regress.
- The attested floor MUST be the highest quorum-ratified checkpoint the node holds.
- A node's own head MUST be carried as a hint and MUST NOT be used as a floor by anyone: a private
  opinion of one's own height is forgeable upward at no cost.
- `head` MUST remain monotone under collection. It MUST be `MAX(idx)`, and a collection MUST write its
  marker at `head + 1` before deleting the segment it collects. A count would make every honest node
  convict itself the moment it collected.
- An attestation MUST be a pure function of committed state.
- The attestation counter MUST be committed before the claim is signed. A crash MUST therefore skip a
  counter value: skipping is free, reuse is fatal.
- The counter MUST be separate from the height. Ordering two claims by the quantity under dispute is
  circular.
- Out-of-band restore MUST be forbidden, or MUST force an identity reset.

### Peers keep the evidence {#cross-attestation}

- A node MUST relay the latest attestation it holds for each peer verbatim and signed by that peer,
  never as an opinion about it.
- A relay MUST carry convictions as well as sightings. A node that convicts keeps the earlier
  statement and refuses the later one, so relaying sightings alone relays only the innocent half.
- A receiver MUST recompute a relayed verdict and MUST NOT believe it.
- Relayed evidence MUST only ever convict, never vouch. No reputation accrues.
- Conviction MUST require a single key contradicting itself: the same counter over different bytes, or
  an increased counter over a decreased height or a decreased floor.
- Accumulators and timestamps MUST NOT enter the conviction predicate.
- Divergence MUST NOT convict. Two keys claiming one height with different accumulators proves
  something is wrong and nothing about who.
- Conviction MUST be terminal for the identity. Recovery MUST be re-join as a new node; there MUST be
  no rehabilitation and no un-shun protocol.
- Shunning MUST follow proven self-contradiction only — never silence, staleness or divergence.
- Shunning MUST be a local read policy. It MUST NOT alter the roster or the quorum arithmetic, so a
  heavily shunned cluster stalls rather than proceeding on a thinned quorum.

## The mempool {#mempool}

- **One predicate decides mempool entry, and every door MUST apply it.** A client submitting and a
  reject returning from settlement ask the same question; two policies that agree today is how they
  stop agreeing later.
- That predicate MUST include the admission window, the signature, **and whether the transaction
  would apply against committed state**. A transaction that cannot apply now would not have landed
  even if a batch chose it, so admitting it costs the client the only thing it wanted: an answer.
- A refusal MUST name its reason, and the reason MUST distinguish a clock fault from an invalid
  transaction — a client can only self-correct if it is told which.
- A reject returning from settlement MUST be **re-evaluated**, not ejected on its verdict. A reject
  can be valid *after* the batch that rejected it: a write guarded on `absent(k)` fails at its
  position if `k` exists there and holds once a bucket-mate has deleted `k`.
- A transaction already in the log MUST NOT re-enter, whatever the state says: the content address is
  unique, so it can never land again.
- Mutually exclusive transactions MAY both be held. Exclusion MUST be resolved by **selection**, not
  by refusal at the door: the candidates are evaluated in order over a layer that absorbs each
  survivor, so a batch carries at most one of them and the loser is still held.
- An endorser MUST refuse a slice containing a transaction it holds that is past `w_valid`. Silence
  is the refusal; a quorum of honest nodes then cannot form around it.
- A transaction MUST NOT be retained past the point at which it can no longer be endorsed
  (#timing).
- The screening the proposer applies, the door applies, and settlement applies MUST be the same
  evaluator. Three implementations that agree today is not agreement.

## Timing {#timing}

- Every timing value MUST be expressed against a **declared quantity**. A literal timing figure MUST
  NOT appear anywhere outside a tunable group's field default.
- The declared quantities are exactly: `RTT_MAX` and `CLOCK_SKEW` (measurements of a deployment),
  `CLIENT_CLOCK_TOLERANCE` (a policy, whose cost is the replay window), and the protocol counts
  `HOPS_TO_QUORUM` and `WAVES_TO_SETTLE`. Adding to this set MUST be a decision, not a default.
- Each dial MUST sit at or above the floor derived from those quantities. A dial MAY exceed its
  floor — that is a margin — and MUST NOT sit below it.
- The bucket width MUST be at least dissemination to a quorum, `HOPS_TO_QUORUM·RTT_MAX + CLOCK_SKEW`.
- The conversation window MUST be at least `CLOCK_SKEW + RTT_MAX`.
- The admission window MUST be at least `CLIENT_CLOCK_TOLERANCE + 2·RTT_MAX`, and it is the **replay
  bound**: a captured transaction stays admittable for that long, so generosity here is paid for in
  replay window rather than in latency.
- The endorsement margin MUST be at least `WAVES_TO_SETTLE·delta + CLOCK_SKEW`, so a transaction
  admitted at the edge of the window survives the round it was admitted for.
- **Nothing MUST be retained past the point it can settle.** The eviction horizon MUST EQUAL
  `w_valid`, and MUST be derived rather than set, because a transaction is unendorsable once
  `|now − ts| > w_valid` and any surplus is a window in which a stale compare-and-swap can be
  re-proposed.
- A backoff ceiling MUST NOT exceed the deadline it is spent against. The deadline is the real limit
  on retrying — it is checked first and clamps every wait — so an attempt count is a backstop and MUST
  NOT be derived from the deadline.
- A check MUST NOT re-implement what it checks. A second model of one rule can disagree with the
  first, and the copy that is wrong is the one nobody runs.
- The freshness window MUST exceed the probe interval that feeds it, with room for a missed probe.
- **A dial MUST have exactly one home**: the group belonging to the object that decides with it. The
  same dial declared in two groups can disagree, and the copy that loses is whichever the caller did
  not read.
- Dials MUST be reachable from the one composed surface. A timing constant in module scope MUST NOT
  exist.

## Enforcement

Covers Compaction, Accumulators, Replication and Trust. **A row with no enforcer is a requirement nothing
obliges**, which is the defect this table exists to make visible rather than plausible.

| requirement | enforced by |
|---|---|
| a marker is ratified before it is applied, on every path | `Store.replay`, `Store.collect` |
| ratification counts distinct signers against the quorum rule | `ops.Compaction.attested` |
| a peer signs only a claim it recomputed | `Node._on_collect` |
| collection is refused while live, current, or too young | `Store.collect` |
| `A_state` is unchanged by collection | `Store._collect` (raises `InvariantError`) |
| a relocation of a management row is currently vouched for | `settle._relocates`, `settle._vouches` |
| a run is contiguous from the recipient's head | `node._uncontiguous` |
| every replayed entry's signature verifies | `store._unverified` |
| a run reconciles with a ratified commitment where it reaches one | `Store._anchors`, `Store._disagrees` |
| a refusal is returned, not raised | `Store.replay` return type |
| bulk state is solicited and from a roster member | `node.SOLICITED`, `Node._on_entries` |
| a checkpoint is adopted only if its signatures verify | `Store.adopt` |
| an unverifiable floor counts as zero | `attest.attested_floor` |
| a statement outside the window is discarded | `attest.fresh` |
| the attestation counter is committed before signing | `Store.attestation` |
| conviction is self-contradiction only | `attest.contradiction` |
| a relayed verdict is recomputed | `Store.judge` |
| shunning does not alter quorum arithmetic | `Node.shunned` |
| every inbound frame is checked against the screen tag | `Postman.deliver` |
| received state is verified against a signed root, row by row | `Store.adopt_state` via `smt.verify` |
| the walk descends only where subtree hashes differ | `Store.subtree`, `Node._on_hashes` |
| a row is served with its own proof | `Node._on_leaves` |
| the verifier chooses the descent depth | `NetTunables.walk_depth`, `Node._on_hashes` |
| a subtree hash is rebuilt from the answer, not believed | `node._folds_to` |
| a reply is correlated to the peer we asked | `Mailbox.arrived` |
| **a bootstrap is driven when catching up is impossible** | **OWED** — `Node.bootstrap` has no caller |
| the manager key is supplied out of band and retained | `Store.provision`, `Store.anchor` |
| a node is not re-provisioned to another manager | `Store.provision` (raises `InvariantError`) |
| the log's manager grant names our anchor | `Store.wrong_cluster`, enforced in `Store.replay` |
| a checkpoint from another cluster is not adopted | `Store.adopt` |
| roster membership traces to the anchor | `Store.unvouched_roster`, enforced in `Store.replay` |
| one implementation of "does this credential vouch for this row" | `settle.vouched` |
| membership is one manager-signed commitment, matching the rows | `Store.roster_incomplete` |
| a roster serial never goes backwards | `Store.roster_incomplete`, `Store.roster_serial` |
| roster completeness is verifiable | **OWED** — needs a manager-signed membership commitment |
| `f+1` fresh corroboration precedes anything else | `Node.corroborated`, gating `Node.bootstrap` |
| a node does not count itself toward `f+1` | `Node.gathered(me=False)` |
| seed addresses are provisioning input | `Store.provision(seeds=)`, `Store.seeds` |
| a node that cannot obtain `(floor, head]` bootstraps instead | **OWED** — no decision point exists |
| a server says what it no longer holds | **OWED** — `_on_pull` answers with what it has |
| every dial sits at or above its derived floor | `Tunables.__post_init__` (raises `InvariantError`) |
| nothing is retained past the point it can settle | `MempoolTunables.evict_after` (a property) |
| a backoff ceiling does not exceed its deadline | `Tunables.__post_init__` |
| one dial has one home | `tests/test_timing.py` |
| tunables are consensus-agreed at a log position | **OWED** — they are per-node defaults today |
| one predicate decides mempool entry, at every door | `Mempool.valid` (`admit`, `reenter`) |
| entry consults committed state | `Mempool.valid` via `settle.would_apply` |
| a reject is re-evaluated, not ejected on its verdict | `Mempool.reenter` |
| exclusion is resolved by selection, not refusal | `Mempool.propose` via `settle.would_apply` |
| an endorser refuses a slice past `w_valid` | `Node._stale` via `Mempool.endorsable` |
| nothing is retained past its endorsable life | `Mempool.evict`, called from `Node.tick` |
| a value carries its epoch in cleartext | `ops.Set.epoch`, `live.epoch` |
| an epoch is not retired while a value references it | `ops.Drained` via `layer.holds` |
| retirement is an ordinary guarded transaction | `Management.retire` (built) |
| retirement is a manager operation, not a duty of the round | `Management.retire`, authored by a manager |
| **the backlog is readable, oldest first** | **OWED** — `Store.epochs` has no reader and no verb |
| **live values are re-encrypted forward** | **OWED to the worker/client layer** — a node holds no data keys |
| stragglers are migrated so a segment can be collected | `Node.housekeep` → `Node.drain` |
| a collectable segment is proposed for collection | `Node.housekeep` → `Node.maybe_collect` |
| the dedup floor applies on every collection path | `Store.collect` — **but defaults to off** |
| effort scales with backlog, with a clamp | `CompactionTunables`, `Store.migration(at_most=)` |
| the current segment is never drained into itself | `Node.housekeep` |
| a hole is explained by the frontier, with no growing set | `Store.horizon`, `Store.retained_from` |
| collection proceeds oldest segment first | `Node.maybe_collect` |
| a server never answers a PULL with a hole | `Node._on_pull` |
| a node behind the frontier stops asking | `Node.behind_the_horizon` |
| **it then bootstraps** | **OWED** — no state-transfer verb exists |
## Keys

### Two secrets, never one {#two-secrets}

`[H]` A **permanent name key** derives name tokens and never rotates; a **rotating value key** derives
item keys per epoch. Rotating one must not re-derive the other, or rotation becomes an O(state)
re-encryption.

### Per-item keys {#per-item-key}

`[H]` `item_key = f(value_key, name_token)`, so no two items share a key.

### Random nonce, no cardinality leak {#random-nonce}

`[H]` The AEAD uses a random nonce and is misuse-resistant. A deterministic nonce would make a key's
value cardinality observable — and a predicate quotes a ciphertext digest rather than recomputing one,
so determinism buys nothing.

### Wrapped masters {#wrapped-masters}

`[H]` One sealed copy of the epoch master per authorised holder, distributed atomically: every holder
gains it together or none does, so no client is left holding data it cannot read.

`[M]` **Retention is refcounted over live values** — a value carries its epoch, so the count is a
function of live state and survives collection. No history, no policy.

### The conveyor {#conveyor}

- Forward secrecy MUST come from **key death**, never from erasing ciphertext: on SSDs, CoW
  filesystems and rented block storage the old bytes cannot be asserted gone.
- An epoch's key MUST NOT be retired while any live value still references it. Retire one value early
  and that value is unreadable by everyone for ever, which is the loss of committed state this system
  exists to prevent.
- Live values MUST therefore be **re-encrypted forward**, which is what drains the last references.
  This is a duty of the layer that holds data keys — a worker or a client — because a node holds
  none.
- Any layer doing this work MUST scale its effort to the backlog, clamped so housekeeping cannot
  crowd out work, and MUST use a heartbeat for the idle case rather than a second conveying path.
- The **threshold** and the **clamp** MUST both exist as tunables. `[H]` The rate at which compaction
  converges is not yet decided, and a threshold of zero — "whenever there is any work" — is the floor
  of the same dial rather than a separate always-on mode.
- A node MUST NOT relocate rows out of the segment that contains the head: migration writes at the
  head, so that returns them to the segment they were in.
- Retirement MUST NOT be a duty of the round. `[H]` Wrap rows are not deleted as housekeeping; the
  management store is low churn, so deleting a client's wraps belongs with the manager operation that
  rotates that client. No node or worker therefore needs management-store authority to keep the belt
  moving.
- The backlog MUST be readable, oldest epoch first, so the conveying layer can ask what to work on.
- Key rotation MUST NOT be treated as forward secrecy on its own: rotating faster without conveying
  faster buys nothing.
- A value MUST carry its epoch in **cleartext**. It MUST NOT be inside the AEAD: retention is
  refcounted over live values, a node that cannot decrypt must still be able to count, and an
  encrypted epoch makes the refcount underivable, so no key could ever die. The leak is forced rather
  than chosen — which epoch a value sits under is public, and so is roughly when it was last written
  or conveyed.
- Retirement MUST be an ordinary transaction guarded by `Drained`, the one predicate that ranges over
  all keys. Every node MUST evaluate it identically at the same log position, and replay MUST
  reproduce it, so a retirement that should not have happened settles nowhere.
- A retired epoch MUST NOT be resurrectable by a stale write, and **no additional rule may be added
  to prevent it**: an epoch outlives a validity window by orders of magnitude, so such a client is
  outside the admission window and is refused there (#timing).
- Retirement MUST NOT be claimed to do more than it does. Deleting the wraps makes a master
  unobtainable *from the record*, and #state-root proves that absence to anyone holding the root.
  Whether a holder that once had the master in memory forgot it is provable by nobody.
- A conveyance MUST write at the head, so one conveyance drains the old epoch **and** vacates the old
  segment. The belt moves once and two things fall off the back.

## Transport

### Transport adds no trust {#transport-adds-no-trust}

`[H]` A message is **point-to-point** even when the carrier is broadcast. Transports move bytes or
raise; no retries, no timeouts, no opinions — a hidden retry is a transmission the link layer cannot
count.

### The screen tag {#screen-tag}

`[H]` `HMAC(key = destination identity, message = sealed bytes)`. Including the sealed bytes is
essential: keyed on identity alone it would be a constant, i.e. a permanent per-node fingerprint. A
**hint**, never authentication.

### Sign then seal {#sign-then-seal}

`[H]` Sealing after signing means an observer sees no identity. Signing a ciphertext would leave the
sender's key in the clear and leak the social graph.

## Errors

### Routine outcomes are returned, not raised {#no-exceptions-for-control-flow}

`[H]` A signature that does not match, a refused admission, a failed guard, an open circuit — all are
**returned values with closed types**. Not hypothetical: verification briefly raised instead of
returning, making `if not verify(...)` vacuously true and silently breaking **every** multisig
verification in the system.

Closed enums reserve **ordinal 0 as `INVALID`**, so a Go port's zero value lands on a named invalid.

---

## Retired tags

None yet. When a rule is retired, its tag stays here with the reason, so a stale citation resolves to
an explanation rather than to nothing.
