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

Provenance: **`[H]`** Harry's ruling · **`[M]`** established by a model in `experiments/` ·
**`[I]`** inference, not yet tested.

---

## 0. Design choices

**Read this section before changing anything.** Everything below §0 is detail; this is the set of
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

## 1. The log

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

## 2. Settlement

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

## 3. Authority

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

## 4. Compaction

### Collection is a log entry {#collection-is-a-log-entry}

`[M]` A collection is an ordinary settled entry, so replay reproduces it.

### A segment is collected whole {#collect-whole-segment}

`[M]` The log is divided into **segments** — physical slices, **not** stores and not ACL domains. The
id derives from the **settled index**, never the author's clock, because the mempool carries late
transactions forward and an author-stamped entry could otherwise land in a collected segment.

Collection deletes a segment entirely and subtracts **one accumulator**. No scattered drop set, no
chain to repair, no run-length problem — a segment *is* a run by construction.

### Collection is refused while live {#collection-refused-while-live}

`[M]` Three refusals, each a correctness property:

- **stragglers remain** — a segment that silently collected live data would lose committed state
- **the segment is current** — migration writes at the head, so draining a segment into itself is a
  no-op and the straggler simply reappears
- **younger than the dedup window** — `op_hash UNIQUE` is what makes a settled transaction
  unrepeatable, and collection forgets those hashes. Expressed as an **age**, not a segment width: a
  width is a count and the window is a duration, so comparing them would need an arrival rate nobody
  has.

### Collection is ratified {#collection-is-ratified}

`[M]` A collection carries `(segment, height, acc_state)` and a **quorum signature over all three**.
Collection deletes the joiner's only other verification path, so an unratified collection is one
nobody can ever check. The refusal names the reason plainly — *"no signature"*.

### Any node may drive a collection {#collection-is-driven-by-any-node}

`[I]` A collection needs no distinguished proposer. Any node that finds a segment collectable —
below the liveness threshold, past the dedup age, not current — migrates its stragglers and proposes
it. Peers **recompute the fold** and sign only if they agree; at quorum every node collects using the
same ratified attestation.

Two nodes proposing the same segment is harmless: the proposals are identical, because a collection is
a function of the segment and the fold rather than of who noticed first. A node that proposes a wrong
fold is refused by everyone who still holds the data — which is the whole reason ratification happens
**while the evidence exists** (#collection-is-ratified).

### Migration keeps the fold invariant {#migration-is-state-invariant}

`[M]` Stragglers are rewritten at the head with the **same value**, so no state element changes and
`A_state` is untouched while provenance moves forward. Without it, collection has a permanent floor:
genesis grants and roster rows are live for the life of the log.

This is the cheap half of the conveyor; see [#conveyor](#conveyor).

## 5. Accumulators

### The state root {#state-root}

`[M]` A **compressed sparse Merkle tree** over live state, keyed by `H(store ‖ name)`, gives what no
accumulator can: a proof about **one key**, checkable by a client holding nothing but the root.

`[M]` **Absence is the point.** #absence-is-revocation makes a revocation nothing more than a grant
that is gone — and until now there was no way to *prove* something is gone. A non-inclusion proof is a
proof of revocation, so revocation freshness becomes data freshness in fact rather than by assertion.

`[M]` It also restores what collection destroys. #collect-whole-segment deletes the joiner's replay
path, which is why collection must be ratified; a state root gives a **second** verification path — a
node that reconstructs state can check it against a root the quorum signed, rather than trusting that
it reconstructed correctly.

`[M]` **Both commitments are kept.** ECMH answers "do we hold the same state" in O(1) and nodes ask
that constantly (#accumulators); the tree is paid only when a proof is served or a checkpoint is cut.
Neither replaces the other.

`[M]` **The root is a function of the live set alone.** Insert-then-delete is indistinguishable from
never-inserted, so two nodes holding the same state agree on the root regardless of how they got
there. No history enters the root — history is the log's job.

`[M]` **Key-indexed with path compression, never sorted-leaf.** A sorted-leaf tree's insert is O(n)
because every later position shifts; probe 20 measured it, and F16's "O(log S) cached" is **retracted**
— the probe-03/06 tree is read-only and must not be lifted into production. Depth is ~24 at 10⁷ keys,
so a proof is ~768 B.

`[M]` **The branch depth is hashed into every internal node**, so the tree's shape is committed and no
proof can be re-folded at a depth it was not issued for. Empty subtrees hash to a fixed constant at
every depth, which is what makes the structure sparse.

`[M]` The root is carried in the ratified checkpoint (#collection-is-ratified) and in a node's
attestation (#monotonicity), so a proof always verifies against something **signed** — by a quorum in
the first case, by a convictable single node in the second.

### Two accumulators {#accumulators}

`A_state` over live `(store, name, value)`; `A_log` over `(index, op_hash)`. Both ECMH: an
order-independent sum with exact subtraction.

`[M]` **`A_state` is unchanged by collection** — collection removes only superseded history. `A_log`
changes, and that is correct: the log changed. What must hold is **replay-invariance** (everyone
replaying the *current* log agrees), not time-invariance, which is impossible once anything is
rewritten.

## 6. Trust

### Storage nodes are untrusted {#nodes-are-untrusted}

`[H]` They hold no trusted component and no keys. `[M]` The adversary is **failure domains** — seizure,
provider loss, accidental rollback from a snapshot restore, operator error — not rational actors with
a payoff. Every node is bought and paid for.

### Authenticity is self-verifying; currency is not {#the-lemma}

`[M]` A signature proves *who spoke*. A hash proves *what*. A proof proves *it was computed
correctly*. **Nothing proves that nobody has spoken since** — there is no such object, so no
cryptography produces one.

*"Is this current?"* is unaskable. The answerable form is *"is this too old?"*, which needs a clock and
a party whose clock you trust.

### Freshness needs f+1; authenticity needs one {#freshness-needs-many}

`[M]` An arm can **withhold** a higher checkpoint, never forge one. So the maximum across `f+1`
responders is correct. A **returning** client holding a receipt carries its own height floor and needs
one responder; a **cold** client needs `f+1`.

`[H]` **There is no priest** — the budget will not carry the cluster and a blessing service. Cold
single-link clients are therefore out of scope.

### Monotonicity is a duty {#monotonicity}

`[M]` Nodes attest a monotone height and never regress; clients take the max over `f+1`. A regression
is a **signed contradiction** anyone can keep — accountability rather than prevention, which needs
durable state and no trusted hardware.

`[M]` The attested floor is the **highest quorum-ratified checkpoint** the node holds. Its own head
rides along as a **hint** and is never a floor: a private opinion of one's own height is forgeable
*upward* at no cost, and #freshness-needs-many's "withhold, never forge" holds only for something
carrying the quorum's signatures. Before the first collection there is no floor, so a young cluster
attests zero and only the hint carries information.

`[M]` **`head` must remain monotone under collection.** It is `MAX(idx)`, and collection writes its
marker at `head+1` before deleting the segment it collects. Were it a count instead, every honest node
would convict itself the moment it collected.

`[M]` The attestation is a **pure function of committed store state**, and the counter is committed
*before* it is signed. Signing over uncommitted state is then unconstructible rather than merely
discouraged: a crash **skips** a counter value, and skipping is free where reuse is fatal. This is the
highest-risk interlock in the design — see #cross-attestation, where an honest node convicting itself
is permanent.

`[M]` The counter is separate from the height. Ordering two claims by the quantity under dispute is
circular: if the counter *were* the height, a regression would be unorderable and so unconvictable.

`[H]` Out-of-band restore is forbidden: it regresses the height and convicts the node for an operator
convenience.

### Peers keep the evidence {#cross-attestation}

`[M]` A node relays the latest attestation it holds for each peer, **verbatim and signed by that
peer**, never as an opinion about it. A relay can therefore neither forge nor alter one — it cannot
frame a peer and cannot be framed by one — so the only lie left anywhere in the scheme is **silence**,
which is measurable against the rest of the cluster.

`[M]` Peers are the **keepers**. Accountability otherwise rests on some client having happened to be
watching, and the accident this catches — a snapshot restored overnight — happens precisely when
nobody is. Every peer a node ever spoke to holds evidence against its future self.

`[M]` Relayed evidence **only ever convicts, never vouches**. A sighting is worth exactly the signature
it carries, so no reputation accrues and collusive vouching buys nothing.

`[M]` This is the partial repair of #known-churn's refutation: a node cannot witness its own
monotonicity, but it can witness its peers'. Single-node and minority rollback become obvious. A
genuine common-mode failure — everything rolling back together — stays invisible.

`[M]` **Conviction is a single key contradicting itself**: the same counter over different bytes, or
an increased counter over a decreased height. Clock-free, self-contained, permanent, and attributable.
Accumulators are deliberately not in the predicate — they are unordered, so nothing can regress.

`[M]` **Divergence is not conviction.** Two keys claiming the same head with different accumulators
proves something is wrong and *nothing about who*; resolving it needs the data. Shunning on divergence
would let a liar get an honest node shunned.

`[H]` Conviction is **terminal for the identity**. Recovery is re-join as a new node — the path a
forbidden restore already forces (#monotonicity), so this adds no mechanism. There is no
rehabilitation and no un-shun protocol.

`[H]` Shunning follows **proven self-contradiction only** — never silence, staleness, or divergence. A
partition makes honest nodes look stalled, and a cluster that shunned on staleness would eat itself.

`[M]` Shunning is a **local read policy**: it does not alter the roster or the quorum arithmetic. A
shunned node still counts toward `n`, so a heavily-shunned cluster **stalls rather than proceeding** on
a thinned quorum, which is the correct direction under #durability-over-latency.

## 7. Keys

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

`[M]` Forward secrecy comes from **key death**, not from erasing ciphertext — on SSDs, CoW filesystems
and rented block storage you cannot assert the old bytes are gone.

An old epoch's key can only die when nothing references it, so live values must be **re-encrypted
forward**. `[H]` Worker bees do this as housekeeping while running their own jobs; effort scales with
backlog pressure, clamped so housekeeping cannot crowd out work. The idle case needs a heartbeat, not a
fallback path.

**Rotating keys faster without conveying faster buys nothing.**

## 8. Transport

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

## 9. Errors

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
