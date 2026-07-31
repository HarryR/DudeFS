---
title: DUDEFS — layered specification (L0–L4)
---

# SPECv2

Documents the settled layers of DUDEFS: primitives, storage, ops, mempool, consensus. Everything at
L5 and above (compaction, sync, transport) is being reshaped and lives elsewhere until it settles.

Supersedes the equivalent material in `SPEC.md`. Where a rule survives from there, its anchor is
preserved so existing citations still resolve; where a rule is retired, its anchor stays in the
retired-tags section with the reason.

## How to cite this

Every normative statement carries a `#tag`. Code cites the tag, never a section number. Positional
references break whenever a section moves and cannot be grepped in both directions. Tags are
permanent — renaming one is a breaking change, retiring one means marking it here rather than
deleting it, so a stale citation resolves to an explanation rather than to nothing.

## What this document is

**Requirements, and nothing else.** Every statement says what an implementation MUST or MUST NOT do,
in a form a reader can check against code. No provenance markers, no rationale beyond at most one
clause naming what goes wrong without a rule. Rejected alternatives and history live in `git log`.

**Every requirement a check can carry appears in the enforcement table**, mapped to the symbol that
enforces it. A requirement with no enforcer is not satisfied by prose; it is marked **OWED**.

---

## Design choices

**Read this section before changing anything.** Each has been re-derived wrongly at least once, at a
cost of days rather than minutes.

### What this is for {#the-workload}

Coordination for blockchain intent-space workflow automation. A job is a register overwritten at
each checkpoint: idempotent steps between checkpoints, certainty required at each one before the
job continues.

The log is **near-total death with a tiny live frontier** — ~90% of it is dead the moment a job
advances. This is not key-value churn; reasoning that assumes churn gets the wrong answer.

### Who is trusted, and who is not {#trust-tiers}

| role | trust | availability |
|---|---|---|
| **manager** | root of trust | cold; offline ~99% of the time |
| **compactor** | manager-adjacent, cannot alter roster or grants | warm; runs periodically |
| **workers** (worker bees) | run in TEEs, hold key material | ephemeral |
| **storage nodes** | ~11 low-spec VPS across jurisdictions | untrusted; no keys, no trusted component |

**There is no priest.** The budget will not carry the cluster and a blessing service. That one
ruling decides three things at once, and they are not separable:

> manager offline ⟺ no priest ⟺ cold clients need `f+1`.

A returning client holding a receipt still works on a single link; a **cold** single-link client is
out of scope, and no amount of cryptography changes that (#the-lemma).

### No token economics {#no-token-economics}

Every node is bought and paid for on 2–4 year prepaid contracts. There is no staking, no incentive
layer, no economically rational adversary, and no "paid bulk holders". The adversary is failure
domains — seizure, provider bankruptcy, accidental rollback from snapshot restore, operator error.

### One global log {#one-global-log}

A worker MUST be able to resume any job without knowing in advance which. That requires one log,
not per-job logs — those turn resumption into a discovery problem across every node.

### Durability over latency {#durability-over-latency}

30-second finality is fine; 1–2 minutes is acceptable. That is the **U** in DUDE. Reducing
synchronisation points pays; shaving milliseconds does not.

### Compaction is not an optimisation {#compaction-is-required}

The live frontier is megabytes while the raw log is gigabytes per day. On prepaid low-spec VPS,
that is the difference between fitting and not.

### Forward secrecy comes from key death {#secrecy-by-key-death}

Not from erasing ciphertext — on SSDs, CoW filesystems and rented block storage the old bytes
cannot be asserted gone. Key destruction is the only erasure controllable, which is why live values
MUST be re-encryptable forward under a new key without decrypting under the old one.

### Things that have been re-derived wrongly {#known-churn}

| tempting conclusion | why it is wrong |
|---|---|
| split storage from attestation, so nodes hold no data | breaks ratification, severs commit-implies-possession |
| give each workflow its own log | work portability requires one global log (#one-global-log) |
| a Merkle/MMR tree over the **log** | a log commits to positions and truncation scatters them |
| a SNARK can establish that state is current | an old proof is a valid proof — currency is not computational (#the-lemma) |
| storage nodes can witness their own monotonicity | they are the observed party; a common-mode failure is invisible to them |

---

## L0 — Primitives

### Canonical codec {#codec}

- The wire format MUST be bencode.
- The encoder MUST be canonical: for any input value there is one encoding, byte-for-byte.
- The decoder MUST reject non-canonical input rather than accepting and re-encoding, because a
  liberal decoder is the mechanism by which two implementations drift apart while both appear to
  work.
- Decoding MUST validate at the boundary: extractors turn a decoded value into a typed one or
  raise, never returning `Any` for a downstream to guess at.

### Cryptographic primitives {#primitives}

- Hashing MUST be BLAKE2b, personalised. Domain separation MUST use BLAKE2b personalisation, never
  a tag concatenated onto the message.
- Signatures MUST be Ed25519, with a list-multisig construction for quorum signatures over one
  payload.
- The AEAD MUST be misuse-resistant with a random nonce — deterministic nonces make a key's value
  cardinality observable.
- One 32-byte master per keyepoch, sealed per authorised holder; per-item keys derive from the
  master by domain-separated keyed-BLAKE2 (#two-secrets, #per-item-key, #wrapped-masters).

### Accumulators {#accumulators}

Two ECMH accumulators, and they answer different questions.

- `A_state` MUST be an ECMH sum over live `(store, name, value)`. It fingerprints the current set
  of live values. Two nodes agreeing on `A_state` hold the same live state.
- `A_log` MUST be an ECMH sum over `(index, op_hash)` for the entries currently retained. Two nodes
  agreeing on `A_state` may disagree on `A_log` — that is *same state, different history*, which is
  legitimate across truncation generations.
- Two nodes agreeing on both `A_state` and `A_log` at the same head are the same node.
- ECMH rather than a hash chain because the log truncates and a chain cannot be maintained
  incrementally under deletion.
- Provenance MUST NOT enter `A_state`. Re-pointing a live key's provenance is exactly what a
  useful compaction does; accumulating it would forbid the compaction worth doing.

### The state root {#state-root}

- The state root MUST be a compressed sparse Merkle tree over live state, keyed by `H(store ‖ name)`.
- It MUST support non-inclusion proofs, which are what make revocation checkable.
- It MUST NOT be a sorted-leaf tree — insert cost is O(n) and depth is unbounded.
- The root MUST be a function of the live set alone: insert-then-delete MUST be indistinguishable
  from never-inserted, and no history may enter the root.
- Every leaf MUST be bound to its own path, and every internal node to its depth **and** its
  prefix, so no hash can be quoted out of position.
- Every leaf MUST also be bound to the credential that authorised its value (#credential-in-every-leaf).
  Without this the root commits to what every key holds and to nothing about who was permitted to
  put it there.
- Empty subtrees MUST hash to a fixed constant per depth.
- The tree structure is **derivable from the leaves**: a receiver holding the same `(store, name,
  value, credential)` set computes the same root. The internal nodes are a memo of a pure function;
  they need not be transmitted.

---

## L1 — Storage

### The log is authoritative {#log-is-authoritative}

- The log is the single authoritative record. Live state is a derived fold of it, and every derived
  view MUST be recomputable from the log alone.
- The log is append-only between checkpoints and truncatable only by a ratified checkpoint (see
  L5). Entries below the last ratified checkpoint MAY be discarded.
- **Positions MUST be preserved.** A settled index is part of the log's identity: predicates and
  checkpoint payloads reference entries by index. Renumbering on replay silently invalidates every
  such reference.

### One store per (store, name) {#one-key-per-pair}

- A key's identity is the pair `(store, name)`. The same name token in two stores is two different
  keys. Keying by name alone lets a data write silently clobber a management value.

### Management is a cleartext prefixed keyspace {#management-is-cleartext}

- The management store MUST hold cleartext paths (`node/<pubkey>`, `grant/<pubkey>`, …), not
  derived tokens: a node must be able to enumerate node records by prefix, which opaque
  fixed-width digests do not support.
- Data stores hold opaque derived tokens whose structure lives only in the client that derived
  them.

### The live view {#live-view}

- Live state MUST hold, for each live key, its current value, the settled index that last wrote it,
  its keyepoch, and the credential that authorised its value.
- Live state MUST be updated atomically with the entry that changes it — one transaction over the
  log, the accumulator, the root and the live view, or none.

### Provenance {#provenance}

- The provenance reported for a live key is the CURRENT head only. The chain behind it is a
  traversal, and truncation may have collapsed it.
- Provenance is not signed and is not carried in `A_state` (#accumulators).

### Credential in every leaf {#credential-in-every-leaf}

- Every live row MUST carry the signed transaction that authorised its current value.
- The leaf hash MUST commit to that credential (#state-root).
- Recording a credential for only some stores makes a data leaf authenticated by quorum say-so and
  nothing more: a quorum at threshold could then assert arbitrary state and every proof would
  verify. With the credential in every leaf a compromised quorum can omit, reorder or replay, but
  cannot invent a value for a key.
- No API MUST allow constructing a live row without a credential. The wrong thing is unsayable
  rather than discouraged.

### Everything is one transaction {#atomic-write}

- Appending an entry, updating the live view, updating both accumulators, and updating the root
  MUST all occur inside one durable transaction, or the store is left at the previous entry
  boundary.
- If the settled invariant `A_state and root are unchanged by anything not a mutation` fires,
  it is a bug of ours, not a peer's — it MUST NOT be catchable as a routine error.

---

## L2 — Ops

### One write vocabulary {#one-write-vocabulary}

- There are two mutations: `set(store, name, value)` and `del(store, name)`. Nothing else.
- No compound operations, no read-modify-write opcodes. A transaction is an ordered log of steps,
  each step a mutation carrying its own guards, evaluated in sequence exactly as if applied
  directly to the store.

### Steps and guards {#step-carries-guards}

- A step MUST bundle its own guards with its mutation. Guards are evaluated immediately before the
  mutation is applied, over the layered state that includes prior steps in the same transaction.
- Hoisting guards to the transaction level yields a second evaluation model that can disagree with
  the store's — which is how *set A, then act on what A now is* becomes inexpressible.

### Last write wins within a transaction {#last-write-wins}

- Within a transaction, the last write to a key wins. A transaction is not a set of writes; it is a
  log of them.

### Predicates quote, never recompute {#predicates}

- A guard MUST reference the exact bytes it demands, not a value the node computes. A predicate
  quotes a ciphertext digest rather than the plaintext it expects — this is what lets a node
  arbitrate a write without holding a key.
- Predicate primitives at v1 are exactly `absent(store, name)` and `holds(store, name, digest)`.
  Adding another primitive is a design change, not a helper.

### Content addressing {#content-address}

- The identity of a settled transaction MUST be the hash of the exact bytes as received —
  `op_hash = H(raw)`. Re-encoding a decoded transaction and hashing that is a different value and
  MUST NOT be substituted.
- Duplicate suppression across the log MUST use `op_hash` — one submission, one appearance, no
  matter how many peers relayed it.

### Positions are not authored {#position-is-not-authored}

- The author signs the transaction's content — store, timestamp, predicates, mutations. The
  author does NOT sign its position: a settled index does not exist until the batch settles.
- Chain pointers and settled indices are attached by settlement and live alongside the entry, never
  inside its signature.

### Transactions are signed atomic units {#tx-atomic}

- A transaction MUST be signed as a whole by one author key. All steps land or none do.
- Composition MUST be at the transaction level (concatenating step lists and re-signing), not by
  chaining separately-signed transactions.

### Authority is the coarse ACL {#coarse-acl}

- Write authority is per store, not per key. A grant names a set of stores.
- A predicate carries its own store, so a transaction MAY read one store while writing another.
- The store id is cleartext in every operation, so a node can check `author may write store`
  without ever seeing a key.

### Roster and grants are settled state {#authority-is-log-state}

- The set of authorised nodes, the set of authorised writers, and every grant MUST be entries in
  the management store (#presence-is-membership). They MUST NOT be configuration.
- A roster change MUST be one transaction {#roster-change-is-atomic} — adding a node, granting it
  the node role, and updating the manager-signed roster commitment atomically. A partial change (a
  node in the roster with no grant, or vice versa) is not a state the API can reach.
- Membership MUST be a single manager-signed commitment matching the individual node rows. A
  subset that "looks like" a roster MUST NOT verify.
- A roster serial MUST be monotone; the commitment carries it, and a lower serial MUST NOT overwrite
  a higher one.

### Presence is membership {#presence-is-membership}

- A node's authorisation is its **presence** as a live row in the management store. Absence is
  revocation (#absence-is-revocation).
- A separate "active" flag or membership list MUST NOT exist. Two representations of membership
  disagree by construction.

### Absence is the revocation {#absence-is-revocation}

- Revocation of a grant is deletion of its row. It MUST NOT be a separate flag or state.
- A revoked grant is un-provable by construction; the state root's non-inclusion proof over the
  grant path is the client's evidence.
- Revocation is forward-only: transactions the revoked identity has already authored remain valid,
  because validity is relative to the position at which they were authorised.

### Keys generate where they live {#possession-proof}

- A key MUST be generated on the machine that will use it. A private key never travels.
- An identity's grant MUST carry a proof-of-possession — a signature by the new key over its own
  authorisation payload — so the manager (or delegate) signs an identity that has actually been
  instantiated.

---

## L3 — Mempool {#mempool}

The mempool is the currently-collecting window. At most one exists at any moment: it accumulates
admissible transactions until its window closes, then hands its contents to a Round (L4) and is
replaced by a fresh empty mempool. It has one door, one predicate, no re-entry path, no eviction
timer — those concerns disappear because the window's close IS the eviction and rejects re-enter
via the same one door as any other submission.

### One door, one predicate {#one-admission-predicate}

- The mempool MUST have exactly one admission entry point, applying exactly one predicate. Client
  submissions, gossip forwards, and rejects returning from a settled Round all pass through the
  same door with the same check.
- The predicate MUST include:
  - the admission window (the transaction's timestamp is inside `w_admit` of now);
  - signature validity;
  - **whether the transaction would apply against currently settled state**.
- A transaction that cannot apply now would not have landed even if a Round chose it; admitting it
  costs the client the only thing it wanted — an answer.

### Refusal names its reason {#admission-refusal-typed}

- An admission refusal MUST distinguish a clock fault from an invalid transaction. A client can
  self-correct only if it is told which.

### Duplicates never enter {#dedup-content-address}

- A transaction already in the log MUST NOT enter the mempool. The content address is unique, so
  it cannot land again — this is a property of the door, not something a later stage catches.

### Rejects return through the same door {#rejects-through-same-door}

- A transaction that a settled Round could not apply (a guard was falsified by a bucket-mate that
  landed first, its author lost authority, its predicate refers to state that has changed) MUST be
  handed back to the current mempool as an ordinary admission attempt.
- There is no separate "re-entry" path, no reject flag, no second-chance logic. If the current
  predicate admits it, it collects again; if not, it is dropped. The Round just found out first
  that a re-admission would fail.

### One evaluator {#one-evaluator}

- The evaluator called by admission, by a Round when it constructs a candidate slice, and by
  settlement when it applies a ratified block, MUST be the same evaluator called on the same
  layered state. Three implementations that agree today is not agreement.

### The mempool's lifecycle is the round window {#mempool-window}

- A mempool MUST NOT be retained past its window's close. Its close IS its eviction.
- The transition — closed mempool → Round, fresh empty mempool for the next window — is atomic
  from the perspective of admission: no transaction is admitted "between" mempools.
- A `Mempool.evict` operation MUST NOT exist. Nothing to evict from — the window closes, the
  mempool is now a Round's input.

---

## L4 — Consensus {#settlement}

### The quorum rule {#quorum-gate}

- Consensus decisions MUST be settled against one quorum rule, computed by one module. Two callers
  computing quorum arithmetic independently is how their answers come to disagree.
- The default rule is two-thirds: `size(n) = ceil(2n/3)`, `tolerates(n) = n - size(n)`, and
  `corroboration(n) = tolerates(n) + 1 = f + 1`.
- The distinction between a quorum (how many must AGREE for consensus) and `f+1` (how many must
  ANSWER before one of them is honest) matters and diverges in both directions. Small clusters
  where the two coincide MUST NOT be a licence to conflate them in code.

### Round buckets {#buckets}

- A round is bounded by a discrete time bucket of width δ: `bucket(t) = floor(t / δ)`. Two nodes
  derive the same bucket for the same instant with zero coordination.
- A transaction is admitted to bucket W by a node if its own timestamp falls inside W's admission
  window (see #timing).
- Bucket width δ MUST satisfy the floor at #timing.

### A Round is a closed mempool being finalized {#round-lifecycle}

- A Round has three states and no others:

  ```
  collect       admit transactions with timestamps inside W's window (this IS the mempool
                for W; see L3)
  finalize      close, then converge on the ratified slice for W (largest intersection over
                a quorum, tie-broken by keyed sort, meta-agreed) and hand the block to
                settlement; hand any surviving-but-not-included transactions back to the
                current collecting mempool
  gone          discard
  ```

- A Round MUST NOT persist past `gone`. Its ratified block lives in the log; nothing else about
  the Round survives.
- Multiple Rounds in `finalize` MAY coexist (pipelining). Exactly one Round is in `collect` at
  any moment — that is L3's mempool.

### Rounds pipeline {#pipelining}

- A Round in `finalize` MUST NOT block the next `collect` window from opening. A slow round does
  not stop admission.
- Blocks settle in bucket order. If Round(W+1) reaches ratification before Round(W), its block
  waits — position assignment is monotone, and admission depends on currently-settled state,
  which requires deterministic block order.

### Exclusion is by selection during slice construction {#exclusion-by-selection}

- Mutually exclusive transactions MAY both be admitted to a Round's `collect` phase. Exclusion
  MUST be resolved in `finalize` — candidates are evaluated in order over a layer that absorbs
  each survivor, so the slice carries at most one of them. The loser returns to the current
  collecting mempool through the one door (#rejects-through-same-door).

### Endorsers refuse a stale slice {#endorser-refuses-stale}

- In the meta-agreement round, a node MUST refuse to sign a slice that contains a transaction it
  holds and considers past `w_valid`. Silence is the refusal; a quorum of honest nodes then
  cannot form around it.
- The eviction horizon MUST EQUAL `w_valid`, derived rather than set: a transaction is
  unendorsable once `|now − ts| > w_valid`, and any surplus is a window in which a stale
  compare-and-swap can be re-proposed.

### Blocks are the unit of consensus {#block-is-unit}

- A block is what a round decides: an ordered list of transactions plus the metadata the round
  attaches (bucket id, height, prev-block reference, the quorum signature). Individual transactions
  are not settled one at a time.
- A block's identity is its content — bucket, height, ordered ops, prev-block — hashed as bencoded
  bytes. The quorum signature is over that identity.

### Gossip is by hash, never body {#gossip-by-hash}

- Nodes MUST advertise the transactions they hold by content address (`op_hash`), never by body.
  A body is fetched on demand only when a peer needs a transaction it does not yet hold.
- The bandwidth of the round is therefore bounded by the count of candidates, not their size.

### No designated leader {#no-leader}

- No single node's proposal is authoritative for a round. There is no leader, no rotation, no
  VRF-selected proposer, no "primary". The block is what a quorum converged on, not what one
  identity said.
- Any design choice that promotes one node's view of a round above the others' MUST be rejected —
  it re-introduces the very failure mode the emergent-agreement design exists to prevent.

### The slice is the largest intersection over a quorum {#slice-is-intersection}

- The block for a bucket MUST be a set of transactions all held by at least a quorum of nodes at
  the moment the bucket closes.
- The chosen set is the **largest** such intersection: a proper superset is preferred to any of its
  subsets, so no transaction that could have been included is silently dropped.
- The intersection is not decided by one node. Every node advertises the candidates it holds (see
  #gossip-by-hash); the largest set held by a quorum emerges from that gossip, and every honest
  node arrives at the same answer given the same evidence.

### Ties broken by keyed sort {#slice-tie-break}

- When more than one candidate set equally satisfies #slice-is-intersection, the block MUST be
  chosen by a **deterministic randomised sort** of the candidate sets: sort each candidate's
  identity by `H(bucket_id ‖ candidate_hash)`, take the first.
- Keying by the bucket makes the sort unpredictable across buckets (an adversary cannot pre-mine
  transactions to win the tie in every future round) and deterministic within a bucket (every
  honest node agrees on the winner given the same candidate set).

### Meta-agreement chooses one slice {#slice-meta-agreement}

- Two different candidate slices may equally satisfy #slice-is-intersection when nodes disagree at
  the edges of what they hold. A further round of gossip MUST establish that a quorum has settled
  on ONE specific slice for the bucket — that "this is the slice everyone chose".
- Meta-agreement produces the quorum signature over the block's identity, and that signature is
  what makes the block ratified. A slice that satisfies #slice-is-intersection but never carries
  a quorum signature is not a block.

### Evidence outlives ratification {#evidence-outlives-ratification}

- A peer whose signatures over two different slices for the same bucket both verify HAS
  equivocated (#cross-attestation), and this is proof against their key. The evidence MUST be
  detected and preserved for the observability layer to act on, **regardless of whether the
  receiving node has already ratified**.
- A byzantine peer's contradiction is evidence that outlives any one round; discarding it because
  the local recipient has moved past it throws away the record. Round MUST verify the peer's
  signature and check for equivocation BEFORE any state-based short-circuit — a `GONE` state
  short-circuits state updates, not evidence extraction.

### Ratification counts distinct signers {#ratification-counts}

- A block is ratified when signatures from a quorum of the roster verify over its identity.
- The signer set MUST be distinct by construction: a bitmap indexed by roster position, so "three
  signatures from one member" is not expressible rather than merely rejected.
- The threshold MUST be derived from the roster at the point of ratification, not passed in — no
  caller can forget it and no two callers can disagree about it.
- Ratification MUST verify every named signature. Verifying the bitmap width without verifying the
  signatures reports success on a claim nobody signed.

### Roster is read at the ratification point {#roster-at-ratification}

- A block is ratified against the roster the log had reached when the block was authored, not
  against a roster hoisted from the current state or the current head.
- A replay from a lower height reads the roster as it evolved through the replay — anything else
  checks a block against a roster the log did not yet know.

### Positions are assigned by settlement {#position-assigned-by-settlement}

- A settled index is assigned by the settlement of a ratified block, in the block's order. Authors
  do not choose positions.
- Chain pointers, checkpoint references and index-bearing metadata are attached by settlement and
  live alongside the entry, never inside the transaction's signature.

### Deterministic application {#deterministic-application}

- All nodes MUST apply a ratified block byte-identically: same evaluator, same input, same order.
  Divergence at this step means one implementation is wrong.
- Application MUST run inside one durable transaction (#atomic-write). A crash mid-block leaves the
  store at the previous block boundary.

### Signatures are always verified {#always-verify-signatures}

- Every signature that could be checked at any point in the pipeline MUST be checked. A signature
  is self-contained and always checkable; there is never an excuse to defer it.
- This applies equally to transactions authored by clients, to ratified blocks, and to any
  attestation carried by a peer.

### Replay does not re-adjudicate {#replay-does-not-readjudicate}

- Applying a settled block **at its recorded index**, from another node's log, MUST NOT
  re-evaluate its predicates. The state a predicate referenced may have been superseded, so
  re-evaluation would fail every retained entry and produce nothing.
- Predicate evaluation belongs to settlement and happens once. A replayer's check is signatures and
  the accumulators, not a re-decision.

### Failure domains {#failure-domains}

- Errors MUST be typed into two disjoint trees:
  - `DudeError` — routine, expected, their fault. Caught at the crash-only boundary.
  - `InvariantError` — a violated postcondition, our fault. **Not** a `DudeError`, so no `except
    DudeError` anywhere can swallow it.
- Routine outcomes MUST be returned, not raised. A settlement that finds nothing to do returns
  nothing to do; a duplicate returns a Dropped reason; a bad signature in a run returns the reason
  in words a log line can carry. Raising a routine outcome from a frame handler is one peer's
  ordinary message taking a node's process down.

### Attribution {#position-attribution}

- The bitmap of signers in a ratified block MUST NOT be used as evidence of who did what.
  `op_hash` covers the block's content and not the signature set, because that set is an artefact
  of which shares happened to arrive first. Eleven signatures are not more true than eight.

---

## Tentative — under construction

This section is a first pass at L5 (settlement) and L6 (sync, no-compaction path). It is here
to be argued with, not to be built against yet. Requirements below use MUST/MUST NOT the same
way the settled sections do, but no enforcement row exists until the shape survives review. The
compaction path (compactor role, log truncation, fast sync, light-client sync via SMT proofs) is
explicitly deferred — that discussion belongs after this line is rock-solid.

## L5 — Settlement (tentative) {#settlement-layer}

Settlement is the layer between "the quorum agreed on which slice" (L4) and "the log has advanced,
every node's state matches, the head is committed". Round produces a RATIFIED slice; settlement
turns that into a SETTLED block.

### Ratified is not settled {#ratified-is-not-settled}

- A slice is RATIFIED when Round's meta-agreement has produced a quorum of signatures over the
  slice's identity (#slice-meta-agreement). Ratification says only that the quorum picked this
  slice.
- A block is SETTLED when a quorum of signatures over the slice's identity **AND the resulting
  post-apply state anchors** has converged. Only SETTLED blocks advance the head.
- The two are distinct events with distinct signatures. A slice can be RATIFIED and never SETTLE
  (see #settlement-may-hang).

### Deterministic application, transaction by transaction {#deterministic-application-per-tx}

- On ratification, every honest node applies the slice's transactions to its own Store in the
  slice's canonical order. Application uses the one evaluator (#one-evaluator).
- A transaction MUST be atomic: all its steps land or none do (#tx-atomic). A step whose guard
  fails causes the whole transaction to fall through — not a partial write.
- A transaction that falls through in one honest node's application MUST fall through in every
  honest node's application: same starting state, same slice, same evaluator, same order.

### Non-applying transactions re-enter the current mempool {#fall-through-through-the-door}

- A transaction from a ratified slice that could not apply MUST be handed to the currently
  collecting mempool as an ordinary admission attempt (#rejects-through-same-door). The mempool
  decides whether the tx is now inadmissible (its author lost authority, its predicate quotes
  state that has moved) or still admissible for a future bucket.
- There is no separate re-entry path, no reject flag, no "settlement queue". If the current
  predicate admits it, it collects again; if not, it is dropped.

### Settlement signs the post-apply anchors {#settlement-signs-post-anchors}

- After applying, a node MUST compute the resulting `state_root`, `A_state`, `A_log`, and `head`
  index, and sign a message binding those to the slice's identity: `sig over (slice_hash, height,
  state_root, A_state, A_log)`.
- The sign happens **after** the durable transaction (#atomic-write) that applied the slice. A
  node MUST NOT sign anchors it has not committed.
- A node that could not apply the slice — because it did not hold every body, or its Store
  refused a transaction the honest evaluator accepted, or its own state was too far behind — MUST
  NOT sign. Silence is the refusal.

### Settlement converges by quorum agreement on the anchors {#settlement-quorum-on-anchors}

- Nodes exchange settlement signatures. A block is SETTLED when a quorum of settlement signatures
  over the same anchors converges — same evaluator on the same inputs producing the same outcome
  is what makes convergence possible without a coordinator.
- The settlement signature set MUST be distinct by construction (bitmap indexed by roster
  position), for the same reason ratification counts distinct signers (#ratification-counts).
- Two nodes producing different anchors from the same slice is a divergence, not a signature
  disagreement about a value judgement. It reveals that one implementation is wrong — the
  evaluator, the accumulator update, the SMT insert, one of them. Divergence at this step is a
  bug of ours.

### Settlement does not reach through the mempool {#settlement-does-not-cross-mempool}

- Settlement MUST NOT hold a reference to the currently-collecting mempool, inspect it, or bypass
  its admission predicate. Fall-through re-entry (#fall-through-through-the-door) is the sole
  crossing, and it is a call through the same one door every other submission uses.
- The mempool MUST NOT know that a caller was Settlement rather than a client or a peer. If it
  did, its predicate would grow a special case, and the "one door, one predicate" invariant
  (#one-admission-predicate) would be a lie by construction.
- Bodies for the ratified slice MUST come from the FROZEN mempool the Round was seeded with, not
  from the currently-collecting one. A body admitted after the bucket boundary belongs to the
  next bucket; using it to satisfy a lookup for the previous bucket would let a slice's contents
  drift under settlement's feet.

### Settlement may hang; not solved here {#settlement-may-hang}

- A slice MAY be RATIFIED and never SETTLE: fewer than a quorum can produce matching post-apply
  signatures (partial holdings on the ⊆-local edge cases, one node down at the wrong moment, a
  transient partition during the exchange). The block stays in the RATIFIED-but-not-SETTLED state
  indefinitely and the head does not advance.
- This is a known gap in the tentative spec. A resolution mechanism is planned but deliberately
  not written here — get the settle-when-it-does-settle path rock-solid first, then close the
  hang case surgically.

### The block is the SETTLED thing {#block-shape-settled}

- A SETTLED block's identity is `(bucket, height, slice_hash, prev_block_hash, state_root,
  A_state, A_log, settle_sigs)`. The `settle_sigs` are a quorum-bounded distinct-signer bitmap
  over `(slice_hash, height, anchors)`.
- Ratify signatures are **not persisted**. They are Round's transient consensus infrastructure —
  the record of *how the quorum came to agree on this slice*, not the record *that they did*.
  What proves the block to a replayer is the settle_sigs alone: a quorum agreed on the outcome,
  and `slice_hash` inside that payload pins which slice they were agreeing about.
- Individual transactions are not settled one at a time. The block is the unit.

## L6 — Sync (tentative, no-compaction only) {#sync-layer-no-compaction}

The path a joining or lagging node walks to become current, in the world where nothing has been
compacted and every node still holds every block from genesis. Fast sync, light-client sync via
SMT proofs, and any compaction-aware sync path are deferred (see #compaction-deferred).

### A joiner starts from the anchor alone {#joiner-starts-from-anchor}

- A joining node arrives holding the manager pubkey (out-of-band anchor) and seed addresses for
  peers. Nothing else — not the current roster, not the current head, not any block.
- Every fact about the cluster the joiner comes to believe MUST be reached from the anchor by
  verified replay. The roster it eventually uses to check the current tip is derived from the log
  it has walked, not fetched separately and trusted.

### No trusted frontier {#no-trusted-frontier}

- A joiner MUST NOT trust a "current head" statement from any peer: it does not yet hold the
  roster that would verify the settlement signatures on that head.
- A lagging node with a stale roster MUST NOT trust a claimed head signed by a roster it cannot
  yet verify. It walks forward to the point where it CAN verify, then verifies.
- Therefore sync is block-by-block from where the joiner is (genesis for a fresh joiner, its last
  SETTLED height for a lagger) to the true head — not a fetch of the head followed by a walk back
  to fill in.

### Sync is log replay {#sync-is-log-replay}

- The sync verb (name pending; not `FRONTIER`) MUST be: "give me the next SETTLED block after
  height X". A block-by-block pull, in order, from the joiner's current height.
- The joiner MUST replay each block through the one evaluator, verify both signature sets against
  the roster in effect at that block's height (#roster-at-ratification), update its own Store,
  and only then advance to X+1.
- Nothing about the walk uses the SMT for correctness. The SMT belongs to a different question
  (light-client proofs — see #smt-for-light-clients).

### The roster walks forward with the log {#roster-walks-forward}

- The roster the joiner uses to verify block N+1's signatures is the roster its Store holds
  after applying blocks 0..N. Roster changes are log-state (#authority-is-log-state), so this
  falls out of #roster-at-ratification without any special mechanism.
- A joiner that hits a roster change block MUST apply the change atomically with the block
  (#roster-change-is-atomic), so the next block is checked against the post-change roster.

### The SMT is not part of sync {#smt-for-light-clients}

- The compressed sparse Merkle tree (#state-root) exists so a light client can be shown a
  membership or non-membership proof for a single key without holding any log. It is not a
  primitive of full-node sync.
- Full-node sync recomputes the SMT locally by folding the log; a joiner never trusts an
  SMT root from a peer as a sync shortcut. That shortcut is exactly the fast-sync path, and
  fast sync is deferred.

### Test shape {#sync-test-shape}

- A three-node cluster runs long enough to produce many SETTLED blocks including at least one
  roster change (adding an authorised writer, granting a new node's role).
- A fourth node is instantiated holding only the manager pubkey and seed addresses. It syncs
  block-by-block through the sync verb, verifies each, catches up to the current SETTLED head,
  then participates in the next Round as a quorum-eligible node.
- Divergence at any step (a block whose signatures fail, whose replay produces different
  anchors, whose slice contains a transaction the joiner cannot resolve) MUST fail loudly, not
  proceed with a warning.

### Compaction is deferred {#compaction-deferred}

- The compactor role (a distinct key with its own authorisation to propose truncation),
  entry discard below a ratified checkpoint (SPEC L1's OWED row), and any sync path shaped for
  a compacted log are deliberately out of scope for the tentative L6.
- The no-compaction path MUST work correctly and be exhaustively tested before compaction is
  introduced. Once it does, compaction becomes a surgical addition — a compactor-signed
  checkpoint that renders older blocks discardable, and a fast-sync path that adopts state at a
  ratified checkpoint rather than replaying from genesis.

---

## Trust (cross-cutting)

Applies at L1–L4 alike and at everything above.

### Storage nodes are untrusted {#nodes-are-untrusted}

- Storage nodes hold no keys and no trusted component. They arbitrate the log; they do not vouch
  for its contents.
- A node's own statement about itself is a hint, never a floor. Signed self-reports are
  DIAGNOSTIC — they let peers detect a rollback if the node ever contradicts an earlier statement,
  and are not a source of currency (#monotonicity).

### Authenticity is self-verifying, currency is not {#the-lemma}

- A signature proves who authored a payload. It does not prove *when*.
- A malicious node can serve a perfectly authentic, perfectly stale world, correctly signed
  throughout. Distinguishing that from the current world requires the count of independent fresh
  witnesses; no signature or hash can substitute.

### Freshness needs `f+1` witnesses {#freshness-needs-many}

- Currency MUST be established by `f+1` distinct fresh statements — the smallest set of which at
  least one must be honest.
- A quorum is not the right threshold here: at n=3 two-thirds tolerates zero faults, so one honest
  fresh answer is already `f+1` while a quorum is two. `f+1` is decided by the quorum module and
  computed nowhere else (#quorum-gate).

### Freshness is gathered, never proved {#freshness-is-gathered}

- Every attestation carries the author's own clock. It is an assertion, not a ratified fact — no
  peer can recompute another's clock.
- Recent-looking attestations from `f+1` distinct keys inside a bounded window are the only
  currency evidence available. An adversary holding fewer than `f+1` keys cannot manufacture recent
  ones; it can replay, and a replay looks old.

### Monotonicity is a duty {#monotonicity}

- A node MUST NOT sign a claim about a lower height after having signed a claim about a higher one.
  A durable monotone counter is bumped and committed *before* the claim is signed, so signing over
  uncommitted state is not expressible.
- The counter is separate from the height. Ordering claims by the quantity under dispute is
  circular: if the counter *were* the height, a regression would be unorderable and therefore
  unconvictable.
- Gaps in the counter are free; reuse is fatal.

### Peers keep the evidence {#cross-attestation}

- Attestations MUST be gossiped, and receiving peers MUST retain the latest one per author.
- A pair of signed statements from one key that contradict each other is EVIDENCE — self-contained,
  needing no third party, valid forever.
- Contradiction MUST be self-contradiction only. Clock skew MUST NOT be convictable — an NTP step
  backwards is a road bump, not a fault.
- A shun is a LOCAL read policy against a convicted key. It does not alter the roster and does not
  alter quorum arithmetic. Ejection is a manager action on the evidence; there is no rehabilitation
  path, because recovery is re-join as a new identity.

---

## Timing {#timing}

Applies at L3 and L4.

- Every timing value MUST be expressed against a declared quantity. A literal timing figure MUST
  NOT appear anywhere outside a tunable group's field default.
- The declared quantities are exactly: `RTT_MAX` and `CLOCK_SKEW` (deployment measurements),
  `CLIENT_CLOCK_TOLERANCE` (a policy whose cost is the replay window), and the protocol counts
  `HOPS_TO_QUORUM` and `WAVES_TO_SETTLE`. Adding to this set MUST be a decision, not a default.
- Each dial MUST sit at or above the floor derived from those quantities.
- The round bucket width MUST be at least dissemination to a quorum: `HOPS_TO_QUORUM·RTT_MAX + CLOCK_SKEW`.
- The admission window MUST be at least `CLIENT_CLOCK_TOLERANCE + 2·RTT_MAX`, and it is the
  **replay bound**: generosity here is paid in replay window, not latency.
- The endorsement margin MUST be at least `WAVES_TO_SETTLE·δ + CLOCK_SKEW`, so a transaction
  admitted at the edge of the window survives the round it was admitted for.
- The freshness window MUST exceed the probe interval that feeds it, with room for a missed probe.
- Nothing MUST be retained past the point it can settle. `w_valid` is derived (see
  #evict-at-w-valid), never set.
- A check MUST NOT re-implement what it checks. A second model of one rule can disagree with the
  first, and the copy that is wrong is the one nobody runs.
- A dial MUST have exactly one home: the group belonging to the object that decides with it. Two
  groups with the same dial disagree by construction.
- Dials MUST be reachable from one composed surface. A timing constant in module scope MUST NOT
  exist.

---

## Keys (the primitives; who does what is L5)

### Two secrets, never one {#two-secrets}

- A permanent **name key** derives name tokens and never rotates.
- A rotating **value key** derives item keys per epoch. Rotating one MUST NOT re-derive the other,
  or rotation becomes an O(state) re-encryption.

### Per-item keys {#per-item-key}

- `item_key = f(value_key, name_token)`. No two items share a key.

### Random nonce, no cardinality leak {#random-nonce}

- The AEAD MUST use a random nonce and MUST be misuse-resistant. A deterministic nonce would make a
  key's value cardinality observable, and a predicate quotes a ciphertext digest rather than
  recomputing one, so determinism buys nothing.

### Wrapped masters {#wrapped-masters}

- One sealed copy of the epoch master per authorised holder, distributed atomically: every holder
  gains it together or none does, so no client is left holding data it cannot read.
- Retention is refcounted over live values — a value carries its epoch, so the count is a function
  of live state and survives truncation. No history, no policy.
- An epoch key MUST NOT be retired while any live value references it. Zero is the only condition
  under which retirement is safe.

### Value carries its epoch {#value-carries-epoch}

- Every stored value MUST carry the id of the keyepoch under which it is encrypted, in cleartext
  next to the value. Nodes that cannot decrypt still need to count.

---

---

## Transport (cross-cutting)

The wire that carries every layer's messages. Sans-I/O below, so the whole protocol can be
exercised with no sockets — failure, partition, timeout and retry become values a test constructs
rather than an environment it has to arrange.

### Transport adds no trust {#transport-adds-no-trust}

- A message is point-to-point even when the carrier is broadcast. Transports move bytes or raise;
  no retries, no timeouts, no opinions. A hidden retry is a transmission the link layer cannot
  count.

### The screen tag {#screen-tag}

- Every sealed frame carries `HMAC(destination identity, sealed bytes)` as an addressing hint.
  Keyed on identity alone it would be a constant, i.e. a permanent per-node fingerprint; including
  the sealed bytes prevents that.
- A hint, never authentication. A matching tag proves nothing about who sent the frame or what they
  may ask for. Acting on a mismatch is cheap and refusing costs an attacker nothing they lacked.

### Sign then seal {#sign-then-seal}

- The signed envelope MUST be sealed, not the reverse. Sealing after signing means an observer sees
  no identity.
- Signing a ciphertext would leave the sender's key in the clear and leak the social graph.

### A peer is an identity, not a path {#peer-not-path}

- A peer is an identity with several addresses. Identity is the unit of reachability.
- Correlation of a reply MUST be by `(peer, message id)`, never by the link it arrived on. Send on
  A, receive on B is ordinary traffic. The dedup key MUST be `(frm, mid)`, never `mid` alone —
  `mid` is chosen by the sender, so any identity that learns an outstanding id could otherwise
  hijack the answer.
- A request whose answer is only ever solicited MUST be registered as awaiting a reply. An
  unregistered request is answered correctly and its answer discarded at the door, which is silent.

### RTT sampling must be attributable {#rtt-attribution}

- A sample MUST come only from a message transmitted exactly once, on exactly one link. Karn &
  Partridge; multi-homing makes this strictly worse than TCP's case, since a reply arriving on B
  after attempts on A and B says nothing about either.
- Each attempt MUST be restamped and re-signed; a reply MUST echo the stamp it answers, or a
  staggered message is a measurement blind spot.
- Where attribution fails, the reply MUST be reported as unattributable rather than guessed at. A
  wrong sample charges one link for another's latency and the estimator cannot notice. Liveness
  still counts; only the measurement is withheld.
- A timeout MUST be built from variance, not the average: `SRTT + max(G, 4·RTTVAR)`.

### Only the breaker declares a link down {#breaker}

- A timeout is a suspicion; a failure is a decision. Nothing outside the breaker MUST declare a
  link down — a single expiry adjusts state and MUST NOT produce a verdict.
- An expiry MUST be charged to a link only when exactly one attempt was made, for the same reason a
  sample must be attributable.

### Retries are budgeted as a fraction of traffic {#retry-budget}

- Backoff MUST carry jitter. A fixed delay re-synchronises every client that failed together, so a
  recovering peer meets a thundering herd.
- Retries MUST be budgeted as a fraction of traffic, not per request. Per-request limits multiply
  — three layers retrying three times is twenty-seven attempts, each within its own limit.
- The budget MUST sit per peer. Per link would fight multi-homing; global would let one dead peer
  starve retries to healthy ones.
- Multi-homed attempts MUST be staggered rather than failed over serially, and MUST spend from the
  same budget as retries — parallel dialling collapses back to serial exactly when the peer is
  unhealthy, with no separate health check deciding.

### Be strict in what you accept {#be-strict}

- Malformed input MUST be refused loudly, never repaired by guessing. The Robustness Principle is
  the mechanism by which two implementations drift apart while both appear to work.
- Delivery is at-least-once by design, so duplicate suppression is the receiver's job. Execution
  idempotence comes from the content address (#content-address); a response cache buys only answer
  stability and is per-verb policy, which most verbs decline.

---

## Errors

### Routine outcomes are returned, not raised {#no-exceptions-for-control-flow}

- A signature that does not match, a refused admission, a failed guard, an open circuit — all are
  returned values with closed types.
- Closed enums MUST reserve ordinal 0 as `INVALID`, so a Go port's zero value lands on a named
  invalid rather than on a real verdict.
- Every function that can refuse MUST have a total return type over closed types: no `None`
  standing in for either "yes" or "no data".

---

## Enforcement (L0–L4)

**A row with no enforcer is a requirement nothing obliges** — the defect this table exists to make
visible rather than plausible.

### L0 primitives

| requirement | enforced by |
|---|---|
| the codec is canonical, both directions | `codec.encode`, `codec.decode` (round-trip tests) |
| the decoder rejects non-canonical input | `codec.decode`, tested by malformed-input fixtures |
| domain separation is by BLAKE2 personalisation | `crypto.h_domain` |
| the state root is a compressed sparse Merkle tree over live | `smt.Tree` |
| every leaf commits to its path, value, and credential | `smt.leaf_hash` |
| every internal node commits to its depth and prefix | `smt.branch_hash` |
| the root is a function of the live set alone | `smt.py` tests (insert-then-delete, order-independence) |
| `A_state` is `(store, name, value)` and excludes provenance | `store.element` |
| `A_log` is `(index, op_hash)` over retained entries | `store.log_element` |

### L1 storage

| requirement | enforced by |
|---|---|
| the write path is one atomic SQLite transaction | `Store.apply`, `Store.replay` |
| every live row carries a credential | `live.cred NOT NULL` schema, `Held.cred` no default |
| the leaf commits to the credential | `smt.leaf_hash(path, vhash, chash)` |
| management is a cleartext prefixed keyspace | `management.py`, keys typed as `P_NODE + …` |
| entries below the last ratified checkpoint may be discarded | **OWED** (L5 pivot in progress) |
| a settled index is preserved on replay | `Store.replay` applies at recorded indices |

### L2 ops

| requirement | enforced by |
|---|---|
| the vocabulary is exactly `set` / `del` | `ops.py` — no other mutation types export |
| steps carry their own guards | `ops.Step` |
| predicates quote, do not recompute | `ops.Holds` requires a value digest |
| content address is over the bytes as received | `SignedTransaction.op_hash = h(raw)` |
| positions are not authored | signature body excludes any position field |
| authority is store-scoped | `Management.may_write` |
| roster changes are one transaction | `Management.add_node` / `set_roster` return one `Transaction` |
| revocation is deletion of a row | `Management.revoke` returns a `Del` |

### L3 mempool

| requirement | enforced by |
|---|---|
| one door, one predicate | `Mempool.valid` |
| admission consults currently-settled state | `Mempool.valid` via `settle.would_apply` |
| duplicates never enter | `Store._settled_hashes` and `Mempool.valid` |
| one evaluator across admission, slice construction, settlement | `settle.evaluate` called from `Store.apply` and `Mempool.valid` |
| a mempool is not retained past its window's close | **OWED** — the current `Mempool` is a long-lived pool with `evict`/`reenter`, not per-window |
| `Mempool.evict` and `Mempool.reenter` do not exist as separate operations | **OWED** — both exist today; both should collapse into the lifecycle |
| rejects re-enter through the same door | **OWED** — the current `Mempool.reenter` is a distinct path, not the same admission call |

### L4 consensus

| requirement | enforced by |
|---|---|
| quorum arithmetic has one implementation | `dude.quorum` |
| `f+1` is decided by the quorum module | `quorum.corroboration` |
| ratification counts distinct signers | `crypto.bitmap_indices` |
| ratification verifies every named signature | `crypto.Ed25519ListMultiSig.verify` |
| ratification threshold is derived, not passed | `attested` (block variant) derives from the roster it is given |
| deterministic application inside one transaction | `Store.apply` (BEGIN IMMEDIATE / COMMIT) |
| routine outcomes are returned, not raised | return types of `Store.apply`, `Store.replay`, `Mempool.admit` |
| invariants terminate the process | `InvariantError` outside the `DudeError` tree |
| Round has exactly three states (collect / finalize / gone) | `dude.round.Round`, `dude.round.State` |
| Round is sans-I/O and testable in isolation | `dude.round` (no imports of `net`, `store`, or the clock; `dude.tests.test_round` exercises it directly) |
| pipelining: one collect window at a time, many finalize windows | `dude.round.Round` is per-bucket by construction; `dude.tests.test_round.TestPipelining` + `TestRandomisedBuckets` |
| gossip advertises by hash, not body | `dude.round.Held` (frozenset of digests); `dude.net.round_adapter.encode` for the wire encoding |
| no designated leader | **structural** — `dude.round.Round` has no leader field or leader-selection logic; enforced by CI review |
| the slice is the largest intersection over a quorum | `dude.round._compute_slice` (enumerates C(n, q) subsets) |
| ties are broken by keyed sort | `dude.round._compute_slice` — `min(candidates, key=lambda c: _slice_id(bucket, c))` |
| a meta-agreement round chooses one slice | `Round._try_ratify` — quorum of matching `Sig` messages over the same `slice_hash` |
| exclusion is by selection during slice construction | Currently `Mempool.propose` via `settle.would_apply`. Moves onto the ratified `Block` when Round is wired (Phase 6). |
| endorsers refuse a slice containing a past-`w_valid` transaction | Currently `Mempool.endorsable`. Moves into Round's `_finalize` when the mempool feeds Round (Phase 7). |
| an equivocating peer's contradiction is preserved as evidence past GONE | `Round._on_sig` (detects equivocation before dropping on `GONE`); `Round.equivocations()` for the observability layer |
| the running Node uses `Round` for consensus | `dude.coordinator.Coordinator` — `Node.tick` calls `Coordinator.tick`, which opens Rounds at bucket boundaries, drives them, hands ratified Blocks to `Store.apply`, and pushes surviving hashes back to the current Mempool through the same admission door. `Node._propose`/`_on_propose`/`_count`/`_settle` are gone. |
| **block-shaped ratification via `Coordinator._settle`** | `dude.round.Block` is the ratified shape; `Coordinator._settle` looks up bodies from the frozen Mempool and passes them as an ordered tuple to `Store.apply`. Block metadata (bucket, signers, sigs) is not yet persisted -- the log records transactions per-entry, not blocks-as-entries. That is a Phase 7 concern with `store.py`. |

### Transport

| requirement | enforced by |
|---|---|
| transports move bytes or raise; no hidden retry | `net.link.Transport` protocol (one method) |
| screen tag is HMAC(destination, sealed bytes) | `crypto.screen_tag`, `Postman.deliver` |
| sign then seal | `envelope.py`: `SignedEnvelope` then `seal` |
| a peer is an identity, correlation is `(peer, mid)` | `Mailbox.arrived` |
| a solicited-answer request is registered as awaiting | `Mailbox.post(await_reply=True)` (required parameter) |
| RTT sample only from a single-attempt, single-link message | `Mailbox.arrived` returns unattributable otherwise |
| timeouts are built from variance, per-link | `net.link.Peer` (RTO from SRTT + 4·RTTVAR) |
| only the breaker declares a link down | `net.link.Breaker` |
| retries carry jitter | `Plan.backoff` (decorrelated jitter) |
| retries are budgeted per peer | `Peer.budget` (token bucket) |
| multi-homed attempts are staggered, spending the budget | `Plan.next` (staggered dial with token spend) |
| malformed input is refused loudly | typed extractors in `codec` and every `decode` raising rather than repairing |

### Trust / attestation

| requirement | enforced by |
|---|---|
| monotone counter bumped and committed before signing | `Store.attestation` (one transaction) |
| gaps in the counter are free, reuse is fatal | `Store.attestation` bumps unconditionally |
| self-contradiction is the only fault | `attest.contradiction` |
| clock skew is not convictable | `attest.contradiction` ignores `at` |
| shun is local read policy, not roster mutation | `Node.shunned` |
| the counter is separate from the height | `Attestation.seq` and `Attestation.head` are distinct fields |
| a relayed verdict is recomputed, not believed | `Witness.judge` |

---

## Retired tags

Tags kept here rather than deleted, so stale citations resolve to an explanation.

- `#collect-whole-segment` — retired. Segment-scoped compaction is superseded by whole-state
  checkpoints (see L5, in progress). Segment as a physical partition of the log for internal
  storage bookkeeping is unaffected; it is no longer a unit of consensus.
- `#collection-is-a-log-entry` — retired. A checkpoint in the L5 pivot is a block payload ratified
  by L4, not an entry-shaped mutation.
- `#collection-is-ratified` — subsumed by #ratification-counts.
- `#collection-refused-while-live` — retired. Live rows in a range are preserved by the snapshot
  itself; there is no "still holds live values" refusal at the truncation boundary.
- `#collection-is-driven-by-any-node` — retired. Compactor role is designated (see L5).
- `#migration-is-state-invariant` — retired. There is no migration of individual rows in the
  snapshot model.
- `#the-floor-authorises` — subsumed by #log-is-authoritative and the checkpoint model.
- `#bootstrap-anchor` — the anchor requirement stays (manager pubkey + seed addresses supplied out
  of band), but the multi-step bootstrap chain around it is being reshaped at L6.
- `#transfer-is-verified` — moves to L6 in the pivoted design; the requirement (verified against a
  signed root, chunk by chunk) survives.
- `#replication` — retired. Replication was the SPEC.md umbrella for `catch_up` + `bootstrap` +
  transfer verbs. The pivoted design has one sync layer (L6) with fewer primitives; the requirements
  survive there.
- `#conveyor` — retired at L0–L4. The primitives are in Keys (#wrapped-masters,
  #value-carries-epoch). The DUTY (which layer re-encrypts, when) is L5+ and will get a fresh
  anchor when it settles. Do not cite `#conveyor` from new code.

---

## Retired documents

`HANDOFF.md`, `PLAN.md`, `FRAMING.md`, `ACCUMULATOR.md`, `THREAT-MODEL.md`, `LINKS.md`,
`MEMPOOL.md`. Each was a work-in-progress discussion document that accumulated superseded reasoning
without removing it, which reads as authority to anyone finding it. The material that survived is
in this file as requirements; history is in git; working practices are in `CLAUDE.md`; open work is
in GitHub issues. A citation to a section number in any retired file is stale by construction —
cite an anchor.
