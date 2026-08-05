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

### The anchor is the axiom {#anchor-is-the-axiom}

- A store has one **anchor** — the pubkey provisioned at `store.provision(anchor)`. It is the
  root of trust: `may_write` returns True for the anchor against any `store_id`, without
  consulting any grant record. Checking the anchor's authority against a log the anchor itself
  authorises would be circular; treating them as always-may-write is what makes bootstrap a
  manager-signed block rather than a special-cased evaluator bypass.
- The anchor is **immutable per store**. `store.provision()` is one-shot; no operation
  replaces `store.anchor()`. Anchor rotation is deferred — loss of the anchor cold-key
  permanently ends the cluster's emergency-intervention capability, while the ordinary
  consensus path continues to work unimpaired.
- The anchor is the **only** identity that may exercise the block-level override
  (#manager-sig-overrides-quorum). A `Role.MANAGER` grant does NOT confer this power — see
  #role-manager-grant.
- Emergency intervention MUST use the same block construction as bootstrap, via one shared
  code path. There is no separate "emergency intervention" wire shape or evaluator branch:
  same manager-slot bitmap, same settle payload, same follower verification. What differs
  between bootstrap and later interventions is only the state of the store (empty vs.
  populated) at the moment of construction.

### Nodes are the storage layer, not authors {#nodes-are-not-authors}

- The four kinds of participant are: the anchor (root of trust, cold), managers (warm
  delegates, author management ops), clients (author data ops within their scope), and
  storage nodes. Storage nodes are the DATABASE — they arbitrate the log, sign settlement
  as a quorum, and serve reads. They do NOT author transactions on their own key's authority.
- A storage node's identity lives in P_NODE with a #cert; it does NOT get a P_GRANT.
  `may_write` on a bare node identity returns False. To do anything to data, a node's key
  must contribute to a quorum-signed settle or be gated by a manager.
- This is by design (#trust-tiers — storage nodes are untrusted, on cheap VPS). A node
  compromised in isolation cannot mutate data — the quorum multi-sig is what admits writes.
- The `Role` enum is exactly `{MANAGER, CLIENT, COMPACTOR}`. There is no Role.NODE.

### Role.MANAGER is anchor-only {#role-manager-grant}

- `Role.MANAGER` is one of the authoring roles (alongside `CLIENT` and `COMPACTOR`) granted
  via `authorise` (#possession-proof required, same as every grant). A cluster MAY have zero,
  one, or many Role.MANAGER identities at any time.
- Role.MANAGER grants confer **blanket authorship**: `may_write` returns True for any
  `store_id`, and `may_send` returns True for any operation kind. They do NOT confer the
  anchor's block-level override.
- **Only the anchor** grants or revokes Role.MANAGER. Managers cannot grant or revoke other
  managers, and quorum-authorised operations MUST NOT create or destroy a Role.MANAGER grant.
  The reason is #light-client-cert-chain: a light client verifies the chain
  `anchor → manager → CLIENT / node roster entry` using only signatures, without reading the
  log; letting managers create other managers would put a hop in that chain the anchor did
  not directly authorise.
- Similarly Role.COMPACTOR is anchor-only. Compactors act on the whole log; the authority
  to appoint one belongs at the axiom.
- Role.CLIENT is anchor-OR-manager granted. Managers can add and remove clients as ordinary
  operational work.
- Every grant on-log MUST carry a #cert whose signer is authorised for that role
  (anchor-only for MANAGER/COMPACTOR, anchor-or-manager for CLIENT). Rotation is via
  `authorise` / `revoke` (#absence-is-revocation).

### One authorisation cert shape, everywhere {#cert}

- A **Cert** is `(signer, subject, purpose, sig)` where `sig = Sig_signer(_CERT_DOMAIN ||
  purpose || subject)`. `subject` is `bytes`, not a pubkey — the shape covers both
  identity certs (subject is the identity's pubkey) and content-commitment certs (subject
  is `H(content)`; see #roster-commitment-cert).
- Applied on every authority-carrying row:
  - P_GRANT rows: `purpose = role.value` (`"manager"` / `"client"` / `"compactor"`);
    `subject = identity_pubkey`.
  - P_NODE rows: `purpose = "roster"`; `subject = identity_pubkey`.
  - P_ROSTER row: `purpose = "roster_commitment"`; `subject = H(serial ‖ sorted_members)`
    (see #roster-commitment-cert).
- The domain tag and purpose binding together ensure: (1) a cert signed for one purpose
  cannot be replayed as another (an anchor's client-cert for X cannot be stuffed into an
  X-as-MANAGER row); (2) a cert bytes cannot be composed with any other anchor-signed
  artefact.
- Signer-authority rules (checked at read time by Management):
  - MANAGER or COMPACTOR purpose: `cert.signer` MUST be `store.anchor()`.
  - CLIENT, ROSTER, or ROSTER_COMMITMENT purpose: `cert.signer` MUST be either
    `store.anchor()` OR an identity currently holding a valid Role.MANAGER grant.
- Read-side checks on every P_GRANT / P_NODE / P_ROSTER decode: (a) subject matches the
  attested content (row key for identity certs; recomputed `H(content)` for commitment
  certs); (b) `cert.purpose` matches the row's role or the fixed purpose (`"roster"` /
  `"roster_commitment"`); (c) `cert.verify()` (sig-only); (d) `cert.signer` satisfies the
  per-purpose authority rule. Failing any means the row is treated as absent by `may_write`
  / `may_send` / `roster()` / `roster_commitment()`.
- Per-row for identity certs (not batched). Adding, removing, or re-attesting one identity
  touches only that row and its cert; the others are unaffected. The commitment cert is
  the exception — see #roster-commitment-cert.
- No serial number. The row is either present (attestation valid) or absent (revoked). Log
  ratification ordering is the only order that matters; a stale cert cannot be replayed
  because it can only enter the log via a settled tx, and the current log-state is the
  authority (#log-is-authoritative).

### The roster commitment carries its own cert {#roster-commitment-cert}

- The P_ROSTER row content is `[serial, sorted_members, cert]`. `cert.purpose =
  "roster_commitment"`; `cert.subject = crypto.h(codec.encode([serial, sorted_members]))`.
  Signer is anchor or a currently-valid manager (same rule as roster entry certs).
- The commitment cert is what makes the roster **complete** — verifiable outside the
  state-root chain. Individual per-entry P_NODE certs prove **provenance** ("this identity
  was legitimately admitted"); the commitment cert proves **completeness** ("the current
  roster is EXACTLY this set at serial N"). Both are needed; each catches attacks the
  other cannot:
  - A lying bootstrap that ships a subset of the real roster: caught by the commitment
    (subset produces a different `H(serial ‖ members)` than the cert's subject).
  - An eventually-compromised manager who signs a commitment adding a fake member: caught
    by the per-entry cert chain (fake member has no anchor-provenanced entry cert).
- **Re-issued on every roster change** — one manager signature per change, no cascade.
  Adding or removing one node changes `H(serial ‖ members)`, so the commitment cert is
  reminted. Per-entry certs of unaffected nodes stay valid.
- **Light client bootstrap depends on this**: without a commitment cert, a light client
  needs `state_root` to trust the roster, which needs the roster to verify — circular.
  The commitment cert breaks the circle by making the roster anchor-verifiable directly.
- `Cert.subject: bytes` was generalised (from `PublicKey`) precisely to accommodate the
  content-hash subject here — one struct covers both identity and commitment attestation.

### Management operations should be typed, not smuggled {#typed-management-ops-owed}

The current shape emits management writes as generic `ops.Set(P_GRANT + who, ...)` /
`ops.Set(P_NODE + who, ...)`. `Management.authorise` / `change_roster` validate the cert
at construction time before emitting; a well-behaved caller cannot land a malformed grant.
The read side (`may_write`, `roster()`) also refuses invalid rows, so authority forgery
is closed either way.

The gap: a caller who bypasses the API and composes an `ops.Set(P_GRANT + who, garbage)`
directly can land the malformed row in state — a manager has blanket authorship of the
management store. Read-side checks refuse the invalid row (`may_write` returns False),
but a decode error on subsequent management reads is a poison-pill DoS risk. This is
not new attack surface — a manager can DoS the cluster by many routes — but it is a real
shape gap.

The RIGHT fix is not a validator hook at the settle boundary. A validator would
re-implement the exact rules `authorise` already enforces, and two implementations of the
same rules disagree by construction. The honest fix is **typed management operations as
first-class op types** (`ops.Authorise`, `ops.Revoke`, `ops.AddRosterEntry`,
`ops.RemoveRosterEntry`, `ops.DistributeWrappedMaster`) so a malformed grant is
unexpressible at the op vocabulary — DDL as its own verb set, not smuggled through
generic `Set` / `Del`.

Deferred until after the light-client work, at which point the management role gets
re-examined and the typed-op refactor can compose with whatever that reshapes. Anyone
tempted to add an eval-time `check_write` hook in the meantime: read this note first,
because that path was considered and rejected as re-implementation.

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

- Consensus decisions MUST be settled against **one** quorum rule, computed by **one** module
  (`dude.quorum`). Two callers computing quorum arithmetic independently is how their answers
  come to disagree, so every question -- size, tolerates, spare, corroboration, would_brick,
  domain composition -- lives behind a module-level function name and no caller does the
  arithmetic inline. Rule choice is not configurable per node; deployment flexibility lives
  in the roster size `n`, not in the rule.
- The rule IS two-thirds:
  - `size(n) = ceil(2n/3)` -- how many must AGREE
  - `spare(n) = n − size(n)` -- how many may be offline while a quorum remains reachable
  - `intersection(n) = 2·size(n) − n` -- guaranteed overlap between any two quorums
  - `tolerates(n) = max(0, intersection(n) − 1)` -- byzantine faults tolerated
  - `corroboration(n) = tolerates(n) + 1 = f + 1` -- how many fresh witnesses need agree
  - `max_domain(n) = min(spare, tolerates)` -- ADVISORY composition ceiling
  - `would_brick(n) = (n < 3)` -- hard bricking condition (spare=0, any reboot removes quorum)
- The distinction between a quorum (how many must AGREE for consensus) and `f+1` (how many must
  ANSWER before one of them is honest) matters and diverges in both directions. Small clusters
  where the two coincide MUST NOT be a licence to conflate them in code.
- **`max_domain` is advisory, not enforcement.** Rack-awareness that severely interferes with
  routine operation is worse than none. Legitimate improvement moves (diluting a concentrated
  cluster) frequently pass through composition-violating intermediate states, and refusing
  them one-at-a-time turned a growth mechanism into a footgun. The operator inspects
  `check_domains()` and acts; no `dude.quorum` function refuses on composition alone. In
  production, single-domain concentration IS the failure mode that bites (provider outage
  removes quorum) -- reporting it is worth doing, hard refusal is not.

### Roster change refuses a hard brick {#roster-change-refuses-brick}

- `Management.change_roster(add, remove)` MUST refuse if the change would move the cluster
  from a safe state (`n_before >= 3`) into a bricked state (`n_after < 3`). Below n=3 the
  spare is zero, so any single node offline removes quorum -- operationally a brick, not just
  a fragile state.
- The refusal is one-sided: growth INTO or THROUGH a bricked size is allowed (bootstrap starts
  at n=0 and grows). Only SHRINKING a safe cluster into brick is refused. This lets a batched
  bootstrap reach the target n in one atomic step without a would-brick intermediate check
  blocking it, while still preventing an operational mistake from turning a working cluster
  into one that a single reboot brings down.
- Escape hatch: `intervene()` (#anchor-is-the-axiom) authors arbitrary manager-signed
  mutations that bypass this check. Use when a deliberate shrink into a bricked state is
  necessary (e.g., replacing a compromised roster during an incident).
- Refusal happens at AUTHORING (`change_roster` raises `ManagementError` and returns no
  Transaction). Refusal at APPLY would brick the cluster (the transaction sits in the mempool
  and blocks progress); authoring is the correct gate.

### Round buckets {#buckets}

- A round is bounded by a discrete time bucket of width δ: `bucket(t) = floor(t / δ)`. Two nodes
  derive the same bucket for the same instant with zero coordination.
- A transaction is admitted to bucket W by a node if its own timestamp falls inside W's admission
  window (see #timing).
- Bucket width δ MUST satisfy the floor at #timing.

### A Round is a closed mempool being finalized {#round-lifecycle}

- A Round has four states and no others:

  ```
  collect       admit transactions with timestamps inside W's window (this IS the mempool
                for W; see L3)
  finalize      close, then converge on the ratified slice for W (largest intersection over
                a quorum, tie-broken by keyed sort, meta-agreed) and hand the block to
                settlement; hand any surviving-but-not-included transactions back to the
                current collecting mempool
  gone          ratified — discard
  abandoned     `abandon_by` passed without ratification; hand every held tx back to the
                current collecting mempool (#endorser-refuses-stale) — discard
  ```

- A Round MUST NOT persist past `gone` or `abandoned`. A ratified block lives in the log;
  nothing else about the Round survives.
- `abandoned` is one-way and terminal. It exists so a Round that cannot form quorum (partitioned
  minority, silent peers, stale-slice refusal) does not hang indefinitely; the `abandon_by`
  deadline is set by cadence (see #endorser-refuses-stale for the derivation).
- Multiple Rounds in `finalize` MAY coexist (pipelining). Exactly one Round is in `collect` at
  any moment — that is L3's mempool.
- The Round MUST carry its held transactions (bodies, not just hashes) from the moment `collect`
  hands off to `finalize`. Signing implies possession — a node that cannot produce the bodies
  for a slice cannot back that slice at settlement — so the possession invariant is structural
  at the Round's input, not a passing convention.

### The pipeline has three stages, one instance each {#one-of-each-in-flight}

At any moment the cluster's L3/L4/L5 pipeline holds AT MOST three things (#one-of-each-in-flight):

  1. **One Mempool** — the current bucket's admission window (accepting txs).
  2. **One Round** — the previous bucket's slice-agreement in progress.
  3. **One SettleRound** — the bucket before that's anchor-agreement in progress.

Each stage takes one bucket width (`delta`) as its cadence budget. The pipeline advances one
stage per bucket boundary:

  - Mempool(W) closes → its bodies feed a new Round(W).
  - Round(W-1) reached ratification → its Block promotes into a new SettleRound(W-1).
  - SettleRound(W-2) reached SETTLED → commit; or ABANDONED → fall-through
    (#fall-through-through-the-door).

**No queue.** There is never more than one Round in flight and never more than one SettleRound
in flight. If a stage did not complete in its bucket window, it ABANDONS on cadence -- its
tx set re-enters the mempool via the one door. The abandoning stage's slot frees, and the
next bucket's promotion can happen. A queue between stages would let a slow stage build up
work behind it; the abandon-on-cadence discipline is what turns that risk into bounded loss
(one bucket's worth of ratification/settlement work re-attempted, not an unbounded backlog).

**Admission never stops.** The one thing that keeps running regardless of pipeline health is
Mempool admission -- the current bucket's door is always open, txs land in it as normal.
Skipped Rounds (a Round couldn't open because the previous Round's Block is still waiting for
the Settle slot to clear) don't lose the txs -- they collect in the mempool and the eventual
next Round that opens gets them.

### Rounds pipeline {#pipelining}

- A Round in `finalize` MUST NOT block the mempool from admitting for the next bucket. A slow
  round does not stop admission (#one-of-each-in-flight). Round abandonment on cadence is what
  keeps the next Round's opening from waiting indefinitely.
- Blocks settle in bucket order. There is never more than one Round or one SettleRound in
  flight at a time; block position (`block_num`) is assigned at `_start_settling` time from
  the current `store.head_block_num()`, so an abandoned SettleRound does not consume a
  `block_num` -- the next Round's Block re-attempts the same position.

### Exclusion is by selection during slice construction {#exclusion-by-selection}

- Mutually exclusive transactions MAY both be admitted to a Round's `collect` phase. Exclusion
  MUST be resolved in `finalize` — candidates are evaluated in order over a layer that absorbs
  each survivor, so the slice carries at most one of them. The loser returns to the current
  collecting mempool through the one door (#rejects-through-same-door).

### Endorsers refuse a stale slice {#endorser-refuses-stale}

Freshness is enforced at three points that compose, not by a per-tx staleness check inside the
Round:

1. **Admission.** A transaction is refused at the mempool door if `|now − ts| > w_valid`
   (#one-admission-predicate). Nothing stale enters.
2. **Possession.** A Round MUST sign only slices whose bodies it holds (#slice-is-intersection
   restricts the candidate space to `⊆ local`). Combined with (1), every signed slice contains
   only txs the node itself admitted while fresh.
3. **Cadence.** A Round MUST abandon (transition to `abandoned`) if `abandon_by` passes without
   ratification. `abandon_by` MUST be `close_by + w_valid_margin` so an aged-out slice never
   gets signed by an honest node: if quorum was going to form within cadence, admission-time
   freshness would still hold; past cadence, the Round gives up rather than continue trying.
   Held transactions surface via the abandoned Round's `surviving` and re-enter the current
   mempool through the one door, where anything past `w_valid` is refused for free.

Silence is the refusal at every point. A stuck Round abandons rather than hangs, and the
abandonment shape turns a potentially permanent hang into a retry on the next bucket. The
eviction horizon MUST EQUAL `w_valid`, derived rather than set: a transaction is unendorsable
once `|now − ts| > w_valid`, and any surplus is a window in which a stale compare-and-swap can
be re-proposed.

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
  equivocated, and this is proof against their key. The evidence MUST be
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

## The View abstraction {#view-abstraction}

`Store` and `Layer` are the same abstraction: a read surface over live state that can compute
the three roots, be frozen, and be a base for another view stacked on top. Their difference is
storage backend (SQLite vs in-memory dict) and lifecycle (persistent vs transient), not
capability. Over several iterations the two collapse to one type — call it `View` — and
snapshot support falls out of the same abstraction: a snapshot is a frozen View that
serialises to bytes and reconstitutes on the receiver.

The staged L5 preview (apply-locally, sign-anchors, exchange-sigs, commit-on-SETTLED) is what
motivates building this now. It needs a way to compute post-apply anchors WITHOUT committing
to durable Store, and the natural shape is a stackable overlay whose base is guaranteed not to
change while the overlay is alive.

### The View protocol {#view-protocol}

- A View MUST expose: `get(store, name)`, `prefix(store, pre)`, `accumulator()`,
  `state_root()`, `hash_under(prefix, depth)`, `prove(store, name)`, `is_frozen`.
- The persistent Store implements View. Layer implements View. Whether a caller sees the
  concrete type or the protocol is API convenience; the operations are the same.
- Extending Store's read surface is what "unification" means in practice — every Store method
  that produces state-view information moves onto the View protocol; Store keeps only the
  log-side (append, replay, entries, provisioning) and the durability backing for its View.

### A Layer's base must be frozen {#frozen-base-for-layer}

- `Layer(base=X)` MUST refuse construction if `not X.is_frozen`. Enforced at the constructor,
  so the invariant is not something a caller must remember.
- A Layer has two states: OPEN (accepts `apply(mutation, credential)` calls that update its
  delta) and FROZEN (refuses `apply`, may serve as another Layer's base). The transition
  OPEN → FROZEN is via `freeze()` and is one-way.
- `is_frozen` MUST be durable: once True, MUST NOT return to False. There is no thaw.
- The invariant this enforces: nothing beneath an open Layer can change while the Layer is
  alive. Every subtree hash a Layer memoises against its base is valid for the Layer's
  lifetime — no invalidation cascade, no coherence protocol between stacked overlays.

### Store does not mutate during settlement {#store-serial-settle}

- The Coordinator MUST NOT call `Store.apply` while any Layer over that Store is OPEN.
- For a single-threaded Coordinator that settles blocks in bucket order (#pipelining), the
  invariant reduces to a lifecycle discipline: create the Layer, evaluate the slice, sign
  anchors, exchange sigs, commit on SETTLED. The Layer's lifetime does not span another
  `Store.apply`.
- Once the persistent Store gains a real `Store.freeze()` (needed for snapshots, deferred),
  the discipline promotes to a version-handle: an open Layer over Store pins a version, and
  `Store.apply` refuses if any handle is outstanding. The single-threaded coordinator does not
  need this yet; the design leaves room for it.

### The pipelining shape falls out {#pipelining-via-frozen-layers}

- Round(N) ratifies. Coordinator creates `layer_N = Layer(base=store)` OPEN, evaluates slice
  into it, signs `(slice_hash_N, height, layer_N.state_root, layer_N.accumulator, ...)`.
- Round(N+1) ratifies before N SETTLES. Coordinator calls `layer_N.freeze()`, creates
  `layer_N_plus_1 = Layer(base=layer_N)` OPEN, evaluates slice N+1 into it, signs anchors
  computed from the stack.
- When N SETTLES: `store.apply(slice_N)` commits. `layer_N` becomes semantically equivalent
  to base (delta folded down); `layer_N_plus_1` continues to read correctly through it.
- If N abandons rather than SETTLES (SettleRound(N) hit `abandon_by` without quorum,
  #settlement-may-hang), `layer_N`'s delta is discarded; the slice's txs re-enter the mempool
  via fall-through; the next Round's Block re-attempts block position N. `layer_N_plus_1`
  is discarded too (it was stacked on `layer_N`'s frozen state, which never lands).

## L5 — Settlement {#settlement-layer}

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

- After evaluating the slice into a Layer over Store (#view-abstraction, #frozen-base-for-layer),
  a node MUST compute the resulting `state_root`, `A_state`, `A_log`, and `head` index from the
  Layer, and sign a message binding those to the slice's identity: `sig over (slice_hash,
  height, state_root, A_state, A_log)`.
- The sign happens BEFORE the durable Store commit, against the OPEN Layer's projected roots.
  Once a quorum of matching sigs converges (SETTLED), the Coordinator commits the Layer's delta
  to Store in one durable transaction (#atomic-write). Signing over Layer-projected roots is
  safe because the Layer's base is frozen (#frozen-base-for-layer) and the Layer's own delta is
  what the sig commits to.
- A node that could not evaluate the slice — because it did not hold every body, or its
  evaluator refused a transaction the honest ones accepted, or its own state was too far
  behind — MUST NOT sign. Silence is the refusal.

### Settlement converges by quorum agreement on the anchors {#settlement-quorum-on-anchors}

- Nodes exchange settlement signatures. A block is SETTLED when a quorum of settlement signatures
  over the same anchors converges — same evaluator on the same inputs producing the same outcome
  is what makes convergence possible without a coordinator.
- The settlement signature set MUST be distinct by construction (bitmap indexed by roster
  position), for the same reason ratification counts distinct signers (#ratification-counts).
- Divergent anchors are handled per #settlement-peer-divergence-is-evidence and
  #settlement-self-divergence-is-invariant — the WHO computed the disagreeing value distinguishes
  a routine drop from a self-terminating fault.

### A peer's divergent anchors are evidence, not an alarm {#settlement-peer-divergence-is-evidence}

- A peer's SettleSig whose anchors differ from our own locally-computed anchors MUST be dropped
  from quorum counting. It MAY be preserved as evidence (same shape as
  #evidence-outlives-ratification) for the observability layer to act on.
- It MUST NOT raise `InvariantError` and MUST NOT terminate the process. A peer sending
  divergent anchors is operationally indistinguishable from a bug in that peer, malice by that
  peer, or a bug in us — no local decision distinguishes them, and treating any peer input as
  fatal-to-us hands every byzantine node a one-byte cluster-shutdown button.
- If our own anchors are the outlier (honest peers reach quorum among themselves without us),
  we simply do not SETTLE this block. Recovery is L6 sync (deferred) — the settlement path
  does not attempt self-repair.

### Our own state disagreeing with our own signed anchors is `InvariantError` {#settlement-self-divergence-is-invariant}

- After committing to Store on SETTLED, the Coordinator MUST safety-check that
  `store.head`, `store.state_root`, `store.accumulator`, `store.log_accumulator` equal what we
  previously signed in the anchors. A mismatch means our evaluator produced different mutations
  between the preview (Layer projection) and the commit (Store.apply) — non-determinism between
  two runs of the same evaluator over the same base state.
- This MUST raise `InvariantError`. It is our own postcondition being violated, not a claim
  about a peer. Per #failure-domains, `InvariantError` is not a `DudeError` and MUST NOT be
  catchable at any crash-only boundary.

### The Coordinator filters already-settled txs before preview {#already-settled-filtering}

- Round ratifies over mempool hashes and does not consult log state. A ratified slice MAY name
  a transaction that has already landed in the log via an earlier bucket's settlement (the tx
  reached one node's mempool late, was carried forward, appeared in a later Round's holdings).
- The Coordinator MUST filter such txs OUT of the preview batch before computing anchors,
  because `Store.apply` at commit will drop them as duplicates (op_hash UNIQUE, per
  #content-address) and the projected height would then exceed what actually commits. Signing
  anchors nobody can reproduce is exactly the self-divergence
  #settlement-self-divergence-is-invariant catches — filter first, sign anchors the commit will
  match.

### Fall-through re-admission re-broadcasts the body {#fall-through-re-broadcasts}

- A tx re-admitted into the current mempool via #fall-through-through-the-door MUST also be
  re-broadcast to peers (via SUBMIT or its equivalent).
- Local-only re-admit isolates the tx: only this node holds it going forward, and Round's slice
  cannot include a tx a quorum does not hold. Without re-broadcast, a tx that survived one
  bucket's ratification-and-drop cycle on this node stays trapped here forever, cycling through
  every subsequent bucket as ours-alone.
- The re-broadcast rides the ordinary SUBMIT re-flood path — no separate wire vocabulary; the
  mempool cannot distinguish re-admitted-fall-through from client-submitted, per
  #settlement-does-not-cross-mempool.

### Every ratified bucket runs settlement, even empty {#empty-bucket-still-settles}

- A bucket that ratifies an empty slice (no txs collected, or every tx dropped in preview) MUST
  still open a SettleRound and exchange sigs. The settlement quorum's agreement is what makes
  the head advance-preserving invariant checkable — an empty settle_sigs bitmap signed over
  `(slice_hash=∅, height=head, anchors=current)` proves the quorum saw the same state at that
  bucket boundary.
- Empty settlements MUST NOT be optimised out. Cost is one message round per bucket regardless
  of workload; that is the shape the design targets (#durability-over-latency) and skipping it
  breaks the "every bucket has a signed post-anchor commitment" property.

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

### Settlement abandons on cadence {#settlement-may-hang}

- A SettleRound that has not reached a matching-anchor quorum by its `abandon_by` deadline
  MUST transition to ABANDONED. The slice's txs re-enter the mempool via the one door
  (#fall-through-through-the-door); no block commits; `block_num` is not consumed. The next
  Round's Block re-attempts the same block position on the next cycle
  (#one-of-each-in-flight).
- `abandon_by` is one bucket width (`delta`) after the SettleRound starts, so the abandonment
  beat aligns with the pipeline cadence. If the SettleRound was going to succeed, it would
  have by then; if it did not, further waiting only stalls the pipeline.
- The related "one node falls out of the settlement quorum while peers settle without it"
  failure mode is recovered via L6 sync (#sync-is-log-replay). The stragglers pull the
  SETTLED block from a peer that did settle it, chain-verify, and continue -- the local
  SettleRound they had going for that block position is abandoned by cadence and its txs
  re-enter their mempool (mostly duplicates against the just-synced block, refused for free
  via the `_settled_hashes` check).
- Both cases -- cluster-wide hang and one-node-fell-behind -- resolve via the same
  abandon-then-retry-or-sync loop. No new mechanism.

### The block is the SETTLED thing {#block-shape-settled}

- A SETTLED block has two distinct notions of "what belongs to it": its **identity** (fields
  every node computes deterministically) and its **quorum proof** (a set of settlement signatures
  that VARIES per node). Both are transmitted and persisted; only identity participates in the
  chain hash.
  - **Identity** = `(bucket, block_num, height, slice, prev_block_hash, state_root, A_state,
    A_log)`. Deterministic. Two nodes with the same slice + same anchors compute byte-identical
    identity bytes and therefore the same `block_hash = H(identity_bytes)`. This is what a
    successor's `prev_block_hash` names.
  - **Quorum proof** = `(signer_bitmap, settle_sigs)` — a distinct-signer subset over the
    `(slice_hash, anchors)` payload, of size `len(roster) + 1` (positions `0..N-1` for roster
    members, position `N` reserved for the manager override — see
    #manager-sig-overrides-quorum). NOT part of `block_hash`. Which sigs a given node holds at
    SETTLE-moment depends on message-arrival timing (once `_try_settle` sees quorum, later
    matching sigs are dropped), so different nodes commit different sig subsets for the same
    block — every one a valid proof.
- **Why the split is load-bearing.** If `block_hash` covered the sig set, timing-race would
  fork the chain: each node would compute a different `prev_block` for the successor, and no two
  would agree. The design tolerates variable proofs; the chain requires deterministic identity.
  Discovered at Stage 1 of L5-close-out; the SPEC previously conflated the two.
- **Wire form** carries both, so a joiner receives identity (for chain-verify) and proof (for
  quorum-verify against roster-at-height) in one payload. Layout: `[identity_bytes,
  signer_bitmap, settle_sigs]` — identity first so a joiner can peek without decoding the sig
  section.
- Ratify signatures (Round's `signers`/`sigs`) are **not persisted**. They are transient
  consensus infrastructure — the record of *how the quorum came to agree on this slice*, not the
  record *that they did*. What proves the block to a replayer is the settle_sigs alone.
- Individual transactions are not settled one at a time. The block is the unit.

### Empty blocks still increment block_num {#block-num-is-monotone}

- `block_num` is a MONOTONE per-block counter, incrementing by one per SETTLED block regardless
  of whether the block committed any transactions. `height` (log Index of last committed tx) is
  NOT monotone across empty blocks — two consecutive empty ratifications share the same height.
- `block_num` is what `GETBLOCK n` names and what the chain is indexed by. Chain-continuity
  requires empty blocks be numbered distinctly so a successor's `prev_block_hash` walks back to
  a well-defined predecessor even when the log height didn't advance.
- Both `block_num` and `height` are signed as part of anchors — a joiner verifies chain position
  (block_num) and log alignment (height) independently.

### Manager signature overrides quorum {#manager-sig-overrides-quorum}

- A SETTLED block MAY be authorized by either a quorum of roster-member settle_sigs (the
  ordinary path) OR by a single manager signature over the settle payload (the override path).
  Either alone is sufficient. Both use the same `settle_sigs` list on the wire; they differ
  only in which bitmap slot carries the sig.
- **Bitmap layout**: `len(roster) + 1` slots. Positions `0..N-1` are roster members (as
  before); position `N` is reserved for the manager. Bitmap serialization uses the existing
  `crypto.SignerBitmap` mechanism with the +1 size; sig list is parallel to set bits.
- **Verification**: for each set bit, verify the corresponding sig against roster[i] (for
  i < N) or against `store.anchor()` (for i == N). Block is authorized iff EITHER the
  manager bit N is set with a valid sig, OR the count of set roster bits with valid sigs
  is ≥ `quorum.size(len(roster))`.
- **Why the manager is a distinct slot and NOT a roster member**: roster is the operational
  quorum of nodes; manager is a policy override that sits above. Putting the manager in the
  roster would change quorum arithmetic silently every time the roster grew or shrank.
  Reserving position N as a wildcard keeps the two concepts orthogonal.
- **The two primary uses**:
  - **Bootstrap**: block 1 is manager-signed. The manager pre-computes the anchors after
    applying the initial-roster grants, signs those anchors, distributes the block bytes.
    Every node (including fresh joiners arriving later) can verify block 1 with the manager
    pubkey alone -- no roster needed pre-block-1. See `dude.consensus.bootstrap`.
  - **Emergency intervention**: post-bootstrap, the manager can sign a block to unstick a
    hung cluster (settlement-may-hang tail case) or replace a compromised roster. Uses the
    same slot AND the same block construction (#anchor-is-the-axiom mandates one shared
    code path); the follower's verification path is uniform.
- **Security implication**: anchor key compromise = ability to sign fraudulent blocks
  unilaterally. This IS the trust model already (the anchor is the axiom of all authority --
  #anchor-is-the-axiom); this rule makes the implication concrete and wire-visible. There
  is no anchor rotation mechanism (deferred, see #anchor-is-the-axiom), so anchor-key hygiene
  is operationally paramount and cannot be delegated to a rotation cadence.
- **Hybrid blocks**: a block with both a quorum of roster sigs AND the manager sig is
  permitted but not produced by any current path -- either sig set alone authorizes, and
  a producer would not add the redundancy. Follower accepts hybrids on verification via
  the same either-or rule.

### The chain roots at the anchor identity {#genesis-stamp-anchors-the-chain}

- `prev_block_hash` at `block_num == 1` (the first SETTLED block) MUST be
  `H("dude.genesis:" || manager_pubkey.bytes)`. A joiner starting from the out-of-band anchor
  (#joiner-starts-from-anchor) computes the same genesis stamp locally with no network round-trip
  and no trust in any peer's word about "where the chain starts".
- Two clusters started from different manager keys have byte-different genesis stamps by
  construction, so a block from cluster A cannot chain-verify against cluster B's history even
  if block_num happens to align.
- Height is a label; the chain is what enforces order. A joiner verifies `block_N.prev_block_hash
  == block_{N-1}.block_hash` before accepting block N, so a peer serving blocks out of chain
  would fail the check regardless of what block_num it stamped them with.
- `bucket` is NOT the chain. A `bucket → block_num` map is one-to-one for SETTLED blocks, but
  the chain identity is `prev_block_hash`, walked backward one link at a time to the genesis
  stamp.

## L6 — Sync (no-compaction only) {#sync-layer-no-compaction}

The path a joining or lagging node walks to become current, in the world where nothing has been
compacted and every node still holds every block from genesis. Fast sync, light-client sync via
SMT proofs (#light-client), and any compaction-aware sync path (#compaction) are the next
design arcs.

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

- The sync verb is `GETBLOCK n` → `SETTLED_BLOCK` (the bytes-form ratified by
  #block-shape-settled). A block-by-block pull, in order, from the joiner's current height:
  request `n = my_head + 1`, verify, apply, increment, repeat.
- The joiner MUST, for each pulled block:
  (a) verify the chain link — `block.prev_block_hash == prev_block.block_hash` (the sig-
      independent identity hash, #block-shape-settled) against the block already in its Store;
      against the genesis stamp (#genesis-stamp-anchors-the-chain) for `n = 1`;
  (b) verify the settle_sigs against the roster in effect at that block's height
      (#roster-at-ratification), using `f+1` / quorum arithmetic from that roster's size;
  (c) apply the block through the one evaluator (#deterministic-application-per-tx), which
      re-checks per-transaction authority against the pre-apply state (see
      #per-tx-authority-verified-at-replay). A tx whose author was not authorised at that
      state MUST fall through — as it would have done on the producer side.
- Only after all three succeed does the joiner advance to `n+1`. Any failure drops the peer as
  a sync source; the pull is retried from another peer or the walk stalls until one becomes
  available.
- Nothing about the walk uses the SMT for correctness. The SMT belongs to a different question
  (light-client proofs — see #smt-for-light-clients).
- A single request is `GETBLOCK n` for one height. "Latest", "earliest", and "next after N"
  reduce to the same primitive at different N — one request shape keeps the decode narrow.
  Batching, streaming, or range queries MAY be added later; they MUST NOT change the correctness
  argument (each block is verified before the next is accepted).

### Per-tx authority is verified during replay, not trusted from the block {#per-tx-authority-verified-at-replay}

- A SETTLED block records that a quorum agreed on these anchors. It does NOT record who was
  authorised to write which key at that height — the authority table is store-state, not block
  content.
- The joiner MUST re-derive per-tx authority during replay by running the one evaluator against
  the store state produced by applying blocks `0..N-1`. The evaluator's authority check
  (author holds the grant / role / possession-proof required for the target key) is the same
  code path as production. A block that "was ratified" but contains a tx that fails authority
  under honest replay MUST be rejected — not because the block is inauthentic (its sigs verify)
  but because it names an outcome the honest evaluator cannot reproduce.
- This is the safety half of "clients authorised at the time" — the block-level check
  (settle_sigs against roster-at-height) proves the QUORUM was authorised; the tx-level check
  proves each individual OP's author was authorised. Both live in the same replay step; the
  evaluator has always done tx-authority, so this rule is code-existing, just spec-explicit.

### Routine height polling is the trigger {#height-poll-is-the-trigger}

- Every node MUST periodically ask each known peer `HEIGHT` → `HEIGHT_REPLY (n, tip_hash)`, where
  `n` is the peer's current SETTLED head as an integer and `tip_hash = H(SettledBlock.bytes)` at
  height `n`. The poll is solicited (request/reply through the ordinary mailbox correlation),
  not gossiped: no separate broadcast mechanism to design or debug.
- The reply body carries no additional signature — the envelope's own signature
  (#signed-envelopes) already binds this reply to the peer that sent it and to this specific
  request via mailbox correlation. What channel auth cannot prove is that the integer + hash
  reflect the peer's actual current state; only concordant honest witnesses can floor that.
- **Starting a pull requires ONE peer above; declaring caught-up requires `f+1` fresh peers at or
  below AGREEING on `(n, tip_hash)`.** A single peer reporting a higher head is a hint — try
  `GETBLOCK(head+1)` against them; the pull's own verification (#sync-is-log-replay) catches a
  lie. But believing "I am caught up" MUST rest on `f+1` distinct peer replies within a freshness
  window (per #freshness-needs-many), all reporting the same `(n, tip_hash)`. Concordance on the
  tuple, not just the integer, is what makes the claim mean "same chain, same tip" rather than
  "coincidentally same number".
- `f+1` is computed from the roster the joiner currently holds, via the same `quorum.size(n)`
  used everywhere else in the design (#quorum-gate). A fresh joiner who has not yet applied a
  block has no roster and therefore cannot claim caught-up on its very first poll — it pulls,
  applies, and gains a roster from the log, then the ordinary `f+1` rule takes effect.
- A crashed-and-rebooted node, a temporarily-unavailable node, and a fresh joiner all use the
  same trigger. There is no separate "join" flow, no "catch-up" flow, no "recovery" flow —
  they are the same failure ("my head is below the cluster's") observed at different starting
  points and solved by the same pull.

### A same-height mismatched tip is a divergence signal {#poll-detects-divergent-tips}

- If a peer's `HEIGHT_REPLY` names the same `n` as the joiner's own head but a DIFFERENT
  `tip_hash`, the joiner and peer are on different chains at that height — a fork, or one of
  them has been corrupted.
- Fork detection is an **observability signal, not an exclusion decision**. The joiner MUST
  log the divergence loudly enough for humans/tooling to catch, and MUST NOT try to reconcile
  automatically (a real fork is a human problem, silent auto-resolution risks adopting the
  wrong side). The joiner MUST NOT blacklist the peer on this evidence alone — WE may be the
  side that is wrong, and locking in "they're bad" against evidence that could point either
  way is a permanent local misconfiguration waiting to happen (#no-shun-only-priority).
- Fork detection at poll time — before any block pull — is the payoff of carrying `tip_hash`
  in `HEIGHT_REPLY` rather than just `n`. Without it, divergence surfaces only when a
  chain-link check fails during a pull, which is later and with less signal about which peer
  drifted. Either way, sync itself is safe: a peer on the wrong chain serves blocks that fail
  chain-link check on our side, so nothing bad ends up in our Store.
- A same-height matched tip is the affirmative signal: the joiner and peer agree on the chain
  up to `n`. This is what f+1 concordance rests on.

### Height is a hint, never a floor {#height-is-a-hint}

- `HEIGHT_REPLY` is UNSIGNED and MUST NOT be trusted for any signed statement. It drives the
  "am I behind?" decision and nothing else. A peer that lies about its height wastes our pull
  request — we ask for `GETBLOCK(N)`, they refuse or reply with a block that fails chain
  verification, we retry against another peer (#no-shun-only-priority — no exclusion, just a
  cheap round-trip).
- Correctness rests entirely on the block payload's own verification (chain link + settle_sigs
  against roster-at-height). The height poll is a scheduling hint; the block-pull is the truth.

### Sync tolerates misbehaving peers; it does not shun them {#no-shun-only-priority}

- Sync fault-tolerance rests on RETRY, not on ACCUMULATING GRUDGES. A peer that serves a bad
  block, times out on a pull, refuses a GETBLOCK, or reports a divergent tip MUST NOT be
  blacklisted, banned, or permanently deprioritised. Every peer above our head remains a
  candidate for the next pull.
- The follower MAY track a per-peer **priority signal** — most naturally, the timestamp of
  the peer's last valid reply — and prefer peers with more recent success when picking a pull
  source. This is a scheduling preference, not an exclusion decision: a peer with a stale (or
  absent) priority signal is still picked when it is the only source above our head or when
  higher-priority peers are exhausted.
- The rationale: any exclusion path is a path by which a byzantine or transient event can
  cause a node to permanently mis-classify honest peers as bad. Local shun state is state
  that can be wrong forever (a network flap turns into a permanent grudge; a fork-detection
  false-positive locks out the honest majority). Better to pay a bounded per-pull retry cost
  than to carry a hidden misconfiguration across restarts. See #sync-safety-vs-full-bft: sync
  is safe against `< f+1` malicious peers WITHOUT any exclusion mechanism.
- Manager-driven ejection stays available as an operator recourse via ordinary
  `Management.revoke` on the evidence an operator gathers out-of-band. It acts on the roster,
  not on any per-follower state; local shun would not compose with it and MUST NOT be
  introduced as a shortcut.

### GETBLOCK refuses with a reason when the block is absent {#getblock-refuses-with-reason}

- A peer receiving `GETBLOCK(n)` for a height it does not hold (has not settled yet, or has
  compacted it away in a future world) MUST respond with `REFUSED` naming the reason:
  `NOT_YET_SETTLED` (n > my head), `COMPACTED_AWAY` (post-#compaction), or
  `UNKNOWN` (n is well below my head but I don't have it — pathological).
- Silence is not the answer. The requester's timeout would fire, waste a full RTT, and re-attempt
  against the same peer or a different one with no more information. Explicit refusal lets the
  requester immediately try the next-highest reporter and lets telemetry attribute the miss.
- The REFUSED reason MUST be a closed enum member so branches on it exhaustive-match, per
  #no-exceptions-for-control-flow.

### Sync lives in its own module {#sync-in-its-own-module}

- The follower — the piece that polls heights, decides when to pull, drives the block-by-block
  walk, and hands blocks to the Store — lives in a NEW top-level module (`dude/sync.py` or
  similar). Not inside Coordinator; not inside Node.
- Rationale: Coordinator PRODUCES SETTLED blocks (drives Round + SettleRound, commits on
  quorum). The follower CONSUMES SETTLED blocks (pulls, verifies, commits). They share the Store
  as the meeting point and nothing else. A node uses both; each has its own tick.
- The follower MUST be sans-I/O in the same discipline as Round and SettleRound: `tick(now)`,
  `receive(env, now)`, `outbox()`. Postman is the impure edge. This keeps the follower testable
  by direct wiring, in the same shape as the consensus tests.
- Coordinator and Follower MUST NOT hold references to each other or exchange messages
  in-process. The only cross-talk is via Store: when the follower commits a block, the
  Coordinator's next tick sees the new head. Same discipline as Settlement-does-not-cross-Mempool
  (#settlement-does-not-cross-mempool) applied to the L4/L6 boundary.

### The roster walks forward with the log {#roster-walks-forward}

- The roster the joiner uses to verify block N+1's signatures is the roster its Store holds
  after applying blocks 0..N. Roster changes are log-state (#authority-is-log-state), so this
  falls out of #roster-at-ratification without any special mechanism.
- A joiner that hits a roster change block MUST apply the change atomically with the block
  (#roster-change-is-atomic), so the next block is checked against the post-change roster.

### The SMT is not part of sync {#smt-for-light-clients}

- The compressed sparse Merkle tree (#state-root) exists for #light-client retrieval, not
  for full-node sync. Full-node sync recomputes the SMT locally by folding the log; a joiner
  never trusts an SMT root from a peer as a sync shortcut. That shortcut is exactly the
  fast-sync path (#compaction), which is a separate arc.

### Test shape {#sync-test-shape}

- A three-node cluster runs long enough to produce many SETTLED blocks including at least one
  roster change (adding an authorised writer, granting a new node's role).
- A fourth node is instantiated holding only the manager pubkey and seed addresses. It syncs
  block-by-block through the sync verb, verifies each, catches up to the current SETTLED head,
  then participates in the next Round as a quorum-eligible node.
- Divergence at any step (a block whose signatures fail, whose replay produces different
  anchors, whose slice contains a transaction the joiner cannot resolve) MUST fail loudly, not
  proceed with a warning.

### Sync safety vs full BFT {#sync-safety-vs-full-bft}

- L6 delivers **safe sync**: a joiner catches up to a head it can independently verify, using
  `f+1` fresh witnesses (#height-poll-is-the-trigger) + per-block chain-and-sigs + per-tx
  authority (#per-tx-authority-verified-at-replay). Under the standard threat model (fewer
  than `f+1` colluding nodes), a joiner cannot be lied into a false head or a false block.
- No BFT observability layer is planned. A Byzantine minority is filtered as noise at every
  merge point (Held tally, Sig tally, SettleSig tally, sync verify) — the pipeline stays safe
  and cadence stays on wall-clock without cross-author attestation retention, monotonicity
  conviction, or evidence-driven ejection. Those axioms and their machinery are retired (see
  the retired-tags list).
- Local per-follower blacklists were explicitly REJECTED (#no-shun-only-priority). The
  follower does not maintain any "banned peer" state — no `_bad_sources`, no persistent
  denylist, no fork-detection exclusion. Every peer above our head remains a candidate for
  the next pull; a priority signal (most recent successful reply) is the only per-peer state
  and it decays naturally as time passes.
- The accepted cost: an active adversary at `< f+1` cannot break sync but MAY cost wasted
  round-trips (a lying peer refused, retried against another). The cost is bounded by
  `pull_timeout × retries_until_honest_source_picked` per pull; correctness is unaffected.

### Compaction is the next work {#compaction}

- The compactor role (a distinct key with its own authorisation to propose truncation), entry
  discard below a ratified checkpoint (SPEC L1's OWED row), and any sync path shaped for a
  compacted log are the next design arc. The no-compaction path is rock-solid — the gate is
  met.
- Compaction is a compactor-signed checkpoint that renders older blocks discardable, plus a
  fast-sync path that adopts state at a ratified checkpoint rather than replaying from
  genesis. Compaction is also the vehicle for #secrecy-by-key-death: routine truncation drops
  ciphertext under old keys as they age out, turning compaction into the conveyor that
  enforces forward secrecy. `#wrapped-masters` retention returns with this work — an epoch key
  becomes retirable exactly when compaction has driven its refcount to zero.
- Requirements not yet specified: compactor identity + authorisation, checkpoint shape,
  ratification-and-discard atomicity, fast-sync verb shape, and how a joiner reasons about a
  checkpoint as the root of its walk rather than genesis.

---

## Light client retrieval {#light-client}

The path a client that does NOT hold the log walks to read a single key. Distinct from L6
sync (which drives a node to a verifiable head by replaying blocks) and from the worker
API (which serves reads to a client that trusts its own daemon). A light client trusts only
the manager pubkey; it wants the current value for one key without holding any blocks.

### Retrieval names one key, returns value + proof {#light-client-get}

- The retrieval verb is `GETKEY(store, name) → (value | ∅, proof, anchors, settle_sigs)`.
- `proof` is an SMT membership or non-membership proof against `anchors.state_root`.
  `anchors` are the anchors of the latest SETTLED block the responder holds; `settle_sigs`
  are the quorum's signatures over those anchors (#block-shape-settled).
- Value present iff the SMT walk terminates at a leaf whose path matches the requested key.
  Non-membership is proved by the terminal-node structure per #state-root.

### The client verifies from the anchor alone {#light-client-verify}

- A light client holds the anchor pubkey and nothing else durable. Bootstrap unfolds in
  three phases; each pass through establishes one trust piece:
  1. **Identity chain from one node** (see #light-client-cert-chain). The bootstrap node
     ships the current manager set (P_GRANT MANAGER rows), the roster commitment (P_ROSTER
     row with its #roster-commitment-cert), and each roster entry (P_NODE rows with certs).
     Each cert verifies against anchor via one or two hops — no `state_root` dependency.
     A lying bootstrap cannot inject fake identities (no anchor key); a subset attack is
     caught by the commitment cert whose subject binds `H(serial ‖ members)`.
  2. **Head corroboration from `f+1` roster members** (see #light-client-freshness).
     `GETANCHORS` against `f+1` distinct members; wait for `f+1` agreeing on
     `(block_num, state_root, prev_block, roster_serial)`. Verify `settle_sigs` in each
     reply against the roster from step 1 (via `Management.authorization`). This
     establishes trust in `(block_num, state_root)`.
  3. **Per-key reads** (steady state). `GETPROOF(store_id, name, block_num)` against any
     one responder. Verify the returned `proof` against the trusted `state_root`; if
     `Value`, verify the leaf's credential authorises whoever last wrote it.
- No trust in the responder at any phase. A malicious responder can only refuse or serve
  a proof that fails verification; it cannot produce valid proofs, valid certs, or valid
  `settle_sigs` for anything the anchor did not attest or the quorum did not agree.

### The cert chain reaches the roster from the anchor alone {#light-client-cert-chain}

Two independent attestation layers, each catching attacks the other cannot:

**Provenance (per-entry #cert)** — chain is `anchor → manager Cert (P_GRANT) → roster
Cert (P_NODE)`. Verifies one roster entry as:
1. `entry_cert.verify()` — signature-only check.
2. Either `entry_cert.signer == anchor` (entry is anchor-attested; done) OR fetch the
   manager's P_GRANT row cert for `entry_cert.signer`, verify it recursively against the
   anchor.
3. Once `state_root` is trusted (phase 2 of #light-client-verify), check the entry's own
   P_NODE row membership at `state_root` for currency (revocation).

**Completeness (#roster-commitment-cert)** — chain is `anchor → manager commitment Cert
(P_ROSTER)`. Verifies as:
1. `commitment_cert.verify()`.
2. Recompute `H(codec.encode([serial, sorted_members]))` and check it equals
   `commitment_cert.subject`.
3. Verify `commitment_cert.signer` is anchor or a valid manager (same recursive check as
   above).

Both are needed and orthogonal:
- Lying bootstrap ships a SUBSET of the real roster → caught by completeness (subset's
  hash doesn't match commitment cert's subject).
- Compromised manager signs a commitment adding a FAKE member → caught by provenance
  (fake member has no anchor-provenanced entry cert).

Currency comes from `state_root`: a cert whose row has been revoked (row deleted) fails
the SMT membership proof and is rejected. Provenance is state-root-independent; completeness
is state-root-independent; currency needs state-root. Bootstrap acquires state-root in
phase 2 after acquiring the identity chain in phase 1.

A roster refresh from a single responder is safe: the responder can neither forge a cert
chain (no anchor key), forge a valid commitment (would require the manager key AND matching
the current serial that f+1 corroboration will surface), nor forge a state-root membership
proof (state_root was corroborated from f+1).

### The roster is a corroborated read, not a bootstrapped fetch {#light-client-roster}

- A light client's initial roster comes from the same `GETANCHORS` reply that corroborates
  the head anchors. Each responder ships `(anchors, settle_sigs, roster_bundle)` where
  `roster_bundle` is the commitment cert + per-entry certs + membership proofs.
- When `known_roster_fingerprint` in the request matches the responder's current fingerprint,
  the responder omits `roster_bundle` — the client uses its cached roster (already verified
  against the anchor per #light-client-cert-chain).
- On fingerprint mismatch, the responder ships the fresh `roster_bundle`; the client
  re-verifies both the commitment cert and each entry cert, replaces its cache. No separate
  "roster fetch" verb — the roster
  rides GETANCHORS as an optional field.

### Non-membership is a first-class answer {#light-client-nonmembership}

- A light client asking "does this key exist" MUST receive a proof either way. The SMT's
  compressed-tree structure encodes non-membership as a proof-of-absence at the level where
  the walk terminates.
- Silence is not a valid answer. A responder that does not hold the requested subtree MUST
  refuse with a reason, same shape as #getblock-refuses-with-reason: closed enum,
  exhaustive-match at the client.

### The retrieval path is stateless per request {#light-client-stateless}

- Each `GETKEY` is a single request/reply exchange. No session, no subscription, no keepalive
  from the client's perspective. A light client on a bad link retries the whole verb.
- The responder MUST answer from the latest SETTLED block it holds; it MUST NOT synthesise
  a proof against an in-flight state. Freshness against the cluster head is the client's
  concern — #light-client-freshness.

### Freshness comes from f+1 witnesses at the retrieval layer {#light-client-freshness}

- A light client wanting "the current value" MUST corroborate the answer against `f+1`
  distinct responders that agree on `(anchors.block_num, anchors.state_root, value_hash)`.
  One responder's answer, however well-signed, only proves "some SETTLED block held this
  value" — not "the current one".
- Same principle as #height-poll-is-the-trigger applied at retrieval time: signatures are
  self-verifying, currency is not.
- A client willing to accept staleness (e.g. archival reads) may skip this and take one
  responder's answer as an at-that-height fact. The requirement is that this is an explicit
  choice, not a silent default.

### The SMT is a primitive of retrieval, not of consensus {#light-client-smt-scope}

- `#state-root` computes the SMT from the live view (#live-view). Consensus does not touch
  it directly — Round agrees on slices of transactions, SettleRound agrees on anchors
  (which include the state root as one field). Light client retrieval is the only
  requirement that walks the SMT for individual proofs.
- Requirements not yet specified: the wire shape of `proof` (path bytes + sibling digests),
  the retrieval refusal enum, and the freshness-corroboration timeout.

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

The **encoding-half** of this section stays wired: `Set.epoch` is on the wire, `live.epoch`
is stored, values carry their keyepoch cleartext next to the ciphertext. The **retirement-
half** — `Management.retire`, the `Drained` predicate, `Store.epoch_live`, the refcount over
live values — was ripped in 2026-08-01 as a mitigation nothing consults. It returns with
client encryption and #compaction together: compaction is the conveyor that drives the
refcount down (routine truncation drops ciphertext under old keys), and client encryption is
the consumer that makes an epoch key meaningful in the first place. The enforcement row for
#wrapped-masters retention is OWED; #value-carries-epoch stays wired.

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

## Enforcement

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
| entries below the last ratified checkpoint may be discarded | **OWED** — compaction ripped 2026-08-01 (rip 2/3); no-compaction path holds every entry from genesis, and the compactor role (SPEC L5+) has not been designed |
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
| the anchor is always authorised (#anchor-is-the-axiom) | `Management.may_write` short-circuits True for `who == self.store.anchor()`; `Management.may_send` treats the anchor via the same rule; `Management.authorization` reserves bitmap slot `N` for the anchor pubkey |
| the anchor is the only identity that may exercise the block override (#anchor-is-the-axiom) | `Management.authorization` verifies bitmap slot `N` against `self.store.anchor()` -- no `Role.MANAGER` grant reaches that slot |
| anchor rotation is deferred (#anchor-is-the-axiom) | **deferred** -- `Store.provision` is one-shot; no operation replaces `store.anchor()`. Loss of the anchor cold-key ends emergency-intervention capability, not the cluster |
| bootstrap and emergency intervention share ONE block-construction path (#anchor-is-the-axiom) | Both call `dude.consensus.bootstrap._build_manager_signed_block(...)` (or equivalent shared helper); no `sign_by_manager` on `SettledBlock` outside that helper |
| Role.MANAGER confers blanket authorship (#role-manager-grant) | `Management.may_write` returns True on `g.role is Role.MANAGER` for any `store_id`; `Management.may_send` returns True on `g.role is Role.MANAGER` for any kind |
| Nodes are not authors (#nodes-are-not-authors) | `Role` enum has no `NODE` member; `Management.authorise` cannot express a node-as-author grant. A bare node identity has no P_GRANT row, so `may_write` returns False. Being in P_NODE keyspace with a valid #cert is the only sense in which a node is "in" the system |
| Only the anchor grants or revokes MANAGER / COMPACTOR (#role-manager-grant) | **partial** — `Management.authorise(role=MANAGER \| COMPACTOR, cert=...)` requires an anchor-signed Cert and validates it before emitting the mutation. Log-boundary refusal of a raw `Set P_GRANT` bypassing `authorise` is DEFERRED per #typed-management-ops-owed |
| One authorisation cert shape (#cert) | **partial** — `Management.Cert` is one dataclass covering every authority-carrying row (`subject: bytes` covers both identity certs and content-commitment certs). `authorise` and `change_roster` require it; `may_write`, `may_send`, `roster()`, and `roster_commitment()` verify it on read (subject, purpose, signature, signer-authority-for-purpose). Log-boundary refusal of a cert-less or wrong-purpose write is DEFERRED per #typed-management-ops-owed |
| Roster commitment carries its own cert (#roster-commitment-cert) | **partial** — P_ROSTER row content is `[serial, sorted_members, cert]`; `Cert.sign_roster_commitment(signer, encode([serial, members]))` binds `subject = H(content)`. `change_roster` requires a `commitment_signer` keypair (anchor or valid manager), emits the cert with the mutation. `Management.roster_commitment()` decodes, recomputes the hash, verifies the cert, and returns None on any failure. Log-boundary refusal DEFERRED per #typed-management-ops-owed |
| Management operations should be typed, not smuggled (#typed-management-ops-owed) | **OWED** — API-side plumbing (this row's Cert enforcement) is a halfway house; the design fix is typed management op types so wrong-shape writes are unexpressible. Deferred until after light-client work per Harry's ruling |

### L3 mempool

| requirement | enforced by |
|---|---|
| one door, one predicate | `Mempool.valid` |
| admission consults currently-settled state | `Mempool.valid` via `settle.would_apply` |
| duplicates never enter | `Store._settled_hashes` and `Mempool.valid` |
| one evaluator across admission, slice construction, settlement | `settle.evaluate` called from `Store.apply` and `Mempool.valid` |
| a mempool is not retained past its window's close | `dude.coordinator.Coordinator` swaps the whole `Mempool` at each bucket boundary — the frozen one goes with the Round, a fresh one starts admitting |
| rejects re-enter through the same door | `Coordinator._settle` calls `self.mempool.admit(tx, ...)` for surviving-but-not-included transactions — the same one door any submission uses |
| `Mempool.evict` / `Mempool.reenter` / `Mempool.propose` / `Mempool.retire` do not exist | Struck 2026-08-01 — Mempool is now a container with one door (`admit`) and one introspection helper (`buckets`), and the Coordinator owns everything else |

### L4 consensus

| requirement | enforced by |
|---|---|
| quorum arithmetic has one implementation and no configurability (#quorum-gate) | `dude.quorum` -- flat module of `size`/`intersection`/`tolerates`/`corroboration`/`spare`/`max_domain`/`satisfied`/`would_brick`/`domain_advisory`. No `Rule` class, no `DEFAULT`, no rule parameters anywhere. Every caller asks the module a named question; none computes. |
| `f+1` is decided by the quorum module | `quorum.corroboration`; consumed by `Follower.caught_up` for the fresh-witness threshold (#freshness-needs-many) |
| composition is advisory, not enforcement (#quorum-gate) | `quorum.domain_advisory` returns violations for operator inspection via `Management.check_domains`; no code path refuses on it |
| roster change refuses a hard brick (#roster-change-refuses-brick) | `Management.change_roster` raises `ManagementError` iff `quorum.would_brick(n_after) AND NOT quorum.would_brick(n_before)` -- shrinking a safe cluster into an unrecoverable state. Batched atomic add+remove sidesteps one-at-a-time refusal; anchor rescue via `intervene()` bypasses this check when a deliberate shrink is needed |
| roster change is atomic (#roster-change-is-atomic) | `Management.change_roster` composes P_NODE writes/deletes, P_POP deletes, AND a fresh P_ROSTER commitment (serial = current + 1) into one Transaction. `add_node` and `remove_node` are wrappers -- the previous `remove_node` skipped the commitment update; fixed. |
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
| exclusion is by selection during slice construction | Naturally satisfied by Round's #slice-is-intersection: a mutually-exclusive tx cannot appear in the largest set held by a quorum unless every quorum member holds it, which for a slice-mate that would invalidate it is precisely what settlement's evaluator refuses at apply time. The falsified loser returns via #fall-through-through-the-door. |
| endorsers refuse a slice containing a past-`w_valid` transaction | Combined enforcement (#endorser-refuses-stale): (1) `Mempool.admit` rejects past-`w_valid` at the door; (2) `Round._compute_slice` restricts to `_local_bodies` (sign only what we admitted); (3) `Round._abandon` bails at `close_by + w_valid_margin` and hands every held tx back to the current mempool via `Coordinator._on_abandoned`, where the same door refuses anything aged out. Three cited sites, one property, no per-tx staleness check. Tested by `TestAbandonmentOnTimeout`. |
| Round carries bodies, not just hashes, for its held transactions | `Round.add_local` takes `Iterable[SignedTransaction]`; `Round._local_bodies: dict[Digest, SignedTransaction] \| None`; `Round.slice_bodies` and `Round.surviving` return `tuple[SignedTransaction, ...]` so the Coordinator receives bodies at ratification without a Mempool sidecar. Enforces the possession invariant at the Round's input rather than by convention. |
| a Round that cannot form quorum abandons rather than hangs | `Round.State.ABANDONED`; `Round._abandon` fires from `tick` when `abandon_by` passes in state FINALIZE; `Coordinator._on_abandoned` re-admits every held tx via `mempool.admit`. Tested by `TestAbandonmentOnTimeout`. |
| an equivocating peer's contradiction is preserved as evidence past GONE | `Round._on_sig` (detects equivocation before dropping on `GONE`); `Round.equivocations()` for the observability layer |
| the running Node uses `Round` for consensus | `dude.coordinator.Coordinator` — `Node.tick` calls `Coordinator.tick`, which opens Rounds at bucket boundaries, drives them, hands ratified Blocks to `Store.apply`, and pushes surviving hashes back to the current Mempool through the same admission door. |
| **block-shaped ratification via `Coordinator._settle`** | `dude.round.Block` is the ratified shape; `Coordinator._settle` looks up bodies from the frozen Mempool and passes them as an ordered tuple to `Store.apply`. Block metadata (bucket, signers, sigs) is not yet persisted — the log records transactions per-entry, not blocks-as-entries. Moves into L5 settlement (SPECv2 #block-shape-settled). |

### L5 settlement

| requirement | enforced by |
|---|---|
| ratified is not settled (#ratified-is-not-settled) | `SettleRound` state machine — `SettleState.COLLECTING → SETTLED` distinct from `Round.State.COLLECT/FINALIZE/GONE/ABANDONED`; `Coordinator._on_ratified` enqueues to `pending` rather than committing |
| deterministic application per-tx (#deterministic-application-per-tx) | `settle.apply_to` (one evaluator, one order); `Store.commit_block` uses the same evaluator; `_Settling.applied` is the ordered tuple |
| non-applying txs re-enter current mempool (#fall-through-through-the-door) | `Coordinator._on_settled` — `s.surviving` and `s.dropped` are re-admitted via `self.mempool.admit` through the one door |
| settlement signs the post-apply anchors (#settlement-signs-post-anchors) | `SettleSig.sign(kp, slice_hash, anchors)` — sig covers `(_ANCHORS_DOMAIN, slice_hash, block_num, height, prev_block, state_root, acc_state, acc_log)` |
| settlement converges by quorum on anchors (#settlement-quorum-on-anchors) | `SettleRound._try_settle` — quorum of matching `SettleSig` messages agreeing on our anchors |
| peer divergent anchors are evidence (#settlement-peer-divergence-is-evidence) | `SettleRound._divergences` accumulator; `SettleRound.divergences()` accessor |
| our own state disagreeing is InvariantError (#settlement-self-divergence-is-invariant) | `Coordinator._on_settled` calls `_expect_anchors` which raises `InvariantError` on any mismatch of head / state_root / A_state / A_log |
| Coordinator filters already-settled before preview (#already-settled-filtering) | `Coordinator._start_settling` — `store._settled_hashes(...)` drops slice txs already in the log before feeding `settle.apply_to` |
| fall-through re-admission re-broadcasts (#fall-through-re-broadcasts) | `Coordinator._on_settled` and `_on_abandoned` call `self.reflood(tx, now)` for every re-admitted tx (Node wires it to `lambda tx, now: self._flood(Verb.SUBMIT, tx.raw, now)`) |
| every ratified bucket runs settlement, even empty (#empty-bucket-still-settles) | `SettleRound` accepts empty slice (empty `hashes` tuple); `Coordinator._start_settling` promotes empty ratifications unchanged; `Anchors.block_num` increments regardless |
| settlement does not cross Mempool (#settlement-does-not-cross-mempool) | **structural** — `dude/consensus/settle_round.py` imports neither `Mempool` nor `Coordinator`; enforced by CI review |
| settlement abandons on cadence (#settlement-may-hang) | `SettleRound.abandon_by` (required constructor arg) + `tick()` transitions COLLECTING → ABANDONED when `now >= abandon_by`; `Coordinator._on_settle_abandoned` re-admits `applied + dropped + surviving` via mempool door and clears the settling slot |
| pipeline holds one of each in flight (#one-of-each-in-flight) | `Coordinator` state: `mempool: Mempool`, `current_round: Round \| None`, `settling: _Settling \| None`. No queue between stages -- if Round ratifies while settling is busy, `current_round` holds the ratified Round until the next tick clears settling and `_promote_to_settling` fires; if settling is busy AND bucket boundary crosses, next Round doesn't open (mempool keeps admitting for the current bucket) |
| block shape is SETTLED (#block-shape-settled) | `SettledBlock` dataclass; `SettledBlock.block_hash` computed over `_identity_bytes()` only (identity/proof split, sig-independent) |
| empty blocks still increment block_num (#block-num-is-monotone) | `Coordinator._start_settling` computes `block_num = (store.head_block_num() or 0) + 1` unconditionally; covered by `Anchors.block_num` in every SettleSig |
| manager signature overrides quorum (#manager-sig-overrides-quorum) | `Management.authorization` — `[*roster, anchor]` composition; bitmap slot `n − 1` reserved for manager; `SettledBlock.sign_by_manager`; `bootstrap()` uses it for block 1 |
| chain roots at anchor identity (#genesis-stamp-anchors-the-chain) | `genesis_stamp(manager) = crypto.h("dude.genesis:" ‖ manager.bytes)`; Follower and Coordinator use it as `prev_block` when `head_block_hash() is None` |

### L6 sync

| requirement | enforced by |
|---|---|
| joiner starts from anchor alone (#joiner-starts-from-anchor) | `Store.provision(manager)` seeds a bare store; `bootstrap()` produces block 1 with manager sig; `test_fresh_joiner_pulls_block_1_via_manager_sig` end-to-end |
| no trusted frontier (#no-trusted-frontier) | `Follower._on_settled_block` runs the full verify pipeline on every pulled block — no whitelist, no "trust this height" shortcut |
| sync is log replay (#sync-is-log-replay) | `Follower._on_settled_block` — chain link + settle_sigs + body-block correspondence + body sigs + preview-anchors-match, then `store.commit_block` |
| per-tx authority at replay (#per-tx-authority-verified-at-replay) | `Follower._preview_matches_signed_anchors` → `settle.apply_to` → `Management.may_write` — same evaluator/authoriser as production |
| routine height polling is the trigger (#height-poll-is-the-trigger) | `Follower.tick` iterates `_poll_at`, emits `HeightAsk`; `Follower.caught_up()` requires f+1 fresh witnesses at `(my_num, my_tip)` |
| same-height mismatched tip = divergence (#poll-detects-divergent-tips) | `Follower._on_height_reply` observes the mismatch; it is stored as a HeightReport (observability signal) but does NOT feed any exclusion decision. Fork resolution is human/tooling territory per #no-shun-only-priority. |
| height is a hint, never a floor (#height-is-a-hint) | `HeightReply` is unsigned at message layer; verified only by the full GETBLOCK pull; a peer that lies about height wastes one round-trip and loses priority (no exclusion) |
| GETBLOCK refuses with reason (#getblock-refuses-with-reason) | `SyncRefusal` closed enum (`NOT_YET_SETTLED`, `UNKNOWN`, `INVALID`); `Refused` message; `serve_getblock` returns typed refusals |
| sync in its own module (#sync-in-its-own-module) | **structural** — `dude/sync/` package; Coordinator and Follower share only `Store`; neither imports the other |
| roster walks forward with the log (#roster-walks-forward) | Follower applies blocks in `block_num` order via `commit_block`; roster is read via `Management(store).roster()` on demand, so it grows with the log naturally |
| SMT is not part of sync (#smt-for-light-clients) | **structural** — `Follower` ships bodies (never SMT proofs) and computes `state_root` locally via `Layer` per applied block; the light-client path (#light-client) is a separate arc |
| sync test shape (#sync-test-shape) | `dude/tests/test_sync.py` direct-wired `Follower` scenarios (6 test classes); `dude/tests/test_sync_e2e.py` full-stack |
| tolerance, not shunning (#no-shun-only-priority) | `Follower` maintains no blacklist. Priority-based `_pick_pull_source` prefers peers with the most recent successful reply (`_last_ok_at`); every peer above our head remains a candidate. On any failure -- bad decode, chain-link violation, timeout, refusal, fork detection -- the in-flight pull clears and next tick picks again from the same pool. |
| sync safety vs full BFT (#sync-safety-vs-full-bft) | **structural, no observability layer planned** — the merge points (`Round._on_sig`, `Round._compute_slice`, `SettleRound.receive`, `Follower._on_settled_block`) each drop unauthenticated / divergent / wrong-slice messages from quorum counting. No blacklist, no persistent per-peer state; `_last_ok_at` is in-memory priority only. |

### Light client retrieval

| requirement | enforced by |
|---|---|
| retrieval names one key, returns value + proof (#light-client-get) | **OWED** — no `GETKEY` verb, no light-client server-side handler, no client-side verifier |
| client verifies from anchor alone (#light-client-verify) | **OWED** — no client-side verify pipeline exists; the anchor pubkey lives in `Store.anchor()` for the full-node path only |
| cert chain reaches roster from anchor alone (#light-client-cert-chain) | **partial** — the cert-emission and cert-storage halves land with #manager-cert / #roster-entry-cert (Management side); the client-side chain-walker is OWED until light client is built |
| roster is a corroborated read via GETANCHORS (#light-client-roster) | **OWED** — no GETANCHORS verb yet; roster ships in the reply via the cert bundle once the wire lands |
| non-membership is first-class (#light-client-nonmembership) | **partial** — `smt.py` supports non-membership proofs structurally; no retrieval verb consumes them yet |
| retrieval is stateless per request (#light-client-stateless) | **OWED** — no verb, so no session model to check |
| freshness via f+1 responders (#light-client-freshness) | **OWED** — no client-side corroboration loop; shape parallels `Follower.caught_up()` |
| SMT is a retrieval primitive, not consensus (#light-client-smt-scope) | **structural** — `smt.py` is imported by `store.py` and `layer.py` only; no consensus module (Round, SettleRound, Coordinator) references it |

### Compaction

| requirement | enforced by |
|---|---|
| compaction is the next design arc (#compaction) | **OWED** — compactor role, checkpoint shape, ratification-and-discard atomicity, fast-sync verb, checkpoint-as-walk-root all unspecified |
| entries below the last ratified checkpoint may be discarded (#log-is-authoritative L1 row) | **OWED** — see above; also blocks `#wrapped-masters` retention (the conveyor Harry described) |

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
- `#cross-attestation`, `#freshness-is-gathered`, `#monotonicity`, `#peers-keep-evidence`,
  `#the-lemma`, `#nodes-are-untrusted` — the attestation duty and its axioms. Ripped
  2026-08-01 as a mitigation nothing consults; not returning. A Byzantine minority is filtered
  as noise at every merge point (Held tally, Sig tally, SettleSig tally, sync verify), so the
  pipeline stays safe against `< f+1` without observing them explicitly. The one honest cost
  — O(retries) wasted round-trips in the sync path when a peer lies — is accepted; see
  #sync-safety-vs-full-bft.
- `#freshness-needs-many` is NOT here — it looked like a Trust axiom but is in fact live: the
  `f+1` corroboration rule is enforced by `Follower.caught_up()` and `quorum.corroboration()`.
  Its home is L6 sync (see the requirement in-body under `#height-poll-is-the-trigger`).

The following is OWED rather than retired — the requirement stands, but the machinery that
enforced it was struck 2026-08-01 and will return with its real consumer:

- `#wrapped-masters` retention rule (refcount over live values, retire-when-zero) — the
  DUTY was ripped with the conveyor. Returns with client encryption + compaction, which
  together form the conveyor that re-encrypts forward and enforces #secrecy-by-key-death.
  `#value-carries-epoch` is NOT here — the wire format survives.

Two wire-verb sets went with these rips and have no anchor to retire (verbs are enum
members, not SPEC tags); noted here for grepability:

- `COLLECT` / `RATIFY` — compaction consensus (rip 2/3, 2026-08-01).
- `FRONTIER` / `STANDING` / `PULL` / `ENTRIES` — attestation probes and log transfer (rip
  3/3c, 2026-08-01). PULL/ENTRIES return in a different shape when L6 sync lands.
- `ANNOUNCE` / `FETCH` / `SUBTREE` / `HASHES` / `LEAVES` / `ROWS` — gossip-by-hash and the
  SMT state walk (rips 1/3 and 3/3a). Neither is expected to return in the same form —
  gossip-by-hash rides Round's `HELD` now, and light-client state queries will be direct
  rather than an interactive walk.

---

## Retired documents

`HANDOFF.md`, `PLAN.md`, `FRAMING.md`, `ACCUMULATOR.md`, `THREAT-MODEL.md`, `LINKS.md`,
`MEMPOOL.md`. Each was a work-in-progress discussion document that accumulated superseded reasoning
without removing it, which reads as authority to anyone finding it. The material that survived is
in this file as requirements; history is in git; working practices are in `CLAUDE.md`; open work is
in GitHub issues. A citation to a section number in any retired file is stale by construction —
cite an anchor.
