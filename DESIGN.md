# DudeFS — Distributed Ultra-Durable Encrypted File System

> **Status:** design definition, revision 6. This document is the canonical model to build against and poke holes in. Mechanisms follow from the definition; when in doubt, return to the definition. Companions: **[PROTOCOL.md](PROTOCOL.md)** — who says what to whom (client↔node, node↔node, manager flows); **[RESILIENCE.md](RESILIENCE.md)** — the fault & adversary analysis (chaos monkey, destructive gorilla, evil interactive octopus); **[FORMAL.md](FORMAL.md)** — the verification plan (Lean for the fold, TLA+ for the coordination layer, and the numbered hypotheses each must discharge); **[RELATED.md](RELATED.md)** — where this design sits in the Paxos/Raft/leaderless/randomized literature (papers archived in [references/](references/)); **[COMPARISON.md](COMPARISON.md)** — the decision-level triangulation matrix (every load-bearing decision → prior mechanism → adopt/reconcile/carve/decline, with verified citations); **[ARCHITECTURE.md](ARCHITECTURE.md)** — the implementation layer decomposition and interface contracts; **[MANAGER.md](MANAGER.md)** — manager capabilities and the admin tool; **[IMPLEMENTATION.md](IMPLEMENTATION.md)** — the Python 3 proof-of-concept plan (stdlib-only, milestones M0–M8). Revision 6 (post-M4 review) replaces §12's materialized snapshot with **log-compaction** — live winner ops retained in place, a continuously-advancing conveyor cut, a delegated compactor identity — and hardens §8's slot-state GC against reborn tags (NOTES items 25, 27, 29–31). Revision 5 (post-M3) drops the ballot-0 fast path — classic two-phase per-slot Paxos, always (§8; NOTES item 21). Revision 4 adds §16, evolution & upgradability. Revision 3 hardened the fold after an adversarial re-read: the lineage-advance invariant, an equivocation-proof total order, precise verdict freezing, tombstone lineage across compaction, a public slot for roster transitions, and the author-amnesia rule.

## 1. What it is

DudeFS is an **authenticated, encrypted, replicated CRDT** over a hierarchical dictionary — a durable, provenance-carrying `etcd` for atomic coordination among a small number of entities.

- **State** is a hierarchical dictionary. It is *never stored*; it is always the deterministic fold of a signed log.
- **Writes** are guarded transactions, ordered by a hybrid logical clock and made durable by **mandatory quorum commit** (the "ultra-durable" `D`).
- **Atomic coordination** (CAS) is provided by **per-slot single-decree agreement** — one ballot-voted Paxos instance per contention slot — linearizable, no split-brain, without global-ordering consensus (no Raft/Paxos *sequencing*).
- **Storage nodes are zero-knowledge for data**: they replicate ciphertext, validate signatures, vote, and prove quorums, but never see keys or values. They fold only the plaintext **control plane** (roster, certs, checkpoints).

One line: *an authenticated CRDT merge over a hierarchical dict (deterministic fold ⇒ strong eventual consistency), made ultra-durable by mandatory quorum commit, with per-slot ballot voting giving linearizable CAS and a watermark rule freezing verdicts into finality — nodes zero-knowledge throughout, enforcing exclusion on opaque keyed tags they can't read.*

### Design targets & non-targets

- **Scale:** 1–3 clients on average; live state bounded by a **5–10 GB ceiling** (a year of a slow, glacier-grade store — §12's compaction model is sized against it; gossip and checkpoints scale with *churn*, never with state). Not built for high write concurrency.
- **Durability over availability:** every write is quorum-committed. A minority partition **blocks** rather than risk split-brain (this is the CAP price, paid deliberately).
- **Fault model:** crash tolerance across a spectrum (chaos-monkey → destructive-gorilla). *Not* a Byzantine/active-attacker model — but equivocation is cryptographically **detected and punished**, not merely ignored. Destructive loss of a node's durable state **retires that node's identity** (§13).
- **Membership is dynamic:** start at 1 node, grow to 3 → 5 → 7 (7 = the most durable config targeted, surviving 3 concurrent failures). **Roster size is always odd** — even sizes enlarge quorums without adding failure tolerance and are rejected by validation. (Oddness, not primality, is the load-bearing property: n=4 tolerates the same 1 failure as n=3 at higher cost; n=9 would be sound but is out of target.)
- **Transport agnostic:** HTTP(S) is one binding; the protocol does not depend on it.

### Three levels of "done" (used throughout)

| Level | Meaning | Established by |
|---|---|---|
| **Accepted** | some node holds + receipted the op | a receipt |
| **Committed** | a quorum holds it; it can never be lost | a QC (§8) |
| **Final** | its fold verdict can never change | quorum watermarks past its `hlc` (§9) |

Commitment is about *durability*; finality is about *meaning*. A committed CAS is durable the instant its QC exists, but its success verdict is knowable only at finality — conflating the two was a bug in revision 1.

---

## 2. Roles

| Role | Trust | Responsibilities |
|---|---|---|
| **Manager** | Fully trusted (root). Compromise = game over; nothing is defended below it. | Trust anchor. Signs authorization certs for clients and nodes. Owns the server/node roster (roster changes are signed control ops). Owns checkpoint authority (compaction — routinely delegated to a compactor cert, §12/§15). Just another client, with privileged capabilities. |
| **Client** | Authorized by a manager cert. Holds the group key. | Submits guarded transactions; folds the log locally; performs quorum reads; verifies durability certificates (QCs) and finality (watermarks). Does all the legwork. |
| **Storage node** | Semi-trusted. Zero-knowledge as to data. | Replicating store of ciphertext envelopes. Validates signatures/authz; acts as Paxos acceptor per slot; issues receipts (votes) and watermarks; gossips (server-to-server); serves ops + QCs. **Folds the plaintext control plane only — never data, never decrypts.** |

The **manager is just another client** whose ops (roster changes, checkpoints, cert issuance/revocation) are privileged because they're signed by the root key or a capability it delegated (§15). Nothing in the data path waits on the manager being online.

---

## 3. Cryptographic material

- **Manager root keypair** — the trust anchor. Its public key ships in the client/node genesis config. Note the distinction: root-key *compromise* is declared game-over; root-key *loss* would permanently brick compaction, roster changes, and revocation. Keep the root offline/escrowed; a threshold-split root is a possible hardening (out of scope for v1, accepted risk).
- **Client keypairs** — sign transactions (provenance: who wrote what, when).
- **Node keypairs** — sign receipts and watermarks; a quorum's receipts form a quorum certificate via the L0 `MultiSig` interface (ARCHITECTURE.md). **v1 (Python POC): Ed25519 signature lists** — no aggregation, no pairing library, no PoP needed. **Target suite: BLS12-381 plain aggregation + signer bitmap, no DKG** (DKG can't handle dynamic membership without re-share ceremonies); when it lands (lane-3 suite bump), plain aggregation's rogue-key exposure makes a **proof-of-possession at node-cert issuance** mandatory — a hygiene requirement of aggregation only, moot for lists.
- **Group data key** — symmetric key encrypting all data payloads (keys and values). Distributed by **envelope encryption**: wrapped to each authorized client's public key. Rotated on membership revocation (`keyepoch` bumps). Clients retain (and new clients are re-wrapped) the epoch key *history*, since committed ops reference the epoch that wrapped them.
- **Group slot secret** — derived from the group data key (per `keyepoch`); used as the PRF key for slot tags (§7). Clients hold it; nodes do not.

---

## 4. The log

The log is a set of **per-author hash-linked chains** woven into one DAG and folded via a deterministic total order.

- Each author appends to its own chain: contiguous `seq` (0,1,2,…), each op carrying `prev = hash(author.op[seq-1])`. This gives tamper-evidence, gap detection, and fork detection.
- Ops reference the observed heads of *other* authors via `deps` (a frontier). A dep is a **commitment to have observed** that head (PeerReview-style — RELATED §9): nodes **resolve deps before accepting** an op (PROTOCOL §2.1 — pull the referenced ops, committed *or merely stored*, or defer), so an op authored under one branch of a fork collides with the other branch at the first cross-view contact and mints equivocation evidence **at accept time**. Deps are evidence and anti-entropy hints, **never fold-validity** (§6): the fold orders by `hlc` alone, and an op is never invalidated by the later death of an op it merely observed.
- **Per-author HLCs are strictly monotone**: an author MUST issue strictly increasing `hlc` values along its own chain (violations are structurally invalid).
- Total order for the fold: **`(hlc, author-id, seq, op_hash)`** — hlc first, then author-id, `seq`, `op_hash`. The `op_hash` component keeps the order total even against an *equivocating* author (two signed ops at the same `(author, seq)` still sort deterministically) — the fold never depends on good behavior for determinism.

### Fork detection (equivocation)

If any author ever signs two different ops at the same `(author, seq)`, that's two valid signatures over conflicting content = a **portable cryptographic proof of misbehavior**. Gossip surfaces it; the manager ejects the offender. The same mechanism catches a storage node that double-votes a slot ballot (§8) or forks its view. Determinism does not wait for punishment: forked ops that each reach commitment simply fold in `op_hash` order like any other ops — equivocation earns ejection, but it can never make two honest clients disagree about state.

### Author amnesia (don't fork yourself)

An author that loses its own chain-head state (*which `seq`/`prev` am I at?*) must not guess — reusing a `seq` is an accidental fork. Recovery: quorum-read your own chain head, then **wait out the skew window δ** (§9) so any op you might have had in flight is either visible or provably dead, and resume at `head+1`. A client may instead simply retire the keypair (manager revokes + reissues — cheap). The **manager cannot retire its root key, so the wait-and-read procedure is mandatory for it** — an accidentally forked manager chain would be indistinguishable from root compromise.

---

## 5. The operation (envelope + payload)

An op splits into a **plaintext signed envelope** (what nodes validate, order, and vote on) and a **payload**. Data-op payloads are encrypted (only clients decrypt and fold); control-op payloads are plaintext (nodes fold them too).

```
Op {
  # --- plaintext envelope (nodes see this) ---
  class:     data | control            # control = roster / cert / revoke / checkpoint
  author:    cert-fingerprint          # who
  seq:       uint                      # per-author, contiguous; gap = missing data
  prev:      hash                      # hash(author.op[seq-1]); genesis for seq 0
  hlc:       (wall_ms, counter)        # hybrid logical clock — order + meaningful "when"
  deps:      [head-hash, ...]          # observed heads of other authors (frontier; accept-time resolved — §4)
  authz:     manager-cert-ref          # manager's authorization + epoch for this author
  keyepoch:  uint                      # which group-key epoch wrapped the payload
  slot_tag:  bytes | null              # contention tag: PRF-opaque for data (§7), public for roster ops (§13); null = blind write
  payload:   bytes                     # data: AEAD ciphertext; control: plaintext body
  sig:       sign(author_sk, ↑ all of the above)
}
op_hash = H(envelope)
```

The **data payload** is AEAD-encrypted under the group data key with **AAD = hash of the envelope-minus-payload** (defense-in-depth binding; the author signature already binds envelope to ciphertext, the AAD makes cross-context decryption fail loudly). It decrypts (client-side only) to a guarded transaction that **restates the slot preimage in plaintext**:

```
Txn {
  slot:      (key, version | ⊥, attempt) | null   # preimage of slot_tag; ⊥ = key absent (creation)
  guards:    [ key ↦ (expected-version | expected-value | absent | present ...) ]  # the condition
  mutations: [ set(path, value) | del(path) | ... ]                                # applied all-or-nothing
}
```

- `slot_tag` is the *public* half of the predicate (contention identity). `guards` is the *private* half (truth). The embedded `slot` preimage lets the fold verify that the public tag and the private intent agree (§6). See §7.
- `hlc` lives in the plaintext envelope so nodes can order/anti-entropy and enforce the skew window (§9); nodes still never fold data.
- The **path/key is inside the ciphertext** — nodes never learn tree shape or values.

**Control ops** (`class = control`) are manager-signed, carry plaintext bodies (roster change, cert issue/revoke, checkpoint), and are the *only* thing nodes interpret beyond the envelope. This is the explicit carve-out from zero-knowledge: the control plane is public to nodes by design, the data plane never is.

---

## 6. The fold (deterministic state derivation)

State is a pure function of the *committed* op-set:

```
fold(committed_ops) → (state, verdicts)
```

Per-key metadata maintained by the fold:

- `value` — current value (or tombstone).
- `version` — the `op_hash` of the op that last **applied** a mutation to the key. A deleted key keeps its tombstone's `version` as the lineage anchor; `⊥` means *never seen at this fold position* — including keys whose tombstones were discarded at a checkpoint barrier (§12).
- `attempt` — a counter of consumed slots at the current version (see the lineage-advance invariant below). Resets to 0 whenever `version` changes.
- The key's **expected tag** is `E(key) = PRF(slot_secret[e], key ‖ version ‖ attempt)` (with `version = ⊥` while the key is absent), always computed with the secret of the *candidate op's declared* `keyepoch`. All historical expected tags of a key are recomputable from its history.

Walk every committed op in `(hlc, author-id, seq, op_hash)` order. For each op:

1. **Structural validity:** valid `authz` at this fold position (§15), valid QC (§8), `prev` resolves (`deps` are accept-time evidence, never fold-validity — §4), per-author `hlc` monotone. Structurally invalid → verdict `invalid`: no mutation ever applies, but if the op's tag equals some key's current expected tag at this position, that slot is still consumed (`attempt(k) += 1`). The lineage-advance invariant below admits **no exception for invalidity** — an op that consumed its slot at vote time (nodes cannot see fold-positional invalidity) must advance the lineage, or the tag stays expected while its slot is already decided: a wedge. Reachable honestly: a just-revoked author's op receipted before the revocation sorts ahead of it (§15).
2. **Blind write** (`slot_tag = null`): decrypt; guards (if any) evaluate against state-so-far; hold → apply mutations atomically (each mutated key: `version := op_hash`, `attempt := 0`); fail → `rejected`.
3. **Slotted op** (`slot_tag = t`): attribute the tag —
   - **`t = E(k)` for the key `k` named in the decrypted preimage, `PRF(preimage) = t`, and guards hold** → verdict `applied`: apply mutations atomically; every mutated key gets `version := op_hash`, `attempt := 0`. If `k` itself is not among the mutated keys (a guard-only slot), advance it by `attempt(k) += 1` instead — see the invariant below.
   - **`t = E(k)` for some key `k`, but the op does not apply** — guards false, payload undecryptable, or preimage/tag mismatch → verdict `rejected` (or `invalid`), and **`attempt(k) += 1`**.
   - **`t` matches no current expected tag** (it matches a *historical* tag, or nothing) → verdict `stale`: no state change. Covers cross-version races, late duplicates, and garbage aimed at nothing.

   **Lineage-advance invariant:** *every committed op whose tag equals `E(k)` at its fold position strictly advances `k`'s lineage* — by version-reset when it applies a mutation to `k`, by `attempt(k) += 1` in every other case (rejected, **invalid**, or applied without mutating `k`). The rule is **universal over the committed set** — it does not care *why* an op failed, only that its tag matched; even Byzantine-committed garbage burns at most one attempt (containment, RESILIENCE §3). No tag is ever expected twice, so a decided slot can never block a lineage. (Without the applied-without-mutation clause, an op that wins `k`'s slot but mutates only *other* keys would leave `E(k)` unchanged with its slot decided — a wedge. Without the invalid clause, a revoked author's receipted-then-invalidated op is the same wedge.)

   Attribution is deterministic and needs **no eager global scan**: evaluating an op that names key `k` requires only replaying `k`'s lineage over the committed prefix — count, in order, the prior committed ops whose tags match `k`'s successive expected tags. Every client decrypts the same committed set, hence derives the same key universe and the same counts. An *undecryptable* op is never attributed for its own sake; it participates only by tag-equality when some key's lineage replay encounters it — the PRF is invertible to no one, but *checkable* by anyone holding the slot secret.

Because the fold is deterministic, **every client computes byte-identical state *and* identical verdicts for the same committed set.** LWW is per-key: two ops on *different* keys both survive; two on the *same* key resolve by `(hlc, author, seq, op_hash)` with the loser retained in history (deletes are tombstones). The merge is order-insensitive given the committed set — the CRDT / strong-eventual-consistency property. What *freezes* at finality (§9) is **state and each op's applied/not-applied bit**: below the finality frontier the committed set can no longer change, so neither can they. Diagnostic sub-labels are one shade softer: an *undecryptable* op filed as `stale` may later be recognized as having consumed some key's slot, once a subsequent op reveals that key — the label refines; the state and applied-bits never move.

### Why `attempt` exists (the wedge, closed)

Slots are consumed at vote time (§8) but succeed or fail at fold time, and zero-knowledge nodes can never learn which. Without `attempt`, an op that wins its slot and then fails its guards (a multi-key transaction whose guard on another key is false) — or applies without mutating its slot key (a guard-only slot) — would leave the key's version unchanged with its only slot spent: a **permanent CAS wedge**, adversarially triggerable by any authorized client and reachable by honest ones. With the lineage-advance invariant, every consumed slot advances the tag lineage: the next CAS reads `(version, attempt)` from the fold and gets a fresh tag. Nothing wedges; nodes learn nothing new.

---

## 7. Predicates & slots under zero-knowledge

A predicate has two halves, and only one is ever visible to a node:

| Half | Meaning | Evaluated by | On |
|---|---|---|---|
| **Slot** (`slot_tag`) | "this op is the unique successor to `(key, version, attempt)`" | **nodes** (§8 ballot voting) | opaque tag — never plaintext |
| **Condition** (`guards`) | "value == X", "version == V", "absent", "counter > N", … | **clients**, in the fold | decrypted plaintext |

**Nodes never evaluate a predicate and never see plaintext.** They run single-decree agreement keyed on an opaque handle (equality comparison only). The condition's *truth* is a deterministic fold-time verdict, agreed by all clients.

### Slot tags must be keyed (not a plain hash)

Config keys are low-entropy (`workflow/job-42/state`). A plain hash of the preimage would be dictionary-attackable by nodes, since `version` is a public `op_hash`. Therefore:

```
slot_tag = PRF( group_slot_secret[keyepoch] ,  key ‖ version ‖ attempt )
           # version = ⊥ (fixed sentinel) while the key is absent — creation CAS is just attempt 0 on ⊥
```

All clients compute the *same* tag for the same contention; nodes compare tags for equality but cannot invert or brute-force them. Closes the low-entropy leak. Creation races (locks — the most common CAS) need no special case: the absent key's lineage starts at `(⊥, 0)`.

### Two contention cases (both deterministic, both at most one winner)

- **Same-lineage race** (both clients read `key` at the same `(version, attempt)`): identical `slot_tag` → single-decree agreement picks exactly one op for that slot (§8) → the loser learns the decided op, re-reads, retries on the next lineage point.
- **Cross-lineage race** (a stale reader): different `slot_tags` → both may commit → the fold marks the stale one `stale` (its tag is no longer any key's expected tag at its fold position).
- **Cross-epoch race** (a key-rotation window): the same `(key, version, attempt)` under two `keyepoch`s yields *different* tags, so node-level exclusion doesn't bite — both may commit, and the fold resolves it exactly like a cross-lineage race (first in fold order advances the lineage, the second goes `stale`). Rotation degrades the optimization, never the outcome.

A slot, once decided, is decided forever — but a decided-and-failed slot only costs an `attempt` increment, never a wedge (§6).

### Leakage boundary (a decision, not an accident)

Nodes never learn keys or values. They **do** learn structural metadata: that a write happened, by which author, when (`hlc`), its causal links (`deps`), and that two ops contend for the same slot (tag equality). They also see the plaintext control plane (§5) — roster, certs, checkpoints — by design. Compaction (§12) adds one declared increment: the checkpoint's dead-set delta teaches nodes which ops superseded one another (grouping and lifetime structure), and retention itself marks which ciphertexts are live state. Hiding the access pattern is ORAM/mixnet territory — **out of scope** for a config store.

### Layered payload encryption — the application inner layer (NOTES 38)

The group AEAD is the protocol's confidentiality **floor, not its ceiling**: an application may encrypt values (and pseudonymize path components) under its own keys *before* they enter the `Txn` — a **lane-1 payload convention** (§16), invisible to the protocol, because the fold interprets paths only by byte-equality and values not at all. This makes the visibility ladder explicit:

| Party | Sees |
|---|---|
| storage nodes / network | envelope metadata + control plane only (structural ZK, above) |
| group-keyring holders — manager, compactor, every authorized client | the **shape**: key identities (or their app-PRF pseudonyms), mutation kinds, guard structure, value sizes, supersession/churn |
| the application's own key holders | the fields |

Constraints, stated once: **(a)** key bytes must be stable per key — a per-app PRF of the path works verbatim, since slot tags and fold attribution are computed over path bytes; **(b)** `value_eq` guards compare inner-*ciphertext* bytes — randomized inner encryption breaks them and deterministic inner encryption leaks value-equality, so the convention for inner-encrypted fields is **version-CAS**, which is unaffected (versions are envelope hashes); **(c)** any future rich guard vocabulary (§17) evaluates at the group layer and cannot see through the inner layer — a field wanting such guards stays group-layer-visible by choice. Two consequences worth their weight: the compactor's §12 blast radius drops from "reads data" to "sees shape" — delegation gets cheaper as applications adopt the layer — and confidentiality of inner-encrypted fields survives even **root** compromise, the one cell of RESILIENCE §3.7 the protocol alone cannot flip (app-key custody permitting).

---

## 8. Durability & commitment (per-slot ballots, receipts, QC)

**Every write must be quorum-committed** — nothing is real until a quorum holds it.

### Receipts

When a node accepts an op it returns a **receipt**:

```
receipt = BLS-sign(node_sk, op_hash ‖ config_epoch ‖ ballot)
```

`ballot = 0` for blind writes (no slot — always receipted, subject only to §9's skew window; the fold picks the survivor by LWW). For slotted ops, `ballot` is the slot ballot at which the node accepted (below).

### Per-slot single-decree agreement (the real thing, with ballots)

Revision 1 used one irrevocable vote per slot. That is safe but not live: votes can split with no winner (n=5, one node down, a 2–2 race), and with nothing committed the retry needs the *same* tag — a deadlock under the design's own fault model. The fix is the standard one: each `slot_tag` names a **single-decree Paxos instance** in which nodes are acceptors, run with **both phases, always**. Ballots are `(round ≥ 1, priority)` with `priority = h(slot_tag ‖ client_fp)` — a deterministic per-slot tiebreak, computed identically by every party holding the tag, so *which* of two fixed contenders wins same-round ties varies per slot instead of following a fixed fingerprint order (starvation-free; not a VRF — nothing is gained by grinding, since fingerprints are manager-certified). Ballots order lexicographically; the `(0, ·)` family is reserved (the blind-write sentinel and a slot's unpromised initial state).

> **Revision 5 note — the ballot-0 fast path is gone.** Rev 4 let a client skip `prepare` and submit directly at ballot 0 (1 RTT uncontended). The M3 simulation showed that this is a *Fast Paxos fast round on bare majority quorums*: two honest un-prepared ballot-0 accepts can interleave so that recovery cannot tell the chosen op from an unchosen one (Lamport's "case 3 — we are stuck"), and two valid QCs for one slot result with no misbehavior anywhere (NOTES item 21). Repairing it costs `N − ⌊N/4⌋` fast quorums (all 3 of 3!) or a per-slot leader. Dropped instead: DudeFS is **ultra-durable, not low-latency** — at config-store cadence (seconds to hours), two round trips are the cheaper price, and classic per-slot Paxos makes every claim below unconditionally true. See COMPARISON.md.

Per `slot_tag`, each node durably keeps `(promised, accepted_ballot, accepted_op)`:

- **Proposal (classic Paxos, two phases, ~two round trips):** the client picks a ballot `b = (r ≥ 1, priority)` above any it has seen and runs: `prepare(t, b)` → nodes with `promised < b` set `promised := b` and reply with their `(accepted_ballot, accepted_op)`; from a quorum of promises the client MUST propose the accepted op with the highest ballot if any was reported (even if it's a rival's op — envelopes are self-contained and re-proposable), else its own; `accept(t, b, op)` → nodes with `promised ≤ b` record `(b, op)` and issue a receipt at ballot `b`. A promise reporting a rival's accepted op is how the loser learns fast — it completes the rival's decision, observes, and retries on the advanced lineage.
- **Decision:** an op is decided for slot `t` when a **quorum of receipts at the same ballot** exists for it. Quorum intersection + the promise rule give the single-decree property: no other op can ever be decided for `t` — every accept is prepared, so this is the classic theorem, with no fast-round caveat.
- Dueling proposers can livelock in theory; the designed escape is **deterministic jitter plus timeout escalation**: re-`prepare` is delayed by a jitter keyed on `(priority, round)` (kernel-pure — no RNG; round 1 has zero backoff so the happy path stays prompt), and a per-round timeout escalates the round even when Nacks are lost. Because the jitter is a function of public data, an adaptive network adversary could compute both duelers' schedules offline (RESILIENCE §3.6) — real drivers therefore mix true entropy into retry timing, which is free: timers are client policy, never protocol (PROTOCOL §4).

A node that signs receipts for two different ops at the same `(t, ballot)` has produced a portable equivocation proof → manager ejects it (§4).

### Safety layering (what the slot machinery is — and is not)

Per-slot agreement is the **coordination layer**: it decides the common case in two round trips and lets losers learn fast (from promises). It is *not* the state-safety layer. Even if exclusion were somehow violated — an equivocating acceptor minting two same-slot QCs (see [RESILIENCE.md](RESILIENCE.md)) — the fold's lineage-advance invariant collapses the duplicates deterministically: the first in fold order advances the lineage, the rest go `stale`. State safety and CAS *success* (§9) rest on fold + finality alone; the slot layer buys latency and liveness, and violating it yields proofs, not divergence.

### Quorum Certificate

```
QC {
  op_hash
  config_epoch                 # which roster this QC is measured against
  ballot                       # 0 for blind writes; the deciding ballot for slotted ops
  signer_bitmap                # which nodes signed
  agg_sig:  BLS-aggregate(receipts)   # all over the identical message — one pairing check
}
```

- **Verification (any client):** look up the roster at `config_epoch` (it's in the control plane), check the bitmap names a **majority** of that roster, verify the single aggregated signature over `op_hash ‖ config_epoch ‖ ballot`.
- **The QC is not the consensus — it's the receipt of it.** Agreement lives in what acceptors *refuse to sign* (§ ballots above); the signature scheme only compresses the evidence. The QC is therefore specified abstractly — *a quorum multi-signature over one identical message plus a signer set* — behind the `MultiSig` interface (ARCHITECTURE.md, L0), with two valid instantiations: a pairing-based aggregate (constant-size, one pairing check, PoP hygiene) or a concatenated signature list (~450 B at n=7, batch-verifiable). **Decided (revised for the Python POC): v1 ships the concatenated Ed25519 list** — vendorable as a single pure-Python file, stdlib-adjacent, no PoP. **BLS12-381 aggregate remains the target suite** (constant-size forever-log artifacts, clean bitmap semantics) and lands later as an L0 substitution + lane-3 suite bump (§16) touching no protocol logic — at which point PoP at node-cert issuance becomes required (§3).
- An op is **committed** iff it carries a valid QC. A QC is single-epoch by construction; for ops in flight across a roster change, see §13.
- Commitment is decided by **quorum vote, never by the clock** (the clock only sorts). Commitment means *durable*; it does not yet mean *succeeded* — that is finality (§9).

### Acceptor-state durability & GC

**Persist commitments, derive views (NOTES 47):** a value is durable iff it *justifies a signature* — slot state, the attested floor, the issuance ledger (§8 rev F18), the adopted cut + horizon (§12), and the **config epoch** (it stamps every receipt/watermark); everything frontier-shaped (`heads()`, summaries, baseline digests, authorization state) is a **derived view, recomputed from the durable base and never materialized** — a persisted view has many writers and one missed co-update makes an honest node *sign a false frontier claim*, while derivation's worst case is recompute cost. Materialization is permitted only single-writer and in the same transaction as its base (the horizon and epoch pattern). Specifically: slot state `(promised, accepted_ballot, accepted_op)` and the node's highest **attested watermark floor** (§9) **must survive crash-restart** — quorum intersection stands on the former, finality on the latter — and a node **signs only after fsync**: no receipt, promise, or watermark may ever outlive the state that justified it. All of it lives in one durability domain with the node's signing key: **lose any part, lose the identity** — a node that loses durable state must not resume it (§13; full inventory in [RESILIENCE.md](RESILIENCE.md)). Slot state is GC'd **only below the checkpoint horizon** (§12): once nodes refuse all receipts below the horizon, no late contender can resurrect a GC'd slot, so forgetting it is safe. (GC-on-successor-commit alone would be unsound: after every node forgets, a late contender could win a second QC for a spent slot.) GC is lazy, but dead state must not *act*: on `prepare`, per-slot state whose `accepted_op.hlc` lies below the node's checkpoint horizon is **void** — discard it and answer as a fresh slot. Without this, a reborn tag (§12: a key deleted below the cut restarts at `(⊥, 0)`, so its recreation tag is byte-identical to the already-decided creation tag) hitting not-yet-GC'd acceptor state would force every proposer, via the promise rule, to re-propose a dead below-horizon op that can never commit again — a livelock lasting until every quorum node happens to GC (NOTES item 27). Clients guard symmetrically: a promise reporting an accepted op whose `hlc` is below the checkpoint horizon is treated as reporting no accept — the `PROMISE` therefore carries the accepted op's `hlc` alongside its ballot and hash (reported by the acceptor, which holds the envelope; deriving it client-side would cost a `FETCH` round trip that fails precisely in the GC'd case the guard exists for — and a signed misreport is portable evidence like any other). **The horizon is not folklore: it is the checkpoint's explicit `horizon` field** — the finality frontier `F` its cut was sealed at (§12) — and both sides source it from the latest *committed* checkpoint they hold: `advance_horizon(F)` node-side, the quorum config client-side. Boundary strictness is deliberate and must stay strict: void/ignore only **strictly below** `F`. An op at exactly `hlc == F` may still be newly committable (`hlc == floor` passes the past gate), so voiding at equality could discard a live accept — a safety hole; not voiding at equality merely leaves a measure-zero livelock candidate to the next conveyor step — a liveness rounding error. Three layers, one rule: the acceptor voids stale slot state on `prepare`, the client ignores below-horizon reports (against nodes that lag their horizon), and after GC the acceptor refuses to *newly receipt* below the horizon (§12's backstop — wired with GC at M7).

### Server-to-server gossip / anti-entropy

- Nodes reconcile by exchanging summaries (per-author `(head_seq, head_hash)`, held checkpoints, receipt sets, watermarks) and shipping the diff; hash-linking lets the receiver validate the run without trusting the sender.
- **Everything is idempotent and order-free:** a duplicate op/receipt/checkpoint is a no-op; nodes accumulate data-plane bytes and fold only the control plane.
- The watermark floor (§9) governs **issuing new receipts** only — gossiped ops carrying already-issued receipts are always accepted and stored, or convergence would break.
- **Receipts let a node act for a client:** a client may push an op to *one* node and go offline; gossip propagates it, peers issue their own receipts (skew window permitting), and any node assembles the QC on the client's behalf. The client polls later for the QC.
- Honest nuance: single-push-then-trust-gossip is *convenience*, not *guarantee* (a rogue node could withhold, and the skew window is ticking — §9). A client wanting a hard guarantee pushes to a quorum directly. Either way, the verified artifact is the same QC.

---

## 9. Finality (watermarks — when verdicts freeze)

Commitment makes an op durable. But the fold order is by `hlc`, and a *lower*-`hlc` op can commit *later* in real time (pushed to one node, gossip-assembled slowly) — inserting itself **before** already-committed ops and flipping their guard verdicts. Safety is never at risk (all clients re-fold identically), but "my CAS succeeded" must not be claimable while the order beneath it can still change. Finality bounds that window.

- Each node maintains a high-water mark `hw` = the highest `hlc` it has ever receipted or stored via gossip, and a **floor** `= max(hw, local_now) − δ`, enforcing the **skew window δ** in both directions on *new receipts*:
  - refuse `op.hlc > local_now + δ` (future-dated), and
  - refuse `op.hlc < floor` (past-dated beneath its promise).

  The `local_now` term matters: a floor is a *promise about future refusals*, and a node can safely make it on wall-clock alone. Without it (`floor = hw − δ`, as an earlier revision had), floors freeze on an idle system and **the last write never finalizes** — finality would require later writes. With it, floors advance in real time and the last write finalizes after ≈ δ + one watermark round. (This is Spanner's commit-wait shape, reached from the opposite direction: they delay visibility until the uncertainty window passes; we delay *verdict-finality* until the refusal window passes.)
- Nodes publish signed, monotone **watermark statements**: `WM = sign(node_sk, hlc_floor ‖ config_epoch)`, attached to gossip and read responses and served fresh on demand (plain signatures, not aggregated — these are cheap and per-node; no continuous gossip needed for finality to advance). Floors are **monotone and durable**: a node never signs a floor below one it has signed before, and never issues a receipt below a floor it has attested — doing so is two signed statements in contradiction, the same portable-proof family as §4.
- **Finality rule:** an `hlc` value `h` is **final** once a client holds watermark statements with `hlc_floor ≥ h` from a **quorum**. From then on, no op with `hlc < h` can ever gather a fresh quorum of receipts (any quorum intersects the attesting one, and floors only rise), and every op *already* committed below `h` is observable by any quorum read (its receipts sit at a quorum). Hence the committed set below `h` — and every fold verdict in it — is frozen.
- **Consequences, stated plainly:**
  - A **CAS is successful** = its QC exists **and** the finality frontier has passed its `hlc` **and** its fold verdict is `applied`. In the healthy case the frontier passes almost immediately; the client's confirmation is one watermark round.
  - An op that lingers below quorum receipts until the frontier passes it is **dead** — it can never commit; its author re-submits with a fresh `hlc` (its per-author chain entry remains, structurally valid but permanently uncommitted; the fold ignores uncommitted ops by definition).
  - The offline-single-push convenience (§8) is bounded by δ: author-then-vanish for longer than the skew window risks the op dying. That is the deliberate price of bounded reordering; pick δ generous (minutes, not milliseconds) since this is a config store, not a message bus.
  - The concrete value of δ is an open question (§16), but its *semantics* are not.

---

## 10. Reads

- **Local read** — fold the local log. Fast, possibly stale (serializable, not linearizable).
- **Quorum read** — fetch from a quorum: per-author frontiers, ops+QCs the client lacks, and current watermark statements; then fold locally. (Nodes cannot serve "a key" — they don't know keys. A read is a *frontier* exchange plus a local fold.) Since every committed op's receipts live at a quorum, a quorum read observes every committed op; the accompanying watermarks establish which prefix is final.
- **Linearizable read** = quorum read taken at a final frontier: report state at the highest `h` covered by quorum watermarks.
- **A correct CAS is: quorum read → obtain the key's `(version, attempt)` at a final frontier → submit (§8) → QC → await frontier past its `hlc` → read verdict.** Skipping the final-frontier read just means the op will be `stale` or `rejected` at fold time — safe, wasted effort.

---

## 11. Ordering vs. commitment vs. finality (don't conflate)

| Concern | Mechanism | Decides |
|---|---|---|
| **Ordering** (the sort) | HLC `(hlc, author, seq, op_hash)` + skew window | *where* an op sits in the fold |
| **Commitment** (the agreement) | quorum receipts → QC; per-slot ballots | *whether* an op is durable / which slot contender is decided |
| **Finality** (the freeze) | quorum watermark statements | *when* verdicts stop moving |

Using wallclock to pick CAS winners is the classic split-brain bug (partitions can't compare clocks). Using QC-time to claim CAS *success* was revision 1's subtler cousin (late low-`hlc` commits reorder the fold under you). **Clock sorts, quorum decides, watermark freezes.**

---

## 12. Compaction (log-compaction — the conveyor cut)

Compaction is a **selection, not a rewrite** — and never a deletion of anything live. The log is compacted **in place**: every live key's *winner op* (the op whose hash is the key's current `version`) is retained at its original position, and everything below the cut that has been superseded is discarded. The log goes **sparse**; nothing is materialized, re-encrypted, or shipped. There is no snapshot blob — at the §1 scale ceiling (5–10 GB of live state) materialize-and-ship would push gigabytes to every node and every bootstrap on every checkpoint, for zero information gain over the ops already in place. The shape is Kafka's compacted topic (retained records keep their offsets; COMPARISON row 20); the cut is a **conveyor** — advanced continuously in small, cheap steps, not minted as a rare heavyweight event.

```
Checkpoint {                          # control op — requires the `compact` capability (§15)
  cut:        { author_i: (seq_i, head_hash_i), ... }   # frontier being sealed — must be entirely FINAL (§9)
                                                        #   (sole exception: the recovery variant seals the salvage
                                                        #    frontier by root fiat — RESILIENCE §2.2)
  horizon:    F                                         # the finality frontier the cut was sealed at (§9): every op
                                                        #   ≤ cut has hlc ≤ F. THE horizon value for §8's void rule,
                                                        #   the client no-accept guard, and the post-GC receipt floor —
                                                        #   carried explicitly, never derived (NOTES 34)
  state_root: merkle_root(folded state at cut)          # audit anchor: sorted live (key, value, version, attempt)
  dead:       [op_hash, ...]                            # NEWLY dead since the previous checkpoint (∝ churn)
  retained:   { author_i: (count_i, digest_i), ... }    # commitment to the FULL retained set ≤ cut (plaintext op-hashes)
  attempts:   ciphertext({ key: attempt, ... })         # sparse sidecar: live keys with NONZERO attempt at the cut
  keyepoch, hlc, prev(author chain), sig
}
```

- **Retention rule.** An op at-or-below the cut is **retained** iff one of:
  1. it is the **winner** of at least one key live at the cut (its hash is that key's `version`) — multi-key winners are retained whole; their superseded mutations on *other* keys are corrected by those keys' own later winners in fold order;
  2. it is the **tombstone-winner of a dead key that some retained op's mutations touch** — the *resurrection mask*: without it, a retained multi-key winner would replay a mutation onto a key whose deletion was GC'd, and bootstrap clients would resurrect a key that full-history clients hold deleted. A mask tombstone is retained *only* to make the bootstrap fold yield "absent"; it is **not** a lineage anchor — the dead key's lineage still resets to `(⊥, 0)` at the barrier;
  3. it belongs to the **control-plane liveness set**: the latest checkpoint, the cert/revocation history, **wrap-sets** (the log is the key-distribution channel — load-bearing for as long as any epoch's ciphertext is live, §3 / PROTOCOL §3.3), and the current roster + endpoint records.

  Everything else at-or-below the cut is **dead**, published incrementally as the `dead` delta. Each checkpoint's `retained` commitment covers the *full* retained set, so only the latest checkpoint need ever survive; the `dead` delta is just that step's GC work.
- **Zero-knowledge forces the oracle upward.** A node cannot see that an op was overwritten — supersession is invisible to a party that cannot decrypt — so nodes can never compact themselves. The **compactor** folds (it holds the group key), computes the dead set as an incremental tail-fold since the previous cut, and signs. Compaction cost is proportional to churn, never to state.
- **The conveyor step is incremental by contract — full-history recompute is not an option (NOTES 34/Q4).** After the first GC anywhere, no party holds full history, so the compactor's inputs are contractually: the previous checkpoint's retained set + `attempts` sidecar (its warm barrier, reconstructed mutations-only exactly as a bootstrap client would), plus the committed tail between the previous cut and the new one. `dead = (prev_retained ∪ covered_tail) ∖ new_retained` — a previously-dead op is never re-listed, so each delta is ∝ churn-since-last-cut (re-listing would grow checkpoints ∝ total history). Note a prev-retained op *can* die in this step (a winner superseded by a tail op; a mask whose referencing winner died) — that is the delta working as intended, since each checkpoint's `retained` commitment independently covers the full set. The precondition — no input op at-or-below the previous cut that is not in its retained set — is asserted, not assumed. The genesis-first checkpoint is the degenerate case (`prev = ∅`: fold the full covered set).
- **The compactor is a delegated identity — the root stays offline.** Routine conveyor operation runs under a `compact`-capability cert (§15) plus the group key, never the root key (§3). Compromise blast radius: wrongful-but-auditable GC, plus the data confidentiality any authorized client already has — never roster, cert, or revocation authority.
- **Cut-lag policy (the audit window).** The cut trails the finality frontier by a window **W** (`cut ≤ frontier − W`): W is the time resident full-history clients have to fold history and audit a checkpoint *before* nodes GC the evidence beneath it. W is a settable constant in the δ family — semantics fixed here, value open (§17).
- **The cut must be final before it is sealed.** The compactor checkpoints only at a frontier covered by quorum watermarks — so no committed-but-unseen op can ever sort below the cut. This is what makes the next rule sound:
- **The barrier sits immediately above the cut — not at the checkpoint op's own fold position.** Because the cut is entirely final, every op it covers sorts below every op that can still commit (finality bounds their `hlc`s), so the fold is well-defined as: fold the covered set, apply the barrier, fold the tail in total order. The checkpoint op itself is an ordinary control op in the tail; only its *pinned cut* places the barrier. Ops that commit while the compactor is minting the checkpoint (`hlc` above the cut's finality frontier but below the checkpoint op's `hlc`) are tail ops and fold **above** the barrier — for everyone.
- **Derive-and-verify.** Bootstrap clients fold `retained ∘ tail` (bootstrap semantics below). Full-history clients *derive* the same barrier state from raw history — applying tombstone-death for keys dead at-or-below the cut — and **verify** the checkpoint by recomputing `state_root`. The two agree byte-for-byte whenever the checkpoint is honest; a mismatch is a corrupt checkpoint — a loud, portable audit failure, never something the fold silently adopts.
- **Tombstones die at the barrier — and so does attribution to dead keys.** A key deleted at-or-below the cut has no winner in the retained set (mask tombstones notwithstanding), and its lineage restarts at `(⊥, 0)`; likewise a never-valued key whose `(⊥, n)` lineage was only ever attempt-advanced resets to `(⊥, 0)`. The **key universe resets with it**: above the barrier, a key is attributable only if it is live at the barrier or named by an op above the cut — otherwise bootstrap clients (who cannot decrypt GC'd history) and full-history clients would attribute differently. Consequence: a CAS computed against a tombstone's version that commits *after* the checkpoint folds as `stale` — retry against the fresh lineage. Rare, safe, bounded by conveyor cadence. Tombstones written *above* the cut survive to the next checkpoint.
- **Live-key lineages carry across the barrier exactly — via the `attempts` sidecar.** A live key's lineage at the barrier is `(winner_hash, attempts[key] or 0)`. The sidecar is mandatory, not an optimization: the ops that justify a nonzero `attempt` (rejected, invalid, and guard-only slot consumers) are precisely dead ops, so without it bootstrap clients would derive `attempt = 0` where full-history clients hold `n > 0`, the two would compute different expected tags, and A4 would fail. It stays tiny because `attempt` resets on every applied write — only keys with consumed-but-unapplied slots since their last write appear.
- **Reborn tags (absent-key lineages) — acknowledged and contained.** A key deleted below the cut restarts at `(⊥, 0)` under the same `keyepoch`, so its recreation tag is byte-identical to its original creation tag, whose slot was already decided. This is harmless at the fold (the barrier scopes attribution) and harmless at the acceptor **given §8's void rule** (per-slot state below the horizon is void on `prepare`). FORMAL B1 is scoped accordingly: per-barrier-interval uniqueness for reborn absent-key tags, global uniqueness otherwise. Live-key tags never rebirth (the sidecar carries their lineage exactly).
- **GC rule (node-side — lazy, local, uncoordinated).** On observing a *quorum-committed* checkpoint, a node may drop: every op named in `dead`; **all receipts and QCs at-or-below the cut** (the checkpoint's `retained` commitment vouches for below-cut commitment — trust surface below); and slot acceptor-state consumed at-or-below the cut (§8, with the void rule making un-GC'd remnants inert). It keeps the latest checkpoint, the retained envelopes, the control-plane liveness set, and the pinned head hashes so later ops still `prev`-validate across the boundary. After GC, nodes refuse receipts for any op with `hlc` below the checkpoint horizon (a floor the watermark rule already implies, restated as a backstop). Clients apply the same `dead` delta to their caches — sync cost is O(live state + tail), never O(history).
- **Pinned heads — the cut IS the pin (NOTES 34/Q1).** The checkpoint's `cut` — per-author `(seq, hash)` — is the pinned-head structure; there is no separate artifact. On adopting a committed checkpoint a node **persists the active cut inside its durability domain** (the pin is load-bearing across crash-restart, like everything else in §8). Cut-aware gates: (a) `heads()` anchors each author's dense tail-run at `cut_seq + 1`, seeded by the pinned hash, instead of at `seq == 0` — and reports the pinned `(seq, hash)` itself when no tail op extends it, so an author never vanishes from the frontier because its below-cut body was GC'd; frontier claims at-or-below the cut are vouched by the checkpoint's `retained` commitment, not by contiguous serving (amending the §8/PROTOCOL §2.1 "no orphan-island heads" invariant, which continues to hold verbatim above the cut). (b) `append()` admits an op whose predecessor has `seq − 1 ≤ cut_seq[author]` without holding that predecessor (PROTOCOL §2.1's contiguity exemption, stated precisely: exemption iff `seq ≤ cut_seq + 1`); authors absent from the cut anchor at `seq == 0` as before. (c) The pin is **metadata, not an op row** — the cut-boundary op itself may be superseded, dead, and dropped; the pin survives it. Granularity is per-author `(seq, hash)`, deliberately: it is already the checkpoint's signed `cut` schema, it is tiny at the §1 scale (≤ ~10 authors), and it preserves the localize-to-one-author property of the `retained` digests (NOTES 29c). A merkle-pinned frontier object is rejected — it solves an author-cardinality scale this design does not have, at the cost of the per-author diff key.
- **Baseline completeness is checkpoint-defined: `retained = covered ∖ dead` (NOTES 34/Q2).** Every below-cut digest computation — `SUMMARY`'s retained digests, baseline verification at intake — is over a party's held covered set **minus the ops the adopted checkpoint names dead**, never over raw holdings: a node lagging GC legitimately still holds dead ops, and a raw-holdings digest would false-reject a complete baseline (worse, a GC'd node and a lazy peer would ping-pong dead envelopes through anti-entropy forever). Dead deltas apply in checkpoint-chain order; a party that missed intermediate checkpoints does not reconstruct unknown deltas — it resyncs the sparse baseline whole (`PULL` against the digests) and re-verifies. A digest mismatch at the node/anti-entropy layer is a **sync signal** (drop what the delta names, pull what the digest localizes, re-verify), never by itself a rejection; it hardens into a rejection only at bootstrap-client intake, where the client holds exactly the retained set and a persistent mismatch has no honest explanation left. "Have ⊇ committed" superset semantics is rejected as unimplementable: a `(count, digest)` commitment can test equality of the projection, not superset membership.
- **Bootstrap.** A new client pulls the retained set (sparse `PULL`s, verified per-author against the `retained` digests — an omission localizes to an author, not to a failed 10 GB fetch), folds the retained winners' **mutations only** in `(hlc, author, seq, op_hash)` order — **no guard re-evaluation** (it is reading settled state, not re-deciding CAS; the guards' truth was consumed at the original fold position, whose context is gone) — applies the `attempts` sidecar, verifies `state_root`, then folds the tail normally above the barrier.
- **Trust surface — why trusting the checkpoint is sound (and smaller than it was).** Compaction **cannot alter a byte; it can only select.** Retained winners are the original author-signed envelopes: fabricating a value would require forging a client signature, so the compactor's entire power over sealed history is omission/selection among genuinely-authored ops — "a compression channel, never a write channel" is now structural, not merely audited. A bootstrap client *verifies*: genesis → the unbroken manager/compactor control chain → the checkpoint signature; every retained op's author signature, cert chain, and `(hlc, seq)` provenance; the `retained` digests; and the recomputed `state_root`. What it *trusts* is exactly the **dead set** — that nothing live was omitted and nothing superseded was kept — and that residue is what resident full-history clients audit continuously, checkpoint by checkpoint, inside the W window. Checkpoint-sync here costs zero trust relative to genesis-replay: genesis and checkpoint are signed by the same root, so replaying history would terminate in the same anchor (this is weak-subjectivity sync made free by a pre-existing root; history replay's only marginal value — catching manager misbehavior along the way — is provided by the residents' standing audit).
- **Rogue-delete protection without a retention window:** a rogue client can only write tombstones — visible (signed, attributed) and reversible in the live log. Only the `compact` capability mints checkpoints, so deletions never become permanent except by that authority's action. No time-based expiry exists (this is a config dictionary; values do not age off).
- **Declared costs.** (a) **Epoch-key history is load-bearing forever**: retained winners never re-encrypt, so clients must hold every `keyepoch` back to the oldest live winner, and a leaked old epoch key exposes everything still live from that epoch — healed only by overwriting. (b) **Mutation-decode back-compat**: lane-2 upgrades must keep the mutation vocabulary of every `pver` still present in the retained set (§16). The recorded escape hatch for both is a manager **re-anchor** op — re-encrypt and re-author a winner under the current epoch/pver, original noted by reference — with its provenance cost declared; not in v1.
- **Idempotent:** content-addressed; applying a checkpoint twice is a no-op.

---

## 13. Membership (dynamic roster, no split-brain)

The roster is the one thing that **must** be strictly, consistently ordered — it is the config log, and the classic split-brain source. Roster changes are manager-signed **control ops**.

- **Roster size is always odd** (see §1). Nodes and clients reject roster ops proposing an even voting-member count. Learners are non-voting and don't count.
- **Joint quorum:** a change `C_old → C_new` activates only once it holds a QC from **a quorum of the old roster AND a quorum of the new roster** (two single-epoch QCs — receipts under `epoch` and `epoch+1` respectively; bitmaps never mix rosters). Rare + manager-serialized ⇒ dual-quorum cost is negligible, and joint commit is safe for arbitrary jumps (even 1→3) with no fragile "one node at a time" subtleties.
- **Roster transitions are slotted — publicly.** A roster op for `e → e+1` carries the *plaintext* slot tag `H("roster" ‖ e)` (the roster is public; this tag needs no PRF secrecy), contested on the **old** roster through the same per-slot ballot machinery as any CAS (§8). At most one change can therefore ever activate out of epoch `e` — two competing roster ops (a crashed-and-retried manager, an amnesiac one) cannot both reach joint quorum. Nodes additionally receipt a roster op only if its `from_epoch` equals their current epoch.
- **Data-possession barrier (agreement is not enough):** the roster op carries a **sync frontier** (per-author `(seq, hash)`, taken by the manager from a final quorum read). A node in the *new* roster issues its receipt for the roster op **only after verifying it holds every committed op and QC at-or-below that frontier**. The new-roster QC is therefore simultaneously an agreement proof *and* a data-possession proof — a shrink or wholesale replacement cannot strand committed writes on departing nodes. **The barrier is cut-relative (NOTES 34, finding 11):** at-or-below the checkpoint cut, possession is verified **by baseline completeness** (the §12 `retained` digests — dead bodies, receipts, and QCs are legitimately absent there), not by per-op holdings; the per-op contiguous-head-plus-exact-frontier-op check applies only above the cut. Without this the first roster change after GC wedges (a B4 liveness break): an idle author's frontier head sinks below the cut, its superseded envelope is GC'd everywhere, and no node — however honest and caught-up — could ever pass the barrier.
- **Add is two-phase:** a new node joins as a non-voting **learner**, catches up to baseline + tail (which is what lets it honestly pass the possession barrier), and is only then promoted via a roster op. Prevents an empty node from hollowing out durability by "acking" data it doesn't hold.
- **In-flight ops across a change:** QCs are single-epoch. An op accepted-but-not-yet-committed when the change activates continues under the new epoch: nodes **re-issue receipts under the new `config_epoch`** for ops and slot-accepts they already hold (idempotent — the underlying acceptor state `(promised, accepted)` is untouched and carries across epochs unchanged). Clients then assemble a fresh single-epoch QC. A stalled slot from the old epoch is completed by any client running §8 recovery against the new roster.
- **The recovery exception (the only fiat in the roster rules):** catastrophic loss of the old quorum (RESILIENCE §2.2) is the *sole* case where a roster op activates without the old-roster half of the joint QC — the old quorum no longer exists to sign it. It activates by root fiat, anchored to the recovery checkpoint (§12's recovery variant), as a visibly distinct epoch fence in the log forever. Nothing else ever bypasses the joint rule. **Concretely (NOTES 36):** the roster op carries a `recovery` field naming the recovery checkpoint's op hash, and a recovery-marked roster op is **root-only** — never authorizable via a delegated `manage-roster` cert, because fiat activation bypasses the joint-quorum safeguard that makes that delegation safe in the first place. Node-side, activation on holding the validated root-signed pair (recovery checkpoint + the roster op referencing it) **is `activate_epoch` with a second trigger** — the same monotone epoch switch, slot state untouched; the only new surface is the validate-fence-then-activate step. The *park* (RESILIENCE §2.3) is its emergent effect, not an extra rule: once switched, a node stamps receipts and watermarks `e+1`, which epoch-checking clients of the old world reject — old-epoch coordination dies wherever the fence has propagated, while reads and gossip continue (serving history is always safe). Distinct from the possession barrier: the barrier gates *joining* the new roster; the fence-trigger parks *everyone who sees it*, member or not.
- **Identity retirement:** a node that loses its durable state (destructive fault) **must not rejoin under its old key** — its slot acceptor-state is what quorum intersection stands on, and an amnesiac acceptor can double-vote. Key and acceptor state share one durability domain (§8), so total loss normally takes the key too; as a backstop the procedure is: manager revokes the old node cert, the machine generates a fresh keypair, and rejoins as a learner. A wiped node that *does* resume and double-votes produces an equivocation proof and is ejected — detect-and-punish closes the residue.
- Every op/QC references its `config_epoch`; QCs are always verified against the roster at that epoch.

### Quorum sizing (majority = ⌈(n+1)/2⌉)

| n | quorum | survives |
|---|---|---|
| 1 | 1 | 0 |
| 3 | 2 | 1 |
| 5 | 3 | 2 |
| 7 | 4 | 3 |

7 nodes → survive 3 concurrent failures, never split. Even sizes are rejected; they raise cost without raising tolerance.

### Fault model detail

- **2f+1 crash quorums + equivocation detection.** Safety assumes an honest majority; a node that double-votes a slot ballot produces two signed messages = a portable proof of guilt → manager ejects it. Detect-and-punish, not prevent. (Full Byzantine 3f+1 was considered and declined: storage nodes can't read data, and the threat model is crash faults, not an active attacker.)

---

## 14. Bootstrap & discovery

- **Genesis config** ships with each client/node: the **manager public key** + **seed endpoint records** (node → access methods). Trust-on-first-use for genesis; everything else flows from the log.
- **Node reachability is control-plane data:** manager-signed **endpoint records** map each node to its access methods — multiple transports and addresses per node, updated by ordinary control ops (PROTOCOL §7.1). Signed records mean a rogue node cannot redirect clients; one reachable seed node suffices to bootstrap roster, endpoints, wrapped keys, and data (PROTOCOL §7.2).
- The live roster is learned by replaying **manager-signed roster ops** (control plane) from the log. New clients bootstrap from the latest **checkpoint** + its retained op set + tail ops, folding at the checkpoint barrier (§12); versions come from the retained winners themselves and the checkpoint's `attempts` sidecar carries the nonzero live-key attempts, so slot lineages continue seamlessly.
- **Roster-change safety for bootstrap:** never remove the entire prior seed set in a single step; clients cache the last-known roster so a stale client can still find at least one reachable node to resync from.

---

## 15. Authorization & revocation

- The manager issues **capability certs**: `authz(subject_pubkey, capabilities, epoch)`, signed by the root key. Capabilities at minimum: `write` (client), `store` (node, requires BLS proof-of-possession — §3), and manager-privileged `compact` / `manage-roster` / `issue-revoke`. **The cert's `epoch` field is issuance provenance — audit metadata, never an authorization fence (NOTES 34/Q3):** a capability authorizes until revoked, across config-epoch bridges. Epoch-fencing certs is rejected for v1: it would turn every roster change into a mass re-attestation event coupled into the joint-commit window — precisely the in-flight continuity §13 exists to preserve — while adding no security that an individual fold-positional revocation does not already provide (a cert revoked before a bridge stays revoked after it; cryptographic material is fenced by `keyepoch` rotation, not by config epoch). A deployment wanting forced re-attestation per epoch is a lane-3 semantics change (§16), not a default. **The operational consequence, stated deliberately (NOTES 36): rotating the roster expires nobody's capabilities.** If a roster change is motivated by distrust of the old *delegate* set — not merely of its machines — it must be **paired with explicit revocations**; nothing epoch-implicit revokes for you, and an epoch bridge never re-attests. The next reader must not assume otherwise, and the tool makes the assumption hard to hold (MANAGER §3: roster commands print the live cert inventory for review before executing). In routine operation `compact` is **delegated**: the conveyor (§12) runs under a dedicated compactor identity holding a `compact` cert plus the group key, so the root key stays offline (§3) — compactor compromise can mint wrongful-but-auditable checkpoints, never roster or cert changes.
- **Revocation** is a manager-signed control op. **Its authoritative semantics are fold-positional:** ops by the revoked author ordered *after* the revocation (by `(hlc, author, seq, op_hash)`) are structurally invalid in the fold; ops before it stand. This is the deterministic rule every client agrees on. Node-side rejection of revoked certs is a *best-effort filter*, not load-bearing — a node that receipts an op just before hearing of the revocation causes no harm; the fold settles it.
- **Revocation drives key rotation:** on revoke, the group data key is rotated and re-wrapped to remaining members, and `keyepoch` bumps — the revoked member cannot read *future* writes (nor compute future slot tags: the slot secret rotates with it). Past ciphertext it already holds is unrecoverable regardless (accepted). During the rotation window, ops under the old epoch may still commit; the fold attributes tags using the secret of the op's declared `keyepoch`, so mixed-epoch tails stay deterministic.

---

## 16. Evolution & upgradability

The log is forever: any op ever committed must fold identically forever. Evolution is therefore governed by one meta-invariant:

> **Sealed history never changes meaning. Upgrades change only how the future folds.**

No new machinery is needed — two existing mechanisms carry all of it. The **checkpoint barrier (§12) is a natural version fence**, and the **zero-knowledge split (§5) makes most features invisible to nodes**. Every change travels one of three lanes:

### Lane 1 — client-local (free)

Anything touching neither the fold nor the nodes: watch/subscribe, caching, value-schema conventions *inside* opaque values, tooling, transport bindings. Ship whenever, to whoever.

### Lane 2 — fold-semantic (fence at a checkpoint)

New guard predicates, mutation types, transaction forms, attribution refinements — anything that changes `fold()`. Two clients folding the same ops under different rules would diverge, so:

- The envelope gains **`pver`** — the fold-semantics version (plaintext, tiny). An op whose `pver` exceeds the *active* version at its fold position is structurally invalid — deterministic for everyone, including clients that don't understand the new feature (they can still see the number).
- The manager activates `v+1` by control op, **effective at the next checkpoint barrier**: below the fence everything folds (and is sealed) under `v`; above it, `v+1`.
- A client that doesn't speak `v+1` **halts at the fence** — read-only at the sealed state, loudly. Fail-stop, never misfold.
- **Compaction is the upgrade mechanism — with one declared remainder.** The fence seals the *verdicts* of history below it, and guard-evaluation code for old versions may be deleted once nothing below the latest fence needs it. But log-compaction (§12) retains raw winner ops rather than a materialized output, so the **mutation-decode** vocabulary of every `pver` still present in the retained set must be kept until its last winner is overwritten (or re-anchored — §12's declared costs).
- Fences are monotone; there is no downgrade. An abandoned feature is a later version that ignores it.

### Lane 3 — node-visible (capability-gated control op)

New verbs, receipt/QC/watermark format changes, gossip changes, crypto suites. Nodes advertise their supported ranges (in node certs / roster ops); the manager activates via control op only once a quorum attests support — the same joint-quorum-plus-possession pattern as a roster change. **An upgrade is a roster change in which the machines stay put.** All signed artifacts already bind `config_epoch`; they additionally bind a protocol-version tag (domain separation), so cross-version artifact confusion is a signature failure, never a parsing surprise.

### Crypto agility

- **Data plane:** AEAD/PRF suites are per-`keyepoch` — the rotation machinery (§15) is already a cipher-migration mechanism.
- **Node plane:** the BLS suite is per-`config_epoch` — a roster change is a re-keying opportunity.
- **Hashes** are the hard one (content addresses everywhere): migration is a new chain grafted at a checkpoint fence, dual-hashing the retained-set commitments and state roots through the transition. Honest cost: a hash migration is a planned rebirth, not a rolling patch.

### Worked examples

| Feature | Lane |
|---|---|
| etcd-style watches | 1 |
| a new guard predicate (`counter > N`) | 2 |
| multi-key transactions | 2 (vocabulary already reserved, §17) |
| value chunking / large values | 1 as payload convention; 2 if the fold must follow chunk links |
| threshold manager key | 3 + 2 (authz validation changes) |
| new transport binding | 1 (a binding, not a version — PROTOCOL §0) |
| post-quantum signatures | 3, + a lane-2 fence for cert formats |

---

## 17. Open questions / to refine

Interaction flows now live in [PROTOCOL.md](PROTOCOL.md); the fault & adversary analysis — including the durable-state inventory and the catastrophic-recovery procedure — in [RESILIENCE.md](RESILIENCE.md); the verification hypotheses and their tool assignments in [FORMAL.md](FORMAL.md).

- Exact `guards` predicate vocabulary (version-CAS, value-equals, exists/absent, numeric comparisons, multi-key transactions). Note the §7 layered-encryption constraint: guards evaluate at the group layer, so value-shaped predicates cannot apply to inner-layer-encrypted fields — version-CAS is the convention there.
- Wire formats / serialization and the transport binding(s) beyond HTTP(S).
- Client watch/subscribe semantics (etcd-style watches over the fold).
- Key-rotation mechanics: the re-wrapping flow and distribution of the epoch-key history to new clients. (Rev 6 settles the other half: retained winners never re-encrypt — the epoch-key history is load-bearing for as long as any winner from an epoch stays live, and the re-anchor op is the recorded escape hatch — §12 declared costs.)
- The concrete value of the skew window δ (§9) — semantics are fixed; the constant (and whether it is a roster-op-settable parameter) is not.
- Ballot recovery backoff parameters (§8) — trivial at 1–3 clients, but should be written down.
- Behavior of a client whose entire cached roster is unreachable (hard bootstrap failure).
- ~~Checkpoint cadence policy~~ **Resolved at rev 6:** compaction is a continuous conveyor (§12) — slot-state GC, receipt floors, tombstone reclamation, and lane-2 fences all ride the routinely-advancing cut. The remaining open constant is the cut-lag audit window **W** (`cut ≤ finality frontier − W`): semantics fixed in §12; the value, and whether it is roster-op-settable like δ, are not.
- Gossip constants: anti-entropy period, eager-push fan-out, receipt-coverage digest encoding (PROTOCOL.md §2).
- Node capability advertisement encoding (lane 3, §16) and the `pver` numbering discipline (lane 2).
- ~~Author signature suite~~ **Resolved for v1: Ed25519 everywhere** (authors *and* node receipts — one vendored file; the genesis suite id keeps secp256k1 and BLS12-381 open as later suites, §8).
- ~~AEAD staging~~ **Resolved 2026-07-21 (CRYPTO.md, NOTES 42 as amended): the one-scheme rule.** `auth0` (authenticated-unencrypted) is **development scaffolding only** — the system never ships without encryption, and dev logs are torn down with their deployments. v1 ships exactly ONE payload scheme (XChaCha20-Poly1305 with SIV-derived nonce, PyNaCl backend); there is **no suite menu and no wire-visible scheme selector** — suite agility is a downgrade/malleability surface, declined. A future scheme change is a **lane-2 `pver` fence** (§16, fail-closed) plus a key rotation; `keyepoch` selects *keys*, never *schemes*. Slot tags stay PRF'd (keyed BLAKE2) always, so slot logic never varies.
- Worker-API encoding (PROTOCOL §6 — crosses no trust boundary, so free to be trivial) and `WATCH` semantics.
- Transport plugin interface and the endpoint-record schema (PROTOCOL §7.1).
- The formal backlog — surface syntax (TLA+ vs Quint), Apalache coverage, fairness formulation — lives in FORMAL.md §6.

---

## 18. The dial ledger (what trades against what — NOTES 35)

The optimization surface, stated once so tuning debates have a fixed vocabulary. First the split that matters most: some properties are **invariants** — never on any dial, at any setting: confidentiality/zero-knowledge, fold determinism/SEC, sign-after-fsync, detect-and-punish totality (every violation mints evidence), root-offline. Everything below trades only *within* what those permit.

**Objectives.** Minimize: gossip/P2P bandwidth · manager effort and frequency · node disk overhead · compaction bandwidth. Maximize: quorum resilience to failing/wonky nodes · write durability · partition tolerance · monkey/gorilla resilience. Plus two the first cut of this list missed: **client sync/bootstrap cost** (structurally settled at O(live state + tail), §12) and **operator-proofness of recovery** (RESILIENCE §2.3 — the most probable >f event is a mistaken one).

**The dials** (all either genesis, control-plane, or unilateral policy):

| Dial | Set where | Raising it buys | Raising it costs |
|---|---|---|---|
| `n` (roster size, odd) | roster op | durability, quorum resilience, gorilla tolerance — all as `f = (n−1)/2` | disk ×n, gossip volume ~×n, marginally larger quorums (latency) |
| gossip cadence | node policy | partition-heal speed, single-push pickup latency | idle bandwidth (bounded: digest-first ≈ tens of bytes) |
| conveyor cadence | compactor policy | lower disk floor, smaller per-step `dead` delta | compactor activity; more frequent barrier resets (marginal stale-CAS retries) |
| `W` (cut lag) | control plane | audit assurance against a rogue compactor; grace window for slow clients (§12 deps) | disk carries W of dead history before GC |
| `δ` (skew window) | control plane (lane 3, NOTES 32) | offline single-push viability, clock-skew tolerance | the time-traveller's playground; finality latency (floors trail `now − δ`) |
| delegation breadth (§15 certs) | root policy | manager effort ↓ (root stays offline) | blast radius of a delegate compromise (bounded per capability) |

**Trilemma honesty.** The surface does not collapse into one trilemma; it is mostly two-way dials, with exactly two genuine three-way tensions: the **replication trilemma** — durability × footprint (disk + gossip) × cluster cost, all riding `n`, where you pick the point on the line but never leave it — and the **compaction trilemma** — disk floor × compaction bandwidth × audit window, where GC'ing sooner costs either bigger deltas or a shorter W. Two non-tensions worth naming so they aren't traded by accident: durability and partition tolerance are the **same dial** (`n` — they move together, never against each other), and write availability under partition is not a dial at all — writes park on any minority side by construction (quorum commitment) while reads continue everywhere (local fold, SEC); that corner of CAP was chosen in §1 and is not for sale.
