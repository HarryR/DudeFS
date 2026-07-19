# DudeFS Protocol — interactions above the wire

> **Status:** companion to [DESIGN.md](DESIGN.md) (rev 5). This defines every conversation in the system — verbs, flows, invariants, crash points — one level above serialization. Wire formats will bind to this; nothing here depends on them.

## 0. Conventions

- **Transport-agnostic request/response.** HTTP(S) is one binding (deferred, non-normative — §5). Any transport that carries a request and a reply works; there is no session state to keep alive.
- **Every artifact is self-authenticating** — ops, receipts, promises, QCs, watermarks, checkpoints, evidence are signed and verifiable offline. The transport adds no trust. TLS is recommended (metadata privacy, DoS hygiene) and never load-bearing for integrity.
- **Every verb is idempotent.** Retry anything, verbatim, any number of times, against any node. Duplicates are no-ops; re-requests re-yield the same signed artifacts.
- **Nodes never fan out.** Every response is served from local state; quorum assembly is always the *caller's* job. Nodes stay trivially simple, and partial failure is a client-visible, client-policy matter — never a server-side mystery.
- Every response carries the node's current `config_epoch` and (where useful) its watermark floor — clients learn of roster changes and finality passively, from any traffic.
- Data-plane reads are served only to bearers of valid certs (per the node's current control-plane view). This is defense-in-depth on ciphertext and metadata; the actual confidentiality boundary is encryption.
- **The manager is not a distinct protocol actor.** It speaks exactly the client verbs below; what distinguishes it is its cert capabilities and that its ops are `class = control` (plaintext, node-folded). There is no manager-only verb or channel.

**Terminology (three tiers).** A **worker** is an application process with *no* protocol identity — it speaks only the local worker API (§6). A **client node** is the daemon (or in-process library) holding a manager-authorized keypair that does everything in §1 on workers' behalf. A **storage node** is the replicating acceptor of DESIGN §2. Unqualified "node" in these documents means storage node; unqualified "client" means client node.

## 1. Client ↔ node

### 1.1 Verbs

| Verb | Request | Response | Notes |
|---|---|---|---|
| `SUBMIT` | **blind** op envelope | `ACCEPTED{receipt}` \| `REJECTED{reason}` | Blind writes only (no slot). A slotted envelope is proposed via `PREPARE`/`ACCEPT`; slotted `SUBMIT` is `REJECTED{needs_ballot}` (rev 5 — the ballot-0 fast path is gone, DESIGN §8). Resubmission re-yields the identical receipt. |
| `PREPARE` | `{slot_tag, ballot}` | `PROMISE{ballot, accepted?: (ballot, op_hash), sig}` \| `NACK{promised}` | Phase 1 of every slotted proposal (DESIGN §8). Promises are signed — they are evidence, and how a loser learns the decided op. |
| `ACCEPT` | `{slot_tag, ballot, op}` | `ACCEPTED{receipt@ballot}` \| `NACK{promised}` | Phase 2. Carries the envelope in case the node lacks it. |
| `FETCH_OP` | `{op_hash}` | envelope + known receipts | |
| `FRONTIER` | – | signed **frontier bundle**: `sign(node_sk, per-author heads ‖ checkpoint_head ‖ config_epoch ‖ floor)` | The read primitive. Heads and floor are signed *at one instant* — this is what makes quorum reads relay-safe (§7.3). |
| `PULL` | `{author, from_seq, to_seq}` | contiguous envelopes + receipts + QCs | Ranges at/below the cut answer with the checkpoint instead. |
| `GET_QC` / `PUT_QC` | `{op_hash}` / `{QC}` | QC / ack | Clients deposit QCs they assemble; nodes also assemble from gossiped receipts. |
| `WATERMARK` | – | fresh signed floor | |
| `RERECEIPT` | `{op_hash \| slot_tag}` | receipt under the node's *current* epoch | For in-flight ops across roster changes (DESIGN §13). Acceptor state untouched. |
| `EVIDENCE` | `{proof}` | ack | Node stores it, gossips it, surfaces it to the manager. |

`REJECTED.reason` ∈ `future_hlc{local_now}` · `below_floor{floor}` · `bad_authz` · `bad_structure` (signature, chain gap, fork mismatch) · `unknown_prev` (node lacks the author's prior op — push it, or let anti-entropy catch up) · `unknown_dep` (node lacks a `deps`-referenced op — same remedy; applies to `SUBMIT` only, ballot `ACCEPT` is exempt so recovery always completes) · `needs_ballot` (a slotted op sent via `SUBMIT` — propose it via `PREPARE`/`ACCEPT`) · `wrong_epoch`.

### 1.2 Quorum read (→ linearizable read)

1. `FRONTIER` to all reachable nodes; proceed once any quorum has answered.
2. `PULL` whatever you lack, from whichever answering node has it.
3. For committed-looking ops without QCs in hand: `GET_QC`, or assemble from the receipts you now hold.
4. Fold locally at the checkpoint barrier (DESIGN §12).
5. The returned `WM`s give the **finality frontier**: the highest `h` such that a quorum attests floors ≥ `h`.

**Linearizable read** = report state at the finality frontier. **Local read** = skip the network and fold your cache (serializable, possibly stale).

Because frontier bundles are signed atomically, the quorum read is **path-independent**: `q` verifiable bundles establish the same guarantee whether fetched directly or relayed through a single reachable node (§7.3). The intersection argument: any op committed below frontier `h` was receipted by some bundle-signer *before* its monotone floor passed `h` — so that signer's bundled heads necessarily include it.

### 1.3 CAS, end to end

0. Quorum read → the key's `(version, attempt)` at the finality frontier.
1. Build `Txn` (slot preimage, guards, mutations), AEAD-encrypt, compute `slot_tag`, envelope with fresh `hlc`.
2. `PREPARE` `(slot_tag, b)` with `b = (r ≥ 1, my-id)` above anything seen, to at least a quorum, in parallel (rev 5: every slotted proposal runs both phases — DESIGN §8).
3. From a quorum of promises: if any reports an accepted op, you MUST `ACCEPT` the highest-ballot one — even a rival's; you may be completing someone else's decision, and that is required, not courtesy. Otherwise `ACCEPT` your own. Quorum of `ACCEPTED@b` → assemble QC → **committed** (durable). If the decided op is a rival's: it is committed — go to step 4, observe, then retry your own intent against the advanced lineage.
4. Poll `WATERMARK` (it piggybacks on any traffic) until a quorum's floors pass `op.hlc` → **final**. Fold verdict: `applied` → success. `rejected`/`stale` → a guard failed or the lineage moved — re-read, reconsider, maybe retry. Done either way; report which.
5. **Contention** (`NACK{promised}` or timeout): pick a round above the reported promise and re-run from step 2. Randomized backoff between rounds (dueling proposers; trivial at 1–3 clients).

### 1.4 Offline / single-push writes

`SUBMIT` to one node and disconnect (blind writes; a slotted op relays its client-signed `PREPARE`/`ACCEPT` artifacts the same way — §7.3); peers receipt via gossip; any node assembles the QC; poll `GET_QC` later. Convenience, not guarantee: a rogue node can withhold, and the skew window is ticking (DESIGN §9). Push to a quorum when it matters.

## 2. Node ↔ node (gossip / anti-entropy)

### 2.1 Invariants

- **Contiguity:** a node stores `(author, seq)` only if it holds `seq−1` (or `seq ≤` the checkpoint cut). Chains always validate locally; there are no orphan islands. An eager-pushed op that would open a gap triggers an immediate `PULL` of the gap; if the gap can't be filled now, drop the push — the periodic cycle will carry it.
- **Dep resolution before acceptance:** a node accepts an op only once every `deps`-referenced op is present locally — committed *or merely stored* (floors gate receipts, not storage, so a dep on an uncommitted op is always satisfiable). Unknown deps trigger a `PULL`; if they can't be fetched now, defer (`unknown_dep`) and let the periodic cycle carry them. This is what makes a fork visible at the first node where two branches' observers meet: the pulled branch collides in the store and mints equivocation evidence **at accept time** (DESIGN §4). Ballot `ACCEPT` (recovery) is exempt, like contiguity — completing a decision must never block on context.
- **The watermark floor never gates gossip.** Floors gate *issuing receipts*; storing and relaying already-receipted material must always proceed, or convergence breaks (DESIGN §8).
- Deduplicate by hash; validate before storing (signature, authz against the current control-plane view, chain links).
- **Learners** speak this entire section but MUST NOT issue receipts, promises, or watermarks — they are invisible to quorum math until promoted (DESIGN §13).

### 2.2 Verbs

| Verb | Payload | Notes |
|---|---|---|
| `SUMMARY` | per-author heads · per-author receipt coverage · checkpoint head · floor · epoch · evidence digest | Exchanged pairwise; each node runs a periodic epidemic round against a uniformly random peer. |
| `DELTA` | contiguous envelope runs + receipts + QCs + checkpoints + control ops + evidence | Ships exactly the diff the `SUMMARY` exposed, honoring contiguity. |
| eager push | `{op, my receipt}` on fresh accept, to all peers | Latency optimization only; correctness rests on the periodic cycle alone. |

Any node accumulating a quorum of receipts assembles, stores, and serves the QC — this is what makes single-push (§1.4) work. Cycle constants and the receipt-coverage digest encoding are wire-adjacent: open (DESIGN §17).

### 2.3 Cost & health accounting

- **Bandwidth scales with churn, not state.** A `SUMMARY` is ≲1 KB (per-author heads × ≤10 authors + coverage bitmaps + floor + epoch); digest-first exchange (`H(summary)` first, full summary only on mismatch) drops the idle case to tens of bytes. At n=7 and 1 Hz cadence, worst case is ~1 KB/s per node — a rounding error for a config store.
- **Floors are the health sensor.** Signed, monotone, self-reported, already in every response: **lag** = a node's floor trailing the quorum-max floor; **drift** = floor velocity vs the observer's clock. Neither is *provable* misbehavior (slowness cannot be distinguished from a slow path — no proof, no punishment; RESILIENCE §1's regime split), but both are *actionable by policy*: a floor persistently trailing by more than k·δ marks a replacement candidate via the ordinary learner → promote flow (§3.1). The manager needs no proof; it is trusted by construction.

## 3. Manager flows

Same verbs throughout; control ops are plaintext ops on the manager's authored chain, folded by nodes as well as clients.

### 3.1 Roster change (`e → e+1`)

1. Final quorum read (§1.2) → the **sync frontier** `SF` (per-author `(seq, hash)`, entirely final).
2. Author the roster op: `{from_epoch: e, new_roster, SF}`, carrying the **public slot tag** `H("roster" ‖ e)` (DESIGN §13). The slot is contested on the *old* roster through the ordinary ballot machinery — so at most one change can ever activate out of `e`, even against a crashed-and-retried or amnesiac manager.
3. `SUBMIT` to old-roster members → slot-guarded receipts under `e` (they are epoch `e`'s acceptors).
4. `SUBMIT` to new-roster members. Each verifies, *before* receipting: `from_epoch` matches its current epoch, **and it holds every committed op and QC ≤ `SF`** (learners are already caught up; anyone else `PULL`s first). Receipts under `e+1`. The new-roster QC is thereby an agreement proof *and* a data-possession proof.
5. Assemble the **joint certificate** — a QC over a quorum of the old roster (epoch `e`) plus a QC over a quorum of the new (epoch `e+1`) — `PUT_QC` both everywhere; gossip spreads them.
6. **Activation:** a node switches epochs the moment it holds the joint certificate. From then on it receipts under `e+1`, answers `RERECEIPT` for in-flight ops (acceptor state carries over untouched), and stalled old-epoch slots complete via ordinary recovery (§1.3 step 5) against the new roster.

Crash at any step: everything is idempotent and slot-guarded; resume or retry verbatim, or abandon. A manager that lost its chain-head state must run the author-amnesia procedure first (DESIGN §4) — mandatory, since the root key cannot be retired.

### 3.2 Checkpoint (compaction)

1. Final quorum read → frontier `F`, entirely final (no straggler can ever sort below it — DESIGN §9/§12).
2. Fold to `F`; build `Checkpoint{cut, state_root, snapshot, …}`. The snapshot holds live keys only, each with `(version, attempt)`; **tombstones die here** and their lineages restart at `(⊥, 0)`.
3. `SUBMIT` like any op → QC → the checkpoint is committed.
4. Nodes, on observing the committed checkpoint, **may** — lazily, locally, at leisure — drop envelopes ≤ `cut`, drop slot acceptor-state consumed ≤ `cut`, and enforce the receipt floor at the horizon. No coordination needed: the barrier is logical, not physical, so nodes GC'ing at different times is normal operation.
5. Any full-history client recomputes `state_root` and shouts on mismatch — compaction stays a *compression* channel, auditable forever (DESIGN §12).

### 3.3 Certs, revocation, key rotation

- **New client:** manager authors a cert control op plus a **wrap-set** op — the group-key history wrapped to the new client's public key. *The log is the key-distribution channel*; nothing travels out-of-band except the genesis config.
- **Revoke:** a revocation control op (fold-positional semantics — DESIGN §15), then rotation: new group data key, a wrap-set for every remaining member, `keyepoch` bump. Old-epoch in-flight data ops still commit and fold deterministically (DESIGN §7, cross-epoch race).
- **New node:** BLS proof-of-possession → node cert → learner-add control op → catch-up via §2 → promotion via §3.1.

## 4. Timeout & retry discipline

- Any verb, any node, any time: retry with backoff or fail over — nodes are interchangeable for committed data; only receipts are per-identity.
- **Hedge, don't timeout-and-blast** (borrowed from QuePaxa — [RELATED.md](RELATED.md) §6): when quorum-fanning a `SUBMIT` or read, fire the preferred quorum immediately and stagger the remaining nodes on short delays (δ_hedge, 2·δ_hedge, …), cancelling stragglers on quorum. Idempotency makes early hedges harmless; the stagger caps redundant work without a conservative timeout anywhere. Pure client policy — no protocol change.
- Healthy-path write latency: blind — one `SUBMIT` round trip; slotted — one `PREPARE` + one `ACCEPT` round trip (two by design, rev 5 — DESIGN §8); plus QC assembly + one watermark pass either way.
- Client-side timers are policy, not protocol: nothing anywhere depends on a client timing out "correctly." A late resumption is always safe (idempotency) and at worst wasteful.

## 5. Wire binding

Deferred deliberately (DESIGN §17). Whatever binds must preserve: **injective encodings** for everything signed or PRF'd (length-prefixed slot preimages; canonical envelope serialization) and **byte-stable content addressing**. An HTTP binding is one route per verb above; nothing in this document cares which — transports are pluggable black boxes (§7.1).

## 6. The client node & the worker API

The client node is a daemon on the worker's machine (or the same stack embedded as a library on a thread/fibre — identical interface, no socket). It holds the manager-authorized keypair, folds the log, runs quorum logistics, and exposes a deliberately tiny **local API** — Unix domain socket by default, with filesystem permissions as the entire worker-authorization boundary.

### 6.1 Worker verbs

| Verb | Semantics |
|---|---|
| `GET path [level=local\|linear]` | Read at the chosen consistency level (default `linear`). |
| `LIST path/ [level=…]` | Enumerate children. |
| `PUT path value [ack=committed\|final]` | Blind LWW write. Returns at the chosen rung of the ladder. |
| `CAS path expect value [ack=…]` | Guarded write; the client node runs the read–tag–submit–recover dance of §1.3 invisibly. |
| `DEL path` | Tombstone. |
| `TXN {guards, mutations} [ack=…]` | Multi-key guarded transaction (vocabulary per DESIGN §17). |
| `WATCH path/` | Stream fold changes (lane-1 feature; semantics open, DESIGN §17). |
| `STATUS` | Roster, reachability, finality frontier, lag spread — the client node's view of the world. |

Design rules: workers perform **no cryptography**, hold **no keys**, and know nothing of quorums, ballots, or floors — the three-level ladder (`accepted / committed / final`) surfaces only as the `ack=`/`level=` knobs, which is the entire consistency story a worker ever sees. The wire encoding of this API can be trivially simple (it crosses no trust boundary — the socket's filesystem permissions are the boundary); encoding open in DESIGN §17.

### 6.2 Provenance granularity

Ops are authored by the *client node's* identity — that is what the log attributes and what revocation revokes. Workers multiplexing through one identity is a deliberate simplification at this scale. If per-worker attribution is ever wanted: issue more client certs (one per worker — the real fix), or embed a worker label inside the encrypted payload (visible to other clients after decryption, never to storage nodes) as a lane-1 convention.

## 7. Transports, endpoints, discovery & relay

### 7.1 Endpoint records (manager-set, control-plane-carried)

Each storage node's reachability is described by an **endpoint record** in the control plane — a manager-signed op mapping `node_id → [(transport, uri, opts), …]`: multiple access methods per node (HTTP at two addresses, SSH, JSON-RPC over XMPP or any other intermediated transport), updated by ordinary control ops as infrastructure moves. Because records are manager-signed and log-carried, **a rogue node cannot redirect clients toward itself** — endpoint spoofing would require the root key. (Endpoints are plaintext control-plane metadata: inside the declared leakage boundary, DESIGN §7.)

A **transport** is anything that can move a request/response pair or a bag of artifacts. Since every protocol message is (or carries) a self-authenticating artifact, transports add no trust — the plugin interface is a pure black box beneath the §1/§2 verbs, chosen per-peer and hedged across a node's addresses like any other fan-out (§4).

### 7.2 Bootstrap & discovery (from one reachable node)

1. **Genesis** ships the manager public key + **seed endpoint records** (DESIGN §14).
2. Reach *any one* storage node via any seed endpoint.
3. Pull the latest **checkpoint** + the control-plane chain; verify manager signatures and quorum commitment — all offline-checkable.
4. From the control chain: current roster, **current endpoint records**, certs/revocations, `keyepoch` wrap-sets (the log is the key-distribution channel, §3.3).
5. Sync the tail (§1.2), fold, cache roster + endpoints (never evict the last-known set — DESIGN §14).
6. Operational: serve workers (§6), stay current by polling/gossip-adjacency.

One reachable seed node therefore suffices to recover *everything*: roster, endpoints, keys wrapped to you — then the data.

### 7.3 Relay operation (one or two reachable nodes)

When a client node can reach only a subset of the roster, the protocol degrades in **latency, never correctness**:

- **Writes** already work via single-push (§1.4): the op is a signed artifact; gossip carries it; peers receipt it; any node assembles the QC; the client polls.
- **Ballots relay too:** `PREPARE` and `ACCEPT` have client-signed artifact forms (tag, ballot, op-hash under the client's key), processed idempotently whenever and however they arrive; promises and receipts (node-signed) gossip back, keyed by request hash. Slot recovery thus needs a *path* to a quorum, not a *connection* to one.
- **Linearizable reads survive relay** via signed frontier bundles (§1.2): the reachable node forwards its peers' bundles, and `q` verifiable bundles are `q` verifiable bundles regardless of the pipe. Staleness is conservative — floors are monotone lower bounds — so a lagging relay costs freshness, never safety.
- No contradiction with "nodes never fan out" (§0): nodes never *synchronously proxy*; gossip is the asynchronous relay fabric, and it was already load-bearing.

### 7.4 Partial, heterogeneous meshes (gorilla-survivability)

Storage nodes likewise need not be pairwise-connected, nor share a common transport: gossip (§2) requires only that the reachability graph is **connected** — eventually, through any composition of transports — and convergence time scales with graph diameter, not degree. Disparate transports per link are a survivability feature: an outage that severs one transport class (HTTP blocked, DNS dead) leaves the mesh connected through another (SSH, an intermediated relay). The manager's endpoint records are the map; gossip finds the path.
