# DudeFS Protocol — interactions above the wire

> **Status:** companion to [DESIGN.md](DESIGN.md) (rev 6). This defines every conversation in the system — verbs, flows, invariants, crash points — one level above serialization. Wire formats will bind to this; nothing here depends on them.

## 0. Conventions

- **Transport-agnostic request/response.** HTTP(S) is one binding (deferred, non-normative — §5). Any transport that carries a request and a reply works; there is no session state to keep alive.
- **Every artifact is self-authenticating** — ops, receipts, promises, QCs, watermarks, checkpoints, evidence are signed and verifiable offline. The transport adds no trust. TLS is recommended (metadata privacy, DoS hygiene) and never load-bearing for integrity.
- **Every verb is idempotent.** Retry anything, verbatim, any number of times, against any node. Duplicates are no-ops; re-requests re-yield the same signed artifacts.
- **Nodes never fan out.** Every response is served from local state; quorum assembly is always the *caller's* job. Nodes stay trivially simple, and partial failure is a client-visible, client-policy matter — never a server-side mystery.
- Every response carries the node's current `config_epoch` and (where useful) its watermark floor — clients learn of roster changes and finality passively, from any traffic.
- Data-plane reads are served only to bearers of valid certs (per the node's current control-plane view). This is defense-in-depth on ciphertext and metadata; the actual confidentiality boundary is encryption.
- **The manager is not a distinct protocol actor** — and neither is the compactor (DESIGN §12). Both speak exactly the client verbs below; what distinguishes them is cert capabilities and that their privileged ops are `class = control` (plaintext, node-folded). There is no manager-only verb or channel.

**Terminology (three tiers).** A **worker** is an application process with *no* protocol identity — it speaks only the local worker API (§6). A **client node** is the daemon (or in-process library) holding a manager-authorized keypair that does everything in §1 on workers' behalf. A **storage node** is the replicating acceptor of DESIGN §2. Unqualified "node" in these documents means storage node; unqualified "client" means client node.

## 1. Client ↔ node

### 1.1 Verbs

| Verb | Request | Response | Notes |
|---|---|---|---|
| `SUBMIT` | **blind** op envelope | `ACCEPTED{receipt}` \| `REJECTED{reason}` | Blind writes only (no slot). A slotted envelope is proposed via `PREPARE`/`ACCEPT`; slotted `SUBMIT` is `REJECTED{needs_ballot}` (rev 5 — the ballot-0 fast path is gone, DESIGN §8). Resubmission re-yields the identical receipt. |
| `PREPARE` | `{slot_tag, ballot}` | `PROMISE{ballot, accepted?: (ballot, op_hash, hlc), sig}` \| `NACK{promised}` | Phase 1 of every slotted proposal (DESIGN §8). Promises are signed — they are evidence, and how a loser learns the decided op. A reported accept carries the accepted op's `hlc` so the proposer can apply the below-horizon no-accept guard (§1.3 step 3) without a fetch round trip. |
| `ACCEPT` | `{slot_tag, ballot, op}` | `ACCEPTED{receipt@ballot}` \| `NACK{promised}` | Phase 2. Carries the envelope in case the node lacks it. |
| `FETCH_OP` | `{op_hash}` | envelope + known receipts | |
| `FRONTIER` | – | signed **frontier bundle**: `sign(node_sk, per-author heads ‖ checkpoint_head ‖ config_epoch ‖ floor)` | The read primitive. Heads and floor are signed *at one instant* — this is what makes quorum reads relay-safe (§7.3). |
| `PULL` | `{author, from_seq, to_seq}` | envelopes + receipts + QCs | Above the cut: contiguous runs. At/below the cut: the **sparse retained subset** of the range (DESIGN §12), with *no* receipts/QCs — the checkpoint's `retained` commitment vouches for below-cut commitment; the caller verifies holdings per author against the `(count, digest)` in the checkpoint. Idempotent range paging is the bootstrap fetch primitive. |
| `GET_QC` / `PUT_QC` | `{op_hash}` / `{QC}` | QC / ack | Clients deposit QCs they assemble; nodes also assemble from gossiped receipts. |
| `WATERMARK` | – | fresh signed floor | |
| `RERECEIPT` | `{op_hash \| slot_tag}` | receipt under the node's *current* epoch | For in-flight ops across roster changes (DESIGN §13). Acceptor state untouched. |
| `EVIDENCE` | `{proof}` | ack | Node stores it, gossips it, surfaces it to the manager. |

`REJECTED.reason` ∈ `future_hlc{local_now}` · `below_floor{floor}` · `bad_authz` · `bad_structure` (signature, chain gap, fork mismatch) · `unknown_prev` (node lacks the author's prior op — push it, or let anti-entropy catch up) · `unknown_dep` (node lacks a `deps`-referenced op — same remedy; applies to `SUBMIT` only, ballot `ACCEPT` is exempt so recovery always completes) · `needs_ballot` (a slotted op sent via `SUBMIT` — propose it via `PREPARE`/`ACCEPT`) · `wrong_epoch`.

### 1.2 Quorum read (→ linearizable read)

1. `FRONTIER` to all reachable nodes; proceed once any quorum has answered.
2. `PULL` whatever you lack, from whichever answering node has it.
3. For committed-looking ops without QCs in hand: `GET_QC`, or assemble from the receipts you now hold. (Above the cut only — below it, receipts/QCs are GC'd and the checkpoint's `retained` commitment is the commitment proof, DESIGN §12.)
4. Fold locally at the checkpoint barrier (DESIGN §12).
5. The returned `WM`s give the **finality frontier**: the highest `h` such that a quorum attests floors ≥ `h`.

**Linearizable read** = report state at the finality frontier. **Local read** = skip the network and fold your cache (serializable, possibly stale).

Because frontier bundles are signed atomically, the quorum read is **path-independent**: `q` verifiable bundles establish the same guarantee whether fetched directly or relayed through a single reachable node (§7.3). The intersection argument: any op committed below frontier `h` was receipted by some bundle-signer *before* its monotone floor passed `h` — so that signer's bundled heads necessarily include it.

### 1.3 CAS, end to end

0. Quorum read → the key's `(version, attempt)` at the finality frontier.
1. Build `Txn` (slot preimage, guards, mutations), AEAD-encrypt, compute `slot_tag`, envelope with fresh `hlc`.
2. `PREPARE` `(slot_tag, b)` with `b = (r ≥ 1, priority)`, `priority = h(slot_tag ‖ my_fp)` (the per-slot tiebreak, DESIGN §8), above anything seen, to at least a quorum, in parallel (rev 5: every slotted proposal runs both phases — DESIGN §8).
3. From a quorum of promises: if any reports an accepted op, you MUST `ACCEPT` the highest-ballot one — even a rival's; you may be completing someone else's decision, and that is required, not courtesy. (Exception: a reported accept whose op `hlc` lies below the checkpoint horizon is dead state — treat as no accept; acceptors void such state themselves on `PREPARE`, DESIGN §8.) Otherwise `ACCEPT` your own. Quorum of `ACCEPTED@b` → assemble QC → **committed** (durable). If the decided op is a rival's: it is committed — go to step 4, observe, then retry your own intent against the advanced lineage.
4. Poll `WATERMARK` (it piggybacks on any traffic) until a quorum's floors pass `op.hlc` → **final**. Fold verdict: `applied` → success. `rejected`/`stale` → a guard failed or the lineage moved — re-read, reconsider, maybe retry. Done either way; report which.
5. **Contention** (`NACK{promised}` or timeout): pick a round above the reported promise and re-run from step 2, after the deterministic per-`(priority, round)` jitter; a per-round timeout escalates the round even when Nacks are lost (DESIGN §8). Real drivers may mix true entropy into these timers — they are policy, not protocol (§4).

### 1.4 ~~Offline / single-push writes~~ — STRUCK (NOTES 52)

The fire-to-one-node-and-disconnect mode is removed: it was the sole reason δ had to cover gossip-propagation time instead of clock skew, and no supported client profile needs it — the **resident client daemon drives the quorum itself** (hedged fanout, ~2 RTT to durable; CLIENT.md §0), which is what makes the worker API's durability gate fast enough to sit on the critical path. What remains of this section's machinery: **relay (§7.3) stays** — a daemon reaching only one node still commits *synchronously through it* via relayed signed artifacts (online-through-a-narrow-path, not disconnect-and-hope). With the strike, δ = a pure clock-skew bound (~1 s class, DESIGN §17), and the §3.4 time-traveller playground shrinks with it.

## 2. Node ↔ node (gossip / anti-entropy)

**Purpose, post-§1.4-strike (NOTES 52/53): gossip is the repair-and-dissemination plane — and the connectivity substrate under partial meshes — never an unattended commit path.** Commitment *correctness* never depends on it (artifacts are signed and path-independent; the client daemon drives until it holds a quorum of signed replies, whether the bytes travel direct, via relays §7.3, or with the epidemic mesh as carrier of last resort). Commit *reachability* under a sparse-but-connected topology may ride it — in which case δ is sized to the quorum-path delivery latency (NOTES 53), not to clock skew alone. What gossip owns: (1) **durability amplification and healing** — a commit lands on q nodes; gossip carries it toward all n and re-fills nodes that were down/partitioned/hedge-skipped, which is what makes "any n−f survivors cover everything" true in practice (RESILIENCE §2); gossiped ops are stored, never receipted (floors gate *issuing*, §2.1); (2) **artifact dissemination** — QCs, checkpoints, certs/rosters, recovery fences, and evidence reach every node epidemically (the daemon's adoption/fence/evidence cycles all feed off it); (3) **baseline sync & bootstrap** — the sparse below-cut PULL path and learner catch-up; (4) **client cache freshness** — client daemons pull the same way, which is what keeps `GET local` and `INSPECT`'s foreign-`pending` view current between quorum reads.

### 2.1 Invariants

- **Contiguity:** a node stores `(author, seq)` only if it holds `seq−1` (or `seq ≤ cut_seq[author] + 1` — the exemption covers both the sparse below-cut baseline **and** the first tail op above the boundary, whose `seq−1` predecessor may be dead and GC'd; below the cut chains are legitimately **sparse**: a node holds exactly the retained subset, validated against the checkpoint's per-author `(count, digest)` commitment over the `covered ∖ dead` projection, DESIGN §12). Chains always validate locally; there are no orphan islands. An eager-pushed op that would open a gap triggers an immediate `PULL` of the gap; if the gap can't be filled now, drop the push — the periodic cycle will carry it.
- **Dep resolution before acceptance:** a node accepts an op only once every `deps`-referenced op is present locally — committed *or merely stored* (floors gate receipts, not storage, so a dep on an uncommitted op is always satisfiable). Unknown deps trigger a `PULL`; if they can't be fetched now, defer (`unknown_dep`) and let the periodic cycle carry them. This is what makes a fork visible at the first node where two branches' observers meet: the pulled branch collides in the store and mints equivocation evidence **at accept time** (DESIGN §4). Ballot `ACCEPT` (recovery) is exempt, like contiguity — completing a decision must never block on context.
- **The watermark floor never gates gossip.** Floors gate *issuing receipts*; storing and relaying already-receipted material must always proceed, or convergence breaks (DESIGN §8).
- Deduplicate by hash; validate before storing (signature, authz against the current control-plane view, chain links).
- **Learners** speak this entire section but MUST NOT issue receipts, promises, or watermarks — they are invisible to quorum math until promoted (DESIGN §13).

### 2.2 Verbs

| Verb | Payload | Notes |
|---|---|---|
| `SUMMARY` | per-author heads · per-author receipt coverage · checkpoint head + retained digests · floor · epoch · evidence digest | Exchanged pairwise; each node runs a periodic epidemic round against a uniformly random peer. Retained digests are over the **`covered ∖ dead` projection** (DESIGN §12) — never raw holdings, or a lazy-GC node and a GC'd one would diff forever; heads at-or-below the cut are pinned by the checkpoint, not served contiguously. |
| `DELTA` | envelope runs (contiguous above the cut; retained-sparse below) + receipts + QCs + checkpoints + control ops + evidence | Ships exactly the diff the `SUMMARY` exposed, honoring contiguity. |
| eager push | `{op, my receipt}` on fresh accept, to all peers | Latency optimization only; correctness rests on the periodic cycle alone. |

A node **persists the receipts it issues** (derived from already-fsynced slot state, so a stored receipt never outlives its justification — RESILIENCE §0); its own receipts are gossip payload like any other. Any node accumulating a quorum of receipts assembles, stores, and serves the QC — this is what makes single-push (§1.4) work. **`DELTA` intake is not peer-gated:** any bearer of a valid cert — a client node, the manager, the compactor — may push artifact bundles through the same validation path; storing already-signed material is always harmless (floors gate receipts, never storage), and this is the salvage path of RESILIENCE §2.2. Cycle constants and the receipt-coverage digest encoding are wire-adjacent: open (DESIGN §17).

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

### 3.2 Checkpoint (conveyor compaction)

Run routinely by the **compactor** — a delegated `compact`-capability identity holding the group key (DESIGN §12/§15); the root key stays offline. The compactor maintains a warm incremental fold; each conveyor step is cheap and proportional to churn.

1. Final quorum read → frontier `F`, entirely final (no straggler can ever sort below it — DESIGN §9/§12). The cut is pinned at `F` itself — **no audit-window lag** (`W` retired, ACCUMULATOR §2).
2. Incremental tail-fold to `F` — inputs are contractually the previous checkpoint's retained set + sidecar plus the inter-cut committed tail (DESIGN §12; full history no longer exists after GC); compute the newly-dead set (superseded or deleted ≤ `cut`, honoring the resurrection mask — DESIGN §12 retention rule: `dead = (prev_retained ∪ covered_tail) ∖ new_retained`) and the full retained commitment; advance the **`state_acc`** ECMH accumulator over the new live set (O(Δ), ACCUMULATOR); build `Checkpoint{cut, horizon: F, state_acc, dead, retained, attempts, …}` — kilobytes, ∝ churn. **Tombstones die here** and their lineages restart at `(⊥, 0)`; live-key attempts ride the encrypted sidecar.
3. `SUBMIT` like any op → QC → the checkpoint is committed.
4. Nodes, on observing the committed checkpoint, **may** — lazily, locally, at leisure — drop the `dead` ops, drop receipts/QCs ≤ `cut` (the `retained` commitment vouches), drop slot acceptor-state consumed ≤ `cut` (void on `PREPARE` regardless — DESIGN §8), and enforce the receipt floor at the horizon. No coordination needed: the barrier is logical, not physical, so nodes GC'ing at different times is normal operation. Clients apply the same `dead` delta to their caches.
5. Any key-holder with continuity across the cut recomputes the **`state_acc`** accumulator (O(Δ), against client-durable lineage) and shouts on mismatch — compaction stays a *selection* channel, auditable with no window (DESIGN §12 trust surface / ACCUMULATOR §5). Silent omission is separately foreclosed at the nodes by the `retained`-partition check (PROTOCOL §2.2 baseline verification).

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

### 6.1 Worker verbs — canonical surface lives in CLIENT.md (NOTES 50–52)

This sketch is superseded: the resolved surface is **JSON-RPC 2.0** (concurrent `id`-correlated requests, no server push, poll-only, **no stubs**) with verbs `TXN` (the primitive: one contended slot + multi-key guards + atomic mutations) · `PUT`/`CAS` (sugar) · `GET` · `INSPECT` (key-centric recovery: final/provisional/pending-with-decoded-intent) · `LIST` (prefix + delimiter + pending flags) · `STATUS` (per-op debugging). The consistency story is the three-event ladder — `durable` / `provisional`(+may_flip) / `final` — exposed as data on every poll, never as blocking `ack=` knobs. Full contract, ladder rules, and the canonical take→durable-intent→leased-idempotent-work pattern: [CLIENT.md](CLIENT.md). Design rules unchanged: workers perform no cryptography, hold no keys, and know nothing of quorums, ballots, or floors.

### 6.2 Provenance granularity

Ops are authored by the *client node's* identity — that is what the log attributes and what revocation revokes. Workers multiplexing through one identity is a deliberate simplification at this scale. If per-worker attribution is ever wanted: issue more client certs (one per worker — the real fix), or embed a worker label inside the encrypted payload (visible to other clients after decryption, never to storage nodes) as a lane-1 convention.

## 7. Transports, endpoints, discovery & relay

### 7.1 Endpoint records (manager-set, control-plane-carried)

Each storage node's reachability is described by an **endpoint record** in the control plane — a manager-signed op mapping `node_id → [(transport, uri, opts), …]`: multiple access methods per node (HTTP at two addresses, SSH, JSON-RPC over XMPP or any other intermediated transport), updated by ordinary control ops as infrastructure moves. Because records are manager-signed and log-carried, **a rogue node cannot redirect clients toward itself** — endpoint spoofing would require the root key. (Endpoints are plaintext control-plane metadata: inside the declared leakage boundary, DESIGN §7.)

Each address's `opts` carries its **L_msg profile** — `{lmsg: plain}` or `{lmsg: sealed}` (§7.5) — a *server-side* property of the endpoint, never a per-message negotiation: the endpoint expects exactly one message shape and rejects everything else, so misconfiguration has nothing to mis-negotiate. Because the record is manager-signed, a hostile intermediary **cannot downgrade `sealed → plain`**.

A **transport** is anything that can move a request/response pair or a bag of artifacts. Since every protocol message is (or carries) a self-authenticating artifact, transports add no trust — the plugin interface is a pure black box beneath the §1/§2 verbs, chosen per-peer and hedged across a node's addresses like any other fan-out (§4).

### 7.2 Bootstrap & discovery (from one reachable node)

1. **Genesis** ships the manager public key + **seed endpoint records** (DESIGN §14).
2. Reach *any one* storage node via any seed endpoint.
3. Pull the latest **checkpoint** + the control-plane chain; verify manager signatures and quorum commitment — all offline-checkable.
4. From the control chain: current roster, **current endpoint records**, certs/revocations, `keyepoch` wrap-sets (the log is the key-distribution channel, §3.3).
5. Sync the retained set (sparse `PULL`s verified against the checkpoint's per-author digests) + the tail (§1.2); fold per DESIGN §12 bootstrap semantics; cache roster + endpoints (never evict the last-known set — DESIGN §14).
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

### 7.5 The L_msg envelope (message-level authentication ± confidentiality)

A transport promises only "**push a message, get a reply — maybe**": message-oriented, sessionless, and often intermediated (XMPP through a server we don't run, HTTPS terminating at a CDN). Channel security (Noise/TLS) is therefore the wrong layer — it can't run on message carriers, and where it runs it authenticates *the stream to the intermediary*, not "this request came from node X", the one fact the request gate needs. So authentication and confidentiality live in the **message**. Three layers:

```
  L_msg    authenticated (± sealed) request/reply envelope   ← peer identity + the gate
  L_art    self-authenticating artifacts (ops, receipts, QCs)  ← integrity (§0)
  L_txport push message → reply, maybe (TCP | HTTPS | WS | XMPP) ← dumb carrier, adds no trust
```

**Scope:** L_msg is the **cluster wire only** (client-daemon ↔ node, node ↔ node, manager ↔ node). The worker socket (§6) is the one exempt surface — genuinely local, keyless, bounded by filesystem permissions. Everywhere else **authenticity is the floor**: every packet is signed, always — even over a local unix socket, which is only a test convenience for an inherently remote protocol. Even a carrier that gives a confidential, peer-authenticated link (a `.onion`, an owned TLS tunnel) authenticates the *tunnel endpoint*, never the DUDE identity — so the signed envelope is still required.

No anonymous traffic — every envelope is authenticated, so the gate always has a `from`. Sealing is the optional layer on top; the one seam that speaks it is `Link` (dudefs/link.py), and carriers live in `dudefs/transports/` (one per scheme).

**Plain (auth only)** — for carriers already confidential to the peer (Tor `.onion`, owned TLS, trusted LAN):

```
{ from, to, epoch, ts, nonce, verb, body, sig }
    sig = Ed25519(from_sk, "dude.msg:" ‖ canon(from, to, epoch, ts, nonce, verb, body))
```

**Sealed (auth + confidentiality)** — for any untrusted-but-encrypted intermediary (CDN-fronted HTTPS, an XMPP server): **sign-then-seal**, the signed struct + a fresh ephemeral **reply-key** wrapped in an `sbx1` anonymous-sender sealed box, so the intermediary sees only `to_hint` + ciphertext — *"a message, to someone"*, not who/verb/tags. The outer is **always** `[to_hint, sealed]`:

```
outer: [ to_hint, sbx1_seal(to_pub, canon(inner, reply_key)) ]
inner:   the same signed { from, …, sig }        reply_key: a fresh ephemeral pubkey
```

- **`canon(…)`** is the existing canonical bencode (§0/§5) — injective, golden-pinned; no new encoding. The `dude.msg:` domain prefix keeps an envelope signature disjoint from an op signature or a proof-of-possession.
- **`to`** binds the message to one recipient *inside the seal* — the anti-reflection field; without it a signed request to A is replayable to B.
- **`epoch` is diagnostic, never a hard gate:** a roster bridge always has an activated party talking to a not-yet-activated one, so an envelope-level `epoch == current` refusal is the over-strict-gate (R1) class. Epoch is enforced by the artifact layer where it is load-bearing (receipts, QCs, RERECEIPT), not at the door.
- **`ts` (+ optional `nonce`)** is freshness/DoS hygiene, not correctness: verbs are idempotent and replay-protected, so a re-sent message is inert.
- **Sealed replies are symmetric:** the node seals its signed reply back to the request's `reply_key`, **also** as `[to_hint, sealed]` (the tag keyed by the reply-key), so the requester screens its own reply for one hash before opening it. The reply-key is **required** in sealed mode (an optional one is a downgrade lever; a sealed request without it is malformed).

**Screening tag `to_hint` — always present on a sealed packet, checked before the ECDH:**

```
to_hint = keyed-BLAKE2(key = target_identity, person = "dude.screen", 16 bytes)(sealed)
```

The sender keys on the target's identity (from its endpoint record); the receiver keys on its **own** identity to test a match — **one symmetric hash, no ECDH** — so the unseal runs only on a tag hit. This is the DoS **pre-filter on every sealed message**, point-to-point as much as multiplexed (a future relay/MUC carrier reuses the *same* tag to pick its inbound; the reply's own tag does it in reverse — additive, not a mode). Over the non-deterministic ciphertext, so it is per-message and unlinkable. **Identity-keyed, deliberately not epoch-keyed:** an epoch-scoped key deadlocks a from-scratch sync (you can't screen the messages that would deliver the epoch key); a node always holds its own long-term identity, so it screens from message zero. This gives a **cost ladder**: internet noise can't produce a valid tag → *free-dropped* at the hash rung (no ECDH); a blocked/ex node forges a tag, climbs to the ECDH rung, and **dies at the gate** (`from` ∉ current roster); members are served. What rests on roster-secrecy is *only* the free-drop rung and tag-unlinkability (best-effort, graceful degradation); admission and data confidentiality never do.

**The request gate** (L_msg's first consumer), on inbound before any store work: (1) if `sealed`, **screen the `to_hint`** (one hash) and drop on a miss, then unseal — else decode the plain envelope; (2) verify `sig` by `from`; (3) `to == self`, `ts` fresh (epoch is diagnostic only); (4) **check `from` against the live control-plane view** — current roster member / un-revoked cert; (5) dispatch, then sign (and, on a sealed endpoint, seal) the reply. Steps 1–4 reject revoked/non-members *at the door* — the gate authorizes the **requester**, never an artifact's author, so it never blocks an authorized proposer carrying a since-revoked author's op through recovery. A refusal is served **only** to a sender that proved it holds our identity (a valid sig over `to == self`), and it says *why* (`NOT_A_MEMBER` / `STALE_ENVELOPE`, not a generic `BAD_AUTHZ`); anything unproven gets **silence** (the carrier's native nothing — closed frame / no stanza / 404), so a reply never leaks our pubkey. **Defence in depth:** gate/seal protect the door and metadata; application values are independently protected by the group *data* key (`xcs1`, DESIGN §7), which rotates on eviction — the layers fail independently. Extended rationale and the eviction/survivor-rekey boundary: [TRANSPORT.md](TRANSPORT.md).
