# DudeFS Resilience — faults & adversaries

> **Status:** companion to [DESIGN.md](DESIGN.md) (rev 5) and [PROTOCOL.md](PROTOCOL.md). Three personas in ascending malice: the **chaos monkey** (crashes, partitions, delays, duplication), the **destructive gorilla** (permanent loss of machines and disks), and the **evil interactive octopus** (Byzantine, adaptive, interactive — least likely, analyzed anyway). The tolerance table is at the end; the honest headline sits right above it.

## 0. Durable-state inventory

What each party must persist — in one crash-consistent durability domain, with **sign-after-fsync** discipline: never emit a signature whose justifying state could still be lost.

**Node** — lose any part ⇒ retire the identity (DESIGN §13):
- BLS identity key
- per-slot acceptor state `(promised, accepted_ballot, accepted_op)`
- highest attested watermark floor
- current `config_epoch` + control-plane view
- stored envelopes, receipts (own and gossiped), QCs, checkpoints, evidence

**Client:**
- signing key — loss is cheap: manager revokes and reissues; no data at risk
- own chain head `(seq, prev)` — loss without key loss ⇒ **author-amnesia procedure** (DESIGN §4): quorum-read own head, wait out δ, resume — or just retire the key
- group-key history — recoverable from log wrap-sets (PROTOCOL §3.3); worst case the manager re-wraps
- log cache — soft state, always refetchable

**Manager:** the root key — irreplaceable (DESIGN §3): escrow offline copies. Chain head: the author-amnesia procedure is *mandatory* (the root cannot be retired).

---

## 1. Chaos monkey — crash-restart, partitions, delay, duplication, reorder

### 1.1 Message-level chaos

Every verb is idempotent and every artifact self-authenticating (PROTOCOL §0), so per message: loss → retry; duplication → no-op; reorder → the gossip contiguity invariant defers, everything else commutes; replay → no-op; corruption → signature fails, drop. **There is no message whose loss or double-delivery changes an outcome — the monkey's entire arsenal converts to latency.**

### 1.2 Crash at every awkward moment

| Who / when | Outcome |
|---|---|
| Client dies mid-`SUBMIT` | Op is at some nodes. Gossip finishes it (QC assembled node-side) or the skew floor kills it. On restart: amnesia procedure, observe committed-or-dead, resume. Never half-applied — the fold is transactional. |
| Client dies mid-ballot-recovery | Any client (or the same one, later) re-runs `PREPARE` at a higher ballot. This is Paxos's whole point. |
| Node dies before persisting an acceptance | It never signed (sign-after-fsync) → as if the message never arrived. |
| Node dies after persist, before reply | Client retries; the identical receipt is re-issued. |
| Node restart | Rejoins gossip, catches up. Persisted floor prevents below-floor receipts; persisted acceptor state prevents double-votes. |
| Manager dies mid-roster-change | Steps are idempotent and the change is slot-guarded (`H("roster" ‖ e)`); resume verbatim or abandon — at most one change activates out of `e` regardless. |
| Manager dies mid-checkpoint | A checkpoint is one op: committed or not; retry verbatim. GC is lazy and local, so nodes GC'ing at different times is normal operation, not a race. |

### 1.3 Partitions

- **Minority side:** local reads only; `SUBMIT`s accumulate sub-quorum receipts that either complete on heal or die at the skew floor; slots may half-promise — recovery ballots (on the majority side, or after heal) finish them. **Blocks, never forks** — the deliberate CAP posture (DESIGN §1).
- **Majority side:** full service, oblivious.
- **Heal:** anti-entropy unions the halves. Nothing conflicts, because nothing sub-quorum ever counted.

### 1.4 Clock chaos (the monkey owns NTP)

| Fault | Effect |
|---|---|
| Client clock fast | Its ops bounce as `future_hlc` → that client loses availability until its clock is fixed. |
| Client clock slow | Its ops bounce as `below_floor` once behind quorum floors → same. |
| Node clock fast | Its floor (`= max(hw, local_now) − δ`) races ahead → it refuses honest current traffic and effectively self-removes. Its inflated floor is still a *valid* promise it must keep — aggressive, not unsafe. |
| Node clock slow | Its floor lags → it contributes late to finality quorums. Harmless from a minority; a slow *quorum* drags the finality frontier (latency, never safety). Persistent laggards show up in floor spread and are replaceable by policy (PROTOCOL §2.3). |
| Skew within δ | Invisible by design. |

Clocks touch **liveness only**. No clock value anywhere decides a winner (DESIGN §11).

### 1.5 What the monkey cannot do

Lose committed data. Fork state. Flip final verdicts. Break determinism. Every capability it has degrades service; none of them corrupts it.

---

## 2. Destructive gorilla — permanent loss

### 2.1 Within tolerance: ≤ f = (n−1)/2 destroyed forever

- **Durability:** committed ⇒ ≥ q = ⌈(n+1)/2⌉ copies; survivors ≥ n − f = q ⇒ pigeonhole leaves at least one surviving copy of every committed op (and in practice clients hold copies too).
- **Availability:** the survivors themselves form a quorum → service continues uninterrupted; replace losses at leisure (learner → promote, PROTOCOL §3.1), with the dead nodes' identities retired.
- **Partial disk loss = total loss.** The durability domain is indivisible (§0): a node missing its acceptor state is a menace, not an asset.
- Worked example, n=7: destroy any 3 → business as usual. The 4 survivors hold a copy of everything and form quorums.
- **Connectivity is a separate axis from survival.** The mesh needs only a *connected* reachability graph across any mix of transports (PROTOCOL §7.4) — the gorilla can sever whole transport classes without partitioning the roster, and a client with a path to just one live node retains full correctness at relay latency (PROTOCOL §7.3). Destroying *machines* and destroying *routes* are both survived, independently.

### 2.2 Beyond tolerance: > f destroyed — catastrophic recovery (explicit, manager-driven, auditable)

With fewer than q survivors nothing new can commit — the system is already parked. Recovery:

1. **Salvage:** union all surviving evidence — every remaining node **and every reachable client**. Clients fold the full log, so they are replicas of everything they ever saw; this is the payoff of client-side folding.
2. **Verify:** every artifact is self-authenticating; the salvaged set is a provably genuine subset of what was committed.
3. **Fence:** the manager mints a **recovery checkpoint** at the salvage frontier plus a fresh roster (all-new identities) — a manager-signed **epoch fence**, visible in the log forever.
4. **Disclose:** any committed-but-unsalvaged op is *lost*. If its QC ever surfaces, that QC is a cryptographic receipt of the broken durability promise — detect-and-disclose, never silently rewrite.

Across a fence: strong eventual consistency of the salvaged prefix holds; linearizability does **not** span the fence, and the design refuses to pretend otherwise.

Why exactly f: an op committed to exactly q nodes, all q of which the gorilla destroys (possible once losses exceed f), has no node copy left — which is precisely why salvage step 1 reaches for clients.

---

## 3. Evil interactive octopus — Byzantine, adaptive, interactive

The trust model is crash-faults + detect-and-punish (DESIGN §13); this section maps the cliff edges without pretending to move them.

**Headline:** *confidentiality and state convergence survive everything below root compromise. Coordination (CAS exclusion) and finality are guaranteed only by an honest quorum — a Byzantine violator cannot be prevented, but every violation necessarily manufactures a portable signed proof of its own occurrence, and even mid-violation, honest clients never diverge on state.*

### 3.1 One evil node

| Move | Result |
|---|---|
| Forge or alter ops | Impossible — client signatures, AEAD. |
| Read data | Impossible — zero-knowledge; it sees only the §7 leakage boundary. |
| Withhold / omit / eclipse a client | Staleness or parked writes for the victim; never unsafety. Healed by one honest contact. An availability nick. |
| **Slot equivocation** (accept two ops for one tag) | Can mint **two QCs for one slot** when the two quorums intersect only in it. Blast radius: **state — none** (the lineage-advance invariant collapses duplicates: first folds, rest go `stale`); **success claims — none** (success is fold-verdict-at-finality; DESIGN §8, safety layering). Cost: wasted round trips. Two signed receipts at the same `(tag, ballot)` for different ops = proof → ejected. |
| **Floor perjury** (attest a floor, receipt beneath it later) | Can let a straggler commit under an already-claimed finality frontier → a verdict some client had called final flips. State still converges (the straggler folds identically for everyone). The WM + the receipt are self-contradicting signatures = proof → ejected. Preventing (rather than detecting) this needs an honest quorum behind every attestation — exactly the standing trust assumption. |
| Gossip lies | Chains and artifacts self-validate; lying reduces to omission (above). |

### 3.2 Colluding minority (< q)

The same list, executed more reliably. Still cannot: forge a QC (needs q signers), erase committed data (≥ q copies, plus clients), or halt the honest majority.

### 3.3 Colluding majority (≥ q)

Can halt everything, double-decide any slot, fake finality at will. Still cannot: forge a single op, read one byte of plaintext, or make two honest clients that exchange logs disagree on the fold. Every fake artifact remains signed evidence. **Confidentiality survives total node compromise** — the zero-knowledge property is unconditional on node behavior.

### 3.4 Evil client (authorized, pre-revocation)

- **Garbage / griefing writes:** attributed, reversible (tombstones + live log), revocable.
- **Slot griefing:** neutralized by attempt counters (DESIGN §6) — a burned slot costs one lineage increment, never a wedge. This includes *invalid* ops: an attributed op that folds `invalid` still consumes its slot (the universal lineage-advance rule), so a just-revoked key-holder racing its own revocation inside δ can burn attempts — and can displace an in-flight honest CAS to `stale` by front-running its tag at a lower `hlc` — until rotation retires the old slot secret. Cost per burn stays one increment; the alternative (invalid ops not consuming) is a permanent wedge, strictly worse.
- **Self-fork (equivocation):** folds deterministically (`op_hash` order) + proof → revoked.
- **Exfiltration:** it holds the keys — unpreventable by construction. Revocation + rotation fence the future, never the past (DESIGN §15).
- **Collusion with nodes:** the union of the two power sets, which composes into nothing qualitatively worse.

#### The time-traveller (a clock-wielding client)

Caged by two gates and a frontier: the **future gate** (`hlc > now + δ` refused), the **past gate** (`hlc < floor` refused), and the **finality frontier**, below which the committed set is immutable. What remains is the δ-wide provisional zone, and every game inside it is bounded, attributed, and deterministic:

- **Forward-stamping** (`now + δ − ε`) wins LWW races — but an authorized client can already overwrite any key with a genuinely later write, so this adds attribution without adding power.
- **Back-stamping** reorders only the not-yet-final zone — which is exactly why CAS success is *verdict at finality*, never at QC (DESIGN §9).
- **Node-assisted travel** is floor perjury (§3.1) — provable, ejectable.

Residual, stated plainly: δ is the traveller's entire playground. Choosing δ trades the playground's size against how long an offline single-push write stays viable — one knob, both directions.

### 3.5 Evil manager

Game over by definition — it is the root of trust (DESIGN §2). One interactive nuance worth writing down: a malicious manager colluding with nodes can mount a **split-view attack** — distinct checkpoint lineages presented to disjoint victims. An isolated victim cannot detect this from inside the protocol; *any two* victims comparing artifacts detect it instantly, because everything is signed. Mitigations are operational, not protocolar: keep the root offline; treat any cross-client channel — even a hallway conversation — as an audit channel.

### 3.6 Evil network (MITM without keys)

Integrity intact — artifacts are self-authenticating. Its powers reduce to the chaos monkey's plus targeted censorship. **The one liveness subtlety** (sharpened by QuePaxa's analysis — [RELATED.md](RELATED.md) §6): CAS recovery is ballot-driven, and a network adversary that can *read* ballots off the wire can selectively delay whichever proposer is currently winning, starving slot liveness indefinitely while safety holds. TLS therefore does real work for **liveness**, not just metadata privacy: an encrypted-link adversary is *content-oblivious* — it can delay nodes, but it cannot aim. Residual: a content-oblivious adversary delaying a fixed minority is the chaos monkey; delaying a rotating majority halts progress like any quorum system's. Accepted, consistent with FORMAL B7's partial-synchrony honesty; the randomized escape hatch is on record in RELATED.md §6.

### 3.7 Tolerance table

| Property | monkey ≤f | gorilla ≤f | gorilla >f | octopus: 1 node | octopus: minority | octopus: majority | octopus: client | octopus: manager |
|---|---|---|---|---|---|---|---|---|
| Confidentiality | ✓ | ✓ | ✓ | ✓ | ✓ | **✓** | ✗ (holds keys) | ✗ |
| State convergence (SEC) | ✓ | ✓ | ✓ (salvaged prefix) | ✓ | ✓ | ✓ (among honest clients) | ✓ | ✗ (split view) |
| Committed durability | ✓ | ✓ | ✗ · with proof (fence) | ✓ | ✓ | ✗ · with proof | ✓ | ✗ |
| CAS exclusion | ✓ | ✓ | — | violable · **with proof** | violable · with proof | ✗ | ✓ | ✗ |
| Finality | ✓ | ✓ | — | violable · **with proof** | violable · with proof | ✗ | ✓ | ✗ |
| Availability | ✓ (latency) | ✓ | ✗ until recovery | ✓ | ✓ | ✗ | ✓ | ✗ |

Legend: **✓** preserved · **violable · with proof** = cannot be prevented, but any violation mints a portable cryptographic proof and never causes state divergence · **✗** lost. The two bold ✓s are the design's proudest cells: confidentiality against a fully Byzantine node majority, and CAS-exclusion violations that hurt nothing but latency.

---

## 4. Assumption ledger

Everything above, in one place:

- **Honest quorum** — for liveness, the CAS-exclusion *guarantee*, and the finality *guarantee*. Violations are detected, proven, and punished; never prevented.
- **≥ 1 honest reachable node** (or a peer client) — for read availability and eclipse healing.
- **Root key: secret AND available** — compromise = game over; loss = control plane bricked. Escrow accordingly (DESIGN §3).
- **Cryptographic primitives** — author signatures, the node MultiSig suite (v1: Ed25519 list; BLS12-381 + proof-of-possession when aggregated), AEAD (POC `auth-only` suite suspends confidentiality only — loudly), PRF.
- **Effective clock skew ≤ δ** — for write liveness only; never for safety.
- **Honest fsync** — the sign-after-fsync discipline (§0). An acceptor whose disk lies to it is a Byzantine acceptor: see §3.1, and note that even then the damage stops at coordination, never state.
