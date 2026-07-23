# DudeFS Related Work — where this design sits in the literature

> **Status:** companion to [DESIGN.md](DESIGN.md) (rev 6). A positioned review of the Paxos/Raft/leaderless/randomized lines and Lamport's research, triggered by reading Cloudflare's Meerkat announcement and the QuePaxa paper (SOSP '23). The per-decision triangulation matrix (decision → prior mechanism → posture, with verified quotes) lives in [COMPARISON.md](COMPARISON.md); this document is the narrative. Verdict up front: **every pillar of DudeFS has a formal ancestor**, which is reassuring — and each ancestor's known failure modes tell us exactly what to model-check hardest.

## 0. Positioning: DudeFS is not SMR

Almost everything below — Paxos, Raft, QuePaxa, Meerkat — is **state machine replication**: agree on a totally-ordered log of *all* commands, then apply. DudeFS deliberately is not. Its one-line genealogy:

> Take Lamport's Generalized-Paxos observation (*only conflicting commands need ordering*) to its limit for a dictionary: commuting writes become a CRDT fold; conflicting CAS becomes a per-lineage single-decree register (CASPaxos kin); reconfiguration goes through an external master (Vertical Paxos — our manager); and acceptors are passive stores (Disk Paxos — our zero-knowledge nodes).

Terminology hazard when reading these papers: their "slot" = a log index (every command gets one, sequentially). Our "slot" = a contention point (only CAS conflicts get one, per key-lineage). Different animals.

## 1. The map

| Line | Representative | Ordering | Contention unit | What DudeFS takes | What DudeFS rejects |
|---|---|---|---|---|---|
| Classic Paxos | Part-Time Parliament '98 | global log (Multi-Paxos) | log slot | single-decree safety core (ballots, quorum intersection) → our §8 | global sequencing |
| Raft / VR | Raft '14, Viewstamped Replication '88 | global log, strong leader | log slot | joint-config caution | leaders, timeouts, leases |
| Leaderless SMR | EPaxos '13, Mencius '08, Tempo '21, Accord | per-command dependency graphs / timestamps | command | timestamp-ordered commit kinship (HLC fold) | dependency-graph execution |
| Register / KV | ABD '95, Disk Paxos '03, CASPaxos '18 | none (per-register) | register | **closest kin** — per-key ballots, passive acceptors | CASPaxos's ad-hoc reconfig |
| Randomized async | Ben-Or '83, Rabia '21, QuePaxa '23 | global log (QuePaxa) | log slot | hedging; content-oblivious adversary framing; validation of our fast-path shape | the full randomized core (overkill at our scale — §6) |
| Reconfiguration | Vertical Paxos '09, Raft joint consensus | — | config | **manager-as-external-master is Vertical Paxos**, formally | organic self-reconfiguration |

## 2. The Lamport line (what to actually read)

- **Time, Clocks, and the Ordering of Events (CACM 1978).** The ancestor of every logical clock, including our HLC. The happened-before relation is our `deps` frontier.
- **The Part-Time Parliament (TOCS 1998) / Paxos Made Simple (SIGACT News 2001).** The single-decree core — ballots, promises, quorum intersection — is *literally* our §8 slot machinery. Our B1 hypothesis (FORMAL.md) is the single-decree safety theorem restated; its proof structure is fifty years of settled ground we should crib, not reinvent.
- **Disk Paxos (Gafni & Lamport, 2003).** Acceptors as passive storage that never talk to each other in the decision path. This is the formal ancestor of our zero-knowledge nodes — and QuePaxa explicitly cites the same lineage for its proposer/recorder split. Precedent: dumb, passive, state-holding acceptors are a *sound* place to put the quorum.
- **Fast Paxos (Dist. Computing 2006).** Fast-path quorums vs classic quorums, and the collision-recovery cost. The warning landed: rev 4's ballot-0 fast path was a fast round on bare majority quorums, and the M3 simulation exhibited Lamport's "case 3 — we are stuck" collision with fully honest acceptors (NOTES item 21). Rev 5 dropped the fast path rather than pay the `N − ⌊N/4⌋` fast-quorum price — see COMPARISON.md row 2.
- **Generalized Consensus and Paxos (MSR TR 2005).** *The* formal justification for DudeFS's central bet: commands that commute need no relative order. LWW writes to different keys commute; the fold is a generalized-consensus structure where only same-lineage CAS ops constitute interference. Worth citing in FORMAL as the frame for A1/SEC.
- **Vertical Paxos (PODC 2009, w/ Malkhi & Zhou) and Reconfiguring a State Machine (SIGACT News 2010).** Configuration changes decided by an auxiliary master rather than by the group itself. **Our manager is a Vertical Paxos auxiliary master** — this is a peer-reviewed precedent that config-by-external-root is sound, plus a catalogue of the reconfiguration hazards (which our joint quorum + possession barrier + public roster slot address; hypotheses B4/B5).
- **The Byzantine Generals Problem (TOPLAS 1982).** The octopus's birth certificate; context for why we declined 3f+1 (RESILIENCE §3).
- **Specifying Systems / TLA+ (2002).** The verification plan's tool of record is Lamport's own; the canonical Paxos TLA+ specs are directly reusable as a starting skeleton for B1.

## 3. The Raft line

Raft (Ongaro & Ousterhout, ATC 2014; Viewstamped Replication is the 1988 ancestor) is what we're *not* building: strong leader, leases, timeout-driven elections — the exact "tyranny of timeouts" QuePaxa attacks, and irrelevant to a leaderless design. Two lessons still land:

- **Joint consensus** for membership change is the part of Raft we did adopt (§13) — and the later-discovered bug in the dissertation's *single-server change* optimization (found 2015, after publication and deployment) is the cautionary tale: reconfiguration edge cases hide from smart authors and reviewers alike. That bug class is exactly why B4/B5 exist and why they get model-checked, not argued.
- Raft's success is a **specification-clarity** lesson more than an algorithmic one. Our PROTOCOL.md plays the same role.

## 4. The leaderless / timestamp line

EPaxos (SOSP 2013) orders commands by dependency graphs, leaderless. Two independent cautionary tales hang off it, both pointing at dependency tracking: **the recovery-path correctness bug is Sutra's** (*On the correctness of Egalitarian Paxos*, arXiv:1906.10917, 2019 — cited by, not found by, the NSDI paper); **EPaxos Revisited (NSDI 2021)'s own finding** is that transitive dependency chains grow without bound under skew — 5-second tails and outright execution livelock ("dependencies may chain recursively and an instance cannot execute until all of its transitive dependencies have committed") until they patched a bound in. Mencius (OSDI 2008) rotates log ownership. Tempo (EuroSys 2021) and Accord (Cassandra's CEP-15) commit via quorum-agreed *timestamps* — the nearest SMR relatives of our HLC-sorted fold with watermark finality: both need a "this timestamp is now stable" mechanism, as we do (§9). The family resemblance is real but they still totally-order execution; we dissolve that need with the CRDT fold and pay instead with the finality wait.

## 5. The register line — closest kin

- **ABD (Attiya, Bar-Noy, Dolev — JACM 1995).** Quorum-replicated read/write registers without consensus. Our **blind LWW writes are ABD-shaped**: quorum write, quorum read, timestamp order, no agreement needed. Formal ancestor for the non-CAS half of the fold.
- **CASPaxos (Rystsov, 2018; Gryadka).** Per-register single-decree Paxos — no log, ballots per key, CAS as the change function. This is DudeFS's slot machinery's nearest published relative. Two instructive deltas: (1) CASPaxos runs consensus *per key on the current value*; we run it *per lineage point on an opaque tag* and let the fold carry values — which is what lets our acceptors be zero-knowledge. (2) **CASPaxos's acknowledged weak point is reconfiguration** — the change is administrative (operators "connect to each proposer and update its configuration", not itself consensus-driven), a K-key store must re-run an identity transition *per key* to migrate, and the paper's own §2.3.2 concedes that mis-sequenced shrink/extend can "sequentially replace every acceptor with an empty acceptor, lose all data and violate linearizability"; external critiques (Howard et al.) pressed the same seam. Per-register consensus multiplied by membership change is a hazardous product. We answered with Vertical-Paxos-style manager changes + the possession barrier + `RERECEIPT` + the public roster slot; B4/B5 are the hypotheses that must carry that weight. This is where our model-checking budget should concentrate.

## 6. The randomized line — Ben-Or → Rabia → QuePaxa

**FLP (JACM 1985)** forbids deterministic asynchronous consensus; every protocol picks its dodge. Classic Paxos/Raft pick partial synchrony (timeouts). Ben-Or (PODC 1983) picked randomness; Rabia (SOSP 2021) made that practical for low-delay datacenter SMR; **QuePaxa (Tennage, Băsescu, Kokoris-Kogias, Syta, Jovanovic, Estrada-Galiñanes, Ford — SOSP 2023)** made it practical *and* fast-path-competitive:

- **Mechanism** (from the paper): recorders hold *interval summary registers* — constant-space integer-max registers over `(priority, proposer, value)` triples, advanced by threshold logical clocks (`step = 4×round + phase`). Proposers attach **random priorities** each round; the leader (if any) gets the reserved maximum priority `H`, giving a 1-RTT fast path in round 1; rounds 2+ are fully asynchronous and each decides with probability ≥ ½ (decision test: `best(E) = best(U)` — best-existent equals best-universal). Simultaneous proposers *cooperate* (they help propagate the winning proposal) instead of destructively interfering as in dueling-ballot Paxos. **Hedging** (staggered activation: δ, 2δ, …) replaces timeouts; a multi-armed-bandit process tunes leader choice and the hedging schedule. Liveness needs a **content-oblivious network adversary** — satisfied by encrypting links.
- **Results:** 584k/250k cmd/s (LAN/WAN) normal-case, on par with Multi-Paxos; under targeted DoS on leaders, ~75k cmd/s at <380ms median while Multi-Paxos and Raft collapse to ~2.5k or stall. Model-checked in Promela/SPIN (their Appendix D) with proofs in an appendix — the same "check the core mechanically, prove on paper" posture as our FORMAL.md.

**What we take:**
1. ~~**Validation of the fast-path shape.**~~ *(historical)* QuePaxa's reserved-priority-`H` leader round resembled our rev-4 ballot-0 fast path — but the resemblance was the warning, not the validation: QuePaxa's fast round is safe because a *leader* owns priority `H`; ours was leaderless on majority quorums, which is the Fast Paxos collision (NOTES item 21). Rev 5 dropped the fast path.
2. **Hedging as client policy.** Submit to a preferred quorum, hedge the remaining nodes on a short stagger rather than timing out and blasting everyone. Adopted as a PROTOCOL §4 note — pure client policy, no protocol change (idempotency already makes it safe).
3. **The content-oblivious adversary, named.** Our RESILIENCE §3.6 said "TLS narrows metadata" — QuePaxa sharpens *why it matters for liveness*: an adversary who can read ballots/priorities off the wire can target the winning proposer indefinitely. With TLS, it can't aim. Now stated explicitly in RESILIENCE.
4. **Their verification order** (SPIN the core; prove around it) matches FORMAL.md §0 — independent confirmation of TLA+-first.

**What we decline, deliberately:** the randomized core itself. QuePaxa buys *timeout-free liveness under DoS-grade asymmetric attack* for a high-throughput global log. DudeFS has 1–3 clients, rare contention, no log, and a durability-over-availability posture that already accepts blocking. Classic per-slot ballots + randomized backoff are dramatically simpler, and our liveness hypothesis (B7) is honest about the partial-synchrony dependence. **Recorded as a fallback:** if backoff tuning ever becomes a real operational nuisance, the escape hatch is QuePaxa-izing the slot — recorders already look like ISRs (passive, constant-space per slot), so random priorities could replace client ballots without touching the fold, the QC format, or finality. The option is cheap to keep open and costs nothing today.

## 7. Meerkat (Cloudflare, 2025)

An experimental global consensus service for Cloudflare's control-plane state across 330+ datacenters: QuePaxa underneath, Rust, log-based SMR with linearizable reads *as log events*, CAS transactions, batching, tested to ~50 replicas; explicitly not production yet. Relevance to us:

- **Independent confirmation of the niche.** "Small, strongly-consistent, fault-tolerant control-plane state; availability so long as a client can reach any replica connected to a majority" is DudeFS's problem statement, minus our two extra axes: **zero-knowledge storage** and **provenance/detect-and-punish**. Nothing in Meerkat's design space addresses either — which is a decent argument that DudeFS isn't reinventing an available wheel.
- Their read path (reads become log events to get linearizability) is the SMR tax we avoid: our linearizable read is a quorum frontier + local fold + watermark check — no write amplification.
- They plan formal verification of a Rust implementation; worth watching as prior art for our trace-validation ambitions (FORMAL §5).

## 8. The clock line

HLCs are Kulkarni, Demirbas et al. (2014) — designed precisely so wall-time-meaningful timestamps can order events without wall-time trust; our envelope `hlc` is this, verbatim. Spanner (OSDI 2012) is the instructive contrast: TrueTime's commit-wait makes a write *invisible until its timestamp is past*, purchasing external consistency with special hardware and an ε-wait. Our watermark finality (§9) is the commodity-hardware dual: writes are visible immediately but *verdicts* wait for quorum floors — δ plays ε's role, enforced by receipt-refusal instead of atomic clocks.

## 9. The accountability line — detect-and-punish's ancestry

**PeerReview** (Haeberlen, Kouznetsov, Druschel — SOSP 2007) is the formal home of our detect-and-punish stance: replace Byzantine *prevention* (3f+1) with *accountability* — tamper-evident logs such that any observable deviation from the protocol yields a **verifiable, portable proof of misbehavior**, while omissions yield (only) verifiable *suspicion*. DudeFS instantiates the same theory with a sharper substrate: our per-author hash chains are PeerReview's tamper-evident logs, and our four equivocation classes (author fork, double-accept, floor perjury, roster double-receipt) are its "faults with proofs." The line PeerReview draws is the one RESILIENCE §1 inherits: **provable misbehavior earns cryptographic ejection; unprovable slowness earns only policy** — because an omission cannot be signed, no third party can distinguish a slow node from a slow path. Two more of its mechanisms were adopted at the M2.5 review (2026-07-20): its **authenticators** are the model for our `deps` semantics — a cross-node reference is a *commitment by its issuer* ("by sending α, j commits to having logged e…"), validated at receive time and usable as portable evidence, never a retroactive validity condition on the referencing entry (DESIGN §4, accept-time dep resolution) — and its **replay audit** (§4.7: re-run the reference implementation from a snapshot, any discrepancy is verifiable evidence "check[able] by any correct node"; §5.2: evidence outlives log truncation) is the shape of our checkpoint `state_acc` audit (DESIGN §12 / ACCUMULATOR.md, derive-and-verify). Blockchain slashing (Casper et al.) is the same idea with economic stakes bolted on; we substitute the manager's authority for the stake. Archived: `references/peerreview-sosp07.pdf`.

## 10. Changes adopted as a result of this review

1. **PROTOCOL §4** — hedged submission discipline (stagger, don't timeout-and-blast).
2. **RESILIENCE §3.6** — the content-oblivious liveness argument: TLS upgraded from "recommended for metadata privacy" to "the thing that denies a network adversary the aim it needs to attack CAS liveness"; targeted-delay starvation named as the residual (accepted, per B7's partial-synchrony honesty).
3. **FORMAL** — B1 to start from the canonical Paxos TLA+ skeleton; B4/B5 flagged as the budget-priority hypotheses (CASPaxos-reconfig and Raft-single-server lessons); QuePaxa-ization of slots recorded as the liveness fallback so B7's backoff assumption is a choice, not a corner.
4. **No change** to the core: the reading strengthened, rather than weakened, the four structural bets (fold over log; per-lineage registers over global consensus; Vertical-Paxos manager; Disk-Paxos-style passive nodes) — each now has named formal precedent.
