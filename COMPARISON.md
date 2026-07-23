# DudeFS Comparison — decision-level triangulation against prior work

> **Status:** companion to [DESIGN.md](DESIGN.md) and [RELATED.md](RELATED.md).
> RELATED.md is the *narrative* literature review (lines of research, what to
> read); this document is the *matrix*: every load-bearing design decision,
> the specific prior mechanism it maps to, and an explicit posture. Quotes
> were verified against the PDFs in [references/](references/) at the M2.5
> review (2026-07-20); section numbers refer to those copies.
>
> **Postures.** **ADOPT** — concede to prior work; take the mechanism as
> established. **RECONCILE** — the same wisdom, restated in our frame; prior
> work is the justification. **CARVE** — no prior work occupies the cell; the
> novelty must be justified and is listed with its price. **DECLINE** — prior
> work solves a problem we deliberately don't have; declining is recorded
> with the trigger that would reverse it.

## 0. The two axes that generate every carve

Every DudeFS novelty traces to exactly two requirements that the SMR/register
literature does not combine:

1. **Zero-knowledge storage** — acceptors must coordinate CAS on values they
   can never read (DESIGN §7).
2. **Accountability** — every trust boundary short of the root is
   detect-and-punish, with portable cryptographic evidence (RESILIENCE §3,
   PeerReview lineage).

A decision that doesn't touch either axis should ADOPT or RECONCILE; a CARVE
that can't cite one of these two axes is a red flag to re-examine.

## 1. The matrix

| # | DudeFS decision | Prior mechanism (verified) | Posture |
|---|---|---|---|
| 1 | Per-slot single-decree ballots (DESIGN §8) | Paxos single-decree core: ballots, promises, quorum intersection (*Paxos Made Simple* §2.2, P2) | **ADOPT** — B1's proof structure is fifty years settled; crib, don't reinvent |
| 2 | ~~Ballot-0 fast path~~ → classic two-phase always (rev 5) | **Fast Paxos** (verified): a fast round on majority quorums leaves recovery "stuck" between two O4-eligible values (§3.1 case 3); the repair is the Quorum Requirement (b) — fast quorums of `N − ⌊N/4⌋` (3-of-3 at n=3), plus the O4 selection rule | **DECLINE the fast round entirely** — the M3 sim exhibited exactly Lamport's case 3 with honest acceptors (NOTES item 21). Rather than pay his fast-quorum price for a guarantee nothing downstream consumes, rev 5 drops to classic 2-RTT: ultra-durability over latency, and rows 1/14's claims become unconditional |
| 3 | Universal lineage-advance: an attributed op consumes its slot however it folds, including `invalid` (DESIGN §6, NOTES 14) | Multi-Paxos **no-op gap-filling**: "we let it fill the gap immediately by proposing … a special 'no-op' command that leaves the state unchanged" (*Paxos Made Simple* §3); the parliament's "olive-day decree" (*Part-Time Parliament* §3.1). Safety is value-agnostic: after phase 1 the proposer is "free to propose any value" | **RECONCILE** — an invalid-but-attributed op is our olive-day decree: the instance is spent, the sequence advances, the value means nothing. Settled wisdom applied per-lineage |
| 4 | The tag lineage itself: `(key, version, attempt)` reborn per contention point, PRF-opaque (DESIGN §6–§7) | **CASPaxos contrast** (Rystsov '18 §2.2): one *eternal* register per key, continuously re-prepared ("replicates state"), version discipline pushed *inside the value* ("if x = (5,∗) then (6, val1)"). No spent-instance notion exists — and none is needed, because acceptors read values | **CARVE (axis 1)** — CASPaxos can reuse one register only because its acceptors see state. Blind acceptors can compare nothing but tags, so the register must be reborn per lineage point; the `attempt` counter is the price of blindness, and #3 is the no-op rule applied at every rebirth. This is the design's core novel cell |
| 5 | Passive, store-shaped acceptors | Disk Paxos (Gafni & Lamport '03): acceptors as storage that never talks in the decision path | **ADOPT** the passivity; **CARVE (axis 1)** the opacity — Disk Paxos disks hold plaintext |
| 6 | Manager-driven configuration | Vertical Paxos auxiliary master (PODC '09) | **ADOPT** — peer-reviewed precedent that config-by-external-root is sound |
| 7 | Joint-quorum roster change + **data-possession barrier** + public roster slot (DESIGN §13) | Raft joint consensus (+ the post-publication single-server-change bug as the cautionary tale); CASPaxos reconfig as the anti-pattern: administrative ("connect to each proposer and update its configuration"), per-key identity-transition rescans, and the paper's own §2.3.2 hazard — mis-sequencing can "sequentially replace every acceptor with an empty acceptor, lose all data and violate linearizability" | **ADOPT** joint quorums; **CARVE (axis 2 + leaderlessness)** the possession barrier — Raft has no analogue because its leader *ships* data to laggards; leaderless, the new-roster QC must itself be a data-possession proof. B4/B5 carry the weight; this row is why they get the model-checking budget |
| 8 | HLC total order; **no dependency-graph execution** (DESIGN §4, §6) | HLC Theorem 1 (`e hb f ⇒ hlc.e < hlc.f`, one-way by design) and its explicit contrast with dependency-graph services: with clocks, "the ordering is based solely on the timestamps assigned to the events" (HLC §6.3, the Kronos comparison). The dependency-graph road's costs, measured: EPaxos recovery correctness bug (Sutra 2019, arXiv:1906.10917) and unbounded dependency chains — 5s tails, livelock — under skew (EPaxos Revisited, NSDI '21 §3, §6.4) | **ADOPT** HLC; **DECLINE** dependency-graph execution, twice-cautioned |
| 9 | `deps` = accept-time commitments, never fold-validity (DESIGN §4, NOTES 20) | PeerReview authenticators (SOSP '07 §4.4–4.5): a cross-node reference is a *commitment by its issuer* ("by sending α, j **commits** to having logged e…"), validated at receive time ("if the signature in α is not valid, j discards m"), forwarded as evidence — never a retroactive validity condition on the referencing entry | **ADOPT** — deps resolve before a node accepts (PULL-then-accept), so forks mint evidence at first cross-view contact; the fold ignores them (HLC needs no help, row 8) |
| 10 | Watermark finality: verdicts freeze when quorum floors pass `hlc` (DESIGN §9) | Spanner commit-wait (OSDI '12): delay *visibility* until TrueTime uncertainty ε passes, on special hardware | **RECONCILE** — the commodity-hardware dual: visibility is immediate, *verdicts* wait; δ plays ε's role, enforced by receipt-refusal instead of atomic clocks |
| 11 | Checkpoint anchoring & per-node lazy GC (DESIGN §12, PROTOCOL §3.2) | Raft §7: `lastIncludedIndex`/`lastIncludedTerm` "preserved to support the AppendEntries consistency check for the first log entry following the snapshot"; "each server takes snapshots independently, covering just the committed entries" | **ADOPT** the anchoring/horizon half — our `checkpoint_head`-anchored frontier and independent node GC are the same theorem shape. *Rev 6:* the snapshot-*contents* half of Raft §7 is superseded by row 20's retention model (no materialized state ships) |
| 12 | **Derive-and-verify** barrier: a key-holder with continuity derives barrier state and audits the `state_acc` ECMH accumulator (incrementally, O(Δ), no window); the fold never adopts snapshot content (DESIGN §12 / ACCUMULATOR.md, NOTES 13) | Raft's receiver rules 7–8 — "discard the entire log; reset state machine using snapshot contents" — with *no* content verification ("consensus has already been reached when snapshotting" justifies blind trust in a crash-fault leader). PeerReview's replay audit (§4.7): re-run the reference implementation from a snapshot; "any discrepancy … is verifiable evidence" checkable by anyone; evidence survives log truncation (§5.2) | **CARVE at the seam (axis 2)** — Raft's compaction mechanics + PeerReview's audit, combined because our compaction authority is trusted-*but-audited*: compaction must stay a compression channel, never a write channel. Explicit price: A4 is conditional on an honest checkpoint; the audit converts violations into portable evidence rather than preventing them. *Rev 6 strengthens the cell:* retained winners are author-signed originals, so checkpoint tampering structurally reduces to **selection** (omission) — the audited residue shrinks from "the whole materialized state" to "the dead set" (row 20, DESIGN §12 trust surface) |
| 13 | `pver` fence activates at the checkpoint barrier (DESIGN §16, NOTES 15) | Raft snapshots carry "the latest configuration in the log as of last included index" (§7) | **RECONCILE** — config-rides-the-snapshot has precedent; "compaction is the upgrade mechanism" is the same idea for fold semantics |
| 14 | Detect-and-punish; proof vs. suspicion (RESILIENCE §1, §3) | PeerReview *exposed*/*suspected* (§3.4, §4.2): provable deviation yields portable proof; omission yields only (retractable) suspicion — "there is no 'smoking gun'" for silence | **ADOPT** — instantiated with the manager's authority in place of witness sets/stakes; our four equivocation classes are its "faults with proofs" |
| 15 | Blind LWW writes need no consensus | ABD ('95): quorum-replicated registers, timestamp order, no agreement | **ADOPT** — the non-CAS half of the fold |
| 16 | Commuting writes need no relative order (the fold as CRDT) | Generalized Consensus (Lamport, MSR TR 2005) | **ADOPT** as the formal frame for A1/SEC |
| 17 | Randomized asynchronous core | QuePaxa (SOSP '23) | **DECLINE** — buys timeout-free liveness under DoS for a high-throughput log; at 1–3 clients with rare contention, backoff suffices. Reversal trigger recorded (RELATED §6): if backoff fairness proves operationally false, QuePaxa-ize the slot — recorders already look like ISRs |
| 18 | Byzantine 3f+1 | Byzantine Generals ('82) | **DECLINE** — nodes can't read data and the threat model is crash+audit; axis 2 (accountability) is the chosen substitute, per row 14 |
| 19 | Leaders, leases, timeouts | Raft / VR | **DECLINE** — nothing in the design depends on a client timing out "correctly" (PROTOCOL §4); hedging replaces timeouts (QuePaxa's gift, RELATED §6) |
| 20 | Log-compaction: per-key winner ops retained **in place**, sparse log, conveyor cut, compactor-computed dead-deltas (DESIGN §12, rev 6) | **Kafka compacted topics**: per-key retention of the latest record, offsets preserved, log goes sparse, superseded records dropped; the *broker* computes the winner set from plaintext keys | **ADOPT** the retention shape (in-place winners, sparse offsets, churn-proportional cleaning); **CARVE (axis 1)** the authority — our storage nodes can never see supersession, so the dead set must be computed by the key-holding **compactor** and shipped as signed deltas, with a per-author retained-set commitment standing in for the broker's self-knowledge. Price: the compactor-oracle role (a delegated capability — DESIGN §12/§15, root stays offline) + the declared selection-trust surface + epoch-key history load-bearing for as long as any winner from that epoch is live |

## 2. Nearest-neighbor triangulation

The closest systems, and the axis on which each falls short of the niche:

| System | Shares | Lacks |
|---|---|---|
| **CASPaxos / Gryadka** | per-key single-decree CAS, no log, passive acceptors | zero-knowledge (acceptors read state); sound reconfiguration (administrative, §2.3.2 hazard); provenance/audit |
| **etcd / Consul** | small config store, CAS, watches | zero-knowledge; accountability; both are leader-SMR with the availability posture we declined |
| **Meerkat (Cloudflare '25)** | exactly our problem statement — small strongly-consistent control-plane state, availability via any-replica-to-majority | both axes: no zero-knowledge, no detect-and-punish; also pays the SMR read tax (reads as log events) that our frontier-fold read avoids |
| **PeerReview** | accountability substrate: tamper-evident logs, portable proofs, replay audit | no data plane at all — it audits *protocols*, not storage; we fuse its audit with an actual replicated store |
| **Encrypted KV / E2EE sync stores** (etcd+TLS, Keybase-style stores) | ciphertext at rest | coordination on ciphertext: none offers linearizable CAS decided *by* blind servers — encryption is at rest/transport, servers still order plaintext-visible keys, or there is no CAS at all |

**The niche, one sentence:** *linearizable CAS decided by servers that can never
read a key or value, over a deterministically-refoldable provenance log where
every trust boundary below the root yields portable cryptographic evidence —
per-lineage consensus on PRF-opaque tags (the empty cell of row 4) is the
mechanism that makes the combination possible.*

## 3. The prices, stated plainly

Carves and declines are only honest with their costs on the table:

- **Finality wait** (rows 3, 10): CAS success is knowable one watermark round
  after δ — the Spanner-dual tax, paid in latency instead of hardware.
- **Two-RTT writes** (row 2): every slotted proposal runs both Paxos phases —
  the deliberate rev-5 price for unconditional single-decree; at config-store
  cadence the extra round trip is noise against the finality wait.
- **Conditional A4** (row 12): snapshot/history equivalence holds only for
  honest checkpoints; the audit detects, never prevents. Manager compromise
  was already game-over (DESIGN §2); this extends nothing, but the theorem is
  weaker than Raft's unconditional (trust-based) version.
- **Attempt-burn griefing** (rows 3–4): a recently-revoked key-holder can
  consume attempts until rotation lands (RESILIENCE §3.4) — the wedge-free
  property is bought with bounded burnable work.
- **Blocking minority** (posture, DESIGN §1): durability over availability,
  deliberately — the CAP price Meerkat and etcd pay differently.
- **Deps liveness deferral** (row 9): an op submitted to a context-lacking
  node defers until anti-entropy fills the gap — same price already paid for
  chain contiguity.
- **Partial-synchrony liveness** (row 17): B7 depends on backoff fairness;
  the reversal trigger is recorded, not hand-waved.
- **Selection trust + forever-keys (row 20):** bootstrap clients trust the
  dead-set *selection* (audited opportunistically by any continuity-holding
  key-holder against client-durable lineage — no window; ACCUMULATOR §2);
  epoch-key history and per-`pver` mutation-decode back-compat stay
  load-bearing for as long as any winner from that era remains live — the
  re-anchor op is the recorded escape hatch (DESIGN §12).
