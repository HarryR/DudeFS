# DudeFS Formal Verification Plan

> **Status:** companion to [DESIGN.md](DESIGN.md) (rev 6). The question "TLA+ or Lean?" has a structural answer: the design already splits into a coordination layer and a safety layer (DESIGN §8, *safety layering*), and the two layers want different tools. This document states the split, the numbered hypotheses each tool must discharge, the model scope, and how the formal artifacts bind to the eventual implementation.

## 0. The split

| Layer | Nature | Tool | Deliverable |
|---|---|---|---|
| **The fold** (+ finality's fold-side half) | pure function; data-heavy; zero concurrency | **Lean 4** | machine-checked theorems **and** an executable reference oracle |
| **Slots, quorums, watermarks, roster, gossip** | temporal; interleaving-heavy; small state | **TLA+ (or Quint) + TLC/Apalache** | model-checked safety & liveness on small configs |

Why not one tool for both: TLC drowns in the fold's data domain and can prove nothing unbounded; asynchronous-interleaving proofs in a theorem prover are person-year territory (Verdi, IronFleet). The seam between the layers is an **assume/guarantee contract**: the TLA+ spec treats `fold` as an abstract deterministic function carrying exactly the properties Lean proves (A1–A7); the Lean development assumes exactly the committed-set properties the protocol layer checks (B1–B3).

**Order of attack: TLA+ first.** Model checking finds protocol bugs in days; theorem proving certifies in months. Evidence from our own history: a TLC run over revision 1 would have mechanically found both the guard-only-slot wedge and the roster dual-activation race — the bug class this design produces is precisely TLC's prey.

## 1. Idealizations (stated once, used everywhere)

- **Hashes** are injective on distinct inputs (collision-freeness is a hypothesis, not a theorem).
- **Signatures** are unforgeable; formally, authorship is ghost state. A Byzantine actor is a process freed from the protocol's transition rules but *not* from no-forgery.
- **The PRF** is an opaque injective map per secret: tag equality ⇔ (secret, preimage) equality. Nodes can evaluate nothing; clients holding the secret can evaluate anything.
- Encodings are injective (the wire format's obligation — PROTOCOL §5).

## 2. Layer A hypotheses — the fold (Lean 4)

- **A1 — Determinism / SEC.** `fold` is a pure function of the committed *set*: any arrival order yields identical `(state, applied-bits)`. Reduces to totality of the sort key `(hlc, author, seq, op_hash)` on distinct ops (needs hash injectivity) plus purity of the walk.
- **A2 — Lineage advance / no wedge.** For every key `k`, the sequence of expected tags `E(k)` never repeats, and every committed op whose tag equals `E(k)` at its position strictly advances `k`'s lineage. Corollary: from any reachable state there is always a fresh, never-decided tag — CAS can always proceed.
- **A3 — Lazy ≡ eager attribution.** The per-key lineage replay (count matching tags over the prefix) and the eager global walk of DESIGN §6 compute identical `(version, attempt, applied)` — including for undecryptable ops and keys revealed retroactively.
- **A4 — Barrier equivalence (rev 6: retained-set form).** If cut `C` is final w.r.t. committed set `S`: `fold(S) = fold(retained(S≤C) ∘ tail)`, where `retained(·)` is the DESIGN §12 retention rule (per-key winners + resurrection-mask tombstones **closed to a fixpoint** — a mask is itself replayed, so masks of masks are retained transitively; NOTES 33.7) folded mutations-only with the `attempts` sidecar applied. Bootstrap clients and full-history clients are byte-identical — including tombstone death, lineage reset to `(⊥, 0)`, and live-key `(version, attempt)` continuity. Conditional on an honest checkpoint (the selection-only trust surface, DESIGN §12); the resurrection mask and the sidecar are each *necessary* — dropping either yields a counterexample (NOTES 29a/29b).
- **A5 — Prefix stability (fold-side finality).** Extending the committed set only with ops of `hlc ≥ h` changes neither state-at-`h` nor any applied-bit of ops below `h`.
- **A6 — Transactionality.** Mutations are all-or-nothing; each op's guards see exactly the state produced by its predecessors in the total order.
- **A7 — Epoch coherence.** A2/A3 hold across mixed `keyepoch`s, with per-op secrets; a cross-epoch same-lineage race resolves to exactly one lineage advance.

The Lean fold **compiles**: it is the reference implementation, not just a model (see §5).

## 3. Layer B hypotheses — the protocol (TLA+/Quint)

- **B1 — Slot safety.** With crash-faulty acceptors, at most one op is ever **decided** per `slot_tag` — across *all* ballots (rev 5: every accept is prepared, so this is classic single-decree safety with no fast-round caveat; same-ballot quorum uniqueness is the lemma). Start from the canonical Paxos TLA+ specification as the skeleton; fifty years of settled proof structure, crib don't reinvent. *History note:* rev 4's ballot-0 fast path made only the same-ballot lemma true — the M3 sim exhibited an honest cross-ballot double-decide (the Fast Paxos collision, NOTES item 21), which is why the fast path was dropped rather than the hypothesis weakened. QuePaxa's Promela models (`references/quepaxa/model-checker/`) are adjacent prior art for the recorder-side state machine. *Rev 6 scope note:* reborn absent-key tags (DESIGN §12 — a deleted key's recreation reuses its creation tag) repeat across checkpoint-barrier intervals; B1 uniqueness is **per barrier interval** for those and global otherwise, and the §8 acceptor void rule (per-slot state below the horizon is dead on `prepare`) is the model element that keeps acceptor state consistent with that scoping. Live-key tags never repeat (the `attempts` sidecar).
- **B2 — Durability.** A committed op survives any ≤ f crashes/destructions: some copy exists in every quorum.
- **B3 — Finality.** Once any client holds quorum watermark floors ≥ `h`, no op with `hlc < h` is ever *newly* committed. (Models floor monotonicity, durability of floors, sign-after-fsync.)
- **B4 — Roster safety.** At most one roster op activates out of any epoch (the public slot); at activation, a quorum of the new roster holds every previously committed op (the possession barrier). No committed op is stranded by any sequence of joint changes — including arbitrary jumps (1→3).
- **B5 — Cross-epoch slot continuity.** A slot undecided at a roster change decides at most once across both epochs (the `RERECEIPT` rule cannot double-decide).
- *(B4/B5 get first claim on the model-checking budget: per-register consensus × membership change is precisely where CASPaxos's reconfiguration drew community fire, and reconfiguration is where Raft's post-publication bug hid — see RELATED.md §3/§5.)*
- **B6 — Byzantine containment** (the safety-layering claim, checked). With one unconstrained-but-non-forging node: duplicate same-slot QCs may exist, yet all honest clients' folds agree (A1 imported as assumption) **and** every safety violation implies the existence of two conflicting signed messages (evidence exists — detect-and-punish is total).
- **B7 — Liveness** (partial synchrony + fairness). A client that keeps retrying eventually gets its slot decided and a final verdict; specifically, the rev-1 split-vote deadlock is absent. Dueling-proposer livelock excluded only under backoff fairness — realized as the deterministic per-`(priority, round)` jitter plus per-round timeout escalation of DESIGN §8 (NOTES 23), modeled as a fairness assumption; drivers may add true entropy (NOTES 28) without touching the model. The partial-synchrony dependence is a *choice* with a documented escape hatch — QuePaxa-style randomized priorities over the same recorder state, RELATED.md §6 — so if backoff fairness ever proves operationally false, the fix is known and localized.
- **B8 — Amnesia safety.** The author-amnesia procedure (quorum-read head + wait δ) never produces a self-fork.

## 4. Model scope

Small-scope deliberately: `n ∈ {1, 3, 5}` · 2 clients · 1–2 keys · an hlc domain of ~6 values · ≤ 1 roster change and ≤ 1 checkpoint per behavior. Every bug found in this design's history manifests within that envelope (the small-scope hypothesis, locally verified). Byzantine runs: exactly one octopus node, per §1's idealization. TLC for explicit-state runs; **Apalache** for B3 (watermark arithmetic is integer inequalities — symbolic beats explicit) and for pushing B1/B4 toward parameterized `n`.

## 5. Binding to the implementation

- **Differential oracle:** the compiled Lean fold takes a committed set, emits `(state, verdicts)`; the production fold is fuzzed against it — byte-identical or bust. Every Lean theorem statement doubles as a property-based test generator.
- **Trace validation** (later): production nodes log protocol transitions; logs are checked as legal behaviors of the TLA+ spec (MongoDB/CCF practice). This is what keeps the model honest after the implementation starts drifting.
- The wire format inherits obligations, not freedoms: injective encodings and byte-stable content addressing (PROTOCOL §5) are *assumptions* of §1 — violating them voids every theorem above.

## 6. Backlog

- Surface-syntax taste call at kickoff: classic TLA+ vs Quint (same checker ecosystem, nicer type discipline).
- Which B-hypotheses get Apalache treatment beyond B3.
- B7 fairness formulation: weak fairness only, or explicit backoff timers.
- An unbounded/parameterized B1 proof (TLAPS or Ivy) if ever warranted — explicitly *not* on the critical path.
