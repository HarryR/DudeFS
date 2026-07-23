# ACCUMULATOR — the state accumulator (state clock)

> **Status: normative (ratified).** Supersedes the binary Merkle `state_root` (DESIGN §12)
> as the checkpoint audit anchor and the state-coherence primitive; construction ruled ECMH
> over ed25519 (§6.1) and landed in code (`crypto`/`fold`/`compactor`/`control`). Also
> retires the cut-lag window `W` (§2/§7). Refines the "zero-knowledge forces the oracle
> upward" premise in the `compactor.py` header (§2). Referenced by DESIGN §12; FORMAL.md
> carries the soundness obligation (§8).

## 0. Summary

The live state at any point is a **set** of `key → (value, version, attempt)` entries.
Digest that set with a **homomorphic accumulator** `A` — a running fingerprint advanced
incrementally per applied op (a *state clock*), not recomputed from a snapshot. Then:

- a checkpoint's claimed state is **audited in O(Δ)** by any continuous **key-holder**
  against its own clock (mis-selection and all), incrementally, with no window `W` and no
  privileged full-history auditor;
- **checkpoint authoring is O(Δ)** (churn since the last cut), never O(n) (state size);
- peers **compare fingerprints in O(1)** during anti-entropy — a *structural* clock for the
  zero-knowledge storage nodes (same committed decisions?) and a *semantic* clock for the
  key-holders (same cleartext state?) — strengthening consensus from "same *ops*" to "same
  *decisions / state*".

The Merkle tree buys inclusion proofs this audit never uses, at the cost of forcing an
O(n) snapshot recompute — which is what pushed the audit into a "recompute-before-GC"
race in the first place (§1).

## 1. The problem with the Merkle `state_root`

`fold.state_root` is a binary BLAKE2 Merkle root over the sorted live leaves
`(key, value, version, attempt)` (DESIGN §12). Three defects:

1. **O(n) snapshot recompute.** Verifying the root requires *all* leaves, sorted, and a
   full tree rebuild. It is not incremental: every audit re-folds the entire state.
2. **It manufactured the "audit-before-GC" race.** Because verification needs the whole
   leaf set, DESIGN §12 / PROTOCOL §3.2.5 framed auditing as *"a resident full-history
   client recomputes `state_root` within `W` and shouts on mismatch"* — coupling an
   **integrity** property to a **liveness** window `W` and to a privileged full-copy
   holder. That framing is a symptom of the wrong digest, not a real requirement (§2).
3. **Wrong tool.** A Merkle tree's distinguishing feature is O(log n) inclusion proofs.
   This audit never produces one — it checks a *whole-state* equality. Paying tree
   structure for a fingerprint we only ever compare wholesale is pure overhead.

## 2. The "full history" framing is false — and the audit is a key-holder's job

Two premises the old framing rested on are wrong; a role distinction it ignored is what
actually matters.

- **There is no "full history."** Once the conveyor advances, the compacted state **is**
  the history — retained-bootstrap ≡ full fold (A4). There is no privileged full copy to
  audit *against*; there is one state.
- **The compactor holds no privileged *visibility*** — but confidentiality splits the
  cluster by role, and the audit lives on the key side of that split:
  - **Storage nodes are zero-knowledge.** They hold ciphertext, opaque slot-tags
    (`PRF(slot_secret, path‖…)`), the op DAG, and QCs — but never cleartext: not paths,
    not values, not even SET-vs-DEL (the mutations ride the *encrypted* payload). A
    storage node therefore **cannot** fold semantic state, and cannot check the
    compactor's selection.
  - **Clients decrypt.** The compactor is a **client-side, key-holding**,
    manager-adjacent `compact`-cap identity with *fewer* privileges. The party that
    computes the dead set (the compactor) and the parties that can **verify** it (other
    key-holding clients) are peers. *(This refines — does not retire — the `compactor.py`
    header: the ZK-node premise stands; "only the compactor decrypts" becomes "all
    key-holders decrypt; the compactor is merely the one that runs compaction, and its
    peers verify it.")*
- **What makes GC safe is structural, not a race — and clients never ratify.** Storage
  nodes enforce the checkpoint's *partition* without decrypting: every committed op ≤ cut
  is classified `dead` or `retained`, and `(below-cut ∖ dead)` must hash to the checkpoint's
  `retained` commitment — this is `verify_baseline`, already wired into adoption. A node
  holding an op the compactor tried to silently drop recomputes a mismatching digest and
  refuses the checkpoint, so **no committed op can be silently omitted**. GC then proceeds
  on the compactor's authority (a `compact`-cap identity) + its committed QC + this
  partition check. **Clients are never waited on** — ephemeral, offline, provisioned by the
  day and dropped (or persistent for months), they cannot ratify anything in-band; a
  checkpoint is a *fast-sync artifact*, and what a client signs is its own lineage.
- **The residual trust is the dead-set *classification*** — whether an op marked `dead` was
  *actually* superseded, which a ZK node cannot check. It is caught **opportunistically**,
  against **client-durable evidence**: an author holds its ops and their QCs indefinitely
  (the lineage it signs), so "op `O` was committed" is provable weeks later, long after
  every node GC'd its copy. So catching a mis-classification **never races GC** — the
  evidence does not expire with GC. A bad checkpoint is a *trusted-compactor compromise*
  (same class as manager compromise): detected into portable evidence, ejected, recovered
  via the fence path — never prevented, never timed. **There is no `W`** (the cut is exactly
  ≤ F, not F − W; §7).
- The **accumulator is the mechanism** of that opportunistic audit: a key-holder with
  continuity across the cut recomputes `A_cut =? A_prev ⊕ Δ(tail)` (or, cold-bootstrapping,
  the internal-consistency check `A(barrier) =? A_cut`) in O(Δ) and shouts on mismatch
  (§5.1) — cheap enough that any key-holder does it as a matter of course.

This gives the accumulator **two views** (§5): a ZK **structural** clock the storage nodes
maintain (op/slot coherence, no keys), and the **semantic** state clock the key-holders
maintain (the checkpoint's cleartext audit anchor, replacing `state_root`).

## 3. The state accumulator

### 3.1 State as a set

The live state at a barrier is
`S = { e(k) : k live }`, where the **element encoding**
`e(k) = enc(k ‖ value_k ‖ version_k ‖ attempt_k)` is a **canonical, injective,
length-prefixed** serialization. Injectivity is load-bearing: distinct live states must
yield distinct element sets, or the digest is meaningless. Tombstones contribute nothing
(they are absent from `S`).

### 3.2 The accumulator

An accumulator is a map `A : 2^E → G` into a group `(G, ⊕)` that is **homomorphic over
set union of distinct elements** and driven by a per-element map `φ : E → G`:

```
A(∅)        = identity(G)
A(S ∪ {e})  = A(S) ⊕ φ(e)          (e ∉ S)
A(S ∖ {e})  = A(S) ⊖ φ(e)          (⊖ = the group inverse of ⊕)
```

`A(S)` depends only on the **set** `S`, never on insertion order (commutativity). `φ(e)`
is `H(e)` mapped into `G` for the hash constructions, or `hash-to-prime(e)` for RSA (§6).

### 3.3 The state clock

Every **key-holder** (client / compactor) maintains the semantic `A` over its live state,
advancing it as it applies committed ops (storage nodes maintain the ZK *structural*
variant instead, §5.2):

| op on key `k` | clock update |
|---|---|
| create `k = s` | `A ⊕= φ(e(k,s))` |
| update `k: s₁ → s₂` | `A ⊖= φ(e(k,s₁)) ⊕= φ(e(k,s₂))` |
| delete `k: s₁ → ⊥` | `A ⊖= φ(e(k,s₁))` |

`A` is thus a **running fingerprint of live state — a clock**. Two replicas with equal
live state hold equal `A`, regardless of the order or the op-set by which they reached it.

## 4. Properties

- **O(Δ) authoring.** The compactor advances `A_cut` from `A_prev` by applying only the
  inter-cut tail's net element changes — cost ∝ churn, never ∝ |state|. A checkpoint
  carries `A_cut`; building it is cheap and warm.
- **~O(1) verification.** A node maintaining its own clock verifies a checkpoint two ways,
  both incremental: (a) *equality* — `A_cut == A_self` at the cut (O(1)); (b) *transition*
  — `A_cut == A_prev ⊕ Δ(tail)`, where `Δ(tail)` is folded from ops the node already holds.
  A fresh bootstrapping node pays O(|retained|) once to seed its clock, then O(1) forever.
- **Order independence.** `A` is a pure function of the live set, so divergent
  op-application orders converging to the same state converge to the same `A`.
- **Soundness.** `A(S) = A(S') ⇒ S = S'` except with negligible probability — reduces to
  collision-resistance of `φ`/`H` plus the accumulator's collision-resistance (§8).

## 5. Uses

### 5.1 Checkpoint audit (replaces `state_root`) — a key-holder's transition check

The checkpoint carries `A_cut` (the semantic clock at the cut) in place of `state_root`.
A **key-holding client** audits it — a storage node cannot and does not. Two checks, by
capability:

- **Continuous key-holder — mis-selection audit.** A client holding the prior cut's clock
  `A_prev` and the committed inter-cut tail verifies the *transition*:
  `A_cut =? A_prev ⊕ Δ(tail)`, `Δ(tail)` folded from ops it already holds. A wrongly-dropped
  winner / resurrected tombstone / stale value perturbs `Δ` and fails the check. **O(Δ), no
  full history, no window** — the evidence (the ops in `Δ`) is client-durable, so this catch
  can happen any time, not before a deadline. This is what makes the dead-set classification
  auditable (§2); silent *omission* is separately foreclosed by the storage nodes'
  `verify_baseline` partition check.
- **Cold-bootstrapping client — internal-consistency check.** With no `A_prev`, a client
  computes `A(barrier)` from the retained winners + unsealed sidecar (WP-A) and checks
  `== A_cut`: the claimed state matches the shipped retained set (catches tampering /
  corruption; the sidecar is part of the element, so a wrong attempt fails here too). It
  cannot *independently* catch mis-classification — it has nothing prior to compare against,
  so it trusts the checkpoint it boots from (weak subjectivity — the accepted price of
  fast-sync), a trust backed by the continuity-holding auditors above.

Mismatch ⇒ reject loudly. No privileged full-history holder, no O(n) snapshot, no window —
a cheap key-holder duty, done as a matter of course by anyone with continuity.

### 5.2 Consensus strengthening — two coherence checks, by view

- **Storage nodes (ZK, no keys): a *structural* clock** over committed
  `(slot_tag → winning op_hash)`. Exchanged in anti-entropy: `A_i == A_j` ⇒ identical
  committed *decisions*, O(1) — a fold-free agreement check that corroborates the quorum
  without any decryption. This is the "nodes check state against each other" use.
- **Key-holders: the *semantic* state clock** of §3. Two clients with equal `A` hold
  identical cleartext state, independent of op-set differences that fold equal.

Both lift anti-entropy from op-set comparison to fingerprint equality. The **ordered dual**
— a hash chain / Merkle-mountain-range over the committed op *sequence* — digests the
**log**: state (a set) wants the unordered accumulator, the log (a sequence) the ordered;
both let peers compare in ~O(1) and both strengthen agreement.

## 6. Constructions (the spectrum)

| accumulator | `G`, `⊕` | `φ(e)` | collision-resistance | remove/update | proofs | cost |
|---|---|---|---|---|---|---|
| **XHASH** (XOR) | `(GF(2)ᵇ, ⊕)` | `H(e)` | **not** CR — subset-XOR / k-sum (Bellare–Micciancio; Wagner) if leaves are grindable | trivial (self-inverse) | none | cheapest |
| **AdHash** | `(ℤ_M, +)` | `H(e)` | CR ≈ weighted subset-sum / knapsack hard (large `M`) | trivial (subtract) | none | cheap |
| **MuHash** | prime-order group, `×` | `H(e)`→group | CR ≈ discrete-log hard (`H` a RO into `G`) | inverse (÷) | none | cheap |
| **RSA / class-group** | `⟨g⟩ ⊂ (ℤ/N)*`, unknown order | `g^{hash-to-prime(e)}` | **strong-RSA** (unknown order: RSA trusted-setup **or** class groups, trustless) | hard without trapdoor / needs witness upkeep | **O(1) membership + non-membership** | heaviest |

Guidance:

- The state clock is **highly dynamic** — every op is a remove+add. XHASH/AdHash/MuHash
  remove trivially (self-inverse / subtract / divide); the **RSA accumulator's removal is
  its known weak point** (no cheap deletion without the group order or witness maintenance),
  a poor match for constant churn — **rejected as too heavy.**
- **XHASH is rejected — it is concretely broken here, not just theoretically.** The break is
  a *silent data omission*: a compactor drops keys `D ⊆ S` while claiming the honest
  `A_cut = A(S)`; the audit passes iff `⊕_{e∈D} H(e) = 0`, and with `|S| > 256` such a `D`
  **exists and is found by Gaussian elimination over GF(2)**. It fools both the bootstrap
  check *and* the transition check (the dropped set contributes 0). The constrained-leaf
  argument does **not** save it — the compactor drops *real* keys, never forging elements —
  and ROM one-wayness is irrelevant: the attack finds a linear dependency among *public*
  hash outputs, it never inverts `H`. (A **keyed** XOR multiset hash is secure — Clarke et
  al. — but our audit is *public*, no shared secret, so we cannot key it.)
- **AdHash is rejected** on cost: its modulus must grow to keep subset-sum hard as the set's
  element count rises (density `n/log M`), so the digest bloats with scale — the wrong shape
  (cf. bloom filters).
- **RSA / class-group** is rejected (above); it would only earn its weight for succinct
  membership proofs we don't need in the base clock.

### 6.1 Ruling — ECMH over the ed25519 prime-order subgroup

`A = Σ_k φ(e_k)` where `φ(e) = crypto_core_ed25519_from_uniform(H("dude.acc:v1" ‖ enc(e)))`
— libsodium's Elligator2 map **with the cofactor cleared**, landing on the prime-order
subgroup — and `Σ` is `crypto_core_ed25519_add`. This is **MuHash instantiated on an
elliptic curve (ECMH)**: collision-resistant under discrete log in the ℓ-subgroup (≈126-bit)
with `H`/`φ` a random oracle into the group; a colliding multiset is a nontrivial
`Σ aᵢ·φ(eᵢ) = 0`, i.e. a DL representation of the identity.

Why ECMH beats the alternatives for *this* system:

- **Fixed 32-byte digest, size-independent security.** DL-bound, so security does not decay
  as the state grows — unlike AdHash. A point is 32 bytes whether the state holds 10³ or
  10⁹ keys.
- **Trivial dynamic updates.** `add` / `sub` are the group op and its inverse — every op's
  remove-old-⊕-add-new is two curve operations.
- **No new dependency, no Ristretto, no unknown-order setup.** See §6.2.

Why **ed25519 + `from_uniform`**, not Ristretto255: a multiset-hash digest needs a
prime-order group (clean DL reduction, no cofactor-8 torsion relations) *and* a canonical
encoding (equal element ⟺ equal bytes). Ristretto packages both, but PyNaCl does **not**
expose it. We get the same two properties directly: `from_uniform` **clears the cofactor**
(prime-order landing), and the standard ed25519 compressed encoding of a *computed* subgroup
point is canonical (y reduced mod p + sign) — so byte-equality ⟺ point-equality. We never
decode an untrusted point into arithmetic (we compare our own canonical digest to the
claimed bytes), which is the only thing Ristretto's decode-side bijection would add.

### 6.2 References + verification

- Bellare & Micciancio, *A New Paradigm for Collision-Free Hashing: Incrementality at
  Reduced Cost*, EUROCRYPT 1997 — AdHash / MuHash / XHASH and the XHASH break.
- Clarke, Devadas, van Dijk, Gassend, Suh, *Incremental Multiset Hash Functions and Their
  Application to Memory Integrity Checking*, ASIACRYPT 2003 — multiset hashing for integrity
  (our exact use); XOR secure only *keyed*.
- Maitin-Shepard, Tibouchi, Aranha, *Elliptic Curve Multiset Hash* (ECMH), 2016 — the EC
  instantiation adopted here.

**Bindings verified** (PyNaCl 1.6.2 / libsodium in-repo): `crypto_core_ed25519_from_uniform`
(32B → prime-order point, output passes `is_valid_point`), `crypto_core_ed25519_add` /
`_sub` (commutative group with inverse), full `crypto_core_ed25519_scalar_*`. Functional
check confirmed order-independence and incremental removal (`A_{a,b,c} − φ(b) == A_{a,c}`);
32-byte digest. `crypto_core_ristretto255_*` is **absent** — hence the ed25519-direct route.

## 7. Integration (landed)

- `fold.state_root`/`_merkle_root`/`state_root_of_barrier` → `fold.state_acc(barrier)` +
  the incremental clock update (`crypto.acc_element`/`acc_add`/`acc_sub`/`ACC_IDENTITY`).
- `Checkpoint.state_root: bytes` → `Checkpoint.state_acc` (a 32-byte ECMH point). Wire-format
  change — the checkpoint golden vectors moved (behavior commit).
- `compactor.verify_state_root` → `verify_state_acc`, the §5.1 check. The `compactor.py`
  header refined per §2 (ZK-storage-node premise stands; the compactor is one key-holder,
  its peers verify).
- **`W` deleted; the horizon is exactly F.** `adopt_committed_checkpoints` refuses any
  checkpoint whose `horizon` does not cover its `cut` (every op ≤ cut sits at/below the
  horizon = F) — a structural, cleartext-hlc check, alongside the QC-verify and the
  `verify_baseline` partition. There is no `cut ≤ F − W`, no cut-lag tunable.
- **Not yet built (rides WP-G — the compactor driver):** the compactor maintaining the warm
  `A` and stamping `A_cut` incrementally; the storage nodes' *structural* clock (§5.2) for ZK
  anti-entropy; `A` on the gossip summary; the cut ≤ quorum-attested-F check at mint.

## 8. Soundness obligation (for FORMAL.md)

Model `φ`/`H` as a random oracle (or a CR hash into `G`). An **accumulator collision** is a
pair `S ≠ S'` of valid live-state sets with `A(S) = A(S')`.

- **AdHash:** a collision yields distinct element multisets summing equally in `ℤ_M`, i.e. a
  nonzero weighted subset-sum to `0` — infeasible for suitable `M`/output size.
- **ECMH / MuHash (adopted):** a collision yields a nontrivial `Σ aᵢ·φ(eᵢ) = 0` — a
  discrete-log representation of the identity in the ed25519 ℓ-subgroup — infeasible under
  DL, with `φ` (Elligator2-then-cofactor-clear) a random oracle into the subgroup. Security
  is independent of `|S|`.
- **XHASH (rejected):** a collision is a subset of `φ`-outputs XORing to `0`, found by GF(2)
  Gaussian elimination once `|S| >` the width — no grinding, no hash inversion. Instantiated
  here it is the *silent key-drop* of §6, defeating both audit checks. Not CR for a public
  (unkeyed) verifier.
- **AdHash (rejected on cost):** CR ≈ weighted subset-sum, but the modulus must scale with
  the element count, so the digest is not fixed-size.
- **RSA/class-group (rejected):** membership soundness under strong-RSA in an unknown-order
  group — power we don't need, weight (and awkward removal) we won't pay.

The ECMH-under-DL obligation joins the FORMAL track alongside A4 and B1–B6.

## 9. Open questions

1. ~~**Which accumulator.**~~ **Resolved: ECMH over the ed25519 prime-order subgroup**
   (§6.1) — 32-byte digest, DL-bound, bindings verified (§6.2).
2. **Unify the two coherence checks?** Does the state clock subsume the retained-set digest
   in gossip, or do both run (state clock for fold-equality, retained digest for op-set
   completeness)? §5.2.
3. **Ordered dual.** Is an ordered accumulator over the committed log wanted now (log
   coherence / faster anti-entropy), or is the unordered state clock sufficient for the POC?
4. **Domain separation & width.** `φ`'s domain tag, output width, and the `enc` canonical
   form must be pinned before the checkpoint golden vectors are regenerated (§7).
