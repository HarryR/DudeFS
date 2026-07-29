# FRAMING.md — what DUDE is, and what the hard problem actually is

Written after eighteen probes in [experiments/](experiments/), several of which overturned conclusions
reached by argument. It exists because the problem was repeatedly mis-stated — including by this
document's author — and a wrong framing is more expensive than a wrong answer.

---

## 1. What it is

**D**istributed · **U**ltra-**D**urable · **E**ncrypted.

A coordination substrate for **blockchain intent-space** workflow automation. Long-running,
multi-step jobs whose intermediate state must survive anything, executed by workers that may change
between steps, holding key material throughout.

| | |
|---|---|
| **storage nodes** | ~11 low-spec VPS across jurisdictions, continents, legal regimes. **Untrusted** — SPEC 6.2 gives them no trusted component. |
| **workers** | a small number of systems in TEEs. They hold key material and execute steps. |
| **compactor** | a higher-trust environment; purges history and attests what remains. Fewer privileges than the manager. |
| **manager** | root of trust. Issues keys, rarely online. |
| **budget** | tight. Low-spec VPS is the operating assumption, not a degraded mode. |

## 2. The workload, stated correctly

A job is **a register overwritten at each checkpoint**. Between checkpoints the steps are idempotent;
at a checkpoint the system must be certain, everywhere, before the job continues.

Three consequences, each of which was got wrong at least once:

- **Near-total death.** Only the latest checkpoint of each job is live. ~90% of the log is dead the
  moment a job advances — this is not key-value churn, it is a tiny live frontier trailing an enormous
  dead history *(experiments F45)*.
- **Work portability requires one global log.** A worker must resume *any* job without knowing in
  advance which. Per-job logs turn that into a discovery problem across 11 nodes *(F44, retracting
  F40)*.
- **Latency is generous, geography is not.** 30 s finality is fine, 1–2 minutes acceptable — the **U**
  in DUDE. But inter-continental RTT is ~250 ms, so a wave costs what it costs *(F48, F49)*.

## 3. The crux of cruxes

> **You cannot prove what you have forgotten.**
>
> Every hard problem here is one instance of that, and every solution is the same move: **keep an
> attestation in place of the history**. Which turns each one into a question about *who signed it* —
> never a question about mechanism.

The substitutions, and what each is really asking:

| you forget | you keep instead | the real question |
|---|---|---|
| superseded entries | a quorum-attested checkpoint | who vouches the fold was done honestly |
| the log before a compaction | the compactor's signature | who vouches this is **current** |
| an old key epoch | nothing — it is *supposed* to be gone | what still needs it |
| historical authority | the grant, retained by backlink | which items still depend on it |

This is why **cryptography kept not helping**. A SNARK proves a computation was performed correctly; it
cannot prove the result is the latest one, because *an old proof is a valid proof* *(F29)*. Freshness is
not a computational property. No rung of the escalation ladder buys it — a **trust tier** does, for
free *(F33)*.

### 3.1 The lemma

Six problems that looked independent, each with its own literature and its own proposed mechanism:

| | asks |
|---|---|
| stale checkpoint to a cold syncer *(F8/F9)* | is this the latest attestation? |
| node revocation *(21)* | is this roster still current? |
| compactor revocation *(21)* | is this delegation still current? |
| key accumulation on old rosters *(21)* | was this quorum current when it signed? |
| compaction unverifiable later *(F1.5)* | did anyone check this while it was checkable? |
| a worker resuming a job *(15)* | is this checkpoint the job's latest? |

**None of them asks whether a signature is valid.** They are one question.

> ### LEMMA
> **Authenticity is self-verifying. Currency is not.**
>
> A signature proves *who spoke*. A hash proves *what was said*. A SNARK proves *it was computed
> correctly*. **Nothing proves that nobody has spoken since** — there is no such object, so no
> cryptography can produce one.

So *"is this current?"* is unaskable. The only answerable form is **"is this too old?"**, which needs a
clock and a party whose clock you trust. Storage nodes are untrusted and cannot answer; the compactor
is in a better environment and can *(F33)*; the client already needs a rough clock for `W_admit`; the
manager is trusted but rarely online, so it delegates *(21)*.

### 3.2 The corollary: it is all one parameter

Every window in the design turns out to be the same quantity seen from a different side:

| window | means |
|---|---|
| freshness | how stale may a checkpoint be |
| roster certificate lifetime | how stale may the node list be |
| revocation latency | how long until a bad node stops counting |
| manager availability | how often must the root re-bless |
| compaction horizon | how far back can anyone still check |
| forward-secrecy lag *(F62)* | how long until an old key is gone |

**These are not six knobs. They are one knob observed from six directions**, and they must be set
consistently or the weakest dominates.

> **MAX STALENESS (tau) is the system's single security parameter.**
>
> `tau = 3600s` means: the manager re-blesses hourly, revocation lands within an hour, a cold client
> trusts nothing older than an hour, and an adversary's stolen keys are worthless after an hour.
>
> Set it once. Everything else is derived from it or dominated by it.

### 3.3 The priest — the role the lemma demands

If currency cannot be proven, someone with a trusted clock must **vouch, freshly, for who is in the
quorum**. That is a distinct duty and it deserves a distinct role **[H]**: the **priest** renews the
nodes' lease on the manager's behalf.

| | needs | if compromised |
|---|---|---|
| **compactor** | the **data**, to purge and attest state | can attest a false **state** |
| **priest** | the **roster** and a clock. **No data access at all** | can bless a wrong **set of nodes** |

Different inputs, different blast radius. Fusing them means one compromise buys both a false roster and
a false state, so the separation is worth a role.

**The priest is tiny** — it holds the roster and an expiry, signs ~500 bytes, parses almost nothing. It
fits a far more constrained enclave than the compactor needs, and is cheap enough to replicate n-of-m.

**And it fails the right way:**

| event | outcome |
|---|---|
| priest offline past expiry | clients trust nothing — **fails closed**, read-only |
| priest compromised | wrong roster, bounded by its delegation (tau) |
| manager offline | the priest keeps blessing until *its* delegation lapses — a longer runway |

It converts *silently trusting stale data* into *visibly refusing to serve*.

### 3.4 What the priest actually buys: consensus becomes opaque

Without it, an ephemeral client must verify the log from genesis, every roster change, every settlement
certificate, and the consensus rules themselves. With it:

```
manager key  -> priest delegation        (1 signature)
priest       -> current roster + expiry  (1 signature)
roster       -> quorum threshold on a checkpoint (count signatures)
checkpoint   -> key + path proof         (768 B, F15)
```

**Four checks, none of which mentions how consensus works.** The client verifies **membership** and
**threshold**, never the protocol.

> **Consensus becomes swappable.** Leaderless, QuePaxa, Raft, opaque MPC — a client cannot tell and does
> not care. Which is what makes the leader question (§5.5) an internal engineering decision rather than
> a client-visible commitment.

And it answers *"can we black-box the consensus quorum?"* — **yes, but only because something outside
the quorum vouches, freshly, for who is in it.** Without the priest the roster is asserted by the very
set being asserted, which is circular, and an ephemeral client has no way in.

### 3.5 Recurrent PCD at the priest — the one site where a proof earns its keep

F29/F30 rejected SNARKs, but they rejected them **over the data log**, where the statement is huge
(*"this state is the fold of 5 GB of ops"*) and the recurrence is per-slice. The priest is a different
site entirely: a **tiny** statement (*"this roster descends from genesis by manager-authorised steps"*)
proved **once per lease**, i.e. `1/tau`.

**What it removes: fabrication.**

| priest is compromised, and it holds… | it can |
|---|---|
| a signing key only | bless **any** set of node keys — fabricate a roster from nothing |
| a signing key **and must produce a PCD proof** | only **replay** a roster the manager genuinely authorised |

Combined with expiry, a compromised priest can **replay but never invent**. That is a categorical
reduction in blast radius, not a quantitative one.

**What it buys, beyond that:**

| | before | after |
|---|---|---|
| delegation chain length | grows with every priest rotation | **O(1)** — folded |
| roster provenance | unverifiable by a client | proven from genesis |
| priest rotation | client must learn the new key | inherits the proof chain |

**What it does NOT fix.** A proof that *R descends from genesis* says nothing about whether R is
**current** — an old proof is a valid proof. **PCD replaces the chain of signatures, not the clock.**
The lemma is unmoved, and `tau` still does that work.

**Why the cost objection does not apply here:** the prover is one small role, the circuit is small, and
the recurrence is `1/tau`. Proving is seconds amortised over an hour; verification is ~2 ms, which F30
called 250× worse than 8 µs and which is noise against a 30 s budget; and the ~200-byte proof is
**smaller than the signature chain it replaces**. Nodes and clients never prove anything.

### 3.6 The angel of monotonicity — and why this is accountability, not deus ex machina

The lemma says currency is unprovable. It does **not** say *monotonicity* is:

| question | answerable? | needs |
|---|---|---|
| is this the **latest**? | **no** — the lemma | no such object exists |
| is this **too old**? | yes | a trusted clock → **the priest** |
| is this **older than what I already saw**? | yes | durable monotone state → **the angel** |

Monotonicity is strictly weaker than currency, and unlike currency it is achievable.

**The two bound different axes and neither implies the other:**

| defence | bounds |
|---|---|
| expiry alone | staleness ≤ `tau` — but *within* `tau` an adversary may pick any point |
| monotone alone | never below N — but N may have been reached long ago; no time bound |
| **both** | within `tau` **and** not below N — in practice, a single point |

**And the angel need not be trusted, only accountable.** A regression is not merely wrong; it is a
signed contradiction anyone can keep forever:

```
angel signs height  30: ok
angel signs height  25: EQUIVOCATION -- provable, permanent, attributable
```

So the angel needs **durable state, not a TEE**. If it rolls back, it convicts itself. That is
`references/peerreview-sosp07.pdf`'s thesis — accountability instead of prevention — and it is why this
is buildable on a VPS while an unrollbackable monotonic counter is not.

> **[H]: this is not deus ex machina, it is accountability forwardly.** An outside power is not
> resolving the problem by fiat. Each attestation **commits the attester**; going backwards is not
> prevented, it is made permanently provable against them. The guarantee is not *"the angel cannot
> lie"* — it is *"a lie is evidence, forever"*.

### 3.7 The trio

| role | answers | failure mode |
|---|---|---|
| **manager** — ordains | who may be in the set *at all*? | offline → runway, not outage |
| **priest** — blesses | who **is** in the set, right now? | offline → fails closed (read-only) |
| **angel** — attests | has anything gone **backwards**? | lies → convicts itself, permanently |

Three roles, three different questions, three different failure modes. **None of them is the consensus
quorum, and none of them touches the data** — which is what keeps consensus opaque (§3.4) and the data
path free of trusted components.

## 4. The second-order crux: correctness and secrecy want opposite things

The same artifact — an epoch key — is pulled in two directions:

- **correctness** says *keep it*: a live value encrypted under epoch E cannot be read without E's key,
  so the refcount pins it *(F22)*.
- **secrecy** says *destroy it*: while E's key exists, every historical ciphertext under E stays
  readable, so a single straggling value defeats forward secrecy entirely *(F60)*.

Only one thing reconciles them: **move the stragglers forward.** Re-encrypt live values under the
current epoch until the old epoch's refcount reaches zero, and the key can die.

That is the conveyor — and it means the conveyor's product is **epoch drainage**, not defragmentation
*(F61, correcting F25)*. Its cost buys a security property.

**And erasure is not available as an alternative.** "Treat the log as a ring buffer" is a *space* model:
on SSDs, CoW filesystems and rented block storage you cannot assert the old bytes are gone *(F59)*. On
11 VPS you do not own the layer that would. **Key death is the only erasure you control**, so forward
secrecy is bounded by conveyor rate — and rotating keys faster without conveying faster buys nothing
*(F62)*.

## 5. What this makes the design

Not conclusions, but the shape the framing forces:

1. **One global log**, because work portability demands it — physically divided into **time segments**,
   collected wholesale. Segments are storage generations, *not* stores; conflating them breaks ACLs and
   predicates *(F46, correcting F36/F38)*.
2. **A compactor tier** that attests *when*, while the node quorum ratifies *what*. Neither substitutes
   for the other, and correctness is checkable at the moment it is claimed — so a lying compactor is
   caught immediately and only becomes unverifiable later *(F34)*.
3. **A conveyor** that migrates live values forward, draining old epochs so their keys can die.
4. **One garbage collector**: mark from live data, sweep the rest. Data supersession, wrap retention and
   management retention all fall out as consequences rather than rules *(F27)*.
5. **A rotating leader**, most likely QuePaxa-shaped. The leaderless purity was already gone — the
   compactor *is* a leader — and a leader dissolves SPEC 2.29 outright, makes recovery ordinary, and
   costs 2.5% of a 30 s budget. Rotation converts the jurisdictional chokepoint into a 1/11 tax, and
   QuePaxa answers the one objection that survives: timeout tuning under high RTT variance *(F54–F58)*.

## 6. What is permanently out of reach

State these as guarantees the system does **not** offer, rather than discovering them later:

- **A cold party with one link cannot establish freshness by itself.** It needs `f+1` responders, prior
  knowledge, or the compactor's timestamp. This contradicts the founding "single link is enough"
  intent, which holds for *authenticity* and for a *returning* client only *(F8–F11, F33)*.
- **Historical guard evaluation.** Authority is recoverable via backlinks; the *state* a predicate
  referenced is not. Replay must not re-adjudicate — SPEC 8.13 is forced, on the narrower ground that
  state is gone, not authority *(F20)*.
- **Sub-linear detection of a lying node.** ~S/2 fetched before a lie is caught, for any chunking.
  Chunking improves *recovery*, not detection *(F12)*.
- **Erasure of ciphertext on rented infrastructure** *(F59)*.

## 7. How to hold this

The framing was wrong in six documented ways, each caught by a probe rather than by review: chunking
"early exit", per-workflow logs, MMR peaks as a sync reference, subtree pruning with a stable root,
`(index, op_hash)` in drop sets, and the conveyor as mere defragmentation.

The pattern in every case was the same — **a plausible mechanism argued into place without a model.**
So: `experiments/` is the authority, `experiments/README.md` records what was retracted and why, and a
claim without an `[M]` beside it is a claim nobody has tested.
