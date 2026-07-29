# DudeFS Threat Model — the adjudicating document

> **Status: canonical.** This is the document every other normative claim is checked against.
> Where DESIGN/PROTOCOL/RESILIENCE disagree with this, **this wins and they get corrected** —
> not the other way round. Where the *code* disagrees with this, the code is wrong.
>
> **Why it exists.** The rest of the corpus was fleshed out through a question-and-response
> framework to reach something implementable, and it doubles as long-term reference across
> sessions where model memory is unreliable. That process is good at detail and bad at holding
> the centre: an expensive rule that goes unimplemented tends to get replaced by a documented
> *fallback*, which then reads as the design (DESIGN §12's liveness-set list; PROTOCOL §2.2's
> authz clause). A short, stable statement of who is trusted and what is fatal is the fixed
> point that makes those detectable.
>
> **Provenance is marked throughout.** `[H]` = stated directly by Harry. `[D]` = drawn from the
> design corpus and consistent with `[H]`. `[I]` = inferred — **the most likely place this
> document is wrong, and the first thing to check.**

---

## 1. Trust tiers

| Tier | Trust | Why |
|---|---|---|
| **Root / manager** | Anchor. Fully trusted; compromise is game over. | `[D]` Genesis TOFU is the anchor; threshold root is the recorded hardening, succession does not mitigate compromise. |
| **Client** | Trusted tier. Holds keys, folds, does the legwork. | `[D]` Authorized by a manager cert. |
| **Compactor** | A key-holding client with a delegated capability. Can wrongfully *select*, never *write*. | `[D]` Blast radius is auditable GC — detect, eject, recover. |
| **Storage node** | **Semi-trusted. The primary adversary position.** | `[H]` Cheap rented VPSs, **no TEE, no attestation**. Zero-knowledge **because** untrusted, not incidentally. **Persistently online ⇒ the longest exposure surface** ⇒ the first thing an attacker gets. |
| **Worker** | Untrusted, keyless, above the API. | `[D]` No crypto, no quorum awareness. |

**The asymmetry that drives everything:** the tier with the *most* exposure and the *least*
hardening is the tier that stores and gossips the data. `[H]`

## 2. The adversary — "the Evil Octopus"

Harry's term `[H]`, applied to two things in practice: **many simultaneous positions** (several
compromised nodes, since they are the cheapest and most-exposed tier), and **malleability** —
anywhere a value is attacker-influenced but unverified, so it can be bent without forging
anything.

Assume the adversary:

- controls one or more storage nodes, including their signing keys `[H]`
- is a legitimate roster member, so it passes the peer gate `[H]`
- can gossip to every honest node, and be gossiped to `[H]`
- knows the protocol, and can enumerate anything public (ballots, slot priorities) `[D]`
- **cannot** forge a client or root signature, break the AEAD, or read plaintext `[D]`

Not assumed: global network control, breaking crypto primitives, root compromise (that is
game-over by construction, not a case to defend).

## 3. Fatal by design

Bright lines. Any of these occurring is a **design failure**, not a degradation to be tolerated
or a POC concession to be deferred. All `[H]`, stated in this conversation:

1. **A node gossips invalid data that is subsequently re-gossiped as gospel by an honest node.**
   Unvalidated intake is an *amplification* vector: one adversary's garbage becomes N nodes'
   stored state, at zero cost to the attacker.
2. **A node signs a receipt over material it lacks the information to authenticate**, per the
   manager's authorization for that node to participate. This launders the adversary's bytes
   through an honest node's identity.
3. **Forgetting that a client or node was authorized while their data is still live**, and
   then accepting their operations without authentication.
4. **Node-to-node gossip carrying anything other than operations validated from real,
   authenticated clients.** If that is not true, there is a *huge authentication failure*.

**Corollary `[I]`:** a Byzantine node breaking a safety property *without leaving portable
evidence* also crosses this line — the recovery story is detect → eject → recover, which
requires detection. Marked `[I]` because it is derived from the resilience posture rather than
stated as a bright line; **confirm or strike.**

## 4. What must therefore be true at every boundary

Derived from §3, not independently decided:

- **Validate before storing.** Signature and structure **unconditionally**, everywhere, with no
  carve-out — both are self-contained and need no external context. `[H]` (§3.1, §3.4)
- **Authorization is positional and always computable.** An op is authorized by the control
  state at *its own* position, never the current view. This is possible because the control ops
  needed to authenticate any retained op are themselves always retained. `[H]`
- **Carve-outs are substitutions, never omissions.** Below the cut, contiguity is exempt
  (predecessors are legitimately GC'd) and per-op QCs are gone — replaced by the checkpoint's
  signed `retained` commitment. Verification changes *basis*; it never weakens. `[H]`
- **A node's signature is only ever over what it verified.** `[H]` (§3.2)
- **Misbehavior is attributable.** A protocol violation should yield portable evidence. `[I]`

## 5. Structural commitments this rests on

- **The store is a DAG, and that is the reason the rest works.** `[H]` Every op has a linear
  history back to whatever authorized it. The **frontier** is the DAG's per-author head set;
  the **cut** is a frontier that has been settled; a **checkpoint** is the signed assertion of
  that settled state — *"if your committed finality set is not X, you have diverged, something
  is deeply wrong"*; **GC is reachability from the cut**. See NOTES (recovered 2026-07-26).
- **Checkpoints, the frontier cadence and δ are synchronization points** — settled, linearized
  ordering. Arbitrary arrival order is a transport artifact to be *resolved against* these
  points, never a licence to skip verification. `[H]`
- **Self-authenticating artifacts; the transport adds no trust.** `[D]`
- **Zero-knowledge is structural** — nodes hold no keyring and no data handler, so they
  *cannot* read values regardless of compromise. `[D]`

## 6. Resilience posture

- Ultra-durability over latency; a minority partition **blocks**, and that is the point. `[D]`
- Audit over throughput. `[D]`
- Recovery is **detect → eject → recover**, anchored on portable evidence and a root fiat fence
  for catastrophic loss. `[D]`
- **The use case requires this resilience.** It is not a research posture to be traded away for
  convenience. `[H]`

---

## How to use this document

1. **A doc/code disagreement is a finding, not an automatic verdict.** The ruling says which
   side moves. "Docs win" is right for code drift and wrong for doc error — PROTOCOL §2.2's
   *"authz against the current control-plane view"* contradicts §7.5 in the same document and
   would break recovery if implemented literally.
2. **A normative claim that contradicts §3 is a bug in the document.** Correct the document.
3. **"POC" / "for now" in code must cite the NOTES item holding the real rule.** No citation
   means the rule was never written down — write it before the shortcut lands. This is the
   mechanism by which a fallback becomes the apparent design.
4. **Every `[I]` above is an invitation.** They are where this document is most likely to have
   misconstrued the object.
