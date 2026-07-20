# Implementation notes — deviations & decisions to reconcile with the design

> Per IMPLEMENTATION.md: "If code and documents disagree, the documents win —
> or the discrepancy is raised as a doc change, never silently coded around."
> This file is that raise-list for M0–M1. Each item is either a proposed
> DESIGN/PROTOCOL edit or a decision that resolves an explicitly-open question.

## Wire / envelope (DESIGN §5)

1. **`author` carries the public key, not a cert-fingerprint.** DESIGN §5 lists
   `author: cert-fingerprint`. The fold must verify the author signature, which
   needs the *public key*; resolving fingerprint→cert→pubkey adds a lookup with
   no security gain at this scale. The POC puts the Ed25519 public key in
   `author` directly; the fingerprint is `h(author)` when needed, and `authz`
   still references the manager cert.
   → **Proposed DESIGN §5 edit:** state that `author` is the author public key
   (fingerprint derivable), or that the envelope carries the pubkey alongside
   the fingerprint.

2. **`pver` is in the envelope from day one.** DESIGN §5's schema omits it; §16
   introduces it for lane-2 fences. Adding it now (plaintext, tiny) avoids a
   later format break; an op with `pver` above the active version folds
   `invalid` (deterministic for everyone).
   → **Proposed DESIGN §5 edit:** add `pver: uint` to the envelope schema.

3. **AEAD nonce derivation is specified as the AAD hash.** DESIGN §5 fixes
   `AAD = h(envelope-minus-payload)` but leaves the nonce unspecified. The POC
   uses `nonce = AAD = h(envelope-minus-payload-minus-sig)` — deterministic and
   unique per op (author/seq/hlc make the envelope unique), which a real cipher
   suite (`b2s1`/`xcp1`) needs.
   → **Proposed DESIGN §5 edit:** specify the nonce source.

4. **`slot_tag = null` is encoded as an absent dict key.** Canonical bencode has
   no null; "null ⇔ key absent" is total and injective. A blind write omits
   `slot_tag`.

## Fold semantics (DESIGN §6)

5. **Attribution uses the global key universe** (all keys named by any
   decryptable op in the committed set), matching §6's "first in fold order
   advances the lineage, the rest go stale" — including when a corrupt/opaque
   op coincidentally carries a live key's current tag. The only residue is the
   §6 diagnostic-refinement clause: an adversarially-crafted opaque op whose tag
   equals the *current* tag of a key first revealed by a *higher-hlc* op can
   refine a `stale` sub-label — but **mutation-state and applied-bits never
   move** (opaque ops never apply mutations; they only ever bump `attempt`).
   Faithful to §6; noted because it is the one place attribution is not a strict
   function of the below-position prefix.

6. **`version_eq` guard also matches a tombstone's anchor version.** Supports
   the DESIGN §12 note that a CAS against a tombstone's version folds `stale`
   after a barrier (the guard can still be *expressed*; the lineage moves).

## Open questions resolved for the POC

7. **Guard vocabulary v1** (DESIGN §17): `absent · present · value_eq(v) ·
   version_eq(op_hash)`. More predicates (`counter > N`, multi-key forms) are a
   lane-2 handler add.

8. **Ballot representation** (DESIGN §8): `(round:int, client_fp:bytes)`, ordered
   lexicographically. Blind writes use the sentinel `BLIND = (0, b"")`.
   *Amended at rev 5 (item 21):* slotted ballots are `(round ≥ 1, client_fp)`;
   the `(0, ·)` family is reserved for the blind sentinel and a slot's
   unpromised initial state — the ballot-0 fast path no longer exists.
   *Amended again (item 24d):* the low-order component is `priority =
   h(slot_tag ‖ client_fp)`, not the raw `client_fp` — a per-slot tiebreak that
   prevents fixed-pair starvation. Order is still lexicographic `(round,
   priority)`; the `Ballot` field is renamed `client_fp → priority`.

9. **Control-op authorization** is simplified to "authored by the root manager
   key" for M1. Delegated capabilities (`compact` / `manage-roster` /
   `issue-revoke` on non-root certs, DESIGN §15) are deferred to M5.

10. **`state_root`** (DESIGN §12) is a binary BLAKE2 Merkle root over sorted
    live `(key, value, version, attempt)`. Concrete shape; open to change.

## Toolchain & typing

11. **Python floor is 3.12** (was "≥ 3.11" in IMPLEMENTATION.md §0). The code now
    uses 3.12 features — PEP 695 `type` aliases (`codec.Bencodable`,
    `artifacts.Heads`, `fold.Keyring/Snapshot/Genesis`, the acceptor result
    unions) and `typing.Self`. → **Applied:** IMPLEMENTATION.md §0 now states
    the 3.12 floor (2026-07-20).

12. **Type-checking is on via Pylance/pyright** (`pyrightconfig.json` +
    `.vscode/settings.json`, `typeCheckingMode: "standard"`, `pythonVersion
    "3.12"`). No CLI checker is installed — diagnostics come from the IDE. The
    dynamic bencode boundary (`codec.decode`) is typed `Any` on purpose (mirrors
    `json.loads`); L6 handlers depend on L5 only through a `StateReader`
    Protocol to avoid an import cycle. A native CLI checker (Astral **ty**, Rust)
    is a possible later addition — a consented install, since pyright is Node.

## M2.5 review resolutions (fold-semantics hardening, decided 2026-07-20)

A post-M2 review found the fold implementing readings of DESIGN that broke A2
and A4 as formally stated. Resolutions decided with the design owner; DESIGN
§6/§12 and RESILIENCE §3.4 have been edited accordingly (documents win).

13. *(Snapshot-era wording superseded at rev 6 — bootstrap now seeds from the retained set, items 25/29; the barrier semantics here remain canonical.)*
    **Checkpoint barrier is cut-relative, derive-and-verify.** The barrier sits
    immediately above the *cut* (well-defined: the cut is final, so covered ops
    sort below everything still committable), NOT at the checkpoint op's own
    hlc position as M1 had it. Full-history clients derive the barrier state
    and verify `state_root` (audit alarm on mismatch); bootstrap clients seed
    from the snapshot. A4 equality is therefore *conditional on an honest
    checkpoint* — accepted: the manager is the root of trust, and a mismatch
    is a portable proof of a corrupt checkpoint. (Alternative considered and
    declined: snapshot-wins canonical state, which would have made A4
    unconditional but let a tampering manager rewrite silently-canonically.)
    Corollary the A4 proof forces: **the key universe resets at the barrier** —
    a key neither live at the cut nor named above it is unattributable above
    the barrier, else snapshot and history clients attribute opaque ops
    differently. `(⊥, n)` attempt-only lineages also reset to `(⊥, 0)`.

14. **Lineage advance is universal (A2).** DESIGN §6 step 1 ("structurally
    invalid → no state change") contradicted the lineage-advance invariant
    ("rejected, invalid, or applied without mutating k"). The invariant wins,
    with no validity case-split: *every* committed op whose tag equals a
    current expected tag consumes that slot, however invalid — bad authz
    (the reachable revocation-race wedge), pver, hlc violations, even bad-sig
    garbage. Cost documented in RESILIENCE §3.4 (bounded attempt-burn by a
    recently-revoked key-holder until rotation).

15. **The lane-2 fence is fail-closed.** (a) `pver` gating applies to *all* op
    classes, not just data (DESIGN §16 says "an op"). (b) `PVER_ACTIVATE` sets
    a *pending* version; it activates at the next checkpoint barrier (§16
    "effective at the next checkpoint barrier"). (c) The fold carries
    `SUPPORTED_PVER`; if activation raises the active version above it, the
    fold raises the typed `FoldHalted` carrying the sealed barrier result —
    fail-stop read-only, never misfold. (d) Unknown guard/mutation vocabulary
    at a *supported* pver is a malformed Txn → `Opaque` → `rejected` with the
    slot consumed — never a silent partial apply.

16. **SUBMIT enforces chain contiguity** (PROTOCOL §1.1 `unknown_prev`; §2.1
    invariant). Ballot ACCEPT stores the envelope contiguity-free (re-proposal
    requires it), so `heads()` reports only each author's **contiguous
    prefix** — a signed frontier bundle never claims an orphan head.
    *Amended at rev 5 (item 21):* slotted ops no longer flow through SUBMIT at
    all, so the SUBMIT gates (contiguity + deps, item 20) bind **blind writes**;
    slotted envelopes arrive via ACCEPT (exempt — recovery liveness) and via
    gossip intake, where §2.1 gates them (M4). `heads()` semantics unchanged.

17. **Fold totality over adversarial soups.** Sig-invalid ops are excluded from
    the per-author HLC-monotonicity baseline and from `prev`-linkage targets
    (a forged unsigned op must not invalidate an honest author's chain), and
    every decode path in the fold is total: malformed control bodies, missing
    envelope fields, and garbage payloads fold `invalid`/`Opaque` — never a
    raised `KeyError`. Control-op bodies are schema-validated per kind
    (including DESIGN §13 roster-parity: even voting-member counts → invalid);
    unknown control kinds fold `invalid` (lane-3 gates new kinds).

18. **QC bitmap is strict:** exactly `⌈n/8⌉` bytes, no set bits above `n` —
    verification returns false (never crashes) otherwise; one signer set has
    one encoding.

19. **`state_root` gains leaf/node domain separation** (`h(0x00‖leaf)`,
    `h(0x01‖l‖r)`, odd node promoted) — closes the duplicate-leaf ambiguity
    class before the shape freezes (amends item 10).

20. **`deps` are accept-time, never fold-validity — RESOLVED 2026-07-20.**
    The old §6 "`deps` resolve" validity condition was unsound: an honest op's
    deps may reference another author's in-flight op that later dies at the
    skew floor (observed ≠ committed), retroactively invalidating the honest
    op. Ruling (design owner): deps are load-bearing at the **accept layer** —
    a node resolves an op's deps (against stored ops, committed or not;
    PULL-then-accept, defer as `unknown_dep`) before receipting a `SUBMIT`,
    so forks mint equivocation evidence at first cross-view contact — and the
    **fold ignores deps entirely** (HLC alone orders; HLC Theorem 1 makes the
    dep graph redundant for ordering). Ballot `ACCEPT` is exempt (recovery
    must complete; same asymmetry as contiguity, item 16). A dep is a
    PeerReview-style commitment-to-have-observed: evidence against its issuer,
    never a validity condition on the referencing op. M2 implements the
    known-dep gate on SUBMIT (reject `unknown_dep`); M4 upgrades reject to
    PULL-then-accept. Grounding quotes/sections: RELATED §4, §5, §9.

## M3 review findings (quorum client + sim, 2026-07-20)

21. **The fast path can commit two different ops for one slot with fully honest
    acceptors — DESIGN §8's single-decree claim overclaims. RAISED, not coded
    around.** The sim harness (seed=11, n=5; also seed=5, n=3) exhibits two
    valid QCs for one `slot_tag`: op **B** decides at ballot `(0, fp_B)` on a
    quorum, then a recoverer for op **A** (with `fp_A > fp_B`) commits **A** at
    a recovery ballot. No acceptor equivocates — every node's per-slot history
    is a legal Paxos trace.
    - **Root cause — the fast path skips PREPARE.** A ballot-0 accept carries no
      "nothing lower was chosen" guarantee (that is what phase-1 buys in classic
      Paxos). Two writers can therefore have *un-prepared* accepts at
      ballot-0-family ballots that are totally ordered but neither dominated the
      other via a promise. The recovery rule "re-propose the highest **accepted
      ballot**" (§8, PROTOCOL §1.3 step 5) then re-proposes A's un-prepared
      `(0, fp_A)` over B's *chosen* `(0, fp_B)` because `(0,fp_A) > (0,fp_B)`.
      This is the textbook **Fast Paxos collision**: a fast round under a bare
      *majority* fast-quorum is not safely recoverable (Fast Paxos needs a
      `⌈3n/4⌉`-style fast quorum, or a leader owning ballot 0).
    - **Item 8 (`ballot0 = (0, client_fp)`) makes it deterministic-wrong**, but
      it is not the whole story: a uniform sentinel `(0, ⊥)` only downgrades the
      hazard to a *tie* at ballot 0 between two different chosen-vs-unchosen
      values, which a majority recovery quorum still cannot disambiguate. The
      hole is the majority fast-quorum, not the fp tiebreak.
    - **Scope of the discrepancy.** DESIGN §8 states "Quorum intersection + the
      promise rule give the single-decree property: no other op can ever be
      decided for `t`", and its *Safety layering* para attributes any exclusion
      violation to "an equivocating acceptor". Both are too strong: exclusion
      breaks under **honest** contention, no equivocation required. FORMAL's B1
      is stated more carefully — "at most one op per `slot_tag` obtains a
      **same-ballot** quorum" — and *that* invariant holds (verified continuously
      by the sim; the same-ballot check never fires). The gap is purely the §8
      prose's stronger cross-ballot claim.
    - **Containment is intact (state-safety does NOT depend on §8 exclusion).**
      Both ops land in the committed set; the fold's universal lineage-advance
      (item 14) + LWW collapse it deterministically to exactly **one `applied`**
      winner, the rest `stale`, byte-identically for every client and every
      input order (verified: the double-commit folds to one applied winner,
      order-independent). CAS *success* is already defined at the fold+finality
      layer (§9: QC ∧ frontier past `hlc` ∧ verdict `applied`), never at the QC
      alone — so a redundant second QC is a wasted round, not a divergence.
    - **Proposed DESIGN §8 edits (owner's call):** (a) soften the single-decree
      prose to the same-ballot B1 wording and state plainly that honest fast-path
      contention may mint a second, losing QC, contained by fold+finality; and/or
      (b) if true slot-level single-decree is wanted, adopt a Fast-Paxos fast
      quorum (`⌈3n/4⌉`) for ballot 0 with the majority recovery quorum, or route
      ballot 0 through a per-slot leader.
    - **RESOLVED 2026-07-20 — option (c): the fast path is DROPPED (rev 5).**
      Owner's ruling: DudeFS is *ultra-durable*, not low-latency — two round
      trips are an acceptable price at config-store cadence (seconds to hours),
      and classic two-phase per-slot Paxos makes §8's single-decree claim, the
      RESILIENCE §3.1 equivocation attribution, and a *strengthened* B1
      (cross-ballot: at most one op ever decided per slot) unconditionally
      true, with the smallest TLA+ surface. Third options considered and
      declined: Fast-Paxos `N−⌊N/4⌋` fast quorums (kills the fast path exactly
      when a node is slow — 3-of-3 at n=3 — for a guarantee nothing downstream
      consumes) and an O4-style plurality selection heuristic (shrinks but
      cannot close the window at n=3; spec complexity for an efficiency gain).
      DESIGN §8, PROTOCOL §1.1/§1.3/§1.4/§4, FORMAL B1, and items 8/16 are
      edited; slotted ballots are `(round ≥ 1, client_fp)`; slotted `SUBMIT` is
      `REJECTED{needs_ballot}`. **Code change handed to the implementing
      agent:** acceptor rejects slotted SUBMIT; `quorum.Commit` starts at
      PREPARE round 1 (no SUBMIT phase); sim invariant strengthened to full
      cross-ballot B1; the two collision seeds become regression tests
      asserting exactly one decided op per slot.

## M4 findings (gossip + integration, 2026-07-20)

22. **Nodes must persist the receipts they issue (RESOLVED, code landed).** M2's
    acceptor issued-and-returned receipts to the requesting client but never
    stored them — fine for the direct reply path, but PROTOCOL §2.2 / §1.4 need
    "any node accumulating a quorum of receipts assembles the QC", so gossip must
    be able to spread a node's own receipts. `on_submit`/`on_accept` now
    `put_receipt` before returning (`_issue_receipt`); storage is derived from
    already-fsynced slot state, so it never outlives its justification
    (RESILIENCE §0). Enables single-push (§1.4) and gossip QC-assembly.

23. **Dueling-proposer liveness stall — RESOLVED 2026-07-20 (code landed).** The
    contention sim (seed 5, n=3, 25% loss) wedged proposer A at PREPARE round 2
    forever — it never terminated. **Safety was always intact** (exactly one op
    decided, cross-ballot B1 held); the gap was purely *liveness*. Exposed (not
    caused) by tuning RTT 2× → 2.222× one-way, which shifted the deterministic
    schedule onto a latent bug any seed/tunable could hit.
    - **Cause 1 — no randomized backoff.** Two proposers stayed phase-locked,
      each invalidating the other's ballot. DESIGN §8 anticipated this
      ("randomized backoff suffices — noted"). **Fix:** `Commit._backoff_ms`
      delays re-PREPARE by a jitter keyed on `(client_fp, round)`, so duelers
      desynchronize and one gets a clean run. Kernel stays pure — the jitter is a
      function of identity+round, no RNG. Round 1 has zero backoff (happy path
      stays prompt).
    - **Cause 2 — `_maybe_reprepare` optimistic under loss.** It escalated only on
      *heard* Nacks (`n − len(nacked) ≥ quorum → wait`), so lost Nacks stalled the
      round bump. **Fix:** a per-round timeout (`round_timeout_ms`, 4·RTT) fires a
      `Wake`; if the round hasn't decided, `_escalate` bumps the round regardless
      of heard replies (or gives up at `max_rounds`). Covers PREPARE, ACCEPT, and
      FETCH. A `(ballot, tag)` guard on promises stops a delayed reply from a
      superseded round filling the current quorum.
    - **Verified:** 80/80 contention scenarios (seeds 0–39 × n∈{3,5}, 25% loss)
      both terminate with exactly one op decided. Sim regression test
      `test_B1_contention_always_terminates_single_decree` sweeps them.

24. **Phase-sync audit (2026-07-20) — one structural lock fixed, rest catalogued.**
    Following the item 23 dueling fix, swept every timing/ordering point for
    synchronized-behavior hazards (independent actors acting in lock-step).
    - **FIXED — identical fan-out order.** Both `_Fanout`s used `range(n)`, so
      *every* client contacted nodes {0,1} first and contenders always collided
      on the same preferred quorum — a structural phase-lock the backoff only
      partly hid. `QuorumConfig.fanout_order` now rotates `range(n)` by an offset
      derived from `client_fp` (pure kernel, no RNG). Measured effect over the
      80-scenario contention sweep: clean LostSlot resolutions 38→43, forced-retry
      Failed 42→37.
    - **Noted, not yet fixed** (lower value / different layer / unbuilt):
      (a) `ClientRunner` retransmit is a fixed interval — synchronized retransmit
      storms; jitter it in the M7 real driver. (b) `Finalize` polls WATERMARK on a
      fixed cadence — synchronized but read-only/cheap; jitter later if needed.
      (c) the gossip driver (unbuilt) MUST use a jittered period + uniformly random
      peer (PROTOCOL §2.2) when it lands.
    - **(d) FIXED 2026-07-20 — per-slot ballot tiebreak.** Ballot ties broke by raw
      `client_fp`, a fixed global order, so for any FIXED pair the higher-fp client
      won *every* same-round tie and could starve the other under sustained
      single-key contention (each CAS attempt is a fresh `slot_tag` but the fp
      order is constant). Ballots are now `(round, priority)` with
      `priority = slot_priority(slot_tag, client_fp) = h(slot_tag ‖ client_fp)`
      (amends item 8). WHICH proposer wins ties now varies per slot, so a fixed
      pair each win ~half — demonstrated: old scheme 2000/2000 (100%, starves) →
      new 48% (`test_per_slot_tiebreak_prevents_starvation`). Deterministic and
      identical on every node (all hold the tag + fingerprints), so single-decree
      / quorum-intersection are untouched — NOT a VRF: honest clients compute it
      the same and a Byzantine node never proposes, so nothing to grind. The
      backoff jitter salt is now per-slot too (`priority[:8]`).

## Compaction model (DESIGN §12) — DESIGN QUESTION, specify before M6

25. **RESOLVED 2026-07-20 — adopted as DESIGN §12 rev 6, amended by items
    29–31 (attempts sidecar, resurrection mask, retained commitment, QC GC,
    compactor delegation, cut-lag W, declared costs).** Original raise text
    kept below as rationale. **Compaction is LOG-COMPACTION (retain live
    winners in place), NOT snapshot
    materialization — REVISE §12. Raised 2026-07-20. This is a *design decision*,
    not an implementation note: it changes the §12 architecture and MUST be
    written into DESIGN §12 (schema + rules + argument), not left as intuition for
    M6 to fill in blindly.** §12 as written embeds `snapshot: ciphertext(
    materialized state at cut)` in the checkpoint op — a config-store-scale
    assumption that breaks at the target scale (5–10 GB, DynamoDB-shard ballpark,
    plausible over a year of a slow "glacier" store).
    - **The better model (Kafka-style log-compaction).** Keep the live *winner op*
      per key in place; GC everything below the cut that it supersedes (overwritten
      ≥ once, or deleted). No materialized blob, no re-encryption, no data push —
      nodes drop dead ops they already hold. The retained winners ARE the baseline,
      in native ciphertext-op form.
    - **Manager-driven because nodes are zero-knowledge.** A node cannot see that an
      op was overwritten (it can't decrypt), so it cannot compact itself. The
      manager folds (it holds the key), computes the dead set, and signs "GC these
      ≤ cut"; the checkpoint carries the DELTA (newly-dead hashes, ∝ churn), not the
      state. Cost is the manager's *incremental tail-fold* — compaction is cheap and
      continuous, not a heavy whole-state event.
    - **Auditability unchanged.** `state_root` still lets a client who kept history
      detect a wrongful GC of a live winner as a root mismatch (detect-and-disclose).
      A single audit root suffices for THIS model — no navigable Merkle tree /
      chunked-snapshot transfer is needed (that machinery only existed to serve a
      materialize-and-ship snapshot this model replaces; amends the exploratory
      "promote state_root to a tree" idea — DON'T).
    - **Bootstrap.** A new client fetches the retained winner ops and LWW-folds
      their *mutations* in hlc order — no guard re-evaluation (it is reading current
      state, not re-deciding CAS) — then verifies `state_root`.
    - **To specify in §12:** checkpoint schema (`retained live-set + cut +
      state_root`, delta-encoded), the GC rule (drop non-retained ≤ cut), the
      zero-knowledge manager-authority + audit argument, bootstrap semantics
      (mutations-only LWW fold), and — explicitly — the **5–10 GB target-scale
      assumption** (the current docs' cost model, e.g. "SUMMARY ≲1 KB, a rounding
      error," silently assumes a far smaller store).

## Review wave R1 — design review of items 22–25 (review side, 2026-07-20)

> **REVIEW MARKER (the line in the sand) — updated 2026-07-20, all rulings
> LANDED.** Items **1–24** reviewed at commit `59e9eda`: settled. **Owner
> rulings received 2026-07-20** (recommended options accepted in full): 27 →
> acceptor void + client guard; 29a → encrypted attempts sidecar; 29d → GC
> QCs below cut, checkpoint vouches; 29f/29g/29i/30 → delegated compactor
> cert / cut-lag window W / accept-and-declare with re-anchor recorded /
> adopt-by-fiat. **The documents have been edited to revision 6 accordingly**
> (DESIGN §1/§7/§8/§12–§17, PROTOCOL, RESILIENCE, FORMAL, MANAGER,
> IMPLEMENTATION, COMPARISON, ARCHITECTURE, README — including item 26's
> mechanical edits and item 28's §3.6 note). Items 25–31 below are retained
> as the **rationale record** for the rev-6 edits; they are all RESOLVED and
> the docs are canonical. **Implementation side (Opus): work from the rev-6
> documents + HANDOFF-R1.md — M5 next, then M6.** New discrepancies go below
> this marker as numbered items, never coded around.

26. **APPLIED 2026-07-20 (all edits landed at rev 6).**
    **Doc edits owed by committed items 22–24 (mechanical — no ruling needed).**
    The code landed but the normative text didn't: (a) DESIGN §8 still says
    ballots are `(round ≥ 1, client-id)` and PROTOCOL §1.3 step 2 says
    `(r ≥ 1, my-id)`; IMPLEMENTATION §2 says `(round, client_fingerprint)` —
    all need the item-24d `(round, priority)` amendment, `priority =
    h(slot_tag ‖ client_fp)`. (b) DESIGN §8's "randomized backoff suffices
    (noted, accepted)" and PROTOCOL §1.3 step 5's "randomized backoff" should
    state the actual mechanism (item 23): deterministic per-`(priority, round)`
    jitter + per-round timeout escalation + `max_rounds`; FORMAL B7's "backoff
    fairness" wording likewise. (c) PROTOCOL §2.2 should state explicitly that
    a node persists the receipts it issues (item 22) — RESILIENCE §0 already
    lists "receipts (own and gossiped)" in the durable inventory, so this is
    alignment, not a change.

27. **RESOLVED 2026-07-20 — ruling: acceptor-side void rule + client guard;
    docs edited (DESIGN §8/§12, PROTOCOL §1.3, FORMAL B1 scope,
    ARCHITECTURE L3); code + regression test land with M6.**
    **Spent-tag rebirth × lazy slot-GC livelock — pre-existing in rev 5,
    independent of item 25; conveyor compaction makes it frequent.** DESIGN §12's barrier resets deleted keys and `(⊥, n)`
    lineages to `(⊥, 0)`. Same key + same `keyepoch` ⇒ the post-barrier
    creation tag `PRF(key ‖ ⊥ ‖ 0)` is **byte-identical** to the pre-barrier
    one, whose slot was already decided — a reborn tag. §8's slot-state GC is
    *lazy*, so a node that hasn't yet GC'd holds `(promised, accepted_ballot,
    accepted_op)` for the old decision; a new creation CAS's PREPARE then gets
    a promise reporting the ancient accepted op, which §1.3 step 3 **MUST**
    re-propose — but its `hlc` is below the horizon floor, so it can never
    commit: livelock until every quorum node happens to GC. Also scopes FORMAL
    B1 ("at most one op ever decided per slot") to barrier intervals for
    reborn tags. Proposed fix: **acceptor-side void rule** — per-slot state
    whose `accepted_op.hlc` is below the node's checkpoint horizon is dead;
    on PREPARE, discard it and answer as a fresh slot (deterministic from
    local state). Belt-and-braces client rule: treat a promised accept with
    `hlc` below the horizon as no-accept. Edits: §8 (acceptor-state GC), §12,
    FORMAL B1 scope note; code lands with M6.

28. **APPLIED 2026-07-20 (RESILIENCE §3.6 + DESIGN §8 + PROTOCOL §1.3.5
    edited; driver-side entropy is an M7 task).**
    **Deterministic backoff is precomputable — note for M7, no ruling.** Item
    23's jitter is a public function of `(priority, round)`, so RESILIENCE
    §3.6's content-*oblivious* delay adversary can compute both duelers'
    schedules offline — TLS no longer restores liveness for the dueling case.
    Consistent with B7's partial-synchrony honesty and the QuePaxa escape
    hatch, but worth one sentence in §3.6. Cheap mitigation: the M7 real
    driver mixes true entropy into retry timing — timers are client policy,
    not protocol (PROTOCOL §4), so the kernel stays pure and the sim stays
    deterministic.

29. **RESOLVED 2026-07-20 — all rulings landed (a: sidecar · d: GC QCs ·
    f: compactor cert · g: cut-lag W · i: accept-and-declare + re-anchor
    recorded); every sub-item below is now written into the rev-6 docs.**
    **Item 25 (log-compaction) — ENDORSED, with mandatory revisions and open
    rulings.** The model is right at the 5–10 GB target and is *less*
    machinery than the snapshot blob (no re-encryption, no chunked transfer,
    delta ∝ churn). But as drafted it has two correctness holes, and several
    §12-adjacent consequences must be specified with it:
    - **(a) RULING — attempt counters don't survive compaction.** The dead ops
      (rejected/invalid/guard-only) that justified a live key's nonzero
      `attempt` are GC'd, so bootstrap clients would derive `attempt = 0`
      where full-history clients hold `n > 0` → different expected tags →
      A4 divergence. The snapshot carried per-key `(version, attempt)`
      precisely for this. Options: **(i, recommended)** checkpoint carries a
      small encrypted sidecar `attempts: ct({key: n})` for *nonzero* attempts
      on live keys only (sparse — attempts reset on every applied write;
      preserves A2/A4 exactly, no new staleness); (ii) universal attempt-reset
      `(v, n) → (v, 0)` at the barrier — simpler but mints reborn tags for
      *live* keys too, widening item 27 and adding stale-CAS races per
      checkpoint on contended keys; (iii) add a barrier counter to the PRF
      preimage — kills all rebirth structurally but staleness-kills every
      CAS in flight across a barrier. `state_root` already commits to
      `attempt`, so whichever is chosen must match its leaf definition.
    - **(b) MANDATORY — resurrection-aware tombstone retention.** A retained
      multi-key winner replays *all* its mutations at bootstrap. If op X is
      retained as winner for live key A but also set key B, and B was later
      deleted below the cut, B's tombstone is "dead" under the draft rule and
      GC'd — bootstrap resurrects B while full-history clients hold it
      deleted: A4 broken. Rule: **a tombstone-winner is GC-able only if no
      retained op mutates its key**; a so-retained tombstone masks
      resurrection only and is *not* a lineage anchor (the key still resets
      to `(⊥, 0)` per §12).
    - **(c) MANDATORY — retained-set commitment.** With sparse below-cut
      chains, per-author contiguous heads no longer describe holdings: a node
      cannot distinguish "never received (live winner)" from "dead and
      dropped", and `state_root` detects omissions only client-side, only
      after a full 5–10 GB fetch. The checkpoint carries a per-author
      `(count, digest)` over retained op-hashes (plaintext-safe — hashes are
      public metadata): nodes verify below-cut completeness locally, the §13
      possession barrier stays checkable, gossip `SUMMARY` gains the digest
      alongside tail heads, and a bootstrap client localizes omissions
      per-author. This *rescues* 25's "no navigable Merkle tree" stance — a
      flat digest list suffices; each checkpoint is self-contained (digest
      over the *full* retained set; the `dead` delta is just incremental GC
      work), so only the latest checkpoint stays pinned.
    - **(d) RULING — GC receipts/QCs below the cut.** Per-op QC retention at
      ~450 B (Ed25519 list, n=7) against millions of live keys is GBs of pure
      overhead. Since A4 is already *conditional on an honest checkpoint*
      (item 13), let the manager-signed retained-set commitment vouch for
      below-cut commitment and GC the QCs — envelopes keep author signatures,
      so provenance survives. Same trust posture, big cost win.
    - **(e) Control-plane retention set** (specify in §12): the latest
      checkpoint, cert/revocation history, **wrap-sets** (the log *is* the
      key-distribution channel — load-bearing forever), current roster +
      endpoint records; old roster epochs droppable once no surviving QC
      references them (moot if (d) adopted).
    - **(f) RULING — the conveyor must not put the root key online.**
      Continuous manager folding contradicts the offline-root posture
      (DESIGN §3, MANAGER §0). Delegate: a **compactor identity** holding a
      manager-issued cert with the `compact` capability (§15 already names
      it; delegation is already M5 per item 9) plus the group key. Blast
      radius on compromise: wrongful-GC (auditable, detect-and-disclose) +
      data confidentiality (any client has that) — never roster/cert
      authority.
    - **(g) RULING — cut-lag policy.** Under rare big-bang checkpoints the
      audit window (time to fold history before it's GC'd) was implicitly
      huge; a conveyor makes it a knob that must be set consciously: cut ≤
      finality frontier − W, with W ≥ client audit cadence. Answers the §17
      "checkpoint cadence" open question; belongs in §12.
    - **(h) Leakage declaration (§7).** The `dead` delta teaches nodes which
      ops were superseded together — supersession/lifetime structure the
      uniform snapshot-era GC never revealed, and retention itself marks
      "this ciphertext is live state". Within the metadata boundary's spirit,
      but the boundary is a *declared* one — declare it.
    - **(i) RULING — epoch-key history becomes load-bearing forever, and §16
      weakens.** Retained winners never re-encrypt: clients must hold every
      `keyepoch` back to the oldest live winner (kills §17's "do snapshots
      re-encrypt?" question — answer is now structurally *no*), a leaked old
      epoch key exposes everything still live from that epoch with no
      re-encryption path short of overwriting, and §16's "implementations may
      eventually delete old fold code" claim shrinks: the *mutation-decode*
      vocabulary of every `pver` still present in the retained set must be
      kept (guards/verdicts still sealable). Accept and declare, or specify a
      manager "re-anchor" op (re-encrypt + re-author a winner, original
      provenance noted by reference) as the escape hatch.
    - **(j) Protocol surface (M6, mechanical once ruled):** `PULL` below the
      cut serves sparse retained runs (+ paged enumeration for bootstrap)
      instead of "answers with the checkpoint"; `SUMMARY` carries the
      retained digest; client caches apply the same `dead` delta.
    - **(k) COMPARISON row.** Add: retained-winner log-compaction ↔ **Kafka
      compacted topics** (ADOPT the retention shape; CARVE axis 1 — the
      *broker* computes Kafka's winner set, our storage nodes can't, hence
      manager-computed dead-deltas); re-cite rows 11/12 (Raft §7 snapshot
      anchoring stays for the *horizon*; the snapshot-contents half is
      superseded).

30. **RESOLVED 2026-07-20 — ruling: adopt-by-fiat; all findings written into
    RESILIENCE §2.2, DESIGN §12/§13, PROTOCOL §0/§2.2, MANAGER.md.**
    **Recovery × compaction interplay — the motivating scenario (gorilla breaks
    quorum, manager reconfigures), walked through under log-compaction.
    Findings for the §12 rewrite + RESILIENCE §2.2 + DESIGN §13.**
    - **The recovery checkpoint is the same artifact as a conveyor checkpoint
      with one precondition swapped:** its cut is the *salvage frontier*,
      adopted by root fiat, not a final frontier — finality cannot advance
      without a quorum, so §12's "cut must be final" is unmeetable during
      recovery by construction. §12 must state both preconditions; the fence
      stays a distinct, non-replayable op kind (§2.2 already implies this).
    - **The retained-set commitment (29c) IS the salvage manifest:** named =
      exists; absent = lost-and-disclosed. **RULING needed — salvaged-but-
      uncommitted ops** (sub-quorum receipts at outage time): adopt-by-fiat
      into the cut (recommended — linearizability already doesn't span the
      fence, and the writes are signed and attributable) or drop-and-disclose.
      §2.2 currently only addresses committed-but-unsalvaged.
    - **29d generalizes to disaster for free:** a salvaged op whose QC was
      destroyed is unprovably-committed; under "the checkpoint vouches below
      the cut" its legitimacy flows from the fence exactly like any routine
      below-cut op — one legitimacy rule, one code path, disaster and routine.
    - **The manager never carries bulk state.** It certifies (a checkpoint op:
      cut + digests + `state_root` + sidecar — KBs); the 5–10 GB of retained
      winners flows peer-to-peer from survivors *and reachable clients* to new
      learners, verified against the digests, with `state_root` as the
      client-side semantic check. Bulk transfer is therefore correctness-free
      — any dumb resumable channel — because the manifest is the invariant.
      **Gap:** no specified mechanical path for *client-held* ops to enter new
      nodes' stores (clients don't speak §2 gossip verbs); needs a salvage-
      mode intake or manager relay in PROTOCOL.
    - **The recovery roster op cannot obtain an old-roster QC** (the old
      quorum is dead). §13's joint-quorum rule is overridden by root fiat
      exactly here and nowhere else — state it in §13 explicitly.
    - **Framing correction for implementers:** retention is **in-place** —
      retained winners keep their original `hlc`/`seq` position and the log
      goes *sparse* (Kafka compacted-topic offsets don't move). Nothing is
      "pushed to the head" of the conveyor; only the cut moves. The sole
      forward-rewrite is the optional 29i re-anchor op, which has a declared
      provenance cost.
    - The compactor's warm fold cache (29f) is itself a salvage source — a
      de-facto client replica; add to §2.2 step 1's inventory.
    - Contrast case, for completeness: **≤ f destroyed is not this scenario**
      — quorum intact, ordinary learner-add + promote, data flows via normal
      gossip catch-up, the manager ships zero data and no checkpoint is
      required at all (compaction only bounds how much the learner copies).

31. **APPLIED 2026-07-20 (DESIGN §12 trust-surface paragraph, RESILIENCE §2.2
    blast-radius note, COMPARISON row 12/20).**
    **Trust-surface characterization for the §12 rewrite's argument section
    (discussion outcome, 2026-07-20).** Three precise statements the new §12
    should make — they are what makes log-compaction *stronger* than the
    snapshot blob, not merely cheaper:
    - **Compaction can no longer alter a byte, only select.** A snapshot was
      manager-*authored* ciphertext: for a bootstrap client, both content and
      selection were fiat (a tampering manager could fabricate values inside
      it, detectable only by history-holders). Retained winners are the
      *original author-signed envelopes*: fabricating a value now requires
      forging a client signature. The manager's power over sealed history
      reduces to **omission/selection of genuinely-authored ops** — "a
      compression channel, not a write channel" becomes structural, not just
      audited. The audit (`state_root` vs resident clients' derived state)
      now guards only the selection, a strictly smaller surface.
    - **What a bootstrap client verifies vs trusts.** Verifies: genesis →
      unbroken manager control chain → checkpoint signature; every retained
      op's author signature, cert chain, `hlc`/`seq` provenance; retained-set
      digests; recomputed `state_root`. Trusts (manager fiat): the dead set —
      that nothing live was omitted and nothing superseded was kept. Resident
      full-history clients audit exactly that residue, continuously,
      checkpoint by checkpoint, within the cut-lag window (29g).
    - **Checkpoint-sync costs zero trust here — unlike a blockchain.**
      Replay-from-genesis exists in trustless systems because there is no
      root; here genesis and the checkpoint are signed by the *same* root of
      trust, so genesis-replay would terminate in the same anchor and buy a
      bootstrap client nothing. History replay's only marginal value —
      detecting manager misbehavior between genesis and now — is provided by
      resident clients' continuous audit instead. (This is weak-subjectivity
      sync, made free by the pre-existing root.) Client sync cost is
      O(live state + tail), never O(history).
    - **Salvage blast-radius precision (amends the item 30 discussion):**
      "> f destroyed loses only in-flight ops" is slightly too optimistic —
      committed-but-narrowly-held tail ops can die too (that is §2.2's
      disclosure clause). The practical bound: what's at risk is ops **no
      client has folded yet** — bounded by client sync cadence, not by
      compaction cadence (compaction changes replication *shape*, not
      durability). The retained baseline is the most-replicated object in
      the system (every node + every client + the compactor cache), so the
      fragile zone is precisely the recent tail.

32. **OPEN — config-plane governance (raised 2026-07-20; RULING pending; does
    NOT block M5/M6 — nothing below is in the current handoff scope).** The
    questions: which parameters are changeable and how; multiple manager
    keys; root rotation; whole-roster replacement; recovering from a wonky
    parameter change. Review-side recommendations, for ratification:
    - **(a) Parameters classify by the existing §16 lanes — no new machinery.**
      Client timers, hedge delays, backoff scale, retransmit/poll cadence:
      **lane 1** — pure client policy (PROTOCOL §4: nothing depends on a
      client timing out "correctly"), change freely, no coordination. Gossip
      cadence: node-local policy, liveness-only. **W** (cut-lag): compactor
      policy, declared in the control plane so clients know their audit
      window. **δ is the one true protocol parameter** — it shapes floors and
      the author-amnesia wait (FORMAL B8), so heterogeneous δ is a liveness
      hazard and an amnesia-soundness hazard: δ must live in the control
      plane and change via a **lane-3 epoch-fenced control op**. Floors/WMs
      already bind `config_epoch`, so mixed-epoch floors interpret
      deterministically across the fence.
    - **(b) Wonky-value protection is the existing three-layer pattern:**
      tool interlocks (MANAGER §3, fail near the operator) → node-side
      bounds validation (reject δ outside fixed sane protocol bounds, exactly
      like even-roster rejection) → the activation gate itself (a change that
      prevents its own acknowledgment quorum simply never activates — the
      joint-quorum pattern is inherently fail-safe; the old epoch continues).
    - **(c) The corrective channel must never be gated by the parameter it
      corrects.** A δ set pathologically small could bounce the very control
      op that reverts it (`future_hlc`/`below_floor` on the manager's own
      write) — a self-locking wedge. Rule: nodes accept `class = control` ops
      under a **fixed protocol-constant skew window δ_control** (generous,
      NOT settable), independent of the settable data-plane δ. Same asymmetry
      family as ballot-`ACCEPT`'s exemption from dep/contiguity gates
      ("completing a decision must never block on context").
    - **(d) Multiple managers: delegation, never co-equal roots.** v1 answer
      is §15 capability certs (M5): several operators can hold
      `issue-revoke` / `manage-roster` / `compact` certs, each revocable by
      the root; the root stays singular and offline. Co-equal independent
      root keys are REJECTED — they widen the §3.5 split-view surface and
      make "root compromise = game over" plural. The recorded hardening
      remains a **threshold root** (§3, §16 worked example), not multiple
      roots.
    - **(e) Root rotation = succession, and it only helps the healthy case.**
      A slotted **root-succession control op** (public slot
      `H("root" ‖ generation)`, old root signs the new root key; the
      succession chain joins the control-plane liveness set forever;
      bootstrap verifies the chain from the genesis root). Serves proactive
      hygiene, escrow refresh, and the §16 post-quantum path. Stated
      honestly: succession does NOT mitigate compromise (a compromised root
      signs a hostile successor just as happily) and CANNOT recover loss
      (the old key must sign) — escrow/threshold remains the loss answer;
      genesis TOFU remains the anchor.
    - **(f) Whole-roster replacement in one go: already sound** — B4 + the
      possession barrier cover arbitrary joint jumps including disjoint
      old/new rosters (stage as learner-adds, then one replace op).
      Operational caveat to write down: full replacement orphans a
      long-offline client whose entire cached seed set is the old roster
      (§17's hard-bootstrap-failure open question) — policy: stage
      replacements, or keep one legacy endpoint record alive as a forwarder
      until client caches have rolled over.

## R1 adversarial review findings (2026-07-21) — false rejections + containment

33. **Adversarial review of M0–M6 (three parallel reviewers, all findings
    verified against code). Two correctness bugs FIXED; a cut-unaware gossip
    trio RAISED for pre-M7 fix.**
    - **(7, SEVERE, FIXED) Resurrection mask must be a FIXPOINT.** `compact()`
      scanned only `winners`, but a retained mask tombstone is itself replayed at
      bootstrap — a chain `W(set A,B) → X(del B, set C) → Z(del C)` retained X to
      mask B but GC'd Z, so bootstrap resurrected C (A4 broken: `full={A}`,
      `boot={A,C}`). NOTES 29b is a fixpoint ("no *retained* op mutates its key").
      Fixed: closure over newly-added masks. Regression:
      `test_A4_resurrection_mask_is_a_fixpoint`.
    - **(5, MEDIUM, FIXED — code, not doc) Client below-horizon guard.** The R1
      reviewer flagged it "unimplementable — `Promise` lacks the accepted op's
      hlc." Owner ruling: **fix the code to meet the design, do not weaken the
      design** — the guard (DESIGN §8 / PROTOCOL §1.3 step 3) is well-specified.
      `Promise` now carries `accepted_hlc` (wire change — R2 note); `QuorumConfig`
      gains `horizon`; `_choose_and_accept` treats a below-horizon accept as
      no-accept. Tests: reborn op wins with the horizon set, ancient re-proposed
      without it. Documents win; the struct grew a field.
    - **(1, CRITICAL, RAISED — latent) `store.heads()` severs the dense tail
      after GC.** heads() anchors runs at `seq==0`; after GC drops a below-cut
      seq-0 op the author vanishes from heads(), so its valid tail is never
      gossiped/advertised/served in a frontier bundle. The `gc_checkpoint`
      docstring promises "pinned heads stay" — NOT implemented. Fix (pre-M7):
      thread the active `cut` into `heads()`/`append()` and keep a pinned per-author
      cut-boundary head that GC preserves.
    - **(2, HIGH, RAISED — latent) `store.append()` GAPs a valid tail op** whose
      `seq-1 ≤ cut` predecessor was GC'd — PROTOCOL §2.1's cut contiguity
      exemption is uncoded. Same fix family as (1).
    - **(3, MEDIUM, RAISED — live) `verify_baseline` false-rejects a complete
      baseline** that still holds not-yet-GC'd dead ops (the normal lazy-GC
      state): its digest is over all covered ops, the checkpoint's over winners
      only. Fix: compare over retained semantics, or accept `have ⊇ committed`.
    - **(4, HIGH, RAISED) `Commit._on_fetch_reply` false-abort.** Returns
      `Failed(EXHAUSTED)` on ANY non-matching reply, so a late/hedged promise or
      Nack during the FETCH window aborts a decidable commit. Fix: `return []`,
      let the round-timeout escalate.
    - **(8/9/10, LOW, R2 rulings)** `dead` is the full below-cut set not the
      incremental delta (cost); cert `epoch` decoded but unenforced (permissive);
      equivocating-manager non-nested cuts → double barrier (Byzantine root, out
      of model). **Reviewers CLEARED** as correctly-strict: skew boundaries,
      equivocation guard, QC bitmap, `_CAP_FOR_KIND`, pver fence, revocation
      ordering, universe reset, attempts-sidecar completeness, codec extractors,
      `holds_frontier`.
    - **Root theme:** M6 compaction left three read/validate gates cut-unaware;
      the M6 tests missed them by using clean already-GC'd stores. The testing
      plan adds a false-rejection matrix (boundary-valid-ACCEPTED beside each
      invalid-rejected test), an adversarial-node sim suite (equivocator / floor
      perjurer / time-traveller / amnesiac manager, per RESILIENCE §3), and A4 as
      a property/fuzz test (the fixpoint class a point vector misses).

## R2 design rulings (2026-07-21) — HANDOFF-R2 Q1–Q5 answered

34. **RESOLVED 2026-07-21 — all HANDOFF-R2 rulings landed as DESIGN/PROTOCOL/
    FORMAL/IMPLEMENTATION edits; this item is the rationale record. Finding 4
    is GO (land now); findings 1–3 are unblocked; one NEW finding (11) raised.**
    - **(Q1 — pinned heads: the cut IS the pin.)** No new artifact: the
      checkpoint's `cut` `{author: (seq, hash)}` is the pinned-head structure,
      persisted in the store's durability domain on checkpoint adoption (the
      pin is load-bearing across crash-restart). `heads()` anchors dense runs
      at `cut_seq + 1` seeded by the pinned hash and reports the pin itself
      when no tail extends it; `append()` exemption confirmed **as proposed**:
      accept iff `pred ∈ store` OR `seq ≤ cut_seq[author] + 1` (note the
      PROTOCOL §2.1 text previously read `seq ≤ cut`, which missed the
      boundary op at `cut+1` — sharpened). The pin is metadata, not an op row
      (the boundary op may itself be dead). Per-author `(seq, hash)`
      granularity RATIFIED; merkle frontier object REJECTED (wrong scale,
      loses the localize-to-author property). DESIGN §12 bullet added.
    - **(Q2 — baseline completeness = equality over `covered ∖ dead`.)**
      Superset-OK is REJECTED as unimplementable: a `(count, digest)`
      commitment cannot test superset membership. Instead the retained
      projection is checkpoint-defined: every below-cut digest (`SUMMARY`,
      `verify_baseline`, `pull_baseline`) is computed over held-covered MINUS
      the adopted checkpoint's `dead` — which also kills the mirror bug the
      handoff didn't name: `summary()`/`pull_baseline()` digest raw holdings
      today, so a GC'd node re-pulls dead envelopes from any lazy peer, every
      round, forever (finding 3's blast radius includes anti-entropy
      oscillation, not just intake false-reject). Mismatch at the node layer
      is a *sync signal* (GC → pull → re-verify); it is a rejection only at
      bootstrap intake. Deltas apply in checkpoint-chain order; a party
      missing intermediate checkpoints resyncs the baseline whole. DESIGN §12
      bullet added.
    - **(Q3 — cert `epoch` is provenance metadata, NOT a fence.)** Caps are
      epoch-independent; fold-positional revocation is the only kill switch.
      Epoch-fencing would make every roster change a mass re-attestation
      event coupled into the joint-commit window — exactly the in-flight
      continuity §13 preserves — for zero security gain (a pre-bridge
      revocation survives the bridge; key material is fenced by `keyepoch`).
      Do NOT add fold enforcement. Forced re-attestation, if ever wanted, is
      lane-3. DESIGN §15 edited.
    - **(Q4 — incremental `dead` by contract.)** The compactor is fed the
      previous checkpoint's retained set + sidecar (its warm barrier,
      reconstructed mutations-only) plus the inter-cut tail; assert the
      precondition (no below-prev-cut input outside prev_retained).
      `dead = (prev_retained ∪ covered_tail) ∖ new_retained` — never re-list
      prior dead. Decisive argument: after the first GC anywhere, full
      history *doesn't exist*, so the current full-recompute signature isn't
      merely slow — it's incoherent at M7. Diffing against the prior `dead`
      list is REJECTED (that list is ∝ prior churn and semantically
      redundant; the retained set is the complete positive statement).
      Genesis-first checkpoint = degenerate `prev = ∅` case. DESIGN §12
      bullet + PROTOCOL §3.2 edited.
    - **(Q5 — `Promise.accepted_hlc` BLESSED; horizon gets an explicit
      carrier.)** The wire field is correct and minimal: the acceptor holds
      the envelope; client-side derivation would need a `FETCH` that fails
      precisely in the GC'd case the guard serves; a signed misreport is
      portable evidence. Pre-1.0, no compat debt. But the provenance ask
      exposed a real gap: **no artifact carried the horizon** — the
      checkpoint op's own `hlc` is UNSOUND as horizon (it sits above `F`;
      using it voids live tail accepts → double-decide), and max-over-
      retained under-approximates (a dead op may hold the highest below-cut
      `hlc`). Ruling: checkpoint schema gains explicit `horizon = F` (the
      sealing finality frontier); `advance_horizon` and `QuorumConfig.
      horizon` both source from the latest committed checkpoint. Strictness:
      void/ignore strictly-below only — at `hlc == F` an op may still newly
      commit (`hlc == floor` passes the past gate), so `≤` would be a safety
      hole while `<` costs a measure-zero livelock candidate. Three layers
      confirmed: acceptor void on prepare + client guard + post-GC receipt
      floor (§12 backstop, wire at M7). No fourth rule needed — "refuse to
      report" IS the void rule. DESIGN §8/§12 + PROTOCOL §1.1 edited.
    - **(Fix 7 verification — CORRECT and COMPLETE.)** The fixpoint closes
      over exactly the right set. Key lemma: `version` is only ever written
      by *applied* mutations, so every retained data op (winner or mask) was
      APPLIED in the full fold — the mutations-only bootstrap replay is
      faithful for them, and the last retained mutator of any key is that
      key's version-op. Guards are structurally irrelevant at bootstrap
      (mutations-only replay never evaluates them), so "a retained winner
      whose guard references a dead version" cannot leak — there is no
      second class. The retention obligation is precisely "the version-op of
      every key any retained op mutates is retained", which the worklist
      closure computes. (The `version != ⊥` branch in the mask scan is
      unreachable armor: any key mutated by an applied op has a real
      version.) FORMAL A4 wording updated to the fixpoint form.
    - **(Fix 5 verification — CORRECT; placement confirmed.)** Client-side
      guard + acceptor void is exactly NOTES 27's two-sided ruling; the
      third layer (receipt floor) was already normative in DESIGN §12 and
      lands with M7 GC wiring. Boundary: both sides strict-`<` (see Q5).
    - **(Finding 4 — GO, land immediately.)** `return []` on any FETCH-phase
      reply that is not the awaited op; the round deadline escalates.
      Prefer matching on the request (`isinstance(req, FetchOpReq)`) over
      the payload type — precise, and robust to future response shapes.
    - **(NEW finding 11, HIGH, latent — `holds_frontier` is a fourth
      cut-unaware gate.)** DESIGN §13's possession barrier checks per-op
      holdings (`heads()` reach + exact frontier envelope); after GC, an
      idle author's frontier entry can name a dead, GC'd envelope, so **no
      honest node can ever pass the barrier → the first post-GC roster
      change wedges (B4 liveness)**. Ruling: below the cut, possession =
      verified baseline completeness (Q2 semantics); the per-op check
      applies only above the cut. Same fix family and sequencing as
      findings 1/2 (before or with M7). DESIGN §13 edited.
    - **(Examined and CLEARED — deps on GC'd ops.)** An op citing a `deps`
      hash that was GC'd is refused `unknown_dep` forever; this is
      *correctly strict*: a client only cites recently-observed ops, the cut
      trails finality by the audit window W, so only a client stale by > W
      hits it — and the remedy is the ordinary re-read-and-retry. Bounded,
      intended; no code change. Recorded so it isn't re-litigated.
    - **(§6 rulings.)** (a) Adversarial personas: YES — first-class sim
      subclasses (equivocator, floor perjurer, time-traveller, amnesiac
      manager); `DOUBLE_VOTE`/`FLOOR_PERJURY` evidence minting lands WITH
      them (it is currently a stub — B6 is claimed, not asserted, for those
      kinds; the personas are its only honest generators). Equivocator
      first. (b) False-rejection matrix: YES, standing rule — landed as
      IMPLEMENTATION §6.5. (c) A4 property fuzz: YES, now — the harness
      exists and the fixpoint bug was a class; landed as IMPLEMENTATION
      §6.6. (d) Split-view detection is NOT paper: divergent manager chains
      from one genesis must fork at some `(author, seq)` (prev-linkage
      forces it), so two victims exchanging logs mint `FORK` evidence via
      ordinary `append` — write the two-victims sim test; landed in
      IMPLEMENTATION §6.4.
    - **Sequencing:** finding 4 now; findings 1/2/11 as one cut-aware-store
      change (Q1 spec) + finding 3 (Q2 spec) before or with M7; Q4's
      incremental compactor before the M7 daemon wires GC; Q5's `horizon`
      field is a checkpoint schema change — land it with the golden-vector
      update in the same commit.

35. **R3 framing rulings (2026-07-21) — optimization ledger, threat
    re-weighting, the fumbling manager.** Issued with HANDOFF-R3.
    - **(a) The dial ledger is DESIGN §18.** Objectives split into invariants
      (confidentiality, determinism/SEC, sign-after-fsync, evidence totality,
      root-offline — never on a dial) and six dials (`n`, gossip cadence,
      conveyor cadence, `W`, `δ`, delegation breadth). Trilemma honesty:
      exactly two genuine three-way tensions (replication: durability ×
      footprint × cost, all riding `n`; compaction: disk floor × delta
      bandwidth × audit window `W`); the rest are two-way dials. Named
      non-tensions so they aren't traded by accident: durability and
      partition tolerance are the SAME dial (`n`); write availability under
      partition is not a dial (writes park on minority sides by
      construction, reads continue everywhere — chosen in §1). Two
      objectives the original list missed: client sync cost (structurally
      settled) and operator-proofness of recovery (see c).
    - **(b) Threat re-weighting: TEE clients.** The reference deployment
      runs client nodes in TEEs, storage nodes bare. Octopus analysis and
      test priority re-weight toward node-side tentacles (equivocator,
      floor perjurer, withholder, amnesiac node); client-side rows stay in
      the model at lower priority. Client-held audit state gains standing;
      the §3.5 two-victims comparison channel strengthens. RESILIENCE §3
      intro edited.
    - **(c) The fumbling manager is a first-class persona — honest-but-
      confused root, the most probable real >f event.** RESILIENCE §2.3
      (self-inflicted gorilla): mistaken recovery against a living quorum
      is possible by construction (absence of a quorum is unprovable);
      containment is protocolar — **activation-is-the-park** (the §13
      recovery exception, restated node-side: observing a valid recovery
      fence for one's own epoch stops receipting under it, fail-stop like
      the lane-2 fence), casualties self-report as QC-vs-manifest
      contradictions, loss bounded by partition duration and never silent.
      Prevention is operational and the TOOL owns it (MANAGER §3: dwell
      probe, hard refusal while a quorum answers, named presumed-dead list,
      printed blast radius). Rule of thumb made normative: recovery is
      never urgent — a parked system loses nothing by staying parked.
    - **(d) HANDOFF-R3 issued:** WP1 = the item-34 correctness wave
      (findings 1/2/3/4/11, Q4 incremental compactor, Q5 horizon schema);
      WP2 = chaos axes (latency incl. heavy-tail + asymmetric, reorder/dup/
      burst loss, partitions incl. one-way + flapping, time skew incl.
      drift + step jumps, crash-restart at every persistence boundary);
      WP3 = node-side personas with DOUBLE_VOTE/FLOOR_PERJURY evidence
      minting; WP4 = the fumbling-manager suite (crash-at-every-step,
      double-press, stale frontier, mistaken recovery, button-masher
      property test).

36. **R3 pushback amendments (2026-07-21, pre-WP1 — implementer review of
    HANDOFF-R3, all three points accepted).**
    - **(a) Activation-is-the-park RULED: a restatement of M5's
      `activate_epoch`, not new machinery** — the same monotone epoch
      switch with a second validated trigger: the root-signed recovery
      pair (recovery checkpoint + roster op carrying a `recovery` field
      that names it) substitutes for the joint certificate. The park is
      the *emergent effect* of the `e+1` receipt/watermark stamp meeting
      client-side epoch checks — no separate park rule exists. New surface
      is exactly one validate-fence-then-activate step, promoted out of
      the WP4 test package into **WP1.7** with its own unit tests, landed
      before any persona exercises it. Security ruling attached:
      recovery-marked roster ops are **root-only** — a delegated
      `manage-roster` cert must never mint fiat activation, because fiat
      bypasses the joint-quorum safeguard that makes that delegation safe.
      Distinct from the possession barrier: the barrier gates *joining*
      the new roster; the fence parks *everyone who sees it*. DESIGN §13
      edited; HANDOFF-R3 amended.
    - **(b) Sequencing gated, not a mega-push:** WP1 fully green → STOP →
      D3 review of that diff (cut-aware store + compactor rewrite are the
      two highest-risk changes; WP1.7 is new acceptor surface) → WP2
      harness alone → WP3/4 personas. HANDOFF-R3 sequencing rewritten.
    - **(c) Q3's consequence acknowledged explicitly, not left implicit:**
      rotating the roster expires nobody's capabilities — a
      distrust-motivated roster change must be PAIRED with explicit
      revocations; an epoch bridge never re-attests. DESIGN §15 states it
      as the deliberate choice it is; MANAGER §3 makes the tool print the
      live cert inventory before roster commands so the
      bridge-re-attests assumption cannot hide.

37. **RAISED 2026-07-21 (finding 12, HIGH, latent) — delegate-minted
    checkpoints authorize but place NO barrier; ruling: control-only
    pre-walk. Lands in WP1.4 scope.** `fold._checkpoint_cuts` skips every
    op with `author != manager_pub`, so a `compact`-delegate's checkpoint
    folds `CONTROL` (the M5 test asserts exactly this verdict) yet never
    partitions the walk — no barrier, no tombstone death, no universe
    reset, no attempts application, no pver activation at its cut. The
    op's entire semantic payload is dropped; the routine-operation path
    the docs describe (delegate-minted conveyor, DESIGN §12/§15) has zero
    client-side effect. Every M6 barrier test uses root-authored
    checkpoints, which is why it survived. Root cause is a chicken-and-
    egg: barrier placement runs before the walk, but delegate
    authorization is fold-positional. **Ruling:** a **control-only
    pre-walk** — walk the op set in total order applying only control ops
    to a `ControlState` (what `ControlReducer` already does), recording
    each checkpoint that is authorized *at its own position*; those cuts
    partition the real fold, ordered by the checkpoint ops' total-order
    positions. Control authorization depends only on prior control ops,
    so the pre-walk is self-contained and deterministic. Regression: the
    delegate-cap test extended to assert **barrier semantics** (tombstone
    death + attempts + universe reset via a delegate-minted checkpoint),
    not just the verdict. Operational note ruled with it: run **one**
    compactor identity — with multiple authorized cut-minters,
    non-nested cuts become an honest possibility rather than the
    out-of-model Byzantine-root case (finding 10); the fold processes
    cuts in total order deterministically either way, but one identity
    keeps the conveyor linear.
    **RESOLVED (WP1.4 wave):** `fold._checkpoint_cuts` replaced by
    `fold._authorized_cuts` — a control-only pre-walk over a fresh
    `ControlState` in total order, recording every checkpoint whose author
    holds `compact` at its own position (agrees op-for-op with the main
    walk's CONTROL verdicts). Regression
    `TestDelegateCheckpointBarrier`: a compact-delegate checkpoint places
    the barrier (a reborn creation tag commits above the cut via the
    universe reset, state identical to a root-minted checkpoint); a
    write-only author places none (the reborn tag collides, key stays
    dead) — barrier semantics, not merely the verdict.

38. **RULED 2026-07-21 — layered payload encryption (application inner
    layer) is a lane-1 payload convention; the visibility ladder is now
    explicit (DESIGN §7).** Harry's deployment intent: storage nodes
    fully opaque (already structural), AND applications add their own
    encryption on values (and pseudonymized path components) so that
    group-keyring holders — manager, compactor, other apps' clients —
    see *shape* but not fields. Ruled compatible with zero protocol
    change: the fold interprets key paths only by byte-equality and
    values not at all, so the inner layer rides inside the Txn as opaque
    bytes. Constraints (normative, §7): (a) key bytes stable per key —
    per-app PRF'd paths work verbatim (slot tags + attribution are over
    path bytes); (b) `value_eq` guards compare inner-CIPHERTEXT —
    randomized inner encryption breaks them, deterministic leaks
    equality; the convention for inner-encrypted fields is version-CAS
    (unaffected: versions are envelope hashes); (c) future rich guard
    vocabulary (§17) evaluates at the group layer and cannot see through
    the inner layer — fields wanting such guards stay group-visible by
    choice. Consequences: the compactor's blast radius drops from "reads
    data" to "sees shape" (delegation gets cheaper as apps adopt the
    layer — confirming the §12/§15 delegation posture), and
    confidentiality of inner-encrypted fields survives even ROOT
    compromise — the one RESILIENCE §3.7 cell the protocol alone cannot
    flip. The minimal-oracle observation recorded for later: the
    compactor needs only key identity, mutation kinds, order, and slot
    preimages — never values — so a protocol-level structure-key/value-
    key split is possible future work; v1 gets the same effect as an
    app-side convention.

39. **D3 REVIEW of WP1 (2026-07-21, `ac4c710..97eeab7`) — NOT cleared:
    one HIGH regression (A4 break, reproduced) + one MEDIUM (reproduced,
    partly pre-existing) + two LOW. Fix wave gates WP2.**
    Overall: WP1.1/1.2/1.3/1.5/1.7 read clean and well-paired; the two
    flagged-highest-risk diffs are where the findings are.
    - **(13, HIGH, WP1.4 REGRESSION — `_mut_meta` treats committed-but-
      REJECTED ops as applied; A4 breaks.)** The docstring's justification
      ("guard-eval ≡ mutations-only on a committed set") is FALSE for the
      compactor's input: it holds only for the RETAINED set (whose ops are
      all applied — the NOTES 34 applied-ops lemma), not for an arbitrary
      committed band, which contains rejected/stale ops whose mutations
      never applied. Reproduced vector (3 ops, single checkpoint):
      `W(set A, set B)` applied; `Z(del B)` applied; `R(guard-fails,
      set B)` committed-REJECTED, sorting after Z. `_mut_meta[B] =
      (True, R.hash)` ⇒ mask scan believes B live ⇒ Z not retained ⇒
      bootstrap resurrects B (`full={A}`, `boot={A,B}`). Honestly
      reachable (any stale client's failing CAS/blind-guard write touching
      a since-deleted key). Mirror vector: a REJECTED `del C` makes
      `_mut_meta` nominate the rejected op as C's "tombstone" — the mask
      scan can then retain a rejected op whose OTHER mutations replay at
      bootstrap. Pre-WP1 code took masks from `r.meta` (guard-evaluated) —
      this is a rewrite regression. **Fix ruling:** universe-wide meta :=
      mutations-only over `prev_retained` data ops ONLY (sound there by
      the applied-ops lemma) **overlaid by `r.meta`** for every key whose
      `r.meta.version != ⊥` (the band's guard-evaluated truth; the ⊥
      guard keeps a band attempt-only lineage from erasing a below-
      prev-cut tombstone). Never feed non-retained band ops to a
      mutations-only fold. Regression tests: both vectors above, plus a
      fuzz generator arm that aims failing-guard writes at DEAD keys —
      the current arm picks targets from live state only, which is
      exactly why 50 seeds missed this.
    - **(14, MEDIUM, reproduced — `_authorized_cuts` does not mirror the
      lane-2 pver fence; partly PRE-EXISTING.)** A checkpoint with
      `op.pver > active pver` folds INVALID in the main walk yet the
      pre-walk records its cut: the barrier of an invalid op runs
      (reproduced: a fenced checkpoint still killed a tombstone lineage
      via barrier death). The old `_checkpoint_cuts` had the same hole
      for root-authored checkpoints; the pre-walk inherited it and adds
      cert-application divergence (a high-pver CERT_ISSUE folds INVALID
      in the main walk but grants caps in the pre-walk). **Fix ruling:**
      the pre-walk mirrors the fence — track its own pver view (skip any
      control op with `op.pver >` that view; apply PVER_ACTIVATE to
      pending; activate pending when the walk first crosses an op not
      covered by a recorded cut, mirroring barrier-position activation).
      Stage-order-vs-total-order divergence under a NON-FINAL (dishonest)
      cut is documented as contained — deterministic for all clients,
      wrongful-but-auditable territory — not solved.
    - **(15, LOW — pre-walk omits the `is_recovery` argument.)**
      `_authorized_cuts` calls `can_author_control` without
      `_is_recovery_roster(body)`, so a delegate's recovery-marked roster
      op is APPLIED in the pre-walk state while folding INVALID in the
      main walk. No cut-authorization impact today (caps don't depend on
      roster state) — but it is a divergence lying in wait. One-line fix.
    - **(16, LOW — `adopt_checkpoint` is not atomic.)** Three `set_meta`
      calls = three COMMITs; a crash between them leaves the cut adopted
      without its retained/dead companions, and nothing re-runs adoption.
      Fix: one transaction, one COMMIT.
    - **Process:** ceaabb3's swept-in doc edits stay as-is — no history
      rewrite; the attribution conflation is recorded here and content is
      intact. This item rides uncommitted in the working tree for the fix
      wave to commit (Opus holds the commit token).
    - **RE-REVIEW 2026-07-21 (`b176821`): CLEARED — WP2 unlocked.** All
      four fixes verified: both D3 reproducer vectors re-run green against
      the fix (A4 holds; fenced checkpoint places no barrier); the diff
      matches the rulings exactly (prev-retained-only `_mut_meta` with the
      ⊥-guarded `r.meta` overlay; pre-walk pver view with barrier-position
      activation; `is_recovery` threaded; atomic adoption). 130 tests
      green. Both reviewer reproducers are landed as in-repo regression
      tests (`test_rejected_write_to_dead_key…`, `test_rejected_op_is_not_
      retained…`, `test_finding14_fenced_checkpoint_places_no_barrier`)
      plus the dead-key fuzz arm with a performed revert-check — this
      cycle is the template for the **found-and-fixed log** convention,
      now standing as IMPLEMENTATION §6.7 (Harry's ruling: reproducers
      live in the repo as regression tests, never in session memory).

40. **WP2 HARNESS REVIEW (2026-07-21, `b176821..3d71dfe`): CLEARED —
    WP3/4 personas unlocked; equivocator + mistaken-recovery lead.**
    Verified: `UniformLinks` reproduces the exact pre-WP2 RNG call order
    (old seeds replay byte-identically — the back-compat claim holds);
    the directed request/reply hop split makes one-way partitions and
    dead-return links real at the protocol edge (and the dead-return
    test proves a commit through the remaining quorum); Gilbert-Elliott
    transitions are correct (bad persists at `1−p_good`, `bad_loss` vs
    base loss per state); every axis is scheduler-driven and seeded — no
    wall clock, no unseeded randomness; the crash suite pins each
    persistence boundary to its invariant (mid-GC rollback rests on
    `gc_checkpoint`'s single-COMMIT, verified true); skew feeds the
    acceptor through an injected per-node clock and B1/B2/B3 continuous
    assertions remain wired through every new axis (the backward-jump
    test finishing IS the B3 proof, as intended). Accepted scope, on
    record: (a) B6's minting side for `DOUBLE_VOTE`/`FLOOR_PERJURY`
    stays deferred to the WP3 personas per NOTES 34/35 — WP2's B6
    asserts honest-mints-nothing plus the live FORK path; (b)
    `gossip_round` is a test-driven pairwise sweep, not the epidemic
    daemon (M7) — sufficient for convergence proofs; (c) two forward
    notes for WP3/4, not defects: `converged()` compares op sets only —
    extend to receipt/QC coverage when the equivocator persona needs
    third-party evidence assembly (the sweep itself already carries
    receipts via `gossip.merge`); and the sim's gossip path is
    cut-unaware — the WP4 mistaken-recovery scenario needs
    checkpoint-aware sim plumbing (adopt/GC hooks) before it can
    compose partitions with compaction.

41. **WP3.1 + WP4.7 REVIEW (2026-07-21, `3d71dfe..0ca9e29`): CLEARED —
    continue through the WP3/4 remainder WITHOUT another hard gate; final
    review at WP3/4 completion. Two rulings issued for the remainder.**
    Verified: `DoubleVoteEvidence` is correctly scoped — omitting an
    epoch-equality check is RIGHT (slot state carries across epochs
    untouched, §13, so two different-op receipts at one ballot is a
    violation in any epoch mix), and skipping author-sig checks on the
    ride-along envelopes is sound (they are hash-bound to the receipts;
    even a garbage envelope the signer receipted is a genuine double
    vote). `detect_double_votes` is the right third-party shape
    (assemble-after-gossip, idempotent, attributed). WP4.7 composes
    WP1.7+WP2.2 with nothing new, as claimed; heal-time fence propagation
    is test-driven `on_recovery_fence` calls standing in for the M7
    daemon observing gossiped control ops — consistent with the NOTES 40
    scope. 150 green.
    - **RULING (a) — B1-assertion scoping under personas; land BEFORE the
      floor-perjurer or button-masher.** The harness's `_B1State` asserts
      strict quorum-level single-decree, which is an HONEST-configuration
      invariant. RESILIENCE §3.1 documents that an equivocator CAN mint
      two QCs for one slot (two quorums intersecting only in it) — a
      contained, evidenced behavior, not a failure. Today's tests don't
      drive that race, so the assertion never fires; the first persona
      run that does (a two-client commit race through the equivocator, or
      the button-masher by chance) will fail the harness on documented
      behavior. Rule: with personas present, quorum-level B1 relaxes to
      exactly FORMAL B6 — *if* duplicate same-slot QCs exist, then (1)
      every involved quorum contains a persona node, (2) the fold still
      yields one winner, (3) a DOUBLE_VOTE proof is assemblable from the
      union of honest stores. Strict B1 stays asserted for quorums
      composed entirely of honest nodes.
    - **RULING (b) — the disclosure gets a detector and an artifact.**
      WP4.7 asserts the disclosure's INGREDIENTS (an e=0 QC verifying
      below the parked epoch) but no detector produces a persistent
      record. RESILIENCE §2.2 step 4's "the QC is a cryptographic receipt
      of the broken durability promise" becomes code: a new evidence kind
      `LOST_COMMIT` — minted when a party holds a QC for an op that is
      (i) below the recovery fence's epoch and (ii) absent from the
      recovery checkpoint's `retained` manifest — persisting the QC + the
      recovery checkpoint reference, attributable to the recovery op.
      Not signer-misbehavior evidence but the same table and audit
      surface (detect-and-disclose has one place to look). Lands with the
      WP4 remainder so the button-masher can assert on it.
    - Standing from NOTES 40, still open and still gating the fuller
      scenarios: `converged()` receipt/QC coverage, and checkpoint-aware
      sim plumbing before partitions compose with compaction.

42. **RULED 2026-07-21 — crypto transition spec (CRYPTO.md).** The
    BLS-vs-PyNaCl / AEAD / AD questions Harry raised, settled:
    - **Ed25519 stays, BLS12-381 declined for v1** (door open via the
      genesis suite id). Decisive: rev-6 compaction GCs below-cut
      receipts/QCs, so aggregation would compress only the dense tail;
      n≤7 QCs are ~300 B; and the §16 threshold-root hardening is
      reachable as FROST threshold Ed25519 (RFC 9591) — ordinary
      signature on the wire — so declining pairings forecloses nothing.
    - **Payload AEAD = `xcs1`: XChaCha20-Poly1305-IETF with SIV-derived
      nonce** (`nonce = PRF(nk, AD ‖ H(plaintext))`). Premise correction:
      PyNaCl ≥1.5 ships real AEAD-with-AD (`nacl.secret.Aead`) — nothing
      is homebrewed from box/secretbox. MRAE-in-practice is LOAD-BEARING
      here, not taste: our nonces are deterministic, and an equivocating
      or crash-retrying author can emit two payloads under one envelope
      header — naive `nonce = H(AD)` then reuses keystream. Folding the
      plaintext into the nonce makes reuse structurally impossible;
      residual is the standard MRAE determinism bound, unreachable
      honestly. Deoxys-II declined with respect (right shape, proven at
      Oasis, thin Python support); AES-SIV/AES-GCM-SIV via PyCA
      recorded as standards-stamped fallbacks — any of them is one
      keyepoch bump away by construction.
    - **AD answered:** not strictly necessary (the author signature over
      the envelope incl. ciphertext already binds) — RETAINED anyway as
      `H(envelope-minus-payload)`: fail-closed decrypt-before-verify
      ordering, the nonce-derivation input, transplant fails at the AEAD
      layer. The derive-a-key-from-AD-with-zero-nonce pattern is
      REJECTED (same equivocation footgun, no added benefit).
    - **Wraps = `sbx1` sealed box**, recipient X25519 derived from the
      member's Ed25519 identity — one keypair per member.
    - **Backend = PyNaCl (PyCA-maintained); vendored pure-Python stays
      as the differential-test oracle** (no-native CI lane, byte-for-byte
      cross-checks). Rust/Go parity verified for every chosen primitive
      (CRYPTO.md §3).
    - **AMENDED same day — the one-scheme rule (Harry's correction).**
      `auth0` was dev scaffolding only; the system never ships
      unencrypted, and dev logs die with dev deployments (no
      auth0-legacy-decode obligation). The per-keyepoch suite-menu
      framing is WITHDRAWN as a downgrade/malleability surface: v1 ships
      exactly ONE scheme; `xcs1`/`sbx1` are internal construction names,
      not wire selectors; the genesis suite id collapses to a pinned
      constant; **a future scheme change is a lane-2 `pver` fence +
      rotation** (existing fail-closed machinery), and `keyepoch` selects
      keys, never schemes. PyNaCl confirmed as the single `uv`-managed
      crypto dependency (stdlib-only rule consciously amended for
      production). Implementation cleanup noted for post-WP3/4: collapse
      the `aead_suite` parameter threading to the pver-determined
      constant. Runner-up recorded in CRYPTO.md §0: PyCA `cryptography` +
      AES-256-GCM-SIV (standards-stamped MRAE, zero AEAD composition;
      kept second on Go-parity and the hand-rolled wrap it would need) —
      flippable cheaply before launch only.

43. **WP3/4 FINAL REVIEW (2026-07-21, `0ca9e29..1586b8c`) — track cleared
    EXCEPT finding 17 (HIGH): FLOOR_PERJURY as built convicts honest
    nodes. One fix wave closes HANDOFF-R3.**
    Cleared: ruling 41(a) implemented exactly (strict B1 for all-honest;
    duplicate QCs must trace to a persona in the quorum intersection;
    revert-checked against the genuine two-QC race); ruling 41(b)
    LOST_COMMIT is sound (disclosure with external-context verify —
    correctly NOT signer-misbehavior; flagging orphaned below-fence
    control-op QCs too is accepted behavior); personas 3.3–3.6, fumbling
    4.1–4.6, the NOTES-40 infra, and the button-masher all read clean.
    163 green.
    - **(17, HIGH — `FloorPerjuryEvidence` is a false-accusation
      machine.)** Its `verify()` = same signer + `op.hlc < wm.floor` +
      two valid signatures. An HONEST node satisfies that with purely
      legitimate artifacts: receipt op X at `hlc=100` while floor=50
      (legal); floor later rises; issue WM@990 (legal, mandatory). The
      pair now "proves" perjury. Aggravated by PROTOCOL §1.1: honest
      nodes MUST re-yield identical old receipts on resubmission (and
      `RERECEIPT` re-issues across bridges), so below-current-floor
      receipts are ordinary honest output forever. The suite is green
      only because the masher never calls `detect_floor_perjury` and the
      dedicated test builds only the true positive. **Root cause is the
      DESIGN, not the code**: RESILIENCE §3.1's "the WM + the receipt
      are self-contradicting signatures = proof" presumes an ORDERING
      ("receipted beneath it *later*") that the two artifacts do not
      cryptographically carry. The reviewers (me included) let that
      overclaim stand in R1; the persona wave faithfully reified it.
    - **RULING — artifact issuance chains (the node-side mirror of the
      author chain).** Receipts and watermarks gain a per-signer
      monotone `issue_seq`, persisted in the signer's durability domain
      and never reused; **idempotent re-issue returns the STORED
      original artifact** (resubmission and RERECEIPT alike — re-signing
      with a fresh seq becomes the crime, so serve-from-store turns
      load-bearing). Perjury proof = one signer's WM at `issue_seq = s`
      attesting floor F **plus** its receipt at `issue_seq > s` for an
      op with `hlc < F`. Sound: an honest node cannot produce the
      ordered pair (after attesting F the past gate refuses below-F
      acceptances, and re-issues carry their original seqs). Complete:
      a perjurer either stops attesting (exits the finality game) or
      yields the pair; counter-reuse (two artifacts at one
      `(signer, issue_seq)`) is its own FORK-analog proof. Framing
      impossible. Wire change (receipt + WM grow ~8 B; golden-vector
      bump) — Harry may veto for the recorded fallback: downgrade
      FLOOR_PERJURY to witness-grade policy evidence (RESILIENCE §1's
      no-proof-no-punishment regime), at the cost of weakening the §3.7
      "finality: violable · with proof" cell to "violable · detected".
      **Quarantine meanwhile:** `detect_floor_perjury` and the pair
      `verify()` are UNSOUND as accusation — gate or remove before
      anything consumes evidence for ejection; the found-and-fixed rule
      applies (the honest-node false-positive vector above becomes the
      regression test — it FAILS against current code).
    - **Scope rulings:** (i) the masher driving manager verbs
      (roster/checkpoint/recovery + inline LOST_COMMIT assertion) is
      accepted as a follow-up, backlog not gate — the dedicated WP4
      tests cover those paths; (ii) the masher-surfaced M4 property —
      a same-author non-contiguous op (e.g. a second create after a
      lost slot leaves an orphan-island accept) cannot be healed by the
      seq-based gossip delta — is RECORDED as a known, accepted M4
      property: orphan islands are by-design excluded from heads
      (NOTES 16), and the healing paths are dep-PULL, re-proposal, and
      the M7 daemon's retransmit; not a defect.
    - **Track status: HANDOFF-R3 is complete modulo the finding-17 fix
      wave** (quarantine + issuance chains or the fallback, Harry's
      call; plus its regression vectors per IMPLEMENTATION §6.7).
    - **BLESSED 2026-07-21: Harry accepts the wire change; the
      witness-grade fallback is DECLINED** (explained and recorded: it
      would move floor perjury into RESILIENCE §1's no-proof-no-punish
      regime — zero wire cost, but no automatic ejection ever, framing
      prevented socially not cryptographically, an adjudication burden
      and accusation-spam surface, and the §3.7 finality cell demoted;
      not worth saving ~8 bytes). Normative edits landed: RESILIENCE
      §3.1 (proof rides the issuance chain; the naive pair is explicitly
      called out as non-proof), IMPLEMENTATION §2 (receipt signs
      `op_hash ‖ epoch ‖ ballot ‖ issue_seq`; **QC carries the
      per-signer `issue_seqs` list parallel to `sigs`** — each receipt's
      signature covers its seq, so QC verification must reconstruct
      per-signer messages; watermarks sign `floor ‖ epoch ‖ issue_seq`).
      **Fix-wave work order (Opus):** (1) `issue_seq` persisted in the
      signer's durability domain, monotone, never reused; stamped into
      receipts + watermarks; (2) serve-from-store re-issue everywhere
      (resubmission, RERECEIPT — re-signing fresh is the crime; the
      idempotent-identical-receipt tests extend to assert seq
      stability); (3) QC schema + assemble/verify carry `issue_seqs`;
      golden-vector bump, one commit; (4) `FloorPerjuryEvidence` becomes
      the ordered pair (WM@s attesting F + receipt@s'>s for op.hlc < F);
      `detect_floor_perjury` reworked accordingly; (5) seq-reuse
      evidence kind (`SEQ_REUSE` or fold into FLOOR_PERJURY's family —
      implementer's naming call, ruling: it must be minted); (6)
      regression vectors: the honest-node false-positive (old receipt +
      newer WM must NOT convict — fails against current code), the true
      perjurer (caught via ordered pair), the re-issue-preserves-seq
      pair, and a masher arm that calls `detect_floor_perjury` under
      honest chaos and asserts zero proofs.

44. **FINDING-17 FIX REVIEW (2026-07-21, `41fcc4c`): CLEARED —
    HANDOFF-R3 IS CLOSED. One MEDIUM follow-up (finding 18, completeness
    not soundness) + the remaining-steps roster (the session-recovery
    record).**
    - **Fix verified sound.** The ordered pair (`rcpt.issue_seq >
      wm.issue_seq`) is the proof; serve-from-store preserves original
      seqs across resubmission AND cross-epoch RERECEIPT (acceptance-
      bound seq); `verify_each` correctly reconstructs per-signer QC
      messages; the masher's honest-chaos arm runs the detector on every
      node across all seeds and asserts zero false accusations — the
      finding-17 false-positive class is dead. Crash edge analyzed
      sound: a receipt row lost between sign and store burns a seq, and
      the re-request can only re-issue for ops still above the floor
      (the skew gate runs first), so no false pair is constructible.
      167 green.
    - **(18, MEDIUM — back-stamping evades the compact proof;
      completeness gap, soundness intact.)** A *sophisticated* perjurer
      controls its own `issue_seq` stamp and can evade the ordered pair:
      (i) stamp the below-floor receipt with the WM's OWN seq —
      `SeqReuseEvidence` compares receipts only, so a receipt-vs-
      watermark collision at one seq mints nothing; or (ii) stamp into a
      **burned gap** (crash-consumed seq) — the artifact then looks like
      an honest old receipt and no third party can refute the claimed
      ordering. No honest node is ever framed (soundness holds — the
      HIGH part of finding 17 stays fixed); the evasion degrades
      detection to witness-grade, which is the RESILIENCE §1 policy
      regime — acceptable interim, but closable: **(a)** cross-kind
      seq-collision evidence — a receipt and a watermark at one
      `(signer, issue_seq)` with contradictory content is a signed
      contradiction; cheap, next wave. **(b)** gap-free issuance —
      consume the seq and persist its justification (which artifact it
      was spent on) in ONE transaction, then sign DETERMINISTICALLY
      (Ed25519 is deterministic: crash-restart re-derives the identical
      artifact instead of burning the seq); with no gaps, every
      back-stamp necessarily collides with a genuine occupant, and (a)
      turns the collision into proof — completeness restored. Lands with
      M7 (it reshapes the issuance flow the daemon wires anyway). Until
      (a)+(b): the §3.7 "finality: violable · with proof" cell carries
      an honest asterisk — proof-grade against straightforward perjury,
      witness-grade against a back-stamping contortionist.
    - **HANDOFF-R3 CLOSED.** Full track: WP1 correctness (findings
      1/2/3/4/11/12 + Q4/Q5 + fence trigger; D3 found+fixed 13–16) →
      WP2 chaos harness (5 axes; NOTES 40) → WP3 personas (equivocator,
      floor-perjurer, withholder, amnesiac, mixed-GC, split-view) → WP4
      fumbling manager (incl. mistaken recovery + button-masher).
      Evidence kinds wired and asserted: FORK, DOUBLE_VOTE,
      FLOOR_PERJURY (ordered), SEQ_REUSE, LOST_COMMIT (disclosure).
      Every finding closed per the §6.7 found-and-fixed log.
    - **REMAINING-STEPS ROSTER (start here after context loss):**
      1. **M7 — daemon + CLI + demo** (IMPLEMENTATION §5), absorbing the
         hooks the track accumulated: GC wiring (checkpoint adoption →
         `adopt_checkpoint`/`gc_checkpoint`/`advance_horizon` on
         observation), the §12 receipt-floor-at-horizon backstop,
         recovery-fence observation as a daemon behavior (today
         test-driven calls), the epidemic gossip loop (today a test
         sweep), and finding 18(b) gap-free issuance.
      2. ~~Finding 18(a) next wave / 18(b) with M7~~ **AMENDED (Harry,
         2026-07-21): finding 18 closes as a standalone interjection
         wave BEFORE HANDOFF-R4** — (a) SEQ_REUSE generalizes to the
         any-kind issuance fork (receipt/WM collisions; the same-op
         cross-epoch RERECEIPT carve-out stays); (b) gap-free issuance
         (seq + justification persisted in ONE transaction, then
         deterministic sign — crash re-derives the identical artifact,
         no burned seqs, so back-stamps always collide and (a) converts
         collisions to proof). Vectors: WM's-own-seq back-stamp mints
         (revert-checked), crash-no-burn, RERECEIPT exemption, masher
         honest arm on the generalized detector. On Fable's re-review:
         the §3.7/§3.1 asterisk comes OFF and HANDOFF-R4 cites finding
         18 as closed. Rationale: 18(b) reshapes the issuance flow M7's
         daemon builds on — close it before scoping M7.
      3. Crypto backend swap per CRYPTO.md/NOTES 42 (PyNaCl, one-scheme
         rule, `aead_suite` parameter collapse) — scheduled with or
         after M7 at Harry's discretion; `uv` dependency consented.
      4. Backlog, explicitly non-gating: masher drives manager verbs +
         inline LOST_COMMIT assertions (NOTES 43); promise `issue_seq`
         (only if promise-ordering accusations are ever wanted); the
         M4 same-author-gap property stands recorded (NOTES 43).
      5. Next coordination artifact: **HANDOFF-R4 (M7 work order)** —
         designer-side, not yet written.

# Not yet built (by design, M2+)

QCs are *constructed and verified* (M0) but no acceptor, quorum client, floor,
watermark collection, gossip, roster activation, or compaction *flow* exists
yet — those are M2–M6. The fold already consumes a committed set as its
precondition (FORMAL's assume/guarantee seam), so M1 stands alone.
