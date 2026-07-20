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

# Not yet built (by design, M2+)

QCs are *constructed and verified* (M0) but no acceptor, quorum client, floor,
watermark collection, gossip, roster activation, or compaction *flow* exists
yet — those are M2–M6. The fold already consumes a committed set as its
precondition (FORMAL's assume/guarantee seam), so M1 stands alone.
