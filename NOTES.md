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

13. **Checkpoint barrier is cut-relative, derive-and-verify.** The barrier sits
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

# Not yet built (by design, M2+)

QCs are *constructed and verified* (M0) but no acceptor, quorum client, floor,
watermark collection, gossip, roster activation, or compaction *flow* exists
yet — those are M2–M6. The fold already consumes a committed set as its
precondition (FORMAL's assume/guarantee seam), so M1 stands alone.
