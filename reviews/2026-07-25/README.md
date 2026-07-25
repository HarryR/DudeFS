# DudeFS external review — 2026-07-25

A fresh-eyes review of the whole tree, run while the `Heads`/`HeadEntry` type-hygiene
refactor was still in flight. Read-only: no tests were run, no typecheck, no edits.

## Scope

| | |
|---|---|
| Commit reviewed | `6e4427e` (+ the then-uncommitted `Heads`/`HeadEntry` retype) |
| Re-checked against | `7a403d4` — three refactor commits (`882cfad`, `7c5648a`, `7a403d4`) landed while this was being written; every **C**-status finding was re-verified against them and none were fixed. `H-1`/`H-2` gained notes. |
| Production code | ~9.4k lines, 20 modules in `dudefs/` |
| Tests | ~13k lines in `tests/` |
| Docs | ~578 KB of markdown (larger than the production source) |
| Reviewers | 5 independent subsystem readers + a synthesis pass |

Subsystem split: consensus core (`quorum`/`acceptor`/`store`/`node`/`wire`) ·
crypto & wire auth (`crypto`/`lmsg`/`codec` + the crypto parts of `artifacts`) ·
I/O edges (`daemon`/`client`/`workerapi`/`gossip`/`transports`/`cli`) ·
state derivation & compaction (`fold`/`compactor`/`checkpoint`/`manager`) ·
test-suite quality & doc fidelity.

The design documents were treated as normative throughout, per IMPLEMENTATION.md
("if code and documents disagree, the documents win"), so code-vs-doc drift is
recorded as a finding rather than as a doc update.

## How to read this

| File | What's in it |
|---|---|
| [TRIAGE.md](TRIAGE.md) | **Start here.** Every finding, one line each, ranked, with fix sketch. |
| [THE-BAD.md](THE-BAD.md) | The real defects in full: mechanism + concrete failure scenario. |
| [THE-UGLY.md](THE-UGLY.md) | Hygiene, doc drift, structural debt, supply chain. Nothing here breaks; all of it costs. |
| [THE-GOOD.md](THE-GOOD.md) | What is genuinely solid — specific, not flattery. Read this before acting on the rest. |
| [ROOT-CAUSES.md](ROOT-CAUSES.md) | The four patterns that generate most of the findings. **This is the actual work-plan.** |
| [FIXED.md](FIXED.md) | Fix log, maintained as findings are closed (not part of the original review). |
| [FIX-REVIEW.md](FIX-REVIEW.md) | Read-only review of fix wave 1: **1 of 4 fully closed**, C-1 regressed, C-2 unfixed + **self-convicting (FIX-6)**, F-2 partial. Contains a marked **correction** of one of my own recommendations. |
| [DESIGN-FINDINGS.md](DESIGN-FINDINGS.md) | Structural findings the wave surfaced: request→reply binding (**K-13**), the Promise's redundant signature (**K-14**), unbounded `slot_state` (**D-1**), and two new root causes (**RC-5**, **RC-6**). |
| [DIRECTIONS.md](DIRECTIONS.md) | **How** to fix, ratified by Harry: RC-1 as a *type* (**D-A**), acceptor named-predicate decomposition (**D-B**), Promise demoted to a response payload (**D-C**). Hierarchy over local patch; construction over enumeration. |

## Verification status legend

Every finding carries one of:

- **CONFIRMED** — the synthesiser re-read the cited code and verified each link in the
  chain personally. No repro was executed (the review was read-only), so "confirmed"
  means *the mechanism is present in the code as described*, not *observed failing*.
- **REPORTED** — the subsystem reviewer verified it against the code and cited
  file:line; the synthesiser did not independently re-read it. Treat as high-confidence
  but re-check before acting.
- **UNVERIFIED** — flagged as a suspicion by the reviewer, explicitly not established.

Nothing in here was accepted on plausibility alone; each reviewer was instructed to
check whether another code path already prevents the issue before reporting it, and
several candidate findings were dropped that way.

## Headline verdict

The protocol implementation is careful, and the parts that were hardest to get right
are largely right: the evidence system, the durability discipline, the canonical codec,
the key hierarchy, the fold's determinism core. No reviewer could construct an
honest-node conviction for any of the five evidence kinds, and no injectivity or
canonicity break was constructible in the codec.

The defects cluster in two places instead:

1. **Seams between individually-careful subsystems.** Both consensus HIGHs live in an
   *interaction* — envelope GC versus slot-state lifetime, and the floor gate versus
   re-proposal idempotency — not in sloppiness within either side.
2. **The roster/epoch path never received the rigor the checkpoint path did.** The
   checkpoint adopt path has `slot_bound` + `minter_authorized` + `qc_final`. The roster
   activation path has none of the three, and the highest-severity finding in this
   review is the direct consequence.

One finding is a privilege escalation reachable by an ordinary WRITE-certed client
(**K-1**), which contradicts an explicit DESIGN §15 guarantee. Two are safety/liveness
defects reachable under pure crash faults (**C-1**, **C-2**). Those three are the ones
that warrant action before anything else in this document.

## Caveat on the in-flight refactor

The working tree held a partially-landed `Heads = dict[bytes, HeadEntry]` retype with
~49 trailing type diagnostics in `tests/` and `checkpoint.py`/`compactor.py`. Those were
excluded from findings as known-transient. Two observations *about* the refactor that
outlive it are recorded in [THE-UGLY.md](THE-UGLY.md) (H-9, H-10).

## Independent corroboration

Three of the five reviewers found the roster-activation hole independently, from three
different angles — authorization (**K-1**), slot binding (**F-5**), and test coverage
(**A1/A2**). None of them saw each other's output. That convergence is the strongest signal
in this review, and it is why the roster path leads the work-plan.

## Two claims in the project's own documentation that this review contradicts

Recorded plainly because they are load-bearing marketing claims, not incidental:

1. **README:** *"All five evidence kinds are sound **and** complete."* Soundness holds —
   no reviewer could construct an honest-node conviction. **Completeness does not:**
   `FLOOR_PERJURY` can never fire in production (**A3**) and `LOST_COMMIT` has zero
   production callers (**A4**).
2. **DESIGN §15:** *"compactor compromise can mint wrongful-but-auditable checkpoints,
   **never roster or cert changes**."* An ordinary `Cap.WRITE`-certed client can currently
   seize the roster (**K-1**).

## All five reviews are recorded

| Subsystem | Findings |
|---|---|
| Consensus core | C-1 … C-9 |
| Crypto & wire auth | K-1 … K-12 |
| I/O edges & daemons | IO-1 … IO-24 |
| Fold & compaction | F-1 … F-12 |
| Test suite | A-1 … A-31 |
| Doc fidelity | B-1 … B-31 |
| Structure & hygiene (synthesis pass) | H-1 … H-10 |
