# Triage table

Ranked. `Status`: **C** = confirmed by the synthesiser re-reading the code, **R** =
reported by the subsystem reviewer with file:line, not independently re-read, **U** =
explicitly unverified. See [README.md](README.md#verification-status-legend).

Detail for HIGH/MEDIUM items is in [THE-BAD.md](THE-BAD.md); hygiene items in
[THE-UGLY.md](THE-UGLY.md). Root-cause groupings in [ROOT-CAUSES.md](ROOT-CAUSES.md).

## HIGH

| ID | Status | RC | Site | Defect | Fix sketch |
|---|---|---|---|---|---|
| **K-1** | C | RC-3 | `daemon.py:385-401` | Roster activation checks no authorization on the op's author, no slot binding, and verifies the new half against the roster **the op itself declares** — a WRITE-certed client can self-ratify itself as the entire roster. Contradicts DESIGN §15. | Add `can_author_control(author, ROSTER)` + `slot_tag == roster_slot_tag(from_epoch)`; verify the new half against a roster the *old* epoch authorized, never `op.roster`. |
| **K-2** | C | RC-3 | `acceptor.py:417-434` | `on_roster_accept` takes `sync_frontier`/`new_epoch` from the wire request, never cross-checked against the op body; `op` isn't checked to be a `RosterOp`. Empty frontier ⇒ possession barrier vacuous. | Derive both from `op`; reject non-`RosterOp`; implement DESIGN §13's `from_epoch == current epoch` check. |
| **C-1** | ✅ **FIXED** `9916093` | RC-2 | `acceptor.py:229` + `daemon.py:333-336` | Void rule fires on `acc is None`, and `_adopt_one`'s `gc_checkpoint(overfull_drop())` deletes envelopes **without advancing the horizon** ⇒ durable slot amnesia ⇒ two QCs for one slot under pure crash faults, no evidence minted. | DONE: void only when the op is present AND below-horizon; envelope absence keeps the accepted op. Regression: `TestC1VoidOnMissingEnvelope`. See [FIXED.md](FIXED.md). |
| **C-2** | C | — | `acceptor.py:261-282` | `_skew_reason` runs *before* the idempotent-re-accept exemption, so a verbatim re-ACCEPT is refused `BELOW_FLOOR` after δ. Checkpoint/roster slots have no `attempt` escape ⇒ permanent deadlock, only clearable by a horizon advance that requires the blocked commit. | Move the floor gate below the `s.accepted_op == op.op_hash` exemption, matching the `BELOW_HORIZON` guard that already has it. |
| **F-1** | C | RC-1 | `client.py:592` | `_committed_ops` admits every control op unconditionally, so an **orphaned** checkpoint op (authored + stored before the drive, never QC'd) places a fold barrier ⇒ full-history and bootstrapped clients derive byte-divergent state from the same committed set. | Require a verified QC for `CheckpointOp` specifically; keep root-signed control ops self-authorizing. |
| **F-2** | ✅ **FIXED** `b4d9835` | RC-1 | `compactor.py:52` | `PrevState.of` calls "everything I hold below the cut" the retained set. An uncommitted op below the cut rewrites the next checkpoint's winners ⇒ a **committed value is permanently lost** and nodes adopt happily (digest matches the lie). | ~~Call the existing `store.baseline_commitment()` (`covered ∖ dead`)~~ DONE: `PrevState.of` masks by `tx.cut_dead()`. Regression: `TestF2RetainedExcludesDead`. See [FIXED.md](FIXED.md). |
| **F-3** | C | — | `compactor.py:74-85,149` | `cut_at` builds the cut only from held ops and never seeds from `prev_cut`, so an author whose entire below-cut set was GC'd vanishes ⇒ `cut_dominates` fails ⇒ **no further checkpoint is ever authored**. Mirror of the finding-11 possession wedge. | Seed the new cut from `prev_cut` — the cut is a per-author pin, not a recomputation from live holdings. |
| **IO-2** | C | RC-3 | `daemon.py:110` | The node daemon reloads its durable `epoch` from the DB but takes `roster` from `bootstrap.json` and only mutates it in memory. Post-restart after any roster change, epoch-N QCs verify against the epoch-0 roster ⇒ checkpoint adoption and roster activation both stall **permanently and silently**. Also violates CLI.md §7 (only `manager_pub` is trusted). | Derive the roster from the log (`fold.rosters_by_epoch`, as the client already does); treat `bootstrap.json` peers as address hints only. |
| **IO-3** | R | RC-4 | `daemon.py:448`, `client.py:546` | `run_periodic` catches only `StoreClosed`/`StoreBusy`; one malformed gossip `Delta` raises `CodecError`/`IndexError` and kills gossip + adoption + activation + fence observation + evidence detection forever, silently, while the node keeps serving. Client `_refresh_loop` same shape (catches only `OSError`) ⇒ silently regresses finding 22. | `except Exception` at the loop top + a logging story; add a liveness field to `status()`. |
| **IO-4** / K-7 | C | RC-4 | `wire.py:54-71`, `transports/unix.py` | No frame-size cap: a 4-byte length commits the node to buffering up to 4 GiB **pre-authentication**, with `buf += chunk` quadratic accumulation, no `settimeout` on accepted conns, unbounded thread per conn. `to_hint` (sold as "a DoS floor") runs *after* the frame is fully read. | Cap the frame length; `settimeout` on accept and dial; `bytearray` accumulation. |
| **IO-1** | R | — | `client.py:456-465` | `sync()` advances `_final_frontier` unconditionally, but `_pull_chain` bails silently on any op it can't fetch and never reports failure ⇒ `may_flip:false` on an answer that later flips. The advance is irreversible. CLIENT.md §2.1 violation. | Propagate pull failure; advance the frontier only over a hole-free chain. |
| **IO-5** | R | RC-1 | `client.py:627-628` | `_bootstrap_barrier`'s "I hold the full covered band" test checks only the *incremental* `dead` band (vacuously true when `dead == ∅`) ⇒ fold runs with no barrier and **no attempts sidecar** ⇒ per-key `attempt` silently resets toward 0, breaking the CLIENT.md §3 monotone fencing token. | Test against the full covered band / the checkpoint's `retained` commitment, not the incremental band. |
| **K-3** | R | RC-1 | `store.py:682-693` + `acceptor.py:312-318` | `put_receipt` is unverified and `_issue_receipt` serves stored receipts verbatim (the finding-17 idempotence rule) ⇒ gossip a forged receipt under a victim's pubkey and it serves the forgery forever. Ballots are enumerable, so poisoning ⌈n/2⌉ nodes makes a chosen op uncommittable. | Verify on `put_receipt`, or verify on serve-from-store before returning. |

## MEDIUM

| ID | Status | RC | Site | Defect |
|---|---|---|---|---|
| **C-3** | C | — | `acceptor.py:370` | `RERECEIPT` is **unreachable**: `on_rereceipt` exists but there is no `RereceiptReq`, no `NodeAPI` method, no wire tag, no caller. PROTOCOL §0's "every verb is idempotent, re-requests re-yield the same signed artifacts" and RESILIENCE §1.2 are currently false once the floor passes `op.hlc`. This is the escape hatch **C-2** needs. |
| **F-5** | C | RC-3 | `artifacts.py:393` | `slot_binding_ok` has **zero callers** in `dudefs/` or `tests/`, so `RosterOp.expected_slot_tag` is never enforced: two roster ops with body `from_epoch=0` but envelope tags `roster_slot_tag(0)`/`roster_slot_tag(9)` contend different slots, so B4's "at most one activates" doesn't bind. |
| **F-4** | C | — | `compactor.py:82` + `store.py:383` | `cut_at`'s tie-break is `o.seq > cur.seq` and `all_ops` is `SELECT raw FROM ops` with **no `ORDER BY`**. Forks are deliberately admitted, so two compactors (or one across a restart) pin a different `op_hash` ⇒ checkpoint bytes are arrival-order dependent. One-token fix: max on `(seq, op_hash)`. |
| **F-6** | C | RC-1 | `fold.py:84-97` | `keyring_from_wraps` does `masters[op.keyepoch] = k` with no authorization check on the `WRAP_SET` author and no ordering rule ⇒ last-wins by arrival order. (a) any signed author seals a bogus master ⇒ arrival-order-dependent divergence; (b) a non-32-byte payload makes `blake2b` raise permanently, re-run on every sync. |
| **F-7** | C | RC-1 | `client.py:635`, `gossip.py:65`, `store.py:495` | The retained projection is computed from raw holdings in three places. One uncommitted below-cut op ⇒ `verify_state_acc` raises ⇒ **every** `get`/`list`/`inspect` fails permanently. Nodes have `overfull_drop` as the remedy; clients have none. |
| **K-4** | R | RC-1 | `store.py:663-680` | `put_op_raw` doesn't verify, reached from gossip Delta baselines. A garbage-sig op planted at a victim's next `(author, seq)` makes `append` mint `ForkEvidence` and refuse the **genuine** signed op forever — that author's chain is censored on that node, and a fork "proof" against an honest author is persisted locally. |
| **K-5** | R | RC-1 | `store.py:729-740` | `put_qc` is `INSERT OR REPLACE`, unverified, and a first-class wire verb ⇒ a genuine QC can be overwritten with garbage, destroying the node's ability to prove finality (reads never reach `level=final`, adoption stalls). |
| **K-6** | C | — | `manager.py:292,364` | Every keyepoch's `K_epoch` is persisted as plaintext hex in `control.db`'s `meta`, and `ChainStore.__init__` does **no `chmod`** ⇒ ambient umask (typically 0644), while the root signing key is deliberately `0o600`. The file holding every group master is less protected than the key that signs. |
| **IO-13** | C | — | `workerapi.py:387` | The worker socket is bound with no `chmod(0o600)` and no umask guard, while CLIENT.md §1 and TRANSPORT.md §0 both make filesystem permissions **the whole worker-authorization boundary**. Under `umask 0o002`/`0o000` any local process can drive the key-holding daemon. |
| **IO-10** | C | — | `cli/node.py:54` | `dude node serve` never unlinks a stale socket, so a killed node cannot restart (`EADDRINUSE`). `cli/client.py:48` *does* unlink, so it's an asymmetry not a policy. The demo's restart scenario passes only because `tests/test_demo.py` unlinks on the test's behalf ⇒ the production path is untested **and** broken. |
| **IO-6** | R | — | `client.py:60` | `may_flip: bool = False` default ⇒ `may_flip:false` returned for `in-flight`, `unknown`, and `lost`, inverting CLIENT.md §2.1's `may_flip:false ⇔ final`. A golden test pins `STATUS` on an unknown op returning `may_flip:false`. |
| **IO-7** | R | — | `client.py:786` | `INSPECT` returns `may_flip:false` for an absent key whenever nothing pending is held locally, and `inspect` never syncs ⇒ a fresh/restarted daemon answers "absent, will never change" for a key committed and final elsewhere. |
| **IO-8** | R | — | `workerapi.py:374-385` | Requests on one worker connection are strictly serialized (`for line in rf:` → dispatch → reply → read), contradicting CLIENT.md §1's "any number of requests in flight per connection / nothing blocks". One `GET level=final` against a parked quorum blocks everything pipelined behind it for seconds. No test covers concurrency on one connection. |
| **IO-11** | R | RC-4 | `wire.py:102-127`, `gossip.py:121,180` | Arity-free decoding: `p[1]`/`p[3]`/`p[5]` indexed with no `as_seq(v, n)` ⇒ `IndexError`, which is not in the `DudeFSError` tree and isn't caught by `daemon.serve`. `codec.as_seq` was built for this and just isn't used here; `lmsg` gets it right. |
| **IO-12** | R | RC-4 | `transports/http.py:32,35,45` | Unbounded `resp.read()`; `int(Content-Length)` raises `ValueError` on a bad header; `dial` catches only `OSError` while `http.client` raises `HTTPException` (not an `OSError`) ⇒ escapes the carrier contract and kills the caller's thread. |
| **IO-14** | R | RC-1 | `client.py:528-536` | `_pull_baseline` takes the first non-empty baseline and `put_op_raw`s every op with no signature check, no `covered(op, cut)` check, and no check against the `retained` commitment — and the client has **no purge path**, so one polluted pull makes `verify_state_acc` raise on every read forever. |
| **IO-15** | R | — | `workerapi.py:264,279` | `level` is unvalidated and passed through as a string compared `== "final"` ⇒ `"FINAL"`/`"finall"` silently downgrades to a cached local read. CLIENT.md §2.1: "the system never trades consistency silently; it labels." |
| **IO-16** | R | — | `workerapi.py:335-372` | JSON-RPC 2.0 gaps: a failing **notification** gets an error reply with `"id":null` (spec-forbidden, and it desynchronizes a pipelining client); empty batch returns nothing instead of `-32600`; `"jsonrpc"` member never validated; `id` type unvalidated. |
| **IO-17** | R | — | `client.py:324` | A missing keyring (post-rotate, pre-wrap-gossip) surfaces as `-32602 invalid params: 0` — a daemon-side key-distribution condition blamed on the worker's request. The broad `except (KeyError, ValueError, TypeError)` also masks genuine internal bugs as caller error. |
| **IO-18** | R | — | `client.py:167,371`, `workerapi.py:399` | One thread per submit, per quorum send, per accepted connection — no pool, no cap, no join ⇒ a CAS storm or slow peer accumulates threads without limit. |
| **IO-19** | R | — | `client.py:389,391` | `_lost`/`_exhausted` mutated off-lock from drive threads while read under `self._lock` — benign under the GIL, but an undocumented deviation from the stated lock discipline. |
| **C-4** | R | — | `client.py:230` vs `quorum.py:388` | `QuorumConfig.horizon` is never set from `tx.get_horizon()`, so the below-horizon promise guard (normative in PROTOCOL §1.3 step 3) is **dead code in production** — only tests pass a real horizon. `Promise.accepted_hlc` is wired end-to-end purely to feed it. |
| **C-5** | R | RC-1 | `store.py:663`, `store.py:352-380` | `put_op_raw` skips `append`'s `(author, seq)` collision check ⇒ fork siblings coexist with **no `ForkEvidence` minted**; and `heads()` picks whichever sibling sqlite yields first (unspecified tie order) ⇒ two nodes sign **different** `head_hash` in their `FrontierBundle` ⇒ possession barrier fails unrepairably. |
| **F-8** | R | — | `checkpoint.py:91-97`, `compactor.py:112` | Candidate selection among equal seqs is by store arrival order (`setdefault`, strict `>`). FORMAL B6 admits duplicate same-slot QCs under one Byzantine node, and `qc_final` checks majority not uniqueness ⇒ two honest nodes adopt different checkpoints at one seq ⇒ different cuts/GC. A lowest-`op_hash` tie-break costs nothing. |

## LOW

| ID | Status | Site | Defect |
|---|---|---|---|
| **F-9** | R | `fold.py:556-562` | Stages assume each cut dominates the previous; incomparable cuts re-stage the walk out of `(hlc, author, seq, op_hash)` order. Dominance is checked node-side and author-side, never fold-side. |
| **F-10** | R | `store.py:785-795` | Node GC drops ops + receipts + QCs for dead hashes, but `detect_double_votes` needs both envelopes *and* both receipts ⇒ detect-and-punish is best-effort for below-cut slots. §12's "detection never races GC" argument covers value audit, not a slot loser's envelope+receipt pair. |
| **F-11** | U | `compactor.py:328` | Retains all control ops but only winner data ops ⇒ a mixed-class author leaves gaps breaking bootstrap prev-validation. Currently unreachable (`manager._CAP_FOR` hands out disjoint caps) — a latent invariant. |
| **F-12** | R | `compactor.py:331` | `[universe[h] for h in keep if h in universe]` silently drops a missing winner ⇒ a checkpoint whose `retained` omits a live key while `state_acc` claims it: unbootstrappable, unadoptable, silent. §12 wants a loud assertion. |
| **C-6** | R | `quorum.py:419-442,131` | `Rejected` is ignored on the ACCEPT path (not added to `_blocked`) ⇒ a unanimously-rejecting quorum burns `MAX_ROUNDS × ROUND_TIMEOUT` then reports `EXHAUSTED`. `CommitFailure.UNREACHABLE` is never constructed anywhere. |
| **C-7** | R | `store.py:440-446` | `get_qc`'s `ORDER BY ballot DESC` is a BLOB memcmp over bencode, so round 10 sorts below round 1 — deterministic but not highest-ballot, contrary to its own comment. Impact nil today. |
| **C-8** | R | `store.py:322` | `issuance` has no `UNIQUE(kind, ident)`; the one-artifact-per-`(kind,ident)` invariant `SEQ_REUSE` rests on is enforced only by a `SELECT`. Proof stays sound today; cheap to pin in the schema. |
| **C-9** | R | `acceptor.py:265` | `on_accept` admits any `ballot >= promised`, so a proposer skipping PREPARE can get two QCs at one slot. **Matches DESIGN §8 verbatim** and RESILIENCE §3.4 accepts it — recorded as a conscious-ruling request, not a defect. |
| **K-8** | R | `client.py:495-500` | `_pull_chain` stores a fetched op without checking `fetched.op_hash == h` or `verify_sig()` ⇒ a malicious node steers a client's chain walk. |
| **K-9** | R | `codec.py:164-176,205` | Hostile input raises untyped exceptions: `b'l'*2000 + b'e'*2000` → `RecursionError`; a 5000-digit int → `ValueError: Exceeds the limit (4300 digits)`. Neither is a `CodecError`, contradicting the module's contract; neither is caught pre-auth. **No canonicity/injectivity break found.** |
| **K-10** | R | `artifacts.py:1417,1512,1733,1785` | Node-signed artifacts carry no domain tag; separation rests on bencode shape + arity. No collision today (checked pairwise), but a future artifact shaped `[bytes,int,list,int]` is a silent receipt transplant. `lmsg`/PoP *do* use prefixes. |
| **K-11** | R | `artifacts.py:1512` | `promise_message` omits `config_epoch`, unlike receipt/watermark ⇒ a promise is valid in every epoch. Not exploitable live (promises counted only for the current round) but promises are documented as portable evidence. |
| **K-12a** | R | `crypto.py:468-475` | `open` reads the nonce from the blob instead of recomputing `_nonce(k, aad, pt)` ⇒ `xcs1` is not the committing/deterministic AEAD CRYPTO.md §2 describes. Doc drift; a key holder can mint many `op_hash`es per plaintext. |
| **K-12b** | C | `artifacts.py:934-937` | `RosterOp` validates odd + non-empty but **not unique** members ⇒ `roster=[k,k,k]` lets one key occupy three bitmap indices and satisfy `QC.verify`'s majority alone. The cheapest route to K-1's new-roster half. |
| **K-12c** | R | `crypto.py:303-309` | `bitmap_indices` indexes `bitmap[i>>3]` with no length check; guarded at the one caller, latent only. |
| **IO-20** | R | `cli/_util.py:41` | `json.loads(b"")` on daemon silence gives `JSONDecodeError`; the JSON-RPC `code` is discarded into a generic `RuntimeError`, flattened by `cli/main.py:33` alongside genuine bugs. |
| **IO-21** | R | `client.py:708-715` | At `level="final"` an absent key is labelled `tier: "local"` (gated on `present`), under-claiming the finality the caller paid a quorum sync for. |
| **IO-22** | R | `client.py:645-658` | Every `GET`/`LIST`/`INSPECT`/`STATUS` re-folds the entire history under two locks, serializing all readers — O(history) CPU where CLIENT.md §1 sells "state the daemon already holds". |
| **IO-23** | R | `wire.py:64-71` | `buf += chunk` is quadratic; `bytearray` is the same code length. |
| **IO-24** | R | `workerapi.py:401-404` | `close()` neither unlinks the socket path nor closes live connections; only `daemon=True` saves it at exit. |
| **IO-9** | R | `client.py:691` | `STATUS` on an unknown op_hash reports `in-flight` — a typo'd ticket is indistinguishable from a genuine in-flight op, so the worker polls forever. The ladder has an honest `unknown` state. |

## Test-suite gaps (A-*)

Detail in [THE-BAD.md §6](THE-BAD.md#6-test-coverage-that-would-let-the-above-ship-green);
vacuous-assertion inventory in [THE-UGLY.md §4](THE-UGLY.md#4-vacuous-and-tautological-tests).

| ID | Status | Site | Gap |
|---|---|---|---|
| **A3** | C | `daemon.py:409,450` | **`FLOOR_PERJURY` can never fire in production** — `run_periodic` calls `sync_once()` with no args, so `wms` is always `[]`. The watermark-collision half of `SEQ_REUSE` is equally dead. B3 accountability is test-only, contradicting the README's "sound **and** complete". |
| **A4** | C | `store.py:865` | **`LOST_COMMIT` has zero production callers.** `evidence_cycle` runs three detectors, not this one. A mistaken recovery destroys committed data with no disclosure record. |
| **A5** | R | `store.py:149,178,219,261,294` | Every evidence `verify()` is positive-only (20 `assertTrue`, 1 `assertFalse`). Delete `FloorPerjuryEvidence.verify`'s ordering clause — the entire content of finding 17 — and **no test fails**, yet any honest node becomes convictable. |
| **A1** | C | `acceptor.py:417-434` | The possession barrier is never tested with a *lying* requester; every test passes a truthful `sync_frontier`. Enables **K-2**. |
| **A2** | C | `daemon.py:387-401` | Roster activation is only ever tested with **manager-authored** ops, so the missing authz check is structurally invisible. Enables **K-1**. |
| **A6** | R | `test_fumbling.py:270-320` | The "button masher" adversarial arm is **inert**: distinct client fingerprints mean the equivocator can never present a duplicate ballot, so the double-vote loop iterates zero times and the real assertions are skipped on ~40% of seeds. Faults are all zero. |
| **A7** | R | `quorum.py:443-455` | The reply-authentication conjuncts have **no negative tests**; the fault carrier never models Byzantine content. Drop `r.signer == roster[node]` and one lying node forges a full QC — suite stays green. `Receipt`/`Promise`/`FrontierBundle.verify` also have zero negative tests. |
| **A8** | R | `artifacts.py:461-467` | `Op.verify_structure()` would pass as `return True`. No test builds `seq < 0`, `len(prev) != 32`, or `seq == 0 and prev != GENESIS_PREV`. |
| **A19** | R | `checkpoint.py:117-131` | `overfull_drop()` has **zero references in `tests/`** yet deletes ops in production (this is **C-1**'s trigger). `select()`'s jump/defer branches and `forward()`'s horizon clause are untested. |
| **A12** | R | `daemon.py:337-343` | The finding-19 "adopt + GC + pin in ONE txn survives crash-restart" claim has no daemon-level crash test; every daemon in the suite is `":memory:"`. |
| **A18** | R | `daemon.py:443` | Peer-gate **revocation** untested — a revoked client remaining admitted would ship. |
| A9-A11, A13-A17, A20-A31 | R | various | Vacuous / tautological / test-local-reimplementation assertions — see [THE-UGLY.md §4](THE-UGLY.md#4-vacuous-and-tautological-tests). |

## Hygiene / drift / debt

See [THE-UGLY.md](THE-UGLY.md): **H-1 … H-10** (structural debt, code that lies about the
code) and **B-1 … B-31** (documentation drift).

Two drift items are load-bearing rather than cosmetic:

- **B9** — CLI.md's claim that the founding roster is on-chain and "never a seeded list to
  be trusted" is false (`roster_seed` is local meta; `bootstrap.json` ships roster pubkeys).
  This is the doc-level face of **IO-2**.
- **B13** — ARCHITECTURE.md's L6 `PayloadHandler` layer, which it calls "the load-bearing
  pattern" and which grounds the zero-knowledge argument, **no longer exists** (no registry,
  zero grep hits). The property still holds, but by type narrowing rather than by build
  composition, so the argument needs rewriting rather than renaming. Relatedly, the stated
  L6-purity rationale is what justifies **K-2**'s vulnerable design.
