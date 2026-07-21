# DudeFS Implementation Plan — Python 3 proof of concept

> **Status:** the hand-off plan for an implementing agent. Normative sources: [DESIGN.md](DESIGN.md) (rev 6) · [PROTOCOL.md](PROTOCOL.md) · [ARCHITECTURE.md](ARCHITECTURE.md) · [MANAGER.md](MANAGER.md). Verification targets: [FORMAL.md](FORMAL.md). **If code and documents disagree, the documents win — or the discrepancy is raised as a doc change, never silently coded around.**
>
> Goal: a working single-machine (then LAN) proof of concept exercising the *entire kernel* — fold, slots+ballots, finality, gossip, roster change, compaction — at n ∈ {1,3,5}, while discovering how small the state machine really is.

## 0. Ground rules

- **Python ≥ 3.12** (bumped from 3.11 per NOTES item 11 — PEP 695 `type` aliases and `typing.Self` are in use). Runtime is **stdlib-only plus exactly one vendored file** (`ed25519.py`, below). Dev/test dependencies (`pytest`, `hypothesis`) are permitted — they never ship in the runtime path.
- The kernel (L1 artifacts, L3 acceptor, L5 fold, L6 handlers) is **pure and synchronous** — no I/O, no clocks, no randomness inside; time and entropy are injected (`Clock`, `Rng` params). `asyncio` appears only at the edges (transports, daemon). This is what makes the simulation harness (§6) and the FORMAL mapping possible.
- Every FORMAL hypothesis gets a test carrying its id in the name (`test_A2_lineage_advance_...`, `test_B1_slot_safety_...`). Golden vectors are committed to the repo.
- Docstrings cite doc sections (`# DESIGN §6 step 3`). Terminology matches the docs exactly: worker / client node / storage node, accepted / committed / final.

## 1. Crypto decisions (L0)

| Primitive | v1 choice | Notes |
|---|---|---|
| `Hash` | `hashlib.blake2b(digest_size=32)` | Content addressing everywhere. |
| `Signer` (authors) | **Ed25519** — vendored single-file RFC 8032 implementation | Pure Python, ~350 LOC. *Not constant-time; POC-only* — flagged in the file header. |
| `MultiSig` (receipts/QC) | **Ed25519 signature list + signer bitmap** | The DESIGN §8 list instantiation. Same vendored file. No PoP needed (aggregation-only concern). |
| `PRF` (slot tags) | `blake2b(key=slot_secret, person=b"dude.tag")` | Keyed BLAKE2 is stdlib and is a designed PRF/MAC. Tags stay PRF'd in **all** payload suites. |
| `AEAD` | staged — see below | Behind the L0 interface from day one. |

**AEAD staging** (per-`keyepoch` suites make migration = key rotation, DESIGN §16):

- **Suite `auth0` (launch):** authenticated-unencrypted. `ct = pt`; `tag = blake2b(key=blake2b(key=K, person=b"dude.mac", data=nonce).digest()[:32], data=len(aad)‖aad‖len(ct)‖ct, digest_size=32)`. **Zero-knowledge is suspended — loudly**: `dude status` and the README banner must say so. Every other property (provenance, durability, CAS, finality, detect-and-punish) is exercised for real.
- **Suite `b2s1` (the "bastard sponge", later):** encrypt-then-MAC from keyed BLAKE2 — `ek = blake2b(key=K, person=b"dude.enc", data=nonce)`; keystream blocks `blake2b(key=ek, person=b"dude.ks", data=le64(i))`; XOR; MAC as in `auth0` with an independent subkey. Honest caveat: a home-rolled composition of a solid PRF — fine for a POC, but before any *real* confidentiality claim, prefer:
- **Suite `xcp1` (alternative):** vendored single-file pure-Python ChaCha20-Poly1305 — same vendoring posture as Ed25519 if/when wanted.
- **Production ruling (2026-07-21, amended — the one-scheme rule):** the staging above is now **dev scaffolding only**; see [CRYPTO.md](CRYPTO.md) (NOTES 42 as amended). v1 ships exactly ONE payload scheme — `xcs1` (XChaCha20-Poly1305, SIV-derived nonce, PyNaCl as the single `uv`-managed crypto dependency; vendored code retained as the differential oracle) — plus `sbx1` sealed-box wraps and Ed25519 signatures (BLS12-381 declined-with-door-open; FROST is the threshold-root path). **No suite menu, no wire selector**: scheme change = lane-2 `pver` fence + rotation. `b2s1`/`xcp1` are struck; `auth0` never ships.

## 2. Encoding decisions (L1)

- **Canonical codec: deterministic bencode-style.** Four types only — `int` (`i…e`), `bytes` (`len:raw`), `list` (`l…e`), `dict` (`d…e`, byte-string keys, **strictly sorted, unique**). No floats, no bools (use ints), no strings (use bytes; UTF-8 by convention where human-readable). Properties required by FORMAL §1 and PROTOCOL §5: **injective** (length-prefixed throughout) and **canonical** (one encoding per value — sorted keys, minimal ints). ~120 LOC including the decoder that *rejects* non-canonical input.
- **Identity = received bytes.** `op_hash = blake2b(bytes-as-received)`; artifacts are stored and re-served as raw bytes, never re-serialized (ARCHITECTURE L1).
- **Artifact schemas:** field-for-field from DESIGN §5 (envelope), §8 (receipt: `op_hash ‖ config_epoch ‖ ballot ‖ issue_seq` — the per-signer issuance chain, NOTES 43; QC: `{op_hash, config_epoch, ballot, signer_bitmap, issue_seqs, sigs}` — the QC carries the per-signer seq list parallel to `sigs`, because each receipt's signature covers its `issue_seq` and QC verification reconstructs each signer's message), §9/PROTOCOL §1 (frontier bundle: `heads ‖ checkpoint_head ‖ config_epoch ‖ floor`, one signature), §12 DESIGN (checkpoint: `cut, state_root, dead, retained, attempts` — rev 6), PROTOCOL §7.1 (endpoint record). Ballot = `(round:int, priority:bytes)` with `priority = h(slot_tag ‖ client_fp)` (DESIGN §8, NOTES 24d), ordered lexicographically; `hlc = (wall_ms:int, counter:int)`. Exact layouts live in `artifacts.py` + golden vectors, not re-specified here.
- **Slot preimage encoding** (PRF input): `key ‖ version ‖ attempt` as a bencoded 3-list (injective by construction); `version = ⊥` is the empty byte string.
- **Cluster wire framing:** 4-byte big-endian length + bencoded message. **Worker API:** JSON-lines over a Unix socket (crosses no trust boundary — PROTOCOL §6).

## 3. Storage decision (L2)

**`sqlite3`** (stdlib) — one database per storage node and per client-node cache. Tables: `ops` (raw bytes, indexed by hash and `(author, seq)`), `receipts`, `qcs`, `slot_state (tag PRIMARY KEY, promised, accepted_ballot, accepted_op)`, `floor (singleton)`, `control_state`, `evidence`, `meta`. **Sign-after-fsync = sign after `COMMIT`**: the transaction that records an acceptance/floor-advance completes before the signature leaves the process (RESILIENCE §0). One DB = one durability domain, exactly as DESIGN §8 requires.

## 4. Module layout (mirrors ARCHITECTURE 1:1)

```
dudefs/
  crypto.py        # L0 interfaces + suite registry
  vendor/ed25519.py
  codec.py         # L1 canonical bencode
  artifacts.py     # L1 typed artifacts + self-verification
  store.py         # L2 sqlite ChainStore + floor
  gossip.py        # L2 summary/delta/eager-push
  acceptor.py      # L3 per-slot state machine
  quorum.py        # L4 fan-out, hedging, QC assembly, finality
  fold.py          # L5 full profile + control reducer
  handlers/
    control.py     # roster / cert / checkpoint (both profiles)
    data.py        # txn: preimage, guards, mutations (client only)
  node.py          # storage-node assembly (L0–L3 + control handlers)
  client.py        # client-node assembly (L0–L6, daemon)
  workerapi.py     # L7 unix-socket JSON-lines server
  cli.py           # `dude` — client + manager commands (MANAGER.md)
  transports/
    memory.py      # simulated network w/ fault injection (first!)
    tcp.py         # length-prefixed frames over asyncio TCP
  sim/harness.py   # deterministic multi-node simulation, seeded chaos
```

## 5. Milestones (each ends green; order is load-bearing)

- **M0 — codec + crypto.** Golden vectors; `decode(encode(x)) == x`; non-canonical inputs rejected; distinct values → distinct bytes (fuzz); RFC 8032 test vectors pass.
- **M1 — the fold** (before any networking — it's pure and it's the hardest logic). `fold.py` + both handlers against hand-built committed sets: forks, undecryptable ops, cross-epoch tags, guard-only slots, tombstones. **A1–A7 as hypothesis-driven property tests** — A1 is shuffle-invariance; A2 is the lineage-advance invariant under adversarial op soups. The Python fold is the de-facto reference oracle until Lean exists (FORMAL §5).
- **M2 — node kernel.** `store.py` + `acceptor.py` + floors. B1 unit scenarios (double-vote refusal, promise/accept ordering, conflict reporting); floor monotonicity across process kill/reopen; contiguity enforcement.
- **M3 — quorum client + simulation harness.** Read **NOTES.md §M2.5 first** — it records post-M2 semantic rulings (cut-relative barrier, universal lineage-advance, fail-closed `pver` fence, accept-time `deps`) that M3+ code must respect. **The quorum client is written sans-I/O**: a pure `(event in) → (commands out)` state machine behind a `NodeAPI` Protocol (the PROTOCOL §1 verbs as typed methods) — no sockets, no clocks; hedging schedules computed from injected `now`/`δ_hedge`. Unit-test the §1.3 rules (MUST re-propose the highest accepted op; conflict → recovery; hedge, don't blast) against scripted adversarial node responses before any transport exists. Then `transports/memory.py` (a separately-tested fault-injecting carrier: seeded loss/dup/reorder/delay) and `sim/harness.py` (composition only: deterministic scheduler + continuous B1/B2/B3 assertions; failures replay from seed; **emit protocol transition logs from day one** — the FORMAL §5 trace-validation seam). End-to-end CAS at n=3: 1-RTT happy path, contention → exactly one winner, split-vote → recovery ballots converge (the rev-1 deadlock as a *regression test*), finality wait, verdict correctness. Discipline for M3–M6: **one new Protocol seam per milestone; only the sim harness composes ≥3 layers** — every rule the chaos monkey could catch must have a smaller home where it is caught first.
- **M4 — gossip + relay.** `summary()`/`delta()` as pure functions over two `ChainStore`s (convergence = a fixpoint of pairwise merges — property-testable with no network); convergence on random *connected* partial meshes; single-push writes; upgrade the M2 `unknown_dep` reject to PULL-then-accept (PROTOCOL §2.1); **the §7.3 property as a test**: linearizable read through exactly one reachable node via relayed signed frontier bundles.
- **M5 — control plane.** Certs, fold-positional revocation, roster 1→3→5 with possession barrier + learner catch-up, the public roster slot (two competing managers → one activation — B4), `RERECEIPT` across the epoch bridge (B5), **delegated capabilities including the `compact` compactor cert** (now load-bearing — DESIGN §12/§15, NOTES 29f).
- **M6 — compaction (log-compaction, DESIGN §12 rev 6 — no snapshot blob).** Checkpoint mint from an incremental fold: dead-set computation honoring the **resurrection mask**, per-author `retained (count, digest)` commitment, encrypted `attempts` sidecar. Lazy GC: dead ops, receipts/QCs ≤ cut, slot-state **void rule** on `prepare` (the NOTES 27 reborn-tag livelock as a regression test). Sparse below-cut `PULL` + `SUMMARY` retained digests. **Retained-bootstrap ≡ full-history fold** (A4 as an integration test — including the resurrection vector and the attempts-sidecar vector, each of which must fail if its mechanism is removed), tombstone death at the barrier, receipt floor at the horizon.
- **M7 — daemon + CLI + demo.** Worker API over the socket; `dude init/cert/node/status/get/set/cas`; **the demo**: 3 nodes + 2 client nodes on localhost, `kill -9` any one node mid-CAS-storm, nothing breaks; wipe a node's disk, watch identity retirement + learner re-add.
- **M8 — stretch.** TCP transport (proving transport pluggability); live suite rotation `auth0 → b2s1` via keyepoch bump (the encryption-later demo); evidence collection + `dude evidence eject` from a deliberately double-voting node build.

## 6. Test strategy

1. **Golden vectors** (M0) — freeze the wire.
2. **Property tests** — every A-hypothesis, via `hypothesis` strategies generating committed-set soups (including garbage, forks, stale tags).
3. **Simulation chaos** — the monkey as a pytest fixture: seeded schedules over `memory.py`; every RESILIENCE §1.2 crash-point row becomes a scenario; every B-hypothesis an assertion checked continuously during simulation. Failures replay from the seed.
4. **Adversarial builds** — small subclass overrides creating an equivocating acceptor, a floor perjurer, a time-traveller client, an amnesiac manager (RESILIENCE §3's personas as first-class sim-node subclasses); assert containment **and evidence generation** (RESILIENCE §3.1's table as tests). Evidence minting for `DOUBLE_VOTE` (two receipts at one `(tag, ballot)` for different ops) and `FLOOR_PERJURY` (a watermark plus a later receipt beneath it) lands *with* these personas — they are its only honest generators; until then B6's "every violation mints a portable proof" is claimed for those kinds, not asserted (NOTES 34). Split-view detection (RESILIENCE §3.5) is testable with existing machinery: two victims fed divergent manager chains and then merged must mint `FORK` evidence at the divergence seq.
5. **The false-rejection matrix (standing rule — NOTES 33/34).** Beside every "invalid input → rejected" test, a paired "boundary-valid input → ACCEPTED" test. The R1 bug class was uniformly *over-strict gates rejecting valid messages* (cut-unaware `heads`/`append`/`verify_baseline`/`holds_frontier`, the FETCH-window abort), and reject-side-only testing is structurally blind to it — a gate that rejects everything passes every reject-side test. Boundary cases get priority: at-the-cut, at-the-horizon (`hlc == F`), at-the-floor, first-op-above-the-barrier.
6. **A4 as a property test** — beyond the hand-built vectors: a seeded random-chain fuzz (N ops of random multi-key set/del/CAS across K keys, compact at a random final cut, assert `fold(full) ≡ bootstrap(retained ∘ tail)` byte-for-byte). The resurrection-mask fixpoint bug was a *class*; a point vector catches one member.
7. **The found-and-fixed log (standing rule — NOTES 39).** Every finding that survives verification lands in the repo as a **regression test** before the finding is closed — a reviewer's scratchpad reproducer is promoted into the suite, never left in session-local memory. The test cites its NOTES item (name or docstring), the NOTES item records the vector, and the pair cross-references: the suite is the executable found-and-fixed log, NOTES is its rationale. Where the bug was a *class* (a generator blind spot let it through), the fix also patches the generator arm and the revert-check is performed once — revert the fix, watch the new arm catch it — so the log proves the coverage, not just the fix.

## 7. Kernel census (how small is the state machine?)

Durable node state: identity key · epoch + control view · **one floor** · per-tag `(promised, accepted_ballot, accepted_op)` · append-only artifact tables. Transitions: `on_submit / on_prepare / on_accept / advance_floor / gossip_merge / gc_at_checkpoint` — **six**. Estimated kernel: acceptor ~100 LOC, floor ~30, fold ~400, handlers ~250, codec ~120, store ~250, gossip ~200, crypto glue ~120 (+350 vendored) — **a kernel under ~1.5k LOC**, POC total ~4–5k with daemon, CLI, and sim harness. If it grows materially beyond that, something is wrong with the code or with the documents — find out which.

## 8. Non-goals for the POC

BLS12-381 (lane-3 later) · SSH/XMPP transports (interface proven by `memory` + `tcp`) · `WATCH` (does not exist — **no stubs anywhere**, NOTES 51; watch *semantics* stays a §17 design question) · HSM · packaging polish. (Historical entries removed as executed: `auth0` died with the crypto swap; pure-Python Ed25519 died with PyNaCl.)

## 9. Runbook target (the definition of done)

```
$ dude init --root ./cluster            # genesis, root key, n=1
$ dude node spawn --listen tcp:...      # ×3, learner-add + promote to n=3
$ dude cert issue --client worker-a.pub
$ dudefs-client --socket /run/dude.sock &
$ echo '{"verb":"CAS","path":"jobs/1/state","expect":{"absent":true},"value":"claimed"}' | nc -U /run/dude.sock
$ kill -9 <node2-pid>                   # chaos, mid-traffic
$ dude status                           # roster, floors, frontier — still green
```
