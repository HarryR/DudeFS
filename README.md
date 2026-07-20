# DudeFS — Python proof of concept

> Implementation of the design in [DESIGN.md](DESIGN.md) (rev 6) and companions
> ([PROTOCOL.md](PROTOCOL.md), [ARCHITECTURE.md](ARCHITECTURE.md),
> [MANAGER.md](MANAGER.md), [RESILIENCE.md](RESILIENCE.md),
> [FORMAL.md](FORMAL.md), [COMPARISON.md](COMPARISON.md)), following the plan in
> [IMPLEMENTATION.md](IMPLEMENTATION.md). **If code and documents disagree, the
> documents win** — deviations are raised in [NOTES.md](NOTES.md), never silently
> coded around.

DudeFS is an **authenticated, encrypted, replicated coordination store** — a
durable, provenance-carrying `etcd` for a small trust group. State is never
stored, only derived: every client folds the same signed log into byte-identical
state. CAS is decided by per-contention-point Paxos on PRF-opaque tags, so the
storage nodes that arbitrate a write **can never read a key or value** — and
every misbehavior below the root of trust mints portable cryptographic evidence.

**Built for:** small, precious, contested state on semi-trusted machines — a few
writers, kilobytes of config/locks/claims, 3–7 rented-or-borrowed nodes, audit
over throughput. **Not for:** write concurrency, big values, low-latency
visibility (finality waits on the skew window δ), or availability-over-durability
(a minority partition blocks; that is the point).

## ⚠️ Zero-knowledge is SUSPENDED in this build

The launch AEAD suite is **`auth0` — authenticated but UNENCRYPTED**
(IMPLEMENTATION.md §1): payloads are stored in the clear and nodes are not yet
zero-knowledge for data. Every *other* property — provenance, canonical wire,
CAS exclusion, the deterministic fold, finality, detect-and-punish — is
exercised for real. Confidentiality arrives as a keyepoch rotation to a real
cipher suite (`b2s1` / `xcp1`); `dudefs.crypto.zero_knowledge_active()` returns
`False` here, by design and on purpose.

## Status: M0–M4 complete (plus three adversarial review passes)

| Milestone | Scope | State |
|---|---|---|
| **M0** | canonical codec, L0 crypto + vendored Ed25519, typed artifacts, golden vectors | ✅ |
| **M1** | the fold (full profile) + control reducer + handlers; A1–A7 as property tests | ✅ |
| **M2** | node kernel: sqlite `ChainStore` + per-slot `Acceptor`; B1 scenarios | ✅ |
| **M2.5** | adversarial review: cut-relative barrier (A4), universal lineage-advance (A2), fail-closed `pver` fence, accept-time `deps`, fold totality — [NOTES.md §M2.5](NOTES.md) | ✅ |
| **M3** | sans-I/O quorum client (`quorum.py` + `node.py` seam) + fault-injecting memory transport + sim harness (continuous B1/B2/B3 checks, seeded replay). The sim caught the fast-path double-commit — resolved by **rev 5: classic two-phase Paxos always** ([NOTES item 21](NOTES.md)) | ✅ |
| **M4** | gossip/anti-entropy (summary/delta fixpoint convergence on partial meshes) + relay: single-push writes, PULL-then-accept deps, the §7.3 relayed linearizable read; consensus hardening — receipt persistence, dueling-proposer liveness (jitter + round-timeout escalation), per-slot ballot priorities ([NOTES items 22–24](NOTES.md)) | ✅ |
| M5+ | control plane (+ delegated compactor cert), compaction (**log-compaction — rev 6**, DESIGN §12), daemon/CLI | not started |

The kernel is **pure and synchronous** — no I/O, no clocks, no randomness; time
is injected as `now_ms`, and the L4 quorum client is a sans-I/O state machine
(events in, commands out). The store is the one stateful edge: one sqlite DB
per node = one durability domain, and the acceptor signs **only after** COMMIT
(sign-after-fsync, RESILIENCE §0). Gossip (M4) is pure-function + sim-harness level; real networking begins at M7 (daemon/demo).

## Layout (mirrors ARCHITECTURE.md)

```
dudefs/
  codec.py         # L1 canonical bencode (injective + canonical; rejecting decoder)
  crypto.py        # L0 suite registry: BLAKE2b, keyed-BLAKE2 PRF, auth0 AEAD, Ed25519 (+list MultiSig)
  vendor/ed25519.py# vendored RFC 8032 (POC-only; not constant-time)
  artifacts.py     # L1 Op envelope, Txn, Receipt, QC, Watermark, FrontierBundle, ballots, slot tags
  handlers/
    data.py        # L6 data/txn handler (client-only): AEAD open + guard evaluation
    control.py     # L6 control handlers: schema-validated roster/cert/rotate/checkpoint/pver bodies
  fold.py          # L5 full profile (clients) + ControlReducer (nodes) + snapshot/state_root
  store.py         # L2 sqlite ChainStore: contiguity, fork evidence, receipts, QCs, slots, durable floor
  acceptor.py      # L3 per-slot Acceptor (SUBMIT/PREPARE/ACCEPT) + skew gates + watermarks
  node.py          # NodeAPI Protocol (the §1 verbs) + typed requests + LocalNode adapter
  quorum.py        # L4 sans-I/O quorum client: Commit (two-phase Paxos) + Finalize (watermarks)
  transports/memory.py  # seeded discrete-event scheduler + fault-injecting carrier
  sim/harness.py   # composition only: chaos schedules + continuous B1/B2/B3 assertions + trace
tests/             # stdlib unittest; property "soups" (A1–A7), B1 scenarios, review regressions, sim
```

## Running

Runtime is **stdlib-only** (Python **3.12+**) plus the one vendored Ed25519 file:

```
python3 -m unittest discover -s tests        # ~12s (pure-Python Ed25519)
```

## Developer toolchain (`make`)

Self-contained under the project — nothing installs to your system. `make
install` bootstraps a project-local `uv` (into `./.uv`) and a `./.venv` with
**ruff** (lint + format) and **ty** (typecheck):

```
make install      # one time
make check        # ruff lint + format-check + ty + tests  (the CI gate; keep it green)
make lint | format | typecheck | test
make clean        # remove .venv + caches   (distclean also removes .uv)
```

Code style: [PYTHON-CODESTYLE.md](PYTHON-CODESTYLE.md) — strict typing, enums
over constants, typed error hierarchy, docstrings citing doc sections.
