# DudeFS — Python proof of concept

> Implementation of the design in **[SPEC.md](SPEC.md)**, which is the only design
> document: requirements and nothing else, each with an anchor the code cites. **If
> code and spec disagree, the spec wins** — a deviation is raised as a requirement or
> an issue, never silently coded around. SPEC's enforcement table maps every rule to
> what enforces it, or marks it OWED. How to work here: **[CLAUDE.md](CLAUDE.md)**.

DudeFS is a **distributed, authenticated, encrypted coordination store** — a
durable, provenance-carrying `etcd` for a small trust group. State is never
stored, only derived: every client folds the same signed log into byte-identical
state. CAS is decided by per-contention-point Paxos on PRF-opaque tags, so the
storage nodes that arbitrate a write **can never read a key or value** — payloads
are XChaCha20-Poly1305 ciphertext and slot tags are keyed-BLAKE2 opaque — and
every misbehavior below the root of trust mints portable cryptographic evidence.

**Built for:** small, precious, contested state on semi-trusted machines — a few
writers, kilobytes of config/locks/claims, 3–7 rented-or-borrowed nodes, audit
over throughput. **Not for:** write concurrency, big values, low-latency
visibility (finality waits on the skew window δ), or availability-over-durability
(a minority partition blocks; that is the point).

## Status: M0–M7 (the daemon/client/CLI stack, encrypted) — 223 tests green

Zero-knowledge is **genuinely on**: the `xcs1` AEAD suite (XChaCha20-Poly1305-IETF
with an SIV-derived, misuse-resistant nonce — CRYPTO.md §2) encrypts
every payload; group keys are distributed with `sbx1` libsodium sealed boxes. One
32-byte master per keyepoch is wrapped; the working keys (data key, slot secret)
derive from it by domain-separated keyed-BLAKE2. Crypto runs on **libsodium via
PyNaCl** — the single runtime dependency.

| Milestone | Scope | State |
|---|---|---|
| **M0** | canonical codec, L0 crypto, typed artifacts, golden vectors | ✅ |
| **M1** | the fold (full profile) + control reducer + handlers; A1–A7 as property tests | ✅ |
| **M2** | node kernel: sqlite `ChainStore` + per-slot `Acceptor`; B1 scenarios (+ M2.5 review) | ✅ |
| **M3** | sans-I/O quorum client + fault-injecting transport + sim harness (**rev 5: two-phase Paxos always**) | ✅ |
| **M4** | gossip / anti-entropy (summary/delta fixpoint) + relay; consensus hardening | ✅ |
| **M5** | control plane: capability certs, epoch bridge + possession barrier, RERECEIPT, public roster slot | ✅ |
| **M6** | **log-compaction** (rev 6, DESIGN §12): conveyor cut, resurrection masks, attempts sidecar; void rule + node GC | ✅ |
| **M7** | the real system: node daemon, client daemon + JSON-RPC worker API (CLIENT.md), the `dude` CLI (MANAGER.md), and the crypto swap to PyNaCl (`xcs1`/`sbx1`) | WP1–3 ✅ · WP4 demo pending |

All five evidence kinds (FORK, DOUBLE_VOTE, FLOOR_PERJURY, SEQ_REUSE, LOST_COMMIT)
are sound **and** complete; the adversarial review findings through #22 are closed
(horizon + epoch persisted across restart, gap-free issuance, client read-side
quorum sync). The rationale record is the git history.

The kernel is **pure and synchronous** — no I/O, no clocks, no randomness; time is
injected as `now_ms`, and the L4 quorum client is a sans-I/O state machine (events
in, commands out). Real networking lives only in the drivers: the node and client
daemons pump those pure machines over unix sockets, and the acceptor signs **only
after** COMMIT (sign-after-fsync, RESILIENCE §0).

## Layout (mirrors ARCHITECTURE.md)

```
dudefs/
  codec.py         # L1 canonical bencode (injective + canonical; rejecting decoder)
  crypto.py        # L0: BLAKE2b, keyed-BLAKE2 PRF, xcs1 AEAD (XChaCha20-Poly1305 + SIV nonce),
                   #     sbx1 sealed-box wraps, Ed25519 (+ list MultiSig) — all over PyNaCl/libsodium
  artifacts.py     # L1 Op envelope, Txn, Receipt, QC, Watermark, FrontierBundle, ballots, slot tags
  handlers/
    data.py        # L6 data/txn handler (client-only): AEAD open + guard evaluation
    control.py     # L6 control handlers: roster / cert / rotate / wrap-set / checkpoint / pver bodies
  fold.py          # L5 full profile (clients) + ControlReducer (nodes) + state_acc + keyring_from_masters
  store.py         # L2 sqlite ChainStore: contiguity, evidence, receipts, QCs, slots, durable floor/horizon/epoch
  acceptor.py      # L3 per-slot Acceptor (SUBMIT/PREPARE/ACCEPT) + skew gates + watermarks + void rule
  node.py          # NodeAPI Protocol (the §1 verbs) + typed requests + LocalNode adapter
  quorum.py        # L4 sans-I/O quorum client: Commit (two-phase Paxos) + Finalize (watermarks)
  gossip.py        # anti-entropy summary/delta + sparse below-cut baseline PULL
  compactor.py     # log-compaction: incremental fold -> dead set + retained commitment + attempts sidecar
  wire.py          # the node p2p wire: length-prefixed bencode framing
  daemon.py        # the node daemon (WP1): socket shell + gossip loop + adoption/fence/evidence cycles
  client.py        # the resident client daemon (WP2): drives quorums, §1.2 read sync, the honest ladder
  workerapi.py     # the JSON-RPC 2.0 worker API (WP2, CLIENT.md) over a local unix socket
  manager.py       # the manager library (WP3): control-op authoring, rotate, roster, recovery interlocks
  cli.py           # the `dude` CLI (WP3): a thin shell over manager.py + the worker socket
  transports/memory.py  # seeded discrete-event scheduler + fault-injecting carrier (sim only)
  sim/             # composition: chaos schedules + adversarial personas + continuous B-invariant assertions
tests/             # stdlib unittest; property "soups" (A1–A7), B scenarios, review regressions, live-socket daemons
```

## Running

Runtime is **stdlib-only** (Python **3.12+**) plus **one dependency: PyNaCl**
(libsodium):

```
python3 -m unittest discover -s tests        # ~6s (libsodium)
```

The `dude` CLI drives the whole system — bootstrap, membership, client reads and
writes, and the heavily-interlocked recovery path:

```
dude init                         # mint root key + genesis
dude cert issue --client <pub>    # authorize a writer
dude set my/key value             # PUT through the client daemon (worker socket)
dude wheres my key                # human key-status: value, finality, fence, pending intent
dude recover                      # disaster recovery — hard-refuses while a quorum still answers
```

## Developer toolchain (`make`)

Self-contained under the project — nothing installs to your system. `make install`
bootstraps a project-local `uv` (into `./.uv`) and a `./.venv` with **ruff** (lint
+ format), **ty** (typecheck), and **PyNaCl**:

```
make install      # one time
make check        # ruff lint + format-check + ty + tests  (the CI gate; keep it green)
make lint | format | typecheck | test
make clean        # remove .venv + caches   (distclean also removes .uv)
```

Code style: [PYTHON-CODESTYLE.md](PYTHON-CODESTYLE.md) — strict typing, enums over
constants, typed error hierarchy, docstrings citing SPEC anchors.
