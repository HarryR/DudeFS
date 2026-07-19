# DudeFS Manager — capabilities & admin tool

> **Status:** companion to [DESIGN.md](DESIGN.md) (rev 5) / [ARCHITECTURE.md](ARCHITECTURE.md). What the manager *is* operationally, what it can do, and the shape of the command-line tool. Command names are a sketch; flows are normative by reference to PROTOCOL.md.

## 0. What the manager is (and is not)

The manager is **the client library plus the root key plus extra commands** — the manager column of ARCHITECTURE's deployment matrix. Concretely:

- **No daemon, no special channel.** The admin tool embeds L0–L6 (client profile) and talks **directly to storage nodes** with the ordinary verbs (PROTOCOL §1), doing its own quorum legwork like any client — "nodes never fan out" applies to it too. It does *not* connect through a local client node; there is no such thing. Any machine with the genesis config, the root key, and a network path to a quorum is a fully-armed manager.
- **Offline-root workflow for free.** Because every artifact is self-authenticating (PROTOCOL §0), signing and submission separate cleanly: `--sign-only` writes the signed op(s) to a file on an air-gapped machine; `submit <file>` from *any* online host — even an untrusted courier — completes the flow. The root key never has to touch a networked machine. (The sign-only step must still respect chain sequencing; the tool tracks the manager chain head across staged ops.)
- **Rarely needed.** The data path never waits on the manager (DESIGN §2). It appears for: bootstrap, membership, identity, rotation, compaction, audit, disaster.

## 1. Persistent state (the manager's durable set)

| Item | Notes |
|---|---|
| Root key | File or HSM behind the L0 `Signer` interface. Loss = control plane bricked (DESIGN §3): escrow offline copies. |
| Manager chain head `(seq, prev)` | **Author-amnesia procedure is mandatory on loss** (DESIGN §4): quorum-read own head, wait out δ, resume. The tool enforces this — it refuses to author after detecting head-state loss until the procedure completes. |
| Genesis config | Manager pubkey + seed nodes (DESIGN §14). |
| Cached roster | For reachability; refreshed from the control plane on any contact. |
| Log cache | Optional, soft — refetchable. Needed locally only for `compact` and `verify` (they fold). |

## 2. Capabilities → commands

One binary (working name: `dude`); manager powers come from *which keys are present*, not which binary — plain client commands (`dude get/set/cas/del/watch/log/status`) share it. Every command is idempotent and resumable: crash → rerun verbatim (flows are slot-guarded where it matters — the public roster slot, ballot-guarded CAS).

| Capability | Command sketch | Flow | Notes |
|---|---|---|---|
| Bootstrap | `dude init` | DESIGN §14 | Mints root key, genesis, n=1 roster. Refuses to run over an existing genesis. |
| Identity | `dude cert issue --client <pubkey>` · `--node <pubkey> [--pop <proof>]` | PROTOCOL §3.3 | `--pop` is required only under aggregate MultiSig suites (BLS, DESIGN §8) — moot for the v1 Ed25519 list; the command checks it locally before signing when required. |
| Revocation | `dude cert revoke <fingerprint>` | DESIGN §15 | Automatically stages `rotate` next (revoke without rotation is a foot-gun; `--no-rotate` to override, loudly). |
| Rotation | `dude rotate` | PROTOCOL §3.3 | New group key, wrap-set for every remaining member, `keyepoch` bump — one control op. |
| Membership | `dude node add <cert>` (learner) · `dude node promote/remove/replace` | PROTOCOL §3.1 | Roster ops; odd-size and possession-barrier validation is node-side, but the tool pre-checks and refuses obviously invalid changes. `replace` = add-learner + promote + remove, staged. |
| Compaction | `dude compact` | PROTOCOL §3.2 | Final-frontier quorum read → local fold → checkpoint op. Refuses a non-final frontier by construction. |
| Audit | `dude verify` | DESIGN §12 | Recomputes `state_root` from raw history vs the latest checkpoint; validates chains and QCs. Any client can run this — it needs no root key. |
| Evidence | `dude evidence list` · `dude evidence eject <node>` | RESILIENCE §3 | Lists collected equivocation proofs (gossiped via `EVIDENCE`); `eject` = revoke + roster-remove, staged from the proof. |
| Disaster | `dude recover --fence` | RESILIENCE §2.2 | Salvage (nodes **and** reachable clients) → verify → recovery checkpoint + fresh roster → disclosure report. Requires an explicit `--i-understand-data-loss`. |
| Telemetry | `dude status` | PROTOCOL §2.3 | Roster + epoch, per-node floors and lag spread, finality frontier, undecided slots, held evidence. Surfaces the three-level ladder (accepted / committed / final) explicitly. |

## 3. Interlocks (the tool protects the operator)

- `init` refuses over existing state; `recover` demands the explicit data-loss flag; `revoke` stages `rotate` by default.
- Roster commands refuse even voting-member counts and un-caught-up learners *client-side* before the node-side barriers would anyway (fail fast, fail near the operator).
- After any crash the tool re-derives where a staged flow stopped (everything is idempotent and observable in the log) and offers `--resume`.
- The amnesia guard (§1) is not skippable: an accidentally self-forked manager chain is indistinguishable from root compromise (DESIGN §4), so the tool treats chain-head uncertainty as radioactive.

## 4. Open bits (implementation, not protocol)

- Final binary/command naming; config-file format; HSM interface selection (PKCS#11 vs cloud KMS vs raw file) — all behind the L0 `Signer` boundary.
- Whether `status` grows a `--watch` mode (lane 1, trivially).
- Packaging of the courier flow (`--sign-only` bundle format) — an L1 artifact container, decide at wire format.
