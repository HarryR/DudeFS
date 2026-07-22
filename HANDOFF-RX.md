# HANDOFF-RX — CLI realisation: namespaces, daemons, worker shortcuts

> **Parked / interim** (renamed from R5). This CLI milestone follows the compaction milestone
> ([HANDOFF-R6.md](HANDOFF-R6.md)); it is a thin operator shell over already-correct machinery.
> "RX" marks it as deferred and likely to split into segmented handoffs as the work proceeds.

> **From:** planner (Opus) · **To:** verification / implementer ·
> **Date:** 2026-07-22 · **Baseline:** `530ad9a` (296 tests green) —
> `python3 -m dudefs` entry point + `CLI.md` namespace plan landed.
>
> **Preamble — what this builds on.** M7 is CLOSED: the daemon, worker API, CLI,
> and encrypted demo are landed and reviewed. `CLI.md` is the **settled**
> plan-of-record for the command surface (`mgr`/`m`/`manager` control-plane +
> `node`/`client`/`compactor` daemon lifecycle) — every naming and shape decision
> in it is ruled (generic `cert` retired, positional `<pub> <pop>`, multi-homed
> `node add`, standalone compactor node, wrap-set key distribution, top-level
> `get/set/cas/del`, `m init` genesis split). This handoff turns CLI.md into code.
> Documents are canonical; discrepancies become NOTES items, never workarounds.

## Context

Today the CLI is flat, exposes only manager verbs + worker-socket passthrough, and
**cannot launch any daemon** — a cluster only stands up in-process (tests). Two
structural problems motivate the work: (1) you can't run a node/client/compactor from
the command line at all, and (2) **nothing drives compaction in production**, so node
data logs *and* the manager's `control.log` grow unbounded (the M6 checkpoint machinery
is complete and golden-tested but un-driven). This plan realises CLI.md in dependency
order — four phases, each a self-contained `make check`-green commit.

### Ordering note
Compaction is **not** part of this milestone — it moved out to its own work order
([HANDOFF-R6.md](HANDOFF-R6.md)) once the sweep showed it is half-implemented and needs its own
testing arc. The CLI's `compactor run/once` + serve verbs wrap that **already-completed** machinery.
Within this milestone the order is foundation-first: namespaces → genesis/identity → serve verbs →
management readers.

### Cross-cutting facts (from exploration)
- **Durable store is free.** `ChainStore` (store.py:328) already uses WAL + `synchronous=FULL`;
  passing a filesystem path instead of `:memory:` gives crash-safe durability with **no code
  change**. A restarted daemon resumes from disk.
- **`control_ops` seed = `control.log`.** The manager persists every control op as a hex line
  in `{dir}/control.log`; a daemon reconstructs its seed via `A.Op.from_bytes(bytes.fromhex(line))`
  (pattern already in test_cli.py:182). `bootstrap.json` supplies the cold-start scalars
  (`manager_pub`, `epoch`, `roster:[{pub,addr}]`); certs/endpoints arrive via that seed + gossip.
- **argparse aliases are transparent.** `sub.add_parser(name, aliases=["m","manager"])`; dispatch
  is via `args.fn` and `dest="cmd"` stores the canonical name — no handler changes (cli.py:341).
- **`node_spawn` is already generic** (manager.py:313) — it just names the keyfile `node-`;
  client/compactor minting is a trivial generalization.

---

## Phase 1 — CLI namespace refactor (restructure existing verbs; no new protocol behavior)

**Goal:** the target command tree, backed entirely by today's handlers. Files: `dudefs/cli.py`
(`build_parser` cli.py:336), `tests/test_cli.py` (invocation paths).

- Add `mgr`/`m`/`manager` alias group; move the manager verbs under it. `init`, `status`,
  `recover`, `rotate` stay 1:1.
- **Retire generic `cert`** → per-principal `mgr {node,client,compactor} authorize <pub> <pop>`
  and `revoke <pub>` (positional). All three map onto existing `cert_issue(kind,…)`/`cert_revoke`
  (manager.py:266/287); `kind` becomes the namespace. Three cert kinds = full cover.
- Move roster ops under `mgr node`: `node authorize|add|promote` (today's flat `node …` + `cert
  issue node`). Keep the single-dispatcher idiom (cmd_node switches on `node_cmd`).
- Worker verbs → `client {get,set,cas,del,wheres,status}`; add **top-level `get/set/cas/del`**
  shortcuts aliasing them (dial `$DUDE_SOCK`).
- Update `tests/test_cli.py` invocations to new paths (behavior identical → assertions unchanged).

**Verify:** `make check` green; `python3 -m dudefs m --help`, `dudefs mgr node --help`,
`dudefs get --help` show the new tree; an end-to-end `test_cli` run against a live cluster still
passes with the renamed verbs.

---

## Phase 2 — Genesis split + identity minting + `node genesis`

**Goal:** `m init` stops minting node keys; principals mint their own; the founding node is
seated cleanly. Files: `dudefs/manager.py` (`init` manager.py:222, `node_spawn`), `dudefs/cli.py`.

- **`m init` = manager-only genesis:** mint root key + epoch-0 group master, write
  `state.json`/`root.key`/`control.log` with an **empty roster**. Remove the `node0.key`
  self-mint (manager.py:229-234) and the `--node-addr` seed.
- **`node/client/compactor init --dir`:** generalize `node_spawn` into a keyfile-minting helper
  that writes `{dir}/<role>.key` (0o600) + prints `pub` + `prove_possession`. (client/compactor
  minting is new but trivial — the same function, different filename.)
- **`m node genesis <pub> <pop> <addr>…`:** new `Manager.node_genesis` — verify PoP, issue the
  `Cap.STORE` cert, seat the node as the sole voting member with its endpoint(s), unilaterally
  (no joint-cert; there is no prior quorum). One control-op batch on the manager chain.
- Multi-homed endpoints: `node genesis`/`node add` accept ≥1 `<addr>` positionals →
  `set_endpoint(pub, [rec,…])` (endpoint_body already takes a list; ManagerState.node_addrs
  must widen from a single `Endpoint` to `list[Endpoint]` — manager.py:57).

**Verify:** `make check`; a scripted `node init → m init → m node genesis → …` produces a valid
n=1 `state.json` (voting roster of 1, endpoint recorded, node key only in the node's dir);
existing manager/init tests updated to the manager-only genesis shape.

---

## Phase 3 — The daemons: `node serve` + `client serve`

**Goal:** launch real daemons from `--dir`. Files: `dudefs/cli.py` (new launch shell),
`dudefs/daemon.py` / `dudefs/client.py` / `dudefs/workerapi.py` (small wiring), new
`bootstrap.json` reader.

- **`node serve --dir`:** load `<dir>/node.key` → sk/pub; open `ChainStore(<dir>/store.sqlite)`;
  read `bootstrap.json` for `manager_pub`/`epoch`/`roster`/seed `peers`; reconstruct
  `control_ops` from a shipped `control.log` (or rely on gossip). Construct `NodeDaemon`, then
  run **both** `serve_forever(uri)` **and** a thread running `run_periodic(period_s, stop)` —
  nothing starts the maintenance loop today (gap #2 from exploration). Clock = wall-ms.
- **`client serve --dir`:** load `<dir>/client.key`; `ChainStore`; construct `ClientDaemon`;
  wrap in `WorkerServer` on `<dir>/worker.sock` (**unlink stale socket first** — workerapi.py:378
  doesn't). The refresh loop already self-starts.
- **Client group key via wrap-unwrap (CLI.md §7, finding 21):** change `ClientDaemon` to derive
  its keyring by finding its own WRAP_SET in the held control ops and calling
  `control.unwrap_group_key(body, sk)` — instead of taking a plaintext `masters` dict
  (client.py:212). **Prerequisite:** the manager must *author* a wrap-set at membership time, not
  only on `rotate` — wire a wrap-set into `m init` (genesis epoch-0 wrap to the founding node)
  and into `client authorize`/`node genesis` (re-wrap to include the new member). Today only
  `rotate()` authors wraps (manager.py:299), so a freshly-authorized member has none.
- **`bootstrap.json`:** emit from `m init`/`m node add` (non-secret projection of `state.json`);
  read in the serve shells. Never carries masters (secret).

**Verify:** `make check`; a real out-of-process drill (new `tests/` or a shell script): `m init`
→ `node init`/`serve` ×3 → `client init`/`serve` → `dudefs set`/`get` round-trips through the
worker socket → kill a node, writes still commit → restart, it resumes from its durable store
(not empty). Port the test_demo assembly (test_demo.py:52-80) to the CLI shells.

---

## Phase 4 — Management readers + endpoint/replace verbs

**Goal:** finish the `mgr` surface. Files: `dudefs/cli.py`, `dudefs/manager.py` (thin readers +
endpoint delta), `dudefs/node.py`/`client.py` (local status readers).

- **`mgr node list` / `mgr client list`:** thin readers over `ManagerState.roster`/`learners`/
  `node_addrs`/`certs` (data all present; only `_print_cert_inventory` exists today).
- **`mgr node endpoint {add,remove,set,list}`:** `set` = replace-all (existing `set_endpoint`);
  `add`/`remove` = read-modify-write over the address **list** (needs ManagerState.node_addrs as
  a list, done in Phase 2); `list` = render. `remove` with no addr = whole-record removal
  (empty `addrs`, already supported).
- **`mgr node replace <old> <new>`:** wire the existing `Manager.node_replace` (manager.py:362).
- **`node/client/compactor status`:** local readers — node floor/frontier/roster from its store
  (no network); client = worker `STATUS`.

**Verify:** `make check`; `dudefs mgr node list` reflects a grown roster; `endpoint add` then
`list` shows a multi-homed node; `node replace` swaps a member (count preserved) against a live
cluster.

---

## Compaction — moved out to its own milestone

The compactor daemon (`compactor run`/`once`) and manager-log compaction were an earlier
"Phase 5" here. Exploration showed compaction is **half-implemented** — a sound fold kernel
but an absent driver, two *mandatory* correctness properties stubbed (the encrypted `attempts`
sidecar and `state_root` derive-and-verify), and the client bootstrap consumer unwired — with
its own substantial testing arc (notably: a client that starts *after* compaction and must
replay to the same state as every other node). It is therefore a **separate milestone with
its own work-order: see [HANDOFF-R6.md](HANDOFF-R6.md).** It **precedes** this CLI milestone
(the CLI is a thin shell over already-correct machinery). The `compactor run/once` and
`m log compact` verbs from CLI.md land in the CLI milestone only *after* the compaction milestone (HANDOFF-R6.md) is
green — as the operator shell over the finished mechanism.

---

## Open decisions (surface before/at execution)

1. **Ordering** — the CLI daemon verbs come **after** the compaction milestone (HANDOFF-R6.md).
   Within the CLI work, foundation-first (namespaces → genesis/identity → serve verbs → readers).
2. **Wrap-set at onboarding (Phase 3)** — to make client key-fetch (B) work, the manager must
   author a wrap-set at `init`/`authorize`, not only `rotate`. Confirm that's in-scope for
   Phase 3 (it's required for `client serve` to obtain a key without a manual `rotate`).

## Scope note
Four CLI phases, each a self-contained `make check`-green commit (style/behavior never mixed;
goldens immovable in style commits). They make the CLI real and the cluster runnable. Compaction
is a **prior** milestone (HANDOFF-R6.md), not a phase here.
