# DudeFS CLI — the `dudefs` command surface

> **Status:** DRAFT for iteration. The operator-facing map of every command, grouped by
> principal, with a description of each. It is the plan of record for the CLI namespacing
> and daemon lifecycle; where it names a *PROPOSED* verb the library machinery usually
> already exists (noted inline) and only the parse-and-delegate shell is missing.

Invocation: `python3 -m dudefs …` (an installed `dudefs` console-script is a later
packaging concern). Examples elide the `python3 -m` prefix.

## 1. The model

Two sides act on the system, and the CLI mirrors that split:

- **`mgr` (aliases `m`, `manager`)** — *manager authority*. Operates on the on-disk
  manager home in `--dir` (root key + `state.json` snapshot + `control.log` audit) and
  **authors control ops** (certs, roster changes, rotations, endpoints, checkpoints).
  Not a daemon — each invocation is a one-shot tool run.
- **`node` / `client` / `compactor`** — *a daemon's own lifecycle*. Each has its own
  home `--dir` where its identity keyfile, SQLite store, socket, and bootstrap seed live.
  It mints its **own** identity there (NOTES 58: keys generate where they live) and runs
  itself. It never holds the root key.

The **subject noun is shared**; the context says which side acts — `mgr node add`
(manager authority *over* a node) vs. `node serve` (the node running *itself*):

| | `mgr <subject> …` (authority over it) | `<subject> …` (it runs itself) |
|---|---|---|
| **node** | genesis · authorize · add · promote · replace · list · endpoint {add/remove/set/list} | init · serve · status |
| **client** | authorize · revoke · list | init · serve · get/set/cas/del/wheres · status |
| **compactor** | authorize · revoke | init · run · once |

Identity verbs are **positional and consistent**: `authorize <pub> <pop>` and
`revoke <pub>` everywhere — every principal is named by its pubkey, never a fingerprint.

Tags below: **EXISTS** = a current `cli.py` command (old name noted where it moved);
*PROPOSED* = not yet wired (library state noted).

## 2. Lifecycles (how the verbs compose)

**Bootstrap the cluster** — the founding node is special: with no prior quorum, the
normal join ladder has nothing to certify against, so the manager (root of trust) seats it
**unilaterally**, fusing authorize + add into one `node genesis`:

```
node   init           --dir ./n0                    # first node mints its key -> pub + PoP
mgr    init           --dir ./mgr                   # manager genesis: root key + group key, no node
mgr    node genesis   <pub> <pop> unix:/run/n0.sock # verify PoP + authorize + seat the sole voting node
node   serve          --dir ./n0                    # the n=1 cluster is live
```

**Grow the roster** — every subsequent node runs the full ladder: certified, added as a
learner (with its endpoints), catches up over gossip, *then* promoted into the quorum (§13
joint certificate — old-roster QC + possession-gated new-roster QC):

```
node   init           --dir ./n1                    # node mints its key -> prints pub + PoP
mgr    node authorize <pub> <pop>                   # manager certs it (Cap.STORE)
mgr    node add       <pub> unix:/run/n1.sock       # add as a learner WITH its endpoint(s)
node   serve          --dir ./n1                    # runs; catches up via gossip
mgr    node promote   <pub>                          # learner -> voting (quorum member)
```

`add` takes the node's endpoint(s) inline, so a learner is reachable for gossip catch-up
the moment it exists — and fully addressed before `promote`. Later address changes go
through the `node endpoint` verbs.

**Onboard a client (writer):**

```
client init             --dir ./c0                  # mints key -> pub + PoP
mgr    client authorize  <pub> <pop>                # cert (Cap.WRITE)
client serve            --dir ./c0                  # daemon up; worker socket exposed
# apps now use:  client get/set/cas/del   (or connect to the socket directly)
```

**Onboard a compactor:**

```
compactor init          --dir ./k0                  # mints key -> pub + PoP
mgr    compactor authorize <pub> <pop>              # cert (Cap.COMPACT)
compactor run           --dir ./k0 --interval 300   # own gossip-synced replica; authors checkpoints
```

**De-provision:** `mgr client revoke <pub>` · `mgr node replace <old> <new>` (count-
preserving swap for disk-wipe retirement) · `mgr node endpoint remove <pub>`.

## 3. `mgr` | `m` | `manager` — control plane

Home via `--dir` / `$DUDE_DIR` (default `.dude`); all verbs carry it.

**`init`** · EXISTS *(behavior changing)* — Establish the **manager genesis**: mint the
root key + the epoch-0 group key, refuse over existing state. It mints **no** node (today's
`init` secretly mints `node0` — that violates keys-generate-where-they-live and is being
removed). Seat the founding node separately with `node genesis`.
> `m init`

**`node genesis`** · *PROPOSED* — Seat the **founding** voting node at cluster genesis,
fusing `authorize` + `add` in one unilateral step (no prior quorum exists to run the
joint-cert ladder against). Verifies proof-of-possession, issues the `Cap.STORE` cert, and
seats the node as the sole voting member with its dial endpoint(s). Used exactly once,
right after `m init`.
> `m node genesis <pub> <pop> unix:/run/n0.sock [tor:abc…onion]`

**`status`** · EXISTS — Probe the roster over the p2p wire; print roster size, each node's
floor / epoch / reachability, and the finality frontier (max attested floor).
> `m status`

**`recover`** · EXISTS — Disaster recovery, heavily interlocked. HARD-REFUSES while a
quorum still answers (the load-bearing safety check), probes reachability over a dwell
window, then authors the recovery fence.
> `m recover --dwell 2 --i-understand-data-loss`

**`rotate`** · EXISTS — Mint a new group key + wrap-set and bump the keyepoch. Expires no
capability — distrust is explicit via `revoke`.
> `m rotate`

**`node authorize`** · EXISTS *(was `cert issue node`)* — Issue a `Cap.STORE` cert for a
storage node, binding its pubkey + proof-of-possession into the authorization chain.
> `m node authorize <pub> <pop>`

**`node add`** · EXISTS — Add an authorized node to the roster as a **learner**
(non-voting) **with its dial endpoint(s) inline** (one or more positionals — a node is
multi-homed), so it's reachable for gossip catch-up the moment it's added. It catches up
before promotion; later address changes use the `node endpoint` verbs.
> `m node add <pub> unix:/run/n1.sock [tor:abc…onion]`

**`node promote`** · EXISTS — Promote a caught-up learner to a **voting** quorum member
via the §13 joint certificate. Refuses an even voting count (quorum intersection needs
odd n).
> `m node promote <pub>`

**`node replace`** · *PROPOSED* (lib `node_replace` exists) — Retire a voting node and
swap in a replacement in one step; the voting count is unchanged (stays odd). For
disk-wipe identity retirement — revoke the old cert separately.
> `m node replace <old-pub> <new-pub>`

**`node list`** · *PROPOSED* — Show the current roster, learners, and their published
endpoints.
> `m node list`

A node is **multi-homed**: its ENDPOINT record (PROTOCOL §7.1) is a *list* of dial
addresses, latest-wins per subject. So endpoint management is add/remove over that list,
not a single clobbering value:

**`node endpoint add`** · *PROPOSED* (lib `set_endpoint` exists) — Append a dial address to
the node's record (read-modify-write); repeat to multi-home.
> `m node endpoint add <pub> unix:/run/n1.sock`

**`node endpoint remove`** · *PROPOSED* — Drop one dial address from the node's record
(remove the whole record — retire reachability — if it was the last one, or none given).
> `m node endpoint remove <pub> unix:/run/n1.sock`

**`node endpoint set`** · *PROPOSED* — Replace the **full** address list in one shot
(several positionals); the deliberate clobber, for re-homing wholesale.
> `m node endpoint set <pub> unix:/run/n1.sock tor:abc…onion`

**`node endpoint list`** · *PROPOSED* — Show a node's current dial addresses.
> `m node endpoint list <pub>`

**`client authorize`** · EXISTS *(was `cert issue client`)* — Issue a `Cap.WRITE` cert for
a client (writer).
> `m client authorize <pub> <pop>`

**`client revoke`** · EXISTS *(was `cert revoke`)* — Revoke a client's cert (blacklist) by
pubkey; stages a rotate by default.
> `m client revoke <pub> [--no-rotate]`

**`client list`** · *PROPOSED* — Show authorized clients and their cert epochs.
> `m client list`

**`compactor authorize`** · EXISTS *(was `cert issue compactor`)* — Issue a `Cap.COMPACT`
cert for a compactor.
> `m compactor authorize <pub> <pop>`

**`compactor revoke`** · EXISTS *(was `cert revoke`)* — Revoke a compactor's cert by pubkey.
> `m compactor revoke <pub>`

**`log compact`** · *PROPOSED* — Prune the manager's append-only `control.log` below the
latest checkpoint, keeping `state.json` as the live snapshot — bounds the manager's own
growth.
> `m log compact`

> The per-principal `authorize`/`revoke` verbs are the ergonomic surface over the generic
> cert primitive (the `kind` is now the namespace); `revoke <pub>` stages a rotate by
> default (rotation expires nothing — distrust is explicit).

## 4. `node` — storage-node daemon

Home via `--dir` (keyfile, store, bootstrap seed). Individual paths (`--store`,
`--listen`) are optional overrides of the `--dir` layout.

**`init`** · EXISTS *(mint logic in `manager.node_spawn`; re-home to the node's own dir)* —
Mint this node's identity keyfile in `--dir` and print its pubkey + proof-of-possession
(hand these to `mgr node authorize`). Keys generate where they live.
> `node init --dir ./n1`

**`serve`** · *PROPOSED* — Run the storage-node daemon from `--dir`: serve acceptor RPCs
behind the socket and stay converged by periodic gossip. Loads the bootstrap seed; learns
certs/roster via gossip. It *serves* requests, hence `serve`.
> `node serve --dir ./n1`

**`status`** · *PROPOSED* — Print this node's local view — attested floor, per-author
frontier, folded roster — read straight from its store, no network.
> `node status --dir ./n1`

## 5. `client` — client-node daemon + worker shortcuts

Home via `--dir`. The worker verbs dial the daemon's socket (`--sock` / `$DUDE_SOCK`, or
derived from `--dir`).

**`init`** · *PROPOSED* (no client minting today) — Mint this client's identity keyfile in
`--dir`; print pubkey + PoP for `mgr client authorize`.
> `client init --dir ./c0`

**`serve`** · *PROPOSED* — Run the client daemon from `--dir`: drive quorums, fold the
CLIENT.md consistency ladder, and expose the **worker socket** for local apps. The worker
verbs below are passthrough to a *running* `serve`.
> `client serve --dir ./c0`

**`get`** · EXISTS — Read a key. `--level local` (fast, may flip) or `final` (quorum-
synced, stable).
> `client get my/key --level final`

**`set`** · EXISTS — Write a value (unconditional PUT).
> `client set my/key value`

**`cas`** · EXISTS — Guarded write: apply only if the key matches `--expect` (a version
hex, or `absent`).
> `client cas my/key value --expect absent`

**`del`** · EXISTS — Delete a key.
> `client del my/key`

**`wheres`** · EXISTS — Human-readable key status (INSPECT): value, finality level, fence,
pending intent.
> `client wheres my key`

**`status`** · *PROPOSED* (worker `STATUS` verb exists, no CLI) — The daemon's ladder /
health.
> `client status`

**Top-level shortcuts.** The four verbs you type constantly are also aliased at the top
level, dialing `$DUDE_SOCK` — `dudefs get/set/cas/del` ≡ `dudefs client get/set/cas/del`.
`wheres`/`status` stay under `client` (occasional, diagnostic).
> `dudefs get my/key` · `dudefs set my/key value` · `dudefs cas my/key value --expect absent` · `dudefs del my/key`

## 6. `compactor` — compaction daemon

The currently-missing driver: `compact()` is golden-tested (M6) but nothing authors real
checkpoints in production, so node data logs *and* the manager `control.log` grow
unbounded. The compactor is **its own node** — its own identity + `Cap.COMPACT`, a
gossip-synced replica of the log (a non-voting reader) held in its `--dir`. It never reads
another node's store file directly.

**`init`** · *PROPOSED* — Mint the compactor identity keyfile in `--dir`; print pubkey +
PoP for `mgr compactor authorize`.
> `compactor init --dir ./k0`

**`run`** · *PROPOSED* — Run the compaction job continuously from `--dir` every
`--interval` seconds: sync its replica via gossip, fold → `compact()` → author a
checkpoint op, then gossip that checkpoint back to the roster. Answers no requests — it
*runs*.
> `compactor run --dir ./k0 --interval 300`

**`once`** · *PROPOSED* — A single compaction pass — one checkpoint — then exit.
> `compactor once --dir ./k0`

## 7. Conventions

- **Every principal has a home `--dir`.** Manager: `--dir` / `$DUDE_DIR` (default `.dude`).
  Daemons: their own `--dir` holding keyfile + SQLite store + socket + bootstrap seed.
- **Explicit overrides.** `--store`, `--listen`, `--sock` override the `--dir` layout for
  non-standard deployments; unset, they derive from `--dir`.
- **Worker socket:** `--sock` / `$DUDE_SOCK` (or derived from the client `--dir`).
- **Bootstrap seed:** `bootstrap.json` inside a daemon's `--dir` —
  `{manager_pub, epoch, roster: [{pub, addr}]}`, emitted by `m init` / `m node add`, so a
  daemon starts gated and finds peers before gossip catches it up. Authz still arrives by
  gossip; this is only the seed.
- **Encryption keys never travel in clear.** A client daemon obtains the per-epoch group
  key by finding *its own* sealed wrap in the gossiped log and opening it with its private
  key (`unwrap_group_key`); the manager publishes a fresh wrap-set on every `rotate`. So
  `client init`/`serve` need only the client keyfile + the log — no key is hand-delivered.

## 8. Open questions (iterate here)

**Resolved:** generic `cert` retired — three cert kinds = three principals, full cover. ·
Compactor is a standalone node with its own gossip-synced replica. · Client group key via
the finding-21 wrap-set unwrap, never a clear-text hand-off. · Two-step node onboarding,
`authorize` then `add`, with endpoint(s) passed **inline to `add`**. · Top-level
`get/set/cas/del` shortcuts kept, aliasing `client …`.

**Genesis resolved:** `m init` is manager-only (mints no node); the founding node is seated
by `m node genesis <pub> <pop> <addr>…`, which fuses authorize + add unilaterally (no prior
quorum). `m init` no longer mints node keys.

Nothing open — the surface is settled. Implementation proceeds in impact order (§ below).
