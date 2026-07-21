# DudeFS clients — the worker API & canonical use cases

> **Status:** canonical (NOTES 50–52), 2026-07-21. This is the doc WP2 codes
> against and the contract workers program against. Supersedes the PROTOCOL
> §6.1 sketch. The design ethos in one line: **the store tells the truth about
> distributed state instead of hiding it** — durability, provisionality, and
> finality are first-class API surface, because distributed-aware protocols
> need them.

## 0. Roles and the async model

```
worker processes ──(JSON-RPC / unix socket)──► client daemon ──(quorum RPC)──► storage nodes
   no keys, no crypto                          THE identity + keyring            zero-knowledge
   fire-and-forget + poll                      drives quorums itself             never decrypt
```

Workers submit and get a token back immediately; the **resident client
daemon** pushes to the storage quorum in the background (hedged fanout,
~2 RTT to durable). The daemon never hands an op to a single node and
disconnects — PROTOCOL §1.4's offline mode is struck (NOTES 52); the daemon
*finishes the job*. Workers hold no state: every question below is answerable
by asking the daemon, from a fresh machine.

## 1. Wire: JSON-RPC 2.0, concurrent, poll-only

- JSON-RPC 2.0 over the unix socket (filesystem permissions = the entire
  worker-authorization boundary). `id`-correlated ⇒ **any number of requests
  in flight per connection**; batches allowed.
- **Every request returns immediately. Nothing blocks. There is no
  server-push.** Polling is the native idiom and it is *local* — a poll costs
  a socket round trip against state the daemon already holds.
- **No stubs** (NOTES 51): every verb below is implemented and reviewed;
  verbs that don't exist aren't in the table.

## 2. The ladder — one write's life, honestly labeled

```
in-flight ─► decided ────────────────► provisional ─► final
             ├ committed  durable forever (QC; survives ≤f disasters)
             ├ lost       a rival won the slot — DEFINITIVE, at network speed
             └ unknown    indeterminate (rare) — keep polling, never guess
             verdicts (committed only):
               provisional {applied|rejected|stale} + may_flip   — from the fold NOW
               final       {applied|rejected|stale}              — floors ≥ hlc; frozen
```

Contract rules: `lost` is the fast-fail (retry against fresh lineage
immediately). `provisional` may flip until `final`, both directions, within
the ~δ (≈1 s) window. **Pipelining on `provisional` is fail-safe by
construction**: dependents restate exact lineage points, so a flipped
ancestor cascades every dependent to `stale` — never a wrong-apply, never a
partial (NOTES 50). `unknown` is honest tri-state; re-poll resolves it.

### 2.1 The consistency contract — what `may_flip` means, precisely

Every client converges on **one serial history** (the fold's total order —
SEC). The trailing ~δ of that history is still *settling*: a write with a
slightly-behind clock can still commit into it and re-attribute everything
that sorts above it. Everything older than the finality frontier is carved
in stone (§9). `may_flip` is the boolean that tells you which side of that
line your answer came from:

- **`may_flip: false` ⇒ this answer IS final** — every op it derives from
  sits at/below the quorum-attested frontier. It will never change, and it
  is monotone across polls. (This makes `may_flip` the cheap finality
  signal: poll `provisional` and act when it goes false — typically ~δ +
  poll cadence after commit — without ever asking for `final` explicitly.)
- **`may_flip: true` ⇒ the answer can change, in exactly one way**: a new
  commit with an *earlier* hlc (bounded by δ — floors refuse anything
  older) re-runs the walk above it. Verdicts can flip `applied↔rejected↔
  stale`; values and absence can flip with them. What can NEVER flip:
  `committed` (durability), `lost`, anything already `final`.

**What never breaks, even on flips — the transactional floor:** no lost
updates and no dirty writes, ever, at any tier. Any write you base on a
provisional read carries that read's fencing token; if the basis flips,
your write folds `stale` — an *explicit retry signal*, never a silent
overwrite. Inside the store, optimism is free.

**The one rule that needs your judgment — external side effects:** a
provisional read used for a *non-CAS* decision (act on a config value, pay
an invoice) can be based on state that flips, and the store cannot fence
the outside world. So: **inside the store, pipeline on provisional freely;
outside the store, buy `final` (wait for `may_flip:false`) or buy
idempotence (the durable-intent pattern, §5).**

**CAP/PACELC, stated exactly:** this is a **CP** system with a labeled
stale-read escape hatch. Writes need a quorum — a minority partition
*parks* (unavailable), never answers wrong. Reads: `level=final` performs
an on-demand quorum sync → linearizable at the frontier (CP; PC/EC).
`level=local` answers from the cached fold → available under any partition
but possibly stale and non-monotone within the δ window (PA/EL). **The tier
tag on every answer tells you which trade you got — the system never
trades consistency silently; it labels.** Cross-client visibility:
read-your-writes is immediate through your own daemon; another daemon's
writes appear at `final` reads always (the sync), at `local` reads within
the refresh cadence.

## 3. Verbs

| Verb | Params | Returns |
|---|---|---|
| `TXN` | `slot:{path,version,attempt}\|null` · `guards:[{path,cond,…}]` · `mutations:[{set/del,path,value}]` | `op` (op_hash) immediately |
| `PUT` | path, value, [guards] | sugar: slotless `TXN` |
| `CAS` | path, expect `(version,attempt)`\|`absent`, mutations | sugar: `TXN` slot on that lineage |
| `GET` | path, level `local\|final` | value + `(version,attempt)` + `as_of` + tier |
| `LIST` | prefix, [delimiter], level | keys with `(version,attempt)` + `pending` flag each |
| `INSPECT` | path | `final` + `provisional`(+`may_flip`) + `pending:[{op,phase,would}]` |
| `STATUS` | op_hash | the full ladder for one op (the *debugging* verb; workflows use `INSPECT`) |

- **`TXN` is the primitive** — one *contended* slot lineage, unlimited
  per-key guards (`absent · present · version_eq · value_eq`), unlimited
  atomic mutations. Transaction graphs: nodes are TXNs, in-edges are version
  guards on upstream keys; the whole graph inherits the fail-safe cascade.
  One-contended-lineage per op: multi-lock grabs are slot-on-A +
  guard-absent-B (race one, check the rest); use lock-ordering discipline
  under contention.
- **`INSPECT` is the recovery verb** — key-centric, so workers recover
  **statelessly**: `pending` lists every known not-yet-final op touching the
  key *with decoded intent* (`would: set→w1`) — complete for ops submitted
  through this daemon, best-effort for foreign in-flight until gossip
  delivers them.
- `(version, attempt)` doubles as a **fencing token**: monotone per key, pass
  it to downstream systems; a zombie's stale token folds `stale` here and is
  refused there.

## 4. Data model

A **flat map**: path → opaque value bytes. Hierarchy is a **prefix
convention** (`/` by convention; `LIST` delimiter gives S3-style children) —
no directory objects, no mkdir, no dir metadata (the etcd-v2→v3 lesson,
adopted). Values are opaque to the store; applications may add an inner
encryption layer (DESIGN §7 layered encryption — inner-encrypted fields use
version-CAS, not `value_eq`). Multi-path atomicity = one `TXN`. No prefix
guards (per-key vocabulary only; LIST-then-guard-specific-keys is the honest
interim).

## 5. The canonical pattern: take → durable intent → leased idempotent work

The financial-grade worker flow (the reason this API looks the way it does):

```jsonc
// 1+2+3 in ONE atomic op: take the item, hold the lock, log the intent
{"jsonrpc":"2.0","id":1,"method":"TXN","params":{
  "slot":     {"path":"queue/items/42/lock","version":"⊥","attempt":0},
  "guards":   [{"path":"queue/items/42/state","cond":"value_eq","value":"pending"}],
  "mutations":[{"set":"queue/items/42/lock",  "value":"{w1, renewed:<hlc>}"},
               {"set":"queue/items/42/state", "value":"taken"},
               {"set":"queue/items/42/intent","value":"<amounts, dest, idem-key>"}]}}
```

1. **Take**: `lost` ⇒ someone else has it — next item, at network speed.
2. **The durability gate**: poll until `committed` (+`provisional:applied`) —
   **~2 RTT + one poll**. Only now perform external side effects: the intent
   (amounts, destination, idempotency key) survives any ≤f disaster and any
   worker can recover it. This gate is why the daemon drives the quorum
   itself — it sits on the critical path before every unit of paid work.
3. **The lease is reader-enforced — safety never depends on it.**
   Renewal = a cheap `PUT` of `renewed:<hlc>` from the *worker's own process*
   on a timer (never the daemon: renewal must die with the worker). Lapse =
   another worker judges `renewed` stale (application policy) and **steals at
   the observed lock version** — one CAS, race-safe. Safety comes from
   durable intent + idempotent work + fencing; the lease only prevents
   duplicate effort. There is **no store-side TTL, deliberately** — nothing
   in the store trusts wall-clock liveness.
4. **Stateless resume** (fresh machine, zero local state):
   `LIST queue/items/ (pending flags)` → `INSPECT` the interesting ones →
   `GET intent` → resume idempotent work fenced by `intent.version`.
   Exact resubmission is a content-addressed dup — never a double-apply.

Python-shaped sugar (client library, thin over the verbs):

```python
item = q.take("queue/items/42", lease=30)   # the TXN above, polled to committed
with item:                                  # renewal thread: PUT every lease/3
    do_idempotent_work(item.intent, fence=item.version)
    item.done()                             # TXN expect lock version → done, del lock
```

## 6. What is deliberately absent

No store-side TTL/lease expiry (reader-enforced lapse, above). No push/watch
(poll; local and cheap — watch *semantics* remains a DESIGN §17 design
question, and per the no-stubs rule nothing ships until it is designed). No
interactive multi-op transactions (the provisional pipeline + guard-graphs
are the model). No multi-slot atomic decree (one contended lineage per op).
No server-side arithmetic (read-CAS-retry; numeric guards are a §17
vocabulary question if ever demanded). Large values are out of scope
(chunking convention, DESIGN §17).

## 7. Provenance

Per PROTOCOL §6.2: ops are authored by the client daemon's identity; workers
multiplex through it, with worker labels living inside values (visible to
keyring holders, never to storage nodes). Per-worker attribution, if ever
wanted, is more client certs — not API surface.
