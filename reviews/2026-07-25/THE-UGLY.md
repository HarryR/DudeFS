# THE UGLY — hygiene, drift, and debt

Nothing here breaks the protocol. All of it costs — mostly in reader trust, since this is a
reference implementation whose written rationale *is* the deliverable.

Status: **C** confirmed by re-reading · **R** reported with file:line · **U** unverified.

---

# 1. Structural debt

## H-1 · C — `artifacts.py` is a god-module, and still growing

1858 lines, 43 classes, imported by essentially every other module. Growth by absorption:

| Commit | artifacts.py lines |
|---|---|
| `eea69db~1` | 1114 |
| `eea69db` (Op hierarchy + control bodies in) | 1830 |
| `6be77f7` | 1800 |
| `b140785` (handlers/ dissolved) | 1836 |
| `6e4427e` (Slot extracted) | 1842 |
| `882cfad` (HeadEntry extracted) | 1858 |
| `7a403d4` (AddrRecord) | **1874** |

The trend continued *during* this review: three commits landed while it was being written
(`882cfad`, `7c5648a`, `7a403d4`) and the file grew another 16 lines.

Each individual move was well-argued. The cumulative result is that L1 holds four
separable concerns: field/error scaffolding, the `Op` decode-once hierarchy, the
coordination artifacts (`Receipt`/`Promise`/`QC`/`Watermark`/`FrontierBundle`), and the
compaction value types (`Baseline`, `RetainedEntry`, `Heads`, `covered`).

Note the pattern in the type-hygiene work: `Slot`, `Baseline`, and `HeadEntry` were all
**extracted as types but not relocated**, so the file grows with each hygiene win. This is
the highest-leverage split available while the retype is already in flight.

## H-2 · C — two stated-layering violations

ARCHITECTURE.md: *"The dependency rule is **strictly downward** — a layer may call only
layers beneath it."*

- **`fold.py:30`** (L5) imports `transports`, only to reach `Endpoint.from_record`
  (`fold.py:298`, `endpoints_of` at `:830`). `Endpoint` is a *value type* — an address
  record — not a carrier. It wants to live beside the other artifacts, leaving
  `transports/` as pure I/O.
  **Re-checked at `7a403d4`** ("AddrRecord owns the ENDPOINT wire codec; Endpoint stops
  escaping"): that commit split the wire codec into `AddrRecord`, so the call is now
  `Endpoint.from_record(rec)` rather than `from_record(*a)` — but `fold.py` still imports
  `transports` and still annotates `dict[bytes, list[transports.Endpoint]]`. **The finding
  stands**; the commit moved adjacent to it. Finishing the job means the fold holding
  `AddrRecord` and never naming `Endpoint`.
- **`transports/unix.py:8`** imports `wire` and calls `wire.frame`/`wire.read_frame`, so the
  transport knows the application framing — while `http.py` and `inproc.py` don't. Framing
  responsibility is split inconsistently across carriers.

## H-3 · C — cross-module private imports

- **`compactor_daemon.py:24`**: `from .client import ClientDaemon, _drive`. A second
  consumer means `_drive` is a real seam, not a private helper.
- **`cli/_util.py:138-139`**: `_floor_probe = floor_probe` with the comment *"Back-compat
  alias: test_demo imports `_floor_probe` from dudefs.cli"* — production code carrying a
  private alias to satisfy a **test's** import path, then re-exported in `cli/__init__.py`'s
  `__all__` (an underscore name in `__all__` is self-contradictory). There is no
  back-compat to preserve pre-1.0; the test should import `floor_probe`.

## H-4 · C — `cli/bootstrap.py` breaks the project's own error rule at a parse boundary

`Bootstrap.__init__` does `raw["manager_pub"]`, `bytes.fromhex(...)`, `int(raw["epoch"])`
directly on decoded JSON, so a hand-edited or truncated `bootstrap.json` raises a bare
`KeyError`/`ValueError`. PYTHON-CODESTYLE §4: *"The catch-all is a real guarantee: **no
decode/parse path may leak a bare `KeyError`/`ValueError`**."* It's also the textbook case
for the `TypedDict` rule — `_ep_json`/`_ep_from_json` traffic in bare `dict | None` for a
known-shape record, which §2 calls a smell.

Separately, **`bootstrap.py:64`** fabricates `Endpoint(UNIX, "/nonexistent.sock")` for a
missing endpoint. That makes "no address configured for this node" permanently
indistinguishable from "node is down" — the lossy collapse §4's *"say why, not what"* rule
forbids, and worse than `None` because it invents a plausible-looking value.

## H-5 · C — the toolchain is unpinned, in a project whose thesis is integrity

No lockfile, no `pyproject.toml`, no constraints file. `make install` pipes
`curl -LsSf https://astral.sh/uv/install.sh | sh` (unpinned, unverified, no checksum) and
then `uv pip install ruff ty pynacl coverage` with **no versions and no hashes** — and CI
runs that on every push. PyNaCl is the single runtime dependency and the entire crypto
substrate, installed floating. `ty` is currently 0.0.61, a pre-release: an unpinned upgrade
can turn the gate red or green with no code change.

For a system whose premise is cryptographic integrity on semi-trusted machines, the build
inputs are the least verified part of the repo.

## H-9 · C — `HeadEntry.dominates` reads like a total order and isn't

`artifacts.py:76` compares `seq` only, ignoring `op_hash`, so two heads at the same `seq`
with different hashes **mutually dominate**, and `cut_dominates` treats a cut holding
`seq=3` at a *different* op as "held".

Traced the callers: this appears **safe by virtue of the slot**, not by this predicate —
checkpoints are slotted one-per-seq by Paxos on `checkpoint_slot_tag(seq)`, and `select()`
additionally requires `not op.baseline.mismatched(self.ops)`. Worth a docstring sentence
saying so, since the function reads like a complete comparison. (F-8 is the case where the
one-per-seq assumption is itself weaker than advertised.)

## H-10 · C — leftovers from the in-flight retype

`wire._encode_heads` still destructures `for a, (s, h) in sorted(...)`, and
`test_checkpoint.py:158` still reads `cut[NODE.public][0]` — both work on a `NamedTuple` but
forgo exactly the readability the retype buys. Worth a sweep before the commit lands.

---

# 2. Code that lies about the code

## H-6 · C — `dudefs/__init__.py`, the package root, is badly stale

Cites *"DESIGN.md (rev 4)"* (it's rev 6) and states *"Milestones M0 …, M1 …, and M2 … are
implemented; the quorum client, gossip, and daemon (M3+) are **not yet**."* M7 is complete.
`__all__` exports only 7 modules, omitting `client`, `daemon`, `manager`, `quorum`,
`workerapi`, `cli`, `checkpoint`, `compactor`, `lmsg`, `link`, `tunables`. First thing a
reader imports; last thing anyone updated. (= **B7**)

## H-7 · C — every production timing value in `tunables.py` is annotated with the wrong number

The header promises *"a round-trip is 2 × the node-to-node one-way latency"*, but
`tunables.py:41` computes `int(2.222 * one_way_ms)`. So `_rtt(25)` is **55, not 50**:

| Constant | Comment says | Actually |
|---|---|---|
| `HEDGE_MS` | 50 | 55 |
| `FINALITY_POLL_MS` | 50 | 55 |
| `ROUND_TIMEOUT_MS` | (implied 200) | 220 |
| `RETRANSMIT_MS` | 500 | 550 |
| `REFRESH_MS` | 500 | 550 |
| `BLIND_DEADLINE_MS` | 5_000 | 5_500 |

Where `2.222` comes from is undocumented — it is exactly the magic number this module
exists to abolish, and it has been wrong since M4 (`59e9eda`). The sim regime's comments
happen to be correct (`_rtt(2) == 4`).

Also `tunables.py:37`: `_REFRESH_RTTS` is documented as *"the AUDIT CADENCE the compaction
cut-lag W trails (DESIGN §12)"* — but ACCUMULATOR.md §2/§7 explicitly **retires** `W`
(*"There is no `cut ≤ F − W`, no cut-lag tunable"*).

## H-8 · C — a refactor commit's headline is factually wrong

`b140785` — *"dissolve dudefs/handlers/ — a lone module-dir in a flat package"*. At its
parent commit `dudefs/` contained **three** directories: `cli/`, `handlers/`, and
`transports/`. The commit *body*'s real rationale (*"down to ONE file doing very little"*)
is sound. Minor — but in a project where the written rationale trail is the artifact, the
headline is the part that gets quoted later.

---

# 3. Documentation drift

The doc set is ~578 KB of markdown against ~476 KB of production Python — more prose than
code. Credit where due: the *protocol* docs are maintained. The `state_root` → `state_acc`
supersession, for instance, landed fully in both code and DESIGN/PROTOCOL (grep finds no
`state_root` anywhere). The drift is concentrated in the **code-adjacent** docs: layouts,
command tables, and status claims.

## HIGH drift

| ID | Status | Site | Drift |
|---|---|---|---|
| **B1** | R | `README.md:65-67` | Names `dudefs/handlers/{data,control}.py`, deleted in `b140785`. `data.decode` → `artifacts.py:495 DataOp.read_txn`; `evaluate`/`_eval_guard`/`EvalResult` → `fold.py:160/168/154`; `Opaque`/`OpaqueReason` → `artifacts.py:1396,1405`. |
| **B2** | R | `README.md:81-82` | Names `transports/memory.py` and `sim/`, both deleted (`80efa0d`, `c2ebd4a`). Real files: `tests/_carrier.py`, `_personas.py`, `_drive.py`. Actual `transports/` = `__init__, base, http, inproc, unix`. |
| **B3** | R | `README.md:80` | Names `cli.py`; now the package `dudefs/cli/{__init__,_args,_util,bootstrap,client,compactor,main,mgr,node}.py`. |
| **B4** | C | `README.md:26` | Claims **"223 tests green"**; actual is **352** test methods (verified: `grep -c '    def test' tests/*.py` → 352). |
| **B5** | R | `README.md:99-103` | **Every CLI example but one is wrong.** `dude init` → `dude mgr init`; `dude cert issue --client <pub>` → `dude mgr client authorize <pubkey> <pop>` (no `cert` verb, no `--client`, `pop` is a required positional); `dude wheres` → `dude client wheres`; `dude recover` → `dude mgr recover --dwell … --i-understand-data-loss`. Only `dude set my/key value` is correct. |
| **B6** | R | `README.md:57-83` | The "Layout (mirrors ARCHITECTURE.md)" block omits 8 modules + 4 transports: `checkpoint.py`, `compactor_daemon.py`, `link.py`, `lmsg.py`, `errors.py`, `tunables.py`, `__main__.py`, `transports/{base,http,inproc,unix}.py`. |
| **B7** | C | `dudefs/__init__.py:3,8-10` | See **H-6**. |
| **B8** | R/U | `COVERAGE-BASELINE.txt` | Lists 9 modules that no longer exist (`cli.py`, `handlers/*`, `sim/*`, `transports/memory.py`, `vendor/__init__.py`) and omits 14 that do. `Makefile:60-65` cites this file as the coverage-ratchet floor, so the per-file "missing lines" columns are unusable and `TOTAL 4124 / 93%` is stale. *(Numeric total UNVERIFIED — coverage was not run.)* |
| **B9** | R | `CLI.md:113-116` | **False trust-model claim.** Says `node genesis` authors "the founding `Roster` op on-chain … never a seeded list to be trusted." Reality: `manager.py:297-309` authors only a `Cap.STORE` cert + optional ENDPOINT, then writes `roster_seed` **local meta**, and `_refold` falls back to it. At n=1 the roster **is** a seeded list, and `cli/bootstrap.py:35` ships roster pubkeys in `bootstrap.json`. Contradicts `CLI.md:300-301` in the same document. **This one is load-bearing — see IO-2.** |
| **B10** | R | `CLI.md:293-295` | `bootstrap.json` schema *and* producer both wrong. Documented `{manager_pub, epoch, peers: [addr]}` from `m init`/`m node add`; reality `{manager_pub, epoch, roster: [{pub, ep}], control_ops: [hex…]}` from `dude mgr bootstrap` to stdout. |
| **B11** | R | `CLI.md:217,207-208,290-291` | The documented `node serve --dir ./n1` invocation **fails**: `--listen` is `required=True` and `--store` does not exist anywhere in `dudefs/`. |
| **B12** | R | `ARCHITECTURE.md:100` | Worker verb list wrong in both directions. Documented `GET/PUT/CAS/DEL/TXN/WATCH/STATUS`; reality `TXN, PUT, CAS, GET, LIST, INSPECT, STATUS`. `DEL` isn't a verb (`dude del` sends `TXN` with `{"del": path}`); `WATCH` doesn't exist and is *forbidden* (IMPLEMENTATION.md:97, CLIENT.md:183); `LIST` and `INSPECT` are undocumented. |
| **B13** | R | `ARCHITECTURE.md:72-96` | **The L6 `PayloadHandler` layer no longer exists** — no `PayloadHandler`, no `handles` selector, **no registry** (zero grep hits). `decode` is a method on the op class, `evaluate` a free function, and "node registers no data handler" is now enforced by `isinstance(op, DataOp)` narrowing plus `ControlReducer` ignoring non-`ControlOp`. ARCHITECTURE:3 calls this *"the load-bearing pattern"* and :94 grounds the zero-knowledge argument in it ("a node build simply contains no data handler and no keyring") — that now describes a type test, not a build. **Needs a rewrite, not a rename.** |
| **B14** | R | `MANAGER.md:29-38` | The whole command table is pre-rename and **6 verbs don't exist at all**: `dude cert issue/revoke`, `dude compact`, `dude verify`, `dude evidence list/eject`, `dude node remove`, `dude recover --fence` (real flags `--dwell` + `--i-understand-data-loss`), `dude watch`, `dude log`. `MANAGER.md:3` hedges "command names are a sketch", but `README.md:44` points readers here as *the* CLI reference. |

## MEDIUM drift

| ID | Status | Site | Drift |
|---|---|---|---|
| **B15** | R | `CLI.md` | Tags **14 implemented verbs as PROPOSED** (`node genesis`, `node replace`, `node list`, `node endpoint add/remove/set/list`, `client list`, `node serve`/`status`, `client init`/`serve`, `compactor init/run/once`). Only `log compact` is genuinely unimplemented. Conversely `compactor status` and `mgr bootstrap` are implemented and **undocumented**. |
| **B16** | R | `CLI.md:266-268` | Says "nothing authors real checkpoints in production" — `compactor_daemon.CompactorDaemon` does, driven by `dude compactor run/once`, with 8 tests. |
| **B17** | R | `CLI.md:16-17,197` | Names `state.json` + `control.log`; reality `manager.py:95` → `("control.db", "root.key")`, and the view is re-folded, not snapshotted. |
| **B18** | R | `IMPLEMENTATION.md:45-67` | The "mirrors ARCHITECTURE 1:1" tree is 5 entries wrong (`vendor/ed25519.py`, `handlers/*`, `cli.py`, `transports/memory.py`, `transports/tcp.py` — which never existed; `sim/harness.py`) and omits 10 existing modules. |
| **B19** | R | `IMPLEMENTATION.md:9,84,85` | Claims dev deps **`pytest` + `hypothesis`** — neither is installed or imported (zero grep hits; `Makefile:58` runs `unittest discover`). "Property tests via hypothesis strategies" are hand-rolled seeded generators in `tests/_builders.py`. Also still claims a vendored `ed25519.py`; the runtime dep is PyNaCl. |
| **B20** | R | `IMPLEMENTATION.md:93` | The kernel LOC budget is ~2.4× off ("a kernel under ~1.5k LOC, POC total ~4-5k" vs `dudefs/` ≈ 11k). The doc makes this a live tripwire (*"if it grows materially beyond that … find out which"*), so it wants an **answer**, not a number bump. |
| **B21** | R | `IMPLEMENTATION.md:102-108` | The §9 "definition of done" runbook is entirely stale: `--root`, `node spawn`, `tcp:` carrier, `cert issue --client`, a `dudefs-client` binary, and a raw `{"verb":…}` newline protocol (the worker API is JSON-RPC 2.0). |
| **B22** | R | `README.md:44` | Says M7 is "WP1-3 ✅ · WP4 demo pending"; WP4 landed at `836dc61` as `tests/test_demo.py` (4 tests). |
| **B23** | R | `PROTOCOL.md:34,68` | Documents the removed `deps` mechanism (`59f0427`). `RejectReason` has no `UNKNOWN_DEP` and has four members PROTOCOL.md omits (`EQUIVOCATION_GUARD`, `BELOW_HORIZON`, `NOT_A_MEMBER`, `STALE_ENVELOPE`). |
| **B24** | R | `WHITE-BOX-AUDIT.md:13,22,26-27` | Cites `sim._raw` (×45) — the `Sim` class is deleted, so that row's regression contract is **void**; lists `ChainStore._write_hw`/`_write_attested` as blessed *private* access when both are public `WriteTxn` methods; points at `dudefs/sim/` as the home of test infrastructure. |
| **B25** | R | `MANAGER.md:10,46` | Documents `--sign-only` / `submit <file>` (offline-root courier) and `--resume`; none exist in `dudefs/cli/`. |
| **B26** | R | `CLI.md:138-141,210,256-258,226,292` | `node add` documented as "one or more" endpoint positionals; `cli/mgr.py:302` is `nargs="?"`. Cites `manager.node_spawn` (real name `mint_identity`). Calls `client status` PROPOSED (implemented, but reads the local store, not the worker `STATUS` verb). Says the worker sock derives from `--dir`; `_args.py:15-16` returns a cwd-relative `"worker.sock"`. |

## LOW drift

| ID | Site | Drift |
|---|---|---|
| **B27** | `CLI.md:1,8,261-263` | Calls the binary `dudefs`; `cli/main.py:16` sets `prog="dude"`. |
| **B28** | `ARCHITECTURE.md:25,30-33,51-54,64-65` | Stale symbols: `Checkpoint`/`Evidence` (real: `CheckpointOp`; evidence is five `store.py` classes), `gossip.on_receive` (real: `Summary.of`/`Delta.owed`/`Delta.apply`), a `Clock` type that doesn't exist, `ChainStore.checkpoints()`, `Quorum.read/submit/recover/await_final` (real: `Commit`/`Finalize` with `start()`/`feed()`), `Fold(handlers)`/`ControlReducer(handlers)` (neither takes handlers). |
| **B29** | `TRANSPORT.md:49,55` | `Link(sk, self_pub, to_pub, endpoint)`; `link.py:17-24` takes three fields and no raw seed. `:55` omits `transports/inproc.py` and `base.py`. |
| **B30** | `CLIENT.md:110` | Names the `STATUS` param `op_hash`; `workerapi.py:318` reads `p["op"]`. |
| **B31** | `CRYPTO.md:178,186` · `ACCUMULATOR.md:267` · `README.md:4-7` | CRYPTO.md still lists the vendored oracle and the "CI no-native lane", contradicting `CRYPTO.md:30,167` in the same file. ACCUMULATOR says `Checkpoint.state_acc` (real: `CheckpointOp`). README's companion list omits CLI.md, TRANSPORT.md, and ACCUMULATOR.md — the last self-declared normative. |

### A governance note

ACCUMULATOR.md opens *"Status: normative (ratified). Supersedes … DESIGN §12"*. So normative
authority is now distributed across documents with an override relation, while README states
only *"if code and documents disagree, the documents win"*. Worth one line somewhere saying
which document wins when **documents disagree with each other** — the `W` retirement (H-7)
is a case where a retired concept survived in a comment precisely because the override
wasn't propagated.

---

# 4. Vacuous and tautological tests

Not "the suite is bad" — see [THE-GOOD.md](THE-GOOD.md), it is above average. These are the
specific assertions that would survive deleting the code they test.

| ID | Site | Problem |
|---|---|---|
| **A15** | `test_compaction.py:895-897` | Textbook: `commit = A.retained_commitment(cr.retained)` then `assertEqual(A.retained_commitment(cr.retained), commit)`. Passes for `return {}`. **(verified)** |
| **A16** | `test_lmsg.py:108` | `assertEqual(tag, C.screen_tag(B, sealed))` where `tag` came *out of* `seal_request`, which computed `screen_tag(to_pub, sealed)`. Rewrite `screen_tag` to ignore `sealed` and every assertion in the file still passes — including `test_wrong_tag_drops_before_the_ecdh`. That variant turns the hint into a static per-node fingerprint (passive linkability, forgeable forever), collapsing the TRANSPORT §3/§4 free-drop rung. **There is no KAT for `screen_tag`.** **(verified)** |
| **A9** | `test_relay.py:33-38` | Validates a **test-local re-implementation** of the finality rule (`sorted(floors, reverse=True)[quorum-1]`), and every finality claim in the file asserts against the copy. Change production to `floors[0]` — the classic "one lying node finalizes everything" bug — and the file is blind. |
| **A10** | `tests/_drive.py:335-342` | B2 (durability) is guaranteed by the same transaction that produces the data it's derived from: `on_accept` does `put_op_raw` + `_issue_receipt` in **one** write txn, so `holders >= quorum` holds by construction. `test_fumbling.py:286` cites this as proof. |
| **A11** | `_drive.py:227`, `test_daemon.py:986` | The invariant threshold is computed with the production function under test — `assertEqual(nd.quorum, A.quorum_size(len(new)))` against `daemon.py:400`'s `quorum_size(len(op.roster))` is literally `f(x) == f(x)`. If `quorum_size` returned `1`, every B1/B2 check still passes. |
| **A13** | `test_chaos_compaction.py` (whole file) | **Not chaos.** No loss/dup/partition/persona; the header concedes *"No commits are driven here"*; `drv.adopt_checkpoint(...)` writes the baseline straight into the store, bypassing the checkpoint op, the QC, `CheckpointView`, and `_RULES`; `drv.gossip_round()` is the **test's** anti-entropy, not `daemon.gossip_round`. |
| **A14** | `test_compaction.py:1039-1041` | The comment says *"load-bearing: WITHOUT the dead mask the GC'd node re-pulls `first`"*, but the call omits the **test helper's** `dead` parameter. Production `daemon._baseline_ops_for` could drop `and o.op_hash not in dead` and the suite stays green. |
| **A17** | `test_quorum.py:154-157` | The split-vote assertion permits the behavior it claims to forbid: `assertIn(qc.op_hash, {opA, opB, mine})` with `Committed` allowed. Break `_choose_and_accept`'s "MUST re-propose the highest accepted op" rule — the single-decree violation — and it still passes. `TestSingleDecree` computes the correct choice *in the test* rather than exercising the client's chooser, so it doesn't cover it either. |
| **A20** | `test_compactor_daemon.py:149-156,216,283,330` | Asserts cluster-wide adoption by reading `fx.nodes[0]` only; its A4 "independent oracle" is the same function (`compact_genesis` *is* `compact(PrevState({},[],{}), …)`); and `assertIsNone(fx.comp.compact_once())` cannot distinguish "correctly skipped" from "never works" — `compact_once` returns `None` for four reasons. |
| **A21** | `workerapi.py:339-351`, `test_wire_goldens.py:184` | `-32700/-32601/-32602/-32603`, notifications, and batches are genuinely tested (good) — but `-32600` is untested, and `except (KeyError, ValueError, TypeError)` reports a genuine internal bug to the caller as `-32602 invalid params` with no test pinning the boundary. `assertTrue(required <= set(result))` is a subset check, so the result key-set isn't pinned in the other direction. |
| **A22** | `test_daemon.py:798` | `assertIsNone(tx.get_op(first.op_hash))` is vacuous — the only peer already deleted it and `f.peers == [d]`, so `f` cannot acquire it regardless. The real risk (a lazy-GC peer re-serving dead envelopes via production `_baseline_ops_for`) is never exercised. |
| **A23** | `test_daemon.py:36` | `delta_ms=BIG` (~16 min) plus `clock=lambda: 100` in **every** daemon test disables the freshness/skew gate for the whole file except `:136-150`. |
| **A24** | `test_compaction.py:273` | `compactor.verify_state_acc(...)  # no raise` — a test with no assertion; passes if the function becomes a no-op. |
| **A25** | `test_compaction.py:722`, `test_fumbling.py:246` | `assertTrue(tx.append(o))` counts `DUP` as success — `AppendResult.__bool__` is `status in (OK, DUP)`. |
| **A26** | `test_compaction.py:237` | `assertNotIn(key, sealed)` asserts confidentiality by **substring absence**; any encoding-preserving leak passes. |
| **A27** | `test_cli.py:56` | "authors a *valid write* cert" asserts only `cert.subject` — not `caps`, not epoch. `caps=[]` or `Cap.COMPACT` passes. |
| **A28** | `test_crypto.py:57,95,127`, `test_quorum.py:277` | Pure `f(x) == f(x)`. Harmless (real KATs sit nearby) **except** that `prf_tag` has no KAT of its own. |
| **A29** | `test_codec.py:60-62` | The collision branch is dead by construction. Separately `codec.as_int/as_bytes/as_seq/as_dict` — documented as *"where malformed wire input is caught"* — have **no wrong-arity/wrong-type tests**, and `as_seq`'s arity check is what stops a 7-field L_msg envelope. |
| **A30** | `test_daemon.py:843,865` | The "PRODUCTION PATH (not a hand-planted receipt)" claim is qualified: it forces the equivocation with `Ballot(1, b"x")` — a ballot no production proposer can emit — via two direct `d.acc.on_accept` calls, skipping `serve`/`dispatch`/the peer gate. |
| **A31** | `cli/_util.py:138-139` | Production code shaped by a test's import path. Same item as **H-3**. |
