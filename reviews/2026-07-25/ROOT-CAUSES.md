# Root causes — the four patterns behind most findings

Most of the ~50 findings are instances of four patterns. Fixing the pattern closes the
cluster; fixing findings one at a time will leave the next instance to be found later.
This is the recommended work-plan ordering.

---

## RC-1 — "An artifact I hold is an artifact the quorum committed"

**The largest cluster.** The store's write path is *deliberately* unverified —
`put_op_raw`, `put_receipt`, `put_qc` all store whatever arrives, on the stated theory
that consumption verifies. `checkpoint.qc_final` even documents it: *"put_qc stores
whatever is gossiped in, so a forged / sub-quorum / wrong-epoch QC must never drive a GC
on a lie."*

That theory is sound, and most consumers honor it. The bug is the consumers that read
stored artifacts as **trusted input** rather than as candidates:

| Site | Reads as trusted | Finding |
|---|---|---|
| `compactor.PrevState.of` | "ops held below the cut ARE the retained set" | **F-2** |
| `client._committed_ops` | every control op, unconditionally | **F-1** |
| `client._bootstrap_barrier` | `retained` from un-QC'd `all_ops` | **F-7** |
| `gossip.Summary.of` | same raw projection | **F-7** |
| `store.append`'s fork detector | a stored op at `(author, seq)` as genuine | **K-4** |
| `acceptor._issue_receipt` | serve-from-store receipt as its own | **K-3** |
| `daemon._activate_one` | stored roster ops as authorized candidates | **K-1** |
| `client._pull_baseline` / `_pull_chain` | peer-supplied ops, unverified, unpurgeable | **IO-14**, **K-8** |

**The fix is one predicate, and it partly already exists.** `store.baseline_commitment()`
computes the correct projection (`covered ∖ dead`) and explains why in its docstring —
`PrevState.of` hand-rolls a wrong version instead of calling it.

**The subtle case worth thinking about separately (F-1):** treating control ops as
self-authorizing is *correct* for certs and roster ops, because they are root-signed and
the manager chain is their authority. It is *wrong* for checkpoint ops, whose authority
to place a fold barrier comes from the quorum QC, not from the author's signature. The
distinction "self-authorizing via the manager chain" vs "authorized by quorum decision"
wants to be explicit in the type system, not implicit in a call site. Every other
consumer of a checkpoint demands a verified QC; the full-history fold demands nothing,
which is why a full-history client and a bootstrapped client can derive byte-divergent
state from the same committed set.

**Suggested shape:** make the trusted/untrusted boundary structural rather than
conventional — e.g. a `Committed[Op]` wrapper that only a QC-verifying constructor can
mint, so a consumer that wants committed state cannot accidentally accept held state.
That converts this whole cluster into a type error.

---

## RC-2 — The horizon is supposed to be the sole GC authority for slot state

DESIGN §8 authorizes exactly one condition for voiding slot state — the accepted op's
`hlc` below the checkpoint horizon — and states the reason explicitly: *"GC-on-successor-commit
alone would be unsound: after every node forgets, a late contender could win a second QC
for a spent slot."*

Two code paths break the invariant from opposite ends:

- `acceptor.on_prepare`'s void rule voids on `acc is None` **or** below-horizon, so
  *envelope absence* is treated as equivalent to *below-horizon* (**C-1**).
- `daemon._adopt_one` produces envelope absence **without** advancing the horizon, by
  running `gc_checkpoint(overfull_drop())` in a txn with no `adopt_checkpoint`.

Neither is wrong alone. Together they are a safety violation under pure crash faults.

**Fix direction:** drop the `acc is None` disjunct — a missing envelope is a *fetch*
problem, not an amnesia trigger — and keep the horizon as the only authority. Then audit
for any other path that deletes from `ops` without advancing the horizon.

---

## RC-3 — The roster/epoch path never received the checkpoint path's rigor

The checkpoint adopt path is genuinely well-built: `slot_bound` (declared seq must bind
the slot actually won), `minter_authorized` (author held the capability at this
position), `qc_final` (epoch-matched, roster-verified QC). Each is a named pure predicate
with a docstring explaining the attack it stops.

The roster path has **none** of the three:

- no `can_author_control(op.author, ControlKind.ROSTER)` — **K-1**
- no slot binding, and `artifacts.slot_binding_ok` is dead code with zero callers — **F-5**
- `new_qc.verify(op.roster)` verifies against the roster *the op itself declares* — **K-1**
- `on_roster_accept` takes the possession frontier from the **requester**, not the op — **K-2**
- DESIGN §13's normative "nodes receipt a roster op only if `from_epoch` equals their
  current epoch" is unimplemented — **K-2**
- `RosterOp` validates odd/non-empty but not **unique** members — **K-12b**

**Fix direction:** the rules already exist as a template. Build the roster equivalent of
`checkpoint.py`'s named-predicate module and compose it the same way. Note the stated
reason the acceptor trusts its caller — *"so the acceptor stays free of the L6 control
vocabulary"* — is contradicted by ARCHITECTURE.md's own L6 matrix, which has nodes
registering `control/roster` (✓ in the node column); `daemon.py` already runs a
`ControlReducer` that observes `RosterOp`. The purity being protected does not exist, and
zero-knowledge concerns **data** ops and the keyring, not roster bodies.

---

## RC-4 — Exception handlers scoped to the one class the author had in mind, on loops that must never die

The package has no logging and no supervisor; long-lived threads are spawned bare with
`daemon=True`. So a handler that misses an exception class doesn't degrade — it silently
removes a subsystem for the process lifetime while the node keeps answering RPCs.

| Loop | Catches | Escapes | Finding |
|---|---|---|---|
| `daemon.run_periodic` | `StoreClosed`/`StoreBusy` | `CodecError`, `IndexError` from `Delta.decode` | **IO-3** |
| `client._refresh_loop` | `OSError` | `CodecError`, `CompactError`, `KeyError`, `HTTPException` | **IO-3** |
| `daemon.serve` | `sqlite3.Error`/`StoreError` | `IndexError` from arity-free wire decode | **IO-11** |
| `transports/http.dial` | `OSError` | `http.client.HTTPException` (not an `OSError`) | **IO-12** |
| `UnixServer._handle` | `OSError` | `RecursionError` from the codec | **K-9** |

Related and same-flavored: the **unbounded inputs at the two places bytes first arrive**
— `wire.read_frame` trusts a 4-byte length up to 4 GiB with no cap (pre-auth), and the
HTTP carrier's `resp.read()` is unbounded.

**Fix direction:** three separate mechanical changes, each cheap —
(a) a frame-size cap + socket timeouts at both byte-entry points;
(b) `codec.as_seq(v, n)` at the wire/gossip decode sites that currently index `p[1]`/`p[3]`/`p[5]`
raw (the helper was built for exactly this and just isn't used there);
(c) `except Exception` at the top of every immortal loop, with the cause surfaced —
which requires deciding on a logging story, currently absent package-wide.

The `lmsg` module already gets (b) and (c) right at every entry point, so there is an
in-repo model to copy.

---

## Suggested ordering

1. **K-1 + K-2** (roster escalation) — a WRITE-certed client contradicting DESIGN §15 is
   the only finding here that is an outright privilege escalation.
2. **C-1** (slot amnesia) — safety violation, pure crash faults, no evidence minted.
3. **C-2 + C-3** (floor gate deadlock + the missing RERECEIPT verb that would relieve it).
4. **RC-1** as a typed boundary, which closes F-1/F-2/F-7 and several K/IO items together.
5. **F-3, F-4** (compaction wedge + non-total cut tie-break) — both small, both affect
   whether checkpoint bytes are a pure function of the committed set.
6. **RC-4** as three mechanical sweeps.
7. Everything in [THE-UGLY.md](THE-UGLY.md), which is safe to interleave with the
   in-flight type-hygiene work since none of it is behavioral.
