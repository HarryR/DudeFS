# THE BAD — real defects

Mechanism + concrete failure scenario for each. One-line index in [TRIAGE.md](TRIAGE.md);
patterns in [ROOT-CAUSES.md](ROOT-CAUSES.md).

Status legend: **C** confirmed by re-reading the code · **R** reported with file:line by
the subsystem reviewer · **U** unverified suspicion.

---

# 1. Roster seizure — the worst finding in this review

**Three of the five reviewers found this independently**, approaching from
authorization (crypto), slot binding (fold/compaction), and test coverage. That
convergence is why it leads.

## K-1 · HIGH · C · `daemon.py:385-401` — roster activation is unauthorized and self-ratifying

`_activate_one` selects activation candidates with only:

```python
if isinstance(op, RosterOp) and op.recovery is None and op.from_epoch == e
```

then activates on `old_qc.verify(self.roster) and new_qc.verify(op.roster)`.

Three checks are absent, and the third is fatal:

1. **No authorization on the author.** There is no
   `can_author_control(op.author, ControlKind.ROSTER)`. Any author's roster op is a candidate.
2. **No slot binding.** No `op.slot_tag == roster_slot_tag(op.from_epoch)`, so ops
   declaring the same `from_epoch` can contend *different* slots — DESIGN §13's "at most
   one change can ever activate out of epoch `e`" stops binding.
3. **The new half is verified against the roster the op itself declares.**
   `new_qc.verify(op.roster)` — so an op declaring `roster=[attacker_key]` needs
   `quorum_size(1) == 1` signature: its own.

### Attack

An ordinary `Cap.WRITE`-certed client:

1. Passes the peer gate — `daemon._peer_authorized` admits anyone holding `Cap.WRITE`.
2. Authors `RosterOp(from_epoch=e, roster=[its own key], sync_frontier={})`.
3. Drives PREPARE/ACCEPT to a genuine old-roster majority QC at epoch `e`. `on_submit`
   and `on_accept` are **deliberately ungated on the op's author** (`acceptor.py:186-194`
   explains why — the gate authorizes the *requester*, never the artifact author).
4. Self-signs the new-roster half via `on_roster_accept` with `sync_frontier={}` (see **K-2**).
5. Gossips op + both QCs.

Every honest node's next `maintenance()` sets `self.roster = [attacker]` and bumps its
epoch. Minimum outcome: the cluster is permanently wedged, because clients exclude the
unauthorized roster op from `rosters_by_epoch` so no post-bridge QC ever verifies.

This contradicts **DESIGN §15** verbatim: *"compactor compromise can mint
wrongful-but-auditable checkpoints, **never roster or cert changes**."*

### Why it shipped

Compare the checkpoint adopt path, which gets all three right and documents each: `slot_bound`
(*"else an adversary wins slot 0 yet claims seq=5 in the body"*), `minter_authorized`
(*"never adopt an unauthorized minter's checkpoint"*), `qc_final` (*"put_qc stores whatever
is gossiped in, so a forged / sub-quorum / wrong-epoch QC must never drive a GC on a lie"*).
The rules exist, well-named and well-reasoned. They were simply never written for rosters.

## K-2 · HIGH · C · `acceptor.py:417-434` — the possession barrier trusts the requester

`on_roster_accept` takes `sync_frontier` and `new_epoch` **from the wire request**
(`RosterAcceptReq`), never cross-checked against `op.sync_frontier` / `op.from_epoch + 1`
— the *signed* fields the op carries. The op isn't even checked to *be* a `RosterOp`.
`holds_frontier({})` is vacuously true (the `for` body never runs), so DESIGN §13's
data-possession barrier is bypassed by omission.

DESIGN §13's normative *"Nodes additionally receipt a roster op only if its `from_epoch`
equals their current epoch"* is also unimplemented — `grep from_epoch dudefs/acceptor.py`
returns nothing.

Finding 23 fixed this on the **manager** path (`manager.py:481-490`). The acceptor, one
layer down, still trusts its caller.

### The stated rationale is worth arguing with

The docstring gives the reason outright:

> The caller (a manager, L4+) supplies `sync_frontier`/`new_epoch` decoded from the op
> body, so the acceptor stays free of the L6 control vocabulary.

That is a deliberate layering-purity choice and it is the direct cause of the hole. But
**ARCHITECTURE.md's own L6 deployment matrix has nodes registering `control/roster`** (✓ in
the node column), and `daemon.py` already runs a `ControlReducer` that observes `RosterOp`.
The vocabulary being avoided is already in the node build. Zero-knowledge concerns **data**
ops and the keyring — not roster bodies. The purity being protected does not exist.

## K-12b · LOW · C · `artifacts.py:934-937` — roster members are not checked for uniqueness

`RosterOp._from_body` validates odd and non-empty but not **unique**, so `roster=[k,k,k]`
lets one key occupy three bitmap indices and satisfy `QC.verify`'s majority test alone.
The cheapest route to K-1 step 4 even without the n=1 trick.

## A1, A2 · HIGH · C — and no test could have caught any of it

Every test passes a *truthful* `sync_frontier`: `test_control_plane.py:380,385,461` reuse
the same `sf` the op was built with; `test_chaos_compaction.py:108` builds with
`sync_frontier={}`; `test_fumbling.py:187-225` passes `{}` for both. **No test anywhere
supplies a short or empty frontier to a node that has not caught up and asserts refusal.**
The suite's own possession-barrier test (`test_control_plane.py:366`) cannot see the hole
because it only ever tells the truth.

Likewise all four `TestJointCertActivation` tests plus `TestLearnerOnboarding`
(`test_daemon.py:973-1111`) feed a **manager-authored** roster op, so the missing authz
check is structurally invisible.

This is the F23/F24 bug class — *"authored but never driven"* — recurring exactly one
layer below where it was fixed.

---

# 2. Consensus safety and liveness

## C-1 · HIGH · C — envelope GC induces durable slot amnesia ⇒ two QCs for one slot

Every link re-read and confirmed:

- **`daemon.py:333-336`** — when `select()` defers, `_adopt_one` runs
  `tx.gc_checkpoint(stale)` in a write txn with **no `adopt_checkpoint`, no
  `advance_horizon`**. Confirmed: `advance_horizon` is reachable *only* via
  `adopt_checkpoint` (`store.py:767`), whose only callers are `daemon.py:341` and
  `compactor_daemon.py:101`.
- **`checkpoint.py:117-131`** — `overfull_drop()` returns
  `[o.op_hash for o in self.ops if o.author in overfull and covered(o, bl.cut)]`: that
  author's **entire** below-cut set, winners included ("reload beats reconcile"), keyed on
  an **unadopted** candidate's cut.
- **`store.py:785-795`** — `gc_checkpoint` deletes from `ops`, `receipts`, `qcs`. It never
  touches `slot_state`.
- **`acceptor.py:229`** — the void rule fires on `acc is None or acc.hlc < tx.get_horizon()`.
  The **`acc is None` disjunct turns envelope absence into slot amnesia**, and on the
  promise-granting path (`ballot > s.promised`) the cleared state is durably written by
  `tx.write_slot`. (On the Nack path it isn't — the txn commits empty.)
- **`acceptor.py:281`** — the `BELOW_HORIZON` backstop also cannot save it, because the
  horizon was never advanced.

### Failure scenario (n=3, q=2, all crash-fault, no Byzantine actor)

1. Client proposes CAS op X on tag T. Nodes 0 and 1 accept at ballot `b1=(1,pA)`; X is
   **decided** (QC assembled).
2. Node 1 has never adopted a checkpoint, so `tx.get_horizon() == HLC(0,0)`.
3. Node 1 sees committed checkpoint C, cannot verify one author's baseline in full ⇒
   `select()` returns `None` ⇒ `overfull_drop()` flags X's author ⇒ `gc_checkpoint`
   **deletes X and node 1's receipt for X**.
4. A second client PREPAREs T at `b2=(2,pB)`. Node 1: `tx.get_op(s.accepted_op)` → `None`
   ⇒ accepted state cleared and **durably written**. Node 2 never accepted X. Both promise
   a fresh slot.
5. `_choose_and_accept` sees `best is None` ⇒ proposes the second client's op Y. Nodes
   {1,2} accept Y at `b2` ⇒ **QC for Y**.

Two valid QCs for slot T, no equivocating node, and **no evidence fires**: `DOUBLE_VOTE`
requires the *same* ballot and `b1 ≠ b2`; the receipt for X was deleted; the issuance row
for `(X, b1)` survives so `SEQ_REUSE` sees nothing.

DESIGN §8 authorizes exactly one void condition and states the reason: *"GC-on-successor-commit
alone would be unsound: after every node forgets, a late contender could win a second QC
for a spent slot."* RESILIENCE §3.7 marks CAS exclusion violable-with-proof only for a
Byzantine node; here it is violable **without** proof under pure crash faults.

**Note:** the same line also voids at `hlc == horizon` on the ordinary adopt path, which
DESIGN §8 explicitly forbids (*"void/ignore only **strictly below** F… voiding at equality
could discard a live accept — a safety hole"*). That instance is measure-zero but it's the
same defect.

## C-2 · HIGH · C — the floor gate precedes the idempotent-re-accept exemption ⇒ permanent deadlock

`acceptor.py:261-282`: `_skew_reason` (which returns `BELOW_FLOOR` when
`op.hlc < self.floor(tx, now_ms)`) is evaluated **before** the
`s.accepted_op != op.op_hash` exemption. So a verbatim re-ACCEPT of the op a node already
accepted is refused once δ has elapsed. The `BELOW_HORIZON` guard below it *has* the
exemption and its comment states the intent — *"Skipped for an idempotent re-accept of the
SAME op, so a RERECEIPT is never blocked"* — which the gate above it defeats.

### Failure scenario

1. Compactor authors checkpoint `C_N` at `hlc=T` on `checkpoint_slot_tag(N)`. PREPARE at
   `b1` succeeds; ACCEPT reaches only node 0 before the compactor is partitioned. Node 0
   durably holds `(promised=b1, accepted=(b1, C_N))`. Sub-quorum ⇒ no QC.
2. δ elapses (`DELTA_MS = 60_000`). Every node's floor is now above `T`.
3. Next pass: `_committed_frontier` returns `best_seq + 1 = N` (no committed checkpoint at
   N), so `plan.seq = N` again — the compactor is pinned to the same slot.
4. PREPARE at `b2`: node 0's promise reports `C_N` accepted at `b1`. `C_N.hlc ≥ horizon`,
   so the void rule does not fire. PROTOCOL §1.3 step 5 **forces re-proposal of `C_N`**.
5. ACCEPT(T_N, b2, C_N) ⇒ **every** node, node 0 included, returns `Rejected(BELOW_FLOOR)`.
   No receipts ⇒ deadline ⇒ escalate ⇒ `Failed(EXHAUSTED)` after `MAX_ROUNDS=8`.
6. Repeat forever. The only escape is the horizon rising above `T`, which requires a
   *committed* checkpoint. **Circular — unrecoverable without DB surgery.**
   `on_recovery_fence` only bumps the epoch; `activate_epoch` leaves slot state untouched.

The same shape hits `roster_slot_tag(e)`, blocking every roster change out of epoch `e`
until the horizon passes it — bounded by the checkpoint interval, unless compaction is
already deadlocked, in which case both are permanent. CAS tags escape via the `attempt`
counter; `roster_slot_tag` and `checkpoint_slot_tag` have no attempt component.

## C-3 · MEDIUM · C — `RERECEIPT` is unreachable, so the idempotency guarantee is not delivered

`Acceptor.on_rereceipt` exists at `acceptor.py:370` and correctly skips the skew gate, but
there is **no `RereceiptReq` in `node.py`'s `Request` union, no `NodeAPI` method, no
`wire.py` tag, and no production caller** — every other mention in `dudefs/` is a comment.

So PROTOCOL §0 (*"Every verb is idempotent. Retry anything, verbatim… re-requests re-yield
the same signed artifacts"*) and RESILIENCE §1.2 (*"Node dies after persist, before reply →
Client retries; **the identical receipt is re-issued**"*) are both false once the floor
passes `op.hlc`. A quorum's worth of durably-accepted receipts can sit on disk and be
unassemblable. This is also the escape hatch **C-2** needs.

---

# 3. The evidence system is sound but two kinds are production-dead

The README claims all five evidence kinds are sound **and complete**. Soundness holds —
no reviewer could construct an honest-node conviction. Completeness does not.

## A3 · HIGH · C — `FLOOR_PERJURY` can never fire in production

`daemon.py:409`: `wms = observed_watermarks or []`. `run_periodic` calls
`self.sync_once()` **with no arguments** (`daemon.py:450`), `sync_once` passes its
`None` straight to `evidence_cycle`, and no production caller ever populates it. Verified:
the only `WatermarkReq` sender is the client's `Finalize` (`quorum.py:504`), which never
feeds them back to a node.

So `detect_floor_perjury([])` and `detect_seq_reuse([])` always run against an empty
watermark list. A running cluster **never mints FLOOR_PERJURY at all**, and the
watermark-collision half of `SEQ_REUSE` is equally dead. B3 accountability is a test-only
property; the only exercise is `test_daemon.py:900` passing `observed_watermarks=[wm]` by hand.

## A4 · HIGH · C — `LOST_COMMIT` has zero production callers

`store.detect_lost_commits` is defined at `store.py:865` and called from **nowhere in
`dudefs/`** — confirmed by grep. `evidence_cycle` deliberately runs three detectors and
not this one. The only callers are `test_fumbling.py:152,159`, which hand-supply
`recovery_epoch=1`, the checkpoint hash, and `frozenset()` — the three arguments no
production caller ever computes.

Consequence: a mistaken recovery destroys committed data with **no disclosure record**,
while the test asserting otherwise is titled *"the recovery op's cryptographic receipt of
the durability it broke."*

## A5 · HIGH · R — every evidence `verify()` is positive-only: 20 `assertTrue`, 1 `assertFalse`

No test feeds a **fabricated** proof to a `verify()` and asserts rejection. That matters
most for `FloorPerjuryEvidence.verify`'s ordering clause
`self.rcpt.issue_seq > self.wm.issue_seq` (`store.py:229`) — documented as the sole thing
separating a crime from legal behavior, and the entire content of finding 17. **Delete it
and no test fails**, yet any honest node becomes convictable by a hand-built proof. Same
for `ForkEvidence.verify`'s `a.verify_sig() and b.verify_sig()`.

The *detectors* have real negative tests. The **portable verifier a third party runs to
judge an accusation** has none — which is exactly the soundness half of the README claim.

---

# 4. State derivation: divergence and permanent loss

## F-1 · HIGH · C — the fold applies barriers from checkpoints that were never committed

`client._committed_ops` (`client.py:592`) admits **every** control op unconditionally
(`if o.is_control: out.append(o)`) while data ops must pass `_qc_ok`. Every other consumer
of a checkpoint demands a verified QC — `checkpoint.qc_final`, `compactor._committed_frontier`,
and the client's own `_bootstrap_barrier`. The full-history fold demands nothing: mere
presence plus `compact` capability places a barrier.

**Reachable with no Byzantine actor:** `CompactorDaemon._author_checkpoint` stores its
checkpoint op locally *before* driving the commit (`compactor_daemon.py:57`
`tx.put_op_raw(op)`). Lose the slot or fail the drive and the op exists, gossips, and never
gets a QC.

### Divergence

Key `k` is deleted below that orphan cut. A version-CAS on `k`'s tombstone anchor commits
above it.

- **Client B** (doesn't hold the orphan): tag matches `Slot(k, tomb_hash, 0)` ⇒ `APPLIED`,
  `k` live.
- **Client A** (holds it): the barrier deleted `k`'s tombstone and reset the key universe
  ⇒ expected tag is `Slot(k, ⊥, 0)` ⇒ `STALE`, `k` absent.

Byte-divergent live state from the same *committed* set — the one invariant the system
exists to guarantee. The same client's state also flips when it later GCs, because
`_bootstrap_barrier` *does* check the QC: full-history and bootstrap disagree.

**Aggravating:** `_authorized_cuts` applies neither `slot_bound` nor cut dominance, so a
`compact`-cap delegate can inject arbitrary cuts and re-stage everyone's walk (see F-9).

## F-2 · HIGH · C — `PrevState.of` calls "everything I hold below the cut" the retained set

`compactor.py:52`: `retained = [o for o in tx.all_ops() if covered(o, prev_cut)]`,
justified by the comment *"after adopt+GC the ops held below the cut ARE the retained set
(dead gone)"*. Nothing enforces that, and `_mut_meta`'s own docstring plus DESIGN §12
(*"The precondition … is asserted, not assumed"*) say it must be.

**The correct projection already exists and isn't used:** `store.baseline_commitment()`
(`store.py:495-501`) computes `covered ∖ cut_dead()` and explains why in its docstring.

**Reachability:** `CompactorView.of` puts only QC'd data ops in `committed`, so an op held
*without* a QC — a slot loser re-proposed via `put_op_raw`, or a `_pull_chain` fetch whose
`GetQCReq` returned nothing — never enters `universe`, is therefore never listed in `dead`,
and is never GC'd. One pass later it sits below `prev_cut` and `PrevState.of` feeds it to
`barrier_state` and `_mut_meta`, both of which replay mutations with **no guard evaluation
and no QC check**.

**Failure:** uncommitted CAS `X` on key `k` sorts above the real winner `W` in
`(hlc, author, seq, op_hash)` ⇒ `prev_barrier[k].version = X.op_hash` ⇒ `winners = {X}` ⇒
`W` is listed `dead` and **physically GC'd**, and `state_acc` commits `X`'s value. A
committed value is permanently lost, and nodes adopt happily because the `retained` digest
matches what the compactor claims. This is finding-13's bug re-entering through the `prev`
door instead of the band door.

## F-3 · HIGH · C — compaction wedges forever once an author's whole below-cut set is GC'd

`cut_at` (`compactor.py:74-85`) builds the cut **only from currently-held ops**, never
seeding from `prev_cut`.

Client A authors exactly one op; it is superseded, marked dead at checkpoint N, and GC'd
everywhere. Pass N+1: A contributes nothing to `committed`, so `cut_at` omits A entirely;
`cut_dominates(cut, committed_cut)` sees `new.get(A) is None` ⇒ `False` ⇒ `plan()` returns
`None`. Not "skip and retry later" — A never comes back, so **no further checkpoint is ever
authored**. Were `plan` bypassed, `compact()` raises `ValueError` instead.

This is the exact mirror of the possession-barrier wedge finding-11 already fixed
(*"an idle author's frontier head sinks below the cut, its superseded envelope is GC'd
everywhere"*). The cut is a per-author **pin** — it must be carried forward, never
recomputed from live holdings.

## F-4 · MEDIUM · C — `cut_at`'s tie-break is not total, so checkpoint bytes are arrival-dependent

`compactor.py:82` uses `if cur is None or o.seq > cur.seq`, and `store.all_ops` is
`SELECT raw FROM ops` with **no `ORDER BY`** (`store.py:383`). Forks — two signed ops at one
seq — are deliberately *not* rejected by the fold, so two compactors (or one across a
restart with different insertion order) produce a different `cut[author].op_hash` for the
identical committed set, hence different checkpoint bytes. **The compactor's output is not
a pure function of its input.**

Downstream this becomes an A4 break: the pinned hash is the only prev-linkage anchor above
the barrier, so the sibling fork's child at `cut_seq+1` folds `INVALID` for a bootstrap
client and valid for a full-history one. **Fix is one token:** max on `(o.seq, o.op_hash)`.

## F-5 · MEDIUM · C — `slot_binding_ok` is dead code

`artifacts.py:393` — **zero callers** in `dudefs/` *or* `tests/`; the only reference is its
own internal call to `expected_slot_tag`. So `RosterOp.expected_slot_tag` (`artifacts.py:926`)
is never enforced: `slot_tag` comes from the envelope, `from_epoch` from the body, and
`on_accept` only checks `op.slot_tag == tag` where `tag` is whatever the proposer sent.

Two roster ops both carrying body `from_epoch = 0` but envelope tags `roster_slot_tag(0)`
and `roster_slot_tag(9)` contend **different** slots, so B4's "at most one activates out of
epoch e" does not bind; both can gather old+new QCs, and `_activate_one` activates
whichever it sees first in arrival order ⇒ two nodes at epoch 1 with **different rosters**.
`checkpoint.slot_bound` enforces exactly this rule for checkpoints — it just isn't wired
for rosters or for the fold's barrier placement.

## F-6 · MEDIUM · C — `keyring_from_wraps` is unauthenticated and arrival-order dependent

`fold.py:84-97` iterates ops doing `masters[op.keyepoch] = k` with **no authorization check
on the `WRAP_SET` author** and no ordering rule; the caller passes `tx.all_ops()` (arrival
order), re-run after every sync.

- **Divergence:** any signed author gossips a `WrapSetOp` at an *existing* keyepoch sealing
  a bogus master to me. Depending on arrival order my `data_key`/`slot_secret` for that
  epoch is wrong ⇒ every op at that epoch folds `Opaque`/`STALE` while peers fold
  `APPLIED`. Two clients with identical op sets differ purely on arrival order.
- **Persistent DoS:** the sealed payload need not be 32 bytes; `EpochKeys.derive` →
  `blake2b(key=master)` raises `ValueError` above 64 bytes. Contained, but **permanent** —
  nothing drops the offending op and `_rederive_keyring` re-runs on every sync.

The docstring's *"same master across dup wraps → idempotent"* holds only if every wrap for
an epoch seals the same master.

## F-7 · MEDIUM · C — the retained projection is rebuilt from raw holdings in three places

`client.py:635-642` (`_bootstrap_barrier`), `gossip.py:65` (`Summary.of`), `store.py:495`.
DESIGN §12's rule is `retained = covered ∖ dead`, which tacitly assumes every held
below-cut op is committed. A client holding one uncommitted below-cut CAS reconstructs a
barrier with an extra or overwritten key ⇒ `verify_state_acc` raises `CompactError` ⇒
**every** `get`/`list`/`inspect` at any level fails, permanently. `checkpoint.overfull_drop`
is the existing "reload beats reconcile" remedy — but only nodes run it.

---

# 5. I/O layer

Diagnosis: the defects are not sloppiness. They are **handlers scoped to the one exception
the author had in mind, on loops that must never die**, plus **unbounded inputs at the two
places bytes first arrive**. See [ROOT-CAUSES.md](ROOT-CAUSES.md#rc-4) for the table.

## IO-2 · HIGH · C — the node daemon never reloads its roster

`daemon.py:110` sets `self.roster` from the constructor (i.e. `bootstrap.json`) and only
ever updates it in `_activate_one`, **in memory**. The acceptor deliberately does the
opposite for `epoch` (`acceptor.py:114-121`, commented *"finding 20: the DB is the single
source of truth"*).

After a restart following a roster change, `acc.epoch` is durable (say 2) while
`self.roster` is the seed's epoch-0 roster. `CheckpointView.of(..., roster=self.roster)`
with `epoch=self.acc.epoch` ⇒ `qc_final` requires
`qc.config_epoch == view.epoch and qc.verify(view.roster)` ⇒ an epoch-2 QC verified against
the epoch-0 roster always fails ⇒ **`select()` returns `None` forever**: the horizon never
advances and compaction never GCs. `_activate_one` fails identically, so the node never
follows another roster change. Both fail closed and **silent**; the node keeps answering
RPCs and `status()` reports nothing wrong.

Also a normative **CLI.md §7** violation: *"Only `manager_pub` is trusted … `epoch` and
`peers` are hints … the seed carries peer addresses, not roster identity (which is
trust-derived, not seeded)."* `bootstrap.py:34` emits roster identity and the node consumes
it as authoritative for QC verification. `fold.rosters_by_epoch` exists and the **client**
uses it correctly; the node does not.

## IO-3 · HIGH · R — one malformed gossip reply permanently kills a node's maintenance loop

`daemon.py:448-454` — `run_periodic` catches only `StoreClosed`/`StoreBusy`.
`sync_once` → `gossip_round` → `gossip.Delta.decode(env.body)` raises
`CodecError`/`ArtifactError`/`IndexError` on a malformed body; nothing catches them. The
thread dies. There is **no logging anywhere in the package** and no supervisor
(`cli/node.py:51` spawns it as a bare daemon thread).

A compromised or buggy roster member returns a signed envelope with a garbage DELTA body.
Every honest node that gossips with it loses gossip, checkpoint adoption, roster
activation, fence observation, evidence detection, and peer refresh — **permanently** —
while continuing to serve accepts and reads. The cluster looks healthy and silently stops
converging and stops minting evidence. `status()` has no liveness field to reveal it.

Same shape in the client: `client.py:546-552` `_refresh_loop` catches only `OSError`, so a
`CodecError`, a `CompactError` from `verify_state_acc`, a `KeyError` from
`_rederive_keyring`, or an `HTTPException` kills read-side sync forever — the daemon then
serves stale `local` reads with no error surfaced, **silently regressing finding 22**.

## IO-4 / K-7 · HIGH · C — no frame-size cap and no server-side timeout, pre-authentication

`wire.py:54-71` unpacks a 4-byte big-endian length and calls `_recv_exact(recv, n)` with
`n` up to 4 GiB, no cap, accumulating with `buf += chunk` (quadratic).
`transports/unix.py:34-60` never calls `settimeout` on an accepted connection, spawns one
unbounded thread per connection, and `listen(16)` is the only limiter. The whole frame must
be buffered **before** `lmsg` can gate it, so this is entirely pre-auth.

An unauthenticated peer opens N connections, sends `\xff\xff\xff\xff`, and trickles a byte
a minute. Each pins a thread forever and grows a buffer without limit. TRANSPORT.md §3
sells `to_hint` as *"a DoS floor"* — that filter runs **after** the frame is fully read.
The same unbounded read applies to the dialer, so a hostile roster member can OOM a
*client* daemon by replying with a huge length prefix.

## IO-1 · HIGH · R — `sync()` advances the finality frontier over a failed pull

`client.py:456-465` — `sync()` calls `_pull_chain` per head, then **unconditionally**
advances `_final_frontier` to `qfloor`. But `_pull_chain` (`client.py:493-497`) bails out
early and silently on any op it cannot fetch (`return  # gap we can't fill now`), and never
reports failure. So the frontier can move above ops the daemon does not hold.

Client B does `GET path level=final`. One head's chain has a hole (the serving node was
killed, or the op sits below a GC cut). The frontier still advances to the quorum-attested
floor; `_committed_ops(final_only=True)` folds a history with a hole; `get`/`inspect` answer
"absent" with `may_flip:false` — *"this absence IS final, it will never change"*. ~500 ms
later the refresh fills the gap and the answer **flips**. CLIENT.md §2.1 forbids exactly
this, and the advance is irreversible (`if qfloor > self._final_frontier`).

## IO-5 · HIGH · R — `_bootstrap_barrier`'s "I hold the full covered band" test is unsound

`client.py:627-628`: `if all(tx.get_op(h) is not None for h in ck.baseline.dead): return None`.
But `ck.baseline.dead` is only the **incremental** band since the previous checkpoint, so
holding it does not imply holding the whole covered band — and `all(...)` over an empty
`dead` is **vacuously true**.

A client bootstraps sparsely at checkpoint N (barrier path, correct). Checkpoint N+1
commits with a `dead` band the client holds in full — or with `dead == ∅`, which any
append-only window produces. `_bootstrap_barrier` now returns `None`, so the fold runs with
no barrier and, critically, **without the attempts sidecar**. `attempt` is derived by
replaying ops, so every below-cut key's `attempt` silently resets toward 0. CLIENT.md §3
promises `(version, attempt)` is monotone per key and safe to hand downstream; here a
zombie's stale token can compare equal again. No `verify_state_acc` runs on this path, so
it fails **silently**.

## K-3 · HIGH · R — a forged receipt served from the store blocks a chosen commit forever

`store.py:682-693` (`put_receipt`, no verification) + `acceptor.py:312-318`
(`_issue_receipt` returns `tx.get_receipt(...)` **unchanged** — the finding-17 idempotence
rule). Delivery via `gossip.py:163-164`.

Forge `Receipt(op_hash=H, epoch=e, ballot=B, issue_seq=k, signer=<victim node pubkey>,
sig=<random>)` and gossip it. The victim stores it under PK
`(op_hash, epoch, ballot, signer)`; thereafter, asked to legitimately receipt `H` at
`(e,B)`, it **serves the forgery**, which the proposer discards on `r.verify()`. Ballots are
enumerable (round ∈ 1..max_rounds, priority = public `slot_priority(slot_tag, client_fp)`),
so poisoning ⌈n/2⌉ nodes across all rounds makes `H` **uncommittable forever**. Aimed at
`(roster_op_hash, e+1, B)` it blocks every roster change; aimed at BLIND it blocks blind-write
retransmits.

## K-4, K-5, C-5 · MEDIUM · R — unverified store writes poison `(author, seq)` and erase QCs

- **`put_op_raw`** (`store.py:663-680`) doesn't verify, and is reached from gossip Delta
  baselines. An op with `author = <victim client pubkey>`, the victim's next `seq`, and a
  garbage sig makes `append` find a different `op_hash` at that `(author, seq)`, mint
  `ForkEvidence`, and return FORK — **the genuine signed op is never stored**. That author's
  chain is censored at that position on that node forever, and a fork "proof" against an
  honest author is persisted locally. Mitigated (not prevented) by `fold._prevalidate`, so
  nothing false-convicts or folds: availability + local evidence noise, not a safety break.
- **`put_op_raw` also skips `append`'s collision check**, so fork siblings coexist with
  **no `ForkEvidence` minted**, and `heads()` picks whichever sibling sqlite yields first
  (tie order unspecified) ⇒ two nodes sign **different** `head_hash` in their
  `FrontierBundle` ⇒ `holds_frontier` fails and the §13 roster change wedges unrepairably.
- **`put_qc`** (`store.py:729-740`) is `INSERT OR REPLACE`, unverified, and a first-class
  wire verb, so a genuine QC can be overwritten with garbage — destroying the node's ability
  to prove finality (reads never reach `level=final`, adoption stalls).

## K-6 · MEDIUM · C — every group master at rest in a default-permission file

`manager.py:292` and `:364-371` persist every keyepoch's `K_epoch` as **plaintext hex** in
`control.db`'s `meta` table (`tx.set_meta("masters", json.dumps({...hex()}))`).
`ChainStore.__init__` does **no `chmod`**, so `control.db` (+ `-wal`/`-shm`) lands at the
process umask (typically 0644) — while the root signing key is deliberately `0o600`
(`manager.py:288`). Any local user reading the manager state dir recovers every group
master and decrypts the entire store, past and present.

The escrow itself is intended; the **asymmetry** is the defect — the file holding every
group master is less protected than the key that signs.

## IO-13 · MEDIUM · C — the worker socket's authorization boundary rests on ambient umask

`workerapi.py:387-391` binds with no `os.chmod(path, 0o600)`, no umask guard, and no check
on the containing directory — while CLIENT.md §1 and TRANSPORT.md §0 both make *"filesystem
permissions on this socket ARE the whole worker-authorization boundary"* load-bearing. Under
`umask 0o002`/`0o000` (common in containers and some service managers) the socket lands
group- or world-writable and any local process can drive the key-holding daemon.

## IO-10 · MEDIUM · C — `dude node serve` cannot restart after a kill

`cli/node.py:54` calls `serve_forever(args.listen)`; `transports/unix.py:36` binds
unconditionally and `daemon.close()` never unlinks. `cli/client.py:47-48` **does** unlink
for the worker socket, so this is an asymmetry, not a policy. The demo's node-restart
scenario passes only because the **test harness** unlinks (`tests/test_demo.py:51-52`) — so
the production restart path is untested **and** broken: `EADDRINUSE` surfaces as
`error: [Errno 98]`.

## IO-6, IO-7 · MEDIUM · R — `may_flip:false` is returned when the answer is not final

`client.py:60` defaults `may_flip: bool = False`, and `client.py:684-691` returns bare
`Ladder(phase=…)` for `in-flight`, `unknown`, and `lost`. CLIENT.md §2.1 makes
`may_flip:false ⇔ final` and markets it as *"the cheap finality signal: poll `provisional`
and act when it goes false"*; `unknown` is defined as *"indeterminate — keep polling, never
guess"*, the exact opposite. `test_wire_goldens.py:179` pins `STATUS` on an op the daemon
has **never seen** returning `may_flip:false`.

`INSPECT` (`client.py:786`) has the same problem for absent keys: the condition is
`bool(pending) or (present and not self._version_final(...))`, `_final_frontier` starts at
`HLC(0,0)`, and `inspect` never syncs. A fresh or just-restarted daemon answers "absent,
will never change" for a key that is committed and final elsewhere. The NOTES 54 nit fixed
the *pending-op* case; the no-pending-op case remains.

## IO-8 · MEDIUM · R — one worker connection serializes its requests

`workerapi.py:374-385` reads a line, dispatches, and writes one reply before reading again.
CLIENT.md §1 is explicit: *"`id`-correlated ⇒ any number of requests in flight per
connection"* and *"Every request returns immediately. Nothing blocks."* But `_v_get`/`_v_list`
at `level="final"` call `self.d.sync()`, which does a full quorum FRONTIER read (2 s joins)
plus sequential per-node chain pulls at 5 s each. One `GET level=final` against a parked
quorum blocks everything already pipelined behind it. **No test covers concurrent in-flight
requests on one connection.**

## Remaining I/O items

`IO-9` (`STATUS` on an unknown op reports `in-flight`), `IO-11` (arity-free wire decoding ⇒
`IndexError` outside the `DudeFSError` tree), `IO-12` (HTTP carrier unbounded read +
`HTTPException` escaping `dial`'s `OSError` catch), `IO-14` (`_pull_baseline` unverified,
unconstrained, unpurgeable — the client lacks the node's `overfull_drop` remedy), `IO-15`
(`level` unvalidated ⇒ `"FINAL"` silently downgrades), `IO-16` (JSON-RPC 2.0: replying to a
failing notification with `"id":null` desynchronizes a pipelining client; empty batch;
`jsonrpc` member and `id` type unvalidated), `IO-17` (missing keyring reported as
`-32602 invalid params`), `IO-18` (unbounded thread creation on three hot paths), `IO-19`
(`_lost`/`_exhausted` mutated off-lock). One-liners in [TRIAGE.md](TRIAGE.md).

---

# 6. Test coverage that would let the above ship green

Beyond A1-A5 above:

- **A6 · HIGH · R — the "button masher" adversarial arm is inert.**
  `test_fumbling.py:270-320`. `EquivocatingAcceptor` differs from `Acceptor` only in
  dropping the same-`(tag,ballot)` guard. But ballot priority is
  `slot_priority(tag, client_fp)` and the test uses **distinct clients per contender** ⇒
  distinct 32-byte priorities ⇒ two contenders can never present the same ballot ⇒ node 0
  behaves identically to an honest acceptor for all 15 seeds. So `for pf in _dvs:` iterates
  **zero** times, and the real assertions sit inside `if not has_persona:` and are skipped
  on ~40% of seeds. Faults are all zero (`Link(base_ms=2, jitter_ms=1)` leaves
  `loss=dup=spike_p=0`). The docstring sells *"partitions × contended commits × an
  occasional equivocator"*; what runs is jitter-only, loss-free, effectively all-honest,
  with *"finishing without a raise IS the proof."*
- **A7 · HIGH · R — the quorum client's reply-authentication conjuncts are never exercised
  negatively.** `quorum._is_receipt` checks five things; the fault carrier models
  loss/dup/delay/partition only, never Byzantine content. Drop
  `r.signer == self.cfg.roster[node]` and one lying node supplies q receipts under other
  nodes' names ⇒ the client assembles a "valid" QC and reports `Committed` for an op no
  quorum accepted. **Suite stays green.** `Receipt.verify`, `Promise.verify`, and
  `FrontierBundle.verify` have **zero** negative tests — and `FrontierBundle.verify` is the
  only thing making the relay read safe.
- **A8 · HIGH · R — `Op.verify_structure()` is positive-only; it would pass as
  `return True`.** No test builds an op with `seq < 0`, `len(prev) != 32`, or
  `seq == 0 and prev != GENESIS_PREV`. It is load-bearing at two layers
  (`on_submit`/`on_accept` and the fold). Drop the genesis clause and a genesis op can
  splice `prev` to an arbitrary hash.
- **A19 · MEDIUM · R — `CheckpointView.overfull_drop()` has zero references in `tests/`**
  yet is live production code returning op hashes to **delete**. An off-by-one in
  `e.size > bl.retained.get(a, (0, b""))[0]` silently deletes a correct baseline.
  `select()`'s bootstrap-jump and defer branches are also untested, and `forward()`'s
  horizon-monotone clause has no negative test. (Note this is the same function as **C-1**.)
- **A12 · MEDIUM · R — the finding-19 atomicity claim has no daemon-level crash test.**
  `_adopt_one` claims *"adopt + GC + pin in ONE write txn: cut/retained/dead/horizon survive
  crash-restart together"*, but no test restarts a daemon **after** an adopt+GC.
  `test_crash.py` covers `ChainStore.gc_checkpoint` alone; every daemon in the suite is
  `":memory:"` and `test_demo.restart_node` explicitly spawns a *fresh* store. A node that
  GC'd `dead` but lost the cut/pin would ship undetected.
- **A18 · MEDIUM · R — peer-gate revocation untested.** `TestPeerGate` covers only
  never-member and stale-envelope; nothing exercises `_rebuild_authz`'s stated purpose
  (*"newly-gossiped certs/revocations take effect at the gate"*), so a revoked client
  remaining admitted would ship.

Vacuous-assertion inventory (A9-A31) is in [THE-UGLY.md](THE-UGLY.md#vacuous-and-tautological-tests).
