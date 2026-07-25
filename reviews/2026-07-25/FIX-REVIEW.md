# Fix review — the 2026-07-25 wave (`b4d9835`, `9916093`, `b0fd1d7`, `f49e72c`)

Read-only review of the four fixes logged in [FIXED.md](FIXED.md), verified against the
code at `06317a0`. No tests were run; every claim below is from reading the diffs, the
resulting code, and the new tests.

## Verdict

| Finding | Fix commit | Verdict | Why |
|---|---|---|---|
| **F-2** | `b4d9835` | ⚠️ **Partial** | Closes a real *adjacent* mechanism (lazily-undropped `dead`). The mechanism F-2 actually reported — an op that never enters `dead` because it never enters `universe` — is untouched. → **FIX-3** |
| **C-1** | `9916093` | ❌ **Regression** | Closes the reported hole, but makes the void rule unable to fire in the *normal* GC path, re-opening the NOTES 27 livelock permanently. → **FIX-1** |
| **K-1 / K-2 / K-12b** | `b0fd1d7` | ✅ **Good** | Correct fix in the right layer, with a genuine attack repro. Two cosmetic follow-ups (**FIX-4**, **FIX-5**). |
| **C-2** | `f49e72c` | ❌ **Does not fix the reported bug** | Only the node that already accepted is exempt; the quorum still cannot re-form. The deadlock stands. → **FIX-2** |

Net: one of four fully closed. Two need rework, one needs completing.

---

# FIX-1 · HIGH · C-1's fix re-opens the NOTES 27 livelock

## What changed

`dudefs/acceptor.py:233-240`:

```python
accepted_hlc: HLC | None = None
if s.accepted_op is not None:
    acc = tx.get_op(s.accepted_op)
    if acc is not None and acc.hlc < tx.get_horizon():   # was: acc is None or acc.hlc < …
        s.accepted_ballot = None
        s.accepted_op = None
    elif acc is not None:
        accepted_hlc = acc.hlc
```

## The structural problem

`SlotState` (`dudefs/store.py:1158-1164`) carries no hlc:

```python
__slots__ = ("promised", "accepted_ballot", "accepted_op")
```

and the table (`dudefs/store.py:314-316`) matches:

```sql
CREATE TABLE IF NOT EXISTS slot_state (
    tag BLOB PRIMARY KEY, promised BLOB NOT NULL,
    accepted_ballot BLOB, accepted_op BLOB);
```

So the below-horizon test **requires the envelope**. Before the fix, envelope absence was
(over-broadly) treated as a void trigger. After the fix, envelope absence means the slot can
**never be voided at all** — there is no code path that can classify it.

## Why that breaks the normal path

The void rule exists for NOTES 27: *"a reborn creation tag must not make PREPARE report an
ancient decided op that §1.3 would re-propose but can never re-commit."* The situation it
targets arises from routine adoption — `dudefs/daemon.py:339-343`, one transaction:

```python
tx.adopt_checkpoint(picked.baseline, picked.horizon)   # horizon advances
tx.gc_checkpoint(sorted(picked.baseline.dead))          # envelopes deleted
```

And `dead` genuinely contains slot-accepted ops. `dudefs/compactor.py:334-336`:

```python
keep = winners | masks | control_live
retained = [universe[h] for h in keep if h in universe]
dead = [h for h in universe if h not in keep]
```

An op that **won its slot** but folded `STALE` (guard failed) or was superseded is not a
`winner`, is not a mask, is not control — so it is `dead`, and its envelope is deleted by the
same transaction that raises the horizon above it.

That slot now has: `accepted_op` set · envelope **absent** · hlc **below the horizon**. It is
precisely the NOTES 27 case, and post-fix it is never voided:

1. `on_prepare` takes `acc = tx.get_op(s.accepted_op)` → `None`.
2. Neither branch runs. `accepted_ballot`/`accepted_op` survive; `accepted_hlc` stays `None`.
3. The `Promise` reports the ancient decided op.
4. PROTOCOL §1.3 step 5 forces the proposer to re-propose exactly that op.
5. No node holds the envelope (`FetchOpReq` fails everywhere — it was `dead` on all of them).
6. Its hlc is below the floor, so even with the envelope it could not re-commit.

Previously this resolved once nodes GC'd (the comment's *"a livelock until every node GCs"*).
Now GC is the thing that **causes** it and nothing resolves it.

## Second-order: the client guard was surrendered

The fix's own comment concedes *"we keep the accepted op and simply cannot report its hlc."*
That defeats `dudefs/quorum.py:388`:

```python
if p.accepted_hlc is not None and p.accepted_hlc < self.cfg.horizon:
    continue
```

`accepted_hlc is None` ⇒ the below-horizon promise guard never skips. This is currently
double-masked by **C-4** (`cfg.horizon` is never set from `tx.get_horizon()` in production),
but it becomes live the moment C-4 is fixed — so C-1's fix has planted a dependency between
two open findings.

## Recommended fix (primary): make the predicate total

Denormalize the accepted op's hlc into the slot state, so the void test never needs the
envelope:

- `slot_state` gains `accepted_wall INTEGER, accepted_ctr INTEGER` (nullable, set whenever
  `accepted_op` is set). Note `dudefs/store.py:801` is positional
  (`INSERT OR REPLACE INTO slot_state VALUES (?,?,?,?)`) and `:505` selects explicit columns,
  so both need updating — and since the DDL is `CREATE TABLE IF NOT EXISTS`, an existing
  node's DB needs a migration step rather than an implicit add.
- `on_prepare` then becomes unambiguous and envelope-independent:

  ```python
  if s.accepted_hlc is not None and s.accepted_hlc < tx.get_horizon():
      s.accepted_ballot = s.accepted_op = s.accepted_hlc = None   # void: below horizon
  else:
      accepted_hlc = s.accepted_hlc                                # always reportable
  ```

This closes C-1 (absence never voids), keeps NOTES 27 working (below-horizon voids even after
GC), restores the client guard, and removes the "ambiguous `None` standing in for a meaningful
condition" that motivated the fix in the first place — the ambiguity disappears rather than
being re-routed.

## Alternative (if the schema change is unwelcome)

Order the adopt transaction **void-then-GC**: before `gc_checkpoint`, void every slot whose
`accepted_op` is in the `dead` set being dropped (the hlc is available there — those ops are
still present at that moment, by construction, inside the same txn). Then envelope absence
never coincides with an un-voided below-horizon slot, and `acc is None` can stay non-voiding.

This is less invasive but weaker: it makes correctness depend on GC-path discipline at every
current and future call site, whereas the denormalized hlc makes the acceptor's own predicate
total. Given that C-1 arose *precisely* because a second GC call site
(`_adopt_one`'s `overfull_drop` branch) didn't follow the horizon discipline, I'd take the
schema change.

---

# FIX-2 · HIGH · C-2's fix does not clear the deadlock

## What changed

`dudefs/acceptor.py:273-278`:

```python
s = tx.get_slot(tag)
if s.accepted_op != op.op_hash:
    skew = self._skew_reason(tx, op, now_ms)
    if skew:
        return Rejected(skew)
```

## Why the reported failure survives

The exemption keys on **this node having already accepted this exact op**. Replay the
scenario from [THE-BAD.md](THE-BAD.md#c-2--high--c--the-floor-gate-precedes-the-idempotent-re-accept-exemption--permanent-deadlock)
(n=3, q=2; ACCEPT of `C_N` reached only node 0; δ elapses; compactor re-drives at ballot `b2`,
and §1.3 step 5 forces re-proposal of `C_N` verbatim):

| Node | `s.accepted_op` | Gate | Outcome |
|---|---|---|---|
| 0 | `C_N.op_hash` | exempt | `Receipt` ✓ |
| 1 | `None` | `None != C_N.op_hash` → floor gate → `op.hlc < floor` | `Rejected(BELOW_FLOOR)` ✗ |
| 2 | `None` | same | `Rejected(BELOW_FLOOR)` ✗ |

One receipt; `quorum_size(3) == 2`. Still `Failed(EXHAUSTED)` after `MAX_ROUNDS`, still
permanently deadlocked, still only clearable by a horizon advance that requires the blocked
commit.

The exemption covers exactly the nodes that *don't* need it and misses exactly the nodes that
do. There is no escape by re-authoring either: a fresh hlc would be a different `op_hash`,
which §1.3 forbids once a promise reports `C_N`.

## What the fix does achieve

Genuine PROTOCOL §0 idempotence for a retried transmit against a node that already accepted —
a dropped-reply retransmit now re-yields its stored receipt instead of being refused. Worth
keeping regardless of how C-2 is ultimately resolved.

## The actual design question

The floor gate's stated job is to stop a **late contender** winning a spent slot. A §1.3-forced
recovery re-proposal is not a late contender — it is the recovery of an existing decree, and
the proposer has no freedom to choose the op. Meanwhile `dudefs/acceptor.py:288-295`'s
`BELOW_HORIZON` guard already describes itself as *"logically implied by the floor (attested ≥
the sealed F), restated as an explicit guard"* — and **C-1 has just re-established the horizon
as the sole authority for a spent slot**.

> ### ⚠️ CORRECTION (same day) — the resolution in this section is WRONG. Do not implement it.
>
> **It would make honest nodes convict themselves.** `FloorPerjuryEvidence.verify` convicts on
> exactly `op.hlc < wm.floor` **and** `rcpt.issue_seq > wm.issue_seq`, and its docstring names
> the past gate as the reason an honest node structurally cannot produce that pair: *"after
> attesting F **the past gate refuses below-F acceptances**, and re-issues preserve their
> original lower seq."* The past gate is load-bearing for finding-17 soundness. Relaxing it —
> in any form, for any slotted ACCEPT that can mint a NEW receipt — hands a portable
> self-conviction to every honest node. Verified empirically in **FIX-6** below, where the
> *already-landed* fix does exactly this.
>
> Nor can C-2b be fixed by voiding aged accepts: a node cannot prove locally that the aged op
> never committed, which is C-1's failure mode again.
>
> **Revised position:** C-2b cannot be resolved by relaxing a gate. The remaining direction is
> to *dissolve* the tension — give `checkpoint_slot_tag`/`roster_slot_tag` an `attempt`
> component so a re-drive contends a **fresh** slot with a fresh hlc and the aged accept dies
> unreferenced. Cost: B4/WP-F(c)'s "one decision per seq" restated over `(seq, attempt)`, a
> tag-derivation change, and it *adds* `slot_state` rows — which is already an unbounded table
> (**D-1**). Harry's read: a nail-shaped answer to a hammer-sized problem. With C-2a narrowed
> (FIX-6), C-2b is a liveness edge — it needs a sub-quorum accept AND δ elapsing AND the drive
> failing to complete — not a safety hole. **Ruling: leave C-2b open as a documented RED
> (`TestC2bRedriveNeedsAQuorum`); don't reach for the attempt hammer until `slot_state` pruning
> exists.** The §9 question thus resolves into a §8/§13 *tag* question, which is its honest home.

The (superseded) original suggestion follows, kept for the record:

So the coherent resolution is to let the horizon carry that duty for slotted ACCEPTs and drop
`BELOW_FLOOR` there:

```python
# Slotted ACCEPT: the FUTURE gate still applies; the past gate is the HORIZON, not the floor.
if op.hlc.wall_ms > now_ms + self.delta_ms:
    return Rejected(RejectReason.FUTURE_HLC)
# (BELOW_HORIZON guard below is the spent-slot authority, with its same-op exemption)
```

That makes the two fixes consistent instead of mutually undercutting, and it clears the
deadlock for nodes 1 and 2 because the horizon has *not* advanced past `C_N` (the checkpoint
never committed — which is the whole premise).

This touches DESIGN §9's past gate, so it wants a ruling rather than a patch. The two
narrower alternatives, for completeness: (a) carry the promise set in the ACCEPT so the
acceptor can distinguish a forced re-proposal from a fresh proposal — more wire, more
verification; (b) exempt only `checkpoint_slot_tag`/`roster_slot_tag` ops, since those are the
tags with no `attempt` escape — smallest change, but ad hoc and it leaves the general
principle unstated.

---

## The repro — HELD OUT OF TREE, restore it here

`TestC2bRedriveNeedsAQuorum` was verified RED (**0 receipts against a quorum of 2**, after the
FIX-6 narrowing removed the mis-aimed exemption that was yielding 1) and is then **removed from
`tests/test_acceptor.py` before committing**, because CI runs `make check` on push and a red
master is precisely what tempts someone to "fix" the acceptance criterion. It lives here verbatim
instead — paste it back into `tests/test_acceptor.py` when C-2b is picked up. It needs no
fixtures beyond that file's existing `_slot_op` / `World` / `NOW` / `DELTA`.

```python
    class TestC2bRedriveNeedsAQuorum(unittest.TestCase):
        """FIX-2 (the half of C-2 that is still open): the same-op floor exemption keys on
        `s.accepted_op == op.op_hash`, so it exempts ONLY a node that already accepted. The
        reported deadlock is a QUORUM property — an ACCEPT that reached a sub-quorum before the
        proposer was partitioned, then δ. On the re-drive, §1.3 step 5 forces re-proposal of the
        SAME op (a fresh hlc would be a different op_hash), and the nodes needed to complete the
        quorum have never seen it, so they still refuse BELOW_FLOOR.

        Shown on a CAS slot for brevity; the mechanism is tag-agnostic. Data lineages escape by
        bumping `attempt` at the fold layer, but `checkpoint_slot_tag`/`roster_slot_tag` have no
        attempt component, so for those this is terminal — only clearable by a horizon advance that
        requires the very commit that is blocked.

        RED: the fix in `f49e72c` yields exactly one receipt here, and quorum is two."""

        def test_subquorum_accept_can_be_redriven_to_quorum_after_delta(self):
            w = World(seed=1, n_clients=1)
            accs = [
                Acceptor(C.SoftwareKeypair.from_seed(bytes([200 + i] * 32)), ChainStore(), 0, DELTA)
                for i in range(3)
            ]
            op, tag = _slot_op(w, 0, b"a", NOW)

            # the ACCEPT reaches only node 0 before the proposer is partitioned -> no QC
            self.assertIsInstance(accs[0].on_accept(tag, Ballot(1, b"x"), op, NOW), A.Receipt)

            later = NOW + 50 * DELTA  # δ passes: every node's floor is now above op.hlc
            b2 = Ballot(2, b"x")
            promises = [a.on_prepare(tag, b2) for a in accs]
            reported = [
                p for p in promises if isinstance(p, A.Promise) and p.accepted_op_hash == op.op_hash
            ]
            self.assertTrue(reported)  # node 0 reports the decree -> §1.3 forces re-proposing IT

            results = [a.on_accept(tag, b2, op, later) for a in accs]
            receipts = [r for r in results if isinstance(r, A.Receipt)]
            # the re-drive must be able to COMPLETE, not just be idempotent at the one node that
            # already holds the op — otherwise the slot is deadlocked for good.
            self.assertGreaterEqual(len(receipts), A.quorum_size(3))
```

**It must stay RED until the §8/§13 tag ruling lands.** Going green by any other route means a
gate was relaxed — which is FIX-6.

---

# FIX-3 · MEDIUM · F-2's fix closes an adjacent mechanism, not the reported one

## What changed

`dudefs/compactor.py:55-56`:

```python
dead = tx.cut_dead()
retained = [o for o in tx.all_ops() if covered(o, prev_cut) and o.op_hash not in dead]
```

This is correct and closes a real bug the fixer found independently: GC is lazy
(`adopt_checkpoint` persists `dead`; `gc_checkpoint` drops it separately), so a superseded
`dead` op that is still physically present used to be counted as retained. The red repro
(`tests/test_compaction.py:190` `TestF2RetainedExcludesDead` — adopt *without*
`gc_checkpoint`, assert the dead op is absent from `PrevState.retained`) is genuine and
exactly right.

## Why the reported mechanism survives

F-2 as reported was about an op that is **never in `dead` in the first place**:

> `CompactorView.of` puts only QC'd data ops in `committed`, so an op held **without** a QC —
> a slot loser re-proposed to this replica via `put_op_raw`, or a `_pull_chain` fetch whose
> `GetQCReq` returned nothing — never enters `universe`, is therefore never listed in `dead`,
> and is never GC'd.

For that op, `o.op_hash not in dead` evaluates **True**, so it is still admitted to
`retained`. A `dead`-mask cannot exclude something `dead` never names. The chain from
[THE-BAD.md](THE-BAD.md) is intact: it reaches `barrier_state` and `_mut_meta`, both of which
replay mutations with no guard evaluation and no QC check, so an uncommitted CAS sorting above
the real winner still becomes `prev_barrier[k].version` and still lists the committed winner
as `dead`.

## The missing predicate

`retained` must be *committed* ∧ *covered* ∧ ¬*dead*. The committed-ness test is the RC-1
predicate, and it is the one thing the fix didn't add.

Note also that the compactor's own notion of committed is presence-based, not verified —
`dudefs/compactor.py:139`:

```python
committed = [o for o in tx.all_ops() if o.is_control or tx.get_qc(o.op_hash) is not None]
```

`tx.get_qc(...) is not None` is mere presence. Combined with **K-5** (`put_qc` is unverified
`INSERT OR REPLACE`, reachable as a wire verb) a forged QC admits an op to `universe`; and
`o.is_control` admits control ops unconditionally, which is **F-1**'s hole on the compactor
side. So RC-1 wants fixing as one predicate used by `PrevState.of`, `CompactorView.of`,
`client._committed_ops`, `client._bootstrap_barrier`, and `gossip.Summary.of` — not five
local patches.

---

# FIX-6 · HIGH · C · the landed C-2a fix makes an honest node convict ITSELF

**The most serious item in this document.** `f49e72c` is not merely incomplete (FIX-2) — it
reopens finding 17.

The exemption keys on the **op alone**, so it also skips the floor gate for a re-ACCEPT at a
**different ballot**. And `reserve_receipt_seq` idents on `(op_hash, ballot)`
(`store.py:718-721`), so a new ballot is a new ident and mints a receipt at a **fresh `MAX+1`
seq** instead of serving the stored one:

1. Node accepts op X (`hlc=T`) at ballot `b1` → receipt at `issue_seq = s1`.
2. Node attests a watermark for floor `F > T` at `s_w > s1`. Entirely legal — floors rise.
3. δ has passed. The §1.3 re-drive arrives as `ACCEPT(tag, b2, X)`.
4. The C-2a exemption fires and **skips the floor gate**.
5. `_issue_receipt` finds no stored receipt for `(X, epoch, b2)` → mints one at `s2 > s_w`.

Result: a receipt for an op with `hlc < wm.floor` whose `issue_seq > wm.issue_seq`, same
signer ⇒ `FloorPerjuryEvidence.verify()` returns **True**.

**Verified, not argued.** `tests/test_acceptor.py::TestC2aReacceptMustNotSelfConvict` is RED,
and a direct probe confirms the conviction is *portable* rather than a detector false-positive:

```
r2 type: Receipt        seqs: r1=1 wm=2 r2=3        proofs: 1
PORTABLE CONVICTION (verify() is True) -> True      signer is the honest node -> True
```

**Fix — narrow the exemption to a genuine verbatim retransmit.** Harry's ruling ("a
dropped/retried transmit re-yields its receipt for your records") is **safe**: a verbatim
re-request is the same `(op, ballot)`, so `_issue_receipt` serves the stored receipt at its
original *lower* seq — no new issuance, no exposure, exactly as the docstring's second clause
promises. The landed code is simply **wider than the ruling**:

```python
if s.accepted_op != op.op_hash or s.accepted_ballot != ballot:
    skew = self._skew_reason(tx, op, now_ms)
    if skew:
        return Rejected(skew)
```

Keeps option (A) (skip both gates, as ruled) but only where no new artifact can be minted. The
repro asserts the *invariant* (never self-convict), not the outcome, so it stays valid however
the re-ACCEPT is answered.

---

# FIX-4 · LOW · K-2 reports `BAD_STRUCTURE` where `WRONG_EPOCH` exists

`dudefs/acceptor.py` (in `on_roster_accept`):

```python
if not isinstance(op, A.RosterOp):
    return Rejected(RejectReason.BAD_STRUCTURE)
if op.from_epoch != self.epoch:
    return Rejected(RejectReason.BAD_STRUCTURE)   # <-- distinct cause, same reason
```

`RejectReason.WRONG_EPOCH` already exists (`dudefs/acceptor.py:55`), and the enum's own
comment insists refusals be *"specific so the refusal says WHY: not 'bad authz' but which door
check the caller failed."* A stale-epoch roster op is not malformed. Two distinct causes
collapsed into one reason is the exact anti-pattern PYTHON-CODESTYLE §4 forbids
(*"say why, not what"*), and it costs a real diagnostic: an operator seeing `BAD_STRUCTURE`
will look for a corrupt op, not a lagging epoch.

---

# FIX-5 · LOW · dead wire fields, and a docstring that overstates the fix

`on_roster_accept`'s parameters are now `_sync_frontier` / `_new_epoch` and unread, but the
wire still carries them and the plumbing still threads them:

- `dudefs/wire.py:87-88` — `_encode_heads(sf)` and `new_epoch` still encoded into the frame.
- `dudefs/node.py:55-56` — `RosterAcceptReq.sync_frontier` / `.new_epoch` still declared.
- `dudefs/node.py:113`, `:132-133`, `:170-172` — still threaded through `NodeAPI` and `LocalNode`.
- `dudefs/node.py:48` still claims they *"ride the wire so the acceptor…"* — now false.

The precedent is established in this repo: `authz` (`2a8a676`) and `deps` (`59f0427`) were
both removed from the wire once nothing read them, each in a deliberate format commit that
moved the goldens. Same treatment applies here.

Separately, the new docstring says:

> it only refuses a requester whose wire values disagree with the op it carries

The code does not compare them — it ignores the wire values entirely. So it **silently
tolerates** disagreement rather than refusing it. Either compare and refuse on mismatch (which
would make the sentence true and give a cause-named rejection), or delete the fields and the
sentence. As written it is a comment asserting a check that does not exist, which is the
`tunables.py` failure mode (**H-7**) in miniature.

---

# What the wave got right

**K-1's fix is in the correct layer and closes the escalation.** The authz gate
(`authz.control.can_author_control(op.author, ControlKind.ROSTER)`) is the load-bearing
change, and putting it in the daemon rather than the acceptor is the right call — the daemon
already owns the control vocabulary via `ControlReducer`, and it is built the same way
`CheckpointView.of` builds its reducer. The added slot-binding and unique-member checks mirror
`checkpoint.slot_bound` faithfully. This is the RC-3 template applied properly.

**It also corrected my review.** My fix sketch's third item said *"verify the new half against
a roster the old epoch authorized, never `op.roster`"*. That was wrong: `new_qc.verify(op.roster)`
is **correct by design** — the incoming roster ratifying is the entire point of DESIGN §13's
joint certificate. The escalation came from the absent authz gate alone. And because
`old_qc.verify(self.roster)` still demands a majority of the *current* roster, a legitimate
`MANAGE_ROSTER` delegate naming itself sole member is exercising granted authority, not
escalating. The fix correctly kept what I wrongly proposed changing.

**`TestK1RosterEscalation` (`tests/test_daemon.py:40`) is a model security regression test.**
It constructs the whole attack — attacker-authored `RosterOp{roster=[self]}`, a real
old-roster majority QC, a self-signed 1-of-1 new half, and an explicit
`assertTrue(old_qc.verify(roster) and new_qc.verify([atk_pub]))` proving both halves genuinely
verify — then asserts the *secure* outcome (`d.roster` unchanged, `epoch == 0`). Hand-building
the QCs *strengthens* the attacker rather than weakening the test, which is the right
direction for a security proof. This is the standard the other three repros should meet.

**`TestF2RetainedExcludesDead` is likewise a real red repro** — it sets up the precise
lazy-GC state (adopt without `gc_checkpoint`) and asserts on `PrevState.retained` directly.

---

# The test-quality gap, concretely

FIXED.md sets its own bar in its header: *"a red-repro test that fails before and passes after
(a genuine regression test, not a re-assertion of the fixed behavior)."* Two of the four meet
it (K-1, F-2). The two that don't are the two whose fixes are wrong — which is not a
coincidence: **a repro built from the reported scenario would have caught both defects.**

**C-2 · `tests/test_acceptor.py:233`** uses a single `Acceptor`: accept, advance the clock by
`50 * DELTA`, re-accept verbatim, assert the same receipt. That tests the exemption, which
works. The reported bug is a *quorum* property. A repro that would have failed:

```
three acceptors, q=2
node0.on_accept(T_N, b1, C_N, NOW)          -> Receipt          (sub-quorum: 1 of 3)
advance to NOW + 50*DELTA                    (δ lifts every floor above C_N.hlc)
for nd in (node0, node1, node2):
    nd.on_prepare(T_N, b2)                   -> Promise; node0 reports C_N accepted
    nd.on_accept(T_N, b2, C_N, later)        -> collect
assert sum(isinstance(r, Receipt) for r in results) >= 2   # FAILS: only node0 yields
```

**C-1 · `tests/test_acceptor.py:256`** GCs the envelope by hand *while holding the horizon at
zero* — a state the production adopt path never produces, since `_adopt_one` advances the
horizon and GCs in one transaction. It proves the narrow thing the fix did. A repro exercising
the **natural** path is what exposes FIX-1:

```
accept op X on tag T (X will fold STALE / be superseded, so it lands in `dead`)
adopt a checkpoint whose horizon > X.hlc and whose `dead` contains X.op_hash
  (the real pairing: tx.adopt_checkpoint(baseline, horizon); tx.gc_checkpoint(dead))
p = on_prepare(T, higher_ballot)
assert p.accepted_op_hash is None        # the void rule MUST fire: below horizon
                                         # FAILS after 9916093 — the envelope is gone,
                                         # so nothing can classify it
```

Both skeletons are cheap — they need no daemon, no sockets, no sim. Worth adding as the
acceptance criteria for the rework.

---

# Status changes to [TRIAGE.md](TRIAGE.md)

- **C-1** — reported hole closed; **new HIGH regression introduced** (FIX-1). Reopened.
- **C-2** — **not fixed** (FIX-2). Reopened; the idempotence improvement is kept.
- **F-2** — **partially fixed** (FIX-3); reported mechanism still open, folded into RC-1.
- **K-1 / K-2 / K-12b / F-5** — remain closed. FIX-4 and FIX-5 are new LOW follow-ups.

RC-1 is now the critical path: it is the un-fixed half of F-2, the whole of F-1 and F-7, and
the reason the compactor's `committed` test is presence-based. It wants one predicate, applied
in five places.
