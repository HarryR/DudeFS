# Structural directions — shapes, not findings

Ratified by Harry during the wave-2 review. These are **how** to fix things, not what is
broken; the findings live in [TRIAGE.md](TRIAGE.md). Recorded because they are the direction
the codebase is being pushed in, and because each replaces a class of local patches with one
structure.

Two principles behind all three:

1. **Hierarchy and type over local patch.** A rule applied at five call sites is five chances
   to forget. A rule expressed as a type, or as a predicate the subclass inherits, is zero.
2. **Correctness by construction over enumeration.** A check that *detects* divergence is a
   reaction to a structure that permits it. Prefer the structure that makes divergence
   unconstructible. (Harry, on the `__slots__`-enumeration tripwire in **D-B**: "it hints at
   another smell where I feel there may be other ways to ensure correctness via construction."
   Correct — the tripwire is the patch-shaped answer.)

---

# D-A — RC-1 as a TYPE, not a predicate copied to five sites

**Replaces:** the recurring assumption *"an artifact I hold is an artifact the quorum
committed"* (RC-1), currently open at five sites and the un-fixed half of F-2.

## The trap to avoid

The obvious fix is a helper like `is_committed(tx, op)`. That is still five call sites and one
chance each to forget — and worse, the naive body inherits **K-5**:

```python
# compactor.py:139 — the presence-based trap, verbatim
committed = [o for o in tx.all_ops() if o.is_control or tx.get_qc(o.op_hash) is not None]
```

`tx.get_qc(...) is not None` is **presence, not verification**, and `put_qc` is an unverified
`INSERT OR REPLACE` reachable as a first-class wire verb. So a predicate written that way
closes F-1/F-2 against an *orphaned* checkpoint and **reopens them against an active peer** who
plants a forged QC. It must verify: epoch-matched, roster-verified majority.

The template already exists — `checkpoint.qc_final`:

```python
qc = view.qcs.get(op.op_hash)
return qc is not None and qc.config_epoch == view.epoch and qc.verify(view.roster)
```

Exactly as K-1 borrowed the checkpoint *adopt* predicates, RC-1 should borrow the checkpoint
*commitment* predicate. Doing it this way **folds K-5 into the same fix** instead of leaving it
as a sixth open door behind the five that were closed.

## The shape

A wrapper type whose **only** constructor verifies:

```
Committed(op)        # unforgeable: no public constructor
  └── Committed.of(ops, qcs, epoch, roster) -> list[Committed]
        keeps an op iff a QC for it VERIFIES against the epoch's roster
```

Then the five consumers take `list[Committed]` rather than `list[Op]`, and "I forgot to verify"
becomes a **type error** rather than a code-review question:

| Site | Today | Outcome |
|---|---|---|
| `client._committed_ops` | control ops admitted unconditionally | ✅ **wired** — closes F-1 |
| `compactor.CompactorView.of` | `get_qc(...) is not None` (presence) | ✅ **wired** — closes the K-5 inheritance |
| `compactor.PrevState.of` | `covered ∖ dead` over held ops | ✅ **wired** — closes F-2's reported half |
| `client._bootstrap_barrier` | `retained` from un-QC'd `all_ops` | ❌ **NOT an RC-1 instance** — see below |
| `gossip.Summary.of` | same raw projection | ❌ **NOT an RC-1 instance** — see below |

## Correction: RC-1 over-collected — two of the five must NOT be QC-gated

Implementing this surfaced an error in the original review's grouping. Both remaining sites
operate **below the cut, where per-op QCs have been GC'd by design**, so requiring a verified QC
there is not merely unnecessary — it is actively wrong.

**`_bootstrap_barrier`** already verifies the thing that matters (the *checkpoint's* own QC,
`self._qc_ok(tx.get_qc(o.op_hash), rosters)`), and its `retained` reconstruction is deliberately
un-gated, with the reason stated in the code:

> the below-cut winners … carry NO per-op QC (dropped below the cut); author-sig is verified in
> the barrier fold and the checkpoint `state_acc` is the vouch — so this is sourced from the held
> ops directly, NOT the QC-gated committed set (else a fresh client reconstructs an empty
> retained set and `verify_state_acc` fails).

The vouch below the cut is `state_acc`, not a QC. F-7's client arm is therefore **IO-14**, not
RC-1: pollution is caught loudly by `verify_state_acc`, and the real gap is that the client has
no **purge path** to recover from it (the node's `overfull_drop` is exactly that remedy).

**`gossip.Summary.of` / `baseline_digest`** is a **possession-comparison protocol**: a node's
digest is compared against the checkpoint's *signed* `retained` commitment and against other
nodes'. That commitment is computed by the compactor over committed ops, so the node side must
reproduce it **exactly**. Filtering the node side by *locally available* QCs would make the
digest depend on local QC availability, so two honest nodes would advertise different digests —
possession comparisons would fail and the §13 roster change would wedge. That is the same shape
as C-5's `heads()` nondeterminism, self-inflicted.

**The generalisable rule:** RC-1 applies where an op's authority is *quorum* authority and the
QC is still present — i.e. **above the cut**. Below the cut, authority has been transferred to
the checkpoint's `state_acc` and its own QC, and that is the thing to verify instead. The
predicate is not universal, and saying so is part of the shape.

## The one carve-out that must stay explicit

Control ops are **not** uniformly QC-gated, and flattening that would be wrong:

- **Root-signed control ops** (cert, roster, rotate, wrap-set) are self-authorizing — the
  manager chain is their authority. Correct to admit without a QC.
- **A `CheckpointOp` is NOT.** Its authority to place a fold barrier comes from the quorum QC,
  not from its author's signature. This is precisely **F-1**.

So the constructor's rule is *"data ops and checkpoints require a verified QC; other control
ops require chain authority"* — and that distinction wants to be visible in the type
(`Committed.of` naming both arms), not implicit in a call site. **F-1 exists because that
distinction was implicit.**

---

# D-B — decompose the acceptor into named predicates

**Replaces:** the hand-copied persona body, the `SlotState`-shape tripwire, and the
"is this guard tested?" question for every guard in `on_accept`.

## Why

`checkpoint.py` is the strongest module in the tree and it demonstrates the pattern: named pure
predicates (`slot_bound`, `qc_final`, `minter_authorized`, `forward`, `horizon_covers_cut`)
composed by a `_RULES` list, each with a docstring naming the attack it stops, each unit-testable
against a crafted view with no daemon and no sim.

`acceptor.on_accept` is the opposite — a monolithic body with inline guards:

```
structure/signature · slot-tag match · future/floor gate (with the FIX-6 verbatim exemption)
· ballot vs promised · equivocation guard · BELOW_HORIZON backstop (with its same-op exemption)
```

Consequences of the monolith, all observed in this review:

- **`EquivocatingAcceptor` must hand-copy the entire body** to drop one guard, so every field
  the honest path later denormalizes into `SlotState` has to be mirrored by hand. `accepted_hlc`
  (FIX-1) was such a field. That is what forced the tripwire.
- Guards are only reachable through a full accept, so the two exemptions (FIX-6's verbatim
  `(op, ballot)`, and `BELOW_HORIZON`'s same-op) are hard to test in isolation — and FIX-6 is
  exactly a bug in one of those exemptions.
- A test cannot say *which* rule rejected, only that something did.

## The shape

Guards become named predicates over a struct (the acceptor's analogue of `CheckpointView`), and
the persona overrides **one**:

```python
class Acceptor:
    def _equivocates(self, s: SlotState, ballot: Ballot, op: Op) -> bool: ...
    # + _skew_ok, _ballot_ok, _above_horizon, … composed by on_accept

class EquivocatingAcceptor(Acceptor):
    def _equivocates(self, s, ballot, op) -> bool:
        return False          # THE lie, and the whole of it — slot writes are inherited
```

What this buys:

- **The persona cannot diverge in slot shape**, because it no longer writes slots. `D-B` deletes
  the reason `TestPersonaMirrorsHonestSlotShape` exists — keep the tripwire only until this lands.
- Each guard gets a direct unit test, including the two exemptions.
- A rejection can name its rule, which is the `RejectReason` "say why, not what" rule applied one
  level up (and would have made **FIX-4**'s `BAD_STRUCTURE`-for-wrong-epoch obvious).
- It matches the module the codebase already got right, so there is one pattern, not two.

Same treatment applies to `on_prepare`'s void rule, which after FIX-1 is a single total
predicate over `SlotState` and reads naturally as a named one.

---

# D-C — demote the Promise to a response payload

**Ruled by Harry: demote.** Closes **K-14**, and **K-11** falls out for free.

## It is not an "ack", but it is not an artifact either

The proposer genuinely consumes `(accepted_ballot, accepted_op_hash, accepted_hlc)` — that
triple **is** Paxos phase 1's return value, and "re-propose the highest accepted op"
(`quorum._choose_and_accept`, PROTOCOL §1.3 step 5) is single-decree safety. It cannot collapse
to a bare acknowledgement.

What falls away is everything that made it an *artifact*:

| Field | Why it goes |
|---|---|
| `sig` | the L_msg envelope already signs the reply |
| `signer` | the envelope's authenticated `frm` already is it |
| `tag`, `ballot` echo | `_on_prepare_reply`'s `result.ballot == self.ballot and result.tag == self.tag` is **request-correlation hand-rolled at L1** — which `request_digest`/`expect_nonce` (K-13) now does properly at the envelope |

Leaving `Promised(accepted: Accept | None)`, a three-field optional record.

## The asymmetry that makes this obvious

`PREPARE`'s two outcomes are `Promise | Nack`. **`Nack` is already a plain unsigned payload**
(`__slots__ = ("promised",)`, no signature), as is `Rejected`. Same verb, same layer, same trust
context — and one of them is a signed artifact for no reason. Demotion makes them siblings.

## What it costs and closes

- **Closes K-11 for free**: `promise_message` omitting `config_epoch` stops mattering when there
  is no signature to be epoch-unbound.
- Drops an Ed25519 sign per PREPARE per node per round on the recovery path.
- **Wire format change** ⇒ the goldens move. That is a deliberate format commit, following the
  `authz` (`2a8a676`) and `deps` (`59f0427`) precedent — never mixed with a style commit.
- **Requires writing the threat-model scope down.** After demotion, promise equivocation is
  unprovable *by design* rather than by accident, and README's "all five evidence kinds sound
  **and** complete" currently reads as covering CAS exclusion. Say plainly that promise
  equivocation is out of scope for the evidence plane.

## ⚠️ Re-take this decision after RC-1

The demote recommendation rests on: promise equivocation needs an actively Byzantine roster
member, who could attack more cheaply via **K-3** (forged receipts served from store) or **K-5**
(QC overwrite) — so buying accountability at the Promise first is the third lock on an open door.

**D-A closes K-5, and the same wave should close K-3.** Once both are shut, promise equivocation
becomes the *remaining* cheapest Byzantine attack on CAS exclusion, and the argument flips toward
**promote** (issuance position + a `SEQ_REUSE` promise arm). Demoting now is not wasted — the
signature genuinely does nothing today — but the decision is **order-dependent**, so revisit it
rather than treating it as settled.

Independent of that: the **ballot-priority binding** (C-9 capability half, blocked on RC-6) is
correct under *either* end-state, touches the Promise not at all, and should be done regardless.
