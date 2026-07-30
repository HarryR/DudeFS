# HANDOFF — 2026-07-29, revised 2026-07-30

Read [PLAN.md](PLAN.md) for step-by-step status and [SPEC.md](SPEC.md) for the normative rules; this
file is only what a fresh agent needs that those two do not say.

```
ruff format dude -q && ruff check dude && ty check dude/ \
  && python3 -m unittest discover -s dude/tests -t . -q
```

**297 tests, all green** — lint, format and typecheck clean, six consecutive runs. The marker test
that was red on purpose (`test_a_pull_for_a_collected_range_is_not_answered_with_a_hole`) now passes:
a server no longer answers a `PULL` below its frontier with a gapped run.

Every step of the plan is landed **except one**: a node that cannot catch up incrementally has to
decide that and sync from scratch (§2). `UNIMPLEMENTED` is down to `ANNOUNCE` / `FETCH` (mempool
dissemination — a transaction currently spreads by re-flooding the whole `SUBMIT`, which works and
does not scale).

**The rule this codebase keeps proving** `[H]`: *"we decided on a mitigation, tested that mitigation
— without mitigating anything."* It builds a check correctly, tests the check in isolation, and then
never consults it where the decision is made. **Six** instances were open and are now closed (PLAN.md,
"The anchor wave"); each passed its own tests, because its own tests exercised the primitive rather
than the path. The last two are the clearest: `attested()` verified signatures and never COUNTED
them, so "ratified" meant *"one roster member signed"*; and the screen tag was compared by no layer
and no transport, so `crypto.screen_tag`'s stated property — a non-member cannot forge a tag, so
**garbage costs one hash** — was simply not delivered.

**`dude/tests/test_wired.py` now enforces the cheap half of this mechanically**: every check named in
`WIRED` must have a production caller, matched on the AST so a mention in prose does not count, and
anything genuinely not consumed yet sits in `OWED` with its reason and its future consumer. Verified
to fail when a check loses its last caller. It cannot catch a check that is called but INCOMPLETE, so
the review question stands: **which line refuses, and what breaks if I delete it?**

---

## Read this before writing code

**Commits `3495bda..34933b6` want a fresh reader.** Three of the last five commits fixed defects the
same session had introduced, and the last one lost an hour to a silent edit failure. Nothing is known
to be wrong; the author's judgement was simply degrading. Start there rather than trusting it.

---

## Next work, in order

### 1. Bootstrap has a roster circularity — what the anchor wave left open

The four "signature never consulted" defects are fixed (PLAN.md, "The anchor wave"), and closing them
surfaced one thing that is **not** a defect but is a genuine gap, found only by writing the tests:

**A node with no state cannot verify a checkpoint, because verifying one needs the roster, and the
roster is state.** `Store.adopt` refuses with *"no roster to check a checkpoint against"* — correctly,
since believing an unverifiable floor is exactly the hole just closed. So today:

- a **provisioned** node — one that holds genesis, hence the roster — can adopt a ratified floor from
  ordinary gossip and bootstrap from it. That works now and is tested.
- a **wiped** node holds nothing, so it can verify nothing, and `[H]` *"re-join as if new"* has no
  starting point. Not fatal today, because re-provisioning a wiped node is a manager action anyway —
  but the join is supposed to be the recovery path, and this is why it cannot be yet.

**The break in the circle is already ruled and half-built: the credential travels with the row.** A
management row carries the manager-signed transaction that authorised it, so a joiner that knows only
the **manager key** out of band can verify roster rows against it, then verify the checkpoint's
signatures against that roster, then verify state against the checkpoint's root. Manager key →
roster → quorum → state, with no step taken on trust. That is what makes item 3 load-bearing rather
than a refinement, and it wants stating in SPEC as the bootstrap chain.

Two smaller things this wave leaves behind:

- **`attested_floor` now requires `roster=`** and counts an unverifiable floor as zero. That is a
  breaking signature change; every caller passes its own roster from its own log. A checkpoint signed
  by a roster the caller no longer recognises is one it cannot check — which is this same circularity
  seen from the client side.
- **A far-behind node's floor can exceed its head**, deliberately. That is the bootstrap trigger and
  it must stay expressible; do not "fix" it. Note `(floor, head]` completeness is vacuous while it
  holds, which is correct — such a node owes no entries, it owes a bootstrap.

### 2. State sync — the node that CANNOT catch up

**This is the whole of the remaining work.** The SMT machinery is built, the control log is in good
shape, and what is missing is one thing: a node that cannot catch up incrementally has to **decide
that, and sync from scratch instead**.

`PULL`/`ENTRIES` only helps a node with a valid **uncollected** prefix. A wiped or far-behind node
cannot replay from genesis, because collection deleted the entries that built the state. It needs
state transferred, verified against a quorum-signed root. `[H]` **re-join as if new** — one path, not
a separate warm-bootstrap mode (PLAN.md's rulings table).

**There is no decision point in the code at all today, and its absence is a crash.** `catch_up`
always asks from `head()+1` ([node.py:404-410](dude/node.py#L404-L410)) and has no notion of "that
range is gone". An honest server answers from its own `entries(frm)`, which **silently skips
collected indices** — so the reply is a run with a hole in it, through no lie by anybody. Then one of
two things happens, both bad:

- the run reaches the sender's attested head → `_agrees` refuses it and raises `StoreError` out of
  `_on_entries`, and `_handle` is **outside** `receive`'s `DudeError` catch
  ([node.py:149-155](dude/node.py#L149-L155)) — so crash-only takes the process down. A node being
  too far behind is a routine condition and it kills the daemon.
- the run stops short of that head (bounded at 256, or the sighting is older) → nothing is checked at
  all, and the hole is **committed in silence**. `catch_up` then asks from the new head, so the hole
  is never revisited and never filled.

So the first half of this work is not the walk. It is: recognise *"the prefix I need has been
collected"* as a first-class outcome, and route it to bootstrap instead of to replay. A server that
cannot serve `frm` should say so, rather than serving what it happens to still hold.

**The SMT gives the chunk-diff for free.** A subtree hash *is* a chunk hash, so sync is a Merkle walk:
compare subtree hashes, descend only where they differ. Cost degrades smoothly with absence, which is
what the `[H]` "re-join as if new" ruling asked for.

**Harry's concern — "changes during the sync invalidate what was just synced" — dissolves.** You do
not need to prevent tearing, and freezing the cluster would be the wrong answer:

> Record `H1` = server's head before starting. Pull chunks over any interval. Record `H2` = server's
> head after. Replay the log `H1+1 .. H2`. For every key: **touched in the window** → the replay
> overwrites whatever torn value the chunk held with the final one; **untouched** → its value was
> constant throughout, so the chunk was already right. There is no third case, and `Set`/`Del` are
> both log entries so creation and deletion are covered.

Verification is machinery that already exists: `Store._agrees` fires when the joiner lands on the
sender's attested head, and a checkpoint carries exactly `store.Commitment`.

**Two things OPEN, both about the server's horizon MOVING during the sync. Do not guess.**

- **`H1+1 .. H2` is not retained by default.** An earlier draft of this file claimed the server keeps
  it because "the collection horizon is behind `H1`". It is behind `H1` *when the walk starts* and
  does not stay there: `collect` refuses only the segment holding `head+1`
  ([store.py:607-612](dude/store/store.py#L607-L612)), so once the head advances past the segment
  containing `H1+1` and its stragglers migrate, the range the joiner still needs is deleted
  underneath it. At `SEGMENT_WIDTH = 1024` a busy cluster reaches that in one segment's worth of
  traffic. Either the server pins a retention floor at `H1` for the life of the walk, or the joiner
  must detect the loss and restart against a newer checkpoint — which is the same decision as the one
  above, so answer both at once.
- **A collection marker inside the replayed range.** A joiner adopts a checkpoint's `Commitment` at
  `height` and replays forward. If the range contains a **collection marker**, the joiner applies it
  without holding the segment being collected, so its `acc_log` arithmetic diverges from the
  server's (`_collect` tolerates a missing segment and subtracts nothing). Either adoption starts
  strictly after the marker, or the marker commits to the segment accumulator it removes.

### 3. The credential in every leaf — RULED, not yet built

`[H]` Harry: *"why not just put it in all leaves? It's an authenticated data store."*

Today `live.cred` holds the authorising transaction for **management rows only**, and the SMT leaf is
`H(path ‖ H(value))` — so the root commits to values but not to who authorised them. The ruling is to
carry it for every row and hash it into the leaf, so a proof answers *"this key holds this value, and
here is the signature that put it there"* in one step.

Four things shape the work, none of them obvious from the code:

- **A `Move` must carry byte-for-byte the credential the row already holds.** `_commit` currently
  writes `m.credential` unconditionally. Once the credential is in the leaf, a Move swapping one
  valid credential for another — both vouching for the same value, e.g. the manager writing the same
  value twice — would **change the root**, and relocation would stop being state-invariant. That
  breaks the whole migration story. Guard it and invariance becomes provable rather than incidental.
- **`_relocates`' data-store shortcut stops being safe.** [settle.py:157-158](dude/store/settle.py#L157-L158)
  returns `True` for any non-management Move without looking at the credential — correct today,
  because a data row's `cred` is `b""` and nothing commits to it. Once the leaf hashes the credential,
  an unvouched Move can write an arbitrary one into a data row and the root will commit to it. Either
  `_vouches` runs for every store, or the byte-identity guard above becomes the universal rule and
  vouching is what it degrades to when the row holds no credential yet.
- **Relocation-invariance becomes a claim about the ROOT, and nothing asserts that.** `_collect`
  checks only that `A_state` did not move ([store.py:670](dude/store/store.py#L670)) — and it never
  will, since `element()` is over `(store, name, value)` and the credential is not in it. That is
  where the root check belongs.
- **Storage wants dedup, later.** A credential is a whole signed transaction, so a transaction
  writing 100 keys stores 100 copies. The natural fix is a credential table keyed by `op_hash` with
  live rows referencing it — the same refcount shape as epochs, possibly sharing machinery. Inline is
  fine for now; at 10⁷ keys it is the difference between ~300 MB and several GB. Note it, defer it.

Expect every root in the test suite to change. `[H]` **that churn is fine, and tests should assert
structure rather than pinned roots** until the design is in a much more solid position — a golden root
is a test of arithmetic nobody is doubting, and it re-costs an hour every time the leaf changes.

### 4. Residual softness in what just landed

**A partial run is committed unverified, and no anchor exists to verify it against.** A bounded `PULL`
returns 256 entries; the check only fires on reaching a height somebody signed, so a peer that never
lets you reach one commits unverified state. This is not a missing call like item 1 — it is a missing
**anchor**, and the difference is why it is here rather than there:

> `A_log` is a commitment to the retained *set* of `(idx, op_hash)`, so it can only be checked against
> a value someone signed at that exact height. Attestations sign the node's *current* head and nothing
> historical, so mid-run there is nothing to compare with. **The state side has no such problem** — a
> subtree hash folds to a signed root, so every chunk self-verifies on arrival.
>
> The fix that restores symmetry is one field: **carry the collected segment's accumulator in the
> ratified marker.** `segment.acc` is already computed and stored; signing it makes each segment a
> self-verifying chunk of log exactly as a subtree is a self-verifying chunk of state. That one field
> also fixes the joiner's `acc_log` arithmetic (§2's second OPEN item) and lets a server say *what* it
> no longer holds instead of serving what it happens to have.

Two more, unrelated to transfer:

- **`_try_collect` swallows `StoreError` broadly** ([node.py:312-319](dude/node.py#L312-L319)).
  Declining on the dedup floor is right — it is a timing condition — but the same `except` hides "not
  ratified", "names a different segment" and "still holds live values", which are faults.
  Discriminate.
- **`_relocates` requires the credential's author to be authorised *now*** ([settle.py:143-159](dude/store/settle.py#L143-L159)).
  Correct as stated, but it means revoking the manager freezes relocation of management rows and
  segment 0 becomes permanently uncollectable. Should be a decision, not a side effect.

---

## Rulings that are not visible in the code

- **Their error and ours are two trees, not one.** `[H]` `DudeError` is *their* fault — routine,
  expected, costs one frame. `InvariantError` is *ours* — a violated postcondition — and is
  deliberately **not** a `DudeError`, so no `except DudeError` anywhere can swallow it and it always
  reaches `crashonly`. Catchability is structural rather than a convention nobody can enforce at the
  catch site. `"collection changed the state accumulator"` is the archetype of ours; *"your run does
  not reconcile with what you signed"* is the archetype of theirs.
- **A refused transfer is routine, so it is RETURNED.** `[H]` A bounded `PULL` races the sender's own
  progress and a sighting goes stale, so a run that does not reconcile is ordinary operation, not
  corruption — `Store.replay` hands back the reason in words a log line can carry, in the same idiom
  as `Compaction.attested`. Raising it out of a frame handler let one peer's ordinary message take a
  node's process down.
- **The floor authorises the hole.** A compacted log is *supposed* to have gaps, so "no holes" is
  never the invariant: `(floor, head]` must be complete, and below the floor a quorum-ratified
  checkpoint is what licenses the absence. This holds whatever order segments are collected in,
  because a collectable segment lies at or below the head at collection time and that head is the
  height its own checkpoint records. Catching up fills `(floor, head]`; **bootstrapping raises the
  floor** so the missing prefix stops being owed.

- **The credential travels with the row.** Collection forgets the entry that first set a roster row,
  so without this a joiner could only take the roster on the quorum's word — and the roster is what
  defines the quorum. This is why `ops.Move` exists.
- **A timestamp cannot be ratified, only asserted.** Nobody can recompute another's clock, so the
  compactor's timestamp role is **struck, not built**; freshness rides attestation gossip
  (#freshness-is-gathered). Freshness is a **bound and a diagnostic**, never adversarial liveness.
- **Clock faults are never convictable.** An NTP step backwards is a road bump. It degrades a node's
  contribution and drops it from the `f+1`; `contradiction()` must never look at time.
- **Conviction is terminal for the identity.** Recovery is re-join as a new node — the path a
  forbidden out-of-band restore already forces. No rehabilitation, no un-shun protocol.
- **Shunning is a local read policy** on proven self-contradiction only — never silence, staleness or
  divergence. It does not alter the roster or quorum arithmetic, so a heavily-shunned cluster
  **stalls** rather than proceeding thin.
- **The validity windows are the coherence contract.** `[H]` *"if your clock is FUBAR you cannot play
  the game."* Do not add guards for cases the admission window already excludes — a redundant
  "refuse writes under a retired epoch" rule was proposed and correctly rejected on these grounds.
- **Pressure is deliberately basic.** `Store.epochs()` oldest-first. Tunable later; the mechanics were
  what had to be right.
- **Smallest-correct, no option-keeping.** A standing ruling. Do not preserve alternatives "in case".

## Working with Harry

- Ask decisions as **plain-text options in the reply**; he dislikes the popup (copy-hostile).
- He rules, then expects the work built and tested. State a recommendation rather than a survey.
- Review requests mean **reading only** — do not run the gate on his behalf during a review.

---

## Traps this codebase keeps hitting

Each of these cost real time, most of them twice.

1. **Encode/decode halves drifting apart, failing in SILENCE.** Twice. `attest_bytes` had no inverse
   (C1); then `acc_log` was added to the entry and the decoder but not to `attest_bytes`. Both times
   every claim on the wire decoded to nothing and the cluster quietly stopped collecting, with no
   error anywhere. Round-trip tests do not catch it — both halves are self-consistent in isolation.
   `test_the_claim_and_the_entry_agree_on_field_count` pins it by **field count**; extend that habit
   to any new pair.
2. **Applying locally what the quorum should agree.** Migration applied its own entries, so three
   honest nodes held byte-different logs at identical indices — with `A_state` and `head` agreeing
   throughout, which is exactly why nothing noticed. **Assert `log_accumulator()` across nodes**, not
   just `accumulator()`. That one assertion caught a second, unrelated instance within a minute.
3. **Routine outcomes raised as exceptions, escaping frame handlers.** `sqlite3.IntegrityError` on a
   duplicate settlement (not even a `DudeError`, so it sailed through the crash-only boundary), and
   `StoreError` on a floor refusal. Both are decisions, not corruption — return them.
4. **Parameters stashed on `self` for another method to read.** `dedup_window` was a `maybe_collect`
   argument saved on the node, so the peer-driven path used whatever a local call had left behind.
   The dedup floor was silently unenforced on half the code paths.
5. **Test builders quietly dropping fields.** `tests/test_store.py::_at` re-homed mutations and
   dropped `epoch`, so every conveyor test wrote `EPOCH_NONE` and passed vacuously.
6. **Run the suite repeatedly.** The duplicate-settlement race appeared in 2 of 6 runs and passed the
   first time. `for i in 1 2 3 4 5 6; do ...; done` before believing a green result.
7. **Blind string-replace edits failing silently.** The `attest_bytes` miss was exactly this. `assert
   old in v` before every replace. And **never run a line-rewrapper over source** — it cannot tell
   code from prose and has broken nine files and the SQL schema before.
