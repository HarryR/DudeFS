# HANDOFF — 2026-07-29

Written at the end of a long session. **239 tests green**, gate clean. Read
[PLAN.md](PLAN.md) for step-by-step status and [SPEC.md](SPEC.md) for the normative rules; this file
is only what a fresh agent needs that those two do not say.

```
ruff format dude -q && ruff check dude && ty check dude/ \
  && python3 -m unittest discover -s dude/tests -t . -q
```

Steps 1–7 of the plan are closed. `UNIMPLEMENTED` is down to `ANNOUNCE` / `FETCH` (mempool
dissemination — a transaction currently spreads by re-flooding the whole `SUBMIT`, which works and
does not scale).

---

## Read this before writing code

**Commits `3495bda..34933b6` want a fresh reader.** Three of the last five commits fixed defects the
same session had introduced, and the last one lost an hour to a silent edit failure. Nothing is known
to be wrong; the author's judgement was simply degrading. Start there rather than trusting it.

---

## Next work, in order

### 1. The credential in every leaf — RULED, not yet built

`[H]` Harry: *"why not just put it in all leaves? It's an authenticated data store."*

Today `live.cred` holds the authorising transaction for **management rows only**, and the SMT leaf is
`H(path ‖ H(value))` — so the root commits to values but not to who authorised them. The ruling is to
carry it for every row and hash it into the leaf, so a proof answers *"this key holds this value, and
here is the signature that put it there"* in one step.

Two things that shape the work, both found while thinking it through and neither obvious from code:

- **A `Move` must carry byte-for-byte the credential the row already holds.** `_commit` currently
  writes `m.credential` unconditionally. Once the credential is in the leaf, a Move swapping one
  valid credential for another — both vouching for the same value, e.g. the manager writing the same
  value twice — would **change the root**, and relocation would stop being state-invariant. That
  breaks the whole migration story. Guard it and invariance becomes provable rather than incidental.
- **Storage wants dedup, later.** A credential is a whole signed transaction, so a transaction
  writing 100 keys stores 100 copies. The natural fix is a credential table keyed by `op_hash` with
  live rows referencing it — the same refcount shape as epochs, possibly sharing machinery. Inline is
  fine for now; at 10⁷ keys it is the difference between ~300 MB and several GB. Note it, defer it.

Expect every root in the test suite to change.

### 2. State sync — for a node past the collection horizon

`PULL`/`ENTRIES` only helps a node with a valid **uncollected** prefix. A wiped or far-behind node
cannot replay from genesis, because collection deleted the entries that built the state. It needs
state transferred, verified against a quorum-signed root.

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

The only requirement is that the server retains the log from `H1+1`, which it does — `H1` was its own
head, and the collection horizon is behind that. Verification is machinery that already exists:
`Store._agrees` fires when the joiner lands on the sender's attested head.

**OPEN, and unresolved — do not guess.** A joiner adopts a checkpoint's `Commitment` at `height` and
replays forward. If the replayed range contains a **collection marker**, the joiner will apply it
without holding the segment being collected, so its `acc_log` arithmetic diverges from the server's
(`_collect` tolerates a missing segment and subtracts nothing). Either adoption must start strictly
after the marker, or the marker must commit to the segment accumulator it removes. This was found
late and thought about only briefly. **Settle it before writing the walk.**

### 3. Residual softness in what just landed

- **The transfer check only fires on reaching the sender's attested head.** A bounded `PULL` returns
  256 entries; a lying peer that sends a bad *partial* run and never lets you reach its attested head
  commits unverified state. This is the obvious way to defeat the check.
- **`_try_collect` swallows `StoreError` broadly.** Declining on the dedup floor is right — it is a
  timing condition — but the same `except` hides "not ratified", "names a different segment" and
  "still holds live values", which are faults. Discriminate.
- **`_relocates` requires the credential's author to be authorised *now*.** Correct as stated, but it
  means revoking the manager freezes relocation of management rows and segment 0 becomes permanently
  uncollectable. Should be a decision, not a side effect.

---

## Rulings that are not visible in the code

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
