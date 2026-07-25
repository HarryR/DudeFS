# DudeFS — deferred work

Running list of things deliberately deferred, so they don't get lost. Dated items use
absolute dates.

## Latent-structure extractions ("shape of things" sweep, 2026-07-25)

A–D landed (commits `6e4427e` Slot, `882cfad` HeadEntry, `7c5648a` KeyMeta, `7a403d4`
AddrRecord). One remains:

- [ ] **E — the receipt/issuance coordinate.** `(op_hash, config_epoch, ballot, issue_seq)`
  is passed as a 4-arg cluster to `artifacts.receipt_message()` and `Receipt.issue()`, and
  `(floor, config_epoch, issue_seq)` to `Watermark.issue()`. Candidate: a named coordinate
  (NamedTuple) that owns its canonical signing-message derivation (`receipt_message` becomes a
  method), the way `Slot` owns `.tag()`. Lower priority than A–D; `Receipt.issue` already
  half-owns it. Revisit after the review-driven fixes.

## Store schema: audit column types — native INTEGER over encoded BLOBs (2026-07-25)

Raised while adding `slot_state.accepted_wall/accepted_ctr` for review finding C-1/FIX-1
(ruled: native `INTEGER`, following the `floor` table's `hw_wall`/`hw_ctr` convention).

The schema is split between two conventions and the newer additions took the worse one. An
integer encoded into a bencode BLOB is **not queryable** — no `WHERE`, no `ORDER BY`, no
index, no `MAX()`; it can only be decoded in Python after a full scan. `store.get_qc`'s
`ORDER BY ballot DESC` is already a live casualty (review **C-7**): it memcmps bencode bytes,
so ballot round 10 sorts below round 1, and the comment claims an ordering the SQL cannot
provide.

- [ ] **Audit every column and pick the native type where the value *is* an integer.**
  Gets it right today (the model to follow): `ops.seq / hlc_wall / hlc_ctr / is_control`,
  `floor.hw_wall / hw_ctr / att_wall / att_ctr`, `receipts.epoch / issue_seq`,
  `qcs.epoch`, `issuance.seq`.
  Encodes integers into BLOBs: `slot_state.promised` and `.accepted_ballot`
  (`Ballot` = `(round: int, priority: bytes)` — the round is queryable data buried in
  bencode), `receipts.ballot`, `qcs.ballot`, `qcs.issue_seqs` (a list of ints),
  and the `meta` rows that hold integers (`horizon` = an HLC's two ints, `epoch`,
  and the `cut`/`cut_retained` pair-maps).
  Likely shape: split `Ballot` into `ballot_round INTEGER, ballot_priority BLOB` wherever it
  is stored, which fixes C-7 for free and makes "highest ballot for this op" a real query.
  Note `write_slot`/`put_receipt`/`put_qc` use positional `VALUES (?,?,…)`, so column changes
  must move in lockstep with them.
  Treat the on-disk store as **ephemeral** (no migration path, pre-production) — this is a
  free change today and stops being free later.

## Name the bytes: `Heads` should be keyed by `PublicKey`, not bare `bytes` (2026-07-25)

Ruled by Harry: the point of `PublicKey`/`AddrRecord`/`Slot` is that **an un-named `bytes`
field can't tell you what it holds** — two `bytes` params are indistinguishable to a reader
*and* to `ty`. `Heads = dict[bytes, HeadEntry]` still keys on an anonymous blob even though
every key is a pubkey, and `Op.author` is already a `crypto.PublicKey`.

Surfaced concretely: writing the C-1 repro, `{op.author: A.HeadEntry(...)}` was rejected by
`ty` (`dict[PublicKey, HeadEntry]` not assignable to `dict[bytes, HeadEntry]` — dict keys are
invariant), so every construction site needs a laundering `cut: A.Heads = {...}` annotation.
`tests/test_storage_concurrency.py:242` has the same pattern un-annotated.

- [ ] **`type Heads = dict[PublicKey, HeadEntry]`.** The wrapping point is the decode
  boundary — `artifacts._heads`, `FrontierBundle.decode`, `wire._decode_heads` — which is
  where "parse, don't validate" says it belongs (PYTHON-CODESTYLE §2/§6). `PublicKey`
  subclasses `bytes`, so there is no wire change and no runtime change; it is purely the
  static check being turned on. Removes the laundering annotations rather than adding more.
- [ ] **`committed.Rosters` too** (`dict[int, list[bytes]]`, added for RC-1/D-A). Same
  invariance bite: a `list[PublicKey]` is not assignable to `list[bytes]`, so
  `tests/test_compaction.py` needs a laundering annotation exactly like `cut: A.Heads`. Fixing
  it means retyping `fold.rosters_by_epoch`'s return, which is why it was left for this sweep
  rather than done mid-fix.
- [ ] **Same treatment for the rest of the pubkey-keyed and hash-keyed maps.** Candidates:
  `retained_commitment` / `Baseline.retained` (`dict[bytes, RetainedEntry]` — pubkey-keyed),
  `ControlState.endpoints`, roster lists (`list[bytes]`), and the op_hash-keyed maps
  (`qcs: dict[bytes, QC]`, `universe`, `dead`/`masks` sets). The op_hash family probably wants
  its own name (`OpHash(bytes)`) for the same reason — today a pubkey and an op hash are the
  same type to the checker, and `ForkEvidence`/`detect_*` juggle both.

## Test-suite type hygiene (recurring finding from the A/B refactors)

- [ ] **Untyped test plumbing hides raw values from ty.** Both the `Slot` (A) and `HeadEntry`
  (B) migrations passed `ty` clean, then failed at *runtime* / a second ty pass, because raw
  tuples slipped through **untyped test helpers**: `def write(self, slot, guards, muts)` (no
  annotations, `tests/test_compactor_daemon.py`), `Any`-typed daemon receivers (`cl.client(...)`
  in `tests/test_client.py`), and builder helpers like `World.checkpoint(cut=...)`. Type-driven
  refactors therefore don't get full static coverage in `tests/`. Fix: annotate the test-helper
  signatures (`slot: A.Slot`, daemon factory return types, builder params) so a future type
  migration is fully `ty`-caught instead of runtime-caught. Small, mechanical, high leverage.
