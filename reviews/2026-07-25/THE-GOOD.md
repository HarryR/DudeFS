# THE GOOD — what is genuinely solid

Read this before acting on [THE-BAD.md](THE-BAD.md). Five reviewers went looking for the
classic failures in their areas; most of what they expected to find wrong was right. That
context matters for triage — several findings are *omissions at a seam*, not symptoms of a
weak foundation, and the fix in each case is to extend a pattern that already exists and
works.

This is not a courtesy section. Each item below is something a reviewer tried to break and
could not.

---

## Durability discipline — the strongest part of the codebase

Sign-after-fsync is real, not aspirational.

- `write_txn` is `BEGIN IMMEDIATE` on a `synchronous=FULL` connection, and **WAL fallback
  is a loud failure rather than a silent degradation** (`store.py:1039-1051`). That check is
  unusual and correct; most implementations quietly accept the weaker mode.
- Every signature-justifying artifact is either signed *inside* the transaction and returned
  only after `COMMIT` (`_issue_receipt`, atomic with the slot state it attests — no
  three-commit window), or re-derived deterministically *after* `COMMIT` from a reserved
  issuance-ledger position (`issue_watermark`, `on_prepare`).
- **`reserve_issue_seq` is the load-bearing idea**: commit the *justification* for a seq
  before signing, so a crash re-derives the identical artifact instead of burning the
  position. This is what makes the gap-free-issuance claim actually hold rather than merely
  be asserted.
- The `BaseException` handler that checks `in_transaction` before `ROLLBACK`, so
  `SQLITE_FULL` isn't masked by "cannot rollback", is the kind of detail most projects get
  wrong.

## The evidence system is sound

No reviewer could construct an **honest-node conviction** for any of the five kinds. The
finding-17/18 work holds up under adversarial reading:

- `FLOOR_PERJURY`'s `rcpt.issue_seq > wm.issue_seq` ordering requirement is genuinely
  frame-free: an honest node cannot produce the pair, because `_skew_reason` reads `floor()`
  as `max(computed, tx.get_attested())` **inside the same write transaction** that would
  issue the receipt, `get_attested` is durable and monotone, and receipt seqs are bound at
  first acceptance — so a cross-epoch RERECEIPT reuses the lower seq rather than
  back-stamping.
- `DOUBLE_VOTE` requires same-signer/same-ballot/same-slot/different-op, which the
  `EQUIVOCATION_GUARD` structurally prevents.
- `SEQ_REUSE`'s reissue-key carve-out matches `reserve_issue_seq`'s `ident` exactly.

(Soundness ≠ completeness: **A3/A4** show two kinds never fire in production. But the proofs
themselves are correct, which is the harder half.)

## Quorum counting is clean

- Both `Commit` and `Finalize` key replies by **node index** and cross-check
  `result.signer == self.cfg.roster[node]`, so a duplicated or replayed reply cannot be
  counted twice and one node cannot fill two slots.
- `QC.verify` is strict where it matters: exact bitmap length, no stray bits above `n`,
  `bitmap_count >= quorum_size(n)`, `len(issue_seqs) == len(sigs)`, per-signer message
  reconstruction. Distinct signers by construction; majority math correct for even rosters.
- Promise freshness (`result.ballot == self.ballot and result.tag == self.tag`) correctly
  prevents a superseded round's reply from filling the current quorum.
- **Routing replies by *request type* rather than by current phase** (`quorum.py:346-361`)
  closes a real bug class, and the comments show it was found the hard way.

## The cryptography is well built

- **Domain separation is correct by construction, not by convention.** `dude.enc` /
  `dude.slot` / `dude.nonce` / `dude.tag` / `dude.screen` are BLAKE2b `person` values — a
  fixed-width 16-byte zero-padded field — so prefix collisions are *structurally impossible*.
  `EpochKeys.derive` matches CRYPTO.md §2's conformance block exactly.
- **AD binding is complete.** `DataOp._aad_fields` covers class, author, seq, prev, hlc,
  pver, keyepoch **and** slot_tag — every envelope field but payload and sig — so a
  ciphertext cannot be relocated to another author, epoch, slot, or chain position. The SIV
  input `aad ‖ h(pt)` is injective because both halves are fixed-length, and `nk` is a
  separate subkey of `data_key`, so a conforming sealer cannot reuse a nonce.
- **The codec is a real canonical codec**: minimal ints, no `-0`, no leading zeros, length
  prefixes throughout, strictly ascending unique dict keys enforced *on decode*, `bool`
  rejected at encode, trailing bytes rejected. The reviewer **could not construct two
  distinct values with one encoding, nor a non-canonical encoding that decodes.**
- **Identity-is-the-received-bytes is honored end to end** (`Op.raw`, `op_hash = h(raw)`,
  `verify_sig` over the re-encoded decoded envelope with `sig` popped, unknown keys rejected
  via `UnknownField`) — so there is no field-extension or re-serialization gap.
- **Verify-before-use is enforced at every semantic consumption point checked**, with no
  signature check computed but not branched on: `store.append`, `acceptor.on_submit`/
  `on_accept`/`on_recovery_fence`, `fold._prevalidate` (with a sound `op_hash`-keyed cache),
  `ControlReducer.observe` — so even the request gate's authz view is signature-checked —
  `quorum._is_receipt`/`_on_prepare_reply`/`_on_fetch_reply`, `client._qc_ok`,
  `checkpoint.qc_final`/`minter_authorized`, and all five evidence `verify()`s.
- `hmac.compare_digest` is used for the one keyed-tag comparison that needs it; no `==` on a
  secret or MAC anywhere else. `SoftwareKeypair` keeps the seed behind `__slots__` with no
  `__repr__`; keyfiles are `0o600`; `lmsg.author` derives `frm` from the signer so a
  signature cannot outrun its identity.

## The determinism core holds

Several traps the reviewer went hunting for are already closed:

- `_total_order_key` is total (the `op_hash` tail) and defensive against garbage envelopes.
- `_prevalidate` correctly excludes sig-invalid ops from both linkage targets *and* the HLC
  baseline (NOTES 17), and deliberately admits forks.
- **The lineage-advance invariant is implemented universally**, including
  `_consume_invalid_slot` for `INVALID` and pver-fenced ops, and `_bump_attempt` on absent
  keys — the wedge §6 warns about.
- **Set iteration is safe by inspection, not by luck.** `_attribute` returns on first match
  and at most one key can match by PRF injectivity; every set that reaches the wire is
  normalized (`retained_commitment` sorts hashes, `CheckpointOp.build` encodes
  `sorted(baseline.dead)`, `codec.encode` sorts dict keys and rejects non-canonical input);
  and **`state_acc` is ECMH, so it is order-independent by construction** rather than by
  sorting discipline.
- No floats, locale, wall-clock, or randomness leak into derivation.
- `Txn.decode`'s strict arity table plus `InvalidOp`-by-type make the fold **total over
  hostile envelopes** — the only raises found are the deliberate `FoldHalted` and the
  compactor's `CompactError`s.

## The manager and control plane

- The **even-roster refusal is enforced twice** — at decode (`artifacts.py:936`) and near
  the operator (`manager.py:429`).
- `node_replace` is count-preserving.
- **Both joint-cert halves are gathered before `persist`** (`manager.py:484-501`), so an
  unratified roster change can never flip the derived view.
- `recover_decision` refuses unconditionally whenever a quorum answers, and fiat recovery is
  root-only in **both** the fold and the acceptor.
- `qc_final` verifying against the epoch roster instead of trusting `put_qc`, and `select()`'s
  jump being simultaneously forward-only, dominance-gated, **and** baseline-verified, are
  both real and correctly built.

## Architecture and layering (where it holds)

- `lmsg` is pure and defends its own decode boundary properly — catching
  `ValueError`/`IndexError`/`CodecError` at every entry, `matches_tag` before any ECDH, and
  check-order documented as load-bearing and actually load-bearing. **It is the in-repo model
  the other decode sites should copy** (see RC-4).
- `Link` is a value, not a held socket. The carrier registry means the same gated wire runs
  over unix/http/inproc with no caller changes, and **the `inproc` carrier driving real
  `serve`/gossip in one thread is a much better test seam than a mock transport.**
- The store's threading story is *reasoned*, not accidental: `check_same_thread=False` with
  explicit reader/writer locks, the nesting guard that raises **before** taking a lock, and
  the rollback handling above.
- The `CheckpointView` / `CompactorView` **"`.of(tx)` is the only store read, everything else
  is pure"** seam makes the adoptability rules genuinely reviewable — decomposed into named
  predicates so a test sees exactly which rule rejected. This is the pattern the roster path
  should be rebuilt on (RC-3).
- `client._author`'s "advance `seq`/`prev` only after the op is durable" comment describes a
  real bug that was really avoided.
- Error handling is mostly cause-named (`RejectReason`, `ReplyOutcome`, `AppendStatus`,
  `StoreClosed` vs `StoreBusy`), and where a `None` collapse does happen (`_rpc`) the code
  **says so out loud** instead of pretending.

## The test suite, where it earns its claims

- **The wire goldens are a real regression net, not a regenerated fiction.**
  `test_wire_goldens.py:20-46` hardcodes 24 byte-digest literals, and git history proves the
  discipline held: goldens moved *only* in commits that intentionally changed the format
  (`59f0427` deps removal, `2a8a676` authz-field removal — 17 values each), while the pure
  refactors that followed (`6e4427e` extract Slot, `882cfad` extract HeadEntry, `eea69db` Op
  hierarchy) changed **zero** golden values. That is the project's own "goldens immovable in
  style commits" rule, independently verified.
- **`test_sim.py` is real chaos**: `Faults(loss=0.25, dup=0.2)` over 20 seeds × n∈{3,5},
  one-way cuts, a *flapping* partition on a 60 ms cadence, NTP-style backward clock
  step-jumps, per-node skew — with continuous B1/B3 invariant hooks and A1
  order-independence checked across six shuffles.
- **`test_storage_concurrency.py` and `test_hardening.py` are exemplary**: real file-backed
  WAL stores, a genuine two-thread RMW slot race resolving to exactly one winner,
  cross-process `StoreBusy` with the sqlite cause chained, and a whole file of adversarial
  negatives (malformed bitmaps, unknown control kinds, even rosters, forged ops that must
  not poison an honest author's chain).
- **Negative controls are used deliberately rather than decoratively**:
  `test_compaction.py:136-139` removes the resurrection mask and shows `B` come back;
  `:183-187` removes the sidecar and shows divergence; `test_client.py:592-622` drops one
  retained winner and requires a **loud** `CompactError` rather than a silently wrong read.
- **The F23/F24 lesson was genuinely learned** at the manager boundary:
  `test_manager.py:259-343` and `TestManagerFumbling` drive roster growth, replace,
  double-press serialization, and the possession-barrier *refusal* through the real
  `manager.py` §13 flow, not hand-built ops. (The criticism in A1-A4 is that it was applied
  *there* and stopped — the same shape sits one layer below, at the acceptor and daemon.)

## Engineering hygiene

- **Zero `TODO`/`FIXME`/`HACK`/`XXX` markers in production code.** Exception-swallowing is
  limited to three `KeyboardInterrupt` handlers and one commented transient-`OSError` retry.
- CI runs **exactly** the developer gate — no CI-only drift, no "works on my machine" gap.
- `tunables.py` deriving every timeout from two measured physical primitives via
  dimensionless multipliers, with an explicit "NOT here: protocol/wire constants — changing
  one breaks the wire format or a safety proof" carve-out, is a genuinely good idea rarely
  seen. (The arithmetic bug in **H-7** is a bug *in* a good design, not a bad design.)
- The `PYTHON-CODESTYLE.md` contract is real and largely honored, and the reasoning recorded
  in it (why `tuple` over `list`, why enums over constants, why a leaf error must be a *kind*
  and not a *message*) is better than most projects' actual code.

---

## The shape of the whole thing

The two consensus HIGHs both live in the **interaction** between subsystems that are
individually careful — envelope GC versus slot-state lifetime, and the floor gate versus
re-proposal idempotency. The roster escalation exists because a well-built pattern
(`checkpoint.py`'s named predicates) was never extended to a sibling path. The RC-1 cluster
exists because a deliberate and *correct* decision — "the store's write path is unverified;
consumption verifies" — was not carried through to every consumer.

None of that is a weak foundation. It is a strong foundation with unfinished edges, and the
edges are enumerable, which is why [ROOT-CAUSES.md](ROOT-CAUSES.md) is short.
