# Design findings — the artifact/envelope layering, and two unbounded things

Findings from the design questions Harry raised while triaging fix wave 1. These are **not**
defects in the fix wave; they are structural findings the fix wave surfaced. All verified by
reading the code at `06317a0`.

Two of them share one root cause, recorded as **RC-5** below.

---

# RC-5 — the artifact layer and the envelope layer were never reconciled after L_msg landed

The `Promise`/`Receipt`/`Watermark` artifacts were designed at M2/M3, when an artifact's own
signature was the **only** authentication available. `L_msg` (TRANSPORT.md, NOTES 58/59)
arrived at M7 and made every message authenticated in its own right — but the artifact layer
was never revisited against it. The result is a layer that is simultaneously **redundant** in
one place (**K-14**) and **absent** in another (**K-13**).

Both findings below are instances of this. Fixing them together is cheaper than separately,
and the design docs need one reconciliation pass either way.

---

# K-13 · HIGH · C · a reply is not bound to its request

`lmsg._check_reply` performs exactly three checks:

```python
if not env.verify_sig():                              return MalformedReply()
if env.frm != expect_from or env.to != expect_to:     return WrongPeer(env.frm)
return Reply(env)
```

So a reply carries: *this node signed it*, *it is addressed to me* (the `to` anti-reflection
field — genuinely well-reasoned), and integrity over its own contents. It carries **no
correlator to the request**, and `_check_reply` does not even compare the reply's `verb` to
the verb that was sent. `link.py:38` passes only `expect_from`/`expect_to` because there is
nothing else to pass.

## The `nonce` field is a trap

`Envelope` has `nonce: bytes`. It is in `_signed_bytes()`, in `encode()`/`decode()`, and
pinned in the wire goldens. And:

- `author(..., nonce: bytes = b"")` defaults empty;
- **no caller anywhere passes one** (grep over `lmsg`/`daemon`/`link`/`client`: the only hits
  are the field, the signing, the encoding, the decode, and the parameter default);
- nothing ever reads it.

A reserved slot that reads like a live anti-replay mechanism. Anyone auditing TRANSPORT.md
would reasonably conclude replay protection exists. Same family as **FIX-5** and **H-7** — a
structure asserting a property the code does not implement.

## Why it hasn't bitten: the binding is emergent, at L1

Request-binding effectively exists, but it lives in **artifact self-description**, not the
envelope — three overlapping accidents:

| Reply | Bound to the request? | By what |
|---|---|---|
| `Promise` | ✅ | `result.ballot == self.ballot and result.tag == self.tag` (`quorum.py:367`) |
| `Receipt` | ✅ | `op_hash` + `ballot` + `config_epoch` in `_is_receipt` |
| `FrontierBundle`, `Watermark` | ❌ but safe | floors only rise, so a replayed old one is a conservative lower bound (the `test_relay.py` argument) |
| `Nack`, `Rejected` | ❌ | liveness only — a stale `promised` costs a wasted round |
| **`FetchOp` result** | ❌ **and unchecked** | **the real hole — K-8** |

Plus `quorum` routes replies by *request type* rather than current phase, catching type
confusion. Three emergent defenses, zero stated ones — fine until someone adds a verb whose
reply is not self-describing, at which point there is no safety net and no comment warning them.

## K-8 upgraded to CONFIRMED, and it composes with F-1

`client._pull_chain` (`client.py:494-500`):

```python
fetched = self._one_of(FetchOpReq(h))
if not isinstance(fetched, Op):
    return
op = fetched
with self.store.write_txn() as tx:
    tx.put_op_raw(op)
...
h = op.prev          # the attacker's prev drives the next iteration
```

No `fetched.op_hash == h`, no `verify_sig()`. Whoever answers a `FetchOpReq` — any roster
member, or a relay — can inject an arbitrary op into a client's store **and steer the rest of
the chain walk**.

**The composition (new — not in the original review):** the injected op lands via
`put_op_raw`, and `_committed_ops` then admits **every control op unconditionally** (**F-1**).
So a substituted *checkpoint* op reaches the fold as a barrier with no QC verification — which
is F-1's divergence, reachable by an active peer rather than only by an orphaned local
checkpoint. **K-8 supplies the op; F-1 trusts it.** Rank the pair above either alone.

## Fix — use what is already there

The responder **already echoes the verb** (`daemon.py:180` authors the reply with `env.verb`),
and the `nonce` field already exists, is already signed, and is already golden-pinned. So:

1. Reply sets `nonce = crypto.h(request._signed_bytes())` — a deterministic request digest.
2. `classify_reply(..., expect_nonce=…)` compares it, alongside `env.verb == sent_verb`.

A handful of lines, no wire-format growth, and it converts an emergent property into a stated
one. It also unlocks the async case PYTHON-CODESTYLE §5 already anticipates — *"handle the
reply as a later inbound event (or via gossip, **keyed by request-hash**)"* — currently
unimplementable because nothing carries a request hash.

**Today's exposure:** over a unix socket the OS supplies correlation (one connection, one
reply), so exploitation needs the peer itself or a MITM. But TRANSPORT §0 explicitly targets
*"sessionless, intermediated carriers"*, and relays plus the HTTP carrier are in scope — the
binding is needed for the transports the design **claims**, not the one it mostly runs.

Independently and regardless of the envelope work: **`_pull_chain` must check
`fetched.op_hash == h` and `verify_sig()`.** Two lines, and it is the actual hole.

---

# K-14 · MEDIUM · C · the Promise is signed but not accountable

Harry's question: *given L_msg authenticates responses, why do we need the Promise at all?*

Verified:

1. **A Promise consumes no issuance-chain position.** Only `reserve_receipt_seq` (`b"r"`) and
   `reserve_watermark_seq` (`b"w"`) exist. `on_prepare` signs and returns; its own comment
   says *"re-derivable, not stored"*.
2. **Promises are excluded from the evidence system.** `SEQ_REUSE` covers *"receipt/receipt,
   receipt/watermark, or watermark/watermark"* — there is no promise arm, and no other
   evidence kind mentions promises.
3. **Promises are never persisted by anyone.** The schema is `ops, receipts, qcs, slot_state,
   floor, evidence, issuance, meta` — no promise table.
4. **Relay-safety is scoped to watermarks and frontier bundles, not promises**
   (`acceptor.py:165`, `artifacts.py:1810`, and `test_relay.py`, which is entirely about reads).
5. `Promise.verify()` has one call site — `quorum.py:368` — by the proposer that received it,
   beside `result.signer == self.cfg.roster[node]`, which is the question the envelope's
   authenticated `frm` already answered.

## So the signature does no work

| Candidate justification | Status |
|---|---|
| Origin auth over an untrusted pipe | `classify_reply` already gives it, `WrongPeer` included; PREPARE/ACCEPT are point-to-point. **Redundant.** |
| Portable evidence | No `issue_seq`, no SEQ_REUSE arm. **Unused.** |
| Third-party verifiability | Nothing third-party ever sees a promise. **Unused.** |
| Stopping a proposer forging promises | Forging promises to yourself fools only yourself; acceptors never take promises as input. **Not a property.** |

## The consequence nobody wrote down

Because promises are never stored and hold no issuance position, **a node can equivocate
across promises with total impunity** — tell client A "nothing accepted" and client B "X
accepted at b1" at the same `(tag, ballot)`. No detector can ever see it, not because the
detectors are weak but because the evidence plane only sees what nodes *persist*.

That matters, because a lying promise breaks single-decree safety. Classic Paxos leans on: if X
was accepted by a majority, every promise-majority contains a node that accepted X. If that
node lies by omission, the proposer proposes a fresh Y at a higher ballot and two values are
chosen. So:

> The Promise is the one point where a **single** Byzantine node can break CAS exclusion, and
> it is the one artifact deliberately excluded from the evidence system.

RESILIENCE §3.7 marks CAS exclusion violable *with proof* under a Byzantine node. Here it is
violable **without** proof — structurally the same shape as C-1, reached from the opposite
direction.

## Two coherent end-states; the code is in neither

**(1) Demote.** Make the promise a plain unsigned reply, authenticated by the envelope like any
other RPC result. Drops an Ed25519 sign per PREPARE per node per round on the recovery path,
drops the redundant `signer == roster[node]` check, and honestly reflects a transient
control-flow value. You accept that promise-equivocation is unprovable — defensible if this
layer's threat model is scoped to crash faults, but it must then be **written down**, because
"all five evidence kinds sound and complete" currently reads as covering CAS exclusion.

**(2) Promote.** Give it an issuance position and a promise arm in `SEQ_REUSE` (or a
`PromiseEquivocation` kind). Then contradictory promises at one `(tag, ballot)` are convictable
and the signature earns its keep. Cost: durable issuance state per PREPARE — which feeds
**D-1**, so bound that table first.

Being signed-but-unaccountable pays the cost of (2) and buys the benefit of neither.

## Capability ≠ accountability

Harry's instinct was that the Promise *should* act as a ticket. Two things were tangled:

- **Capability** — "may this requester act at this ballot?" Needs **no** promise.
  `Ballot.priority = slot_priority(slot_tag, client_fp)` already bakes the client's fingerprint
  into the ballot, and L_msg already authenticates `frm`. So the check is a pure function:
  `ballot.priority == slot_priority(tag, fingerprint(authenticated_from))`. `slot_priority` is
  currently computed **only by proposers** (`quorum.py:246`, `manager.py:483`) and **never
  checked by any acceptor** — this is the unclosed half of review finding **C-9**.
- **Accountability** — "can a node be held to what it promised?" That is the issuance-position
  question, and the only reason to keep a signature on a Promise at all.

**Recommendation: (1) demote, plus the ballot binding, and write the threat-model scope down.**
Promise equivocation needs an actively Byzantine roster member, which the same node could
exercise more cheaply via **K-3** (forged receipts served from store) or **K-5** (QC overwrite),
both still open — so buying accountability *here* first is fixing the third lock on an open
door. Revisit (2) once RC-1 and the store's unverified write path are closed and
Byzantine-node accountability is the actual frontier.

---

# RC-6 · the acceptor is denied the requester identity it needs

Three findings share one cause: `on_accept`/`on_roster_accept` receive no authenticated
requester, because the peer gate lives at daemon level (`_peer_authorized`).

- **K-2** — the possession frontier had to be taken from the requester's wire values (fixed by
  reading the op body instead, but the layering cause remains).
- **C-9 / K-14 capability** — the ballot's priority cannot be checked against the caller.
- Generally: L3 makes safety decisions with less context than L4 already holds.

`on_roster_accept`'s docstring states the rationale — *"so the acceptor stays free of the L6
control vocabulary"* — but ARCHITECTURE.md's own L6 matrix has nodes registering
`control/roster` (✓ in the node column) and `daemon.py` already runs a `ControlReducer` that
observes `RosterOp`. **The purity being protected does not exist.** Thread the authenticated
requester into L3 once, rather than working around its absence three times.

---

# D-1 · MEDIUM · C · `slot_state` is never pruned — unbounded durable growth

There is **no `DELETE FROM slot_state` anywhere in the codebase.** The void rule nulls
`accepted_ballot`/`accepted_op`; the row survives with its `promised`. And every CAS attempt
creates a *new* tag (`Slot(key, version, attempt)`), so:

> `slot_state` grows ~linearly in **total writes ever**, forever, on every node — in a system
> whose §12 GC exists to bound storage and which advertises "kilobytes of state".
> `gc_checkpoint` does not touch it. No document mentions it.

**The fix converges with FIX-1 and Harry's INTEGER ruling.** A slot whose accepted op is below
the horizon is already semantically void, so the row can be `DELETE`d outright rather than
nulled — collapsing growth to O(live contended slots). That prune is only expressible as an
indexed query — `DELETE FROM slot_state WHERE accepted_wall < ?` — **if** the accepted hlc is a
native `INTEGER` column. So FIX-1 stops being merely a bug fix and becomes the enabler for
bounding the one unbounded durable structure in the system.

Safety: deleting the row resets `promised` to `BLIND` for that tag, which is exactly what the
reborn-tag rule already sanctions for a below-horizon slot. No new exposure.

---

# Closed as unfounded: the attempts sidecar does NOT accumulate

Recorded so it is not re-litigated. Harry's concern was that the checkpoint system accumulates
`attempt` counters in perpetuity and passes them along, collecting cruft — especially if the
tunables are wrong. It does not. `compactor.py:289`:

```python
attempts = {k: e["attempt"] for k, e in barrier.items() if e["attempt"] > 0}
```

A **projection over live barrier state, recomputed from scratch each pass** — not an
append-only carry-forward. One `int` per key, replaced wholesale each checkpoint; keys at
attempt 0 excluded; `seal_attempts({})` returns `b""`, so an empty sidecar carries nothing.
Size is O(keys currently carrying a nonzero attempt) and **independent of retry volume or
tunable error** — a retry storm raises an integer, it does not add entries.

One honest caveat: tombstones are deliberately retained (the resurrection mask), so a *deleted*
key that had been contended keeps its entry. The key set is therefore monotone over "keys ever
created and contended" rather than strictly-live keys. That is semantically required — it is
what stops a zombie CAS matching after deletion — not cruft.

**The cruft instinct was right; the location was `slot_state` (D-1), one table over.**
