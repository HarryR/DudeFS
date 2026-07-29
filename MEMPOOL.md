# MEMPOOL.md — the mempool and its gossip

The node-side sub-protocol that turns *arriving transactions* into *a slice proposed for settlement*.
Deliberately isolated: everything above it receives a slice that has already been decided, and
everything below it is transport.

Provenance marks as in [SPEC.md](SPEC.md): **[H]** is Harry's ruling, **[I]** is inference that has
not been ruled on. An [I] next to a mechanism means it is not yet load-bearing.

Nothing here is implemented yet — [dude/quorum.py](dude/quorum.py) is the only landed piece.

---

## 0. The loop

**[H]** *"Find the largest intersection within a time slice of transactions, choose those as a slice
and get quorum on the slice choice, settle them and kick the rejected transactions back into the
mempool (dropping those that can't be applied any more given the settled current state), rinse and
repeat forever."*

That is the whole specification of this layer. Everything below is mechanism for it.

```
   clients submit ─→ [ mempool ]
                          │
              (1) attested gossip: bodies spread, holdings become verifiable
                          │
              (2) PROPOSE  a slice — the largest intersection within this bucket
                          │
              (3) CONFIRM  the slice by quorum: "yes, this slice is the slice"
                          │
              (4) SETTLE   the slice through settle.evaluate → the log
                          │
              (5) RETURN   rejects to the mempool, dropping the now-unappliable
                          │
                          └────────────────────────── forever
```

## 1. Buckets

**[H]** *"The bucketing for time is partly just a convention to help agree on the same slice and…
slice up the work should it be coming in quick and fast."* — and **[H]** *"the convention acts as a
safety rail, yes it's safety, yes it's a convention."*

Both at once, and the two are not in tension:

- **Convention**, because a bucket is *arithmetic on the transaction's own timestamp* — `bucket = ts / δ`
  **[H]**. Boundaries are therefore **computed, never negotiated**. There is no protocol for agreeing
  where a bucket starts, no message about it, and nothing to disagree about: every node derives the same
  bucket id for the same transaction with zero communication. That is the whole of the "agreement aid".
- **Safety rail**, because that same arithmetic bounds what may be settled together and how far in
  time a transaction may travel before it lands. Not a rail because it is *negotiated* — a rail because
  it is *not*.

Its two jobs: raise the probability that two nodes propose the same slice, and slice up the work when
transactions arrive quickly so one ever-growing slice is not proposed.

### 1.1 The admission gate

A transaction is refused at the door if its `ts` is outside `W_admit` of the receiving node's now
**[H]**. This is the *only* place a client's clock is judged, and refusal is the desired outcome: a
client with a broken clock is told, immediately, by every node it talks to.

`W_admit` has a floor: it must exceed worst-case delivery, or an honest client with a correct clock is
refused for being slow rather than wrong.

**Late transactions are carried forward, not stranded.** A transaction whose derived bucket has already
passed lands in a later one, so a client running behind has its writes settle a few buckets further
ahead than its own clock suggests, **bounded by `W_admit`** **[H]**. The bucket is a floor, not an
exclusion window; nothing that passes the gate can be stranded by arithmetic.

### 1.2 W_valid — and why it is small

Endorsers cannot re-apply `W_admit`: that would make confirmation require all `q` endorsers' windows to
agree on every member, so any skew kills otherwise-valid slices. Admission is the admitting node's
business.

But something must be checked at endorsement, or an *unguarded* write is replayable indefinitely by any
node. Hence `W_valid`, checked by every endorser — and **[H]** it is *"a function of the window size,
and still relatively small"*, not hours.

The argument for small is stronger than a preference, because the primary replay defence is not the
clock at all:

> **Exact replay is caught by dedup on the transaction hash**, which the store can do because it
> already holds `op_hash`. `W_valid` exists only to keep the replayable window *inside the horizon over
> which dedup still works* — and **compaction collects entries, so `op_hash` retention is bounded**.
>
> Therefore: **`W_valid` < compaction horizon.** An `W_valid` of hours would exceed it and reopen the
> exact hole it was introduced to close.

`W_valid` differs from `W_admit` only by pipeline latency — a transaction admitted at the edge of
`W_admit` is endorsed a wave or two later — so `W_valid = W_admit + O(δ)`. A margin of a couple of
buckets, not a second tier.

### 1.3 Broken nodes are not accommodated

**[H]** *"If its clock is fubar it's useless to me and I'm not going to add complexity to account for
nodes that are broken."*

A node whose clock is broken is not a case to be handled — it is **detected and replaced**: node clocks
ride along in gossip as a diagnostic (§8), and `manager.node_replace` is the remedy.

**And the exclusion happens lower than this document, at the framing layer** **[H]**. The p2p envelope
carries its own timestamp and is *gated on it*, so a node outside the window **cannot hold a conversation
at all** — the door closes on defect. The check is mutual, so such a node self-partitions symmetrically
rather than being partially present. See [TRANSPORT.md](TRANSPORT.md) and `dude/net/envelope.py`.

Consequence **[I]**, and it is stronger than an earlier draft of this document claimed: there is no
regime in which a node is *skewed enough to matter but still endorsing*. Either its clock is inside the
envelope window, in which case skew costs it throughput — a poorly-chosen slice, a lost round, never a
wrong log — or it is outside, in which case it is **mute**. Two regimes, no third, and no code for one.
SPEC §2.6 should be revisited against this split.

## 2. Attestation is an artifact, not the decision

**[H]** *"The certificate making membership evidence-backed instead is simply an artifact of the
cryptographically attested gossip protocol — it's the agreement towards 'yes this slice is the slice'
which is then later confirmed — it's a proposed slice."*

**A correction is recorded here on purpose.** Having read Narwhal's certificate-of-availability, I
argued that self-certifying batch membership *replaced* the agreement step — that if a slice's contents
were provable, no one needed to agree on the choice. That was wrong, and the shape of the error is
worth keeping: I mistook *evidence about the contents* for *agreement about the selection*.

The two are separate, and both are needed:

| | question | answered by |
|---|---|---|
| attestation | "did these transactions really exist, held by whom?" | signatures accumulated during gossip |
| confirmation | "is **this** the slice we are settling?" | a quorum, per §4 |

Attestation falls out of the gossip protocol for free, because gossip is signed anyway. It buys
verifiability of a proposal's contents — which is what lets a node accept a slice it did not assemble.
It does not choose.

## 3. Gossip: what moves, and how much

### 3.1 Naming a subset is cheap; inverting a name costs 2ⁿ

An early idea was to enumerate the ECMH powerset of a bucket, then broadcast the 32-byte accumulator of
one's best subset. **The powerset is 2ⁿ, not quadratic** — 20 transactions is a million subsets, 30 is
a billion — so enumeration dies almost immediately.

But the instinct is right and already satisfied: **ECMH names any subset in 32 bytes, incrementally, with
no enumeration at all.** The powerset was only needed to *invert* a name — to discover which subset an
accumulator denotes. That is never necessary, because **whoever names a subset can also enumerate it**,
and the accumulator then serves as the O(1) check that the enumeration matches the name.

So: accumulators are commitments, not compression. Naming is free; inverting is not; nothing needs
inverting.

### 3.2 Set reconciliation: the correct mechanism, and why we decline it

The proper tool for recovering a set *difference* from a compact sketch is **PinSketch** — a BCH
syndrome, `minisketch`, deployed in Erlay/BIP330 — at O(d) bytes for a difference of size d.

We decline it, for a reason Erlay itself supplies: **Erlay increases network-wide relay time from
3.15 s to 5.75 s** to buy its bandwidth saving. Bitcoin can pay ~80% more latency against a 10-minute
block time. Here, wave latency *is* finality latency, so it is the exact inverse of the priority.

The arithmetic, with `n` nodes, `m` transactions per slice, `b` body bytes:

| scheme | announcement bytes | body bytes | round trips |
|---|---|---|---|
| flood everything | — | m·b·fanout | 1 |
| announce + pull | m·32·fanout | m·b | 2 |
| PinSketch | d·32 | m·b | 2–3, needs a `d` estimate, may fail to decode |

`m·b` appears in every row and dominates: in a roster of 10–30 where a slice must be held by ≥ q nodes,
**every node needs every body anyway**. All the cleverness competes over the announcement term alone —
at m=1000, 32 KB versus ~2 KB, i.e. under 1 MB/s across the whole roster, in exchange for a round trip
added to a δ that is only a few round trips wide.

**Ruling [I]: flood announcements, pull bodies. No reconciliation in v1.** Revisit at m ≈ 10⁴–10⁵ per
slice. The upgrade path is prefix-sharded accumulators (compare shard roots, recurse into differing
shards), which reuses machinery we already have; **rateless** Bloom filters
(`rateless-bloom-filters-2025`) are the alternative worth reading first, because they need no `d`
estimate — the operational objection to both PinSketch and IBLT.

### 3.3 Pull, not push — and Narwhal agrees

> *"We do not implement the standard push strategy that requires quadratic communication, but instead
> use a pull strategy to make sure we do not pay the communication penalty in the common case."*
> — Narwhal §4.1

Their creator sends a batch once, collects signatures, and thereafter **only metadata moves** (their
reference is 32 B + 8 B). Missing bodies are pulled on demand: `O(1)` active requests per item, `O(n)`
worst case under active attack, which matches the theoretical lower bound. Their scale-out to 600k tx/s
comes from *sharding bodies across workers*, never from set algebra.

Same conclusion as §3.2, reached independently and measured.

## 4. Proposing and confirming a slice

### 4.1 One batch per node per bucket

**[I]**, transposed from Narwhal's validity condition (4) — a block is valid only if it is *"the first
one received from the creator for round r"*, and signers refuse to sign a second.

Each node forms **one** batch per bucket, from transactions it received directly from clients, and
gossips it. Two consequences:

- **Equivocation cannot produce two confirmed batches.** Any two quorums share at least
  `2q − n` members (see [dude/quorum.py](dude/quorum.py)); if that overlap contains an honest node, and
  honest nodes sign only the first batch per `(node, bucket)`, then two conflicting batches can never
  both reach a quorum of signatures. **No trusted counter is required** — which is precisely the
  distinction for which TrInc is shelved as a non-fit (SPEC 6.3).
- **The slice-selection space is bounded by n, not by m.** A bucket contains at most `n` batches, so
  choosing a slice is choosing among ≤ n objects. At n=10–30 that is small enough to reason about
  exhaustively even though 2ⁿ is still too large to enumerate.

### 4.2 Attestation gives retrievability, not delivery

Narwhal is explicit, and it is the more useful reading:

> *"A certificate-of-availability does not guarantee the totality property needed for reliable
> broadcast: it may be that some honest nodes receive a block but others do not."*

Totality is recovered *afterwards*: because ≥ `q − f` honest nodes hold each attested batch, any node
can pull it, and a handful of requests succeeds with exponentially growing probability.

So "held by ≥ q" obliges the data to be **available**, not **delivered**. That is a materially cheaper
obligation than the one I had been assuming, and it is what makes a node able to confirm a slice
containing a batch it has not yet downloaded.

### 4.3 Confirmation

The step **[H]** calls *"get quorum on the slice choice"*. A node that proposes a slice, and a node that
receives a proposal it can verify (§4.2), both endorse it; `dude.quorum.satisfied(n, endorsements)`
decides. **[I]** If no slice reaches a quorum within the bucket, the round yields nothing and its
transactions fall into the next bucket — disagreement costs a round, never correctness, matching
"skew fails closed".

## 5. Settlement and re-entry

Settlement is already built and needs nothing new: `settle.would_apply(reader, slice, auth)` returns
`(survivors, rejects)` over a `Layer`, touching no storage — the same evaluator the store, the client,
and this layer all use, so all three agree by construction.

Re-entry is where **[H]**'s *"dropping those that can't be applied any more"* needs a distinction the
phrasing hides: **reject reasons are not equally final.**

| verdict | can it ever become valid? | action |
|---|---|---|
| `signature` | never | drop permanently |
| `authority` | yes — a grant may be re-issued | keep |
| `guard` | yes — a predicate may become true again | keep |

So "cannot be applied" must mean *cannot be applied now*, and evicting on it would discard transactions
that are merely early. **[I]** Re-screen and keep, evicting on an **age horizon** against the author
timestamp; Bitcoin's precedent is age-based expiry (14 days) plus fee-rate ordering when full. **The
horizon value is an open question — Harry owes a number.**

## 6. What does not transfer from Narwhal, and why it matters

Narwhal's pacing is **entirely message-driven** — a validator advances to round r once it holds `2f+1`
certificates from r−1. No clocks anywhere. And its ordering trick is: *don't agree on a set, agree on
one anchor and take its causal closure* — *"given a certificate all validators see the same causal
history."*

That would dissolve the round-agreement problem outright. It is unavailable here, because anchor
selection needs a leader (Narwhal-HotStuff) or a shared random coin (Tusk), and both are excluded — no
leaders per SPEC 2.17, no beacon, no threshold crypto.

**So the clock is what buys leaderlessness.** The δ-bucket is not merely a convenience over Narwhal's
design; it is what replaces the anchor. That reframes §1: the bucket is a *convention* in how precisely
it must be shared, but it is *structural* in that removing it forces the excluded machinery back in.

Adoptable: certificates of availability, first-batch-per-bucket anti-equivocation, pull-not-push,
metadata-only references. Not adoptable: anchor-based causal-closure ordering — which is exactly the
part that makes their agreement free, and exactly where
[ROUND-AGREEMENT.md](ROUND-AGREEMENT.md)'s open §2.29 sits.

## 7. Leakage

The mempool sees plaintext *structure* and no plaintext *values* — transactions carry AEAD ciphertext
under keys storage nodes never hold, and predicates quote a ciphertext digest rather than recomputing
one.

Worth stating plainly: **this is an encrypted mempool by construction.** Shutter and Ferveo spend DKG
plus threshold encryption to obtain it, and `choudhuri-mempool-privacy-attacks-2024` is evidence that
the resulting machinery is attackable. We get the property by not holding the key, and we exclude the
machinery.

What the mempool *does* leak is unchanged from SPEC §7's closed list: existence, timing, size, store
id, and name token. Nothing here adds to it.

## 7.5 Tunables live in the management store

**[H]** The predecessor modelled everything on accepted clock skew and expected inter-node round-trip
time in a `tunables.py`. These move into the management database, **adjustable at runtime**, because the
transport varies — a mixnet carrying ultra-durability and anti-gorilla measures is a different δ from a
LAN.

The gain is bigger than flexibility: a tunable in the management store is a **consensus-agreed value at
a log position**, so every node uses the same δ at the same position. A local config file cannot rule out
silent per-node drift; this can. Mechanically it is already supported — `Management` writers return
transactions, so a tunable change is an ordinary authorised write.

Known shape and size **[H]**: compaction is most likely **daily**, probably paired with twice-daily
backups. Which settles §1.2's constraint rather than leaving it open — a `W_valid` measured in seconds
sits nowhere near a daily compaction horizon. Backward clock steps are **tens of seconds** on nodes with
good NTP discipline, so §8's persistence requirement is a small durability fix, not a design problem.

**One caveat [I].** Because `bucket = ts / δ`, changing δ **re-buckets everything**. A δ change must take
effect at a boundary aligned to both the old and the new value, or bucket ids are ambiguous across the
change. Raising δ is safe; lowering it can strand in-flight proposals.

## 8. Clock faults, case by case

Inside this layer: **the clock may choose, it may not judge.** It is consulted when deciding what to
*propose* and at the admission gate. It appears nowhere in verifying a proposal, settling it (settlement
is by log index), or replaying it (replay does not re-adjudicate, SPEC 8.13). A node can therefore check
a confirmed slice completely **without consulting its own clock**, which is why it follows a quorum
result rather than being told to.

Judgement on clocks happens **one layer down**, at the envelope (§1.3): a badly-skewed node is refused
the conversation rather than tolerated as a poor participant. So the cases below are all *within* the
envelope window — outside it there is nothing to analyse, because nothing is exchanged.

| situation | effect |
|---|---|
| **Skewed client, correct nodes** | The good failure: refused at the gate by every node, immediately and observably. The only clock fault with a built-in signal. |
| **Skewed node, correct clients** | Disagrees on admission *in both directions* — refuses legitimate transactions whose `ts` reads as stale, admits ones from equally-skewed clients that correct nodes refuse. Its mempool both lacks and exceeds its peers'. It still endorses, still counts toward quorum, still syncs; its own proposals are just poorly chosen. Push the skew past the envelope window and it stops being a participant at all — there is no middle regime. |
| **All nodes drift together** | The outage with no internal signal — same bad NTP server, every window shifts, correct clients refused *en masse*, and nothing inside notices because the nodes agree with each other. Hence gossiping each node's now: a node can see it is the outlier. **Diagnostic, never a gate** (same ruling as envelope epoch in TRANSPORT). |
| **Split skew, no quorum either side** | Only stalls if an endorser demands the proposal's bucket match its own local one. It must not: **bucket labels are advisory, endorsement is on contents.** Two slices for one bucket may then both confirm, which is harmless *because settlement dedups by transaction hash* — the same dedup §1.2 relies on. |
| **Clock steps backward** | NTP correction, VM suspend/resume, leap second. The node re-enters a bucket it has already proposed for and proposes a **second** batch — precisely the equivocation §4.1 convicts on, with no malice involved. **Highest-bucket-proposed must be persistent and monotone**, or a crash plus a backward step manufactures the fault. Same class as the previous package's finding 19 (horizon not persisted across restart), and the likeliest of these to happen in production. Use a monotonic clock for intra-process progression; the wall clock only for bucket ids. |
| **Client backdates deliberately** | The only *profitable* clock fault. If selection orders by `(ts, tx_hash)`, an older `ts` sorts earlier, so backdating buys ordering priority — bounded by `W_admit`, and with no fee auction the only prize is winning CAS races on a contended key. Open, §9. |

## 9. Open

**[H]** δ, `W_admit`, `W_valid` and the eviction horizon are **tunables of known shape and size** (§7.5) —
deployment values, not design questions. They are not listed here. What remains:

| # | Question | Owner |
|---|---|---|
| 0 | **Carry-forward vs drop-and-re-issue.** §1.1 says a late transaction is relocated to a current bucket. **[H]** later: *"when the tunables gate says no, and/or the predicates say no… it gets dropped, and it's up to the client to monitor the state of the transactions it's trying to get included and re-issue them according to whatever logic the application layer decides."* Those are different models — node-side relocation vs client-side retry — and drop-and-re-issue is the simpler one, since it keeps the node from silently altering which bucket a client signed for. `Mempool.admit` currently carries forward. **Unsettled; the liveness window is where this lands.** | Harry |
| 1 | Backdating for ordering priority: accept a `W_admit`-bounded advantage, or order by hash alone and give up `ts` fairness? (§8) — the only clock fault that is *profitable* rather than costly | Harry |
| 2 | Does confirmation endorse a slice *digest*, or the slice *contents*? Digest is smaller; contents let a node detect it is confirming something it mis-assembled | [I] |
| 3 | SPEC §2.6 against §1.3's two regimes — skew within `W_valid` costs throughput, beyond it costs participation, and there is no third case | doc |
| 4 | Round agreement itself: SPEC 2.29 / ROUND-AGREEMENT, unchanged by this document | open |
