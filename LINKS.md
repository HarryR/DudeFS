# LINKS.md — multi-homed links, and the rules they follow

How a node decides where to send, what counts as a failure, and what it may believe about a link's
behaviour. Scoped to the **link layer only**: everything here sits below [MEMPOOL.md](MEMPOOL.md) and
carries the envelopes of [TRANSPORT.md](TRANSPORT.md) without understanding any of them.

Provenance as in [SPEC.md](SPEC.md): **[H]** Harry's ruling, **[I]** inference not yet ruled on.
**[C]** marks a rule taken from the published canon rather than derived here — the point of this
document **[H]**: *"a few extremely well considered and widely deployed rules to abide by that have
been battle tested."* Nothing in §2 is our invention, and that is the intent.

Not merged into the codebase. `dude/net/mailbox.py` currently violates rules 5, 6 and 7.

---

## 1. Two objects, and the distinction is the whole layer

| | is | identified by | fails |
|---|---|---|---|
| **Peer** | a participant | its public key | never — a peer is not up or down, only reachable or not right now |
| **Link** | one path to a peer | `(peer, address)` | often, transiently, and independently of the peer |

**A peer has many links and they are not interchangeable in behaviour.** A unix socket and a mixnet
hop to the same node differ by orders of magnitude in latency and variance, so anything measured must
be measured per link, never per peer.

**Three objects, not two.** The set of links to one peer is itself a thing, and it is where
multi-homing lives — `dude/net/link.py`'s `Peer`:

| | owns | knows nothing about |
|---|---|---|
| `Link` | one path's estimator, breaker, transport | its siblings, messages, retries |
| `Peer` | the link set, selection, stagger (R7), the shared retry budget | messages, correlation |
| `Mailbox` | messages, deadlines, `mid` correlation, attempt bookkeeping | paths |

The tell that `Peer` was missing: `RetryBudget` is peer-scoped while everything else is link-scoped,
so it had nowhere to live but the caller. Attempt bookkeeping stays in `Mailbox` because it is
per-*message* — `mid -> [(link, sent_at, ts)]` — and `Mailbox` therefore decides **attributability**
and hands `Peer` the verdict, since only it knows how many links a message went out on.

**Which is where `reply_ts` (§3.4a) pays off twice.** One attempt outstanding gives
`rtt = now - sent_at`, attributed. Several attempts, and Karn says discard — *unless* the reply echoes
the attempt's `ts`, which matches it to exactly one entry and recovers both the sample and the link.
**Without it, R7 means the more you multi-home the less you know about your links**; with it,
staggering stays measurable.

**Reconfiguration is a diff, never a rebuild [H].** A new endpoint set is applied by adding and
removing, and **surviving links keep their state**. Not an optimisation: rebuilding would reset every
estimator and, far worse, every breaker — so a roster edit would become a way to silently un-break a
broken link, with an open circuit coming back CLOSED and being dialled at once on no evidence.
Endpoints change for reasons unrelated to a path's health, so health must survive the change. A
removed address stops being selectable immediately; an attempt already in flight on it cannot be
cancelled, so a late reply for a departed link is simply unattributable — a case §3.3 already covers.

**Per `(peer, address)` rather than per address [I].** The measured quantity is end-to-end to a
specific peer, and an address may be shared — a relay or proxy fronting several nodes. If it is shared
and we key per address, one peer's slow backend is blamed on another, which is a wrong measurement
silently. If it is *not* shared and we key per `(peer, address)`, we merely keep some redundant state.
The costs are asymmetric, so the safe key wins.

## 2. The rules

### R1 — Identity is not the path **[C]**

QUIC's connection id exists so a connection survives a change of address ([RFC 9000]): the peer is the
id, not the four-tuple.

**Here:** correlation is by `mid`, and *never* by the link a message arrived on. **Send on link A,
receive on link B is normal traffic, not an anomaly to detect.** This is the property the
mailbox/transport split exists to provide **[H]**.

*Already satisfied* — `Mailbox.arrived` matches on `reply_to` and cannot see a link.

### R2 — Never sample RTT from a retransmission **[C]**

Karn & Partridge (SIGCOMM 1987), normative in [RFC 6298] §3: if a message was sent more than once you
cannot tell which transmission the reply answers, so the sample is meaningless — and using it
attributes a slow path's reply to a fast path, poisoning the estimate in the direction that makes
timeouts too short.

**Multi-homing makes this strictly worse than TCP's case**: not only *which transmission*, but *which
link*. A reply arriving on link B after attempts on A and B tells you nothing about either.

**Rule: an RTT sample counts only from a message transmitted exactly once, on exactly one link.**

### R3 — Predictability is mean plus four deviations **[C]**

[RFC 6298] §2, per link:

```
RTTVAR = (1 - β)·RTTVAR + β·|SRTT - R|        β = 1/4
SRTT   = (1 - α)·SRTT   + α·R                 α = 1/8
RTO    = SRTT + max(G, 4·RTTVAR)              floored
```

Note the order: `RTTVAR` updates against the *old* `SRTT`. The load-bearing part is `4·RTTVAR` —
**variance, not the average, is what a timeout must be built from**, which is exactly why a
naive "timeout = 2× average" behaves so badly on a link with occasional long tails.

### R4 — A timeout is a suspicion; a failure is a decision **[C]**

Circuit breaker (Nygard, *Release It!*; deployed in Envoy, resilience4j, gRPC): **closed** → N
consecutive failures → **open** (fail immediately, attempt nothing) → after a cooldown → **half-open**
(exactly one probe) → closed on success, open on failure.

One timeout says almost nothing. The φ-accrual detectors used in Cassandra and Akka exist because
binary up/down is a lie about a distribution.

**Rule: nothing outside the breaker may declare a link down.** A single expiry adjusts state; it does
not produce a verdict.

### R5 — Backoff always carries jitter **[C]**

AWS, [*Exponential Backoff and Jitter*][aws-jitter]: **decorrelated jitter**,
`sleep = min(cap, random(base, prev·3))`, matching the AWS SDK default.

The randomisation is the point, not the growth: a fixed delay re-synchronises every client that failed
together, so a recovering peer is met by a thundering herd of perfectly aligned retries.

**We violate this** — `Mailbox.backoff` is a constant 250 ms, which is precisely that shape.

### R6 — Budget retries as a fraction of traffic, not per request **[C]**

Google's SRE book, and gRPC retry throttling. The reason per-request limits are insufficient: they
*multiply*. Three layers each retrying three times is twenty-seven attempts for one logical request,
and every layer is individually within its limit. This is the rule most often missing, and the one
that converts a brownout into an outage.

**We have nothing here at all.**

**How the budget is computed [C]** — a token bucket, gRPC's `retryThrottling` shape:

```
tokens        starts at max_tokens
a retry       costs 1 token, and is refused if tokens < 1
a success     returns token_ratio tokens (0.1), capped at max_tokens
```

So under sustained failure retries decay to roughly `token_ratio` of traffic, and a healthy peer
refills to full. It is a *ratio of traffic*, not a count per message, which is exactly the property
per-request limits lack.

**Where it sits: per PEER [I].** Not per link — links fail independently by design, and that is what
multi-homing is *for*, so a per-link budget would fight R7. Not global either, since one dead peer
would then starve retries to healthy ones. Per peer matches §1's rule that the peer is the unit of
reachability, and confines a failing peer's cost to itself.

**And staggered attempts spend from the same budget [I].** R7's parallel dial is extra load on the
peer whether or not we call it a retry. Charging it makes the two rules interlock rather than
compete: when a peer is healthy the budget is full and staggering is free, and as it degrades the
budget collapses staggering back to serial failover — **Happy Eyeballs turns itself off exactly when
parallel dialling would be harmful**, with no separate health check deciding that.

### R7 — Stagger multi-homed attempts; do not fail over serially **[C]**

Happy Eyeballs v2 ([RFC 8305]): begin the next attempt after a **Connection Attempt Delay of 250 ms**
rather than waiting for the previous one to time out, and take whichever answers first.

Serial failover makes worst-case latency the *sum* of every address's timeout, so a peer whose first
address is a blackhole is unreachable for the length of a full timeout even though its second address
is healthy.

**We violate this** — `_next_address` is strictly serial.

### R8 — At-least-once delivery makes exactly-once processing the receiver's job **[C]**

Every rule above generates duplicates deliberately. The receiver dedups on the idempotency key and
**returns the cached response to a duplicate instead of re-executing** (Stripe's idempotency keys are
the widely-deployed form).

`mid` is that key. **[H]** *"strong idempotence matters a lot"* — and it is not a nicety: it is the
precondition that makes R5, R7 and every retry safe to have.

**But the obligation is much smaller than the rule implies here, and it is per verb [H].**

Two things are being conflated in the general statement of R8, and this system already has one of
them. *Execution* idempotence for a submitted transaction is provided by the store: duplicates are
dropped on `op_hash`, and the mempool refuses a re-offered transaction outright (MEMPOOL.md §1.2). So
a duplicate `SUBMIT` cannot double-execute no matter what this layer does.

What a cache would add is only **answer stability** — returning the *same* response to a duplicate
rather than a freshly computed one. That is worth much less, and it is needed only for verbs whose
re-execution is not equivalent to execution:

| verb class | example | needs a response cache? |
|---|---|---|
| naturally idempotent reads | `FETCH`, `PULL`, `FRONTIER` | **no** — just re-execute |
| liveness | `PING` | **no** |
| effectful, already deduped downstream | `SUBMIT` | only for answer stability |

So the cache is per-verb policy rather than a flat TTL, its retention is a tunable, and the
application may set it **[H]**. Most verbs opt out entirely.

### The anti-rule — do NOT be liberal in what you accept **[C]**

The Robustness Principle ([RFC 1122] §1.2.2) is now understood as a cause of ossification and
implementation divergence; the IETF's own protocol-maintenance work argues against it. It is the exact
mechanism by which two implementations drift apart while both appear to work.

**Be strict in what you accept, and fail loudly.** This is the closed-`Verb` ruling in another domain.

## 3. Consequences worth stating separately

### 3.1 PING is the primary source of measurement, not a liveness nicety

Follows from R2 + R7, and it is the non-obvious result of this document.

Under multi-homing, **most real traffic is disqualified from producing an RTT sample**: anything
retried, and anything staggered across two links, is ambiguous by Karn. A busy node could therefore
run for a long time with a link it has never measured — and R3's timeout and R4's breaker both need
measurements.

So the periodic `PING` exists to manufacture clean samples: one transmission, one link, never staggered,
never retried. That is what makes it the answer to **[H]** *"the occasional ping, latency
identification, round-trip time stuff"* — the occasional ping is not checking liveness as such, it is
**the only reliably valid measurement in the system**.

**[I]** A link should be pinged when it has gone longer than some interval without a valid sample,
not on a fixed schedule — a link carrying clean single-attempt traffic needs no pings at all.

### 3.2 R7 and R8 are a package

Staggering *deliberately* sends one message down two paths. It is only sound because `mid` dedup makes
the duplicate harmless. Taking R7 without R8 means deliberately double-executing writes. **Neither is
safe to adopt alone.**

### 3.3 What a failure is

Per link, in order of confidence:

| observation | confidence | effect |
|---|---|---|
| transport refused to dial / wrote an error | high — the local stack knows | breaker failure, no RTT sample |
| deadline expired with no reply, single attempt on this link | medium | breaker failure, no RTT sample (R2) |
| deadline expired, message staggered or retried | **none** | **nothing** — unattributable to any link |

That last row is the discipline this document mostly exists to enforce. An expiry that cannot be
attributed must not be charged to a link, or a healthy link accumulates other links' failures and the
breaker opens on the wrong one.

### 3.4 What the wire has to change

Most of §2 is sender-side bookkeeping and touches nothing: R3's estimator, R4's breaker and R5's
jitter are entirely local, and R1 is already satisfied. Three things do.

**(a) A reply must echo the request's timestamp — `reply_ts` [C].** The one real format change.

R2 disqualifies most traffic from producing a sample, and §3.1 concluded that `PING` therefore becomes
the primary measurement. That conclusion is *correct but weak*, and worth reversing: measuring a link
only with synthetic pings means **measuring it while idle, so the estimate is most wrong exactly when
it matters most — under load.**

TCP solved this with the Timestamps option ([RFC 7323]): the reply echoes the value it saw, so a reply
is attributable to a specific transmission and **Karn's restriction lifts**. Under multi-homing it does
more work than it does for TCP, because attempt *n* went out on a known link — so an echoed timestamp
identifies both **which transmission** and **which link**, which is exactly the pair §3.3 says is
otherwise unattributable.

Since a retransmit is restamped and re-signed, `(mid, ts)` names one attempt. The reply carries
`reply_to = mid` as now, plus `reply_ts = ts` of the attempt it answers.

- *Caveat [I]:* two attempts within the same millisecond would collide. Backoff makes that unlikely,
  and the failure mode is a slightly wrong sample — no worse than the Karn behaviour it replaces.
- *It also fixes a latent trap:* `Envelope.answer()` currently seeds the reply's `ts` from the
  **request's** `ts`, so a caller forgetting `.at(now)` sends a reply that still passes the freshness
  window while carrying the wrong time. With an explicit echo field the request's time has its own
  home and the reply's own `ts` has to be set, so the mistake stops being expressible.

**(b) ~~`REFUSED` carries pushback~~ — STRUCK for v1 [H].** Server-side pushback (HTTP's
`Retry-After`, gRPC's `grpc-retry-pushback-ms`) would let an overloaded receiver say *"do not retry for
N ms"*. **[H]** *"I'm not going to implement the logic here initially; if it needs it it'll be in a very
limited set of circumstances."*

Recorded rather than deleted because the reasoning survives if it comes back: R6's budget is then
purely sender-side, which is guesswork about the receiver's state — acceptable because the budget is
per-peer and self-correcting (a receiver that stops answering depletes its own bucket), and because
`REFUSED`'s `body` is already opaque, so adding a retry-after later is a body schema change and not a
framing change. **Nothing needs to be reserved for it now.**

**(c) The dedup key is `(frm, mid)`, never `mid` alone [I].** An interpretation rule rather than a
format change, but a security one: **`mid` is chosen by the sender.** If a receiver keys R8's dedup
cache on `mid` alone, any peer can pick another peer's `mid` and either suppress that request or be
served its cached response. Scoping to the envelope's authenticated `frm` closes it, and `frm` is
already signed.

Two properties that need no change and are worth recording so nobody "fixes" them:

- **Retransmissions are unlinkable to an observer.** A sealed box is non-deterministic and the screen
  tag covers the sealed bytes, so the same envelope sent twice produces different bytes *and* a
  different tag. An observer watching both links cannot correlate the two attempts.
- **Frame replay is already harmless** once R8 holds: a captured frame replayed later hits the dedup
  cache and receives the cached response. Idempotence is doing double duty as the framing layer's
  replay defence, which is why no anti-replay field is needed on the envelope.

## 4. What changes in the codebase

| | where | change |
|---|---|---|
| R2, R3, R4 | new `dude/net/link.py` | per-`(peer, address)` `SRTT`/`RTTVAR`/`RTO` and breaker state; sample admission gated on single-attempt-single-link |
| R5 | `Mailbox` | decorrelated jitter replaces the constant `backoff` |
| R6 | `Mailbox` | a retry budget shared across all peers |
| R7 | `Peer` | ✅ sketched — `choose()` picks up to `max_parallel` usable links, budget-gated; `stagger_delay()` is `min(cap, best link's RTO)` rather than RFC 8305's flat 250 ms, because unlike a browser we *have* per-link history |
| R7 | `Mailbox` | `due()` may return several transmits for one `mid`, staggered by that delay |
| R8 | receiver side | dedup on **`(frm, mid)`** with a cached response, not merely a dropped duplicate |
| §3.4a | `Envelope` | **`reply_ts`** — the one wire change; also removes `answer()`'s inherited-`ts` trap |
| §3.4b | `REFUSED` | a body schema: reason **and** retry-after |
| §3.1 | driver | ping a link that has gone too long without a valid sample — much rarer once `reply_ts` lands, since ordinary traffic then measures |

R7 is the one that changes a signature: `due()` currently returns at most one `Transmit` per message
and the in-flight flag assumes it. Staggering means several transmits may be outstanding for one
`mid`, and `failed()` must therefore name **which attempt** failed rather than just the message.

## 5. Open

**No constant in this document may live in the module that uses it [H]:** *"having any tunables deep
within code is just going to linger."* The Connection Attempt Delay, the budget's `max_tokens` and
`token_ratio`, the breaker's threshold and cooldown, the backoff cap and every response-cache retention
belong on ONE tunables surface, sourced from the management store so they are consensus-agreed at a log
position (MEMPOOL.md §7.5). `Mailbox.backoff = 250` is exactly the buried constant that ruling
forbids, and `mempool.Tunables` is the shape the consolidated one should take.

| # | Question | Owner |
|---|---|---|
| 1 | Consolidate `mempool.Tunables`, the envelope window, and every value above into one tunables type before any of this is merged | next |
| 2 | Retry budget numbers — gRPC's defaults are `max_tokens=10`, `token_ratio=0.1`; a 10–30 node roster where every node needs every body may want a slower decay | tunable |
| 3 | ~~Breaker health into gossip~~ — **deferred [H]**: incremental cluster-health QoL, tack on later | closed |

[RFC 6298]: https://www.rfc-editor.org/rfc/rfc6298
[RFC 8305]: https://datatracker.ietf.org/doc/html/rfc8305
[RFC 9000]: https://www.rfc-editor.org/rfc/rfc9000
[RFC 1122]: https://www.rfc-editor.org/rfc/rfc1122
[aws-jitter]: https://aws.amazon.com/blogs/architecture/exponential-backoff-and-jitter/

[RFC 7323]: https://www.rfc-editor.org/rfc/rfc7323
