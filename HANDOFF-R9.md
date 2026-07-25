# HANDOFF-R9 — retire the sim transport: real daemons everywhere, a hair-thin fault seam

> **Goal.** Delete `dudefs/transports/memory.py` (the `MemoryTransport` fake network +
> `ClientRunner`/`drive` sim driver + `Scheduler`) and reforge the ~880 lines of tests over it
> onto the **real** daemons/machines. The ONLY thing left "simulated" is fault injection on
> message *delivery* — a hair-thin seam, not a parallel network+client. Preserve every invariant
> the sim tests guard (partition tolerance, time-skew, loss/dup/reorder resilience, hedge,
> recovery-under-partition, contention/single-decree, determinism).
>
> **From:** post-Keypair-wave (`6be77f7`), `fold._covered` collapsed (`962fa95`), 347 green.
> **Status: DESIGN — iterate the shapes below before executing.**

---

## 0. Enabling refactor — lift the decisions OUT of the daemon loops (do this FIRST)

The daemons should be thin wiring over tested subsystems; today the meat is buried in loops, so you
can only reach it by running a whole daemon (hence the sim). The move: **a frozen struct at every
seam whose `.of(tx, …)` classmethod is the ONLY store read; every rule/decision is a pure
function/method over that struct.** Draw the I/O boundary there and everything above it is
unit-testable with a hand-built struct — no store, clock, daemon, or sim. That is ~80% of the
sans-io win, and it is the `Baseline` instinct generalised.

### 0.1 What to lift (and what to leave)
- **`NodeDaemon.sync_once` is already a clean 7-step tick** ([daemon.py:538](dudefs/daemon.py)):
  `gossip_round · adopt_committed_checkpoints · observe_roster_activations · observe_fences ·
  evidence_cycle · refresh_peers · _rebuild_authz`, and `run_periodic` is thin — **leave those**. The
  smell is the `while` loops *inside* two steps:
  - **`adopt_committed_checkpoints`** ([daemon.py:330](dudefs/daemon.py) `while True:`) buries the
    6-check adoptability predicate → `CheckpointView.adoptable(op)` (§0.3/§0.4) + `_adopt_one() ->
    bool`; the method becomes `while self._adopt_one(): pass`.
  - **`observe_roster_activations`** ([daemon.py:497](dudefs/daemon.py) `while cands:`) →
    `_activate_one() -> bool`; method = `while self._activate_one(): pass`.
- **`CompactorDaemon.compact_once`** ([compactor_daemon.py:127](dudefs/compactor_daemon.py)) = one
  48-line pipeline → **decide / do**: `plan = compactor.plan_compaction(view, prev, F)` (PURE, returns
  a typed `CompactionPlan | None`); `if plan: self._commit_and_adopt(self._seal(plan))` (the thin I/O
  shell). Loop stays `while do_one`.

### 0.2 Modules — rules vs algorithm (the split)
`_cut_dominates` today lives in `daemon.py:63` and `compactor_daemon.py` does `from .daemon import
_cut_dominates` — a checkpoint *rule* homed in the node daemon, reached into by the compactor. That
cross-daemon import IS the shared chunk. Resolve into:

| `dudefs/checkpoint.py` (NEW) — the **rules** (WP-F invariants, both sides obey) | `dudefs/compactor.py` (existing) — the **algorithm** (author-only) |
|---|---|
| `cut_dominates(new, cur)` (move from `daemon.py`) | `compact(...) -> CompactResult` (fold retained + tail) |
| `CheckpointView` + `.adoptable(op)` (from `adopt_committed_checkpoints`) | `plan_compaction(view, prev, F) -> CompactionPlan \| None` (uses `checkpoint.cut_dominates`) |
| the primitives: `slot_bound` · `qc_final` · `minter_authorized` · `horizon_covers_cut` · `forward` | `_cut_at(ops, F)` / `_advances(cut, prev)` (author planning), `seal_/open_attempts`, `compact_genesis`, `verify_state_acc` |

The line: **`checkpoint.py` answers "is this checkpoint valid / adoptable / forward?" — imported by
BOTH the node (to adopt) and the compactor (to not-regress). `compactor.py` answers "how do I *build*
a checkpoint's compacted baseline?" — author-only.** The node imports `checkpoint`, never `compactor`.

### 0.3 The structs — all `Baseline`-shaped (frozen dataclass + `.of()` builder + behaviour)
```python
@dataclass(frozen=True)
class CheckpointView:                      # the adopt-decision's inputs; ONE store read via .of()
    ops: list[Op]; cut: Heads; horizon: HLC; adopted_seq: int; qcs: dict[bytes, QC]
    epoch: int; roster: list[PublicKey]; manager_pub: PublicKey
    @classmethod
    def of(cls, tx, *, epoch, roster, manager_pub) -> "CheckpointView": ...   # sole I/O boundary;
        # ALSO replays control ops into the authz reducer here -> .authorized(author, kind) is on self
    def authorized(self, author, kind) -> bool: ...
    def adoptable(self, op: CheckpointOp) -> bool: ...     # pure, like Baseline.mismatched

@dataclass(frozen=True)
class PrevState:                           # the compactor's own adopted baseline (was _prev_state)
    cut: Heads; retained: list[Op]; attempts: dict[bytes, int]
    @classmethod
    def of(cls, tx, keyring) -> "PrevState": ...

@dataclass(frozen=True)
class CompactionPlan:                      # plan_compaction's typed output (no loose tuple)
    cut: Heads; seq: int; committed: list[Op]; prev: PrevState; horizon: HLC
```

### 0.4 The rules as named predicates — composed tacitly (functional)
Don't leave `adoptable` as one method with 6 inline checks. Each rule is a small pure
`(view, op) -> bool`; compose declaratively:
```python
_RULES = (slot_bound, qc_final, minter_authorized, horizon_covers_cut, forward)
def adoptable(self, op): return all(rule(self, op) for rule in _RULES)
```
Wins: each rule unit-tested in isolation, **precise failure attribution** (which rule rejected), and
the composition reads as its own spec.

### 0.5 Test-surface impact — the payoff (integration → unit)
The WP-F invariants are today reachable only through a full daemon + store + quorum (+ sim for
adversarial cases). After §0 they are pure predicates over a crafted struct:

| invariant (finding) | today | after |
|---|---|---|
| slot-binding: seq-jump forgery rejected (`_reslot` exists *because* this is hard to reach) | forge raw envelope, run daemon, inspect store | `assert not view.adoptable(forged)` |
| QC-verify: sub-quorum / wrong-epoch / forged QC never drives GC (finding #5) | gossip a bad QC into a daemon | craft `qcs={h: bad_qc}`, one assert |
| horizon-covers-cut (finding #8) | seal a not-yet-final op through a cluster | craft ops `hlc > horizon`, one assert |
| forward-only / dominance (WP-F(a), finding #4) | two daemons racing cuts | two `Heads`, `cut_dominates(a, b)` |

~a dozen adversarial cases (the `_reslot`/`_forged_data` helpers) collapse to direct
`view.adoptable(op)` unit tests; the daemon's own tests shrink to **wiring** smoke tests (does the
tick call its steps, does the loop stop on `stop`). The sim's reason-to-exist evaporates.

### 0.6 The functional/OO line (chosen per layer)
| layer | style | why |
|---|---|---|
| rules (`slot_bound`, …) | functional — pure `(view, op) -> bool`, tacit `all(...)` | isolation + attribution |
| views / plans (`CheckpointView`, `CompactionPlan`, `PrevState`, `Baseline`) | OO — frozen dataclass + `.of()` + behaviour | one I/O boundary, craftable |
| machines (`Commit`/`Finalize`) | OO sans-io — stateful, `feed` → commands | driver-agnostic (§1) |
| daemons | thin imperative — `loop → tick → steps` | just wiring |

### 0.7 Sans-io enablers, ranked
1. **Structs at seams, `.of(tx)` the sole I/O touch** (§0.3) — the boundary that makes everything above pure.
2. **Effects-as-data / decide-do** — `plan → (pure)`, `apply → (thin shell)`; loop-until-done is `while do_one(): pass` with a pure `do_one`. (The quorum machine already emits `Send/Wake/Done` — that's *why* `StepDriver` works.)
3. **Injected clock/RNG** (already: `clock=lambda: 100`, `now` into `feed`) — never `time.time()`/`random` inside logic.
4. **Determinism = pure-function-of-input** — the fold already is; make the checkpoint rules the same, and a seeded fuzz is just replaying a pure function.

## 1. The finding that makes this cheap — the logic is already real & sans-io

`quorum.Commit` / `quorum.Finalize` are **pure sans-io machines** ([quorum.py:230](dudefs/quorum.py),
[:466](dudefs/quorum.py)): `start(now) -> [Command]`, `feed(Reply(node,req,resp,now) | Tick(now)) ->
[Command]`, where `Command ∈ {Send(node,req), Wake(at_ms), Done(outcome)}`. **No I/O inside.**

There are **two drivers of that same machine**:
- **Production:** `client._drive(machine, rpc, stop)` ([client.py:131](dudefs/client.py)) — a
  synchronous `rpc(node, req) -> Response | None` loop (real `Link`/`lmsg`/socket).
- **Sim:** `memory.ClientRunner`/`drive` ([memory.py:263](dudefs/transports/memory.py)) — an async
  pump over `MemoryTransport` + `Scheduler`, with a retransmit layer.

And the **nodes are already real**: `_harness.Sim` runs `LoggingNode(LocalNode(Acceptor))`
([_harness.py:79](tests/_harness.py)) — a trace wrapper over the real in-process node dispatch over
the real `Acceptor`. The gossip side is *already* reforged: `test_daemon.TestSansIoGossipDriver`
drives **real `NodeDaemon`s** through `summary()/_gossip_reply()/apply_gossip()`, choosing message
order itself.

**So the sim's only fake surface is the NETWORK + the async driver.** The Commit/Finalize/Acceptor
logic under test is production code. "Rip out the sim" = replace the fake network with real-node
calls + a thin delivery controller; keep everything else.

## 2. One deterministic driver over the real machine (not the threaded `_drive`)

Production `_drive` ([client.py:131](dudefs/client.py)) is **threaded** — `Send` fans out on worker
threads, `Wake` arms a real `threading.Timer` → `Tick`. Great for production; **useless as a
deterministic test driver** (thread interleavings). So the reforge drives the **same real
`Commit`/`Finalize` machine** through its sans-io `feed()` from a **single-threaded** test driver
with a **test clock** — the `TestSansIoGossipDriver` pattern, one level down (quorum machine instead
of gossip seam). This is deterministic by construction and exercises the exact invariant-bearing
logic. Faults are the driver's **delivery policy** (drop/dup/reorder/delay) over *real node
responses* — no fake transport. One driver covers BOTH sync faults (loss/adversary/skew — the node
just isn't delivered, or is an adversarial `Acceptor` subclass) and async faults (reorder/dup/hedge
— the test chooses Reply order). The **threaded production `_drive` + real `ClientDaemon`/`NodeDaemon`
over `inproc`** stay exercised end-to-end by `test_daemon` (the transport + threading shell); the
reforged invariant tests target the machine, deterministically.

**Retransmit finding (open Q#3 resolved).** `_drive` re-sends ONLY via the machine's `on_tick`
(Wake-driven hedge/timeout). The sim's `ClientRunner` added an **extra blind retransmit** every
`retransmit_ms` that production does NOT have. The `StepDriver` must mirror **production** (machine
`on_tick` re-send only). If any reforged loss-test then fails where the sim passed, it exposes a
real product gap (loss recovery that only ever worked in the sim) — surface it, don't paper over it
with a test-only retransmit.

## 3. Proposed shape — one thin test driver, `tests/_drive.py`

```python
# A hair-thin sans-io pump: feeds a REAL machine (Commit/Finalize) against REAL nodes,
# the test choosing delivery. No fake network, no parallel client — just "who answers, when".
class StepDriver:
    def __init__(self, machine, nodes: list[NodeVerbs], *, clock, faults: Faults | None = None): ...
    def run(self) -> object:            # pump to Done|deadline, applying `faults` to delivery
    # exact-control surface for Tier B tests:
    def pending_sends(self) -> list[tuple[int, Request]]   # what the machine wants to send now
    def deliver(self, node, *, dup=False): ...             # call the REAL node, feed the Reply
    def drop(self, node): ...                              # never feed it (loss/partition)
    def tick(self, now): ...                               # feed Tick (hedge/retransmit timers)
```
- `NodeVerbs` = the real node's callable verb surface — `LocalNode`(real `Acceptor`) for
  quorum-logic tests, or a real `NodeDaemon` for end-to-end.
- `faults`/`LinkModel` (the KEPT fault models, lifted out of `memory.py`) apply to *delivery of real
  responses*, not to a fake transport. Determinism = a seeded delivery order (same seed → same run),
  same guarantee the sim gives today; named-scenario tests use the explicit `deliver/drop/dup`
  surface instead of a policy.
- `StepDriver` mirrors production `_drive`'s re-send model (machine `on_tick` only — NO extra
  retransmit, per §2).

**Open shape questions to settle first (§6).**

## 4. Coverage inventory — every invariant must survive the reforge

| file | invariants (must be preserved) | tier |
|---|---|---|
| `test_sim.py` (305L) | single-decree/B1, split-vote recovery, minority-parks-majority-commits, one-way-link, flapping-heals, backward-step floor-monotone, past-gate, δ-skew commit, A1 fold-order-independence, B6 fork evidence, B3 finality→applied | A (most) + B (partitions/one-way) |
| `test_fumbling.py` (318L) | mistaken-recovery parks on heal, over-window lost-commit evidence, recovery-fence root-only under partition, manager retry-storm idempotent, double-press one-activation-across-crash, abandoned-flow never-half-activates, amnesiac reused-seq forks, button-masher random-chaos invariants | A + B |
| `test_chaos_compaction.py` (115L) | mixed-laziness GC digest stability + no oscillation, stale-frontier-below-cut no-wedge | **NodeDaemon gossip seams** (like `TestSansIoGossipDriver`) |
| `test_personas.py` (370L, 12T) | adversarial acceptors — split: the CONTAINMENT cases (`Sim(seed,n,personas={…})`: honest state unaffected by an equivocator/floor-perjurer) reforge onto `StepDriver`; the DIRECT-acceptor EVIDENCE cases ([:115-122](tests/test_personas.py#L115-L122) etc. — `Acceptor(…).on_accept(…)` asserting a portable proof mints, B6) are ALREADY unit-level, keep as-is. `_personas.py` (the persona subclasses) is KEPT — `test_daemon` reuses it. | containment → B; evidence already unit |
| `test_transport.py` (139L, 8T) | **tests `MemoryTransport`'s OWN behavior** (loss/dup/reorder/determinism of the mock) — the sim carrier's private API, nothing in the product depends on it. **PURE DELETE with the mock.** The real product-resilience claims it gestures at (hedge-masks-heavy-tail, asymmetric-dead-link-commits-via-others, burst-loss-survives, same-seed-determinism) are NOT re-homed FROM here — they are re-authored fresh as `StepDriver` Tier-B cases driving the REAL machine (§1 proves one; the reforged `test_sim` one-way/minority cases cover the rest). | delete (claims re-authored on `StepDriver`) |
| `_harness.py` (383L) | the `Sim` driver itself (`LoggingNode`, `ClientRunner` pump, `MemoryTransport` wiring) | → becomes `StepDriver` + real nodes |

`_harness.Sim` is imported by EXACTLY four files (`test_sim`, `test_fumbling`, `test_chaos_compaction`,
`test_personas`) — the precise reforge set. `test_carrier.py` is NOT a sim file (it tests the real
unix/HTTP carriers; it only names `transports.memory` in a comment) — leave it untouched.

**Deletes:** `transports/memory.py` (whole), `test_transport.py` (tested the mock — no invariant to
re-home), `_harness.Sim` + `ClientRunner`. **Keeps (lifted to `tests/`):** `Faults`,
`LinkModel`/`NetworkLinks`/`UniformLinks` (fault models), a deterministic clock/order,
`_personas.py` (persona subclasses, reused by `test_daemon`).

## 5. Staged plan (each a green `make check`)

0. **Enabling refactor (§0)** — lift the decisions out of the daemon loops into pure functions
   (`checkpoint.adoptable` / `plan_compaction` / the shared checkpoint-rules module) with unit tests;
   daemons shrink to `loop → tick → steps`. Wire-neutral, behaviour-preserving; land + green FIRST so
   the reforge below has real seams to drive.
1. **`tests/_drive.py`** — `StepDriver` + lift `Faults`/`LinkModel`/clock out of `memory.py`. Prove
   it on ONE reforged Tier-B case (loss+dup+reorder single-decree) driving real Commit + real
   `LocalNode`s. No production code changes.
2. **Reforge `test_sim.py`** — all cases onto `StepDriver` over real `Commit`/`Finalize` + real
   `LocalNode`s (explicit delivery for named scenarios: minority-parks, one-way, flapping; seeded
   `Faults` for fuzz). Assert the SAME invariants (single-decree, floor monotone,
   fold-order-independence).
3. **Reforge `test_fumbling.py`** — recovery + manager-chaos onto real nodes + real `Manager`.
4. **Reforge `test_chaos_compaction.py`** — onto real `NodeDaemon` gossip seams (extend the
   `TestSansIoGossipDriver` pattern with fault choices).
5. **Reforge `test_personas.py` containment cases** — the `Sim(personas={…})` cases onto `StepDriver`
   over real `Acceptor` personas (the persona subclasses ARE the node's `on_accept`, so they drop
   straight in); the direct-acceptor evidence cases already stand — no change.
6. **Delete** `transports/memory.py` + `test_transport.py` + `_harness.Sim`/`ClientRunner`; confirm
   nothing imports them (`_personas.py` stays). `make check` green, coverage checklist (§4) ticked.

## 6. Open questions — ITERATE HERE before executing

1. **How thin is thin? — RESOLVED (Harry).** Faults are expressed as **high-level, semantic delivery
   choices at the `Send`/`Reply` seam** — a policy `deliver(src, dst, msg, tick) -> bool` (plus
   dup/delay), keyed on *who/when*, never on message contents or wire bytes. That granularity is
   verb-agnostic: a new verb still flows through `Send`/`Reply`, so a "drop node N's replies until
   tick T" fault applies UNCHANGED — it won't be superseded when functionality is added, which was
   the requirement. BOTH modes over that one seam: explicit ordering for named scenarios
   (minority-parks, one-way, flapping), a seeded policy for the button-masher fuzz.
2. **Node granularity / retransmission coupling — RESOLVED (Harry's framing).** The real question was
   whether correctness is TIGHTLY COUPLED to network-level retransmission — i.e. does a machine that
   sent a message assume a reply WILL come? **It does not, and the design is sound.** Retransmission
   is a first-class *protocol* action: `Commit.feed(Tick)` past the round deadline calls `_escalate`,
   which begins a new round and RE-FANS-OUT Sends ([quorum.py:279-280](dudefs/quorum.py#L279-L280));
   the deadline `Wake` is armed at every round start ([:310](dudefs/quorum.py#L310),
   [:323](dudefs/quorum.py#L323)). A lost `Send`/`Reply` just leaves that round's slot empty and the
   deadline escalates — "even if the Nacks were lost." So `StepDriver` drives the **real machine over
   real `Acceptor`s** (the node's own `on_*`), injects loss at the delivery seam, and asserts the
   machine still reaches `Done` via escalation. No transport shell in the quorum-logic tier
   (`test_daemon` covers `NodeDaemon`'s lmsg/gossip/socket); a lost message that WEDGES is a real
   finding, surfaced not papered over.
3. **The extra retransmit — RESOLVED (drop it).** The sim's blind transport-level retransmit was
   REDUNDANT with the escalation of §6.2 and could mask a genuine wedge by resending where production
   never would. `StepDriver` mirrors production exactly (escalation only); the reforged loss tests
   assert escalation recovers. If one can't without the extra resend, that is a design defect to fix
   in the product (or the higher-layer `_drive_to_final` re-attempt), never a retransmit added back
   to the harness.
4. **Determinism contract.** Same-seed-replays-identically is a real property today. On `StepDriver`
   with a seeded delivery order we keep it; with fully-explicit delivery it's trivially deterministic.
   Confirm we still want a seeded-fuzz mode (button-masher) and where its seed lives.
5. **Clock/`Tick`.** Hedge + retransmit are timer-driven (`Wake(at_ms)`). The StepDriver needs a
   test clock that advances on `tick()`. Deterministic and explicit — fine — but confirm the hedge
   timing (`delta_hedge`) is exercised in at least one reforged test (it's a real latency-masking path).
6. **§0 module boundary — RESOLVED in §0.2/§0.3.** `checkpoint.py` = the shared rules (`cut_dominates`,
   `CheckpointView.adoptable`, the primitives); `compactor.py` = the algorithm + `plan_compaction`.
   Snapshots are `Baseline`-shaped frozen structs (`CheckpointView`/`PrevState`/`CompactionPlan`) with
   `.of(tx)` as the sole I/O boundary. Only remaining nit: `plan_compaction` in `compactor.py`
   (author-side) vs `checkpoint.py` (next to `adoptable`) — leaning `compactor.py` so `checkpoint.py`
   stays purely the shared rules.

---

### Appendix — why this isn't the drift we killed
The earlier objection ("a separate product tested against itself") was about `MemoryTransport` +
`ClientRunner` being a parallel network+driver. But the **machine** they drive (`Commit`/`Finalize`)
and the **nodes** (`Acceptor`) were always production. R9 removes the parallel network+driver and
drives the same production machine/nodes through their sans-io seams — so "green" finally means the
product works, not that the mock does.
