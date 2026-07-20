# HANDOFF-R4 — M7 work order: the daemon, the CLI, the demo

> **From:** designer/reviewer (Fable) · **To:** implementer (Opus) ·
> **Date:** 2026-07-21 · **Baseline:** `9141810` (169 tests green) plus the
> NOTES 45 / RESILIENCE §3.1 closure edits riding in the same commit-wave as
> this file.
>
> **Preamble — what this builds on.** HANDOFF-R3 is CLOSED (NOTES 44): the
> correctness wave, the chaos harness, six personas, and the fumbling-manager
> suite are landed and reviewed. **Finding 18 is CLOSED** (NOTES 45): the
> issuance chain is gap-free and the artifact-fork evidence is any-kind, so
> every accusation kind (FORK, DOUBLE_VOTE, FLOOR_PERJURY, SEQ_REUSE) is both
> sound and complete, and LOST_COMMIT covers disclosure. The issuance flow M7
> wires into a daemon is SETTLED — do not reopen it. Documents are canonical;
> discrepancies become NOTES items, never workarounds.

## Scope

M7 per IMPLEMENTATION §5: worker API over a socket; `dude
init/cert/node/status/get/set/cas`; the §9 runbook demo — 3 nodes + 2 client
nodes on localhost, `kill -9` any node mid-CAS-storm with nothing breaking,
then a disk wipe → identity retirement → learner re-add. M7 is
**composition**: the kernel is built and reviewed; the daemon is drivers
around it. The M3 discipline holds — the sans-io kernel stays pure (sockets
and clocks live in drivers only), and per NOTES 36(b): if any WP below turns
out to need NEW protocol behavior, STOP — it lands as its own unit-tested
step with a ruling on whether it is new or a restatement, before the WP
continues.

## WP1 — the node daemon (gate: my review before WP2/3)

1. **Process shell:** config file, store open (one durability domain), a
   unix-socket listener speaking the cluster framing (4-byte BE length +
   bencode, IMPLEMENTATION §2), dispatch to the acceptor verbs. TCP stays M8
   (transport pluggability is proven there, not here).
2. **The epidemic gossip loop** — the real one, replacing the test sweep:
   periodic anti-entropy against a uniformly random peer (digest-first
   SUMMARY, then DELTA), eager push on fresh accept as latency icing
   (PROTOCOL §2.2 — correctness rests on the periodic cycle alone).
   Cut-aware from day one: summaries advertise the retained projection
   (`covered ∖ dead`). Constants (period, fanout) are **lane-1 policy** —
   defaults in `tunables.py`, no doc ceremony (NOTES 32a).
3. **The checkpoint adoption pipeline:** on holding a quorum-committed
   checkpoint — verify authorization (ControlReducer) and the retained
   digests against own holdings, then `adopt_checkpoint` →
   `advance_horizon(horizon field)` → lazy `gc_checkpoint`. **Plus the §12
   receipt-floor-at-horizon backstop** (refuse to newly receipt below the
   horizon after GC): this is already-ruled protocol behavior (NOTES 34/Q5's
   third layer) — land it as its own unit-tested acceptor step FIRST, with
   its false-rejection pair (`hlc == horizon` accepted), then wire it.
4. **Recovery-fence observation:** the daemon recognizes a root-signed
   recovery pair among gossiped control ops and calls `on_recovery_fence` —
   WP4.7's test-driven calls become behavior. Nothing new: recognition +
   invocation only.
5. **The evidence duty-cycle:** after gossip rounds, run the detectors
   (`detect_double_votes`, `detect_seq_reuse` with observed watermarks,
   `detect_floor_perjury`); persist, gossip, and surface evidence in status.
   Honest-run-mints-nothing stays asserted in the sim.

## WP2 — client node daemon + worker API

PROTOCOL §6: JSON-lines over a unix socket, crossing no trust boundary. The
client daemon holds the identity + keyring, runs the sans-io quorum client,
maintains the fold cache. Verbs: `GET` (local fold read; `--linearizable`
runs the §1.2 quorum read), `SET` (blind write), `CAS` (the §1.3 flow,
end-to-end: read → propose → finality poll → verdict), `STATUS`, `WATCH` (a
stub returning `unimplemented` — §8 non-goal). Embeddable-as-library posture
preserved (the daemon is a thin shell over the same objects).

## WP3 — the `dude` CLI (MANAGER.md)

`init` (genesis + root key, refuses over existing state) · `cert
issue/revoke` (revoke stages rotate by default) · `node
spawn/learner-add/promote` (the §3.1 roster flow; cert-inventory print
before roster commands — NOTES 36c) · `status` (floors/lag health; the
zero-knowledge banner in dev builds) · `get/set/cas` passthrough · `recover`
with the **full MANAGER §3 interlock set**: mandatory dwell probe, hard
refusal while a quorum answers, named presumed-dead list, printed blast
radius, and the "recovery is never urgent" nag. The interlocks are
load-bearing design surface (RESILIENCE §2.3), not CLI decoration — they get
tests (a reachable quorum must hard-refuse).

## WP4 — the demo as an executable test

The IMPLEMENTATION §9 runbook, scripted and asserted: spawn 3 nodes + 2
clients on localhost; run a CAS storm; `kill -9` one node mid-storm —
commits keep landing, the restarted node re-joins via gossip; wipe a node's
disk — identity retirement (revoke + fresh key) and learner → promote
re-add. Optional, non-gating: fold the masher-drives-manager-verbs backlog
(NOTES 43) in here if it composes cheaply.

## Decision box (Harry): crypto-swap timing

Options: **(A)** swap to PyNaCl + `xcs1` during M7, demo runs encrypted;
**(B)** demo on the `auth0` dev scaffolding, swap as the first M8 wave.
**Recommendation: (B)** — M7's risk is composition and lifecycle; keep the
crypto variable frozen while the daemon is new, then land the swap as its
own reviewed wave behind the L0 boundary (it is mechanical: CRYPTO.md §4).
Either way `auth0` never ships (NOTES 42, one-scheme rule).

## Sequencing

WP1 → **STOP for my review** (the daemon shell + adoption pipeline + gossip
loop are the risk concentration) → WP2 + WP3 (parallelizable) → WP4 demo →
track review. `make check` green at every commit; found-and-fixed log
discipline (IMPLEMENTATION §6.7) continues; new tests seeded and replayable.
Non-gating backlog stays recorded: promise `issue_seq` (only if
promise-ordering accusations are ever wanted), the M4 same-author-gap
property (NOTES 43), masher manager-verbs.
