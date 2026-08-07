# Working in this repository

## Where the record lives

**`SPEC.md` is the spec, and it is the only design document.** It states requirements and nothing
else. Every rule carries an anchor (`{#some-tag}`); code cites the anchor, never a file or a section
number. Its enforcement table maps each requirement to what enforces it, or marks it **OWED** — a
row with no enforcer is a requirement nothing performs, and saying so is the point.

Everything else has a job that is not "design discussion":

| file | holds |
|---|---|
| `SPEC.md` | requirements, and the enforcement table |
| `README.md` | what this is, for someone arriving |
| `PYTHON-CODESTYLE.md` | how the code is written |
| `CLAUDE.md` | this: how to work here |
| git history | why anything changed — commit messages carry the reasoning |
| GitHub issues | work not yet done |

**Do not add a document.** Handover notes, framing essays, plans and threat models all existed here
and were retired at `HEAD` — every one of them accumulated superseded reasoning that read as current,
and a stale justification is worse than no justification because it reads as authority. If a decision
needs recording: a requirement goes in SPEC, a reason goes in the code beside what it explains, a
history goes in the commit message, and an open question goes in an issue.

## The gate

`make check` — lint, format-check, typecheck, test. It must be green before a commit.

**The flake loop is occasional, and it is Harry's call to spend it.** Six full runs is roughly
eight minutes, so it is not part of the ordinary gate — **ask before running it**, and say what
in the change makes it worth the time.

```sh
for i in 1 2 3 4 5 6; do .venv/bin/python -m unittest discover -s dude/tests -t . -q 2>&1 | tail -2; done
```

It exists for one failure mode: a race that a single green run does not disprove. A
duplicate-settlement race once appeared in 2 of 6 runs and passed the first time; the state walk
stalled in roughly half of them. So it is worth proposing when a change touches **scheduling,
threading, ordering, timing, or the wire** — anything where two runs can legitimately differ.

It buys nothing on a change that cannot vary between runs: a rename, a type split, a docstring, a
pure refactor with no new control flow. Running it there is not caution, it is eight minutes and a
misleading signal — six greens on a deterministic change say exactly what one green said.

## Two rules about tests

**Test the production path, driven the way production drives it.** A test that calls a handler
directly proves the handler works and says nothing about whether anything calls it. Writing one
end-to-end test that ran a node's own `tick` found four defects in one afternoon — including that no
production request had ever registered itself as awaiting a reply, so every solicited answer in the
system was served correctly and discarded at the door. Nothing errored; a node simply never synced.

**Revert-check every fix.** Put the old code back and confirm the new test fails. A fix whose test
passes either way is not held by anything.

## Working with Harry

- Ask decisions as **plain-text options in the reply**. He dislikes the popup — it is copy-hostile.
- He rules, then expects the work built and tested. Give a recommendation, not a survey.
- A review request means **reading only**. Do not run the gate on his behalf during a review.
- **Smallest-correct, no option-keeping.** A standing ruling: do not preserve alternatives "in case".

## Traps this codebase keeps hitting

Each of these cost real time, most of them twice.

1. **Encode/decode halves drifting apart, failing in SILENCE.** Twice. `attest_bytes` had no inverse;
   then `acc_log` was added to the entry and the decoder but not to `attest_bytes`. Both times every
   claim on the wire decoded to nothing and the cluster quietly stopped collecting, with no error
   anywhere. Round-trip tests do not catch it — both halves are self-consistent in isolation.
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
   argument saved on the node, so the peer-driven path used whatever a local call had last left
   behind. The dedup floor was silently unenforced on half the code paths.
5. **Test builders quietly dropping fields.** `_at` in `test_store.py` re-homed mutations and dropped
   `epoch`, so every conveyor test wrote `EPOCH_NONE` and passed vacuously.
6. **Blind string-replace edits failing silently.** `assert old in v` before every replace. And
   **never run a line-rewrapper over source** — it cannot tell code from prose, and has broken nine
   files and the SQL schema between them.
7. **A mitigation nothing consults, and a ruling nothing builds.** These are duals and both recur.
   `tests/test_wired.py` catches the first mechanically: `WIRED`/`OWED` for checks, `DRIVEN`/
   `UNDRIVEN` for duties, and the test fails the moment a debt is repaid so the list cannot rot.
   Nothing catches the second — a ruling recorded outside the code while the code argues the old way
   is invisible to whoever reads the code next. That is why rulings go into SPEC as requirements and
   into the comment beside the thing they govern, and never into a note.
8. **A default that is right for one caller and silently wrong for another.** `Held.cred` defaulting
   to empty would have made an unauthenticated leaf constructible by forgetting an argument;
   `Mailbox.post`'s `await_reply` defaulting to `False` meant no production request ever awaited its
   answer. Make the wrong thing unsayable rather than discouraged.
9. **State advancement scheduled on a timer that races the events depending on it.** Consensus
   state (`settling`, `current_round`, `current_bucket`, `mempool`) was only advanced by
   `Coordinator.tick`, called on `tick_interval` cadence from `Node._run`. `Coordinator.on_round_msg`
   and `on_settle_msg` dispatched incoming frames by routing on THAT state -- so a peer's HELD/SIG
   for the current bucket that arrived in the ~tick_interval window before our own tick had
   advanced state was dropped as "no matching Round" / "not for the block we are settling", and
   consensus stalled on buckets the whole cluster held the same tx for. Mempool stayed at one tx
   per node, empty blocks streamed past, one SUBMIT never settled -- looked exactly like a
   reflood-loss bug at every layer we inspected. First try (tick-per-frame in `Node._run`) was
   correct but blunt: O(F) full node ticks including reconcile / postman / follower. Second try
   (a narrower `_close_current_bucket` sub-primitive) was insufficient because opening the next
   Round requires the previous one to have TICKED to ABANDONED first. Real fix: `on_round_msg` and
   `on_settle_msg` invoke `Coordinator.tick(now)` themselves before dispatching -- the atomic
   state-advance primitive is what the dispatch path needs, and it's O(1) in steady state and only
   runs per-Round/Settle-message (not per-frame). The scheduled tick and the message-triggered
   tick land at the same state; the naming makes the invariant load-bearing rather than a lucky
   property of timing.
