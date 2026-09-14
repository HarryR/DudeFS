# Rules

## Memory

Keep CLAUDE.md concise. Don't duplicate rules into memory files.
Memory is for things not visible at project level: user context,
design assumptions, process pointers.

## Git safety

Never: checkout/restore/reset/stash/clean on paths. To undo, reverse the edit.
Never checkout old commits to compare — use `git show`.

## Comments and documents

A comment names the silent regression it prevents. Nothing else survives.
No new documents. Reasoning in commits, work tracking in GitHub issues.

## Gate

`make check` green before every commit.
Don't re-run the suite for flakes without asking.
Don't install packages without explicit permission. Use uv + Makefile.

## Tests

Write tests that exercise the production path end-to-end as a real caller
would use it. Run coverage to find untested edges, then fold those into
existing tests where the state is already set up.

## Working agreements

Decisions as plain-text options, never the popup.
Review = read-only, don't run the gate.
Smallest-correct, no option-keeping.
Commit whole subjects, never half-working.
Don't commit without explicit authorisation.
Don't spawn subagents without explicit permission.
Python 3.12+. No `from __future__ import annotations` in new files.

## Design assumptions

Wall time (NTP) is load-bearing. Freshness is a wall-clock bound.
Do not replace with logical clocks or re-derive the opposite.

## Traps

1. Encode and decode must live on the same class. Split pairs drift.
2. Expected outcomes are return values, not exceptions. Exceptions are bugs.
3. Assert old content before replacing. No blind edits.
4. A dispatch path must advance the state it dispatches on. Timers race events.
