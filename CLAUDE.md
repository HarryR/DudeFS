# Working in this repository

## NEVER MOVE THE WORKING TREE TO A COMMITTED STATE

**This has destroyed uncommitted work repeatedly. It is the single most expensive habit here.**

`git checkout -- <path>` does not undo your last edit. It replaces the file with HEAD, taking every
uncommitted change in it, silently. There is no reflog for a file that was never committed. Same
destroyer: `git restore`, `git reset --hard`, `git stash`, `git clean`, and
`git show HEAD:<path> > <path>` — that last is not obviously in the family and is exactly as final.

**To undo an edit, reverse the edit**, as narrowly as the change was. Gutting a function for a
revert-check? `cp` to the scratchpad first, `cp` back after, `diff` to prove the restore.

Switching branches (`git checkout -b`, `git switch`) is fine. It is the **path form** that destroys.

## Where the record lives

| file | holds |
|---|---|
| `SPEC.md` | requirements, and the enforcement table |
| `README.md` | what this is, for someone arriving |
| `PYTHON-CODESTYLE.md` | how the code is written |
| `CLAUDE.md` | this: how to work here |
| git history | why anything changed — commit messages carry the reasoning |
| GitHub issues | work not yet done |

**A comment must name the specific regression that returns silently if it is deleted.** If you
cannot name one, delete it. This kills header essays, banners, cross-references, restatements of
the code below them, and most docstrings. What survives is traps: why a value is that value, what
broke last time, why the obvious simplification is wrong.

**Do not add a document.** Handover notes, framing essays, plans and threat models all lived here
and were retired — each accumulated superseded reasoning that read as current, and a stale
justification is worse than none because it reads as authority.

## The gate

`make check` — lint, format-check, typecheck, test. Green before a commit.

**The flake loop is occasional and it is Harry's call to spend it.** Six runs is about eight
minutes — **ask first**, and say what in the change makes it worth the time.

```sh
for i in 1 2 3 4 5 6; do .venv/bin/python -m unittest discover -s dude/tests -t . -q 2>&1 | tail -2; done
```

One failure mode only: a race a single green run does not disprove — one appeared in 2 of 6 runs
and passed the first time. Propose it for **scheduling, threading, ordering, timing, or the wire**.
Where two runs cannot differ, six greens say exactly what one green said.

## Three rules about tests

**Test the production path, driven the way production drives it.** A test calling a handler
directly proves the handler works and says nothing about whether anything calls it. One test that
ran a node's own `tick` found four defects in an afternoon, including that no production request
had ever registered itself as awaiting a reply — every solicited answer was served correctly and
discarded at the door, nothing errored, and a node simply never synced.

**Revert-check every fix, and the revert must fail for the reason you predicted.** A revert that
dies of `AttributeError` because the old shape no longer resolves has proved nothing and certified
something. A fix whose test passes either way is not held by anything.

**A test that passes first time is a suspect, not a result.** Instrument it — frames actually
mutated, branches actually reached. An exploit test once passed while mutating zero frames, because
the client had lagged and never made the request.

## Working with Harry

- Ask decisions as **plain-text options in the reply**. He dislikes the popup — it is copy-hostile.
- He rules, then expects the work built and tested. Give a recommendation, not a survey.
- A review request means **reading only**. Do not run the gate on his behalf during a review.
- **Smallest-correct, no option-keeping.** Do not preserve alternatives "in case".
- Commit whole subjects. Granular commits that leave the tree half-working corrupt the history.

## Traps this codebase keeps hitting

Each cost real time, most of them twice.

1. **Encode/decode halves drifting apart, in SILENCE.** A field added to the record and the decoder
   but not the signer: every artifact on the wire decoded to nothing and the cluster quietly stopped
   collecting, no error anywhere. Round-trips do not catch it — both halves are self-consistent
   alone. Pin every such pair by **field count**, as `test_..._agree_on_field_count` does.
2. **Applying locally what the quorum should agree.** Three honest nodes held byte-different logs at
   identical indices while `A_state` and `head` agreed throughout, which is why nothing noticed.
   **Assert `log_accumulator()` across nodes**, not just `accumulator()`.
3. **Routine outcomes raised as exceptions, escaping frame handlers.** A duplicate-settlement
   `IntegrityError` was not even a `DudeError`, so it sailed through the crash-only boundary.
   Decisions are returned, not raised.
4. **Parameters stashed on `self` for another method to read.** A floor passed to one entry point
   and saved on the node was silently unenforced on every other path.
5. **Test builders quietly dropping fields.** A helper that re-homed mutations dropped `epoch`, so a
   whole suite wrote the default and passed vacuously.
6. **Blind edits failing silently.** `assert old in v` before every string replace. **Never run a
   line-rewrapper over source** — it cannot tell code from prose, and has broken nine files and the
   SQL schema. And moving code between scopes means `Write` the whole file: index arithmetic over
   the source has interleaved two class bodies into each other.
7. **A mitigation nothing consults, and a ruling nothing builds.** `tests/test_wired.py` catches the
   first mechanically and fails the moment a debt is repaid, so the list cannot rot. Nothing catches
   the second: a ruling recorded where the code still argues the old way is invisible to whoever
   reads the code next.
8. **A default right for one caller and silently wrong for another.** `await_reply` defaulting to
   `False` meant no production request ever awaited its answer. Make the wrong thing unsayable.
9. **State advanced on a timer, raced by the events that depend on it.** `on_round_msg` routed on
   state only `tick` advanced, so a peer's HELD/SIG arriving in the pre-tick window was dropped as
   "no matching Round" and consensus stalled — looking exactly like packet loss at every layer we
   inspected. **A dispatch path must advance the state it dispatches on.**
