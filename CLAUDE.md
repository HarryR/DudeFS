# Working in this repository

## Never move the working tree to a committed state

`git checkout -- <path>`, `git restore`, `git reset --hard`, `git stash`, `git clean` and
`git show HEAD:<path> > <path>` all replace a file with HEAD, silently, taking every uncommitted
change in it. There is no reflog for a file that was never committed.

**To undo an edit, reverse the edit**, as narrowly as the change was. Gutting a function for a
revert-check? `cp` to the scratchpad first, `cp` back after, `diff` to prove the restore.

Switching branches (`git checkout -b`, `git switch`) is fine. It is the **path form** that destroys.

## Comments and documents

**A comment must name the specific regression that returns silently if it is deleted.** If you
cannot name one, delete it. This kills header essays, banners, cross-references, restatements of
the code below them, and most docstrings. What survives is traps: why a value is that value, why
the obvious simplification is wrong.

**Do not add a document.** Reasoning goes in commit messages, work not yet done goes in GitHub
issues, and neither goes into a new file. A stale justification is worse than none: it reads as
authority.

## The gate

`make check` — lint, format-check, typecheck, test. Green before a commit.

Repeated runs of the suite to hunt a flake cost about eight minutes of CPU. **Ask first**, and only
for scheduling, threading, ordering, timing or the wire. Where two runs cannot differ, six greens
say exactly what one green said.

## Three rules about tests

- **Test the production path, driven the way production drives it.** A test calling a handler
  directly proves the handler works and says nothing about whether anything calls it.
- **Revert-check every fix, and the revert must fail for the reason you predicted.** A revert that
  dies of `AttributeError` because the old shape no longer resolves has proved nothing and
  certified something. A fix whose test passes either way is not held by anything.
- **A test that passes first time is a suspect, not a result.** Instrument it: assert that the
  state it claims to exercise actually moved.

## Working agreements

- Ask decisions as **plain-text options in the reply**, never the popup — it is copy-hostile.
- A review request means **reading only**. Do not run the gate during a review.
- **Smallest-correct, no option-keeping.** Do not preserve alternatives "in case".
- Commit whole subjects. Granular commits that leave the tree half-working corrupt the history.

## Traps this codebase keeps hitting

1. **Two halves of one fact drifting apart, in SILENCE.** Encode and decode; the preview that
   computes a block's anchors and the applier that settles it. Each half stays self-consistent
   alone, so round-trips do not catch it. Pin the pair against each other.
2. **Applying locally what the quorum should agree.** Assert `log_accumulator()` across nodes, not
   just `accumulator()`.
3. **Routine outcomes raised as exceptions.** Decisions are returned, not raised. Anything that is
   not a `DudeError` sails through the crash-only boundary.
4. **Blind edits.** `assert old in v` before every string replace. Never run a line-rewrapper over
   source — it cannot tell code from prose. Moving code between scopes means `Write` the whole file.
5. **A default right for one caller and silently wrong for another.** Make the wrong thing
   unsayable.
6. **State advanced on a timer, raced by the events that depend on it.** A dispatch path must
   advance the state it dispatches on.
