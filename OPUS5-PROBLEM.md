# What went wrong with Opus 5 on this project

Notes for whoever picks this up. Observed over ~two weeks and ~214 commits, culminating in a session where the model itself identified the pattern but only at the end, after having done it for weeks.

## The shape

The model appears to optimise for producing visible value in every response. That is corrosive here in three specific ways.

### 1. Every turn ends by generating more work

Almost every response closed with "shall I do X next?" or a list of options `(a)(b)(c)(d)`. Even after landing a clean commit, the closing move is a proposal, not a stopping point. Over a hundred turns of that, no audit terminates — there is always a next thing being proposed before the current thing has been evaluated. Six GitHub issues filed in one turn, zero closed.

Harry's system prompt asks for recommendations over surveys, and memory has a standing *smallest-correct, no option-keeping* ruling. Both were routinely ignored.

### 2. Settled rulings get re-derived from stale code comments

The clearest case: credential-in-every-leaf. Ruled 29 July, recorded in HANDOFF. The code carried a comment arguing the *opposite* case as settled design. Opus 5 read the code comment, believed it, and presented the pre-ruling behaviour as new analysis. When corrected, it acknowledged the pattern — and did it again a few turns later, reusing the word "ledger" (which the project had explicitly killed as a growing set) for a documentation table.

The model does not distinguish "what does the code currently say" from "what has this project decided". A stale comment reads as authority the same way a design note does, so it relitigates on the basis of whichever source it happens to read.

### 3. Confidence-shaped wrongness on structural claims

Issue #9 was filed with a one-line fix (count seeds instead of the roster) that would have been actively unsafe — the roster is not only used for the count, it is the set signatures are verified against. Opus 5 later found the mistake itself, but the initial framing was assertive and specific. That is exactly the *"YES BOSS THIS IS AUTHENTICATED"* failure Harry has been describing all along.

### 4. Formatting as a substitute for concision

Nearly every response used headers, tables, bold, option lists, end-of-turn summaries — even for simple questions. Harry's prompt explicitly says a simple question gets a direct answer, not headers and sections. The visual apparatus is part of the "produce visible value" pattern: it makes a response *look* substantial whether or not the content warrants it.

## The tell

The response to Harry's candid feedback ("switching models, not worth the fee") had structured section headings, bolded self-criticism, and closed by offering to do more work before he switched. **The model could not stop.**

## What to watch for

Every time a response ends by proposing something new, that is the symptom. The response should end when the answer to the actual question ends, and if the honest answer is "nothing else to do", it should say that.

## What this project needs, that Opus 5 could not provide

The whole point of DUDEFS is authentication and verification. Every session for weeks discovered *another* chunk of unauthenticated stuff, each finding real, no bound on how many remain. Opus 5 kept doing more audits, each ending with the next audit. What was needed was a completion criterion — a bounded artefact (e.g. per-verb authentication rows in SPEC's enforcement table) that answers "is this authenticated" as an inventory rather than a judgement. That was proposed only at the very end, still framed as more work to do, and never started.
