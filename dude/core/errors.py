# dude — error hierarchy (package root).
#
# One tree, so a consumer can `except DudeError` to catch anything this package raises,
# `except <module>.<ModuleError>` for one module, or a specific leaf for one failure.
# Per-module bases live in their own modules and subclass DudeError; this file holds only
# the root and imports nothing, so every module can depend on it without a cycle.
#
# THE DISTINCTION THAT MATTERS (#no-exceptions-for-control-flow, and the crash-only precondition in
# crashonly.py) is THEIR FAULT versus OURS, and it is expressed as two trees rather than one:
#
#   DudeError          their fault. A KNOWN, EXPECTED outcome — including adversarial input at a
#                      decode boundary. Costs one frame; the process keeps serving. Adding a
#                      subclass here is a statement that the condition is one we can knowingly
#                      recover from.
#
#   InvariantError  our fault. Something this node believed about its OWN state is false.
#                      Unrecoverable by construction, so it is deliberately NOT a `DudeError` —
#                      no `except DudeError` anywhere can swallow it, and it reaches `crashonly`.
#
# `[H]` The two used to be one tree, and the conflation has cost real time repeatedly: a routine
# refusal raised as an exception escaped a frame handler and took a node down, while a genuine
# invariant violation was indistinguishable from it at every boundary that tried to catch one and
# not the other. Two roots make "which of these is it" a type question rather than a judgement call
# at the catch site.


class DudeError(Exception):
    """Root of every error raised by `dude` that is THEIR fault. Module bases (CodecError,
    CryptoError, …) subclass it; `except DudeError` catches all of them."""


class InvariantError(Exception):
    """Something this node believed about its own state is false — OUR fault, and terminal.

    NOT a `DudeError`, and that is the whole design: catchability is structural rather than a
    convention nobody can enforce at a distance. A boundary that drops hostile input cannot also
    accidentally drop the news that our own store is broken, because the only tree it names does
    not contain this class.

    Raise it for a violated postcondition, never for a decision. "Collection changed the state
    accumulator" is this; "your run does not reconcile with what you signed" is not — that one is
    routine, and routine outcomes are RETURNED."""
