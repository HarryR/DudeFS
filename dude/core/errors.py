# dude — error hierarchy (package root).
#
# One tree, so a consumer can `except DudeError` to catch anything this package raises,
# `except <module>.<ModuleError>` for one module, or a specific leaf for one failure.
# Per-module bases live in their own modules and subclass DudeError; this file holds only
# the root and imports nothing, so every module can depend on it without a cycle.
#
# The distinction that matters (#no-exceptions-for-control-flow, and the crash-only precondition in
# crashonly.py):
# an error in this tree is a KNOWN, EXPECTED outcome — including adversarial input at a decode
# boundary. Anything outside this tree is a bug, and a bug takes the process down. So adding a
# subclass here is a statement that the condition is one we can knowingly recover from.


class DudeError(Exception):
    """Root of every error raised by `dude`. Module bases (CodecError, CryptoError, …)
    subclass it; `except DudeError` catches all of them."""
