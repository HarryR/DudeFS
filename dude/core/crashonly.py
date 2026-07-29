# dude/core/crashonly.py — let it crash, loudly, and take the process with it.
#
# The rule: errors we can KNOWINGLY recover from as part of routine operation are caught and
# returned as typed results (see errors.py). Everything else is thrown — the thread dies, the
# process dies with it, and the cause goes on the record. Respawning a supervised process and
# reading what killed it beats trying to handle every case in-line, so `except Exception` at a
# loop top is the bug, not the cure: it turns a silent thread death into a silent infinite retry.
#
# This module is what makes that true. Python's default is the opposite: a long-lived loop on a
# `daemon=True` thread loses only THAT thread to an uncaught exception, so the process keeps
# serving while silently doing none of its work. A silently half-dead daemon is strictly worse
# than a dead one.
#
# THE PRECONDITION, which is not optional: this is only safe because hostile input is a TYPED,
# EXPECTED outcome at every decode boundary — `codec` raises CodecError for over-deep nesting
# and oversized integers, and every wire decode arity-checks before indexing. Without that,
# "crash on anything unexpected" hands an unauthenticated peer a remote kill switch. Typed
# parsing first, crash-only second, in that order. The previous package installed crash-only
# while its codec could still raise RecursionError through dict nesting; that combination was
# a remote process kill, and it is why this comment names the ordering as a precondition
# rather than a preference.

from __future__ import annotations

import logging
import os
import sys
import threading
import types

log = logging.getLogger(__name__)


def _die(kind: str, exc: BaseException | None, tb: types.TracebackType | None) -> None:
    log.critical(
        "%s died — taking the process down so a supervisor can respawn it",
        kind,
        exc_info=(
            type(exc) if exc is not None else BaseException,
            exc if exc is not None else BaseException(),
            tb,
        ),
    )
    for h in logging.getLogger().handlers:
        h.flush()
    sys.stderr.flush()
    # os._exit, not sys.exit: we are (usually) on a non-main thread, where SystemExit would
    # only unwind THAT thread and leave the half-dead process alive — the exact failure we are
    # here to prevent. No atexit/finalizers: the store's durability is fsync-on-COMMIT, so
    # there is nothing to flush that correctness depends on (RESILIENCE §0).
    os._exit(70)  # EX_SOFTWARE


def install() -> None:
    """Make an uncaught exception anywhere fatal to the PROCESS, with the cause logged.

    Call once from a `serve` entry point. Idempotent-ish: re-installing simply re-points the
    hooks at the same handler. Left OUT of library/test paths on purpose — importing `dude`
    must never install a process-killing hook."""
    threading.excepthook = lambda a: _die(
        f"thread {a.thread.name if a.thread else '?'}", a.exc_value, a.exc_traceback
    )
    # `_et` is the exception TYPE, unused: `_die` re-derives it from the value.
    sys.excepthook = lambda _et, ev, tb: _die("main thread", ev, tb)


def configure_logging(level: int = logging.INFO) -> None:
    """Standard per-module logging, wired at the entry point only.

    Modules do `log = logging.getLogger(__name__)` and never configure anything — so a library
    embedder keeps full control of handlers, and `dude.*` slots into an existing logging
    setup the ordinary way. Only the CLI, which owns the process, calls this."""
    logging.basicConfig(
        level=level,
        format="%(asctime)s %(levelname)-8s %(name)s: %(message)s",
        stream=sys.stderr,
    )
