# dudefs/crashonly.py — let it crash, loudly, and take the process with it.
#
# The ruling (Harry, review RC-4): errors we can KNOWINGLY recover from as part of routine
# operation are caught and returned as typed results. Everything else is thrown — the thread
# should die, the daemon should die with it, and the cause should be on the record. Respawning
# a supervised process and reading what killed it beats trying to handle every case in-line.
#
# This module is the piece that makes that true. Python's default is the opposite: every
# long-lived loop runs on a `daemon=True` thread, so an uncaught exception kills only THAT
# thread — the process keeps serving, silently missing gossip, checkpoint adoption, roster
# activation, fence observation and evidence detection, with `status()` showing nothing wrong
# (review IO-3). A silent partial daemon is strictly worse than a dead one.
#
# NOTE the precondition, which is not optional: this is only safe because hostile input is a
# TYPED, EXPECTED outcome at every decode boundary — `codec` raises CodecError for oversized
# ints and over-deep nesting (K-9), `wire.decode_request` arity-checks every arm (IO-11), and
# `daemon.serve` renders the whole DudeFSError tree as carrier silence. Without that, "crash on
# anything unexpected" would hand any unauthenticated peer a remote kill switch. Typed-parsing
# first, crash-only second — in that order.

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
    hooks at the same handler. Left OUT of library/test paths on purpose — importing dudefs
    must never install a process-killing hook."""
    threading.excepthook = lambda a: _die(
        f"thread {a.thread.name if a.thread else '?'}", a.exc_value, a.exc_traceback
    )
    sys.excepthook = lambda et, ev, tb: _die("main thread", ev, tb)


def configure_logging(level: int = logging.INFO) -> None:
    """Standard per-module logging, wired at the entry point only.

    Modules do `log = logging.getLogger(__name__)` and never configure anything — so a library
    embedder keeps full control of handlers, and `dudefs.*` slots into an existing logging
    setup the ordinary way. Only the CLI, which owns the process, calls this."""
    logging.basicConfig(
        level=level,
        format="%(asctime)s %(levelname)-8s %(name)s: %(message)s",
        stream=sys.stderr,
    )
