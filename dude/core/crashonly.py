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
    os._exit(70)


def install() -> None:
    threading.excepthook = lambda a: _die(
        f"thread {a.thread.name if a.thread else '?'}", a.exc_value, a.exc_traceback
    )
    sys.excepthook = lambda _et, ev, tb: _die("main thread", ev, tb)


def configure_logging(level: int = logging.INFO) -> None:
    logging.basicConfig(
        level=level,
        format="%(asctime)s %(levelname)-8s %(name)s: %(message)s",
        stream=sys.stderr,
    )
