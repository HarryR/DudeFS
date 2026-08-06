# dude.core.units -- primitive scalar aliases shared across the codebase.
#
# WHY THIS EXISTS. A Python `type Millis = int` alias enforces nothing at runtime and nothing at
# type-check time (int and Millis are interchangeable). But repeating the same alias in eleven
# files was worse: two nodes converging on "Millis" is one shared vocabulary; two nodes each
# redefining it is a coincidence waiting to drift. This module is the one home.
#
# WHY ONLY MILLIS. `NodeId` was also here-shaped, and we deleted it: `crypto.PublicKey` was the
# real type, `NodeId` was a synonym that only two files used while fifty use-sites elsewhere said
# `crypto.PublicKey` -- two vocabularies for one type is exactly the discipline gap the audit is
# for. Alias only when the underlying primitive is the whole story (a wall-time integer) and no
# domain layer above it is doing the work.

from __future__ import annotations

import time

type Millis = int
"""Wall-time in milliseconds. Always a parameter through most of the codebase -- every
function that takes `now: Millis` is deterministic in its arguments, which is what lets
tests drive time by handing in `T0 + DELTA * N`. The ONE legitimate wall-clock reader is
the runtime driver loop (`Node._run` / `LightClient._run`), via `now_ms()` below."""


def now_ms() -> Millis:
    """Read the wall clock as `Millis`. Called only by the runtime driver loops -- the
    one place a real clock enters the system. Production Node/LightClient own a thread
    that reads this every tick; test callers pass `T0 + DELTA * N` explicitly and never
    reach for it. Uses `time.time_ns()` (monotonic-enough for tick cadence; not a
    replacement for `time.monotonic()` where duration matters)."""
    return time.time_ns() // 1_000_000
