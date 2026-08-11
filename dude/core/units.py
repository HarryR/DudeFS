from __future__ import annotations

import time

type Millis = int

type Bucket = int
"""`floor(t / delta)`. A UNIT, not a consensus concept, and it lives here so `tunables` can name
one without importing the mempool that used to own it -- the import that made every tunable group
live in the module that reads it."""


def now_ms() -> Millis:
    return time.time_ns() // 1_000_000
