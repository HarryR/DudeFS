from __future__ import annotations

import time

type Millis = int


def now_ms() -> Millis:
    return time.time_ns() // 1_000_000
