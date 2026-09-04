from __future__ import annotations

import time


class Seconds(float):
    @property
    def as_millis(self) -> Millis:
        return Millis(int(self * 1000))

    @staticmethod
    def now() -> Seconds:
        return Seconds(time.monotonic())


class Millis(int):
    @property
    def as_seconds(self) -> Seconds:
        return Seconds(self / 1000)

    @staticmethod
    def now() -> Millis:
        return Millis(time.time_ns() // 1_000_000)

    def __add__(self, other: int) -> Millis:
        return Millis(int.__add__(self, other))

    def __radd__(self, other: int) -> Millis:
        return Millis(int.__radd__(self, other))

    def __sub__(self, other: int) -> Millis:
        return Millis(int.__sub__(self, other))

    def __rsub__(self, other: int) -> Millis:
        return Millis(int.__rsub__(self, other))

    def __mul__(self, other: int) -> Millis:
        return Millis(int.__mul__(self, other))

    def __rmul__(self, other: int) -> Millis:
        return Millis(int.__rmul__(self, other))

    def __floordiv__(self, other: int) -> Millis:
        return Millis(int.__floordiv__(self, other))

    def __neg__(self) -> Millis:
        return Millis(int.__neg__(self))

    ZERO: Millis


Millis.ZERO = Millis(0)


type Bucket = int
"""``floor(t / delta)``. A UNIT, not a consensus concept, and it lives here so ``tunables`` can name
one without importing the mempool that used to own it -- the import that made every tunable group
live in the module that reads it."""
