from __future__ import annotations

from collections.abc import Mapping

from .core.errors import DudeError


class QuorumError(DudeError): ...


def size(n: int) -> int:
    if n < 1:
        raise QuorumError(f"a quorum needs at least one node, got n={n}")
    return -(-2 * n // 3)


def intersection(n: int) -> int:
    return 2 * size(n) - n


def tolerates(n: int) -> int:
    return max(0, intersection(n) - 1)


def corroboration(n: int) -> int:
    return tolerates(n) + 1


def spare(n: int) -> int:
    return n - size(n)


def max_domain(n: int) -> int:
    return min(spare(n), tolerates(n))


def satisfied(n: int, agreeing: int) -> bool:
    return agreeing >= size(n)


def would_brick(n: int) -> bool:
    return n < 3


def domain_advisory(counts: Mapping[bytes, int], n: int) -> dict[bytes, int]:
    limit = max_domain(n)
    return {d: c for d, c in counts.items() if c > limit}
