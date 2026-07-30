# dude.quorum — the gate. See SPEC.md (#quorum-gate).
#
# "It decides what is and is not consensus, and nothing else in this document may depend on how it
# decides." So this module is deliberately tiny and has no dependencies: given a node count, how
# many must agree. Replaceable at will — including by a deterministic chaos monkey.
#
# THE ARITHMETIC THAT ACTUALLY MATTERS, because the choice of rule and the tolerable fault count are
# ONE decision, not two (#quorum-gate):
#
#   two quorums of size q drawn from n intersect in at least   2q - n   members
#   for that intersection to be guaranteed to contain an HONEST node:   2q - n > f
#
# So a rule is not "how many feels safe" — it is a statement about how many faults you tolerate:
#
#   rule            q(n)        intersection   tolerates f <
#   majority        n/2 + 1     2              1            (crash faults only)
#   MAJORITY_PLUS   n/2 + 2     4              3
#   TWO_THIRDS      ceil(2n/3)  ~n/3           n/3
#
# `f` here is the number that may be faulty AND COLLUDING. #nodes-are-untrusted rests the fault
# assumption on
# the node set being geographically, operationally and legislatively diverse — that diversity is the
# independence argument which makes any particular `f` credible. The rule cannot supply it.

from __future__ import annotations

from collections.abc import Callable
from dataclasses import dataclass

from .core.errors import DudeError


class QuorumError(DudeError):
    """A node count or threshold that cannot be satisfied."""


@dataclass(frozen=True, slots=True)
class Rule:
    """A quorum rule: how many of `n` must agree, and what that buys.

    `size` is the whole interface — everything above asks only "what N satisfies a quorum". The rest
    is here so the trade is legible at the point of choosing, rather than discovered later."""

    name: str
    size: Callable[[int], int]
    note: str

    def __call__(self, n: int) -> int:
        return self.size(n)

    def intersection(self, n: int) -> int:
        """Guaranteed overlap between any two quorums: `2q - n`. Non-positive means two disjoint
        quorums are possible, i.e. two contradictory decisions with no member in common."""
        return 2 * self.size(n) - n

    def tolerates(self, n: int) -> int:
        """The largest `f` for which every two quorums share an honest member: `2q - n - 1`, floored
        at zero. This is the number the deployment's diversity has to make credible
        (#nodes-are-untrusted)."""
        return max(0, self.intersection(n) - 1)

    def spare(self, n: int) -> int:
        """How many nodes may be unavailable and still leave a quorum reachable: `n - q`.

        The OTHER half of the trade, and not implied by `tolerates`: the two move in opposite
        directions. `majority+1` at n=4 needs 4 of 4 — perfect safety overlap and **zero** crash
        tolerance, so one node rebooting stops the cluster. A rule is sound for a given `n` only
        when both numbers are acceptable, which is why both are reported rather than leaving
        `size()` to be read as the whole answer."""
        return n - self.size(n)

    def max_domain(self, n: int) -> int:
        """The largest number of nodes that may share a FAILURE DOMAIN — provider,
        jurisdiction, ASN,
        billing account, hypervisor.

        `min(spare, tolerates)`, and availability is the bound that usually binds: at n=11
        two-thirds
        gives spare=3 and tolerates=4, so **3**. Seizure, bankruptcy and a provider outage
        all remove
        a node's AVAILABILITY, so what matters is how many may vanish while a quorum can
        still form —
        not how many may lie while safety holds.

        Sufficient on its own: since this is < `size(n)`, no quorum can be drawn from a
        single domain,
        so no separate "quorum diversity" rule is needed."""
        return min(self.spare(n), self.tolerates(n))

    def satisfied_by(self, n: int, agreeing: int) -> bool:
        """Does `agreeing` constitute consensus among `n`? The one question the layers above ask."""
        return agreeing >= self.size(n)


MAJORITY = Rule(
    "majority",
    lambda n: n // 2 + 1,
    "smallest rule with any overlap; intersection 2, so it tolerates crash faults and no collusion",
)

MAJORITY_PLUS = Rule(
    "majority+1",
    lambda n: n // 2 + 2,
    "#quorum-gate's first candidate; intersection 4, so 3 colluding faults keep an honest overlap",
)

TWO_THIRDS = Rule(
    "two-thirds",
    lambda n: -(-2 * n // 3),  # ceil(2n/3) without floats — SPEC portability: no floating point
    "#quorum-gate's second candidate; the classical BFT shape, tolerating f < n/3",
)

RULES = {r.name: r for r in (MAJORITY, MAJORITY_PLUS, TWO_THIRDS)}

# The default is the more conservative of #quorum-gate's two candidates. Named rather than inlined
# so a
# deployment changes ONE symbol, and so a reader sees that a default was chosen, not assumed.
DEFAULT = TWO_THIRDS


def size(n: int, rule: Rule = DEFAULT) -> int:
    """How many of `n` nodes must agree.

    Refuses `n < 1` rather than returning a number: "a quorum of zero nodes" is satisfied by nobody
    agreeing, which is the kind of vacuous truth that silently finalises everything."""
    if n < 1:
        raise QuorumError(f"a quorum needs at least one node, got n={n}")
    q = rule(n)
    if q > n:
        raise QuorumError(f"{rule.name} needs {q} of {n}, which is unsatisfiable")
    return q


def satisfied(n: int, agreeing: int, rule: Rule = DEFAULT) -> bool:
    """Whether `agreeing` of `n` is consensus. The whole interface the layers above use."""
    return agreeing >= size(n, rule)
