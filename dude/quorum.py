# dude.quorum -- the gate. See SPECv2 (#quorum-gate).
#
# "It decides what is and is not consensus, and nothing else in this document may depend on how
# it decides." So this module is tiny and has one dependency: `DudeError`. Given a node count,
# it answers every arithmetic question about quorums that any other module needs -- no caller
# does quorum math inline. That is the whole discipline: two callers computing quorum
# arithmetic independently is how their answers come to disagree.
#
# THE RULE IS TWO-THIRDS. NOT CONFIGURABLE PER NODE. Two nodes running different quorum rules
# is a per-node consensus break; deployment flexibility lives in the roster size (n), not in
# the rule. Previously three rules coexisted with a `DEFAULT` -- retired; there is one shape
# now, and any change to it is a whole-cluster decision.
#
# THE ARITHMETIC (#quorum-gate). Choice of rule and tolerable fault count are ONE decision:
#
#   two quorums of size q drawn from n intersect in at least   2q - n   members
#   for that intersection to be guaranteed to contain an HONEST node:   2q - n > f
#
# For two-thirds: q(n) = ceil(2n/3). Then:
#
#   spare(n) = n - q(n) = floor(n/3)                   -- how many can be offline
#   intersection(n) = 2q - n                            -- guaranteed overlap
#   tolerates(n) = max(0, 2q - n - 1)                   -- byzantine faults tolerated
#   corroboration(n) = tolerates(n) + 1                 -- how many fresh witnesses need agree
#   max_domain(n) = min(spare, tolerates)               -- advisory composition ceiling

from __future__ import annotations

from collections.abc import Mapping

from .core.errors import DudeError


class QuorumError(DudeError):
    """A node count that cannot yield a valid quorum."""


def size(n: int) -> int:
    """How many of `n` nodes must agree: ceil(2n/3). Refuses `n < 1` -- "a quorum of zero
    nodes" is satisfied by nobody agreeing, which is the kind of vacuous truth that silently
    finalises everything."""
    if n < 1:
        raise QuorumError(f"a quorum needs at least one node, got n={n}")
    return -(-2 * n // 3)  # ceil(2n/3) without floats; SPEC portability


def intersection(n: int) -> int:
    """Guaranteed overlap between any two quorums: `2q - n`. Non-positive means two disjoint
    quorums are possible, i.e. two contradictory decisions with no member in common."""
    return 2 * size(n) - n


def tolerates(n: int) -> int:
    """Largest `f` for which every two quorums share an honest member: `max(0, 2q - n - 1)`.
    This is the byzantine fault count the deployment's diversity must make credible
    (#nodes-are-untrusted)."""
    return max(0, intersection(n) - 1)


def corroboration(n: int) -> int:
    """`f + 1` -- how many INDEPENDENT FRESH statements a floor needs before at least one is
    honest. A DIFFERENT QUESTION FROM `size`, and the reason this lives here rather than at
    the call site (#quorum-gate: one module decides, and nothing else depends on how it
    decides). A quorum is how many must AGREE for consensus; this is how many must ANSWER
    before at least one of them is honest. At n=3 tolerates zero faults, so a single honest
    fresh answer is already `f+1` -- while a quorum is two."""
    return tolerates(n) + 1


def spare(n: int) -> int:
    """How many nodes may be unavailable and still leave a quorum reachable: `n - q`.

    The OTHER half of the trade, and not implied by `tolerates`: the two move in opposite
    directions. At n=11 two-thirds gives spare=3 and tolerates=4, so a rule is sound only when
    BOTH numbers are acceptable."""
    return n - size(n)


def max_domain(n: int) -> int:
    """Advisory composition ceiling: the largest number of nodes that may share a FAILURE
    DOMAIN (provider, jurisdiction, ASN, billing account, hypervisor) without either safety
    or availability degrading.

    `min(spare, tolerates)`. Availability usually binds: at n=11 spare=3 and tolerates=4, so
    max=3. Seizure, bankruptcy and a provider outage all remove a node's AVAILABILITY, so what
    matters is how many may vanish while a quorum can still form -- not just how many may lie
    while safety holds.

    ADVISORY, NOT ENFORCED. Domain composition is guidance for the operator; no code path
    refuses a change on domain-count violation. Rack-awareness that severely interferes with
    routine operation is worse than none, and legitimate improvement moves (diluting a
    concentrated cluster) frequently pass through composition-violating intermediate states.
    Callers query `domain_advisory` and act on the result themselves."""
    return min(spare(n), tolerates(n))


def satisfied(n: int, agreeing: int) -> bool:
    """Whether `agreeing` of `n` is consensus. The whole interface the layers above use."""
    return agreeing >= size(n)


def would_brick(n: int) -> bool:
    """True iff a cluster of this size CANNOT survive a single node offline -- equivalently,
    `n < 3` (below that, `spare` is zero and every node is required for quorum). THE hard
    bricking condition, and the one that `change_roster` refuses on. At n<3 any reboot
    (kernel update, disk swap, cable kicked) removes progress until the offline node
    returns -- operationally a brick, not just a fragile state. `n=0` is also bricked (no
    cluster at all).

    Anchor rescue via `intervene()` remains the escape hatch for a stuck cluster."""
    return n < 3


def domain_advisory(counts: Mapping[bytes, int], n: int) -> dict[bytes, int]:
    """Domains where the node count exceeds `max_domain(n)`. ADVISORY -- for operator
    inspection. If any of these domains fails (rack outage, provider ban, network partition
    at that boundary), the cluster loses quorum until the failure heals; safety under
    byzantine collusion within the over-count domain is also weakened.

    NOT AN ENFORCEMENT PATH. `change_roster` does not refuse on this; the operator sees the
    dict and decides. In production this is THE failure mode that bites (concentration in
    one provider or region), and the reason it stays advisory is that enforcing it as a hard
    refusal blocks legitimate incremental improvements to a concentrated cluster."""
    limit = max_domain(n)
    return {d: c for d, c in counts.items() if c > limit}
