# dude.core.timing — the declared quantities, and the floor every timing dial derives from.
#
# THE RULING THIS FILE SERVES: no dial is an arbitrary figure. Every timing value in the system is
# expressed against a quantity a deployment can MEASURE — the network's tolerable round trip, the
# clocks' tolerable disagreement — times a count that comes from the protocol, being the hops needed
# to reach a quorum and the waves needed to settle.
#
# WHAT IS DECLARED AND WHAT IS DERIVED, because the distinction is the whole point:
#
#   declared    four numbers, below. Two are measurements of a deployment, one is a security policy
#               with its cost stated, one pair is protocol shape. Changing one of these is a real
#               decision and moves everything downstream.
#   derived     a FLOOR for each dial, computed here. A dial may sit above its floor — that is a
#               deliberate margin — but never below, and `tests/test_timing.py` fails if one does.
#
# Floors rather than exact values, deliberately: several dials are tolerances where more is safer
# and the cost of generosity is only memory or latency. Pinning those to an exact derivation is
# false precision. Where a value must equal its derivation it is a property, not a field, so it
# cannot be set inconsistently — `MempoolTunables.evict_after` is the example.
#
# WHY THIS LIVES IN `core` rather than in `tunables.py`: each module declares the shape of its own
# dials and needs these primitives to express its defaults, and a module cannot import the one that
# imports it. `tunables.py` remains the single composed surface that everything is handed.

from __future__ import annotations

type Millis = int


# --------------------------------------------------------------------------------------------- #
# DECLARED. Everything else in this file is arithmetic over these.                               #
# --------------------------------------------------------------------------------------------- #

RTT_MAX: Millis = 300
"""The largest round trip between two cluster members that this deployment tolerates.

Not an average and not a measurement of the current network: a bound. Cross-region links run
150-300 ms, so a member consistently slower than this is out of tolerance and its links will be
retired by the breaker rather than accommodated. A mixnet deployment declares a different number
and every floor below moves with it."""

CLOCK_SKEW: Millis = 250
"""The largest disagreement tolerated between two honest NODES' clocks.

Nodes are operated and NTP-disciplined, which typically holds them inside 50 ms; this is generous
by 5x. It bounds everything that compares one node's timestamp against another's, and a node
outside it degrades its own contribution — see #freshness-is-gathered, and note that a clock fault
is never convictable."""

CLIENT_CLOCK_TOLERANCE: Millis = 25_000
"""How far a CLIENT's clock may be from a node's before its transactions are refused at the door.

A POLICY, not a measurement, and the one number here with a security cost rather than a latency
cost: a captured signed transaction stays replayable for roughly this long, because the admission
window is what makes an old transaction un-admittable (#one-write-vocabulary's ops carry no nonce).
Shrinking it tightens replay and refuses clients whose clocks are further out; a client is not
assumed to run NTP at all. It is deliberately far larger than `CLOCK_SKEW`, which is about nodes."""

HOPS_TO_QUORUM = 2
"""Delivery hops from one member to a quorum: direct, plus one relay for a member it cannot reach.

Two rather than a function of `n` because the gossip substrate is a connectivity substrate — a
message reaches a quorum by direct send, relay, or epidemic spread, and correctness is
path-independent. Raise it for a deployment whose topology is deeper than one relay."""

WAVES_TO_SETTLE = 3
"""Message waves between a closed bucket and a settled batch: propose, endorse, count.

A protocol constant, not a tunable: it is the shape of the round, so it changes only if the round
changes."""


# --------------------------------------------------------------------------------------------- #
# DERIVED FLOORS. A dial may exceed its floor; none may sit below it.                            #
# --------------------------------------------------------------------------------------------- #

DISSEMINATION: Millis = HOPS_TO_QUORUM * RTT_MAX + CLOCK_SKEW
"""How long a message needs to reach a quorum, worst case. 850 ms at the declared values."""

BUCKET_FLOOR: Millis = DISSEMINATION
"""Floor for the bucket width. A bucket narrower than dissemination closes before the transactions
in it could have reached the nodes that must propose them, so every bucket would carry work forward
and the pipeline would never be in step. Boundaries are computed from the author's timestamp, so
skew does not enter — nodes agree on which bucket a transaction belongs to whatever their clocks
read."""

CONVERSATION_FLOOR: Millis = CLOCK_SKEW + RTT_MAX
"""Floor for the envelope conversation window. Below skew plus one trip, two honest nodes cannot
hold a conversation at all, which self-partitions the cluster."""

ADMISSION_FLOOR: Millis = CLIENT_CLOCK_TOLERANCE + 2 * RTT_MAX
"""Floor for the admission window: the client's tolerated clock error, plus its transaction's trip
to a node and the reply's trip back. Below this an honest client with a merely imprecise clock is
refused for being slow rather than for being wrong."""


def endorse_margin(bucket_width: Millis) -> Millis:
    """Floor for the margin between `w_admit` and `w_valid`.

    A transaction admitted at the very edge of the admission window still has to survive the whole
    round before it settles, so the endorsement bound needs one round's worth of room plus skew.
    A function of the bucket width rather than a constant, because that is what a round costs."""
    return WAVES_TO_SETTLE * bucket_width + CLOCK_SKEW


def retry_total(base: Millis, cap: Millis, attempts: int) -> Millis:
    """What an exponential retry schedule really spends: base doubling per attempt, capped, summed.

    Exists so the deadline and the schedule can be CHECKED against each other rather than chosen
    independently. They were chosen independently: eight attempts from a 100 ms base spend 25.5 s
    against a 10 s deadline, so the last three attempts were unreachable, and the backoff cap was
    30 s against the same deadline — a cap that could never be applied."""
    return sum(min(base * 2**i, cap) for i in range(attempts))
