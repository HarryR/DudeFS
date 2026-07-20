# DudeFS — global default tunables, DERIVED from physical primitives.
#
# The operational timeouts are not magic numbers: a hedge/retransmit/poll period
# is "N round-trips", and a round-trip is 2 × the node-to-node one-way latency.
# So each regime states two physical primitives — its one-way network latency
# and its clock-skew budget — and every latency-shaped default is derived from
# them by a dimensionless multiplier. Retune the network assumption in one place
# and the whole timing envelope reflows consistently.
#
# Two regimes, entirely different clocks; they share the multipliers, not the
# primitives:
#   * PRODUCTION — a real network / daemon (tens-to-hundreds-of-ms hops).
#     Defaults the real components (acceptor, quorum client) and the M7/M8 driver.
#   * SIMULATION — the discrete-event harness compresses time to a few ticks per
#     hop. Consumed ONLY by sim-only machinery (fault injector, ClientRunner /
#     drive, Sim). Nothing here runs for real.
#
# NOT here: protocol / wire constants (sentinels, the BLIND ballot, suite ids,
# DIGEST_SIZE, SUPPORTED_PVER, field keys, arities). Changing one breaks the wire
# format or a safety proof — those are not "tunable".
#
# All durations are milliseconds.

# ============================================================================ #
# Dimensionless derivation multipliers (shared by both regimes)                #
# ============================================================================ #
# A timeout is expressed in round-trips (RTT = 2 × one-way latency).
_HEDGE_RTTS = 1  # trickle the rest of the fan-out after ~1 RTT of silence (QuePaxa)
_RETRANSMIT_RTTS = 10  # resend an un-acked verb after ~10 RTT — a reply is lost, not merely late
_FINALITY_POLL_RTTS = 1  # re-poll watermarks about once per RTT (no point polling faster)
_ROUND_TIMEOUT_RTTS = 4  # a ballot round escalates if it neither decides nor is nacked-out in this


def _rtt(one_way_ms: int) -> int:
    return int(2.222 * one_way_ms)


# ============================================================================ #
# PRODUCTION regime                                                            #
# ============================================================================ #
# Physical primitives — the two things a deployment actually measures.
AVERAGE_NODE2NODE_ONE_WAY_LATENCY_MS = 25  # avg node<->node (and client<->node) one-way
MAX_CLOCK_SKEW_MS = 60_000  # δ: wall-clock disagreement budget (NTP-grade), NOT latency

_PROD_RTT = _rtt(AVERAGE_NODE2NODE_ONE_WAY_LATENCY_MS)  # 50

# Consensus — acceptor skew window δ (DESIGN §9). From clock skew, not latency:
# floor = max(hw, now) − δ, and commitment is by quorum vote never the clock (§11).
DELTA_MS = MAX_CLOCK_SKEW_MS  # 60_000

# Quorum client — hedging, recovery, finality (PROTOCOL §1.3-§1.4, §4).
HEDGE_MS = _HEDGE_RTTS * _PROD_RTT  # 50
FINALITY_POLL_MS = _FINALITY_POLL_RTTS * _PROD_RTT  # 50
ROUND_TIMEOUT_MS = _ROUND_TIMEOUT_RTTS * _PROD_RTT  # re-PREPARE if a round stalls (loss-proof)
MAX_ROUNDS = 8  # recovery ballot rounds before a Commit gives up — a COUNT, regime-independent
MAX_POLLS = 1_000  # finality poll attempts before a Finalize gives up — a COUNT

# Client driver — at-least-once reliability (PROTOCOL §0: idempotent verbs).
# RESERVED for the M7/M8 real driver (the in-sim driver uses SIM_* below); it
# will likely add randomized backoff (DESIGN §8) atop this base period.
RETRANSMIT_MS = _RETRANSMIT_RTTS * _PROD_RTT  # 500
# A coarse give-up backstop, not a latency — patience, not a round-trip count.
DRIVE_DEADLINE_MS = 100_000

# Fold — verification memo cache (performance, regime-independent).
SIG_CACHE_MAX = 100_000

# ============================================================================ #
# SIMULATION regime — the compressed discrete-event clock                      #
# ============================================================================ #
# Physical primitives. The fault injector's per-hop delay window brackets the
# one-way latency (± jitter), so the "network" and the derived timeouts agree.
SIM_ONE_WAY_LATENCY_MS = 2  # a hop in the compressed clock
_SIM_JITTER_MS = 1
SIM_MAX_CLOCK_SKEW_MS = 10_000  # δ ≫ hop so skew rarely gates in-sim

_SIM_RTT = _rtt(SIM_ONE_WAY_LATENCY_MS)  # 4

SIM_DELTA_MS = SIM_MAX_CLOCK_SKEW_MS  # 10_000 — acceptor δ the sim builds nodes with
SIM_DELAY_LO_MS = max(1, SIM_ONE_WAY_LATENCY_MS - _SIM_JITTER_MS)  # 1 (≥1 so time advances)
SIM_DELAY_HI_MS = SIM_ONE_WAY_LATENCY_MS + _SIM_JITTER_MS  # 3 (reorder emerges from lo..hi)
SIM_RETRANSMIT_MS = _RETRANSMIT_RTTS * _SIM_RTT  # 40 — hop-scale, so a lossy link gets many retries
SIM_DRIVE_DEADLINE_MS = 100_000  # per-machine give-up (coarse backstop, not latency)
SIM_RUN_DEADLINE_MS = 100_000  # whole-run wall-clock budget before Sim.run stops stepping

# Reserved for when the sim exercises HEDGING (deferred until the Lean/TLA+ track
# lands): wire this into Sim.cfg so the quorum client runs at sim cadence and the
# hedge actually fires (at production 50 ms it never does — hops are 1-3 ms).
# SIM_HEDGE_MS = _HEDGE_RTTS * _SIM_RTT            # 4
# SIM_FINALITY_POLL_MS = _FINALITY_POLL_RTTS * _SIM_RTT  # 4
