# Every dial sits at or above the floor it derives from, and the ones that must AGREE do.
#
# WHY THIS FILE EXISTS. The floors are written in `core/timing.py` and cited in each dial's
# docstring, and a docstring obliges nothing — this session has already found six checks that were
# built, documented and never consulted. So the derivation is enforced here, where a value drifting
# below its floor fails the gate instead of reading plausibly.
#
# WHAT IT CAUGHT when it was first written, all four from arithmetic rather than from a failure:
#
#   `w_valid_margin`   3_000 against a floor of 3_250 — a transaction admitted at the edge of the
#                      window could be refused by endorsers inside the round it was admitted for
#   `evict_after`      300_000 against an endorsable lifetime of 33_250: 9x dead weight, and exactly
#                      the surplus in which a stale compare-and-swap could be re-proposed
#   `backoff_cap`      30_000 against a 10_000 deadline — a ceiling that could never be applied
#   `max_attempts`     8, spending 25.5 s against the same 10 s deadline, so three attempts were
#                      unreachable. The schedule and the deadline had been chosen independently.
#
# A floor is a floor, not an equality: several of these are tolerances where generosity costs only
# memory or latency, so sitting above the floor is a margin rather than a defect. Where a value MUST
# equal its derivation it is a property and cannot be set at all (`evict_after`).

from __future__ import annotations

import unittest

from ..core import timing
from ..tunables import DEFAULT


class TestDeclaredQuantities(unittest.TestCase):
    def test_the_declared_set_is_small(self):
        """Four declared numbers and two protocol counts. If this grows, the derivation is being
        bypassed by declaring the answer instead of computing it."""
        declared = [n for n in vars(timing) if n.isupper() and not n.endswith("_FLOOR")]
        self.assertEqual(
            sorted(declared),
            [
                "CLIENT_CLOCK_TOLERANCE",
                "CLOCK_SKEW",
                "DISSEMINATION",
                "HOPS_TO_QUORUM",
                "RTT_MAX",
                "WAVES_TO_SETTLE",
            ],
        )

    def test_a_client_is_tolerated_more_loosely_than_a_node(self):
        """Nodes are NTP-disciplined and clients are not assumed to be, so the two tolerances are
        different quantities — collapsing them would either refuse honest clients or widen the
        replay window for everyone."""
        self.assertGreater(timing.CLIENT_CLOCK_TOLERANCE, timing.CLOCK_SKEW)


class TestEveryDialIsAboveItsFloor(unittest.TestCase):
    def test_the_bucket_is_wider_than_dissemination(self):
        self.assertGreaterEqual(DEFAULT.mempool.delta, timing.BUCKET_FLOOR)

    def test_the_conversation_window_admits_a_round_trip_plus_skew(self):
        self.assertGreaterEqual(DEFAULT.net.window, timing.CONVERSATION_FLOOR)

    def test_the_door_admits_a_client_whose_clock_is_merely_imprecise(self):
        self.assertGreaterEqual(DEFAULT.mempool.w_admit, timing.ADMISSION_FLOOR)

    def test_endorsement_has_a_whole_round_of_margin(self):
        """The one that was below its floor: a margin shorter than a round means a transaction
        admitted at the edge of `w_admit` can be refused by endorsers before its own round ends."""
        self.assertGreaterEqual(
            DEFAULT.mempool.w_valid_margin, timing.endorse_margin(DEFAULT.mempool.delta)
        )


class TestDialsThatMustAgree(unittest.TestCase):
    def test_nothing_is_held_past_the_point_it_could_settle(self):
        """`evict_after` EQUALS `w_valid`, and is a property so it cannot be set otherwise.

        A transaction is unendorsable once `|now - ts| > w_valid`, so retention beyond that keeps
        something that can never land — and keeps it re-proposable, which is the ABA window."""
        self.assertEqual(DEFAULT.mempool.evict_after, DEFAULT.mempool.w_valid)

    def test_the_retry_schedule_fits_inside_the_deadline(self):
        """Otherwise the later attempts are unreachable and `max_attempts` is decoration. It spent
        25.5 s against a 10 s deadline."""
        plan, net = DEFAULT.plan, DEFAULT.net
        spent = timing.retry_total(plan.backoff_base, plan.backoff_cap, plan.max_attempts)
        self.assertLessEqual(
            spent, net.ttl, f"the schedule spends {spent}ms of a {net.ttl}ms budget"
        )

    def test_the_backoff_cap_is_reachable(self):
        """A ceiling above the deadline is a dial with no effect — it was 30 s against 10 s."""
        self.assertLessEqual(DEFAULT.plan.backoff_cap, DEFAULT.net.ttl)

    def test_freshness_outlives_the_probe_that_feeds_it(self):
        """Gathered statements are as old as the last probe round, so a window at or below the probe
        interval makes every bundle stale by construction and the floor unanswerable."""
        att = DEFAULT.attest
        self.assertGreater(att.fresh_within, att.probe_every)
        self.assertGreaterEqual(att.fresh_within, 2 * att.probe_every + timing.RTT_MAX)

    def test_one_dial_is_not_two(self):
        """`stagger_cap` and `max_parallel` were declared in BOTH the link and plan groups, and only
        the plan's copies were ever read. Two dials with one name can disagree, and they did — by
        50 ms, the moment one was derived from `RTT_MAX` — with the loser being whichever the caller
        did not read. The link's copies are gone; this pins that they stay gone."""
        for dead in ("stagger_cap", "max_parallel"):
            self.assertFalse(
                hasattr(DEFAULT.link, dead), f"link.{dead} is back, and plan.{dead} still decides"
            )


class TestNoDialHidesOutsideTheOneSurface(unittest.TestCase):
    def test_the_transfer_bound_is_a_tunable(self):
        """`_PULL_MAX` was a module constant in `node.py`. This file's ruling is that a dial deep in
        code lingers, so the bound lives on the surface a deployment overrides."""
        self.assertEqual(DEFAULT.net.pull_max, 256)
