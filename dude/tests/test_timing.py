# The one thing about the tunables surface a reader cannot see by looking at it: the declared
# set is small on purpose, and `block_time` is not in it. If either changes silently, this file
# catches it.

from __future__ import annotations

import unittest
from dataclasses import replace

from ..core.errors import DudeError, InvariantError
from ..tunables import DEFAULT, Tunables


class TestBlockTimeDerivation(unittest.TestCase):
    def test_a_specific_input_yields_a_specific_block_time(self):
        """Pins the arithmetic against a sign flip, a missing summand, or an off-by-one in the
        wave count. Monotonicity tests would miss any of those."""
        t = Tunables(
            rtt_max=100,
            clock_skew=200,
            retry_budget=2,
            held_convergence_max=3,
            safety_margin=2,
        )
        # single_wave_budget       = retry_budget * rtt_max          = 2 * 100 = 200
        # held_wave_budget         = held_convergence_max * single   = 3 * 200 = 600
        # block_time_floor         = held + 2 * single + clock_skew  = 600 + 400 + 200 = 1200
        # block_time               = safety_margin * floor           = 2 * 1200 = 2400
        self.assertEqual(t.block_time, 2400)

    def test_a_count_of_zero_is_refused(self):
        for field in ("retry_budget", "held_convergence_max", "safety_margin"):
            with self.assertRaises(InvariantError):
                replace(DEFAULT, **{field: 0})

    def test_the_refusal_is_ours_and_therefore_fatal(self):
        """Misconfiguration must not run. Never catchable as a peer's fault."""
        self.assertFalse(issubclass(InvariantError, DudeError))


class TestTheDeclaredSetIsSmall(unittest.TestCase):
    def test_declared_quantities_and_nothing_else(self):
        """A RATCHET. Fails when a field is added, which is the point: it forces the question
        of whether the new dial is a measurement, a decision, a count, or arithmetic that
        should have been a property."""
        self.assertEqual(
            sorted(Tunables.__dataclass_fields__),
            [
                "breaker_threshold",
                "budget_max_tokens",
                "budget_token_ratio",
                "client_clock_tolerance",
                "clock_skew",
                "desired_links_per_peer",
                "granularity",
                "held_convergence_max",
                "max_attempts",
                "pull_batch",
                "retry_budget",
                "rtt_max",
                "safety_margin",
                "ticks_per_cadence",
                "windows_to_settle",
            ],
        )
