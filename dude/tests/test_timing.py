# Every dial clears the floor it derives from, and a configuration that does not CANNOT be built.
#
# WHERE THE ENFORCEMENT LIVES. `Tunables.__post_init__` refuses an incoherent set, so this file does
# not re-check the defaults so much as prove the refusal works and pin what it refuses. A test can
# only ever prove that one tuple of numbers is coherent; the constructor proves it for whatever a
# deployment overrides, which is the difference between a rule and a claim about a default.
#
# WHAT DERIVING THE DIALS ACTUALLY FOUND, stated honestly because the first version of this file
# overstated it:
#
#   w_valid_margin   3_000 against a floor of 3_250 — BELOW its own floor, so a transaction admitted
#                    at the edge of the window could be refused by endorsers inside the round it was
#                    admitted for. A real defect, fixed.
#   evict_after      300_000 against an endorsable lifetime of 33_250. Nine times dead weight, and
#                    that surplus is exactly the window in which a stale compare-and-swap can be
#                    re-proposed. A real defect, and now a property that cannot be set.
#   stagger_cap,     declared in BOTH LinkTunables and PlanTunables with only the plan's copies ever
#   max_parallel     read. They disagreed by 50 ms the moment one was derived. Real, and deleted.
#   backoff_cap      30_000 against a 10_000 deadline. NOT a defect as first claimed: `Plan.next`
#                    clamps every wait to the deadline, so the cap was incoherent rather than
#                    ineffective. Refused by the constructor now.
#   max_attempts     claimed to be unreachable at 8. WRONG: `backoff` is decorrelated jitter, so its
#                    minimum spend is `attempts · base` = 800 ms, and the deadline is checked
#                    explicitly. The claim came from re-implementing the schedule in a checker with
#                    the wrong growth base — a second model of one fact, which is the defect the
#                    check was hunting. Restored to 8, and no checker models it.

from __future__ import annotations

import unittest
from dataclasses import replace

from ..consensus.mempool import Tunables as MempoolTunables
from ..core.errors import DudeError, InvariantError
from ..net.plan import PlanTunables
from ..tunables import DEFAULT, NetTunables, TimingTunables, Tunables


class TestTheDeclaredSetIsSmall(unittest.TestCase):
    def test_five_declared_quantities_and_nothing_else(self):
        """If this grows, a derivation is being bypassed by declaring the answer instead."""
        self.assertEqual(
            sorted(TimingTunables.__dataclass_fields__),
            [
                "client_clock_tolerance",
                "clock_skew",
                "hops_to_quorum",
                "rtt_max",
                "waves_to_settle",
            ],
        )

    def test_a_client_is_tolerated_more_loosely_than_a_node(self):
        """Nodes are NTP-disciplined and clients are not assumed to be. Collapsing the two would
        either refuse honest clients or widen the replay window for everyone."""
        t = DEFAULT.timing
        self.assertGreater(t.client_clock_tolerance, t.clock_skew)


class TestTheDefaultsAreCoherent(unittest.TestCase):
    """`DEFAULT` is constructed at import, so `__post_init__` has already run over it — these state
    the relationships explicitly so a reader sees what is being asserted."""

    def test_the_bucket_is_wider_than_dissemination(self):
        self.assertGreaterEqual(DEFAULT.mempool.delta, DEFAULT.timing.dissemination)

    def test_the_door_admits_a_client_whose_clock_is_merely_imprecise(self):
        self.assertGreaterEqual(DEFAULT.mempool.w_admit, DEFAULT.timing.admission_floor)

    def test_endorsement_has_a_whole_round_of_margin(self):
        self.assertGreaterEqual(
            DEFAULT.mempool.w_valid_margin, DEFAULT.timing.endorse_margin(DEFAULT.mempool.delta)
        )

    def test_nothing_is_held_past_the_point_it_could_settle(self):
        """`evict_after` EQUALS `w_valid`, as a property, so the two cannot drift apart."""
        self.assertEqual(DEFAULT.mempool.evict_after, DEFAULT.mempool.w_valid)
        with self.assertRaises(TypeError):  # not a field: it cannot be set at all
            MempoolTunables(evict_after=1)  # ty: ignore[unknown-argument]


class TestAnIncoherentDeploymentCannotBeBuilt(unittest.TestCase):
    def test_a_bucket_narrower_than_dissemination_is_refused(self):
        with self.assertRaises(InvariantError) as cm:
            Tunables(mempool=MempoolTunables(delta=100))
        self.assertIn("below its derived floor", str(cm.exception))

    def test_a_door_tighter_than_a_client_clock_is_refused(self):
        with self.assertRaises(InvariantError):
            Tunables(mempool=MempoolTunables(w_admit=1_000))

    def test_a_margin_shorter_than_a_round_is_refused(self):
        with self.assertRaises(InvariantError):
            Tunables(mempool=MempoolTunables(w_valid_margin=100))

    def test_a_backoff_cap_above_the_deadline_is_refused(self):
        with self.assertRaises(InvariantError) as cm:
            Tunables(plan=PlanTunables(backoff_cap=30_000))
        self.assertIn("never bind", str(cm.exception))

    def test_raising_a_declared_quantity_moves_every_floor(self):
        """The point of declaring them: a mixnet deployment with a 5 s round trip does not get to
        keep a 1 s bucket, and finds out at construction rather than in production."""
        with self.assertRaises(InvariantError) as cm:
            Tunables(timing=replace(DEFAULT.timing, rtt_max=5_000))
        self.assertIn("mempool.delta", str(cm.exception))

    def test_the_refusal_is_ours_and_therefore_fatal(self):
        """A misconfigured process must not run, so it must never be catchable as a peer's fault."""
        self.assertFalse(issubclass(InvariantError, DudeError))


class TestNoDialHidesOutsideTheOneSurface(unittest.TestCase):
    def test_the_transfer_bound_is_on_the_surface(self):
        """`_PULL_MAX` was a module constant in `node.py`."""
        self.assertEqual(DEFAULT.net.pull_max, NetTunables().pull_max)

    def test_one_dial_has_one_home(self):
        """`stagger_cap` and `max_parallel` were in both the link and plan groups, and only the
        plan's were read. Two dials with one name disagreed the moment one was derived."""
        for dead in ("stagger_cap", "max_parallel"):
            self.assertFalse(hasattr(DEFAULT.link, dead), f"link.{dead} is back")
