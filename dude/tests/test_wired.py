# Every check must have a caller that acts on it; every duty must have a driver that performs it.
#
# THE FAILURE THIS EXISTS TO CATCH, and it has now happened six times in this codebase `[H]`:
# *"we decided on a mitigation, tested that mitigation... without mitigating anything."* A check is
# specified, implemented correctly, unit-tested against its own inputs — and then nothing consults
# it where the decision is made. Every instance passed its own tests, because those tests exercised
# the primitive rather than the path.
#
#   `attested()`            verified signatures and never COUNTED them, so "ratified" meant
#                           "one roster member signed"
#   `replay`'s marker       applied any collection with no ratification check at all
#   `_collect` on replay    fabricated an unsigned floor and stored it as the node's own
#   the ratified checkpoint never adopted, so a transfer was checked against the SENDER's word
#   `attested_floor`        took a max over floors whose signatures it never verified
#   `addressed_to`          the screen tag was compared by no layer, in no transport
#
# AND THE SAME FAILURE FOR DUTIES, which hid longer because it looks like nothing at all. A thing
# can be specified, built, unit-tested and correct while nothing in the round ever calls it. The
# whole compaction and conveyor subsystem is in that state: `Management.retire` kills an epoch and
# has no caller, `Node.drain` migrates stragglers and has no caller, `Node.maybe_collect` proposes
# a collection and has no caller, and `Store.epochs` is the backlog queue with no reader. So nothing
# migrates, nothing collects, nothing retires, and forward secrecy — the point of the conveyor — is
# unreachable, while every primitive underneath is correct and tested.
#
# WHAT THIS FILE CAN AND CANNOT DO. It catches a check with no caller — which was four of those six.
# It cannot catch a check that is called but incomplete (`attested` counting nothing), or one
# called in the wrong place (the frame boundary). For those the discipline is the review question:
# **which line refuses, and what breaks if I delete it?**
#
# A static test rather than coverage, deliberately: coverage says a line RAN, and every one of these
# ran constantly. The question here is whether anything DEPENDS on it.

from __future__ import annotations

import ast
import pathlib
import unittest

_DUDE = pathlib.Path(__file__).resolve().parent.parent
_PROD = sorted(p for p in _DUDE.rglob("*.py") if "tests" not in p.parts)

WIRED = {
    # the check                what it refuses, in one line
    "addressed_to": "a frame tagged for somebody else",
    "attested": "a checkpoint the quorum did not ratify, or too few of it did",
    "satisfied": "a decision taken on fewer signatures than the rule requires",
    "verify_possession": "a grant to a key nobody proved they hold",
    "accept": "an envelope for someone else, out of window, or unsigned",
    "contradiction": "believing a peer that has contradicted itself",
    "attested_floor": "a floor asserted by fewer than f+1 fresh responders",
    "fresh": "a statement too old to say anything about now",
    "may_write": "a write into a store the author holds no grant for",
    "_violations": "a roster whose failure-domain placement cannot survive its own bound",
    "admit": "a transaction outside the admission window, or already settled",
    "holds": "a transaction whose guards do not hold against committed state",
    "_vouches": "a relocation of a management row nobody currently authorised",
    "_relocates": "a Move that is not true of live state",
    "_disagrees": "a transferred run that does not reproduce a signed commitment",
    "_unverified": "a replayed entry whose signature does not verify",
    "_uncontiguous": "a run that would land somewhere other than the position owed",
    "adopt": "a checkpoint whose quorum signatures do not verify",
    "wrong_cluster": "a log our provisioned manager key does not authorise",
    "provision": "re-provisioning a node into a different cluster",
}
"""Checks that must have a live consumer in production code.

Keyed by the callable's name — `smt.verify`-style qualified names work too, for a name that is
ambiguous on its own."""

OWED = {
    "smt.verify": (
        "No proof is served on the wire — there is no verb for one, and `Store.prove` has no "
        "production caller either, so nothing is trusting an UNVERIFIED proof; the proof half of "
        "#state-root is absent at both ends. Its first consumer is the joiner, which verifies "
        "roster rows present and revoked ones absent against a signed root (HANDOFF.md §1, §2). "
        "The root itself IS checked: recomputed in `_on_collect` before this node will sign, and "
        "compared in `_disagrees` on every transfer."
    ),
    "conflicts": (
        "RULING PENDING: wire the exclusion rule into batch selection, or strike it. Sound either "
        "way -- settlement re-evaluates every guard, which is the backstop `falsifies` names -- so "
        "the cost today is a wasted slot and a GUARD refusal where an exclusion was meant, never "
        "wrong state. Do not leave this entry here indefinitely (HANDOFF.md §4)."
    ),
}
"""Checks with no consumer YET, each with the reason and who will consume it.

An entry here is a DEBT, stated where it cannot be mistaken for a delivered capability — which is
the documentation half of the same failure. Adding one is cheap and honest; leaving one for ever is
neither, so the test below fails as soon as an entry becomes wired."""


def _called(tree: ast.AST) -> set[str]:
    """Every name this module CALLS, as the FULL dotted path and as each suffix of it.

    Only `ast.Call` nodes count: a mention in a docstring, a comment or an import is not a consumer,
    and grepping cannot tell the difference.

    THE WHOLE CHAIN, not just the attribute, because two duties can share a method name: `retire` is
    both `Mempool.retire`, which the round calls, and `Management.retire`, which nothing calls. A
    detector that recorded only `retire` reported the second as driven — a guard against believing
    things happen, satisfied by a coincidence of names for the second time."""
    names: set[str] = set()
    for node in ast.walk(tree):
        if not isinstance(node, ast.Call):
            continue
        parts: list[str] = []
        f = node.func
        while isinstance(f, ast.Attribute):
            parts.append(f.attr)
            f = f.value
        if isinstance(f, ast.Name):
            parts.append(f.id)
        elif parts:
            parts.append("?")  # a call or subscript at the root: the chain is still usable
        else:
            continue
        chain = ".".join(reversed(parts))
        names.add(chain)
        # every suffix, so a list can key on "mgmt.retire" without knowing it is reached via `self`
        for i in range(1, len(parts)):
            names.add(".".join(reversed(parts[:i])))
    return names


def _production_calls() -> set[str]:
    out: set[str] = set()
    for p in _PROD:
        out |= _called(ast.parse(p.read_text()))
    return out


DRIVEN = {
    # the duty                what performs it, each round
    "mempool.evict": "ages out what can no longer be endorsed",
    "mempool.admit": "screens what a client offers",
    "mempool.reenter": "re-evaluates what settlement kicked",
    "mempool.propose": "offers this node's batch for a closed bucket",
    "mempool.retire": "forgets what landed in the log",
    "probe": "asks peers where they are, so a rollback is seen",
    "catch_up": "asks the longest peer for what we are missing",
    "postman.tick": "sends what is due and reaps what expired",
    "store.apply": "settles the agreed slice",
}
"""Duties that MUST be performed by the round. Keyed by the dotted call as production writes it.

A duty differs from a check: a check refuses something, a duty makes something happen. Both fail the
same way — no caller — but an unperformed duty leaves no trace at all, because nothing refuses and
nothing errors. The system simply never does the thing."""

UNDRIVEN = {
    "mgmt.retire": (
        "NOT a duty of the round `[H]`: wrap rows are not deleted as housekeeping. Retirement is a "
        "MANAGER operation, and a manager already may write the management store — deleting a "
        "client's wraps rides along with rotating that client. Listed because it still has no "
        "caller anywhere, not because the round owes it."
    ),
    "store.epochs": (
        "The conveyor's work queue, oldest epoch first, with no reader and no verb, so the layer "
        "that would convey cannot ask what to convey. Owed by a verb plus the worker/client layer "
        "that holds data keys. A node holds none, so re-encryption is correctly absent from this "
        "tree and is recorded OWED in SPEC's enforcement table rather than here."
    ),
}
"""Duties with no driver YET, each naming what owes it.

Same contract as `OWED`: cheap and honest to add, dishonest to leave for ever, and the test below
fails the moment one becomes driven so the list cannot rot into "we believe this happens"."""


class TestEveryCheckIsConsulted(unittest.TestCase):
    def test_every_check_has_a_production_caller(self):
        """A check nothing calls is not a mitigation, however well it is tested.

        Matching is EXACT, with no fall back from `smt.verify` to `verify`: `verify` is called all
        over the codebase on public keys, so a loose match reported the Merkle-proof check as wired
        and the debt list as stale. A guard against believing things happen must not itself be
        satisfied by a coincidence of names."""
        called = _production_calls()
        missing = {n: why for n, why in WIRED.items() if n not in called}
        self.assertEqual(
            missing,
            {},
            "these checks have no production caller, so nothing refuses what they describe",
        )

    def test_an_owed_check_that_became_wired_is_removed_from_the_debt_list(self):
        """The anti-rot half. A debt list that outlives its debts is how "specified and owed" decays
        back into "we believe this happens" — the exact confusion this file exists to prevent."""
        called = _production_calls()
        stale = sorted(n for n in OWED if n in called)
        self.assertEqual(
            stale, [], "these are wired now: delete them from OWED and add them to WIRED"
        )

    def test_the_two_lists_do_not_overlap(self):
        """A name cannot be both consulted and owed. Overlap means one of the two is a guess."""
        self.assertEqual(set(WIRED) & set(OWED), set())


class TestEveryDutyIsDriven(unittest.TestCase):
    def test_every_duty_has_a_driver(self):
        """A duty nothing calls is not implemented, however correct it is."""
        called = _production_calls()
        missing = {n: why for n, why in DRIVEN.items() if n not in called}
        self.assertEqual(missing, {}, "these duties are never performed by the round")

    def test_an_undriven_duty_that_became_driven_is_removed_from_the_debt_list(self):
        """The anti-rot half, and the one that will fire when compaction is finally driven."""
        called = _production_calls()
        stale = sorted(n for n in UNDRIVEN if n in called)
        self.assertEqual(
            stale, [], "these are driven now: delete them from UNDRIVEN and add them to DRIVEN"
        )

    def test_the_duty_lists_do_not_overlap(self):
        self.assertEqual(set(DRIVEN) & set(UNDRIVEN), set())

    def test_a_duty_is_not_confused_with_a_check(self):
        """`retire` is both `Mempool.retire`, which the round calls, and `Management.retire`, which
        nothing calls. Keying on the bare attribute reported the second as driven."""
        called = _production_calls()
        self.assertIn("mempool.retire", called)
        self.assertNotIn("mgmt.retire", called)
