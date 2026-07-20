# M3 — the sans-io quorum client (L4), unit-tested against REAL node responses
# with NO transport: a trivial synchronous driver executes Sends via
# node.dispatch and feeds replies back. Exercises the PROTOCOL §1.3 rules
# (rev 5, two-phase only): uncontended PREPARE/ACCEPT -> QC, contention ->
# recovery re-proposing the highest accepted op, split -> convergence (the rev-1
# deadlock as a regression), and "hedge, don't blast".

import unittest
from collections import deque

from dudefs import artifacts as A
from dudefs import crypto as C
from dudefs import node as N
from dudefs import quorum as Q
from dudefs.acceptor import Acceptor
from dudefs.store import ChainStore
from tests._builders import World

NOW = 100
BIG_DELTA = 10_000  # sidestep the skew gate in these unit tests


class _Clock:
    """A mutable wall-clock the driver advances as simulated time passes; all
    nodes in a cluster share one (they agree on time in these unit tests)."""

    def __init__(self, t: int = NOW):
        self.t = t

    def __call__(self) -> int:
        return self.t


def _cluster(n, delta=BIG_DELTA):
    """n honest LocalNodes sharing one mutable clock, plus a roster of pubkeys."""
    clk = _Clock()
    nodes = []
    for i in range(n):
        sk = bytes([200 + i] * 32)
        pub = C.SIGNER.public(sk)
        acc = Acceptor(sk, pub, ChainStore(), config_epoch=0, delta_ms=delta)
        nodes.append(N.LocalNode(acc, clk))
    roster = [nd.acc.pub for nd in nodes]
    return nodes, roster


def _cfg(roster, client_pub):
    return Q.QuorumConfig(
        roster=roster, epoch=0, client_fp=A.fingerprint(client_pub), delta_hedge_ms=50
    )


class _Driver:
    """A minimal deterministic driver: dispatches Sends immediately (latency 0,
    in send order), records contacted nodes, fires Wakes as Ticks in time order.
    NOT the transport — just enough to exercise the coordinator sans network."""

    def __init__(self, nodes):
        self.nodes = nodes
        self.clock: _Clock = nodes[0].clock  # the shared cluster clock
        self.contacted: list[int] = []

    def run(self, machine):
        now = NOW
        queue = deque(machine.start(now))
        ticks: list[int] = []
        for _ in range(10_000):  # guard against a stuck machine
            if not queue:
                if not ticks:
                    raise AssertionError("stuck: no commands, no ticks")
                now = ticks.pop(0)
                self.clock.t = now  # simulated time reaches the next wake
                queue.extend(machine.feed(Q.Tick(now)))
                continue
            cmd = queue.popleft()
            if isinstance(cmd, Q.Done):
                return cmd.outcome
            if isinstance(cmd, Q.Wake):
                ticks.append(cmd.at_ms)
                ticks.sort()
            elif isinstance(cmd, Q.Send):
                self.contacted.append(cmd.node)
                result = N.dispatch(self.nodes[cmd.node], cmd.req)
                queue.extend(machine.feed(Q.Reply(cmd.node, cmd.req, result, now)))
        raise AssertionError("driver did not terminate")


def _preaccept(nodes, op, ballot):
    """Seed a node state by ACCEPTing `op` at `ballot` (rev 5: slotted envelopes
    reach a node only via ballot ACCEPT, never SUBMIT — item 21)."""
    assert op.slot_tag is not None
    for nd in nodes:
        r = nd.acc.on_accept(op.slot_tag, ballot, op, NOW)
        assert isinstance(r, A.Receipt)


def _create(w: World, ci: int, val: bytes) -> A.Op:
    """A creation CAS on key `k` (absent -> val) authored by client `ci`."""
    return w.cas(
        ci, b"k", A.VERSION_ABSENT, 0, [[A.Guard.ABSENT, b"k"]], [[A.Mutation.SET, b"k", val]]
    )


class TestTwoPhase(unittest.TestCase):
    def test_happy_path_prepare_accept_hedge_not_blast(self):
        nodes, roster = _cluster(3)
        w = World(seed=1, n_clients=1)
        op = _create(w, 0, b"v")
        cfg = _cfg(roster, op.author)
        drv = _Driver(nodes)
        outcome = drv.run(Q.Commit(cfg, op))
        # committed with a verifiable QC over the client's own op (2 phases,
        # uncontended: PREPARE round 1 finds nothing accepted -> ACCEPT own)
        self.assertIsInstance(outcome, Q.Committed)
        assert isinstance(outcome, Q.Committed)
        self.assertEqual(outcome.qc.op_hash, op.op_hash)
        assert op.slot_tag is not None
        prio = A.slot_priority(op.slot_tag, cfg.client_fp)  # per-slot tiebreak (24d)
        self.assertEqual(outcome.qc.ballot, A.Ballot(1, prio))  # round 1, not 0
        self.assertTrue(outcome.qc.verify(roster))
        # hedge, don't blast: each phase contacts only a quorum (the same {0,1})
        self.assertEqual(len(set(drv.contacted)), cfg.quorum)


class TestContention(unittest.TestCase):
    def test_conflict_recovers_to_the_decided_rival(self):
        nodes, roster = _cluster(3)
        w = World(seed=2, n_clients=2)
        rival = _create(w, 0, b"A")
        mine = _create(w, 1, b"B")
        self.assertEqual(rival.slot_tag, mine.slot_tag)  # same lineage -> same tag
        _preaccept(nodes, rival, A.Ballot(1, b"\x01"))  # rival decided at (1,·) everywhere

        outcome = _Driver(nodes).run(Q.Commit(_cfg(roster, mine.author), mine))
        # my PREPARE sees the rival accepted -> recovery MUST re-propose the
        # highest accepted op (the rival) -> I lose the slot; rival gets its QC.
        self.assertIsInstance(outcome, Q.LostSlot)
        assert isinstance(outcome, Q.LostSlot)
        self.assertEqual(outcome.winner, rival.op_hash)
        self.assertTrue(outcome.qc.verify(roster))
        self.assertEqual(outcome.qc.op_hash, rival.op_hash)


class TestSplitVote(unittest.TestCase):
    def test_split_vote_recovers_to_exactly_one_winner(self):
        # n=5, 2-2 split (rev-1 deadlock regression): opA on {0,1}, opB on {2,3},
        # node 4 uncommitted. A recoverer decides the slot for exactly one op.
        nodes, roster = _cluster(5)
        w = World(seed=3, n_clients=3)
        opA = _create(w, 0, b"A")
        opB = _create(w, 1, b"B")
        _preaccept(nodes[0:2], opA, A.Ballot(1, b"\x01"))
        _preaccept(nodes[2:4], opB, A.Ballot(1, b"\x02"))
        mine = _create(w, 2, b"C")

        outcome = _Driver(nodes).run(Q.Commit(_cfg(roster, mine.author), mine))
        # a winner emerges (recovery converges — no deadlock); its QC is valid and
        # is for one of the already-accepted ops (highest ballot re-proposed).
        self.assertIsInstance(outcome, (Q.Committed, Q.LostSlot))
        qc = outcome.qc  # type: ignore[union-attr]
        self.assertTrue(qc.verify(roster))
        self.assertIn(qc.op_hash, {opA.op_hash, opB.op_hash, mine.op_hash})


class TestBallotFairness(unittest.TestCase):
    def test_per_slot_tiebreak_prevents_starvation(self):
        # NOTES item 24d: a fixed pair of clients (raw fp ordering is constant, so
        # the old scheme let one win EVERY same-round tie and starve the other)
        # must each win ~half the same-round ties across distinct slots.
        fp_a = A.fingerprint(C.SIGNER.public(bytes([1] * 32)))
        fp_b = A.fingerprint(C.SIGNER.public(bytes([2] * 32)))
        self.assertNotEqual(fp_a > fp_b, fp_a < fp_b)  # one is globally "higher"
        a_wins = 0
        n = 1000
        for i in range(n):
            tag = C.h(b"lineage/%d" % i)  # a distinct slot per version/attempt
            if A.slot_priority(tag, fp_a) > A.slot_priority(tag, fp_b):
                a_wins += 1
        self.assertTrue(0.4 * n < a_wins < 0.6 * n, f"unfair split: A won {a_wins}/{n}")


class TestFinalize(unittest.TestCase):
    def test_polls_until_a_quorum_attests_past_the_target(self):
        # δ=5, clock starts at 100; a floor is `now − 5`. target hlc 120 is final
        # once a quorum of nodes attest floor ≥ 120, i.e. once now ≥ 125. The
        # poller re-polls every 20ms; the driver advances the clock on each Wake.
        nodes, roster = _cluster(3, delta=5)
        cfg = _cfg(roster, b"client")
        outcome = _Driver(nodes).run(Q.Finalize(cfg, A.HLC(120, 0)))
        self.assertIsInstance(outcome, Q.Final)
        assert isinstance(outcome, Q.Final)
        # a quorum's worth of verifiable watermarks, all at/above the frontier
        self.assertGreaterEqual(len(outcome.watermarks), cfg.quorum)
        self.assertLessEqual(A.HLC(120, 0), outcome.frontier)
        for wm in outcome.watermarks:
            self.assertTrue(wm.verify())
            self.assertLessEqual(outcome.frontier, wm.floor)


if __name__ == "__main__":
    unittest.main()
