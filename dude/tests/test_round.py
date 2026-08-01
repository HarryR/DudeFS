# Tests for dude.round -- the consensus protocol as a sans-I/O state machine.
#
# THE HARNESS IS DIRECT-WIRED. No net stack, no envelopes, no seals, no InProc. `wire()` is a
# 10-line helper that drains every Round's outbox and delivers to targets. This exists so the
# protocol is *found* by scenarios rather than *asserted* by code that nobody probes -- the
# previous round mechanism was a placeholder for weeks and nothing noticed, precisely because
# every test that touched it went through the wire and answered a different question. Here every
# scenario is a state machine on a table.
#
# Signatures are REAL. `crypto.Keypair.generate()` is fast enough that faking signatures buys
# nothing and loses the property that ratification actually verifies. A malicious node in a test
# is an actual peer with an actual key that signs something it should not.

from __future__ import annotations

import random
import unittest

from .. import quorum
from ..consensus.round import Block, Recipient, Round, RoundMsg, Sig, State, _slice_body, _slice_id
from ..core import crypto

T0 = 1_700_000_000_000
DELTA = 1_000
CLOSE_BY = T0 + 5 * DELTA
"""Collection window for tests: five ticks. Enough for a Held to reach every peer and be
re-observed by the sender before any node tries to finalize."""


def _wire(nodes: dict[crypto.PublicKey, Round], now: int) -> None:
    """Drain every Round's outbox and deliver to targets.

    A message addressed to `Recipient.ALL` goes to every OTHER node (never back to sender).
    A message addressed to a specific NodeId goes only to that node. Nothing here retries,
    reorders, or drops -- those are what the pipelining / partition scenarios will construct."""
    for src_id, src in nodes.items():
        for target, msg in src.outbox():
            for dst_id, dst in nodes.items():
                if dst_id == src_id:
                    continue
                if target is Recipient.ALL or target == dst_id:
                    dst.receive(msg, from_=src_id, now=now)


def _setup(
    n: int, bucket: int = 1, close_by: int = CLOSE_BY
) -> tuple[list[crypto.Keypair], dict[crypto.PublicKey, Round]]:
    """N nodes, one Round instance each, all for the same bucket."""
    keys = [crypto.Keypair.generate() for _ in range(n)]
    roster = tuple(k.public for k in keys)
    rounds = {
        k.public: Round(bucket=bucket, me=k, roster=roster, now=T0, close_by=close_by) for k in keys
    }
    return keys, rounds


def _run(nodes: dict[crypto.PublicKey, Round], rounds: int = 20, start: int = T0) -> int:
    """Tick + wire, `rounds` times. Returns the final `now`."""
    now = start
    for _ in range(rounds):
        for r in nodes.values():
            r.tick(now)
        _wire(nodes, now)
        now += DELTA
    return now


# --------------------------------------------------------------------------------------------- #
# Phase 1 scenarios: the smallest cases that pin the state machine's shape.                     #
# --------------------------------------------------------------------------------------------- #


class TestAllNodesAgree(unittest.TestCase):
    """The base case: three nodes hold the same set. Ratification is trivial -- the intersection
    is everything, there is no tie, nothing is left over. If this doesn't converge, nothing will."""

    def test_the_ratified_block_is_that_set(self):
        _keys, nodes = _setup(3)
        shared = frozenset({crypto.h(b"a"), crypto.h(b"b"), crypto.h(b"c")})
        for r in nodes.values():
            r.add_local(shared)

        _run(nodes)

        blocks = [r.ratified() for r in nodes.values()]
        for i, b in enumerate(blocks):
            self.assertIsNotNone(b, f"node {i} did not ratify")

        # narrow: every entry non-None per the loop above
        rats: list[Block] = [b for b in blocks if b is not None]
        expected_hashes = tuple(sorted(shared))
        self.assertEqual(
            {b.hashes for b in rats}, {expected_hashes}, "nodes ratified different sets"
        )
        for r in nodes.values():
            self.assertEqual(list(r.surviving()), [], "unexpected surviving hashes")

    def test_every_node_ends_in_state_gone(self):
        _keys, nodes = _setup(3)
        shared = frozenset({crypto.h(b"a"), crypto.h(b"b")})
        for r in nodes.values():
            r.add_local(shared)

        _run(nodes)

        for r in nodes.values():
            self.assertEqual(r.state(), State.GONE, "a node did not reach GONE")


class TestDisagreementAtTheEdge(unittest.TestCase):
    """One node holds an extra transaction nobody else does. The slice is the intersection
    (what a quorum can attest to); the extra is `surviving`, returned to the current mempool."""

    def test_the_extra_is_not_in_the_slice_and_is_returned_as_surviving(self):
        _keys, nodes = _setup(3)
        shared = {crypto.h(b"a"), crypto.h(b"b"), crypto.h(b"c")}
        extra = crypto.h(b"only-c")

        node_ids = list(nodes)
        for nid in node_ids[:2]:
            nodes[nid].add_local(frozenset(shared))
        nodes[node_ids[2]].add_local(frozenset(shared | {extra}))

        _run(nodes)

        blocks = [r.ratified() for r in nodes.values()]
        rats: list[Block] = [b for b in blocks if b is not None]
        self.assertEqual(len(rats), 3, "not all nodes ratified")
        self.assertEqual(
            {b.hashes for b in rats}, {tuple(sorted(shared))}, "ratified different sets"
        )
        for i, nid in enumerate(node_ids):
            expected = [extra] if i == 2 else []
            self.assertEqual(list(nodes[nid].surviving()), expected, f"node {i} wrong surviving")


class Fabric:
    """A simulated network for fault-injection scenarios. Wraps the direct-wire loop with:

      * per-edge partition (drop `(src, dst)` messages entirely)
      * per-message delay (deliver after N ticks instead of immediately)
      * message injection (deliver an arbitrary message to a node, bypassing sender's outbox)

    The default configuration is: no partition, no delay -- functionally identical to `_wire`.
    Every fault is a value the test constructs; nothing here reads a clock or sleeps."""

    def __init__(self, nodes: dict[crypto.PublicKey, Round], delay_ticks: int = 0) -> None:
        self.nodes = nodes
        self.delay = delay_ticks * DELTA
        self.partition: set[tuple[crypto.PublicKey, crypto.PublicKey]] = set()
        self.pending: list[tuple[crypto.PublicKey, crypto.PublicKey, RoundMsg, int]] = []

    def partition_pair(self, a: crypto.PublicKey, b: crypto.PublicKey) -> None:
        """Nothing flows between `a` and `b`, either direction."""
        self.partition.add((a, b))
        self.partition.add((b, a))

    def inject(
        self, msg: RoundMsg, from_: crypto.PublicKey, to: crypto.PublicKey, now: int
    ) -> None:
        """Deliver `msg` to `to` as if from `from_`, right now. Bypasses outbox and partition."""
        self.nodes[to].receive(msg, from_=from_, now=now)

    def tick(self, now: int) -> None:
        """One round: drain every Round's outbox into `pending`, then deliver anything due."""
        for src_id, src in self.nodes.items():
            for target, msg in src.outbox():
                for dst_id in self.nodes:
                    if dst_id == src_id:
                        continue
                    if target is not Recipient.ALL and target != dst_id:
                        continue
                    if (src_id, dst_id) in self.partition:
                        continue
                    self.pending.append((src_id, dst_id, msg, now + self.delay))
        remaining = []
        for src_id, dst_id, msg, deliver_at in self.pending:
            if deliver_at <= now:
                self.nodes[dst_id].receive(msg, from_=src_id, now=now)
            else:
                remaining.append((src_id, dst_id, msg, deliver_at))
        self.pending = remaining


def _run_fabric(
    nodes: dict[crypto.PublicKey, Round], fabric: Fabric, rounds: int = 20, start: int = T0
) -> int:
    now = start
    for _ in range(rounds):
        for r in nodes.values():
            r.tick(now)
        fabric.tick(now)
        now += DELTA
    return now


def _run_multi(rounds_list: list[tuple[crypto.PublicKey, Round]], ticks: int = 20) -> int:
    """Wire a list of `(node_id, Round)` where multiple Rounds MAY share a `node_id` (one per
    bucket, per node). A Round drops foreign-bucket messages internally, so all deliveries flow
    through this one loop and buckets stay independent."""
    now = T0
    for _ in range(ticks):
        for _nid, r in rounds_list:
            r.tick(now)
        for src_id, src in rounds_list:
            for target, msg in src.outbox():
                for dst_id, dst in rounds_list:
                    if dst_id == src_id:
                        continue
                    if target is not Recipient.ALL and target != dst_id:
                        continue
                    dst.receive(msg, from_=src_id, now=now)
        now += DELTA
    return now


class TestEmptyBucket(unittest.TestCase):
    """No node holds anything. The bucket ratifies an empty block rather than stalling."""

    def test_ratified_block_is_empty(self):
        _keys, nodes = _setup(3)
        for r in nodes.values():
            r.add_local(frozenset())

        _run(nodes)

        blocks = [r.ratified() for r in nodes.values()]
        rats: list[Block] = [b for b in blocks if b is not None]
        self.assertEqual(len(rats), 3, "not all nodes ratified an empty bucket")
        self.assertEqual({b.hashes for b in rats}, {()}, "ratified something in an empty bucket")


class TestDelayedMessages(unittest.TestCase):
    """Messages arrive late. Nodes MUST still converge, and MUST sign based on observations
    at close_by -- not on whatever happens to arrive first."""

    def test_delivery_delayed_by_two_ticks_still_converges(self):
        # Push close_by out far enough that the delayed Helds still arrive before it.
        close_by = T0 + 20 * DELTA
        _keys, nodes = _setup(3, close_by=close_by)
        shared = frozenset({crypto.h(b"a"), crypto.h(b"b")})
        for r in nodes.values():
            r.add_local(shared)

        fabric = Fabric(nodes, delay_ticks=2)
        _run_fabric(nodes, fabric, rounds=30)

        blocks = [r.ratified() for r in nodes.values()]
        rats: list[Block] = [b for b in blocks if b is not None]
        self.assertEqual(len(rats), 3, "delayed delivery prevented ratification")
        self.assertEqual({b.hashes for b in rats}, {tuple(sorted(shared))}, "diverged")


class TestPartitionedMinority(unittest.TestCase):
    """A single node is fully partitioned from the others. The remaining quorum ratifies without
    it; the partitioned node does not corrupt or block anything."""

    def test_quorum_ratifies_without_partitioned_node(self):
        keys, nodes = _setup(3)
        shared = frozenset({crypto.h(b"a"), crypto.h(b"b")})
        for r in nodes.values():
            r.add_local(shared)

        # Partition node 2 from nodes 0 and 1.
        fabric = Fabric(nodes)
        fabric.partition_pair(keys[0].public, keys[2].public)
        fabric.partition_pair(keys[1].public, keys[2].public)

        _run_fabric(nodes, fabric)

        # Two connected nodes ratify. Partitioned node does not.
        connected = [nodes[k.public].ratified() for k in keys[:2]]
        isolated = nodes[keys[2].public].ratified()

        self.assertTrue(all(b is not None for b in connected), "connected quorum did not ratify")
        conn: list[Block] = [b for b in connected if b is not None]
        self.assertEqual({b.hashes for b in conn}, {tuple(sorted(shared))})
        # Isolated: either did not ratify at all, or ratified an empty slice on its own evidence
        # alone (which would not reach quorum, so it stays in FINALIZE).
        self.assertIsNone(isolated, "isolated node ratified without a quorum")


class TestByzantineEquivocation(unittest.TestCase):
    """One node signs two contradictory slices for the same bucket. Ratification MUST NOT be
    corrupted, and the pair MUST be exposed for the evidence machinery."""

    def test_equivocation_is_detected_and_ratification_survives(self):
        keys, nodes = _setup(3)
        shared = frozenset({crypto.h(b"a"), crypto.h(b"b")})
        for r in nodes.values():
            r.add_local(shared)

        fabric = Fabric(nodes)
        # Run one tick+wire so Helds propagate.
        for r in nodes.values():
            r.tick(T0)
        fabric.tick(T0)

        # Craft a bogus Sig from node 2 for a slice that isn't the real one, then inject it into
        # node 0 BEFORE the real round produces the honest Sig.
        bogus_slice = frozenset({crypto.h(b"nope")})
        bogus_hash = _slice_id(1, bogus_slice)
        bogus_sig = Sig(
            bucket=1,
            slice_hash=bogus_hash,
            sig=keys[2].sign(_slice_body(1, bogus_hash)),
        )
        fabric.inject(bogus_sig, from_=keys[2].public, to=keys[0].public, now=T0 + DELTA)

        # Now let the round complete normally.
        _run_fabric(nodes, fabric, rounds=30, start=T0 + 2 * DELTA)

        # Nodes 0 and 1 (a quorum) ratify the honest slice.
        r0 = nodes[keys[0].public].ratified()
        r1 = nodes[keys[1].public].ratified()
        self.assertIsNotNone(r0, "node 0 did not ratify")
        self.assertIsNotNone(r1, "node 1 did not ratify")
        assert r0 is not None and r1 is not None
        self.assertEqual(r0.hashes, tuple(sorted(shared)), "node 0 ratified the wrong slice")
        self.assertEqual(r1.hashes, tuple(sorted(shared)))

        # Node 0 saw the equivocation from node 2.
        eqs = list(nodes[keys[0].public].equivocations())
        self.assertEqual(len(eqs), 1, "node 0 did not expose the equivocation")
        (who, first, second) = eqs[0]
        self.assertEqual(who, keys[2].public)
        self.assertNotEqual(first.slice_hash, second.slice_hash)


class TestPipelining(unittest.TestCase):
    """Two Rounds for two buckets, running concurrently on the same nodes. Round instances are
    scoped by bucket; messages for a foreign bucket are silently dropped, so buckets do not
    interfere even when routed through the same wire."""

    def test_two_buckets_ratify_independently(self):
        keys = [crypto.Keypair.generate() for _ in range(3)]
        roster = tuple(k.public for k in keys)
        rounds_b1 = {k.public: Round(1, k, roster, T0, CLOSE_BY) for k in keys}
        rounds_b2 = {k.public: Round(2, k, roster, T0, CLOSE_BY) for k in keys}
        set_b1 = frozenset({crypto.h(b"b1-a"), crypto.h(b"b1-b")})
        set_b2 = frozenset({crypto.h(b"b2-x"), crypto.h(b"b2-y"), crypto.h(b"b2-z")})
        for r in rounds_b1.values():
            r.add_local(set_b1)
        for r in rounds_b2.values():
            r.add_local(set_b2)

        _run_multi(list(rounds_b1.items()) + list(rounds_b2.items()))

        # Bucket 1: all ratify with set_b1
        rats_b1 = [r.ratified() for r in rounds_b1.values()]
        rats_b1_ok: list[Block] = [b for b in rats_b1 if b is not None]
        self.assertEqual(len(rats_b1_ok), 3, "bucket 1 did not all ratify")
        self.assertEqual({b.hashes for b in rats_b1_ok}, {tuple(sorted(set_b1))})

        # Bucket 2: all ratify with set_b2, independently
        rats_b2 = [r.ratified() for r in rounds_b2.values()]
        rats_b2_ok: list[Block] = [b for b in rats_b2 if b is not None]
        self.assertEqual(len(rats_b2_ok), 3, "bucket 2 did not all ratify")
        self.assertEqual({b.hashes for b in rats_b2_ok}, {tuple(sorted(set_b2))})


class TestRandomisedBuckets(unittest.TestCase):
    """Same shape as pipelining, but across many buckets started in random order. Confirms
    each bucket is independent -- the ordering of Round construction and message delivery
    does not affect what any bucket settles on."""

    def test_ten_buckets_random_order_each_ratifies_its_own_set(self):
        rng = random.Random(0xC0DE)
        keys = [crypto.Keypair.generate() for _ in range(3)]
        roster = tuple(k.public for k in keys)

        # Distinct set of hashes per bucket, so we can assert bucket B ratified set B.
        buckets = list(range(1, 11))
        rng.shuffle(buckets)
        contents = {
            b: frozenset({crypto.h(f"b{b}-{i}".encode()) for i in range(3)}) for b in buckets
        }

        # Construct Rounds in the shuffled order; add_local in the shuffled order.
        rounds_by_bucket: dict[int, dict[crypto.PublicKey, Round]] = {}
        for b in buckets:
            rounds_by_bucket[b] = {k.public: Round(b, k, roster, T0, CLOSE_BY) for k in keys}
            for r in rounds_by_bucket[b].values():
                r.add_local(contents[b])

        # One shared wire for every Round of every bucket -- Rounds filter foreign buckets.
        all_rounds: list[tuple[crypto.PublicKey, Round]] = [
            (nid, r) for by_node in rounds_by_bucket.values() for nid, r in by_node.items()
        ]
        _run_multi(all_rounds)

        # Every bucket ratifies its own contents.
        for b in buckets:
            rats = [r.ratified() for r in rounds_by_bucket[b].values()]
            rats_ok: list[Block] = [x for x in rats if x is not None]
            self.assertEqual(len(rats_ok), 3, f"bucket {b} did not all ratify")
            self.assertEqual(
                {x.hashes for x in rats_ok},
                {tuple(sorted(contents[b]))},
                f"bucket {b} ratified the wrong set",
            )


class TestTieBreak(unittest.TestCase):
    """Two candidate slices of equal maximum size (#slice-tie-break).

    A: {1, 2, 3}, B: {1, 2, 4}, C: {1, 2, 3, 4}. Quorum = 2. Candidate intersections: AB={1,2}
    (size 2), AC={1,2,3} (size 3), BC={1,2,4} (size 3). Two maximal candidates -- honest nodes
    that can back the winning slice MUST converge on ONE by a deterministic keyed sort, and
    the KEY MUST include the bucket so an adversary cannot pre-mine transactions to guarantee
    winning in every future round.

    LIVENESS IS QUORUM-SCOPED, NOT UNIVERSAL. `_compute_slice` restricts to slices ⊆ local
    (a node MUST NOT sign what it does not hold), so whichever candidate wins the tie-break,
    exactly one of {A, B} cannot back it and does not ratify. That is not a bug: it is what
    `⊆ local` guarantees. Two ratifiers is a quorum; the one non-ratifier will re-enter its
    unwitnessed tx to the next bucket."""

    def test_ratifiers_converge_on_the_same_maximal_candidate(self):
        _keys, nodes = _setup(3)
        h1, h2, h3, h4 = (crypto.h(b"1"), crypto.h(b"2"), crypto.h(b"3"), crypto.h(b"4"))
        node_ids = list(nodes)
        nodes[node_ids[0]].add_local(frozenset({h1, h2, h3}))
        nodes[node_ids[1]].add_local(frozenset({h1, h2, h4}))
        nodes[node_ids[2]].add_local(frozenset({h1, h2, h3, h4}))

        _run(nodes)

        blocks = [r.ratified() for r in nodes.values()]
        rats: list[Block] = [b for b in blocks if b is not None]
        # Liveness: at least the quorum (2) of nodes that CAN back the winning slice ratifies.
        self.assertGreaterEqual(len(rats), 2, f"fewer than a quorum ratified: {len(rats)}")
        # Safety: everyone who ratified ratified the same slice.
        distinct_slices = {b.hashes for b in rats}
        self.assertEqual(len(distinct_slices), 1, f"nodes disagreed: {distinct_slices}")
        (chosen,) = distinct_slices
        self.assertEqual(len(chosen), 3, "the chosen slice should be one of the maximal candidates")
        self.assertIn(chosen, {tuple(sorted({h1, h2, h3})), tuple(sorted({h1, h2, h4}))})

    def test_the_tie_break_key_depends_on_the_bucket(self):
        """Same holdings, different bucket -> the tie-break rolls the dice again.

        With only two candidates, half of all buckets pick one and half pick the other on
        average, so any modest range of buckets contains at least one of each. We probe up to
        32 buckets and assert the ratified winner is not always the same. Which node ratifies
        depends on which candidate wins the bucket -- so we take the winner from ANY ratifier,
        not specifically node 0, whose slice may not have won this bucket."""
        h1, h2, h3, h4 = (crypto.h(b"1"), crypto.h(b"2"), crypto.h(b"3"), crypto.h(b"4"))

        seen: set[tuple[crypto.Digest, ...]] = set()
        for bucket in range(1, 33):
            _keys, nodes = _setup(3, bucket=bucket)
            node_ids = list(nodes)
            nodes[node_ids[0]].add_local(frozenset({h1, h2, h3}))
            nodes[node_ids[1]].add_local(frozenset({h1, h2, h4}))
            nodes[node_ids[2]].add_local(frozenset({h1, h2, h3, h4}))
            _run(nodes)
            rats = [b for r in nodes.values() if (b := r.ratified()) is not None]
            self.assertGreaterEqual(len(rats), 2, f"bucket {bucket}: fewer than a quorum ratified")
            distinct = {b.hashes for b in rats}
            self.assertEqual(len(distinct), 1, f"bucket {bucket}: ratifiers disagreed: {distinct}")
            (winner,) = distinct
            seen.add(winner)
            if len(seen) >= 2:
                return
        self.fail(f"tie-break winner was constant across 32 buckets: {seen}")


# --------------------------------------------------------------------------------------------- #
# Phase 4: property tests. The scenario suite pins specific shapes; this catches the space in   #
# between by running many seeded random topologies through the same invariants.                 #
# --------------------------------------------------------------------------------------------- #

_UNIVERSE = tuple(crypto.h(f"tx{i}".encode()) for i in range(16))
"""A small pool of hash values so random subsets overlap enough to make intersections interesting.
Sixteen is chosen so C(16, k) is small enough that any per-node subset is enumerable, and large
enough that at n=7, quorum=5 we get non-trivial edge cases."""


def _random_setup(
    rng: random.Random, n: int, bucket: int = 1
) -> tuple[
    list[crypto.Keypair],
    dict[crypto.PublicKey, Round],
    dict[crypto.PublicKey, frozenset[crypto.Digest]],
]:
    """N nodes, per-node random holdings drawn from `_UNIVERSE`."""
    keys, nodes = _setup(n, bucket=bucket)
    holdings: dict[crypto.PublicKey, frozenset[crypto.Digest]] = {}
    for k in keys:
        size = rng.randint(0, len(_UNIVERSE))
        holdings[k.public] = frozenset(rng.sample(_UNIVERSE, size))
        nodes[k.public].add_local(holdings[k.public])
    return keys, nodes, holdings


def _distinct_blocks(nodes: dict[crypto.PublicKey, Round]) -> set[tuple[crypto.Digest, ...]]:
    """The set of distinct block hashes among nodes that ratified. Safety demands `len ≤ 1`."""
    return {b.hashes for r in nodes.values() if (b := r.ratified()) is not None}


class TestPropertyConvergence(unittest.TestCase):
    """SAFETY: no two honest nodes ratify different blocks in the same bucket, ever.

    Note liveness is NOT universal: `_compute_slice` restricts to slices ⊆ local, so a node
    holding fewer txs than the quorum's intersection cannot sign for the full slice and does
    not ratify. That is correct -- a node MUST NOT sign a slice it cannot back with bodies. The
    liveness property is quorum-scoped: at least the quorum of nodes holding the winning slice
    do ratify."""

    def test_no_faults_at_most_one_distinct_block(self):
        for seed in range(50):
            with self.subTest(seed=seed):
                rng = random.Random(seed)
                n = rng.randint(3, 7)
                _keys, nodes, _holdings = _random_setup(rng, n)

                _run(nodes, rounds=20)

                blocks = _distinct_blocks(nodes)
                self.assertLessEqual(
                    len(blocks), 1, f"n={n} produced {len(blocks)} distinct blocks"
                )

    def test_random_delays_still_agree(self):
        """Under delayed delivery (up to 3 ticks), a wide enough close_by still lets all nodes
        gather stable evidence. Convergence (safety) rests on stable evidence, not fast."""
        for seed in range(50):
            with self.subTest(seed=seed):
                rng = random.Random(seed)
                n = rng.randint(3, 7)
                # Push close_by well beyond the maximum delay so evidence stabilises.
                close_by = T0 + 30 * DELTA
                keys = [crypto.Keypair.generate() for _ in range(n)]
                roster = tuple(k.public for k in keys)
                nodes = {k.public: Round(1, k, roster, T0, close_by) for k in keys}
                for k in keys:
                    size = rng.randint(0, len(_UNIVERSE))
                    nodes[k.public].add_local(frozenset(rng.sample(_UNIVERSE, size)))

                fabric = Fabric(nodes, delay_ticks=rng.randint(0, 3))
                _run_fabric(nodes, fabric, rounds=60)

                blocks = _distinct_blocks(nodes)
                self.assertLessEqual(len(blocks), 1, f"delayed n={n} diverged: {len(blocks)}")


class TestPropertySafetyUnderPartition(unittest.TestCase):
    """One node fully partitioned from the others. SAFETY: the connected part MUST NOT ratify a
    block different from what an unpartitioned run would produce, and MUST NOT ratify a block
    the partitioned node also (independently) ratifies."""

    def test_single_partition_keeps_safety(self):
        for seed in range(50):
            with self.subTest(seed=seed):
                rng = random.Random(seed)
                n = rng.randint(3, 7)
                q = quorum.DEFAULT.size(n)
                # Partition needs n - 1 >= quorum for the connected part to make progress.
                if n - 1 < q:
                    continue
                keys, nodes, _holdings = _random_setup(rng, n)
                isolated = rng.choice(keys)

                fabric = Fabric(nodes)
                for k in keys:
                    if k is not isolated:
                        fabric.partition_pair(isolated.public, k.public)

                _run_fabric(nodes, fabric, rounds=20)

                blocks = _distinct_blocks(nodes)
                # At most one block anywhere (isolated might independently sign an empty slice,
                # but that alone can never reach quorum, so it cannot ratify).
                self.assertLessEqual(
                    len(blocks), 1, f"partition n={n} produced disagreement: {blocks}"
                )
                # Isolated node does NOT ratify (it has only its own evidence, cannot reach quorum).
                self.assertIsNone(nodes[isolated.public].ratified(), "isolated node ratified alone")


class TestPropertySafetyUnderByzantine(unittest.TestCase):
    """A byzantine peer injects a bogus Sig into one honest node. SAFETY: honest nodes still
    ratify the same block (or none). The bogus Sig may either be a signature over a wholly
    fabricated slice, or a valid signature over a different real slice than the one this
    byzantine node would have signed honestly."""

    def test_injected_bogus_sig_does_not_corrupt_ratification(self):
        for seed in range(50):
            with self.subTest(seed=seed):
                rng = random.Random(seed)
                n = rng.randint(4, 7)  # need f >= 1 for a byzantine node with quorum still met
                keys, nodes, _holdings = _random_setup(rng, n)

                fabric = Fabric(nodes)
                # First tick+wire so Helds propagate.
                for r in nodes.values():
                    r.tick(T0)
                fabric.tick(T0)

                # Byzantine node picks a random victim and sends a bogus Sig for a slice that
                # differs from anything real.
                byz, victim = rng.sample(keys, 2)
                bogus_hashes = frozenset(rng.sample(_UNIVERSE, rng.randint(1, 5)))
                bogus_hash = _slice_id(1, bogus_hashes)
                bogus_sig = Sig(1, bogus_hash, byz.sign(_slice_body(1, bogus_hash)))
                fabric.inject(bogus_sig, from_=byz.public, to=victim.public, now=T0 + DELTA)

                _run_fabric(nodes, fabric, rounds=30, start=T0 + 2 * DELTA)

                blocks = _distinct_blocks(nodes)
                # Safety: at most one distinct block among all ratifying nodes.
                self.assertLessEqual(
                    len(blocks), 1, f"byzantine n={n} caused disagreement: {blocks}"
                )


if __name__ == "__main__":
    unittest.main()
