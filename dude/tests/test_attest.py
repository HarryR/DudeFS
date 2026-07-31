"""Attestations, and what two of them prove (#monotonicity, #cross-attestation).

The asymmetry worth remembering while reading these: a missed rollback costs a stale read, and a
false conviction permanently kills a paid-for node. Several tests below exist only to pin the
NON-faults -- the honest crash, the partition, the node that merely made progress.
"""

import itertools
import tempfile
import unittest

from dude.core import crypto
from dude.core.errors import DudeError
from dude.store import attest, ops, store

D = ops.STORE_DATA


NOW = 1_700_000_000_000
WINDOW = 120_000


def _claim(seq: int, head: int, acc: bytes = b"s", at: int = NOW) -> attest.Attestation:
    """A claim with each quantity settable on its own, so a test can move exactly one."""
    return attest.Attestation(seq, head, crypto.acc_element(acc), crypto.acc_element(b"log"), at=at)


class TestEncoding(unittest.TestCase):
    """Both halves of every pair, because C1 shipped an `attest_bytes` with no inverse and every
    claim on the wire decoded to nothing in total silence."""

    def setUp(self):
        self.kp = crypto.Keypair.generate()

    def test_a_claim_round_trips(self):
        c = _claim(7, 4242)
        self.assertEqual(attest.Attestation.decode(c.encode()), c)

    def test_a_signed_attestation_round_trips_and_verifies(self):
        s = attest.SignedAttestation.make(self.kp, _claim(7, 4242))
        back = attest.SignedAttestation.decode(s.encode())
        self.assertEqual(back, s)
        self.assertTrue(back.verify())

    def test_a_tampered_claim_does_not_verify(self):
        """The signature covers the claim, so raising the head after signing is not a lie anyone
        will believe -- it is simply not a signed statement any more."""
        s = attest.SignedAttestation.make(self.kp, _claim(7, 4242))
        forged = attest.SignedAttestation(s.by, _claim(7, 999_999), s.sig)
        self.assertFalse(forged.verify())

    def test_an_attestation_refuses_garbage(self):
        with self.assertRaises(DudeError):
            attest.Attestation.decode(b"not-bencode")


class TestContradiction(unittest.TestCase):
    def setUp(self):
        self.kp = crypto.Keypair.generate()
        self.other = crypto.Keypair.generate()

    def _sign(self, claim, kp=None):
        return attest.SignedAttestation.make(kp or self.kp, claim)

    def test_progress_is_not_a_fault(self):
        """The overwhelmingly common case, and the one a false positive would destroy."""
        a, b = self._sign(_claim(1, 100)), self._sign(_claim(2, 140))
        self.assertIsNone(attest.contradiction(a, b))

    def test_a_regression_convicts(self):
        a, b = self._sign(_claim(1, 100)), self._sign(_claim(2, 90))
        ev = attest.contradiction(a, b)
        assert ev is not None
        self.assertEqual(ev.fault, attest.Fault.REGRESSION)
        self.assertEqual(ev.culprit, self.kp.public)
        self.assertEqual((ev.earlier.claim.head, ev.later.claim.head), (100, 90))

    def test_equivocation_convicts(self):
        a, b = self._sign(_claim(4, 100)), self._sign(_claim(4, 101))
        ev = attest.contradiction(a, b)
        assert ev is not None
        self.assertEqual(ev.fault, attest.Fault.EQUIVOCATION)

    def test_the_same_statement_twice_is_not_equivocation(self):
        """A node re-serves its current attestation to everyone who asks. Identical bytes at one
        counter value are one statement, not two -- otherwise answering twice would be fatal."""
        c = _claim(4, 100)
        self.assertIsNone(attest.contradiction(self._sign(c), self._sign(c)))

    def test_argument_order_does_not_matter(self):
        a, b = self._sign(_claim(1, 100)), self._sign(_claim(2, 90))
        self.assertEqual(attest.contradiction(a, b), attest.contradiction(b, a))

    def test_two_keys_are_never_a_conviction(self):
        """Divergence, not conviction. Two nodes disagreeing proves something is wrong and NOTHING
        about who -- and shunning on it would let a liar get an honest node shunned."""
        a = self._sign(_claim(1, 100, acc=b"one"))
        b = self._sign(_claim(1, 100, acc=b"two"), kp=self.other)
        self.assertIsNone(attest.contradiction(a, b))

    def test_unsigned_bytes_are_not_evidence(self):
        """Anyone can WRITE an incriminating claim. Only the key can make it evidence."""
        real = self._sign(_claim(1, 100))
        planted = attest.SignedAttestation(self.kp.public, _claim(2, 5), real.sig)
        self.assertIsNone(attest.contradiction(real, planted))

    def test_a_stalled_node_is_not_convicted(self):
        """Silence and staleness are not faults (#cross-attestation). A frozen node attests
        truthfully forever -- it is not FRESH, which is a different property this cannot supply."""
        a, b = self._sign(_claim(1, 100)), self._sign(_claim(9, 100))
        self.assertIsNone(attest.contradiction(a, b))


class TestTheInterlock(unittest.TestCase):
    """`Store.attestation` is where an honest crash could manufacture evidence against an honest
    node, and conviction is terminal. These are the tests that keep that from happening."""

    def setUp(self):
        self.s = store.Store()
        self.kp = crypto.Keypair.generate()

    def test_the_counter_strictly_increases(self):
        seqs = [self.s.attestation(NOW).seq for _ in range(5)]
        self.assertEqual(seqs, sorted(set(seqs)), "a reused counter is a self-conviction")
        self.assertEqual(seqs[0], 1)

    def test_the_counter_is_committed_before_the_caller_can_sign(self):
        """The crash case: build a claim, never sign it, crash. The counter must NOT come back:
        a gap costs nothing, and reuse over different bytes convicts by the node's own key."""
        dropped = self.s.attestation(NOW)  # signed by nobody; the process died here
        again = self.s.attestation(NOW)
        self.assertGreater(again.seq, dropped.seq, "the counter came back after a crash")

    def test_a_reopened_store_does_not_reuse_the_counter(self):
        """Same, across a restart rather than a dropped claim: the counter is durable, not a
        process-lifetime variable. On disk, because that is where a restore happens."""
        with tempfile.TemporaryDirectory() as d:
            path = f"{d}/log.db"
            first = store.Store(path)
            seq = first.attestation(NOW).seq
            first.close()
            self.assertGreater(store.Store(path).attestation(NOW).seq, seq)

    def test_the_snapshot_is_coherent(self):
        """One transaction, so head and both folds belong to the same moment. Five separate reads
        could attest a head whose accumulator came from before it."""
        a = self.s.attestation(NOW)
        self.assertEqual(a.head, self.s.head())
        self.assertEqual(a.acc_state, self.s.accumulator())
        self.assertEqual(a.acc_log, self.s.log_accumulator())

    def test_an_honest_node_never_convicts_itself(self):
        """The property the whole design hangs on, stated directly: every consecutive pair of a
        healthy node's own attestations must be clean."""
        signed = [attest.SignedAttestation.make(self.kp, self.s.attestation(NOW)) for _ in range(6)]
        for a, b in itertools.pairwise(signed):
            self.assertIsNone(attest.contradiction(a, b), "an honest node convicted itself")


class TestFreshness(unittest.TestCase):
    """#freshness-is-gathered. What is being tested is a BOUND becoming visible, not currency
    becoming provable -- a client that is being starved must be able to SEE that it is.

    Without compaction (rip 2/3), a node's `head` is the only currency signal it can offer; the
    max-across-f+1-fresh-answers shape stays, but it now reports the highest signed head rather
    than the highest ratified floor."""

    def setUp(self):
        self.keys = [crypto.Keypair.generate() for _ in range(4)]

    def _bundle(self, at: int = NOW, head: int = 100, n: int = 3):
        return [attest.SignedAttestation.make(kp, _claim(1, head, at=at)) for kp in self.keys[:n]]

    def _head(self, atts, need: int, now: int = NOW, window: int = WINDOW):
        return attest.attested_head(atts, need, now, window)

    def test_a_fresh_bundle_answers_the_question(self):
        got = self._head(self._bundle(), 3)
        self.assertEqual(got, 100)
        self.assertEqual(attest.staleness(self._bundle(), NOW, WINDOW), 0)

    def test_a_replayed_bundle_is_visibly_old(self):
        """The only lie an adversary without f+1 keys can tell. It cannot manufacture recent
        statements, so a starved client sees old timestamps rather than believing it is current."""
        old = self._bundle(at=NOW - WINDOW * 3)
        self.assertIsNone(self._head(old, 3))
        self.assertIsNone(attest.staleness(old, NOW, WINDOW))

    def test_staleness_is_a_number_not_an_unknown(self):
        """The client's actual gain: it can say how far behind it is at worst."""
        lagged = self._bundle(at=NOW - 45_000)
        self.assertEqual(attest.staleness(lagged, NOW, WINDOW), 45_000)
        self.assertEqual(self._head(lagged, 3), 100)

    def test_a_future_timestamp_is_discarded(self):
        """A statement dated tomorrow would still read as recent when replayed tomorrow, so it is
        refused now -- the same window logic the envelope applies to a conversation."""
        ahead = self._bundle(at=NOW + WINDOW * 2)
        self.assertIsNone(self._head(ahead, 3))

    def test_one_stale_arm_does_not_stop_the_others(self):
        """A node with a bad clock DEGRADES its own contribution and nothing else. It is dropped
        from the count, never convicted."""
        mixed = [*self._bundle(n=2), *self._bundle(at=NOW - WINDOW * 5, n=1)]
        self.assertIsNone(self._head(mixed, 3), "the stale arm still counted")
        self.assertEqual(self._head(mixed, 2), 100)

    def test_a_lagging_arm_cannot_drag_the_head_down(self):
        """Max, not majority: withholding is the only lie available, so the highest honest answer
        wins (#freshness-needs-many)."""
        behind = attest.SignedAttestation.make(self.keys[3], _claim(1, 20))
        self.assertEqual(self._head([*self._bundle(), behind], 4), 100)

    def test_a_clock_stepping_backwards_convicts_nobody(self):
        """An NTP correction is a road bump. `contradiction` never looks at time, because
        conviction is terminal and a paid-for node must not die of a clock."""
        kp = self.keys[0]
        a = attest.SignedAttestation.make(kp, _claim(1, 100, at=NOW))
        b = attest.SignedAttestation.make(kp, _claim(2, 140, at=NOW - 30_000))
        self.assertIsNone(attest.contradiction(a, b))

    def test_the_window_must_exceed_the_probe_interval(self):
        """Otherwise every gathered statement is stale by construction, since a bundle is as old as
        the last probe round, and the floor becomes permanently unanswerable."""
        t = attest.AttestTunables()
        self.assertGreater(t.fresh_within, t.probe_every)


if __name__ == "__main__":
    unittest.main()
