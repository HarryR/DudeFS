# WP3 — adversarial node personas (IMPLEMENTATION §6.4 / RESILIENCE §3). Each
# persona is a misbehaving sim node; the test asserts BOTH containment (honest
# state unaffected) AND evidence (the violation mints a portable proof — B6
# becomes an assertion). TEE profile (NOTES 35): node personas are the priority.

import unittest

from dudefs import artifacts as A
from dudefs import crypto as C
from dudefs import fold, gossip
from dudefs.acceptor import Acceptor
from dudefs.handlers import control as ctl
from dudefs.sim.harness import Sim
from dudefs.sim.personas import EquivocatingAcceptor, FloorPerjurer
from dudefs.store import AppendStatus, ChainStore, EvidenceKind
from tests._builders import World
from tests._cluster import creation_op

NOW = 100
BIG = 1_000_000


class TestEquivocator(unittest.TestCase):
    """WP3.1: a node that signs two ops at one (tag, ballot). Its own two receipts
    are a portable DOUBLE_VOTE proof; honest state collapses the duplicates."""

    def test_double_vote_mints_evidence_and_state_is_contained(self):
        sim = Sim(seed=1, n=3, personas={0: EquivocatingAcceptor})
        w = World(seed=1, n_clients=2)
        a = creation_op(w, 0, b"A")  # key k
        b = creation_op(w, 1, b"B")  # key k -> SAME slot as a
        assert a.slot_tag is not None
        self.assertEqual(a.slot_tag, b.slot_tag)
        tag, ballot = a.slot_tag, A.Ballot(1, b"x")

        # the equivocator signs BOTH at one ballot (an honest node would refuse b)
        ra = sim.nodes[0].accept(tag, ballot, a)
        rb = sim.nodes[0].accept(tag, ballot, b)
        self.assertIsInstance(ra, A.Receipt)
        self.assertIsInstance(rb, A.Receipt)

        # a third party (honest node 1) gossips in the equivocator's ops+receipts
        # and ASSEMBLES the proof (B6): a portable, self-verifying DOUBLE_VOTE.
        gossip.merge(sim._raw[1].acc.store, sim._raw[0].acc.store)
        proofs = sim._raw[1].acc.store.detect_double_votes()
        self.assertEqual(len(proofs), 1)
        self.assertTrue(proofs[0].verify())
        self.assertEqual(proofs[0].signer, sim.roster[0])  # attributed to the equivocator
        minted = sim._raw[1].acc.store.evidence()
        self.assertTrue(any(k == EvidenceKind.DOUBLE_VOTE for k, _ in minted))

        # detection is idempotent — re-running mints nothing new
        self.assertEqual(sim._raw[1].acc.store.detect_double_votes(), [])

        # CONTAINMENT: a single equivocator never reached a quorum for either op
        # (B1 at the quorum level never fired), and the fold collapses the double
        # vote to exactly ONE winner per slot — honest state is unaffected.
        self.assertEqual(sim.decided_ops(tag), set())
        r = fold.fold([*w.all_control(), a, b], w.keyring, w.genesis)
        self.assertIn(r.state.get(b"k"), (b"A", b"B"))  # one value, never both

    def test_two_qcs_via_equivocator_pass_relaxed_b1(self):
        # NOTES 41 (a): an equivocator CAN mint two QCs for one slot (two quorums
        # intersecting only in it). The old STRICT B1 would crash the harness on
        # this documented behavior; the relaxed rule passes it — every duplicate
        # traces to the persona, the fold yields one winner, a proof is assemblable.
        sim = Sim(seed=3, n=3, personas={0: EquivocatingAcceptor})
        w = World(seed=3, n_clients=2)
        a, b = creation_op(w, 0, b"A"), creation_op(w, 1, b"B")  # same slot
        assert a.slot_tag is not None
        tag, ballot = a.slot_tag, A.Ballot(1, b"x")
        # node 0 (persona) signs BOTH; node 1 signs a, node 2 signs b -> QCs {0,1},{0,2}
        sim.nodes[0].accept(tag, ballot, a)
        sim.nodes[0].accept(tag, ballot, b)
        sim.nodes[1].accept(tag, ballot, a)
        sim.nodes[2].accept(tag, ballot, b)  # this call reaches the 2nd QC; relaxed B1 must pass
        self.assertEqual(sim.decided_ops(tag), {a.op_hash, b.op_hash})  # two decrees, allowed
        # B6's other clauses: proof assemblable + fold still one winner
        gossip.merge(sim._raw[1].acc.store, sim._raw[0].acc.store)
        self.assertTrue(sim._raw[1].acc.store.detect_double_votes())
        r = fold.fold([*w.all_control(), a, b], w.keyring, w.genesis)
        self.assertIn(r.state.get(b"k"), (b"A", b"B"))

    def test_equivocator_alone_does_not_trip_quorum_b1(self):
        # the honest B1 continuous check (quorum-level) must NOT fire for a lone
        # equivocator: it holds only its own two receipts, never a quorum's.
        sim = Sim(seed=2, n=3, personas={1: EquivocatingAcceptor})
        w = World(seed=2, n_clients=2)
        a, b = creation_op(w, 0, b"A"), creation_op(w, 1, b"B")
        assert a.slot_tag is not None
        ballot = A.Ballot(1, b"y")
        sim.nodes[1].accept(a.slot_tag, ballot, a)
        sim.nodes[1].accept(a.slot_tag, ballot, b)  # would raise if B1 tripped
        self.assertEqual(sim.decided_ops(a.slot_tag), set())


class TestAmnesiacNode(unittest.TestCase):
    """WP3.4: a node that lost its durable store but resumes under its OLD key
    (DESIGN §13 forbids this). Forgetting it already voted, it double-votes; the
    portable proof enables identity retirement (revoke + fresh learner)."""

    def test_amnesia_double_votes_and_is_retirable(self):
        w = World(seed=40, n_clients=2)
        a, b = creation_op(w, 0, b"A"), creation_op(w, 1, b"B")  # same slot
        assert a.slot_tag is not None
        tag, ballot = a.slot_tag, A.Ballot(1, b"x")
        nsk = bytes([240] * 32)
        npub = C.SIGNER.public(nsk)

        acc1 = Acceptor(nsk, npub, ChainStore(), config_epoch=0, delta_ms=BIG)  # life 1
        ra = acc1.on_accept(tag, ballot, a, NOW)
        acc2 = Acceptor(nsk, npub, ChainStore(), config_epoch=0, delta_ms=BIG)  # WIPED, same key
        rb = acc2.on_accept(tag, ballot, b, NOW)  # forgot A -> votes B at the same ballot
        self.assertIsInstance(ra, A.Receipt)
        self.assertIsInstance(rb, A.Receipt)

        # a party assembles the double vote from the two lives' receipts + ops
        store = ChainStore()
        store.put_op_raw(a)
        store.put_op_raw(b)
        assert isinstance(ra, A.Receipt) and isinstance(rb, A.Receipt)
        store.put_receipt(ra)
        store.put_receipt(rb)
        proofs = store.detect_double_votes()
        self.assertEqual(len(proofs), 1)
        self.assertTrue(proofs[0].verify())
        self.assertEqual(proofs[0].signer, npub)  # retirement targets this identity


class TestWithholder(unittest.TestCase):
    """WP3.3: a node that WITHHOLDS a committed op cannot cause unsafety —
    staleness is never divergence; one honest contact heals the victim."""

    def test_withheld_op_heals_via_one_honest_contact(self):
        sim = Sim(seed=42, n=3)
        w = World(seed=42, n_clients=1)
        op = creation_op(w, 0, b"v")
        # nodes 1,2 hold the committed op; node 0 is eclipsed (withheld from it)
        sim._raw[1].acc.store.append(op)
        sim._raw[2].acc.store.append(op)
        self.assertIsNone(sim._raw[0].acc.store.get_op(op.op_hash))  # victim lacks it
        # a single honest contact (anti-entropy from node 1) heals the victim
        gossip.merge(sim._raw[0].acc.store, sim._raw[1].acc.store)
        self.assertIsNotNone(sim._raw[0].acc.store.get_op(op.op_hash))


class TestSplitView(unittest.TestCase):
    """WP3.6 (RESILIENCE §3.5, now provable): a root serves two divergent chains
    from one genesis. Each victim holds one side; when they compare, the fork mints
    at the divergence seq — upgrading the detection claim from paper to test."""

    def test_two_victims_detect_the_fork_at_the_divergence_seq(self):
        w = World(seed=30, n_clients=0)
        pubx = C.SIGNER.public(bytes([1] * 32))
        puby = C.SIGNER.public(bytes([2] * 32))
        a = w._mgr_op(ctl.roster_body(0, [pubx], {}))  # chain A, manager seq 0
        w._mseq, w._mprev = 0, A.GENESIS_PREV  # the root rewinds -> a divergent view
        b = w._mgr_op(ctl.roster_body(0, [puby], {}))  # chain B, manager seq 0 (a fork)
        self.assertNotEqual(a.op_hash, b.op_hash)

        v1, v2 = ChainStore(), ChainStore()  # two victims, one side each
        v1.append(a)
        v2.append(b)
        self.assertEqual(v1.evidence(), [])  # neither alone sees a fork
        self.assertEqual(v2.evidence(), [])

        # the victims compare (§3.5). Gossip's seq-range delta cannot ship a
        # SAME-seq sibling, so the comparison pulls the peer's head by hash — that
        # is the split-view detector: appending it reveals the fork at seq 0.
        peer_head = v2.heads()[w.mgr_pub][1]  # b's op_hash
        peer_op = v2.get_op(peer_head)
        assert peer_op is not None
        res = v1.append(peer_op)
        self.assertEqual(res.status, AppendStatus.FORK)
        assert res.evidence is not None
        self.assertEqual(res.evidence.seq, 0)  # the divergence seq
        self.assertTrue(res.evidence.verify())
        self.assertTrue(any(k == EvidenceKind.FORK for k, _ in v1.evidence()))


class TestFloorPerjurer(unittest.TestCase):
    """WP3.2: a node that attests a finality floor, then receipts an op beneath it.
    Its watermark + that receipt are a portable FLOOR_PERJURY proof; honest finality
    (which never finalizes below its own floor) is unaffected."""

    def test_floor_perjury_mints_evidence_honest_rejects(self):
        sim = Sim(seed=1, n=3, delta=10, personas={0: FloorPerjurer})
        w = World(seed=1, n_clients=1)
        op = creation_op(w, 0, b"v")  # small hlc
        assert op.slot_tag is not None
        perjurer = sim._raw[0].acc

        wm = perjurer.issue_watermark(1000)  # attests floor ~990
        self.assertGreater(wm.floor.wall_ms, op.hlc.wall_ms)  # op is beneath the sworn floor

        # the perjurer receipts the below-floor op; an HONEST node rejects it (B3).
        rc = perjurer.on_accept(op.slot_tag, A.Ballot(1, b"x"), op, 1000)
        self.assertIsInstance(rc, A.Receipt)
        honest = sim._raw[1].acc
        honest.issue_watermark(1000)
        hr = honest.on_accept(op.slot_tag, A.Ballot(1, b"y"), op, 1000)
        self.assertNotIsInstance(hr, A.Receipt)  # BELOW_FLOOR

        # a third party assembles the proof (B6) from the watermark + receipt + op
        store = sim._raw[2].acc.store
        store.put_op_raw(op)
        assert isinstance(rc, A.Receipt)
        store.put_receipt(rc)
        proofs = store.detect_floor_perjury([wm])
        self.assertEqual(len(proofs), 1)
        self.assertTrue(proofs[0].verify())
        self.assertEqual(proofs[0].signer, sim.roster[0])
        self.assertTrue(any(k == EvidenceKind.FLOOR_PERJURY for k, _ in store.evidence()))
        self.assertEqual(store.detect_floor_perjury([wm]), [])  # idempotent

    def test_honest_below_floor_receipt_is_not_perjury(self):
        # THE finding-17 regression: an honest node legally receipts op X while its
        # floor is low (issue_seq s1), the floor later rises, and it attests F >
        # X.hlc (issue_seq s2 > s1). The naive pair "proves" perjury; the ORDERED
        # pair does not — the receipt was issued BEFORE the attestation. FAILS
        # against the pre-fix detector (which had no seq check).
        sim = Sim(seed=2, n=3, delta=10_000)  # all honest
        w = World(seed=2, n_clients=1)
        op = creation_op(w, 0, b"v")
        assert op.slot_tag is not None
        honest = sim._raw[0].acc
        rc = honest.on_accept(op.slot_tag, A.Ballot(1, b"x"), op, 100)  # floor(100) < 0 -> legal
        assert isinstance(rc, A.Receipt)
        wm = honest.issue_watermark(1_000_000)  # floor rises far above op.hlc; a LATER seq
        self.assertGreater(wm.floor.wall_ms, op.hlc.wall_ms)  # op below the (later) floor
        self.assertLess(rc.issue_seq, wm.issue_seq)  # ...but receipted BEFORE attesting

        store = sim._raw[1].acc.store
        store.put_op_raw(op)
        store.put_receipt(rc)
        self.assertEqual(store.detect_floor_perjury([wm]), [])  # NOT convicted
        self.assertEqual(store.evidence(), [])

    def test_reissue_preserves_issue_seq(self):
        # serve-from-store: a resubmitted ACCEPT returns the identical receipt, and a
        # RERECEIPT under e+1 reuses the ACCEPTANCE seq — re-signing fresh would frame
        # the node, so seq stability is load-bearing (not just idempotent bytes).
        sim = Sim(seed=3, n=3, delta=10_000)
        w = World(seed=3, n_clients=1)
        op = creation_op(w, 0, b"v")
        assert op.slot_tag is not None
        acc = sim._raw[0].acc
        r1 = acc.on_accept(op.slot_tag, A.Ballot(1, b"x"), op, 100)
        r2 = acc.on_accept(op.slot_tag, A.Ballot(1, b"x"), op, 100)  # resubmission
        assert isinstance(r1, A.Receipt) and isinstance(r2, A.Receipt)
        self.assertEqual(
            (r1.issue_seq, r1.config_epoch, r1.sig), (r2.issue_seq, r2.config_epoch, r2.sig)
        )

        acc.activate_epoch(1)
        rr = acc.on_rereceipt(op.slot_tag)  # RERECEIPT under e+1
        assert isinstance(rr, A.Receipt)
        self.assertEqual(rr.config_epoch, 1)  # a new epoch...
        self.assertEqual(rr.issue_seq, r1.issue_seq)  # ...but the ORIGINAL acceptance seq


class TestSeqReuse(unittest.TestCase):
    """WP finding-17: reusing one issuance-chain position for two different ops is
    the FORK-analog of the issuance chain — it mints SEQ_REUSE."""

    def test_seq_reuse_mints_evidence(self):
        w = World(seed=4, n_clients=2)
        a, b = creation_op(w, 0, b"A"), creation_op(w, 1, b"B")
        nsk = bytes([250] * 32)
        npub = C.SIGNER.public(nsk)
        ballot = A.Ballot(1, b"x")
        ra = A.Receipt.issue(nsk, npub, a.op_hash, 0, ballot, 5)  # issue_seq 5
        rb = A.Receipt.issue(nsk, npub, b.op_hash, 0, ballot, 5)  # 5 REUSED, different op
        store = ChainStore()
        store.put_receipt(ra)
        store.put_receipt(rb)
        proofs = store.detect_seq_reuse()
        self.assertEqual(len(proofs), 1)
        self.assertTrue(proofs[0].verify())
        self.assertEqual(proofs[0].signer, npub)
        self.assertTrue(any(k == EvidenceKind.SEQ_REUSE for k, _ in store.evidence()))
        self.assertEqual(store.detect_seq_reuse(), [])  # idempotent

    def test_legitimate_cross_epoch_reissue_is_not_reuse(self):
        # the same op at one issue_seq across two epochs (a RERECEIPT) is NOT reuse.
        w = World(seed=5, n_clients=1)
        a = creation_op(w, 0, b"A")
        nsk = bytes([251] * 32)
        npub = C.SIGNER.public(nsk)
        ballot = A.Ballot(1, b"x")
        r_e0 = A.Receipt.issue(nsk, npub, a.op_hash, 0, ballot, 7)
        r_e1 = A.Receipt.issue(nsk, npub, a.op_hash, 1, ballot, 7)  # same op, e+1, same seq
        store = ChainStore()
        store.put_receipt(r_e0)
        store.put_receipt(r_e1)
        self.assertEqual(store.detect_seq_reuse(), [])  # same op -> legitimate


if __name__ == "__main__":
    unittest.main()
