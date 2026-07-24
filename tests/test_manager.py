# WP3 — the manager LIBRARY (dudefs/manager.py), tested directly (not via the CLI).
# The delicate, protocol-specific control-plane logic lives here and is exercised as
# a library so programmatic automation and the `dude` CLI share ONE tested
# implementation (Harry's rule: no CLI-only protocol logic). The recover interlock
# DECISION is a pure function, tested across its whole matrix.

import tempfile
import unittest

from dudefs import artifacts as A
from dudefs import crypto as C
from dudefs.acceptor import Acceptor, Rejected, RejectReason
from dudefs.artifacts import quorum_size
from dudefs.handlers import control as ctl
from dudefs.manager import (
    HLC,
    Manager,
    ManagerError,
    ManagerState,
    RecoverDecision,
    RecoverReport,
    recover_decision,
)
from dudefs.node import LocalNode, dispatch
from dudefs.store import AppendStatus, ChainStore
from tests._builders import World

ZERO = HLC(0, 0)
NOW = 100
BIG = 10**9


def NOP_RPC(_pub, _req):
    return None  # roster-precondition refusals fire before any node I/O


def _nk(i):
    sk = bytes([i] * 32)
    return C.SIGNER.public(sk), sk


def _roster_cluster(node_keys, base, holders):
    """In-process acceptors keyed by pubkey + an rpc(pub, req) driving them via the
    real node dispatch — so the manager's §13 flow is exercised end to end (barrier,
    slot, joint cert) without sockets. `holders` store `base` (possession)."""
    nodes = {}
    for pub, sk in node_keys:
        acc = Acceptor(sk, pub, ChainStore(), 0, BIG)
        if pub in holders:
            with acc.store.write_txn() as tx:
                tx.append(base)
        nodes[pub] = LocalNode(acc, lambda: NOW)

    def rpc(pub, req):
        ln = nodes.get(pub)
        return dispatch(ln, req) if ln is not None else None

    return nodes, rpc


def _report(n, reachable, salvage=ZERO):
    return RecoverReport(
        n=n,
        quorum=quorum_size(n),
        reachable=sorted(reachable),
        presumed_dead=[i for i in range(n) if i not in reachable],
        salvage=salvage,
    )


def _founding(m, seed=99, addr="/n0.sock"):
    """Seat a founding voting node (init is manager-only, so tests seat their own)."""
    sk = bytes([seed] * 32)
    pub = C.SIGNER.public(sk)
    m.node_genesis(pub, C.prove_possession(sk), [addr] if addr else [])
    return pub


class TestRecoverDecisionPure(unittest.TestCase):
    # The load-bearing interlock as a pure function — the whole matrix, no sockets.
    def test_quorum_answering_always_refuses(self):
        # n=3, quorum=2: 2 or 3 answering -> REFUSE regardless of the ack flag
        for reachable in ([0, 1], [0, 1, 2]):
            for ack in (False, True):
                d = recover_decision(_report(3, reachable), ack)
                self.assertIs(d, RecoverDecision.REFUSE_QUORUM)

    def test_dead_quorum_needs_ack_then_proceeds(self):
        rep = _report(3, [0])  # only 1/3 answers -> below quorum, cluster is dead
        self.assertIs(recover_decision(rep, False), RecoverDecision.NEED_ACK)
        self.assertIs(recover_decision(rep, True), RecoverDecision.PROCEED)

    def test_none_answering_still_needs_ack(self):
        rep = _report(3, [])
        self.assertIs(recover_decision(rep, False), RecoverDecision.NEED_ACK)
        self.assertIs(recover_decision(rep, True), RecoverDecision.PROCEED)


class TestManagerOps(unittest.TestCase):
    def test_init_refuses_over_existing(self):
        with tempfile.TemporaryDirectory() as d:
            Manager.init(d)
            self.assertTrue(ManagerState.exists(d))
            with self.assertRaises(ManagerError):
                Manager.init(d)

    def test_cert_issue_authors_a_valid_write_cert(self):
        with tempfile.TemporaryDirectory() as d:
            m = Manager.init(d)
            sub = C.SIGNER.public(bytes([9] * 32))
            op = m.cert_issue("client", sub, C.prove_possession(bytes([9] * 32)))
            body = ctl.decode(op)
            assert isinstance(body, ctl.CertIssue)
            self.assertEqual(body.subject, sub)
            self.assertEqual(body.caps, [ctl.Cap.WRITE])

    def test_cert_issue_refuses_a_bad_proof_of_possession(self):
        # the manager never certifies an unheld key (NOTES 58): a pop signed by a
        # DIFFERENT key is refused, and nothing is authored for the subject.
        with tempfile.TemporaryDirectory() as d:
            m = Manager.init(d)
            sub = C.SIGNER.public(bytes([9] * 32))
            forged = C.prove_possession(bytes([8] * 32))  # possession of the WRONG key
            with self.assertRaises(ManagerError):
                m.cert_issue("client", sub, forged)
            self.assertNotIn(sub.hex(), [c["subject"] for c in m.state.certs])

    def test_mint_identity_emits_a_verifiable_pop_for_the_held_key(self):
        from dudefs.manager import mint_identity

        with tempfile.TemporaryDirectory() as d:
            pub, keyfile, pop = mint_identity(d, "node")  # keys generate where they live
            self.assertTrue(keyfile.endswith("node.key"))
            self.assertTrue(C.verify_possession(pub, pop))  # the pop matches the pubkey
            with open(keyfile, "rb") as f:
                self.assertEqual(C.SIGNER.public(f.read()), pub)  # and the local key is the sk
            # the pop the node hands over actually certifies it
            m = Manager.init(d)
            op = m.cert_issue("node", pub, pop)
            self.assertIsNotNone(ctl.decode(op))

    def test_node_authorize_wraps_nothing_client_authorize_wraps_the_full_live_set(self):
        # issue #2 gap 3: nodes are zero-knowledge (no wrap); a key-holder is back-wrapped
        # EVERY live keyepoch at authorize, so its fold (which spans all epochs) can decrypt.
        with tempfile.TemporaryDirectory() as d:
            m = Manager.init(d)
            m.rotate()  # masters {0, 1}
            npub = C.SIGNER.public(bytes([7] * 32))
            m.cert_issue("node", npub, C.prove_possession(bytes([7] * 32)))
            with m.state.store.read_txn() as tx:
                wraps = [b for o in tx.all_ops() if isinstance(b := ctl.decode(o), ctl.WrapSet)]
            self.assertFalse(any(npub in w.wraps for w in wraps))  # ZK node: no wrap

            # both key-holder kinds (client AND compactor — the compactor decrypts to compute
            # supersession) are back-wrapped every live keyepoch.
            for kind, seed in (("client", 8), ("compactor", 6)):
                sub = C.SIGNER.public(bytes([seed] * 32))
                cert = m.cert_issue(kind, sub, C.prove_possession(bytes([seed] * 32)))
                caps = ctl.decode(cert)
                assert isinstance(caps, ctl.CertIssue)
                self.assertEqual(caps.caps, m._CAP_FOR[kind])  # the right capability
                with m.state.store.read_txn() as tx:
                    wraps = [b for o in tx.all_ops() if isinstance(b := ctl.decode(o), ctl.WrapSet)]
                got = {w.keyepoch for w in wraps if sub in w.wraps}
                self.assertEqual(got, {0, 1}, kind)  # EVERY live keyepoch

    def test_revoke_stages_rotate_bumps_keyepoch_and_wraps_all_members(self):
        with tempfile.TemporaryDirectory() as d:
            m = Manager.init(d)
            _founding(m)
            sub = C.SIGNER.public(bytes([9] * 32))
            m.cert_issue("client", sub, C.prove_possession(bytes([9] * 32)))
            self.assertEqual(m.state.keyepoch, 0)
            ops = m.cert_revoke(sub)  # rotate staged by default
            self.assertEqual(len(ops), 3)  # revoke + wrap-set + rotate
            self.assertEqual(m.state.keyepoch, 1)
            self.assertIn(1, m.state.masters)
            # the revoked subject is NOT wrapped into the new epoch; the roster is
            wrap_body = ctl.decode(ops[1])
            assert isinstance(wrap_body, ctl.WrapSet)
            self.assertIn(m.state.roster[0], wrap_body.wraps)
            self.assertNotIn(sub, wrap_body.wraps)  # revoked -> excluded

    def test_no_rotate_leaves_keyepoch(self):
        with tempfile.TemporaryDirectory() as d:
            m = Manager.init(d)
            sub = C.SIGNER.public(bytes([9] * 32))
            m.cert_issue("client", sub, C.prove_possession(bytes([9] * 32)))
            ops = m.cert_revoke(sub, rotate=False)
            self.assertEqual(len(ops), 1)  # revoke only
            self.assertEqual(m.state.keyepoch, 0)

    def test_promote_refuses_even_roster(self):
        with tempfile.TemporaryDirectory() as d:
            m = Manager.init(d)
            _founding(m)  # roster = 1 (odd)
            npub = C.SIGNER.public(bytes([5] * 32))
            m.node_add(npub)
            with self.assertRaises(ManagerError):
                m.node_promote(npub, NOP_RPC)  # -> 2 voting = even (refused before I/O)
            self.assertEqual(len(m.state.roster), 1)  # unchanged

    def test_node_add_rejects_duplicate(self):
        with tempfile.TemporaryDirectory() as d:
            m = Manager.init(d)
            _founding(m)
            npub = C.SIGNER.public(bytes([5] * 32))
            m.node_add(npub)
            with self.assertRaises(ManagerError):
                m.node_add(npub)  # already a learner
            with self.assertRaises(ManagerError):
                m.node_add(m.state.roster[0])  # already a voting member

    def _control_log(self, d):
        # the control log is the manager ChainStore now; return ops in authoring order
        st = ManagerState.load(d)
        with st.store.read_txn() as tx:
            return sorted(tx.all_ops(), key=lambda o: o.seq)

    def test_node_add_with_addr_authors_an_endpoint(self):
        with tempfile.TemporaryDirectory() as d:
            m = Manager.init(d)
            npub = C.SIGNER.public(bytes([5] * 32))
            m.node_add(npub, addr="/run/node5.sock")
            body = ctl.decode(self._control_log(d)[-1])
            assert isinstance(body, ctl.EndpointRecord)
            self.assertEqual(body.subject, npub)
            self.assertEqual(body.addrs, [(b"unix", b"/run/node5.sock", {})])

    def test_node_genesis_seats_the_founding_node(self):
        from dudefs import fold, transports

        with tempfile.TemporaryDirectory() as d:
            m = Manager.init(d)
            self.assertEqual(m.state.roster, [])  # manager-only genesis
            pub = _founding(m, addr="/run/node0.sock")
            self.assertEqual(m.state.roster, [pub])  # sole voting member
            book = fold.endpoints_of(self._control_log(d), m.state.manager_pub)
            self.assertEqual(book[pub], [transports.Endpoint(b"unix", "/run/node0.sock", False)])
            with self.assertRaises(ManagerError):  # genesis-only
                _founding(m, seed=98)

    def test_cert_issue_rejects_unknown_kind(self):
        with tempfile.TemporaryDirectory() as d:
            m = Manager.init(d)
            with self.assertRaises(ManagerError):
                m.cert_issue(
                    "wizard", C.SIGNER.public(bytes([9] * 32)), C.prove_possession(bytes([9] * 32))
                )

    def test_promote_requires_a_learner(self):
        with tempfile.TemporaryDirectory() as d:
            m = Manager.init(d)
            with self.assertRaises(ManagerError):
                m.node_promote(C.SIGNER.public(bytes([7] * 32)), NOP_RPC)  # never added

    # ---- the §13 roster-change drive (findings 23/24), through the REAL manager -- #
    def _base(self, seed=1):
        w = World(seed=seed, n_clients=1)
        return w.blind(0, [], [[A.Mutation.SET, b"k", b"v"]])

    def test_change_roster_1_to_3_drives_the_joint_certificate(self):
        # the real growth path (single-promote can't leave an odd roster): 1 -> 3 as
        # ONE roster op, decided on the OLD roster (old QC) + possession-gated on the
        # NEW roster (new QC). Findings 23 (non-empty SF) + 24 (public roster slot).
        with tempfile.TemporaryDirectory() as d:
            m = Manager.init(d)
            keys = [_nk(50), _nk(51), _nk(52)]
            pubs = [k[0] for k in keys]
            m.state.roster = [pubs[0]]
            base = self._base()
            _, rpc = _roster_cluster(keys, base, holders=set(pubs))  # all caught up
            change = m.change_roster(pubs, rpc)

            self.assertEqual(change.op.slot_tag, A.roster_slot_tag(0))  # F24: on the slot
            self.assertEqual(change.old_qc.config_epoch, 0)
            self.assertEqual(change.new_qc.config_epoch, 1)
            self.assertTrue(change.new_qc.verify(pubs))  # possession-gated new QC
            self.assertEqual(m.state.roster, pubs)
            self.assertEqual(m.state.epoch, 1)
            body = ctl.decode(change.op)
            assert isinstance(body, ctl.Roster)
            self.assertTrue(body.sync_frontier)  # F23: the barrier has real teeth

    def test_change_roster_refused_when_new_node_lacks_possession(self):
        # F23 regression, via the REAL manager flow: a new-roster node that has NOT
        # caught up to the sync frontier is refused by the possession barrier, so the
        # new-roster QC can't form and the change aborts (no partial commit).
        with tempfile.TemporaryDirectory() as d:
            m = Manager.init(d)
            keys = [_nk(50), _nk(51), _nk(52)]
            pubs = [k[0] for k in keys]
            m.state.roster = [pubs[0]]
            base = self._base()
            _, rpc = _roster_cluster(keys, base, holders={pubs[0]})  # only n0 caught up
            with self.assertRaises(ManagerError):
                m.change_roster(pubs, rpc)  # n1, n2 fail the barrier -> no new quorum
            self.assertEqual(m.state.roster, [pubs[0]])  # unchanged
            self.assertEqual(m.state.epoch, 0)

    def test_roster_op_is_serialized_on_the_public_slot(self):
        # F24 (B4): the manager's roster op sits on roster_slot_tag(epoch), so a
        # crashed-and-retried double-press — a rival op at the same (tag, ballot) — is
        # refused by the old roster's equivocation guard (at most one change/epoch).
        with tempfile.TemporaryDirectory() as d:
            m = Manager.init(d)
            keys = [_nk(50), _nk(51), _nk(52)]
            pubs = [k[0] for k in keys]
            m.state.roster = [pubs[0]]
            base = self._base()
            nodes, rpc = _roster_cluster(keys, base, holders=set(pubs))
            change = m.change_roster(pubs, rpc)

            tag = A.roster_slot_tag(0)
            ballot = A.Ballot(1, A.slot_priority(tag, m.state.manager_pub))
            rival = A.Op.build(
                author_sk=bytes([99] * 32),
                author_pub=C.SIGNER.public(bytes([99] * 32)),
                cls_=A.OpClass.CONTROL,
                seq=0,
                prev=A.GENESIS_PREV,
                hlc=A.HLC(2, 0),
                deps=[],
                keyepoch=0,
                payload=ctl.roster_body(0, [pubs[0]], {}),
                slot_tag=tag,
            )
            self.assertNotEqual(rival.op_hash, change.op.op_hash)
            r = nodes[pubs[0]].accept(tag, ballot, rival)  # same slot, same ballot
            assert isinstance(r, Rejected)
            self.assertEqual(r.reason, RejectReason.EQUIVOCATION_GUARD)

    def test_node_replace_drives_joint_cert_and_refuses_non_member(self):
        with tempfile.TemporaryDirectory() as d:
            m = Manager.init(d)
            keys = [_nk(50), _nk(51), _nk(52), _nk(53)]  # n0,n1,n2 + fresh
            n0, n1, n2, fresh = (k[0] for k in keys)
            m.state.roster = [n0, n1, n2]
            base = self._base()
            _, rpc = _roster_cluster(keys, base, holders={n0, n1, n2, fresh})
            change = m.node_replace(n2, fresh, rpc)
            self.assertEqual(len(m.state.roster), 3)  # count preserved (stays odd)
            self.assertIn(fresh, m.state.roster)
            self.assertNotIn(n2, m.state.roster)
            self.assertEqual(change.op.slot_tag, A.roster_slot_tag(0))
            with self.assertRaises(ManagerError):
                m.node_replace(C.SIGNER.public(bytes([200] * 32)), fresh, NOP_RPC)  # old absent

    def test_fence_authoring_produces_the_recovery_pair(self):
        with tempfile.TemporaryDirectory() as d:
            m = Manager.init(d)
            _founding(m)
            rep = _report(1, [], salvage=A.HLC(500, 0))  # nobody answers
            ckpt, rop = m.author_recovery_fence(rep)
            cbody = ctl.decode(ckpt)
            rbody = ctl.decode(rop)
            assert isinstance(cbody, ctl.Checkpoint)
            assert isinstance(rbody, ctl.Roster)
            self.assertEqual(cbody.horizon, A.HLC(500, 0))  # salvage frontier = fiat horizon
            self.assertEqual(rbody.recovery, ckpt.op_hash)  # the pairing
            self.assertEqual(m.state.epoch, 1)

    def test_node_addr_summary_decomposes_and_survives_json_round_trip(self):
        # node_addrs is the manager's dial SUMMARY (avoids re-folding the log): it stores
        # the decomposed Endpoint, parsed once from the operator URL, and persists it.
        with tempfile.TemporaryDirectory() as d:
            m = Manager.init(d)
            npub = C.SIGNER.public(bytes([5] * 32))
            m.node_add(npub, addr="sealed+http://host:8080/dude")
            (ep,) = m.state.node_addrs[npub.hex()]  # single-homed -> one entry
            self.assertEqual(
                (ep.transport, ep.uri, ep.sealed), (b"http", "http://host:8080/dude", True)
            )
            self.assertEqual(ManagerState.load(d).node_addrs[npub.hex()], [ep])  # durable summary

    def test_endpoint_add_remove_list_round_trips_multi_home(self):
        # a node is multi-homed (PROTOCOL §7.1): add/remove read-modify-write the address
        # LIST (no longer collapsed to one), dial keeps taking the first, and it's durable.
        with tempfile.TemporaryDirectory() as d:
            m = Manager.init(d)
            npub = C.SIGNER.public(bytes([6] * 32))
            m.node_add(npub, addr="/run/n1.sock")
            m.endpoint_add(npub, "/run/n1-alt.sock")  # multi-home
            uris = [e.uri for e in m.endpoint_list(npub)]
            self.assertEqual(uris, ["/run/n1.sock", "/run/n1-alt.sock"])
            first = m.state.dial(npub.hex())
            assert first is not None
            self.assertEqual(first.uri, "/run/n1.sock")  # dial = first
            m.endpoint_add(npub, "/run/n1-alt.sock")  # re-add is a no-op replay, not a dup
            self.assertEqual(len(m.endpoint_list(npub)), 2)
            m.endpoint_remove(npub, "/run/n1.sock")  # drop the primary
            self.assertEqual([e.uri for e in m.endpoint_list(npub)], ["/run/n1-alt.sock"])
            promoted = m.state.dial(npub.hex())
            assert promoted is not None
            self.assertEqual(promoted.uri, "/run/n1-alt.sock")  # failover promotes
            m.endpoint_remove(npub)  # empty addr -> whole-record removal
            self.assertEqual(m.endpoint_list(npub), [])
            self.assertIsNone(ManagerState.load(d).dial(npub.hex()))  # durable removal

    def test_probe_roster_with_injected_prober(self):
        # probe I/O is injected -> the dwell/report logic is tested without sockets
        from dudefs import transports

        with tempfile.TemporaryDirectory() as d:
            m = Manager.init(d)
            _founding(m, addr="")  # roster = 1, endpoint set below
            # a synthetic prober answers node0's Endpoint with a floor — no sockets
            ep0 = transports.Endpoint(transports.UNIX, "/n0.sock")
            m.state.node_addrs[m.state.roster[0].hex()] = [ep0]
            answers = {ep0: A.HLC(9, 0)}
            rep = m.probe_roster(lambda _pub, e: answers.get(e), dwell=0.0, sleep=lambda _s: None)
            self.assertEqual(rep.reachable, [0])
            self.assertEqual(rep.presumed_dead, [])
            self.assertEqual(rep.salvage, A.HLC(9, 0))

    def test_state_roundtrips_through_disk(self):
        with tempfile.TemporaryDirectory() as d:
            m = Manager.init(d)
            m.cert_issue(
                "client", C.SIGNER.public(bytes([9] * 32)), C.prove_possession(bytes([9] * 32))
            )
            reloaded = ManagerState.load(d)
            self.assertEqual(reloaded.manager_pub, m.state.manager_pub)
            self.assertEqual(reloaded.mseq, m.state.mseq)
            self.assertEqual(len(reloaded.certs), 1)


class TestManagerFumbling(unittest.TestCase):
    """The fumbling-manager safety properties driven through the REAL manager module
    (NOTES 57 item 2 / the findings-23-24 lesson): a property proven only on
    hand-built ops can be bypassed by the production path, so it must ALSO be proven
    through manager.py authoring."""

    def test_retry_before_save_is_idempotent(self):
        # crash AFTER authoring but BEFORE persisting the chain head: on restart the
        # manager re-derives the IDENTICAL op (same seq/prev/hlc/payload -> same hash),
        # so a node sees a content-addressed dup, never a second logical change.
        with tempfile.TemporaryDirectory() as d:
            m = Manager.init(d)
            pre = (m.state.mseq, m.state.mprev, m.state.mhlc)
            sub = C.SIGNER.public(bytes([9] * 32))
            first = m.cert_issue("client", sub, C.prove_possession(bytes([9] * 32)))
            m.state.mseq, m.state.mprev, m.state.mhlc = pre  # amnesia: head not saved
            m.state.certs.pop()
            retry = m.cert_issue(
                "client", sub, C.prove_possession(bytes([9] * 32))
            )  # same payload at the same head
            self.assertEqual(first.op_hash, retry.op_hash)  # identical -> idempotent
            st = ChainStore()
            with st.write_txn() as tx:
                self.assertEqual(tx.append(first).status, AppendStatus.OK)
                self.assertEqual(tx.append(retry).status, AppendStatus.DUP)  # no double-apply

    def test_amnesia_reused_seq_forks_the_control_chain(self):
        # chain-head uncertainty is radioactive (MANAGER §3): a manager that forgets
        # it advanced and authors a DIFFERENT op at the same (author, seq) FORKS — a
        # node holding both mints portable evidence. The honest fresh-seq path doesn't.
        with tempfile.TemporaryDirectory() as d:
            m = Manager.init(d)
            pre = (m.state.mseq, m.state.mprev, m.state.mhlc)
            a = m.cert_issue(
                "client", C.SIGNER.public(bytes([1] * 32)), C.prove_possession(bytes([1] * 32))
            )
            m.state.mseq, m.state.mprev, m.state.mhlc = pre  # amnesia
            m.state.certs.pop()
            b = m.cert_issue(
                "client", C.SIGNER.public(bytes([2] * 32)), C.prove_possession(bytes([2] * 32))
            )  # DIFFERENT payload
            self.assertNotEqual(a.op_hash, b.op_hash)
            self.assertEqual((a.author, a.seq), (b.author, b.seq))  # collide on the chain slot
            st = ChainStore()
            with st.write_txn() as tx:
                tx.append(a)
                res = tx.append(b)
            self.assertEqual(res.status, AppendStatus.FORK)
            self.assertIsNotNone(res.evidence)  # portable FORK proof

    def test_double_press_roster_change_serializes_to_one(self):
        # a double-pressed roster change (crash-retry) contends the SAME public roster
        # slot; the old roster's single-decree machinery decides at most one (B4),
        # driven through the real change_roster authoring.
        with tempfile.TemporaryDirectory() as d:
            m = Manager.init(d)
            keys = [_nk(50), _nk(51), _nk(52)]
            pubs = [k[0] for k in keys]
            m.state.roster = [pubs[0]]
            base = World(seed=1, n_clients=1).blind(0, [], [[A.Mutation.SET, b"k", b"v"]])
            nodes, rpc = _roster_cluster(keys, base, holders=set(pubs))
            change = m.change_roster(pubs, rpc)

            tag = A.roster_slot_tag(0)
            ballot = A.Ballot(1, A.slot_priority(tag, m.state.manager_pub))
            # a competing press: a different roster op on the same slot/ballot is
            # refused by the node that already decided the first (equivocation guard)
            rival = A.Op.build(
                author_sk=bytes([99] * 32),
                author_pub=C.SIGNER.public(bytes([99] * 32)),
                cls_=A.OpClass.CONTROL,
                seq=0,
                prev=A.GENESIS_PREV,
                hlc=A.HLC(2, 0),
                deps=[],
                keyepoch=0,
                payload=ctl.roster_body(0, [pubs[0]], {}),
                slot_tag=tag,
            )
            r = nodes[pubs[0]].accept(tag, ballot, rival)
            assert isinstance(r, Rejected)
            self.assertEqual(r.reason, RejectReason.EQUIVOCATION_GUARD)
            self.assertEqual(change.op.slot_tag, tag)


if __name__ == "__main__":
    unittest.main()
