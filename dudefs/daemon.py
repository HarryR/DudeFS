# DudeFS — the node daemon (M7 WP1). Drivers around the sans-io kernel: a store
# (one durability domain), the acceptor verbs behind a unix socket, the real
# epidemic gossip loop, the checkpoint-adoption pipeline, recovery-fence
# observation, and the evidence duty-cycle. No NEW protocol behavior lives here —
# recognition + invocation of kernel verbs only (IMPLEMENTATION §5 / NOTES 36b).
#
# The socket/clock live ONLY in the shell (serve_forever); every behavior below is
# a pure method over the store, so the daemon is testable in-process (two daemons
# calling each other's `serve`) exactly like the sim.

from __future__ import annotations

import sqlite3
import threading
from collections.abc import Callable
from dataclasses import dataclass

from . import crypto, gossip, lmsg, transports, tunables, wire
from .acceptor import Acceptor, Rejected, RejectReason
from .artifacts import (
    Cap,
    ControlKind,
    Op,
    RosterOp,
    Watermark,
    covered,
    quorum_size,
    roster_slot_tag,
)
from .checkpoint import CheckpointView
from .fold import ControlReducer, ControlState, endpoints_of
from .gossip import Delta
from .link import Link
from .node import LocalNode, dispatch
from .store import (
    ChainStore,
    ReadTxn,
    StoreBusy,
    StoreClosed,
    StoreError,
)

LOCAL_TRANSPORT = transports.UNIX  # the POC carrier; ENDPOINT addrs are (transport, uri, opts)

# the signed 'no' says WHY (PROTOCOL §7.5): the specific door check the caller failed,
# not a generic BAD_AUTHZ — the requester already holds our identity, so it leaks nothing.
_REFUSAL_REASON = {
    lmsg.Gate.NOT_A_MEMBER: RejectReason.NOT_A_MEMBER,
    lmsg.Gate.STALE: RejectReason.STALE_ENVELOPE,
}


@dataclass(frozen=True)
class Peer:
    """A gossip peer: its identity (the L_msg `to`) and the Endpoint to reach it —
    so anti-entropy dials whatever carrier the node's ENDPOINT record names."""

    pub: bytes
    endpoint: transports.Endpoint


class NodeDaemon:
    """One storage node: an Acceptor + store, served over a socket, kept converged
    by anti-entropy, and self-auditing for evidence."""

    def __init__(
        self,
        key: crypto.Keypair,
        store_path: str = ":memory:",
        *,
        roster: list[bytes] | None = None,
        manager_pub: bytes,
        peers: list[Peer] | None = None,
        control_ops: list[Op] | None = None,
        clock: Callable[[], int] | None = None,
        epoch: int = 0,
        delta_ms: int = tunables.SIM_DELTA_MS,
        acceptor_cls: type[Acceptor] = Acceptor,
    ):
        self.peers: list[Peer] = peers or []  # anti-entropy peers (identity + Endpoint)
        # the node's sole identity — signs L_msg envelopes (PROTOCOL §7.5), backs the
        # Acceptor, and unseals sealed requests; no raw seed is held.
        self.key = key
        self._sealed = False  # inbound profile; serve_forever(sealed=True) unseals first
        self.store = ChainStore(store_path)
        self.manager_pub = manager_pub
        with self.store.write_txn() as tx:
            for op in control_ops or []:  # seed the authorization view (certs/roster)
                tx.put_op_raw(op)
        # the request gate's authz view (NOTES 58): a ControlState rebuilt from the
        # control ops we hold, refreshed each maintenance tick as certs gossip in.
        self._authz = ControlState(manager_pub, epoch)
        # `acceptor_cls` is the seam for an adversarial persona (EquivocatingAcceptor,
        # FloorPerjurer): its misbehavior then flows the PRODUCTION accept -> gossip ->
        # evidence path, so the adversary-mints-proof test runs real code, not a
        # hand-planted receipt. Defaults to the honest Acceptor.
        self.acc = acceptor_cls(
            key,
            self.store,
            config_epoch=epoch,
            delta_ms=delta_ms,
            # SUBMIT's author IS the requester: a certed writer's blind write OR a
            # compactor's blind checkpoint (R6 WP-G). Fold-positional authz still has the
            # final say on the op's KIND (a COMPACT author can only carry a checkpoint).
            authz=lambda a: (
                self._authz.is_authorized(a, Cap.WRITE) or self._authz.is_authorized(a, Cap.COMPACT)
            ),
        )
        self.pub = key.public
        self._clock = clock or (lambda: 0)
        self.node = LocalNode(self.acc, self._clock)
        self.roster = roster or [self.pub]
        self.quorum = quorum_size(len(self.roster))
        self._rebuild_authz()

    def _rebuild_authz(self) -> None:
        """Rebuild the request gate's authorization view from the control ops I hold
        (best-effort — fail-closed until a cert propagates, NOTES 59). Reference swap
        is atomic; serving threads read the latest without a lock."""
        r = ControlReducer(self.manager_pub, self.acc.epoch)
        with self.store.read_txn() as tx:
            ops = tx.all_ops()
        for op in ops:
            if op.is_control:
                r.observe(op)
        self._authz = r.control

    # ---- request serving (socket-facing; also the in-process peer RPC) ------ #
    def serve(self, data: bytes) -> bytes | None:
        """Process one inbound L_msg envelope (PROTOCOL §7.5) and return the reply
        bytes, or None to render carrier-native SILENCE. That is an Option (reply /
        no-reply) — the single bit the transport needs — not a collapse of errors: the
        specific outcome is matched here, and only a requester that PROVED it holds our
        identity (a valid sig over `to == self`) ever draws a reply, so a signed 'no'
        never leaks our pubkey to a party that didn't already have it. A vanished store
        (this node being killed mid-request) yields silence — the handler owns its own
        store error so the transport stays a dumb pipe."""
        # No daemon-wide lock: the store serializes its own access (reader/writer
        # connections + WAL, R5), so serving threads run concurrently and a request
        # never blocks behind the maintenance tick.
        try:
            # sealed endpoint: unseal FIRST (a party that can't seal to us never
            # yields an envelope -> silence, the seal IS the screen); else plain.
            reply_key: bytes | None = None
            if self._sealed:
                opened = lmsg.unseal_request(self.key, data)
                if opened is None:
                    return None  # not sealed to me / malformed -> reveal nothing
                env0, reply_key = opened
                outcome: lmsg.Inbound = lmsg.gate_envelope(
                    env0,
                    self_pub=self.pub,
                    now=self._clock(),
                    delta=self.acc.delta_ms,
                    authorized=self._peer_authorized,
                )
            else:
                outcome = lmsg.classify_inbound(
                    data,
                    self_pub=self.pub,
                    now=self._clock(),
                    delta=self.acc.delta_ms,
                    authorized=self._peer_authorized,
                )
            match outcome:
                case lmsg.Gated(env):
                    return self._reply(env, self._dispatch(env.body), reply_key)
                case lmsg.Refused(env, reason):
                    refusal = Rejected(_REFUSAL_REASON[reason])  # the signed 'no' says WHY
                    return self._reply(env, wire.encode_response(refusal), reply_key)
                case lmsg.Dropped(_reason):
                    return None  # unproven identity / malformed -> reveal nothing
        except (sqlite3.Error, StoreError):
            return None  # store closed/busy under us (node killed or contended) -> silence

    def _reply(self, env: lmsg.Envelope, body: bytes, reply_key: bytes | None) -> bytes:
        """A signed reply back to the requester (mirrors the request's verb); sealed to
        the requester's ephemeral reply-key when the inbound was sealed."""
        reply = lmsg.author(
            self.key, env.frm, env.verb, body, epoch=self.acc.epoch, ts=self._clock()
        )
        if reply_key is None:
            return reply.encode()
        return lmsg.seal_reply(reply, crypto.PublicKey(reply_key))

    def _peer_authorized(self, frm: bytes) -> bool:
        """The peer gate's policy: a current roster node (gossip / ballots), a certed
        client (writes), a certed STORE node (a LEARNER catching up read-only before it is
        promoted into the quorum — issue #2), a certed COMPACT node (a compactor syncing the
        log + blind-committing checkpoints — R6 WP-G), or the root manager (control-plane
        drive). Requester-based — a revoked client / never-member is none of these and is
        refused. Neither a learner's nor a compactor's receipts ever count toward a QC (it
        verifies against the roster, which excludes them), so admission grants participation
        in the wire, not a vote; a compactor's checkpoint still needs a real node quorum."""
        return (
            frm in self.roster
            or self._authz.is_authorized(frm, Cap.WRITE)
            or self._authz.is_authorized(frm, Cap.STORE)
            or self._authz.is_authorized(frm, Cap.COMPACT)
            or frm == self.manager_pub
        )

    def _dispatch(self, data: bytes) -> bytes:
        """Dispatch a gated inner payload: a gossip exchange (return the DELTA I owe)
        or a node RPC verb (dispatch to the acceptor). Idempotent, local-only."""
        summ = gossip.Summary.from_request(data)
        if summ is not None:
            return self._gossip_reply(summ).encode()
        return wire.encode_response(dispatch(self.node, wire.decode_request(data)))

    # ---- anti-entropy, sans-io: three pure seams a driver composes -------- #
    # A round is plan -> exchange -> apply. `summary()` plans (below), `_gossip_reply`
    # is the RESPONDER, `apply_gossip` is the APPLY — all pure store ops, no network.
    # Production wires them through the peer's carrier in `gossip_round`; a deterministic
    # test driver composes them DIRECTLY against real daemons (A.summary() ->
    # B._gossip_reply() -> A.apply_gossip()), controlling delivery order itself — the
    # I/O is the driver's, never the logic's, so no mock transport is needed.

    def _gossip_reply(self, summ: gossip.Summary) -> gossip.Delta:
        """The DELTA I owe a peer whose SUMMARY is `summ`: the ops/receipts/QCs it lacks
        plus the sparse below-cut baseline for any author whose retained digest differs
        (WP-E — it rides its OWN field, intaken contiguity-free, not the tail's append
        gate). A pure function of my store + the peer's summary."""
        with self.store.read_txn() as tx:  # the delta + baseline are ONE snapshot
            d = gossip.Delta.owed(tx, summ)
            base = tuple(self._baseline_ops_for(tx, summ))
            return Delta(d.ops, d.receipts, d.qcs, baseline=base)

    def apply_gossip(self, delta: gossip.Delta) -> None:
        """Intake a peer's DELTA into my store (one write transaction) — the APPLY seam."""
        with self.store.write_txn() as tx:
            delta.apply(tx)

    # ---- the epidemic gossip loop (WP1.2) ---------------------------------- #
    def summary(self) -> gossip.Summary:
        with self.store.read_txn() as tx:
            cut = tx.cut()
            return gossip.Summary.of(
                tx,
                self.acc.epoch,
                cut or None,
                tx.get_meta("checkpoint") or b"",
                tx.cut_dead(),
            )

    def address_book(self) -> dict[bytes, list[transports.Endpoint]]:
        """Node reachability derived from the ENDPOINT control ops I hold (PROTOCOL
        §7 / NOTES 58) — the control plane IS the peer registry."""
        with self.store.read_txn() as tx:
            ops = tx.all_ops()
        return endpoints_of(ops, self.manager_pub, self.acc.epoch)

    def refresh_peers(self) -> None:
        """Rebuild the anti-entropy peer list from the address book (every roster peer
        but my own). Each Peer keeps its dial Endpoint, so gossip reaches it over
        whatever carrier its ENDPOINT record names — a mixed mesh just works. Called
        after gossip pulls in new records; seed endpoints bootstrap the first round."""
        peers: list[Peer] = []
        for pub, addrs in self.address_book().items():
            if pub == self.pub or not addrs:
                continue
            peers.append(Peer(pub, addrs[0]))  # a node's first advertised address (no failover yet)
        if peers:  # supersede the seed/kwarg only ONCE endpoint records exist
            self.peers = peers

    def gossip_round(self, peer: Peer) -> None:
        """One anti-entropy round against `peer` OVER THE WIRE: dial my SUMMARY through
        the peer's carrier, apply the DELTA it owes. This is the production DRIVER of the
        three seams above — the SUMMARY is read in its own snapshot, the dial holds no
        transaction, the reply is applied in one write. A test driver skips this and
        composes summary()/`_gossip_reply`/`apply_gossip` directly for step control."""
        link = Link(self.key, crypto.PublicKey(peer.pub), peer.endpoint)
        match link.request(
            b"gossip", self.summary().request(), epoch=self.acc.epoch, ts=self._clock()
        ):
            case lmsg.Reply(env):
                self.apply_gossip(gossip.Delta.decode(env.body))
            case _fault:  # NoReply / MalformedReply / WrongPeer — a missed round
                pass

    def _baseline_ops_for(self, tx: ReadTxn, peer: gossip.Summary) -> list[Op]:
        """The below-cut RETAINED winners I hold for any author whose retained digest
        differs from the peer's — the sparse baseline half of a cut-aware round
        (checkpoint-certified envelopes, no receipts/QCs below the cut). Reads within
        the caller's snapshot `tx`."""
        cut = tx.cut()
        if not cut:
            return []
        dead = tx.cut_dead()
        mine = tx.baseline_commitment()
        return [
            o
            for o in tx.all_ops()
            if covered(o, cut)
            and o.op_hash not in dead
            and mine.get(o.author) != peer.retained.get(o.author)
        ]

    # ---- checkpoint adoption pipeline (WP1.3) ------------------------------ #
    def adopt_committed_checkpoints(self) -> None:
        """Adopt quorum-committed, AUTHORIZED checkpoints — advancing the cut, raising the
        horizon to F, lazily GC-ing `dead`. TWO modes (the resurrecting-far-behind ruling):

        - HOT / incremental — the next link `seq == adopted+1`: apply its incremental `dead`
          band. Checkpoints CHAIN (seq N's `dead` is the band since N-1), so a near-current
          node walks them one at a time; the while-loop chains a lagging node forward here.
        - WARM/COLD / bootstrap — a seq-DISTANT link whose signed `retained` baseline I hold
          in FULL (verify_baseline clean): adopt it DIRECTLY, jumping the sequence. Safe
          because the retained commitment is a COMPLETE baseline, not a delta — a verified
          hold means my below-cut set already IS the retained set, so the predecessor-relative
          `dead` band GC is a no-op. This is what lets a wiped / new / long-offline node catch
          up once compaction has GC'd the intermediate checkpoints; finding #10 stays covered
          — a jump only ever happens against a fully-verified baseline, never an out-of-order
          `dead` band.

        Forward-only in both modes (per-author cut dominance + monotone horizon); a node ahead
        of the quorum frontier is refused, and the root-signed recovery fence is the sole
        deliberate rewind (observe_fences). Deferred while no candidate's baseline verifies."""
        while self._adopt_one():
            pass

    def _adopt_one(self) -> bool:
        """Adopt ONE committed checkpoint I can — the HOT next link or a verified bootstrap JUMP
        (`CheckpointView.select`) — in one adopt+GC+pin write txn (finding 19); or, when none is
        adoptable, drop the over-full below-cut extras (reload-beats-reconcile) and defer. Returns
        whether a checkpoint was adopted, so `adopt_committed_checkpoints` loops it forward. All the
        WP-F decision logic is on the CheckpointView (checkpoint.py) — testable without a daemon."""
        with self.store.read_txn() as tx:
            view = CheckpointView.of(
                tx, epoch=self.acc.epoch, roster=self.roster, manager_pub=self.manager_pub
            )
        picked = view.select()
        if picked is None:
            stale = view.overfull_drop()  # reload-beats-reconcile, or [] to defer
            if stale:
                with self.store.write_txn() as tx:
                    tx.gc_checkpoint(stale)
            return False
        # adopt + GC + pin in ONE write txn (finding 19): cut/retained/dead/horizon survive
        # crash-restart together, and the GC of `dead` is never observable without the cut that
        # vouches for it.
        with self.store.write_txn() as tx:
            tx.adopt_checkpoint(picked.baseline, picked.horizon)
            tx.gc_checkpoint(sorted(picked.baseline.dead))
            tx.set_meta("checkpoint", picked.op_hash)
        return True

    # ---- recovery-fence observation (WP1.4) -------------------------------- #
    def observe_fences(self) -> None:
        """Recognize a root-signed recovery pair among gossiped control ops (a ROSTER
        op carrying a `recovery` field naming a checkpoint) and invoke the kernel's
        on_recovery_fence — WP4.7's test-driven calls become daemon behavior."""
        with self.store.read_txn() as tx:
            all_ops = tx.all_ops()
        ckpts = {o.op_hash: o for o in all_ops if o.is_control}
        for op in all_ops:
            if not isinstance(op, RosterOp):
                continue
            rec = op.recovery
            if rec is None or rec not in ckpts:
                continue
            self.acc.on_recovery_fence(op, ckpts[rec], op.from_epoch + 1, rec, self.manager_pub)

    # ---- joint-certificate activation (findings 23/24 follow-up) ----------- #
    def observe_roster_activations(self) -> None:
        """Adopt a roster change once I hold its JOINT CERTIFICATE (DESIGN §13): a
        committed ROSTER op plus BOTH halves — an old-roster QC at epoch e (the old
        configuration decided the change) AND a new-roster QC at e+1 (possession-
        gated: the new configuration holds the data and agrees). Both gate the epoch
        bump so a node never activates on a forged or half-ratified change. Ordered +
        monotone: I only advance FROM my current epoch, verifying the old half against
        the roster I hold for it, so a lagging node catches up one epoch per round
        (chained within this pass as `activate_epoch` moves me forward). Distinct from
        observe_fences — that is the ROOT-signed recovery substitute when the quorum
        is dead and there is no new-roster QC to be had."""
        while self._activate_one():
            pass

    def _activate_one(self) -> bool:
        """Activate ONE roster change I hold the JOINT CERTIFICATE for — an old-roster QC at my
        current epoch e AND a new-roster QC at e+1, both verified — advancing my epoch/roster by
        one. A slot may be CONTENDED (B4: a crash-retry re-authors the same roster slot), so an
        epoch can hold several candidates of which the old roster decided at most one; the undecided
        ones are skipped, never starving the activation. Returns whether one activated, so the loop
        chains a lagging node forward one epoch per call."""
        e = self.acc.epoch
        with self.store.read_txn() as tx:
            qcs = {(qc.op_hash, qc.config_epoch): qc for qc in tx.all_qcs()}
            all_ops = tx.all_ops()
            cands = [
                op
                for op in all_ops
                if isinstance(op, RosterOp) and op.recovery is None and op.from_epoch == e
            ]
            # authorization state at this position — the roster path's missing rigor (review
            # K-1/RC-3). The daemon (L4+) owns the control vocabulary, so the authz gate lives
            # here, not in the L3 acceptor. Built like CheckpointView.of's reducer.
            authz = ControlReducer(self.manager_pub, e)
            for op in sorted(all_ops, key=lambda o: (o.hlc.as_tuple(), o.op_hash)):
                if op.is_control:
                    authz.observe(op)
        for op in cands:
            # Mirror the checkpoint adopt predicates (minter_authorized / slot_bound): never seat
            # a roster whose author did not hold MANAGE_ROSTER at this position (K-1), that does
            # not sit on the slot its from_epoch binds (F-5 / B4), or whose members are not unique
            # (K-12b: a repeated key would fill a majority of bitmap slots and self-ratify alone).
            if not authz.control.can_author_control(op.author, ControlKind.ROSTER):
                continue  # unauthorized minter — the DESIGN §15 escalation guard
            if op.slot_tag != roster_slot_tag(op.from_epoch):
                continue  # the declared from_epoch must bind the slot actually won (B4)
            if len(set(op.roster)) != len(op.roster):
                continue  # duplicate members -> the new-half QC is satisfiable by one key
            old_qc, new_qc = qcs.get((op.op_hash, e)), qcs.get((op.op_hash, e + 1))
            if old_qc is None or new_qc is None:
                continue  # incomplete joint cert for THIS candidate
            if not old_qc.verify(self.roster) or not new_qc.verify(op.roster):
                continue  # a half that does not ratify -> not a valid activation
            self.acc.activate_epoch(e + 1)  # monotone + durable (finding 20)
            self.roster = op.roster
            self.quorum = quorum_size(len(op.roster))
            return True
        return False

    # ---- evidence duty-cycle (WP1.5) --------------------------------------- #
    def evidence_cycle(self, observed_watermarks: list[Watermark] | None = None) -> int:
        """Run every detector over held artifacts (+ observed watermarks) and persist
        any proof. Honest nodes mint nothing; a gossiped-in equivocator/perjurer is
        caught here and the proof spreads with the next round. Returns the count."""
        wms = observed_watermarks or []
        with self.store.write_txn() as tx:  # detectors read + persist any proof
            n = (
                len(tx.detect_double_votes())
                + len(tx.detect_seq_reuse(wms))
                + len(tx.detect_floor_perjury(wms))
            )
        return n

    def status(self) -> dict:
        with self.store.read_txn() as tx:
            return {
                "epoch": self.acc.epoch,
                "floor": tx.get_attested().as_tuple(),
                "ops": len(tx.all_ops()),
                "checkpoint": tx.get_meta("checkpoint") or b"",
                "evidence": len(tx.evidence()),
                "issuance_gapless": tx.issuance_gapless(),
            }

    # ---- the maintenance driver (gossip + adopt + observe + audit) --------- #
    def sync_once(self, observed_watermarks: list[Watermark] | None = None) -> None:
        """One maintenance tick: anti-entropy against every reachable peer, then
        adopt any committed checkpoint, observe recovery fences, and audit for
        evidence. (A large deployment picks a uniformly random peer per tick — the
        §9 demo's handful lets us sweep all to the same fixpoint; a down peer is
        just a missed round.)"""
        for peer in self.peers:
            self.gossip_round(peer)
        self.adopt_committed_checkpoints()
        self.observe_roster_activations()  # adopt a joint-certified roster change
        self.observe_fences()
        self.evidence_cycle(observed_watermarks)
        self.refresh_peers()  # newly-gossiped ENDPOINT records join next tick's peer set
        self._rebuild_authz()  # newly-gossiped certs/revocations take effect at the gate

    def run_periodic(self, period_s: float, stop: threading.Event) -> None:
        """The epidemic cycle on a timer until `stop` — correctness rests on the
        periodic sweep alone (PROTOCOL §2.2)."""
        while not stop.wait(period_s):
            try:
                self.sync_once()
            except StoreClosed:
                return  # store closed under us (shutting down) -> end the loop quietly
            except StoreBusy:
                continue  # another process contended the store this tick -> retry next

    # ---- the listening carrier (the transport owns the I/O; §7 seam) ------- #
    def serve_forever(
        self,
        uri: str,
        ready: threading.Event | None = None,
        *,
        scheme: bytes = LOCAL_TRANSPORT,
        sealed: bool = False,
    ) -> None:
        """Listen on a carrier (`scheme`, default the local unix socket) and serve gated
        envelopes until `close`. The transport owns the accept loop + framing; we supply
        only the pure `serve`, so the same gated wire runs over unix, HTTP, or any
        carrier the ENDPOINT names. `sealed` = this endpoint's L_msg profile: inbound is
        unsealed (and replies sealed back) instead of read plain."""
        self._sealed = sealed
        self._server = transports.open_server(scheme)
        self._server.serve(uri, self.serve, ready)

    def close(self) -> None:
        server = getattr(self, "_server", None)
        if server is not None:
            server.close()
        self.store.close()
