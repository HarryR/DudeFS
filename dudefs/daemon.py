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
    CheckpointOp,
    ControlKind,
    Op,
    RosterOp,
    Watermark,
    checkpoint_slot_tag,
    covered,
    quorum_size,
)
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
    baseline_digest,
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


def _cut_dominates(
    new: dict[bytes, tuple[int, bytes]], cur: dict[bytes, tuple[int, bytes]]
) -> bool:
    """Does `new` per-author advance-or-hold every author of `cur`? (A checkpoint's cut may
    add authors / higher seqs, but must never take one BACKWARDS — GC past a cut is
    irreversible, WP-F(a)/#4.) Vacuously true against the empty (pre-first-checkpoint) cut."""
    return all((e := new.get(a)) is not None and e[0] >= seq for a, (seq, _h) in cur.items())


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
        stale: list[bytes] = []
        while True:
            reducer = ControlReducer(self.manager_pub, self.acc.epoch)
            # collect every VALID forward candidate in ONE read snapshot, then select the mode
            with self.store.read_txn() as tx:
                all_ops = tx.all_ops()
                cur_cut = tx.cut()  # the checkpoint I've adopted (empty before the first)
                cur_horizon = tx.get_horizon()
                adopted = tx.get_meta("checkpoint")
                next_seq = 0
                if adopted is not None:  # chain from the seq I last adopted
                    cur = tx.get_op(adopted)
                    next_seq = cur.checkpoint_seq + 1 if isinstance(cur, CheckpointOp) else 0
                for op in sorted(all_ops, key=lambda o: (o.hlc.as_tuple(), o.op_hash)):
                    if op.is_control:
                        reducer.observe(op)  # authorization state up to here
                candidates: dict[int, tuple[Op, CheckpointOp]] = {}
                for op in all_ops:
                    if not isinstance(op, CheckpointOp):
                        continue
                    if op.checkpoint_seq < next_seq:
                        continue  # already adopted / superseded — only ever look forward
                    # BIND the declared seq to the slot the op actually won: without this an
                    # adversary could win slot-0 yet claim seq=5 in the body, jumping the chain.
                    # The slot decrees one-per-seq only if checkpoint_seq == the contended slot.
                    if op.slot_tag != checkpoint_slot_tag(op.checkpoint_seq):
                        continue
                    qc = tx.get_qc(op.op_hash)
                    if qc is None:  # not quorum-committed
                        continue
                    # VERIFY the QC, don't just note its presence (WP-F(b), finding #5):
                    # put_qc stores whatever is gossiped in, so a forged / sub-quorum /
                    # wrong-epoch QC would otherwise drive a GC on a lie. Mirror the roster
                    # path — a MAJORITY of THIS epoch's roster must have signed it.
                    if qc.config_epoch != self.acc.epoch or not qc.verify(self.roster):
                        continue
                    if not reducer.control.can_author_control(op.author, ControlKind.CHECKPOINT):
                        continue  # unauthorized minter — never adopt
                    # WP-D — horizon covers the cut (finding #8): the horizon is F, the
                    # finality frontier the cut was sealed at, so EVERY op the checkpoint
                    # compacts (≤ cut) must sit at/below it. A cut reaching above its horizon
                    # would seal a not-yet-final op — GC + bootstrap would then diverge from a
                    # full fold. Structural (hlc is cleartext), so a ZK node enforces it. No
                    # cut-lag margin: the horizon is exactly F, not F − W (W is vestigial —
                    # the audit is deterministic recomputation, not a timed race).
                    if any(covered(o, op.baseline.cut) and o.hlc > op.horizon for o in all_ops):
                        continue
                    # WP-F(a) / #4 — never adopt a checkpoint that would REGRESS what I hold: GC
                    # past a cut and the monotone horizon are both irreversible, so a cut that
                    # does not per-author dominate my adopted cut, or a lower horizon, is
                    # impossible by definition — refuse it. Forward-only, both modes.
                    if op.horizon.as_tuple() < cur_horizon.as_tuple() or not _cut_dominates(
                        op.baseline.cut, cur_cut
                    ):
                        continue
                    candidates.setdefault(op.checkpoint_seq, (op, op))  # the slot => one per seq
                picked = self._select_checkpoint(tx, candidates, next_seq)
                if picked is None:
                    # can't fast-path. If I'm over-full — holding MORE below-cut ops than a
                    # committed checkpoint's signed retained count — I carry stale extras a pull
                    # can never fix; drop that author's whole below-cut set and let gossip
                    # refetch exactly the winners (reload beats reconcile). Else it's a plain
                    # missing-baseline lag a later round fills: defer.
                    stale = self._overfull_below_cut(tx, candidates)
                    break
                op, ckpt = picked
            # adopt + GC + pin the active checkpoint in ONE write transaction (finding 19):
            # cut/retained/dead/horizon must survive crash-restart together, and the GC of
            # `dead` must not be observable without the cut that vouches for it.
            with self.store.write_txn() as tx:
                tx.adopt_checkpoint(ckpt.baseline, ckpt.horizon)
                tx.gc_checkpoint(sorted(ckpt.baseline.dead))
                tx.set_meta("checkpoint", op.op_hash)
            # loop: the following seq may already be committed (lagging-node catch-up).
            # adopt_checkpoint persisted the horizon (finding 19); the guards read it
            # transactionally, so there is no in-memory horizon to advance here.
        if stale:  # over-full reload: drop the stale extras; gossip refetches the winners, then
            with self.store.write_txn() as tx:  # a later round's bootstrap adopts (never-stuck)
                tx.gc_checkpoint(stale)

    def _overfull_below_cut(
        self, tx: ReadTxn, candidates: dict[int, tuple[Op, CheckpointOp]]
    ) -> list[bytes]:
        """The below-cut ops to DROP when the fast path is impossible. For the furthest
        committed checkpoint I can't verify, any author where I hold MORE retained-projection
        ops than its signed `retained` count is proof I carry stale superseded extras a PULL can
        never fix (pull only adds). Reload beats reconcile (no delta/union logic): drop that
        author's whole below-cut set and let gossip refetch exactly the retained winners — the
        manager-signed count is the below-cut authority, so this only ever drops non-winners
        plus winners that immediately return. [] = nothing over-full — a plain missing-baseline
        lag that a later gossip round fills on its own (never a destructive reload for mere lag)."""
        if not candidates:
            return []
        bl = candidates[max(candidates)][1].baseline  # the furthest target I'm trying to reach
        have = baseline_digest(tx.all_ops(), bl.cut, bl.dead)
        overfull = {a for a, e in have.items() if e.size > bl.retained.get(a, (0, b""))[0]}
        if not overfull:
            return []
        return [o.op_hash for o in tx.all_ops() if o.author in overfull and covered(o, bl.cut)]

    def _select_checkpoint(
        self,
        tx: ReadTxn,
        candidates: dict[int, tuple[Op, CheckpointOp]],
        next_seq: int,
    ) -> tuple[Op, CheckpointOp] | None:
        """Choose which committed checkpoint to adopt from the valid forward candidates: the
        HOT next link if I hold its baseline (incremental, applying its `dead` band); else the
        HIGHEST seq whose signed `retained` baseline I hold in FULL — a bootstrap JUMP over
        links GC'd while I was away. None = defer: the next link isn't here and no reachable
        baseline verifies. The verify gate is what keeps the jump safe — I only ever leap to a
        checkpoint I demonstrably already satisfy, so the skipped `dead` bands never matter."""

        def holds_baseline(c: tuple[Op, CheckpointOp]) -> bool:
            # no mismatched authors == I hold the full below-cut baseline the checkpoint pins
            return not c[1].baseline.mismatched(tx.all_ops())

        hot = candidates.get(next_seq)
        if hot is not None and holds_baseline(hot):
            return hot
        for seq in sorted(candidates, reverse=True):  # jump as far as a held baseline allows
            if seq != next_seq and holds_baseline(candidates[seq]):
                return candidates[seq]
        return None

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
        with self.store.read_txn() as tx:
            qcs = {(qc.op_hash, qc.config_epoch): qc for qc in tx.all_qcs()}
            all_ops = tx.all_ops()
        # roster-change ops grouped by the epoch they advance FROM. A slot may be
        # CONTENDED (B4: a crash-retry re-authors the same roster slot), so an epoch
        # can hold several candidate ops of which the old roster decided at most one;
        # keep them all and pick the joint-certified one below (never let an undecided
        # contender starve the activation).
        by_from: dict[int, list[tuple[Op, list[bytes]]]] = {}
        for op in all_ops:
            if not isinstance(op, RosterOp):
                continue
            if op.recovery is not None:
                continue  # the recovery path is observe_fences, not the joint cert
            by_from.setdefault(op.from_epoch, []).append((op, op.roster))
        while cands := by_from.get(self.acc.epoch):
            e = self.acc.epoch
            for op, new_roster in cands:
                old_qc, new_qc = qcs.get((op.op_hash, e)), qcs.get((op.op_hash, e + 1))
                if old_qc is None or new_qc is None:
                    continue  # incomplete joint cert for THIS candidate
                if not old_qc.verify(self.roster) or not new_qc.verify(new_roster):
                    continue  # a half that does not ratify -> not a valid activation
                self.acc.activate_epoch(e + 1)  # monotone + durable (finding 20)
                self.roster = new_roster
                self.quorum = quorum_size(len(new_roster))
                break  # advanced one epoch; the while re-reads at the new epoch
            else:
                break  # no candidate at this epoch carried a full joint cert -> done

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
