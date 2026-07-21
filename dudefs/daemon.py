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

from . import codec, gossip, lmsg, transports, tunables, wire
from .acceptor import Acceptor, Rejected, RejectReason
from .artifacts import Op, Watermark, quorum_size
from .fold import ControlReducer, ControlState, endpoints_of
from .gossip import Delta
from .handlers import control as ctl
from .link import Link
from .node import LocalNode, dispatch
from .store import ChainStore, covered

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


def _gossip_request(summ: gossip.Summary) -> bytes:
    return codec.encode([b"gossip", gossip.encode_summary(summ)])


class NodeDaemon:
    """One storage node: an Acceptor + store, served over a socket, kept converged
    by anti-entropy, and self-auditing for evidence."""

    def __init__(
        self,
        sk: bytes,
        pub: bytes,
        store_path: str = ":memory:",
        *,
        roster: list[bytes] | None = None,
        manager_pub: bytes,
        peers: list[Peer] | None = None,
        control_ops: list[Op] | None = None,
        clock: Callable[[], int] | None = None,
        epoch: int = 0,
        delta_ms: int = tunables.SIM_DELTA_MS,
    ):
        self.peers: list[Peer] = peers or []  # anti-entropy peers (identity + Endpoint)
        self.sk = sk  # the node's identity key — signs L_msg envelopes (PROTOCOL §7.5)
        self.store = ChainStore(store_path)
        self.manager_pub = manager_pub
        for op in control_ops or []:  # seed the authorization view (certs/roster)
            self.store.put_op_raw(op)
        # the request gate's authz view (NOTES 58): a ControlState rebuilt from the
        # control ops we hold, refreshed each maintenance tick as certs gossip in.
        self._authz = ControlState(manager_pub, epoch)
        self.acc = Acceptor(
            sk,
            pub,
            self.store,
            config_epoch=epoch,
            delta_ms=delta_ms,
            authz=lambda a: self._authz.is_authorized(a, ctl.Cap.WRITE),
        )
        self.pub = pub
        self._clock = clock or (lambda: 0)
        self.node = LocalNode(self.acc, self._clock)
        self.roster = roster or [pub]
        self.quorum = quorum_size(len(self.roster))
        self._lock = threading.Lock()  # serializes store access across conn threads
        self._rebuild_authz()

    def _rebuild_authz(self) -> None:
        """Rebuild the request gate's authorization view from the control ops I hold
        (best-effort — fail-closed until a cert propagates, NOTES 59). Reference swap
        is atomic; serving threads read the latest without a lock."""
        r = ControlReducer(self.manager_pub, self.acc.epoch)
        for op in self.store.all_ops():
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
        with self._lock:
            try:
                match lmsg.classify_inbound(
                    data,
                    self_pub=self.pub,
                    now=self._clock(),
                    delta=self.acc.delta_ms,
                    authorized=self._peer_authorized,
                ):
                    case lmsg.Gated(env):
                        return self._reply(env, self._dispatch(env.body))  # gate passed
                    case lmsg.Refused(env, reason):
                        refusal = Rejected(_REFUSAL_REASON[reason])  # the signed 'no' says WHY
                        return self._reply(env, wire.encode_response(refusal))
                    case lmsg.Dropped(_reason):
                        return None  # unproven identity / malformed -> reveal nothing
            except sqlite3.Error:
                return None  # store closed under us (node killed) -> carrier silence

    def _reply(self, env: lmsg.Envelope, body: bytes) -> bytes:
        """Seal a signed reply back to the requester (mirrors the request's verb)."""
        return lmsg.author(
            self.sk, env.frm, env.verb, body, epoch=self.acc.epoch, ts=self._clock()
        ).encode()

    def _peer_authorized(self, frm: bytes) -> bool:
        """The peer gate's policy: a current roster node (gossip / ballots), a certed
        client (writes), or the root manager (control-plane drive). Requester-based —
        a revoked client / never-member is none of these and is refused."""
        return (
            frm in self.roster
            or self._authz.is_authorized(frm, ctl.Cap.WRITE)
            or frm == self.manager_pub
        )

    def _dispatch(self, data: bytes) -> bytes:
        """Dispatch a gated inner payload: a gossip exchange (return the DELTA I owe)
        or a node RPC verb (dispatch to the acceptor). Idempotent, local-only."""
        first = codec.as_seq(codec.decode(data))[0]
        if codec.as_bytes(first) == b"gossip":
            summ = gossip.decode_summary(codec.as_bytes(codec.as_seq(codec.decode(data))[1]))
            d = gossip.delta(self.store, summ)
            d = Delta((*d.ops, *self._baseline_ops_for(summ)), d.receipts, d.qcs)
            return gossip.encode_delta(d)
        return wire.encode_response(dispatch(self.node, wire.decode_request(data)))

    # ---- the epidemic gossip loop (WP1.2) ---------------------------------- #
    def summary(self) -> gossip.Summary:
        cut = self.store.cut()
        return gossip.summary(
            self.store,
            self.acc.epoch,
            cut or None,
            self.store.get_meta("checkpoint") or b"",
            self.store.cut_dead(),
        )

    def address_book(self) -> dict[bytes, list[tuple[bytes, bytes, dict[bytes, bytes]]]]:
        """Node reachability derived from the ENDPOINT control ops I hold (PROTOCOL
        §7 / NOTES 58) — the control plane IS the peer registry."""
        return endpoints_of(self.store.all_ops(), self.manager_pub, self.acc.epoch)

    def refresh_peers(self) -> None:
        """Rebuild the anti-entropy peer list from the address book (every roster peer
        but my own). Each Peer keeps its dial Endpoint, so gossip reaches it over
        whatever carrier its ENDPOINT record names — a mixed mesh just works. Called
        after gossip pulls in new records; seed endpoints bootstrap the first round."""
        peers: list[Peer] = []
        for pub, addrs in self.address_book().items():
            if pub == self.pub or not addrs:
                continue
            t, u, o = addrs[0]  # a node's first advertised address (POC: no failover yet)
            peers.append(Peer(pub, transports.Endpoint.from_record(t, u, o)))
        if peers:  # supersede the seed/kwarg only ONCE endpoint records exist
            self.peers = peers

    def gossip_round(self, peer: Peer) -> None:
        """One anti-entropy round against `peer`: advertise my SUMMARY (digest first)
        over a Link (L_msg envelope + the peer's carrier), apply the DELTA it owes me.
        Cut-aware — the peer's reply folds in the sparse below-cut baseline for any
        author whose retained digest differs."""
        link = Link(self.sk, self.pub, peer.pub, peer.endpoint)
        match link.request(
            b"gossip", _gossip_request(self.summary()), epoch=self.acc.epoch, ts=self._clock()
        ):
            case lmsg.Reply(env):
                gossip.apply_delta(self.store, gossip.decode_delta(env.body))
            case _fault:  # NoReply / MalformedReply / WrongPeer — a missed round
                pass

    def _baseline_ops_for(self, peer: gossip.Summary) -> list[Op]:
        """The below-cut RETAINED winners I hold for any author whose retained digest
        differs from the peer's — the sparse baseline half of a cut-aware round
        (checkpoint-certified envelopes, no receipts/QCs below the cut)."""
        cut = self.store.cut()
        if not cut:
            return []
        dead = self.store.cut_dead()
        mine = self.store.baseline_commitment()
        return [
            o
            for o in self.store.all_ops()
            if covered(o, cut)
            and o.op_hash not in dead
            and mine.get(o.author) != peer.retained.get(o.author)
        ]

    # ---- checkpoint adoption pipeline (WP1.3) ------------------------------ #
    def adopt_committed_checkpoints(self) -> None:
        """On holding a quorum-committed, AUTHORIZED checkpoint whose retained
        digests my baseline satisfies: adopt the cut, advance the horizon to its F,
        and lazily GC. Skipped until I hold the full below-cut baseline (verify_
        baseline non-empty means gaps — defer, a later gossip round fills them)."""
        reducer = ControlReducer(self.manager_pub, self.acc.epoch)
        for op in sorted(self.store.all_ops(), key=lambda o: (o.hlc.as_tuple(), o.op_hash)):
            if op.is_control:
                reducer.observe(op)  # authorization state up to here
        best = None
        for op in self.store.all_ops():
            body = ctl.decode(op) if op.is_control else None
            if body is None or body[ctl.BK_KIND] != ctl.ControlKind.CHECKPOINT:
                continue
            if self.store.get_qc(op.op_hash) is None:  # not quorum-committed
                continue
            if not reducer.control.can_author_control(op.author, ctl.ControlKind.CHECKPOINT):
                continue  # unauthorized minter — never adopt
            if best is None or op.hlc > best[0].hlc:
                best = (op, body)
        if best is None:
            return
        op, body = best
        if self.store.get_meta("checkpoint") == op.op_hash:
            return  # already adopted this one
        # only adopt once my below-cut baseline satisfies the signed retained digests
        # — projected over the CHECKPOINT's dead (not the store's still-empty one).
        if gossip.verify_baseline(
            self.store, body[b"cut"], body[b"retained"], frozenset(body[b"dead"])
        ):
            return  # missing baseline — defer to a later round
        # persist cut + retained + dead + horizon in ONE atomic COMMIT (finding 19):
        # the horizon must survive crash-restart alongside the cut, else the void
        # rule + backstop go inert on the reborn op after a restart.
        self.store.adopt_checkpoint(
            body[b"cut"], body[b"retained"], body[b"dead"], body[b"horizon"]
        )
        self.acc.advance_horizon(body[b"horizon"])
        self.store.gc_checkpoint(body[b"dead"])
        self.store.set_meta("checkpoint", op.op_hash)

    # ---- recovery-fence observation (WP1.4) -------------------------------- #
    def observe_fences(self) -> None:
        """Recognize a root-signed recovery pair among gossiped control ops (a ROSTER
        op carrying a `recovery` field naming a checkpoint) and invoke the kernel's
        on_recovery_fence — WP4.7's test-driven calls become daemon behavior."""
        ckpts = {o.op_hash: o for o in self.store.all_ops() if o.is_control}
        for op in self.store.all_ops():
            body = ctl.decode(op) if op.is_control else None
            if body is None or body[ctl.BK_KIND] != ctl.ControlKind.ROSTER:
                continue
            rec = body.get(b"recovery")
            if rec is None or rec not in ckpts:
                continue
            self.acc.on_recovery_fence(
                op, ckpts[rec], body[b"from_epoch"] + 1, rec, self.manager_pub
            )

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
        qcs = {(qc.op_hash, qc.config_epoch): qc for qc in self.store.all_qcs()}
        # roster-change ops grouped by the epoch they advance FROM. A slot may be
        # CONTENDED (B4: a crash-retry re-authors the same roster slot), so an epoch
        # can hold several candidate ops of which the old roster decided at most one;
        # keep them all and pick the joint-certified one below (never let an undecided
        # contender starve the activation).
        by_from: dict[int, list[tuple[Op, list[bytes]]]] = {}
        for op in self.store.all_ops():
            body = ctl.decode(op) if op.is_control else None
            if body is None or body[ctl.BK_KIND] != ctl.ControlKind.ROSTER:
                continue
            if body.get(b"recovery") is not None:
                continue  # the recovery path is observe_fences, not the joint cert
            by_from.setdefault(body[b"from_epoch"], []).append((op, body[b"roster"]))
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
        n = 0
        n += len(self.store.detect_double_votes())
        n += len(self.store.detect_seq_reuse(wms))
        n += len(self.store.detect_floor_perjury(wms))
        return n

    def status(self) -> dict:
        return {
            "epoch": self.acc.epoch,
            "floor": self.store.get_attested().as_tuple(),
            "ops": len(self.store.all_ops()),
            "checkpoint": self.store.get_meta("checkpoint") or b"",
            "evidence": len(self.store.evidence()),
            "issuance_gapless": self.store.issuance_gapless(),
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
            self.sync_once()

    # ---- the listening carrier (the transport owns the I/O; §7 seam) ------- #
    def serve_forever(
        self, uri: str, ready: threading.Event | None = None, *, scheme: bytes = LOCAL_TRANSPORT
    ) -> None:
        """Listen on a carrier (`scheme`, default the local unix socket) and serve gated
        envelopes until `close`. The transport owns the accept loop + framing; we supply
        only the pure `serve`, so the same gated wire runs over unix, HTTP, or any
        carrier the ENDPOINT names."""
        self._server = transports.open_server(scheme)
        self._server.serve(uri, self.serve, ready)

    def close(self) -> None:
        server = getattr(self, "_server", None)
        if server is not None:
            server.close()
        self.store.close()
