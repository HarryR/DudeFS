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

import socket
import sqlite3
import threading
from collections.abc import Callable

from . import codec, gossip, tunables, wire
from .acceptor import Acceptor
from .artifacts import Op, Watermark, quorum_size
from .fold import ControlReducer
from .gossip import Delta
from .handlers import control as ctl
from .node import LocalNode, dispatch
from .store import ChainStore, covered


def _gossip_request(summ: gossip.Summary) -> bytes:
    return codec.encode([b"gossip", gossip.encode_summary(summ)])


def _bytesource(data: bytes) -> Callable[[int], bytes]:
    pos = 0

    def recv(n: int) -> bytes:
        nonlocal pos
        chunk = data[pos : pos + n]
        pos += len(chunk)
        return chunk

    return recv


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
        peers: list[str] | None = None,
        clock: Callable[[], int] | None = None,
        epoch: int = 0,
        delta_ms: int = tunables.SIM_DELTA_MS,
    ):
        self.peers = peers or []  # peer node socket paths for anti-entropy
        self.store = ChainStore(store_path)
        self.acc = Acceptor(sk, pub, self.store, config_epoch=epoch, delta_ms=delta_ms)
        self.pub = pub
        self.manager_pub = manager_pub
        self._clock = clock or (lambda: 0)
        self.node = LocalNode(self.acc, self._clock)
        self.roster = roster or [pub]
        self.quorum = quorum_size(len(self.roster))
        self._lock = threading.Lock()  # serializes store access across conn threads

    # ---- request serving (socket-facing; also the in-process peer RPC) ------ #
    def serve(self, data: bytes) -> bytes:
        with self._lock:
            return self._serve(data)

    def _serve(self, data: bytes) -> bytes:
        """Serve one framed payload: a gossip exchange (I return the DELTA I owe) or
        a node RPC verb (I dispatch to the acceptor). Idempotent, local-only."""
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

    def gossip_round(self, peer_rpc: Callable[[bytes], bytes]) -> None:
        """One anti-entropy round against a peer: advertise my SUMMARY (digest
        first), apply the DELTA it owes me. Cut-aware — the peer's reply folds in
        the sparse below-cut baseline for any author whose retained digest differs.
        `peer_rpc` takes a framed request and returns the UNFRAMED reply payload."""
        payload = peer_rpc(wire.frame(_gossip_request(self.summary())))
        if not payload:
            return
        gossip.apply_delta(self.store, gossip.decode_delta(payload))

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
    def _connect_rpc(self, path: str) -> Callable[[bytes], bytes]:
        def rpc(framed: bytes) -> bytes:
            with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as s:
                s.connect(path)
                s.sendall(framed)
                return wire.read_frame(s.recv) or b""

        return rpc

    def sync_once(self, observed_watermarks: list[Watermark] | None = None) -> None:
        """One maintenance tick: anti-entropy against every reachable peer, then
        adopt any committed checkpoint, observe recovery fences, and audit for
        evidence. (A large deployment picks a uniformly random peer per tick — the
        §9 demo's handful lets us sweep all to the same fixpoint; a down peer is
        just a missed round.)"""
        for path in self.peers:
            try:
                self.gossip_round(self._connect_rpc(path))
            except OSError:
                pass
        self.adopt_committed_checkpoints()
        self.observe_fences()
        self.evidence_cycle(observed_watermarks)

    def run_periodic(self, period_s: float, stop: threading.Event) -> None:
        """The epidemic cycle on a timer until `stop` — correctness rests on the
        periodic sweep alone (PROTOCOL §2.2)."""
        while not stop.wait(period_s):
            self.sync_once()

    # ---- the socket shell (the ONLY I/O; a thin frame loop) ---------------- #
    def serve_forever(self, path: str, ready: threading.Event | None = None) -> None:
        srv = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        srv.bind(path)
        srv.listen(16)
        self._srv = srv
        if ready is not None:
            ready.set()
        while True:
            try:
                conn, _ = srv.accept()
            except OSError:
                return  # socket closed -> shutdown
            threading.Thread(target=self._handle_conn, args=(conn,), daemon=True).start()

    def _handle_conn(self, conn: socket.socket) -> None:
        with conn:
            while True:
                try:
                    payload = wire.read_frame(conn.recv)
                    if payload is None:
                        return
                    conn.sendall(wire.frame(self.serve(payload)))
                except (OSError, sqlite3.Error):
                    return  # peer vanished, or the store closed under us (node killed)

    def close(self) -> None:
        srv = getattr(self, "_srv", None)
        if srv is not None:
            srv.close()
        self.store.close()
