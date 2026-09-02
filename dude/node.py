import contextlib
import threading
import time

from .consensus import Coordinator, Mempool, RoundAdapter, SettleAdapter
from .consensus.canonical import bodies_canonical
from .consensus.settle_round import SettledBlock
from .core import codec, crypto
from .core.errors import DudeError
from .core.units import Millis
from .net import MessageId, Verb
from .net.link import Acceptor, Dialer
from .net.postman import Delivered, Postman
from .net.socket_server import SocketServer
from .session import Inflight, KeyCache, SessionRW, SubmitHandle, SubmitResult, Substrate
from .store import Store, ops
from .store.layer import BlockHead, Held
from .store.management import MgmtReader, Role
from .sync.adapter import (
    GetBlocks,
    Refused,
    SyncAdapterError,
    SyncMsg,
    SyncRefusal,
)
from .sync.checkpoint_adapter import (
    CheckpointAdapterError,
    ChunksReply,
    GetCheckpoint,
    GetChunks,
)
from .sync.checkpoint_server import CheckpointServer
from .sync.follower import Follower, serve_getblocks, serve_height
from .sync.lite import serve_get_anchors, serve_get_proof
from .sync.lite_adapter import (
    GetAnchors,
    GetProof,
    LiteAdapterError,
    LiteMsg,
    LiteRefused,
    TxStatus,
    TxStatusKind,
    TxStatusReply,
)
from .tunables import DEFAULT, Tunables

# ---------------------------------------------------------------------------
# Base — the run loop, lifecycle, peer reconciliation, follower, sync handlers.
# ---------------------------------------------------------------------------


class _BaseNode:
    def __init__(self, me: crypto.Keypair, store: Store, tunables: Tunables = DEFAULT) -> None:
        self.me = me
        self.store = store
        self.tunables = tunables
        self.postman = Postman(me, tunables)
        self.follower = Follower(
            me=me, store=store, mgmt_reader=store.mgmt_reader, tunables=tunables
        )
        self.inflight = Inflight()
        self.commit_seq = 0
        self.commit_cond = threading.Condition()
        self._stopping = threading.Event()
        self._thread: threading.Thread | None = None
        self._socket_servers: list[SocketServer] = []

    @property
    def mgmt_reader(self) -> MgmtReader:
        return self.store.mgmt_reader

    def roster(self) -> tuple[crypto.PublicKey, ...]:
        return self.store.mgmt_reader.roster()

    # -- lifecycle ----------------------------------------------------------

    def add_acceptor(self, acceptor: Acceptor) -> None:
        self.postman.add_acceptor(acceptor)

    def add_dialer(self, dialer: Dialer) -> None:
        self.postman.add_dialer(dialer)

    def add_socket(self, path: str) -> None:
        sub = _ReplicaSubstrate(self)
        srv = SocketServer(path, sub)
        self._socket_servers.append(srv)

    def __enter__(self):
        self.start()
        return self

    def __exit__(self, *_: object) -> None:
        self.stop()

    def start(self) -> None:
        if self._thread is not None:
            return
        self._stopping = threading.Event()
        self._reconcile_peers()
        self.postman.start()
        for srv in self._socket_servers:
            srv.start()
        prefix = "replica" if isinstance(self, ReplicaNode) else "node"
        self._thread = threading.Thread(
            target=self._run,
            name=f"{prefix}-{self.me.public.hex()[:8]}",
            daemon=True,
        )
        self._thread.start()

    def stop(self) -> None:
        thread = self._thread
        if thread is None:
            return
        self._thread = None
        self._stopping.set()
        for srv in self._socket_servers:
            srv.stop()
        self.postman.stop()
        thread.join()
        self.store.close()

    def _run(self) -> None:
        tick_interval = self.tunables.tick_interval.as_seconds
        while not self._stopping.is_set():
            now = Millis.now()
            for output in self.postman.drain_output(timeout=tick_interval):
                for d in output.delivered:
                    self._on_delivered(d, now)
            with contextlib.suppress(DudeError):
                self._tick(now)

    def _tick(self, now: Millis) -> None:
        self._reconcile_peers()
        checkpoint_block = self.follower.needs_checkpoint()
        if checkpoint_block is not None:
            self._download_checkpoint()
            return
        self.follower.tick(now)
        self._flush_follower(now)

    def _on_delivered(self, d: Delivered, now: Millis) -> None:
        raise NotImplementedError

    # -- checkpoint download (synchronous, blocks the tick loop) ------------

    def _send_and_wait(
        self,
        peer: crypto.PublicKey,
        verb: Verb,
        body: bytes,
        timeout_sec: float,
    ) -> Delivered | None:
        mid = self.postman.send_raw(peer, verb, body, self.tunables.ttl_exchange)
        tick = self.tunables.tick_interval.as_seconds
        deadline = time.monotonic() + timeout_sec
        while time.monotonic() < deadline and not self._stopping.is_set():
            remaining = min(tick, deadline - time.monotonic())
            if remaining <= 0:
                break
            for output in self.postman.drain_output(timeout=remaining):
                for d in output.delivered:
                    if (
                        d.in_reply_to is not None
                        and d.in_reply_to.correlation_id == mid.correlation_id
                    ):
                        return d
                    self._on_delivered(d, Millis.now())
        return None

    def _download_checkpoint(self) -> None:
        from .store.checkpoint import CheckpointMeta
        from .store.smt_sync import TreeImporter

        peers = list(self.follower.compacted_peers())
        if not peers:
            return
        timeout = self.tunables.ttl_exchange.as_seconds
        get_cp_verb, get_cp_body = GetCheckpoint().encode()

        for peer in peers:
            if self._stopping.is_set():
                return
            d = self._send_and_wait(peer, get_cp_verb, get_cp_body, timeout)
            if d is None or d.verb != Verb.CHECKPOINT_META or not d.body:
                continue

            meta_bytes = d.body
            meta = CheckpointMeta.decode(meta_bytes)
            if meta.verify_compactor(self.store.anchor()) is not None:
                continue

            checkpoint_id = crypto.h(meta_bytes)
            chunks: list = []
            offset = 0
            ok = True
            while not self._stopping.is_set():
                req_verb, req_body = GetChunks(checkpoint_id=checkpoint_id, offset=offset).encode()
                d = self._send_and_wait(peer, req_verb, req_body, timeout)
                if d is None or d.verb != Verb.CHUNKS_REPLY:
                    ok = False
                    break
                reply = ChunksReply.decode(d.body)
                chunks.extend(reply.chunks)
                if not reply.more:
                    break
                offset += len(reply.chunks)

            if not ok or self._stopping.is_set():
                continue

            with self.store.write() as w:
                w.reset_for_checkpoint()
                importer = TreeImporter(w, expected_root=meta.state_root)
                for chunk in chunks:
                    importer.load(chunk)
                importer.verify()
                w.bootstrap_checkpoint(meta.anchor, meta.settled_block_bytes)

            roster = tuple(sorted(self.store.mgmt_reader.roster()))
            if meta.verify_quorum(roster) is not None:
                continue

            self.follower.clear_compacted()
            return

    # -- peer reconciliation ------------------------------------------------

    def _reconcile_peers(self) -> None:
        nodes = self.mgmt_reader.nodes()
        roster = self.mgmt_reader.roster()
        now = Millis.now()
        peers: dict[crypto.PublicKey, tuple] = {}
        for pk in roster:
            if pk == self.me.public:
                continue
            rec = nodes.get(pk)
            if rec is not None and rec.endpoints:
                peers[pk] = rec.endpoints
            self.follower.add_peer(pk, now)
        self.postman.sync(peers, authorized=self.mgmt_reader.authorized_identities())

    # -- shared helpers -----------------------------------------------------

    def _reply(self, d: Delivered, verb: Verb, body: bytes) -> MessageId:
        return self.postman.send_raw(
            d.frm,
            verb,
            body,
            self.tunables.ttl_exchange,
            await_reply=False,
            reply_to=d.mid,
        )

    def _flush_follower(self, now: Millis) -> None:
        for peer, msg in self.follower.outbox():
            self.postman.send(peer, msg, self.tunables.ttl_exchange)

    # -- sync verb handlers (shared) ----------------------------------------

    def _on_ping(self, d: Delivered, now: Millis) -> MessageId:
        return self._reply(d, Verb.PONG, b"")

    def _on_height_reply(self, d: Delivered, now: Millis) -> None:
        try:
            msg = SyncMsg.decode(d.verb, d.body)
        except SyncAdapterError:
            return
        self.follower.receive(msg, d.frm, now)

    def _on_settled_block(self, d: Delivered, now: Millis) -> None:
        try:
            msg = SyncMsg.decode(d.verb, d.body)
        except (SyncAdapterError, DudeError):
            self.follower.cancel_pull(d.frm, now)
            return
        self.follower.receive(msg, d.frm, now)

    def _on_sync_refused(self, d: Delivered, now: Millis) -> None:
        try:
            msg = SyncMsg.decode(d.verb, d.body)
        except SyncAdapterError:
            return
        self.follower.receive(msg, d.frm, now)
        self._flush_follower(now)


# ---------------------------------------------------------------------------
# Node — consensus participant.
# ---------------------------------------------------------------------------

CONSENSUS_ONLY = frozenset({Verb.BODIES, Verb.HELD, Verb.SIG, Verb.SETTLE_SIG})


class Node(_BaseNode):
    def __init__(self, me: crypto.Keypair, store: Store, tunables: Tunables = DEFAULT) -> None:
        super().__init__(me, store, tunables)
        self.adapter = RoundAdapter(me, self.postman, tunables.ttl_round)
        self.settle_adapter = SettleAdapter(me, self.postman, tunables.ttl_round)
        self.coordinator = Coordinator(
            me,
            store,
            self.adapter,
            self.settle_adapter,
            tunables,
            self.follower.behind,
        )
        self.checkpoint_server: CheckpointServer | None = None

    def _run(self) -> None:
        tick_interval = self.tunables.tick_interval.as_seconds
        while not self._stopping.is_set():
            now = Millis.now()
            for output in self.postman.drain_output():
                for d in output.delivered:
                    self._on_delivered(d, now)
            with contextlib.suppress(DudeError):
                self._tick(now)
            self._stopping.wait(timeout=tick_interval)

    @property
    def mempool(self) -> Mempool:
        return self.coordinator.mempool

    def set_immediate(self, enabled: bool = True) -> None:
        self.coordinator.set_immediate(enabled)

    def _tick(self, now: Millis) -> None:
        self._reconcile_peers()
        prev_head = self.store.head_block_num()
        self.coordinator.tick(now)
        if self.store.head_block_num() != prev_head:
            self._notify_followers()
        self.follower.tick(now)
        self._flush_follower(now)

    def _notify_followers(self) -> None:
        reply = serve_height(self.store)
        roster = frozenset(self.roster())
        for pub in self.postman.peers:
            if pub not in roster:
                self.postman.send(pub, reply, self.tunables.ttl_exchange)

    # -- inbound dispatch ---------------------------------------------------

    def _on_delivered(self, d: Delivered, now: Millis) -> None:
        if d.verb in CONSENSUS_ONLY and not self._is_node(d.frm):
            return
        match d.verb:
            case Verb.SUBMIT:
                self._on_submit(d, now)
            case Verb.HELD:
                self._on_held(d, now)
            case Verb.SIG:
                self._on_sig(d, now)
            case Verb.BODIES:
                self._on_bodies(d, now)
            case Verb.SETTLE_SIG:
                self._on_settle_sig(d, now)
            case Verb.HEIGHT:
                self._on_height(d, now)
            case Verb.HEIGHT_REPLY:
                self._on_height_reply(d, now)
            case Verb.GETBLOCK:
                self._on_getblock(d, now)
            case Verb.SETTLED_BLOCK:
                self._on_settled_block(d, now)
            case Verb.SYNC_REFUSED:
                self._on_sync_refused(d, now)
            case Verb.PING:
                self._on_ping(d, now)
            case Verb.GET_ANCHORS:
                self._on_get_anchors(d, now)
            case Verb.GET_PROOF:
                self._on_get_proof(d, now)
            case Verb.TX_STATUS:
                self._on_tx_status(d, now)
            case Verb.GET_CHECKPOINT:
                self._on_get_checkpoint(d, now)
            case Verb.GET_CHUNKS:
                self._on_get_chunks(d, now)
            case Verb.PROVISION:
                self._on_provision(d, now)

    def _is_node(self, who: crypto.PublicKey) -> bool:
        return who == self.store.anchor() or self.mgmt_reader.is_member(who)

    # -- consensus verb handlers --------------------------------------------

    def _on_submit(self, d: Delivered, now: Millis) -> MessageId:
        tx = ops.SignedTransaction.decode(d.body)
        refusal = self.coordinator.submit(tx, now)
        if refusal is not None:
            return self._reply(d, Verb.REFUSED, refusal.value.encode())
        return self._reply(d, Verb.ACCEPTED, tx.op_hash)

    def _on_held(self, d: Delivered, now: Millis) -> None:
        self.coordinator.on_round_msg(d.frm, d.verb, d.body, now)

    def _on_sig(self, d: Delivered, now: Millis) -> None:
        self.coordinator.on_round_msg(d.frm, d.verb, d.body, now)

    def _on_bodies(self, d: Delivered, now: Millis) -> None:
        self.coordinator.on_round_msg(d.frm, d.verb, d.body, now)

    def _on_settle_sig(self, d: Delivered, now: Millis) -> None:
        self.coordinator.on_settle_msg(d.frm, d.verb, d.body, now)

    # -- provisioning -------------------------------------------------------

    def _on_provision(self, d: Delivered, now: Millis) -> None:
        if d.frm != self.store.anchor():
            return
        if self.store.head_block_num() is not None:
            self._reply(d, Verb.REFUSED, b"already provisioned")
            return
        outer = codec.as_seq(codec.decode(d.body), 2)
        block_bytes = codec.as_bytes(outer[0])
        bodies = tuple(
            ops.SignedTransaction.decode(codec.as_bytes(item)) for item in codec.as_seq(outer[1])
        )
        sb = SettledBlock.decode(block_bytes)
        ordered = bodies_canonical(bodies).txs
        self.store.commit_block(
            sb.anchors.block_num,
            first_height=1,
            block_bytes=block_bytes,
            block_hash=sb.block_hash,
            batch=ordered,
            auth=self.mgmt_reader,
        )
        self._reconcile_peers()
        self._reply(d, Verb.ACCEPTED, b"provisioned")

    # -- serving sync requests ----------------------------------------------

    def _on_height(self, d: Delivered, now: Millis) -> MessageId:
        return self.postman.reply(d, serve_height(self.store), self.tunables.ttl_exchange)

    def _on_getblock(self, d: Delivered, now: Millis) -> MessageId | None:
        if not self._replica_authorised(d.frm):
            return self.postman.reply(
                d, Refused(reason=SyncRefusal.UNAUTHORISED), self.tunables.ttl_exchange
            )
        try:
            req = SyncMsg.decode(d.verb, d.body)
        except SyncAdapterError:
            return self.postman.reply(
                d, Refused(reason=SyncRefusal.UNKNOWN), self.tunables.ttl_exchange
            )
        if not isinstance(req, GetBlocks):
            return None
        return self.postman.reply(
            d,
            serve_getblocks(self.store, req, self.tunables.pull_batch),
            self.tunables.ttl_exchange,
        )

    # -- serving checkpoint requests -----------------------------------------

    def _replica_authorised(self, who: crypto.PublicKey) -> bool:
        if who == self.store.anchor() or self.mgmt_reader.is_member(who):
            return True
        grant = self.mgmt_reader.grant_of(who)
        return grant is not None and grant.role in (Role.MANAGER, Role.COMPACTOR)

    def _on_get_checkpoint(self, d: Delivered, now: Millis) -> MessageId | None:
        if not self._replica_authorised(d.frm):
            return self.postman.reply(
                d,
                Refused(reason=SyncRefusal.UNAUTHORISED),
                self.tunables.ttl_exchange,
            )
        if self.checkpoint_server is None:
            return self.postman.reply(
                d,
                Refused(reason=SyncRefusal.NO_STATE),
                self.tunables.ttl_exchange,
            )
        return self.postman.reply(
            d,
            self.checkpoint_server.serve_meta(),
            self.tunables.ttl_exchange,
        )

    def _on_get_chunks(self, d: Delivered, now: Millis) -> MessageId | None:
        if not self._replica_authorised(d.frm):
            return self.postman.reply(
                d,
                Refused(reason=SyncRefusal.UNAUTHORISED),
                self.tunables.ttl_exchange,
            )
        if self.checkpoint_server is None:
            return self.postman.reply(
                d,
                Refused(reason=SyncRefusal.NO_STATE),
                self.tunables.ttl_exchange,
            )
        try:
            req = GetChunks.decode(d.body)
        except CheckpointAdapterError:
            return self.postman.reply(
                d,
                Refused(reason=SyncRefusal.MALFORMED_QUERY),
                self.tunables.ttl_exchange,
            )
        reply = self.checkpoint_server.serve_chunks(req)
        if reply is None:
            return self.postman.reply(
                d,
                Refused(reason=SyncRefusal.CHECKPOINT_STALE),
                self.tunables.ttl_exchange,
            )
        return self.postman.reply(d, reply, self.tunables.ttl_exchange)

    # -- serving lite requests ----------------------------------------------

    def _on_get_anchors(self, d: Delivered, now: Millis) -> MessageId | None:
        if not self._lite_authorised(d.frm):
            return self.postman.reply(
                d, LiteRefused(SyncRefusal.UNAUTHORISED), self.tunables.ttl_lite
            )
        try:
            req = LiteMsg.decode(d.verb, d.body)
        except (LiteAdapterError, DudeError):
            return self.postman.reply(
                d, LiteRefused(SyncRefusal.MALFORMED_QUERY), self.tunables.ttl_lite
            )
        if not isinstance(req, GetAnchors):
            return None
        return self.postman.reply(
            d,
            serve_get_anchors(self.store, req, self.tunables.liveness_window),
            self.tunables.ttl_lite,
        )

    def _on_get_proof(self, d: Delivered, now: Millis) -> MessageId | None:
        if not self._lite_authorised(d.frm):
            return self.postman.reply(
                d, LiteRefused(SyncRefusal.UNAUTHORISED), self.tunables.ttl_lite
            )
        try:
            req = LiteMsg.decode(d.verb, d.body)
        except (LiteAdapterError, DudeError):
            return self.postman.reply(
                d, LiteRefused(SyncRefusal.MALFORMED_QUERY), self.tunables.ttl_lite
            )
        if not isinstance(req, GetProof):
            return None
        if not self.mgmt_reader.may_read(self.store, d.frm, req.store_id):
            return self.postman.reply(
                d, LiteRefused(SyncRefusal.UNAUTHORISED), self.tunables.ttl_lite
            )
        return self.postman.reply(
            d,
            serve_get_proof(self.store, req, self.tunables.liveness_window),
            self.tunables.ttl_lite,
        )

    def _on_tx_status(self, d: Delivered, now: Millis) -> MessageId | None:
        if not self._lite_authorised(d.frm):
            return self.postman.reply(
                d, LiteRefused(SyncRefusal.UNAUTHORISED), self.tunables.ttl_lite
            )
        try:
            req = LiteMsg.decode(d.verb, d.body)
        except (LiteAdapterError, DudeError):
            return self.postman.reply(
                d, LiteRefused(SyncRefusal.MALFORMED_QUERY), self.tunables.ttl_lite
            )
        if not isinstance(req, TxStatus):
            return None
        info = self.store.settlement_of(req.op_hash)
        if info is not None:
            reply = TxStatusReply(
                status=TxStatusKind.SETTLED,
                block_num=info.block_num,
                block_hash=info.block_hash,
            )
        elif req.op_hash in self.coordinator.mempool.all_hashes():
            reply = TxStatusReply(status=TxStatusKind.PENDING)
        else:
            reply = TxStatusReply(status=TxStatusKind.UNKNOWN)
        return self.postman.reply(d, reply, self.tunables.ttl_lite)

    def _lite_authorised(self, requester: crypto.PublicKey) -> bool:
        if requester == self.store.anchor():
            return True
        if self.mgmt_reader.is_member(requester):
            return True
        return self.mgmt_reader.valid_grant(requester) is not None


# ---------------------------------------------------------------------------
# ReplicaNode — full validating follower, own state DB, no consensus.
# ---------------------------------------------------------------------------


class ReplicaNode(_BaseNode):
    def submit(self, tx: ops.SignedTransaction, to: crypto.PublicKey) -> MessageId:
        return self.postman.send_raw(
            to,
            Verb.SUBMIT,
            tx.raw,
            self.tunables.ttl_exchange,
        )

    def session(self, store_id: int = ops.STORE_DATA) -> SessionRW:
        sub = _ReplicaSubstrate(self)
        return SessionRW(sub, store_id)

    def _run(self) -> None:
        tick_interval = self.tunables.tick_interval.as_seconds
        while not self._stopping.is_set():
            now = Millis.now()
            for output in self.postman.drain_output(timeout=tick_interval):
                for d in output.delivered:
                    self._on_delivered(d, now)
                for e in output.expired:
                    self.inflight.on_expired(e.prefix)
            with contextlib.suppress(DudeError):
                self._tick(now)

    def _on_settled_block(self, d: Delivered, now: Millis) -> None:
        super()._on_settled_block(d, now)
        with self.commit_cond:
            self.commit_seq += 1
            self.commit_cond.notify_all()

    def _on_delivered(self, d: Delivered, now: Millis) -> None:
        if d.in_reply_to is not None and self.inflight.on_reply(
            d.in_reply_to.correlation_id, d.verb, d.body
        ):
            return
        match d.verb:
            case Verb.HEIGHT_REPLY:
                self._on_height_reply(d, now)
            case Verb.SETTLED_BLOCK:
                self._on_settled_block(d, now)
            case Verb.SYNC_REFUSED:
                self._on_sync_refused(d, now)
            case Verb.PING:
                self._on_ping(d, now)


class _ReplicaSubstrate(Substrate):
    __slots__ = ("_key_cache", "_node")

    def __init__(self, node: _BaseNode) -> None:
        self._node = node
        self._key_cache: KeyCache | None = None

    def _ensure_cache(self) -> KeyCache:
        if self._key_cache is None:
            self._key_cache = KeyCache(self._node.me, self)
        return self._key_cache

    def anchor(self) -> crypto.PublicKey:
        return self._node.store.anchor()

    def get(self, store: int, name: bytes) -> Held | None:
        return self._node.store.get(store, name)

    def token(self, store_id: int, name: str) -> bytes:
        return self._ensure_cache().token(store_id, name)

    def seal(self, store_id: int, name: str, value: bytes) -> tuple[bytes, bytes, int]:
        return self._ensure_cache().seal(store_id, name, value)

    def decrypt(self, store_id: int, name: str, ciphertext: bytes, epoch: int) -> bytes:
        return self._ensure_cache().decrypt(store_id, name, ciphertext, epoch)

    def submit(self, tx: ops.Transaction) -> SubmitHandle:
        signed = tx.sign(self._node.me, Millis.now())
        roster = self._node.mgmt_reader.roster()
        if not roster:
            raise DudeError("no roster members to submit to")
        target = roster[0]
        mid = MessageId.random()
        handle = SubmitHandle(mid=mid, op_hash=signed.op_hash, _sub=self)
        self._node.inflight.register(mid, handle)
        self._node.postman.send_raw(
            target,
            Verb.SUBMIT,
            signed.raw,
            self._node.tunables.ttl_exchange,
            mid=mid,
        )
        return handle

    def settled(self, op_hash: crypto.Digest) -> SubmitResult | None:
        return self._node.store.settlement_of(op_hash)

    def evict_after_sec(self) -> float:
        return self._node.tunables.evict_after.as_seconds

    def wait_for_commit(self, timeout: float, since: int = -1) -> None:
        with self._node.commit_cond:
            baseline = since if since >= 0 else self._node.commit_seq
            self._node.commit_cond.wait_for(
                lambda: self._node.commit_seq > baseline,
                timeout=timeout,
            )

    @property
    def commit_cond(self) -> threading.Condition:
        return self._node.commit_cond

    @property
    def commit_seq(self) -> int:
        return self._node.commit_seq

    def head(self) -> BlockHead | None:
        num = self._node.store.head_block_num()
        if num is None:
            return None
        h = self._node.store.head_block_hash()
        if h is None:
            return None
        return BlockHead(num, h)
