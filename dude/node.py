import threading
import time
from abc import ABC
from collections.abc import Callable
from dataclasses import dataclass

from .consensus import Mempool
from .consensus.canonical import bodies_canonical
from .consensus.coordinator import (
    BlockSettled,
    Coordinator,
    RoundMessage,
    SendConsensus,
    SettleMessage,
)
from .consensus.settle_round import SettledBlock
from .core import codec, crypto
from .core.errors import DudeError
from .core.event_loop import Event, EventLoop
from .core.units import Millis
from .net import MessageId, Verb
from .net.link import Acceptor, Dialer
from .net.postman import Delivered, Output, Postman
from .net.socket_server import SocketServer
from .session import Inflight, KeyCache, SessionRW, SubmitHandle, SubmitResult, Substrate
from .store import Store, ops
from .store.checkpoint import CheckpointMeta
from .store.layer import BlockHead, Held
from .store.management import MgmtReader, Role
from .store.smt_sync import TreeImporter
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
from .sync.follower import (
    BlockCommitted,
    Follower,
    PeerAdded,
    PeerMessage,
    PullCancelled,
    SendToPeer,
    serve_getblocks,
    serve_height,
)
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

# -- node events -----------------------------------------------------------


class NodeEvent(Event, ABC):
    __slots__ = ()


@dataclass(frozen=True, slots=True)
class MessageIn(NodeEvent):
    delivered: Delivered


@dataclass(frozen=True, slots=True)
class MessageExpired(NodeEvent):
    prefix: bytes


class ReconcilePeers(NodeEvent):
    __slots__ = ()


# ---------------------------------------------------------------------------
# Base — the run loop, lifecycle, peer reconciliation, follower, sync handlers.
# ---------------------------------------------------------------------------


class _BaseNode:
    def __init__(
        self,
        me: crypto.Keypair,
        store: Store,
        on_follower_commit: Callable[[BlockCommitted], None],
        tunables: Tunables = DEFAULT,
    ) -> None:
        self.me = me
        self.store = store
        self.tunables = tunables

        def _on_postman_output(out: Output) -> None:
            for d in out.delivered:
                self._loop.post(MessageIn(d))
            for e in out.expired:
                self._loop.post(MessageExpired(e.prefix))

        self.postman = Postman(me, tunables, on_output=_on_postman_output)

        def _on_send(e: SendToPeer) -> None:
            self.postman.send(e.peer, e.msg, tunables.ttl_exchange)

        self.follower = Follower(
            me=me, store=store, mgmt_reader=store.mgmt_reader,
            tunables=tunables, on_send=_on_send, on_commit=on_follower_commit,
        )
        self.inflight = Inflight()
        self.commit_seq = 0
        self.commit_cond = threading.Condition()
        self._socket_servers: list[SocketServer] = []

        self._loop: EventLoop[NodeEvent] = EventLoop()
        self._loop.register(MessageIn, self._on_message_in)
        self._loop.register(MessageExpired, self._on_message_expired)
        self._loop.register(ReconcilePeers, self._on_reconcile_peers)

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
        self.follower.start()
        self._reconcile_peers()
        self.postman.start()
        for srv in self._socket_servers:
            srv.start()
        self._loop.start()
        self._schedule_reconcile()

    def stop(self) -> None:
        self._loop.stop()
        for srv in self._socket_servers:
            srv.stop()
        self.follower.stop()
        self.postman.stop()
        self.store.close()

    # -- event handlers --------------------------------------------------------

    def _on_message_in(self, event: MessageIn) -> None:
        self._on_delivered(event.delivered)

    def _on_message_expired(self, event: MessageExpired) -> None:
        self.inflight.on_expired(event.prefix)

    def _on_reconcile_peers(self, _event: ReconcilePeers) -> None:
        self._reconcile_peers()
        checkpoint_block = self.follower.needs_checkpoint()
        if checkpoint_block is not None:
            self._download_checkpoint()
        self._schedule_reconcile()

    def _schedule_reconcile(self) -> None:
        self._loop.schedule(
            Millis.now() + self.tunables.tick_interval, ReconcilePeers()
        )

    def _on_delivered(self, d: Delivered) -> None:
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
        while time.monotonic() < deadline and self._loop.running:
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
                    self._on_delivered(d)
        return None

    def _download_checkpoint(self) -> None:

        peers = list(self.follower.compacted_peers())
        if not peers:
            return
        timeout = self.tunables.ttl_exchange.as_seconds
        get_cp_verb, get_cp_body = GetCheckpoint().encode()

        for peer in peers:
            if not self._loop.running:
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
            while self._loop.running:
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

            if not ok or not self._loop.running:
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
        peers: dict[crypto.PublicKey, tuple] = {}
        for pk in roster:
            if pk == self.me.public:
                continue
            rec = nodes.get(pk)
            if rec is not None and rec.endpoints:
                peers[pk] = rec.endpoints
            self.follower.post(PeerAdded(pk))
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

    # -- sync verb handlers (shared) ----------------------------------------

    def _on_ping(self, d: Delivered) -> MessageId:
        return self._reply(d, Verb.PONG, b"")

    def _on_height_reply(self, d: Delivered) -> None:
        try:
            msg = SyncMsg.decode(d.verb, d.body)
        except SyncAdapterError:
            return
        self.follower.post(PeerMessage(msg, d.frm))

    def _on_settled_block(self, d: Delivered) -> None:
        try:
            msg = SyncMsg.decode(d.verb, d.body)
        except (SyncAdapterError, DudeError):
            self.follower.post(PullCancelled(d.frm))
            return
        self.follower.post(PeerMessage(msg, d.frm))

    def _on_sync_refused(self, d: Delivered) -> None:
        try:
            msg = SyncMsg.decode(d.verb, d.body)
        except SyncAdapterError:
            return
        self.follower.post(PeerMessage(msg, d.frm))


# ---------------------------------------------------------------------------
# Node — consensus participant.
# ---------------------------------------------------------------------------

CONSENSUS_ONLY = frozenset({Verb.BODIES, Verb.HELD, Verb.SIG, Verb.SETTLE_SIG})


class Node(_BaseNode):
    def __init__(self, me: crypto.Keypair, store: Store, tunables: Tunables = DEFAULT) -> None:
        def _on_follower_commit(_e: BlockCommitted) -> None:
            with self.commit_cond:
                self.commit_seq += 1
                self.commit_cond.notify_all()
            self._notify_followers()

        super().__init__(me, store, on_follower_commit=_on_follower_commit, tunables=tunables)

        def _on_consensus_send(e: SendConsensus) -> None:
            verb, body = e.msg.encode()
            self.postman.send_raw(e.peer, verb, body, tunables.ttl_round, await_reply=False)

        def _on_block_settled(_e: BlockSettled) -> None:
            self._notify_followers()

        self.coordinator = Coordinator(
            me, store, tunables,
            behind=self.follower.behind,
            on_send=_on_consensus_send,
            on_settled=_on_block_settled,
        )
        self.checkpoint_server: CheckpointServer | None = None

    def start(self) -> None:
        super().start()
        self.coordinator.start()

    def stop(self) -> None:
        self.coordinator.stop()
        super().stop()

    @property
    def mempool(self) -> Mempool:
        return self.coordinator.mempool

    def set_immediate(self, enabled: bool = True) -> None:
        self.coordinator.set_immediate(enabled)

    def _notify_followers(self) -> None:
        reply = serve_height(self.store)
        verb, body = reply.encode()
        for pub in self.postman.peers:
            self.postman.send_raw(pub, verb, body, self.tunables.ttl_exchange, await_reply=False)

    # -- inbound dispatch ---------------------------------------------------

    def _on_delivered(self, d: Delivered) -> None:
        if d.verb in CONSENSUS_ONLY and not self._is_node(d.frm):
            return
        match d.verb:
            case Verb.SUBMIT:
                self._on_submit(d)
            case Verb.HELD | Verb.SIG | Verb.BODIES:
                self.coordinator.post(RoundMessage(d.frm, d.verb, d.body))
            case Verb.SETTLE_SIG:
                self.coordinator.post(SettleMessage(d.frm, d.verb, d.body))
            case Verb.HEIGHT:
                self._on_height(d)
            case Verb.HEIGHT_REPLY:
                self._on_height_reply(d)
            case Verb.GETBLOCK:
                self._on_getblock(d)
            case Verb.SETTLED_BLOCK:
                self._on_settled_block(d)
            case Verb.SYNC_REFUSED:
                self._on_sync_refused(d)
            case Verb.PING:
                self._on_ping(d)
            case Verb.GET_ANCHORS:
                self._on_get_anchors(d)
            case Verb.GET_PROOF:
                self._on_get_proof(d)
            case Verb.TX_STATUS:
                self._on_tx_status(d)
            case Verb.GET_CHECKPOINT:
                self._on_get_checkpoint(d)
            case Verb.GET_CHUNKS:
                self._on_get_chunks(d)
            case Verb.PROVISION:
                self._on_provision(d)

    def _is_node(self, who: crypto.PublicKey) -> bool:
        return who == self.store.anchor() or self.mgmt_reader.is_member(who)

    # -- consensus verb handlers --------------------------------------------

    def _on_submit(self, d: Delivered) -> MessageId:
        tx = ops.SignedTransaction.decode(d.body)
        refusal = self.coordinator.submit(tx, Millis.now())
        if refusal is not None:
            return self._reply(d, Verb.REFUSED, refusal.value.encode())
        return self._reply(d, Verb.ACCEPTED, tx.op_hash)

    # -- provisioning -------------------------------------------------------

    def _on_provision(self, d: Delivered) -> None:
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

    def _on_height(self, d: Delivered) -> MessageId:
        return self.postman.reply(d, serve_height(self.store), self.tunables.ttl_exchange)

    def _on_getblock(self, d: Delivered) -> MessageId | None:
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

    def _on_get_checkpoint(self, d: Delivered) -> MessageId | None:
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

    def _on_get_chunks(self, d: Delivered) -> MessageId | None:
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

    def _on_get_anchors(self, d: Delivered) -> MessageId | None:
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

    def _on_get_proof(self, d: Delivered) -> MessageId | None:
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

    def _on_tx_status(self, d: Delivered) -> MessageId | None:
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
    def __init__(self, me: crypto.Keypair, store: Store, tunables: Tunables = DEFAULT) -> None:
        def _on_follower_commit(_e: BlockCommitted) -> None:
            with self.commit_cond:
                self.commit_seq += 1
                self.commit_cond.notify_all()

        super().__init__(me, store, on_follower_commit=_on_follower_commit, tunables=tunables)

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

    def _on_delivered(self, d: Delivered) -> None:
        if d.in_reply_to is not None and self.inflight.on_reply(
            d.in_reply_to.correlation_id, d.verb, d.body
        ):
            return
        match d.verb:
            case Verb.HEIGHT_REPLY:
                self._on_height_reply(d)
            case Verb.SETTLED_BLOCK:
                self._on_settled_block(d)
            case Verb.SYNC_REFUSED:
                self._on_sync_refused(d)
            case Verb.PING:
                self._on_ping(d)


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
