import contextlib
import threading
from dataclasses import dataclass, field

from .consensus import Coordinator, Mempool, RoundAdapter, SettleAdapter
from .core import crypto
from .core.errors import DudeError
from .session import KeyCache, SessionRW, SubmitHandle
from .core.units import Millis, now_ms
from .net import Verb, MessageId
from .net.link import Listener
from .net.postman import Delivered, Postman
from .store import Store, ops
from .store.layer import Held, Settled
from .store.management import MgmtReader
from .sync.adapter import (
    GetBlocks,
    Refused,
    SyncAdapterError,
    SyncMsg,
    SyncRefusal,
)
from .sync.checkpoint_adapter import CheckpointAdapterError, GetChunks
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


@dataclass(slots=True)
class _BaseNode:
    me: crypto.Keypair
    store: Store
    tunables: Tunables = DEFAULT
    postman: Postman = field(init=False)
    follower: Follower = field(init=False)

    _stopping: threading.Event = field(default_factory=threading.Event, init=False)
    _thread: threading.Thread | None = field(default=None, init=False)

    def __post_init__(self) -> None:
        self.postman = Postman(self.me, self.tunables)
        self.follower = Follower(
            me=self.me,
            store=self.store,
            mgmt_reader=self.store.mgmt_reader,
            tunables=self.tunables,
        )

    @property
    def mgmt_reader(self) -> MgmtReader:
        return self.store.mgmt_reader

    def roster(self) -> tuple[crypto.PublicKey, ...]:
        return self.store.mgmt_reader.roster()

    # -- lifecycle ----------------------------------------------------------

    def add_listener(self, listener: Listener) -> None:
        self.postman.add_listener(listener)

    def start(self) -> None:
        if self._thread is not None:
            return
        self._stopping = threading.Event()
        self._reconcile_peers()
        self.postman.start()
        prefix = "replica" if isinstance(self, ReplicaNode) else "node"
        self._thread = threading.Thread(
            target=self._run,
            name=f"{prefix}-{self.me.public.hex()[:8]}",
            daemon=True,
        )
        self._thread.start()

    def stop(self) -> None:
        self._stopping.set()
        self.postman.stop()
        thread = self._thread
        self._thread = None
        if thread is not None:
            thread.join()

    def _run(self) -> None:
        tick_interval = self.tunables.tick_interval / 1000
        while not self._stopping.is_set():
            now = now_ms()
            for output in self.postman.drain_output(timeout=tick_interval):
                for d in output.delivered:
                    self._on_delivered(d, now)
            with contextlib.suppress(DudeError):
                self._tick(now)

    def _tick(self, now: Millis) -> None:
        self._reconcile_peers()
        self.follower.tick(now)
        self._flush_follower(now)

    def _on_delivered(self, d: Delivered, now: Millis) -> None:
        raise NotImplementedError

    # -- peer reconciliation ------------------------------------------------

    def _reconcile_peers(self) -> None:
        nodes = self.mgmt_reader.nodes()
        roster = self.mgmt_reader.roster()
        now = now_ms()
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
            d.frm, verb, body, self.tunables.ttl_exchange,
            await_reply=False, reply_to=d.mid,
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


@dataclass(slots=True)
class Node(_BaseNode):
    adapter: RoundAdapter = field(init=False)
    settle_adapter: SettleAdapter = field(init=False)
    coordinator: Coordinator = field(init=False)
    checkpoint_server: CheckpointServer | None = field(default=None, init=False)

    def _run(self) -> None:
        tick_interval = self.tunables.tick_interval / 1000
        while not self._stopping.is_set():
            now = now_ms()
            for output in self.postman.drain_output():
                for d in output.delivered:
                    self._on_delivered(d, now)
            with contextlib.suppress(DudeError):
                self._tick(now)
            self._stopping.wait(timeout=tick_interval)

    def __post_init__(self) -> None:
        _BaseNode.__post_init__(self)
        self.adapter = RoundAdapter(self.me, self.postman, self.tunables.ttl_round)
        self.settle_adapter = SettleAdapter(self.me, self.postman, self.tunables.ttl_round)
        self.coordinator = Coordinator(
            self.me,
            self.store,
            self.adapter,
            self.settle_adapter,
            self.tunables,
            self.follower.behind,
        )

    @property
    def mempool(self) -> Mempool:
        return self.coordinator.mempool

    def _tick(self, now: Millis) -> None:
        self._reconcile_peers()
        self.coordinator.tick(now)
        self.follower.tick(now)
        self._flush_follower(now)

    # -- inbound dispatch ---------------------------------------------------

    def _on_delivered(self, d: Delivered, now: Millis) -> None:
        if d.verb in CONSENSUS_ONLY and not self._is_node(d.frm):
            return
        match d.verb:
            case Verb.SUBMIT: self._on_submit(d, now)
            case Verb.HELD: self._on_held(d, now)
            case Verb.SIG: self._on_sig(d, now)
            case Verb.BODIES: self._on_bodies(d, now)
            case Verb.SETTLE_SIG: self._on_settle_sig(d, now)
            case Verb.HEIGHT: self._on_height(d, now)
            case Verb.HEIGHT_REPLY: self._on_height_reply(d, now)
            case Verb.GETBLOCK: self._on_getblock(d, now)
            case Verb.SETTLED_BLOCK: self._on_settled_block(d, now)
            case Verb.SYNC_REFUSED: self._on_sync_refused(d, now)
            case Verb.PING: self._on_ping(d, now)
            case Verb.GET_ANCHORS: self._on_get_anchors(d, now)
            case Verb.GET_PROOF: self._on_get_proof(d, now)
            case Verb.TX_STATUS: self._on_tx_status(d, now)
            case Verb.GET_CHECKPOINT: self._on_get_checkpoint(d, now)
            case Verb.GET_CHUNKS: self._on_get_chunks(d, now)

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

    # -- serving sync requests ----------------------------------------------

    def _on_height(self, d: Delivered, now: Millis) -> MessageId:
        return self.postman.reply(d, serve_height(self.store), self.tunables.ttl_exchange)

    def _on_getblock(self, d: Delivered, now: Millis) -> MessageId | None:
        try:
            req = SyncMsg.decode(d.verb, d.body)
        except SyncAdapterError:
            return self.postman.reply(d, Refused(reason=SyncRefusal.UNKNOWN), self.tunables.ttl_exchange)
        if not isinstance(req, GetBlocks):
            return None
        return self.postman.reply(
            d, serve_getblocks(self.store, req, self.tunables.pull_batch), self.tunables.ttl_exchange
        )

    # -- serving checkpoint requests -----------------------------------------

    def _on_get_checkpoint(self, d: Delivered, now: Millis) -> MessageId | None:
        if self.checkpoint_server is None:
            return self.postman.reply(
                d, Refused(reason=SyncRefusal.NO_STATE), self.tunables.ttl_exchange,
            )
        return self.postman.reply(
            d, self.checkpoint_server.serve_meta(), self.tunables.ttl_exchange,
        )

    def _on_get_chunks(self, d: Delivered, now: Millis) -> MessageId | None:
        if self.checkpoint_server is None:
            return self.postman.reply(
                d, Refused(reason=SyncRefusal.NO_STATE), self.tunables.ttl_exchange,
            )
        try:
            req = GetChunks.decode(d.body)
        except CheckpointAdapterError:
            return self.postman.reply(
                d, Refused(reason=SyncRefusal.MALFORMED_QUERY), self.tunables.ttl_exchange,
            )
        return self.postman.reply(
            d, self.checkpoint_server.serve_chunks(req), self.tunables.ttl_exchange,
        )

    # -- serving lite requests ----------------------------------------------

    def _on_get_anchors(self, d: Delivered, now: Millis) -> MessageId | None:
        if not self._lite_authorised(d.frm):
            return self.postman.reply(d, LiteRefused(SyncRefusal.UNAUTHORISED), self.tunables.ttl_lite)
        try:
            req = LiteMsg.decode(d.verb, d.body)
        except (LiteAdapterError, DudeError):
            return self.postman.reply(d, LiteRefused(SyncRefusal.MALFORMED_QUERY), self.tunables.ttl_lite)
        if not isinstance(req, GetAnchors):
            return None
        return self.postman.reply(d, serve_get_anchors(self.store, req, self.tunables.liveness_window), self.tunables.ttl_lite)

    def _on_get_proof(self, d: Delivered, now: Millis) -> MessageId | None:
        if not self._lite_authorised(d.frm):
            return self.postman.reply(d, LiteRefused(SyncRefusal.UNAUTHORISED), self.tunables.ttl_lite)
        try:
            req = LiteMsg.decode(d.verb, d.body)
        except (LiteAdapterError, DudeError):
            return self.postman.reply(d, LiteRefused(SyncRefusal.MALFORMED_QUERY), self.tunables.ttl_lite)
        if not isinstance(req, GetProof):
            return None
        if not self.mgmt_reader.may_read(self.store, d.frm, req.store_id):
            return self.postman.reply(d, LiteRefused(SyncRefusal.UNAUTHORISED), self.tunables.ttl_lite)
        return self.postman.reply(d, serve_get_proof(self.store, req, self.tunables.liveness_window), self.tunables.ttl_lite)

    def _on_tx_status(self, d: Delivered, now: Millis) -> MessageId | None:
        if not self._lite_authorised(d.frm):
            return self.postman.reply(d, LiteRefused(SyncRefusal.UNAUTHORISED), self.tunables.ttl_lite)
        try:
            req = LiteMsg.decode(d.verb, d.body)
        except (LiteAdapterError, DudeError):
            return self.postman.reply(d, LiteRefused(SyncRefusal.MALFORMED_QUERY), self.tunables.ttl_lite)
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


@dataclass(slots=True)
class ReplicaNode(_BaseNode):
    _key_cache: KeyCache | None = field(default=None, init=False)
    _inflight: dict[bytes, SubmitHandle] = field(default_factory=dict, init=False)
    _commit_seq: int = field(default=0, init=False)
    _commit_cond: threading.Condition = field(default_factory=threading.Condition, init=False)

    def submit(self, tx: ops.SignedTransaction, to: crypto.PublicKey) -> MessageId:
        return self.postman.send_raw(
            to, Verb.SUBMIT, tx.raw, self.tunables.ttl_exchange,
        )

    def session(self, store_id: int = ops.STORE_DATA) -> SessionRW:
        sub = _ReplicaSubstrate(self)
        if self._key_cache is None:
            self._key_cache = KeyCache(self.me, sub)
        return SessionRW(sub, self.me, store_id)

    def _run(self) -> None:
        tick_interval = self.tunables.tick_interval / 1000
        while not self._stopping.is_set():
            now = now_ms()
            for output in self.postman.drain_output(timeout=tick_interval):
                for d in output.delivered:
                    self._on_delivered(d, now)
                for e in output.expired:
                    handle = self._inflight.pop(e.prefix, None)
                    if handle is not None:
                        handle.expire()
            with contextlib.suppress(DudeError):
                self._tick(now)

    def _on_settled_block(self, d: Delivered, now: Millis) -> None:
        _BaseNode._on_settled_block(self, d, now)
        with self._commit_cond:
            self._commit_seq += 1
            self._commit_cond.notify_all()

    def _on_delivered(self, d: Delivered, now: Millis) -> None:
        if d.verb in (Verb.ACCEPTED, Verb.REFUSED) and d.in_reply_to is not None:
            handle = self._inflight.pop(d.in_reply_to.correlation_id, None)
            if handle is not None:
                handle.resolve(d.verb, d.body)
            return
        match d.verb:
            case Verb.HEIGHT_REPLY: self._on_height_reply(d, now)
            case Verb.SETTLED_BLOCK: self._on_settled_block(d, now)
            case Verb.SYNC_REFUSED: self._on_sync_refused(d, now)
            case Verb.PING: self._on_ping(d, now)


class _ReplicaSubstrate:
    __slots__ = ("_node",)

    def __init__(self, node: ReplicaNode) -> None:
        self._node = node

    def anchor(self) -> crypto.PublicKey:
        return self._node.store.anchor()

    def get(self, store: int, name: bytes) -> Held | None:
        return self._node.store.get(store, name)

    def submit(self, tx: ops.SignedTransaction) -> SubmitHandle:
        roster = self._node.mgmt_reader.roster()
        if not roster:
            raise DudeError("no roster members to submit to")
        target = roster[0]
        mid = MessageId.random()
        handle = SubmitHandle(mid=mid, op_hash=tx.op_hash, _sub=self)
        self._node._inflight[mid.correlation_id] = handle
        self._node.postman.send_raw(
            target, Verb.SUBMIT, tx.raw, self._node.tunables.ttl_exchange, mid=mid,
        )
        return handle

    def settled(self, op_hash: crypto.Digest, peer: crypto.PublicKey | None = None) -> Settled | None:
        return self._node.store.settlement_of(op_hash)

    def evict_after_sec(self) -> float:
        return self._node.tunables.evict_after / 1000

    def wait_for_commit(self, timeout: float) -> None:
        with self._node._commit_cond:
            seq = self._node._commit_seq
            self._node._commit_cond.wait_for(
                lambda: self._node._commit_seq > seq, timeout=timeout,
            )


