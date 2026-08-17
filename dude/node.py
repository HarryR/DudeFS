import contextlib
import threading
from collections.abc import Callable
from dataclasses import dataclass, field

from .consensus import Coordinator, Mempool, RoundAdapter, SettleAdapter
from .core import crypto
from .core.errors import DudeError
from .session import KeyCache, Session, SubmitHandle
from .core.units import Millis, now_ms
from .net import Verb, MessageId
from .net.link import Listener
from .net.postman import Delivered, Postman
from .store import Store, ops
from .store.layer import Held
from .store.management import MgmtReader
from .sync.adapter import (
    GetBlocks,
    Refused,
    SyncAdapterError,
    SyncMsg,
    SyncRefusal,
)
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
            mgmt=MgmtReader(self.store),
            tunables=self.tunables,
        )

    @property
    def mgmt(self) -> MgmtReader:
        return MgmtReader(self.store)

    def roster(self) -> tuple[crypto.PublicKey, ...]:
        return self.store.mgmt.roster()

    # -- lifecycle ----------------------------------------------------------

    def add_listener(self, listener: Listener) -> None:
        self.postman.add_listener(listener)

    def start(self) -> None:
        if self._thread is not None:
            return
        self._stopping = threading.Event()
        self.postman.start()
        prefix = "mgmt" if isinstance(self, ManagementNode) else "node"
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
        nodes = self.mgmt.nodes()
        roster = self.mgmt.roster()
        now = now_ms()
        peers: dict[crypto.PublicKey, tuple] = {}
        for pk in roster:
            if pk == self.me.public:
                continue
            rec = nodes.get(pk)
            if rec is not None and rec.endpoints:
                peers[pk] = rec.endpoints
            self.follower.add_peer(pk, now)
        self.postman.sync(peers, authorized=self.mgmt.authorized_identities())

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

CONSENSUS_ONLY = frozenset(
    {
        Verb.BODIES,
        Verb.HELD,
        Verb.SIG,
        Verb.SETTLE_SIG,
    }
)

HANDLED = frozenset(
    {
        Verb.SUBMIT,
        Verb.HELD,
        Verb.SIG,
        Verb.BODIES,
        Verb.SETTLE_SIG,
        Verb.HEIGHT,
        Verb.HEIGHT_REPLY,
        Verb.GETBLOCK,
        Verb.SETTLED_BLOCK,
        Verb.SYNC_REFUSED,
        Verb.PING,
        Verb.GET_ANCHORS,
        Verb.GET_PROOF,
        Verb.TX_STATUS,
    }
)


@dataclass(slots=True)
class Node(_BaseNode):
    adapter: RoundAdapter = field(init=False)
    settle_adapter: SettleAdapter = field(init=False)
    coordinator: Coordinator = field(init=False)

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
        fn = _DISPATCH.get(d.verb)
        if fn is None:
            return
        if d.verb in CONSENSUS_ONLY and not self._is_node(d.frm):
            return
        fn(self, d, now)

    def _is_node(self, who: crypto.PublicKey) -> bool:
        return who == self.store.anchor() or self.mgmt.is_member(who)

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
        if not self.mgmt.may_read(self.store, d.frm, req.store_id):
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
        if self.store.has_settled(req.op_hash):
            status = TxStatusKind.SETTLED
        elif req.op_hash in self.coordinator.mempool.all_hashes():
            status = TxStatusKind.PENDING
        else:
            status = TxStatusKind.UNKNOWN
        return self.postman.reply(d, TxStatusReply(status=status), self.tunables.ttl_lite)

    def _lite_authorised(self, requester: crypto.PublicKey) -> bool:
        if requester == self.store.anchor():
            return True
        if self.mgmt.is_member(requester):
            return True
        return self.mgmt.valid_grant(self.store, requester) is not None


_DISPATCH: dict[Verb, Callable[[Node, Delivered, Millis], MessageId | None]] = {
    v: getattr(Node, f"_on_{v.name.lower()}") for v in HANDLED
}


# ---------------------------------------------------------------------------
# ManagementNode — full validating follower, own state DB, no consensus.
# ---------------------------------------------------------------------------

_MGMT_HANDLED = frozenset({
    Verb.HEIGHT_REPLY,
    Verb.SETTLED_BLOCK,
    Verb.SYNC_REFUSED,
    Verb.PING,
})


@dataclass(slots=True)
class ManagementNode(_BaseNode):
    _key_cache: KeyCache | None = field(default=None, init=False)
    _inflight: dict[bytes, SubmitHandle] = field(default_factory=dict, init=False)
    _commit_seq: int = field(default=0, init=False)
    _commit_cond: threading.Condition = field(default_factory=threading.Condition, init=False)

    def submit(self, tx: ops.SignedTransaction, to: crypto.PublicKey) -> MessageId:
        return self.postman.send_raw(
            to, Verb.SUBMIT, tx.raw, self.tunables.ttl_exchange,
        )

    def session(self, store_id: int = ops.STORE_DATA) -> Session:
        sub = _MgmtSubstrate(self)
        if self._key_cache is None:
            self._key_cache = KeyCache(self.me, sub)
        return Session(sub, self.me, store_id, self._key_cache)

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
        fn = _MGMT_DISPATCH.get(d.verb)
        if fn is not None:
            fn(self, d, now)


class _MgmtSubstrate:
    __slots__ = ("_node",)

    def __init__(self, node: ManagementNode) -> None:
        self._node = node

    def get(self, store_id: int, name: bytes) -> Held | None:
        return self._node.store.get(store_id, name)

    def submit(self, tx: ops.SignedTransaction) -> SubmitHandle:
        roster = self._node.mgmt.roster()
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

    def settled(self, op_hash: crypto.Digest, peer: crypto.PublicKey | None = None) -> bool:
        return self._node.store.has_settled(op_hash)

    def evict_after_sec(self) -> float:
        return self._node.tunables.evict_after / 1000

    def wait_for_commit(self, timeout: float) -> None:
        with self._node._commit_cond:
            seq = self._node._commit_seq
            self._node._commit_cond.wait_for(
                lambda: self._node._commit_seq > seq, timeout=timeout,
            )


_MGMT_DISPATCH: dict[Verb, Callable[[ManagementNode, Delivered, Millis], MessageId | None]] = {
    v: getattr(ManagementNode, f"_on_{v.name.lower()}") for v in _MGMT_HANDLED
}
