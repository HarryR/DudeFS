from __future__ import annotations

import contextlib
import threading
from collections.abc import Callable
from dataclasses import dataclass, field

from .consensus import Coordinator, Mempool, RoundAdapter, SettleAdapter
from .core import crypto
from .core.errors import DudeError
from .core.units import Millis, now_ms
from .net import Verb, MessageId
from .net.link import Listener
from .net.postman import Delivered, Postman
from .store import Store, ops
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
)
from .tunables import DEFAULT, Tunables

NODE_ONLY = frozenset(
    {
        Verb.BODIES,
        Verb.HELD,
        Verb.SIG,
        Verb.SETTLE_SIG,
        Verb.HEIGHT,
        Verb.HEIGHT_REPLY,
        Verb.GETBLOCK,
        Verb.SETTLED_BLOCK,
        Verb.SYNC_REFUSED,
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
    }
)


@dataclass(slots=True)
class Node:
    me: crypto.Keypair
    store: Store
    tunables: Tunables = DEFAULT
    postman: Postman = field(init=False)
    adapter: RoundAdapter = field(init=False)
    settle_adapter: SettleAdapter = field(init=False)
    coordinator: Coordinator = field(init=False)
    follower: Follower = field(init=False)

    _stopping: threading.Event = field(default_factory=threading.Event, init=False)
    _thread: threading.Thread | None = field(default=None, init=False)

    def __post_init__(self) -> None:
        self.postman = Postman(self.me, self.tunables)
        self.adapter = RoundAdapter(self.me, self.postman, self.tunables.ttl_round)
        self.settle_adapter = SettleAdapter(self.me, self.postman, self.tunables.ttl_round)
        self.follower = Follower(
            me=self.me,
            store=self.store,
            mgmt=MgmtReader(self.store),
            tunables=self.tunables,
        )
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

    @property
    def mgmt(self) -> MgmtReader:
        return MgmtReader(self.store)

    def roster(self) -> tuple[crypto.PublicKey, ...]:
        return self.store.mgmt.roster()

    # -- the run loop -------------------------------------------------------

    def start(self, *listeners: Listener) -> None:
        if self._thread is not None:
            return
        for listener in listeners:
            self.postman.add_listener(listener)
        self.postman.start()
        self._thread = threading.Thread(
            target=self._run,
            name=f"node-{self.me.public.hex()[:8]}",
            daemon=True,
        )
        self._thread.start()

    def stop(self, timeout: float = 5.0) -> None:
        self._stopping.set()
        self.postman.stop()
        thread = self._thread
        self._thread = None
        if thread is not None and thread.is_alive():
            thread.join(timeout=timeout)

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

    def _tick(self, now: Millis) -> None:
        self._reconcile_peers()
        self.coordinator.tick(now)
        self.follower.tick(now)
        self._flush_follower(now)

    # -- peer reconciliation ------------------------------------------------

    def _reconcile_peers(self) -> None:
        nodes = self.mgmt.nodes()
        roster = self.mgmt.roster()
        peers: dict[crypto.PublicKey, tuple] = {}
        for pk in roster:
            if pk == self.me.public:
                continue
            rec = nodes.get(pk)
            if rec is not None and rec.endpoints:
                peers[pk] = rec.endpoints
        self.postman.sync(peers)

    # -- inbound dispatch ---------------------------------------------------

    def _on_delivered(self, d: Delivered, now: Millis) -> None:
        fn = _DISPATCH.get(d.verb)
        if fn is None:
            return
        if d.verb in NODE_ONLY and not self._is_node(d.frm):
            return
        fn(self, d, now)

    def _is_node(self, who: crypto.PublicKey) -> bool:
        return who == self.store.anchor() or self.mgmt.is_member(who)

    def _reply(self, d: Delivered, verb: Verb, body: bytes) -> MessageId:
        return self.postman.send_raw(
            d.frm, verb, body, self.tunables.ttl_exchange,
            await_reply=False, reply_to=d.mid,
        )

    # -- verb handlers ------------------------------------------------------

    def _on_ping(self, d: Delivered, now: Millis) -> MessageId:
        return self._reply(d, Verb.PONG, b"")

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

    def _on_height(self, d: Delivered, now: Millis) -> MessageId:
        return self.postman.reply(d, serve_height(self.store), self.tunables.ttl_exchange)

    def _on_height_reply(self, d: Delivered, now: Millis) -> None:
        try:
            msg = SyncMsg.decode(d.verb, d.body)
        except SyncAdapterError:
            return
        self.follower.receive(msg, d.frm, now)

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

    def _on_sync_refused(self, d: Delivered, now: Millis) -> None:
        try:
            msg = SyncMsg.decode(d.verb, d.body)
        except SyncAdapterError:
            return
        self.follower.receive(msg, d.frm, now)
        self._flush_follower(now)

    def _on_settled_block(self, d: Delivered, now: Millis) -> None:
        try:
            msg = SyncMsg.decode(d.verb, d.body)
        except (SyncAdapterError, DudeError):
            self.follower.cancel_pull(d.frm, now)
            return
        self.follower.receive(msg, d.frm, now)

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

    def _lite_authorised(self, requester: crypto.PublicKey) -> bool:
        if requester == self.store.anchor():
            return True
        if self.mgmt.is_member(requester):
            return True
        return self.mgmt.valid_grant(self.store, requester) is not None

    # -- follower outbox ----------------------------------------------------

    def _flush_follower(self, now: Millis) -> None:
        for peer, msg in self.follower.outbox():
            self.postman.send(peer, msg, self.tunables.ttl_exchange)


_DISPATCH: dict[Verb, Callable[[Node, Delivered, Millis], MessageId | None]] = {
    v: getattr(Node, f"_on_{v.name.lower()}") for v in HANDLED
}
