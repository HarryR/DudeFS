from __future__ import annotations

import contextlib
import queue
import threading
from collections.abc import Callable
from dataclasses import dataclass, field

from .consensus import Coordinator, Mempool, RoundAdapter, SettleAdapter
from .core import crypto
from .core.errors import DudeError
from .core.units import Millis, now_ms
from .net import Verb
from .net.envelope import Frame, SignedEnvelope
from .net.link import Listener
from .net.postman import Postman
from .net.session import Inbound, Session, SessionBindError
from .store import Store, ops
from .store.management import MgmtReader
from .sync.adapter import (
    GetBlocks,
    Refused,
    SyncAdapter,
    SyncAdapterError,
    SyncMsg,
    SyncRefusal,
)
from .sync.follower import Follower, serve_getblocks, serve_height
from .sync.lite import serve_get_anchors, serve_get_proof
from .sync.lite_adapter import (
    GetAnchors,
    GetProof,
    LiteAdapter,
    LiteAdapterError,
    LiteMsg,
    LiteRefused,
)
from .tunables import DEFAULT, Tunables

REPLIES = frozenset(
    {
        Verb.PONG,
        Verb.ACCEPTED,
        Verb.REFUSED,
        Verb.ANCHORS_REPLY,
        Verb.PROOF_REPLY,
        Verb.LITE_REFUSED,
    }
)
"""Answers a Node never consumes -- ACCEPTED and REFUSED by a submitting client, the last three
by a `LightClient`. A reply the Node DOES consume must be in HANDLED or the dispatch table
discards it: HEIGHT_REPLY, SETTLED_BLOCK and SYNC_REFUSED all answer a Node's own request."""

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
"""Verbs only a roster seat (or the anchor) may speak. A CLIENT grant does not make you a node,
and a manager is not a node either -- it reads the chain through GET_ANCHORS/GET_PROOF like any
other principal. The Round and SettleRound already refuse a non-member, but they refuse it after
we have decoded and dispatched for them, and a refusal nobody can see is not a boundary."""

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
    sync_adapter: SyncAdapter = field(init=False)
    lite_adapter: LiteAdapter = field(init=False)
    coordinator: Coordinator = field(init=False)
    follower: Follower = field(init=False)

    _last_reconciled_serial: int = field(default=-1, init=False)

    _managed_peers: set[crypto.PublicKey] = field(default_factory=set, init=False)

    _inbox: queue.SimpleQueue[Inbound] = field(default_factory=queue.SimpleQueue, init=False)

    _stopping: threading.Event = field(default_factory=threading.Event, init=False)

    _thread: threading.Thread | None = field(default=None, init=False)

    _listeners: tuple[Listener, ...] = field(default=(), init=False)

    def __post_init__(self) -> None:
        self.postman = Postman(
            self.me,
            window=self.tunables.net.window,
            link_tunables=self.tunables.link,
        )
        self.adapter = RoundAdapter(self.me, self.postman, self.tunables.net.ttl)
        self.settle_adapter = SettleAdapter(self.me, self.postman, self.tunables.net.ttl)
        self.sync_adapter = SyncAdapter(self.me, self.postman, self.tunables.net.ttl)
        self.lite_adapter = LiteAdapter(self.me, self.postman, self.tunables.net.ttl)
        # Follower first: the Coordinator asks it whether we are too far behind to lead.
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

    def _reconcile_peers(self, now: Millis) -> None:
        commitment = self.mgmt.roster_commitment()
        if commitment is None:
            return
        roster = set(self.mgmt.roster())
        self._reconcile_roster(commitment.serial, roster, now)
        for pubkey in list(self._managed_peers):
            if pubkey not in roster:
                if pubkey in self.postman.peers:
                    self.postman.remove_peer(pubkey)
                self._managed_peers.discard(pubkey)

    def _reconcile_roster(self, serial: int, roster: set[crypto.PublicKey], now: Millis) -> None:
        if serial == self._last_reconciled_serial:
            return
        self._last_reconciled_serial = serial
        nodes = self.mgmt.nodes()
        for pubkey in roster:
            if pubkey == self.me.public:
                continue
            if pubkey in self.postman.peers:
                continue
            rec = nodes.get(pubkey)
            if rec is None or not rec.endpoints:
                continue
            self.postman.add_peer(pubkey, rec.endpoints)
            self.follower.add_peer(pubkey, now=now)
            self._managed_peers.add(pubkey)

    def roster(self) -> tuple[crypto.PublicKey, ...]:
        return self.store.mgmt.roster()

    def receive(self, frame: Frame, now: Millis, session: Session | None = None) -> None:
        try:
            got = self.postman.deliver(frame, now)
            # WE GATE WHO MAY INITIATE. An answer correlated to a request WE sent is admitted
            # on the strength of our having chosen the correspondent -- the mailbox only matches
            # a 16-byte mid we issued. Gating replies too deadlocks a joiner: its store is empty,
            # so it recognises nobody, so it may not accept the very blocks that would teach it
            # who the cluster is.
            is_node = self._is_node(got.envelope.frm)
            solicited = got.reply is not None
            if not solicited and not is_node and not self._granted(got.envelope.frm):
                # CUT OFF, not merely ignored. Sealing a frame needs only our public key, so a
                # stranger can spend our unseal and our signature verify on every frame they send
                # -- and a revoked identity kept a live socket, because dropping a peer entry only
                # stopped us dialling it. The first frame is unavoidable; this is what stops the
                # second. Before this, an inbound session also MINTED a Peer for whatever pubkey
                # bound it, so an attacker grew that table one invented key at a time.
                self._cut_off(got.envelope.frm, session)
                return
            if session is not None:
                self._bind_session(session, got.envelope.frm)
            self._handle(got.envelope, now, is_node or solicited)
        except DudeError:
            return

    def _cut_off(self, who: crypto.PublicKey, session: Session | None) -> None:
        if session is not None:
            with contextlib.suppress(Exception):
                session.close()
        if who in self.postman.peers:
            self.postman.remove_peer(who)
        self._managed_peers.discard(who)

    def _bind_session(self, session: Session, frm: crypto.PublicKey) -> None:
        was_unbound = session.identity is None
        try:
            session.bind(frm)
        except SessionBindError:
            session.close()
            return
        if was_unbound:
            self.postman.register_session(session)

    def _handle(self, env: SignedEnvelope, now: Millis, is_node: bool) -> None:
        verb = env.env.verb
        fn = _DISPATCH.get(verb)
        if fn is None:
            return
        if verb in NODE_ONLY and not is_node:
            return  # silently: answering tells an unauthorised sender what we run
        fn(self, env, now)

    def _is_node(self, who: crypto.PublicKey) -> bool:
        return who == self.store.anchor() or self.mgmt.is_member(who)

    def _granted(self, who: crypto.PublicKey) -> bool:
        return self.mgmt.valid_grant(self.store, who) is not None

    def _on_ping(self, env: SignedEnvelope, now: Millis) -> None:
        self._reply(env, Verb.PONG, b"", now)

    def _on_submit(self, env: SignedEnvelope, now: Millis) -> None:
        tx = ops.SignedTransaction.decode(env.env.body)
        refusal = self.coordinator.submit(tx, now)
        if refusal is not None:
            self._reply(env, Verb.REFUSED, refusal.value.encode(), now)
            return
        self._reply(env, Verb.ACCEPTED, tx.op_hash, now)

    def _on_held(self, env: SignedEnvelope, now: Millis) -> None:
        self.coordinator.on_round_msg(env, now)

    def _on_sig(self, env: SignedEnvelope, now: Millis) -> None:
        self.coordinator.on_round_msg(env, now)

    def _on_bodies(self, env: SignedEnvelope, now: Millis) -> None:
        self.coordinator.on_round_msg(env, now)

    def _on_settle_sig(self, env: SignedEnvelope, now: Millis) -> None:
        self.coordinator.on_settle_msg(env, now)

    def _on_height(self, env: SignedEnvelope, now: Millis) -> None:
        self.sync_adapter.reply(env, serve_height(self.store), now)

    def _on_height_reply(self, env: SignedEnvelope, now: Millis) -> None:
        try:
            msg = SyncMsg.decode(env.env.verb, env.env.body)
        except SyncAdapterError:
            return
        self.follower.receive(msg, env.frm, now)

    def _on_getblock(self, env: SignedEnvelope, now: Millis) -> None:
        try:
            req = SyncMsg.decode(env.env.verb, env.env.body)
        except SyncAdapterError:
            self.sync_adapter.reply(env, Refused(reason=SyncRefusal.UNKNOWN), now)
            return
        if not isinstance(req, GetBlocks):
            return
        self.sync_adapter.reply(
            env, serve_getblocks(self.store, req, self.tunables.sync.pull_batch), now
        )

    def _on_sync_refused(self, env: SignedEnvelope, now: Millis) -> None:
        # A peer's answer to our own GETBLOCK. It had no dispatch entry, so every sync
        # refusal was discarded at the door: the follower's refusal handling ran only in
        # tests that called it directly, each refusal cost a full pull_timeout instead of
        # a same-tick retry, and the correct-down of a liar's claimed head never ran.
        try:
            msg = SyncMsg.decode(env.env.verb, env.env.body)
        except SyncAdapterError:
            return
        self.follower.receive(msg, env.frm, now)
        # The refusal path may retry against another source in the same tick; that retry
        # sits in the follower's outbox and must not wait for the next tick to be sent.
        self._flush_follower(now)

    def _on_settled_block(self, env: SignedEnvelope, now: Millis) -> None:
        try:
            msg = SyncMsg.decode(env.env.verb, env.env.body)
        except (SyncAdapterError, DudeError):
            self.follower.cancel_pull(env.frm, now)
            return
        self.follower.receive(msg, env.frm, now)

    def _lite_authorised(self, requester: crypto.PublicKey) -> bool:
        """May this identity ask us for chain metadata at all. It asked only whether a grant row
        EXISTED -- so a grant issued by a since-revoked manager still read, long after the same
        grant had stopped writing. Per request against current state, never cached."""
        if requester == self.store.anchor():
            return True
        if self.mgmt.is_member(requester):
            return True
        return self.mgmt.valid_grant(self.store, requester) is not None

    def _on_get_anchors(self, env: SignedEnvelope, now: Millis) -> None:
        if not self._lite_authorised(env.frm):
            self.lite_adapter.reply(env, LiteRefused(SyncRefusal.UNAUTHORISED), now)
            return
        try:
            req = LiteMsg.decode(env.env.verb, env.env.body)
        except (LiteAdapterError, DudeError):
            self.lite_adapter.reply(env, LiteRefused(SyncRefusal.MALFORMED_QUERY), now)
            return
        if not isinstance(req, GetAnchors):
            return
        reply = serve_get_anchors(self.store, req, self.tunables.light_client.liveness_window)
        self.lite_adapter.reply(env, reply, now)

    def _on_get_proof(self, env: SignedEnvelope, now: Millis) -> None:
        if not self._lite_authorised(env.frm):
            self.lite_adapter.reply(env, LiteRefused(SyncRefusal.UNAUTHORISED), now)
            return
        try:
            req = LiteMsg.decode(env.env.verb, env.env.body)
        except (LiteAdapterError, DudeError):
            self.lite_adapter.reply(env, LiteRefused(SyncRefusal.MALFORMED_QUERY), now)
            return
        if not isinstance(req, GetProof):
            return
        if not self.mgmt.may_read(self.store, env.frm, req.store_id):
            # SCOPED THE SAME WAY WRITING IS. Unscoped, a grant for one store read every store,
            # store 0 included -- grants, roster rows, possession proofs, wrapped keys.
            self.lite_adapter.reply(env, LiteRefused(SyncRefusal.UNAUTHORISED), now)
            return
        reply = serve_get_proof(self.store, req, self.tunables.light_client.liveness_window)
        self.lite_adapter.reply(env, reply, now)

    def tick(self, now: Millis) -> None:
        self._reconcile_peers(now)
        self.coordinator.tick(now)
        self.follower.tick(now)
        self._flush_follower(now)
        self.postman.tick(now)

    def start(self, *listeners: Listener) -> None:
        if self._thread is not None:
            return
        started: list[Listener] = []
        try:
            self.postman.start(self._inbox)
            for listener in listeners:
                listener.start(self._inbox)
                started.append(listener)
        except Exception:
            for listener in reversed(started):
                with contextlib.suppress(Exception):
                    listener.stop()
            with contextlib.suppress(Exception):
                self.postman.stop()
            raise
        self._listeners = tuple(started)
        self._thread = threading.Thread(
            target=self._run,
            name=f"node-{self.me.public.hex()[:8]}",
            daemon=True,
        )
        self._thread.start()

    def stop(self, timeout: float = 5.0) -> None:
        self._stopping.set()
        for listener in self._listeners:
            with contextlib.suppress(Exception):
                listener.stop()
        self._listeners = ()
        self.postman.stop()
        thread = self._thread
        self._thread = None
        if thread is not None and thread.is_alive():
            thread.join(timeout=timeout)

    def _run(self) -> None:
        tick_interval_ms = self.tunables.tick_interval
        last_tick = now_ms()
        while not self._stopping.is_set():
            try:
                inbound = self._inbox.get(timeout=tick_interval_ms / 1000)
                self.receive(inbound.frame, now_ms(), session=inbound.session)
            except queue.Empty:
                pass
            now = now_ms()
            if now - last_tick >= tick_interval_ms:
                # A backwards wall-clock step raises out of tick. Unguarded, that is
                # `threading.excepthook` -> `os._exit(70)`.
                with contextlib.suppress(DudeError):
                    self.tick(now)
                last_tick = now

    def _flush_follower(self, now: Millis) -> None:
        for peer, msg in self.follower.outbox():
            if peer not in self.postman.peers:
                continue
            self.sync_adapter.send(peer, msg, now, await_reply=True)

    def _reply(self, to: SignedEnvelope, verb: Verb, body: bytes, now: Millis) -> None:
        if not self.postman.can_reply(to.frm):
            return
        self.postman.mailbox.post(
            to.answer(verb, body).sign(self.me, now), now, self.tunables.net.ttl, await_reply=False
        )


_DISPATCH: dict[Verb, Callable[[Node, SignedEnvelope, Millis], None]] = {
    v: getattr(Node, f"_on_{v.name.lower()}") for v in HANDLED
}
