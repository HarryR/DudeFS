import threading
import time
from abc import ABC
from collections.abc import Callable, Iterable
from dataclasses import dataclass, replace
from enum import Enum, auto

from .. import quorum
from ..consensus.settle_round import SettledBlock, _settle_payload
from ..core import crypto
from ..core.errors import DudeError
from ..core.event_loop import Event, EventLoop, Scheduled
from ..core.units import Millis
from ..net.address import Endpoint
from ..net.envelope import Verb
from ..net.postman import Delivered, Output, Postman
from ..net.socket_server import SocketServer
from ..participant import Participant
from ..session import (
    InflightHandle,
    KeyCache,
    SessionProvider,
    SessionRW,
    SettleResult,
    SubmitHandle,
    Substrate,
    TxStatusTimeoutError,
    Unknown,
)
from ..store import ops, smt
from ..store.layer import BlockHead
from ..store.management import (
    CERT_PURPOSE_ROSTER,
    CERT_PURPOSE_ROSTER_COMMITMENT,
    Authorization,
    Grant,
    Role,
    RosterCommitment,
)
from ..store.ops import Held, Sealed
from . import chain
from .lite_adapter import (
    AnchorsReply,
    CountPrefix,
    CountPrefixReply,
    GetAnchors,
    GetProof,
    LiteAdapterError,
    LiteMsg,
    LiteRefused,
    NthPrefix,
    ProofReply,
    RosterBundle,
    SyncRefusedReason,
    TrustedBlock,
    TxStatus,
)


class LightClientError(DudeError): ...


class _LiteEvent(Event, ABC):
    __slots__ = ()


@dataclass(frozen=True, slots=True)
class _LiteDelivered(_LiteEvent):
    delivered: Delivered


@dataclass(frozen=True, slots=True)
class _LiteExpired(_LiteEvent):
    prefix: bytes


class _CheckStalePeers(_LiteEvent):
    __slots__ = ()


class State(Enum):
    UNBOOTSTRAPPED = auto()

    BOOTSTRAPPING = auto()

    READY = auto()

    FAILED = auto()


@dataclass(frozen=True, slots=True)
class TrustedState:
    roster: tuple[crypto.PublicKey, ...]

    managers: tuple[crypto.PublicKey, ...]

    node_endpoints: dict[crypto.PublicKey, tuple[Endpoint, ...]]

    roster_fingerprint: crypto.Digest

    head: SettledBlock


@dataclass(slots=True)
class GetResult:
    value: bytes
    credential: bytes
    absent: bool
    epoch: int
    block_num: int
    state_root: crypto.Digest


@dataclass(slots=True)
class Failed:
    reason: str


ZERO_MILLIS = Millis(0)


@dataclass(slots=True)
class PeerView:
    last_block_num: int = 0
    last_activity: Millis = ZERO_MILLIS
    consecutive_failures: int = 0


class _Pending: ...


PENDING = _Pending()


@dataclass(slots=True)
class Read(InflightHandle):
    peer: crypto.PublicKey
    client: "LightClient"
    store_id: int
    name: bytes
    result: GetResult | Failed | None = None

    def poll(self) -> GetResult | Failed | _Pending:
        return PENDING if self.result is None else self.result

    def on_reply(self, verb: Verb, body: bytes) -> None:
        now = Millis.now()
        try:
            msg = LiteMsg.decode(verb, body)
        except (LiteAdapterError, DudeError):
            self.result = Failed(reason="malformed reply")
            return
        try:
            self.client.resolve_read(self, msg, now)
        except DudeError as e:
            self.result = Failed(reason=f"responder reply refused: {e}")
        self.client.note_read_result(self, now)

    def on_expired(self) -> None:
        self.result = Failed(reason="request expired")


@dataclass(slots=True)
class _BootstrapRequest(InflightHandle):
    peer: crypto.PublicKey
    client: "LightClient"

    def on_reply(self, verb: Verb, body: bytes) -> None:
        now = Millis.now()
        try:
            msg = LiteMsg.decode(verb, body)
        except (LiteAdapterError, DudeError):
            return
        try:
            self.client.on_bootstrap_reply(self.peer, msg, now)
        except DudeError:
            self.client.forget_bootstrap_peer(self.peer)

    def on_expired(self) -> None:
        pass


@dataclass(slots=True)
class _BootstrapReply:
    fingerprint: crypto.Digest | None = None
    bundle: RosterBundle | None = None
    anchors_reply: AnchorsReply | None = None


class LightClient(Participant, SessionProvider):
    def __init__(
        self,
        me: crypto.Keypair,
        anchor: crypto.PublicKey,
        postman: Postman,
    ) -> None:
        super().__init__(me, postman)
        self.anchor = anchor

        self.state: State = State.UNBOOTSTRAPPED
        self.trusted_state: TrustedState | None = None
        self.bootstrap_peers: dict[crypto.PublicKey, _BootstrapReply] = {}
        self._key_cache: KeyCache | None = None
        self.peer_views: dict[crypto.PublicKey, PeerView] = {}

        self.on_ready: Callable[[TrustedState], None] | None = None
        self.on_block: Callable[[SettledBlock], None] | None = None
        self.on_trust_lost: Callable[[], None] | None = None

        self._stale_timer: Scheduled[_LiteEvent] | None = None
        self._socket_servers: list[SocketServer] = []

        self._init_loop()

    def peer_view(self, peer: crypto.PublicKey) -> PeerView:
        pv = self.peer_views.get(peer)
        if pv is None:
            pv = PeerView()
            self.peer_views[peer] = pv
        return pv

    def note_read_result(self, req: "Read", now: Millis) -> None:
        pv = self.peer_view(req.peer)
        pv.last_activity = now
        if isinstance(req.result, GetResult):
            pv.last_block_num = req.result.block_num
            pv.consecutive_failures = 0
        elif isinstance(req.result, Failed):
            pv.consecutive_failures += 1

    def add_bootstrap_peer(self, peer: crypto.PublicKey, endpoints: tuple[Endpoint, ...]) -> None:
        self.postman.add_peer(peer, endpoints)
        self.bootstrap_peers[peer] = _BootstrapReply()

    def bootstrap(self, timeout: float | None = None, now: Millis | None = None) -> None:
        if self.state is State.READY:
            return
        if self.state is State.UNBOOTSTRAPPED:
            if not self.bootstrap_peers:
                raise LightClientError("no bootstrap peers registered")
            self.state = State.BOOTSTRAPPING
            self._ask_for_anchors(self.bootstrap_peers, now or Millis.now())
        budget = timeout if timeout is not None else self.tunables.evict_after.as_seconds
        deadline = time.monotonic() + budget
        while time.monotonic() < deadline:
            if self.state is State.READY:
                return
            time.sleep(self.tunables.rtt_max.as_seconds)
        raise LightClientError("bootstrap did not converge")

    def _ask_for_anchors(self, peers: Iterable[crypto.PublicKey], _now: Millis) -> None:
        req = GetAnchors(known_roster_fingerprint=None, known_trusted_block=None)
        for peer in peers:
            handle = _BootstrapRequest(peer=peer, client=self)
            self.request(peer, req, self.tunables.ttl_lite, handle)

    def _ask_stale_peers(self, now: Millis) -> None:
        waiting = {r.peer for r in self.inflight.pending_of_type(_BootstrapRequest)}
        stale = [
            peer
            for peer, entry in self.bootstrap_peers.items()
            if peer not in waiting
            and (
                entry.anchors_reply is None
                or chain.is_stale(entry.anchors_reply.head.block.bucket, now, self.tunables)
            )
        ]
        if stale:
            self._ask_for_anchors(stale, now)

    def bootstrapped(self) -> bool:
        return self.state is State.READY

    def request_get(self, store_id: int, name: bytes, peer: crypto.PublicKey, _now: Millis) -> Read:
        if self.state is not State.READY or self.trusted_state is None:
            raise LightClientError(f"request_get in state {self.state.name}; not READY")
        req = GetProof(
            store_id=store_id,
            name=name,
            block_num=self.trusted_state.head.anchors.block_num,
            known_roster_fingerprint=self.trusted_state.roster_fingerprint,
            known_trusted_block=TrustedBlock(
                self.trusted_state.head.anchors.block_num, self.trusted_state.head.block_hash
            ),
        )
        handle = Read(peer=peer, client=self, store_id=store_id, name=name)
        self.request(peer, req, self.tunables.ttl_lite, handle)
        return handle

    # -- the run loop -------------------------------------------------------

    def add_socket(self, path: str) -> SocketServer:
        sub = _LiteSubstrate(self)
        srv = SocketServer(path, sub)
        self._socket_servers.append(srv)
        return srv

    def __enter__(self):
        self.start()
        self.bootstrap()
        return self

    def __exit__(self, *_: object) -> None:
        self.stop()

    def _init_loop(self) -> None:
        self._loop = EventLoop()
        self._loop.register(_LiteDelivered, self._on_lite_delivered)
        self._loop.register(_LiteExpired, self._on_lite_expired)
        self._loop.register(_CheckStalePeers, self._on_check_stale_peers)

        def _on_postman_output(out: Output) -> None:
            for d in out.delivered:
                self._loop.post(_LiteDelivered(d))
            for e in out.expired:
                self._loop.post(_LiteExpired(e.prefix))

        self.postman.on_output = _on_postman_output

    def start(self) -> None:
        if self._loop.running:
            return
        self.postman.start()
        for srv in self._socket_servers:
            srv.start()
        self._loop.start()
        if self.state is State.UNBOOTSTRAPPED and self.bootstrap_peers:
            self.state = State.BOOTSTRAPPING
            self._ask_for_anchors(self.bootstrap_peers, Millis.now())
            self._schedule_stale_check()

    def stop(self) -> None:
        self._loop.stop()
        for srv in self._socket_servers:
            srv.stop()
        self.postman.stop()

    # -- event handlers --------------------------------------------------------

    def _on_lite_delivered(self, event: _LiteDelivered) -> None:
        self._on_delivered(event.delivered)

    def _on_delivered(self, d: Delivered) -> None:
        if d.in_reply_to is None:
            if d.verb == Verb.HEIGHT_REPLY:
                with self.commit_cond:
                    self.commit_seq += 1
                    self.commit_cond.notify_all()
            return
        if self.inflight.on_reply(d.in_reply_to.correlation_id, d.verb, d.body):
            with self.commit_cond:
                self.commit_cond.notify_all()

    def _on_lite_expired(self, event: _LiteExpired) -> None:
        self.inflight.on_expired(event.prefix)
        with self.commit_cond:
            self.commit_cond.notify_all()

    def _on_check_stale_peers(self, _event: _CheckStalePeers) -> None:
        self._stale_timer = None
        if self.state is State.BOOTSTRAPPING:
            self._ask_stale_peers(Millis.now())
            self._schedule_stale_check()

    def _schedule_stale_check(self) -> None:
        if self._stale_timer is not None:
            self._stale_timer.cancel()
        self._stale_timer = self._loop.schedule(
            Millis.now() + self.tunables.poll_interval, _CheckStalePeers()
        )

    # -- bootstrap ----------------------------------------------------------

    def forget_bootstrap_peer(self, peer: crypto.PublicKey) -> None:
        self.bootstrap_peers.pop(peer, None)

    def on_bootstrap_reply(self, peer: crypto.PublicKey, msg: LiteMsg, now: Millis) -> None:
        if self.state is not State.BOOTSTRAPPING:
            return
        if isinstance(msg, LiteRefused):
            self._check_bootstrap_convergence(now)
            return
        if not isinstance(msg, AnchorsReply):
            return
        if msg.bundle is None:
            return
        if not _verify_bundle(self.anchor, msg.bundle):
            return
        if not _verify_settle_sigs_against_bundle(self.anchor, msg, msg.bundle):
            return
        entry = self.bootstrap_peers.setdefault(peer, _BootstrapReply())
        entry.fingerprint = msg.roster_fingerprint
        entry.bundle = msg.bundle
        entry.anchors_reply = msg
        pv = self.peer_view(peer)
        pv.last_block_num = msg.head.anchors.block_num
        pv.last_activity = now
        pv.consecutive_failures = 0
        self._check_bootstrap_convergence(now)

    def _check_bootstrap_convergence(self, now: Millis) -> None:
        agreed: dict[crypto.Digest, list[_BootstrapReply]] = {}
        for entry in self.bootstrap_peers.values():
            if entry.fingerprint is None or entry.anchors_reply is None:
                continue
            if chain.is_stale(entry.anchors_reply.head.block.bucket, now, self.tunables):
                continue
            agreed.setdefault(entry.fingerprint, []).append(entry)
        for fingerprint, entries in agreed.items():
            first = entries[0]
            if first.bundle is None or first.anchors_reply is None:
                continue
            threshold = quorum.corroboration(len(first.bundle.commitment_members))
            if len(entries) >= threshold:
                self._promote_to_ready(fingerprint, entries[0])
                return

    def _promote_to_ready(self, fingerprint: crypto.Digest, corroborated: _BootstrapReply) -> None:
        if corroborated.bundle is None or corroborated.anchors_reply is None:
            raise LightClientError("promote_to_ready with incomplete bootstrap reply")
        bundle = corroborated.bundle
        head = corroborated.anchors_reply.head
        self.trusted_state = TrustedState(
            roster=tuple(sorted(bundle.commitment_members)),
            managers=tuple(sorted(g.identity for g in bundle.managers)),
            node_endpoints={rec.identity: rec.endpoints for rec in bundle.entries},
            roster_fingerprint=fingerprint,
            head=head,
        )
        self.state = State.READY
        if self.on_ready is not None:
            self.on_ready(self.trusted_state)

    # -- read resolution ----------------------------------------------------

    def resolve_read(self, req: Read, msg: LiteMsg, now: Millis) -> None:
        entry = req
        if isinstance(msg, LiteRefused):
            entry.result = Failed(reason=msg.reason.value)
            if msg.reason in (SyncRefusedReason.FORK_DETECTED, SyncRefusedReason.COMPACTED):
                self.state = State.UNBOOTSTRAPPED
                self.trusted_state = None
                if self.on_trust_lost is not None:
                    self.on_trust_lost()
            return
        if not isinstance(msg, ProofReply):
            entry.result = Failed(reason="unexpected reply verb")
            return
        if self.trusted_state is None:
            entry.result = Failed(reason="trusted state lost; re-bootstrap")
            return
        if msg.roster_fingerprint != self.trusted_state.roster_fingerprint:
            entry.result = Failed(reason="roster changed; re-bootstrap")
            self.state = State.UNBOOTSTRAPPED
            self.trusted_state = None
            if self.on_trust_lost is not None:
                self.on_trust_lost()
            return
        if not self._advance_head(msg.headers, msg.head):
            entry.result = Failed(reason="header chain-link or settle_sigs verify failed")
            return
        if self.trusted_state is None:
            entry.result = Failed(reason="trusted state lost; re-bootstrap")
            return
        if self.trusted_state.head.block_hash != msg.head.block_hash:
            entry.result = Failed(reason="behind the responder; retry")
            return
        if chain.is_stale(self.trusted_state.head.block.bucket, now, self.tunables):
            entry.result = Failed(reason="responder head is stale")
            return
        try:
            proof = smt.Proof.decode(msg.proof)
        except DudeError:
            entry.result = Failed(reason="malformed proof")
            return
        if msg.name != entry.name:
            entry.result = Failed(reason="reply name does not match request")
            return
        held = None if msg.absent else Held(msg.value, msg.epoch, msg.credential)
        if self.trusted_state is None:
            entry.result = Failed(reason="trusted state lost; re-bootstrap")
            return
        if not smt.verify(
            self.trusted_state.head.anchors.state_root,
            entry.store_id,
            msg.name,
            held,
            proof,
        ):
            entry.result = Failed(reason="proof-verify-failed")
            return
        entry.result = GetResult(
            value=msg.value,
            credential=msg.credential,
            absent=msg.absent,
            epoch=msg.epoch,
            block_num=msg.head.anchors.block_num,
            state_root=msg.head.anchors.state_root,
        )

    def _advance_head(
        self, headers: tuple[SettledBlock, ...], responder_head: SettledBlock
    ) -> bool:
        if self.trusted_state is None:
            return False
        ts = self.trusted_state
        above = _contiguous_from(ts.head.anchors.block_num, (*headers, responder_head))
        if not above:
            return True
        walked = chain.advance(ts.head.block_hash, above, ts.roster, self.anchor)
        if isinstance(walked, chain.ChainRefusal):
            return False
        self.trusted_state = replace(ts, head=walked)
        if self.on_block is not None:
            self.on_block(walked)
        return True

    def substrate(self) -> Substrate:
        return _LiteSubstrate(self)

    def session_rw(self, store_id: int = ops.STORE_DATA) -> SessionRW:
        return SessionRW(self.substrate(), store_id)


@dataclass(slots=True)
class _TxStatusHandle(InflightHandle):
    peer: crypto.PublicKey
    client: "LightClient"
    result: SettleResult | None = None

    def on_reply(self, verb: Verb, body: bytes) -> None:
        if verb != Verb.TX_STATUS_REPLY:
            return
        self.result = SettleResult.decode(body)
        pv = self.client.peer_view(self.peer)
        pv.last_activity = Millis.now()
        pv.consecutive_failures = 0

    def on_expired(self) -> None:
        self.result = Unknown()


@dataclass(slots=True)
class _SubmitFanOut:
    handle: SubmitHandle
    total: int
    client: "LightClient"
    accepted: bool = False
    refuse_count: int = 0


@dataclass(slots=True)
class _SubmitPeerHandle(InflightHandle):
    peer: crypto.PublicKey
    fan: _SubmitFanOut

    def on_reply(self, verb: Verb, body: bytes) -> None:
        pv = self.fan.client.peer_view(self.peer)
        pv.last_activity = Millis.now()
        pv.consecutive_failures = 0
        if self.fan.accepted:
            return
        if verb == Verb.ACCEPTED:
            self.fan.accepted = True
            self.fan.handle.peer = self.peer
            self.fan.handle.on_reply(verb, body)
        elif verb == Verb.REFUSED:
            self.fan.refuse_count += 1
            if self.fan.refuse_count >= self.fan.total:
                self.fan.handle.on_reply(verb, body)

    def on_expired(self) -> None:
        pass


@dataclass(slots=True)
class _PrefixCountHandle(InflightHandle):
    count: int | None = None

    def on_reply(self, verb: Verb, body: bytes) -> None:
        if verb == Verb.COUNT_PREFIX_REPLY:
            try:
                msg = CountPrefixReply.decode_inner(body)
                self.count = msg.count
            except (LiteAdapterError, DudeError):
                self.count = 0

    def on_expired(self) -> None:
        self.count = 0


@dataclass(slots=True)
class _PrefixNthHandle(InflightHandle):
    store_id: int
    lc: "LightClient"
    done: bool = False
    result: tuple[bytes, Held] | None = None

    def on_reply(self, verb: Verb, body: bytes) -> None:
        if verb == Verb.LITE_REFUSED:
            self.done = True
            return
        if verb != Verb.PROOF_REPLY:
            self.done = True
            return
        try:
            msg = ProofReply.decode_inner(body)
        except (LiteAdapterError, DudeError):
            self.done = True
            return
        if msg.absent:
            self.done = True
            return
        if not self.lc._advance_head(msg.headers, msg.head):  # noqa: SLF001
            self.done = True
            return
        ts = self.lc.trusted_state
        if ts is None:
            self.done = True
            return
        held = Held(msg.value, msg.epoch, msg.credential)
        try:
            proof = smt.Proof.decode(msg.proof)
        except DudeError:
            self.done = True
            return
        if not smt.verify(ts.head.anchors.state_root, self.store_id, msg.name, held, proof):
            self.done = True
            return
        self.result = (msg.name, Held(msg.value, msg.epoch, msg.credential))
        self.done = True

    def on_expired(self) -> None:
        self.done = True


class _LiteSubstrate(Substrate):
    __slots__ = ("_key_cache", "_lc")

    def __init__(self, lc: LightClient) -> None:
        self._lc = lc
        self._key_cache: KeyCache | None = None

    def _ensure_cache(self) -> KeyCache:
        if self._key_cache is None:
            self._key_cache = KeyCache(self._lc.me, self)
        return self._key_cache

    def anchor(self) -> crypto.PublicKey:
        return self._lc.anchor

    def _ranked_peers(self) -> list[crypto.PublicKey]:
        ts = self._lc.trusted_state
        if ts is None or not ts.roster:
            return list(self._lc.bootstrap_peers)
        head_num = ts.head.anchors.block_num
        views = self._lc.peer_views

        def rank(peer: crypto.PublicKey) -> tuple[int, int, int]:
            pv = views.get(peer)
            if pv is None:
                return (1, 0, 0)
            in_sync = 1 if pv.last_block_num >= head_num else 0
            return (in_sync, -pv.consecutive_failures, pv.last_block_num)

        return sorted(ts.roster, key=rank, reverse=True)

    def _pick_peer(self) -> crypto.PublicKey:
        ranked = self._ranked_peers()
        if not ranked:
            raise LightClientError("no peers available")
        return ranked[0]

    def get(self, store: int, name: bytes) -> Held | None:
        deadline = time.monotonic() + self._lc.tunables.ttl_lite.as_seconds
        while time.monotonic() < deadline:
            peer = self._pick_peer()
            req = self._lc.request_get(store, name, peer, Millis.now())
            with self._lc.commit_cond:
                while time.monotonic() < deadline:
                    result = req.poll()
                    if isinstance(result, GetResult):
                        if result.absent:
                            return None
                        return Held(result.value, result.epoch, result.credential)
                    if isinstance(result, Failed):
                        break
                    remaining = deadline - time.monotonic()
                    if remaining <= 0:
                        break
                    self._lc.commit_cond.wait(remaining)
        return None

    def token(self, store_id: int, name: str, *, plaintext: bool = False) -> bytes:
        return self._ensure_cache().token(store_id, name, plaintext=plaintext)

    def seal(self, store_id: int, name: str, value: bytes, *, plaintext: bool = False) -> Sealed:
        return self._ensure_cache().seal(store_id, name, value, plaintext=plaintext)

    def decrypt(self, store_id: int, name: str, ciphertext: bytes, epoch: int) -> bytes:
        return self._ensure_cache().decrypt(store_id, name, ciphertext, epoch)

    def count_prefix(self, store: int, prefix: bytes) -> int:
        peer = self._pick_peer()
        handle = _PrefixCountHandle()
        self._lc.request(
            peer,
            CountPrefix(store_id=store, prefix=prefix),
            self._lc.tunables.ttl_lite,
            handle,
        )
        deadline_ms = Millis.now() + self._lc.tunables.ttl_lite
        with self._lc.commit_cond:
            while Millis.now() < deadline_ms:
                if handle.count is not None:
                    return handle.count
                remaining = Millis(deadline_ms - Millis.now()).as_seconds
                if remaining <= 0:
                    break
                self._lc.commit_cond.wait(remaining)
        return 0

    def nth_prefix(
        self, store: int, prefix: bytes, n: int, *, descending: bool = False
    ) -> tuple[bytes, Held] | None:
        ts = self._lc.trusted_state
        if ts is None:
            return None
        peer = self._pick_peer()
        handle = _PrefixNthHandle(store_id=store, lc=self._lc)
        self._lc.request(
            peer,
            NthPrefix(
                store_id=store,
                prefix=prefix,
                n=n,
                descending=descending,
                block_num=ts.head.anchors.block_num,
                known_roster_fingerprint=ts.roster_fingerprint,
                known_trusted_block=TrustedBlock(
                    ts.head.anchors.block_num,
                    ts.head.block_hash,
                ),
            ),
            self._lc.tunables.ttl_lite,
            handle,
        )
        deadline_ms = Millis.now() + self._lc.tunables.ttl_lite
        with self._lc.commit_cond:
            while Millis.now() < deadline_ms:
                if handle.done:
                    return handle.result
                remaining = Millis(deadline_ms - Millis.now()).as_seconds
                if remaining <= 0:
                    break
                self._lc.commit_cond.wait(remaining)
        return None

    def submit(self, tx: ops.Transaction) -> SubmitHandle:
        signed = tx.sign(self._lc.me, Millis.now())
        peers = self._ranked_peers()
        if not peers:
            raise LightClientError("no peers available")
        ts = self._lc.trusted_state
        count = quorum.corroboration(len(ts.roster)) if ts is not None else 1
        targets = peers[: max(count, 1)]

        handle = SubmitHandle(
            op_hash=signed.op_hash,
            _sub=self,
            peer=targets[0],
        )
        fan = _SubmitFanOut(handle=handle, total=len(targets), client=self._lc)

        for target in targets:
            self._lc.request_raw(
                target,
                Verb.SUBMIT,
                signed.raw,
                self._lc.tunables.ttl_exchange,
                _SubmitPeerHandle(peer=target, fan=fan),
            )

        return handle

    def tx_status(self, op_hash: crypto.Digest) -> SettleResult:
        peer = self._pick_peer()
        handle = _TxStatusHandle(peer=peer, client=self._lc)
        self._lc.request(peer, TxStatus(op_hash=op_hash), self._lc.tunables.ttl_lite, handle)
        deadline_ms = Millis.now() + self._lc.tunables.ttl_lite
        with self._lc.commit_cond:
            while Millis.now() < deadline_ms:
                if handle.result is not None:
                    return handle.result
                remaining = Millis(deadline_ms - Millis.now()).as_seconds
                if remaining <= 0:
                    break
                self._lc.commit_cond.wait(remaining)
        raise TxStatusTimeoutError("no reply from consensus node")

    def evict_after_sec(self) -> float:
        return self._lc.tunables.evict_after.as_seconds

    def wait_for_commit(self, timeout: float, since: int = -1) -> None:
        cap = self._lc.tunables.block_time.as_seconds
        with self._lc.commit_cond:
            if since >= 0:
                self._lc.commit_cond.wait_for(
                    lambda: self._lc.commit_seq > since, timeout=min(timeout, cap)
                )
            else:
                self._lc.commit_cond.wait(min(timeout, cap))

    @property
    def commit_cond(self) -> threading.Condition:
        return self._lc.commit_cond

    @property
    def commit_seq(self) -> int:
        return self._lc.commit_seq

    def head(self) -> BlockHead | None:
        ts = self._lc.trusted_state
        if ts is None:
            return None
        return BlockHead(ts.head.anchors.block_num, ts.head.block_hash)


def _contiguous_from(head_num: int, offered: tuple[SettledBlock, ...]) -> tuple[SettledBlock, ...]:
    by_num = {b.anchors.block_num: b for b in offered}
    run: list[SettledBlock] = []
    n = head_num + 1
    while (b := by_num.get(n)) is not None:
        run.append(b)
        n += 1
    return tuple(run)


def _verify_bundle(anchor: crypto.PublicKey, bundle: RosterBundle) -> bool:
    manager_pubkeys: set[crypto.PublicKey] = set()
    for grant in bundle.managers:
        if not _verify_grant_cert(grant, anchor, expected_role=Role.MANAGER):
            return False
        manager_pubkeys.add(grant.identity)
    signer = bundle.commitment_cert.signer
    if signer != anchor and signer not in manager_pubkeys:
        return False
    if bundle.commitment_cert.purpose != CERT_PURPOSE_ROSTER_COMMITMENT:
        return False
    if not bundle.commitment_cert.verify():
        return False
    expected_subject = crypto.h(
        RosterCommitment.content(
            bundle.commitment_serial,
            bundle.commitment_members,
            RosterCommitment.fingerprint(bundle.entries),
        )
    )
    if bundle.commitment_cert.subject != expected_subject:
        return False
    for rec in bundle.entries:
        if rec.cert.subject != rec.identity:
            return False
        if rec.cert.purpose != CERT_PURPOSE_ROSTER:
            return False
        if not rec.cert.verify():
            return False
        entry_signer = rec.cert.signer
        if entry_signer != anchor and entry_signer not in manager_pubkeys:
            return False
    return True


def _verify_grant_cert(grant: Grant, anchor: crypto.PublicKey, expected_role: Role) -> bool:
    if grant.role is not expected_role:
        return False
    cert = grant.cert
    if cert.subject != bytes(grant.identity):
        return False
    if cert.purpose != expected_role.value:
        return False
    if not cert.verify():
        return False
    return not (expected_role in (Role.MANAGER, Role.COMPACTOR) and cert.signer != anchor)


def _verify_settle_sigs_against_bundle(
    anchor: crypto.PublicKey, reply: AnchorsReply, bundle: RosterBundle
) -> bool:
    roster = tuple(sorted(bundle.commitment_members))
    head = reply.head
    payload = _settle_payload(head.block.slice_hash, head.anchors)
    return Authorization(head.multisig, payload, roster, anchor).verify()


__all__ = [
    "PENDING",
    "Failed",
    "GetResult",
    "LightClient",
    "LightClientError",
    "PeerView",
    "State",
    "TrustedState",
]
