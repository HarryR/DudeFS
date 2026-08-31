import contextlib
import threading
import time
from abc import ABC, abstractmethod
from collections.abc import Callable, Iterable
from dataclasses import dataclass, field, replace
from enum import Enum, auto

from .. import quorum
from ..consensus.settle_round import SettledBlock, _settle_payload
from ..core import crypto
from ..core.errors import DudeError
from ..core.units import Millis, now_ms
from ..net.address import Endpoint
from ..net.envelope import MessageId, Verb
from ..net.postman import Delivered, Postman
from ..session import KeyCache, SessionRW, Settled, SubmitHandle, SubmitResult, Substrate
from ..store import ops, smt
from ..store.layer import BlockHead, Held
from ..store.management import (
    CERT_PURPOSE_ROSTER,
    CERT_PURPOSE_ROSTER_COMMITMENT,
    Authorization,
    Grant,
    Role,
    RosterCommitment,
)
from ..tunables import Tunables
from . import chain
from .lite_adapter import (
    AnchorsReply,
    GetAnchors,
    GetProof,
    LiteAdapterError,
    LiteMsg,
    LiteRefused,
    ProofReply,
    RosterBundle,
    SyncRefusal,
    TrustedBlock,
    TxStatus,
    TxStatusKind,
    TxStatusReply,
)


class LightClientError(DudeError): ...


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


@dataclass(slots=True)
class PeerView:
    last_block_num: int = 0
    last_activity: Millis = 0
    consecutive_failures: int = 0


class _Pending: ...


PENDING = _Pending()


class Request(ABC):
    mid: MessageId
    peer: crypto.PublicKey

    @abstractmethod
    def resolve(self, client: "LightClient", msg: LiteMsg, now: Millis) -> None: ...
    @abstractmethod
    def expire(self) -> None: ...


@dataclass(slots=True)
class Read(Request):
    mid: MessageId
    peer: crypto.PublicKey
    store_id: int
    name: bytes
    result: GetResult | Failed | None = None

    def poll(self) -> GetResult | Failed | _Pending:
        return PENDING if self.result is None else self.result

    def resolve(self, client: "LightClient", msg: LiteMsg, now: Millis) -> None:
        try:
            client.resolve_read(self, msg, now)
        except DudeError as e:
            self.result = Failed(reason=f"responder reply refused: {e}")
        client._note_read_result(self, now)

    def expire(self) -> None:
        self.result = Failed(reason="request expired")


@dataclass(slots=True)
class _BootstrapRequest(Request):
    mid: MessageId
    peer: crypto.PublicKey

    def resolve(self, client: "LightClient", msg: LiteMsg, now: Millis) -> None:
        try:
            client.on_bootstrap_reply(self.peer, msg, now)
        except DudeError:
            client.forget_bootstrap_peer(self.peer)

    def expire(self) -> None:
        pass


@dataclass(slots=True)
class _BootstrapReply:
    fingerprint: crypto.Digest | None = None
    bundle: RosterBundle | None = None
    anchors_reply: AnchorsReply | None = None


@dataclass(slots=True)
class LightClient:
    me: crypto.Keypair
    anchor: crypto.PublicKey
    postman: Postman

    @property
    def tunables(self) -> Tunables:
        return self.postman.tunables

    state: State = State.UNBOOTSTRAPPED
    trusted_state: TrustedState | None = None

    _bootstrap_peers: dict[crypto.PublicKey, _BootstrapReply] = field(default_factory=dict)
    _inflight: dict[bytes, Request] = field(default_factory=dict)
    _submit_callbacks: dict[bytes, Callable[[int, bytes], None]] = field(
        default_factory=dict, init=False
    )
    _key_cache: KeyCache | None = field(default=None, init=False)
    _peer_views: dict[crypto.PublicKey, PeerView] = field(default_factory=dict, init=False)

    _commit_cond: threading.Condition = field(default_factory=threading.Condition, init=False)
    _commit_seq: int = field(default=0, init=False)
    _stopping: threading.Event = field(default_factory=threading.Event, init=False)
    _thread: threading.Thread | None = field(default=None, init=False)
    _socket_servers: list = field(default_factory=list, init=False)

    def _peer_view(self, peer: crypto.PublicKey) -> PeerView:
        pv = self._peer_views.get(peer)
        if pv is None:
            pv = PeerView()
            self._peer_views[peer] = pv
        return pv

    def _note_read_result(self, req: "Read", now: Millis) -> None:
        pv = self._peer_view(req.peer)
        pv.last_activity = now
        if isinstance(req.result, GetResult):
            pv.last_block_num = req.result.block_num
            pv.consecutive_failures = 0
        elif isinstance(req.result, Failed):
            pv.consecutive_failures += 1

    def add_bootstrap_peer(self, peer: crypto.PublicKey, endpoints: tuple[Endpoint, ...]) -> None:
        self.postman.add_peer(peer, endpoints)
        self._bootstrap_peers[peer] = _BootstrapReply()

    def bootstrap(self, now: Millis) -> None:
        if self.state is not State.UNBOOTSTRAPPED:
            raise LightClientError(f"bootstrap in state {self.state.name}; expected UNBOOTSTRAPPED")
        if not self._bootstrap_peers:
            raise LightClientError("no bootstrap peers registered")
        self.state = State.BOOTSTRAPPING
        self._ask_for_anchors(self._bootstrap_peers, now)

    def _ask_for_anchors(self, peers: Iterable[crypto.PublicKey], now: Millis) -> None:
        req = GetAnchors(known_roster_fingerprint=None, known_trusted_block=None)
        for peer in peers:
            mid = MessageId.random()
            self._inflight[mid.correlation_id] = _BootstrapRequest(mid=mid, peer=peer)
            self.postman.send(peer, req, self.tunables.ttl_lite, mid=mid)

    def _ask_stale_peers(self, now: Millis) -> None:
        waiting = {r.peer for r in self._inflight.values() if isinstance(r, _BootstrapRequest)}
        stale = [
            peer
            for peer, entry in self._bootstrap_peers.items()
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

    def request_get(self, store_id: int, name: bytes, peer: crypto.PublicKey, now: Millis) -> Read:
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
        mid = MessageId.random()
        handle = Read(mid=mid, peer=peer, store_id=store_id, name=name)
        self._inflight[mid.correlation_id] = handle
        self.postman.send(peer, req, self.tunables.ttl_lite, mid=mid)
        return handle

    # -- the run loop -------------------------------------------------------

    def add_socket(self, path: str) -> None:
        from ..net.socket_server import SocketServer  # noqa: PLC0415

        sub = _LiteSubstrate(self)
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
        self.postman.start()
        for srv in self._socket_servers:
            srv.start()
        self._thread = threading.Thread(
            target=self._run,
            name=f"lite-{self.me.public.hex()[:8]}",
            daemon=True,
        )
        self._thread.start()

    def stop(self) -> None:
        self._stopping.set()
        for srv in self._socket_servers:
            srv.stop()
        self.postman.stop()
        thread = self._thread
        self._thread = None
        if thread is not None:
            thread.join()

    def _run(self) -> None:
        tick_interval = self.tunables.tick_interval.as_seconds
        while not self._stopping.is_set():
            now = now_ms()
            activity = False
            for output in self.postman.drain_output(timeout=tick_interval):
                for d in output.delivered:
                    self._on_delivered(d, now)
                    activity = True
                for e in output.expired:
                    req = self._inflight.pop(e.prefix, None)
                    if req is not None:
                        req.expire()
                        self._peer_view(req.peer).consecutive_failures += 1
                        activity = True
            if activity:
                with self._commit_cond:
                    self._commit_seq += 1
                    self._commit_cond.notify_all()
            if self.state is State.BOOTSTRAPPING:
                with contextlib.suppress(DudeError):
                    self._ask_stale_peers(now)

    def _on_delivered(self, d: Delivered, now: Millis) -> None:
        if d.in_reply_to is None:
            return
        if d.verb in (Verb.ACCEPTED, Verb.REFUSED):
            cb = self._submit_callbacks.pop(d.in_reply_to.correlation_id, None)
            if cb is not None:
                cb(d.verb, d.body)
            return
        try:
            msg = LiteMsg.decode(d.verb, d.body)
        except (LiteAdapterError, DudeError):
            return
        req = self._inflight.pop(d.in_reply_to.correlation_id, None)
        if req is None:
            return
        req.resolve(self, msg, now)

    # -- bootstrap ----------------------------------------------------------

    def forget_bootstrap_peer(self, peer: crypto.PublicKey) -> None:
        self._bootstrap_peers.pop(peer, None)

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
        entry = self._bootstrap_peers.setdefault(peer, _BootstrapReply())
        entry.fingerprint = msg.roster_fingerprint
        entry.bundle = msg.bundle
        entry.anchors_reply = msg
        pv = self._peer_view(peer)
        pv.last_block_num = msg.head.anchors.block_num
        pv.last_activity = now
        pv.consecutive_failures = 0
        self._check_bootstrap_convergence(now)

    def _check_bootstrap_convergence(self, now: Millis) -> None:
        agreed: dict[crypto.Digest, list[_BootstrapReply]] = {}
        for entry in self._bootstrap_peers.values():
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

    # -- read resolution ----------------------------------------------------

    def resolve_read(self, req: Read, msg: LiteMsg, now: Millis) -> None:  # noqa: C901, PLR0911
        entry = req
        if isinstance(msg, LiteRefused):
            entry.result = Failed(reason=msg.reason.value)
            if msg.reason in (SyncRefusal.FORK_DETECTED, SyncRefusal.COMPACTED):
                self.state = State.UNBOOTSTRAPPED
                self.trusted_state = None
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
        held = None if msg.absent else (msg.value, msg.credential, msg.epoch)
        if self.trusted_state is None:
            entry.result = Failed(reason="trusted state lost; re-bootstrap")
            return
        if not smt.verify(
            self.trusted_state.head.anchors.state_root,
            entry.store_id,
            entry.name,
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
        return True

    def session(self, store_id: int = 1) -> SessionRW:
        sub = _LiteSubstrate(self)
        return SessionRW(sub, store_id)


@dataclass(slots=True)
class _TxStatusHandle(Request):
    mid: MessageId
    peer: crypto.PublicKey
    result: TxStatusKind | None = None
    block_num: int | None = None
    block_hash: crypto.Digest | None = None

    def resolve(self, client: "LightClient", msg: LiteMsg, now: Millis) -> None:
        if isinstance(msg, TxStatusReply):
            self.result = msg.status
            self.block_num = msg.block_num
            self.block_hash = msg.block_hash
            pv = client._peer_view(self.peer)
            pv.last_activity = now
            pv.consecutive_failures = 0

    def expire(self) -> None:
        self.result = TxStatusKind.UNKNOWN


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
            return list(self._lc._bootstrap_peers)
        head_num = ts.head.anchors.block_num
        views = self._lc._peer_views

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
            req = self._lc.request_get(store, name, peer, now_ms())
            with self._lc._commit_cond:
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
                    self._lc._commit_cond.wait(remaining)
        return None

    def token(self, store_id: int, name: str) -> bytes:
        return self._ensure_cache().token(store_id, name)

    def seal(self, store_id: int, name: str, value: bytes) -> tuple[bytes, bytes, int]:
        return self._ensure_cache().seal(store_id, name, value)

    def decrypt(self, store_id: int, name: str, ciphertext: bytes, epoch: int) -> bytes:
        return self._ensure_cache().decrypt(store_id, name, ciphertext, epoch)

    def submit(self, tx: ops.Transaction) -> SubmitHandle:
        signed = tx.sign(self._lc.me, now_ms())
        peers = self._ranked_peers()
        if not peers:
            raise LightClientError("no peers available")
        ts = self._lc.trusted_state
        count = quorum.corroboration(len(ts.roster)) if ts is not None else 1
        targets = peers[: max(count, 1)]

        mid = MessageId.random()
        handle = SubmitHandle(mid=mid, op_hash=signed.op_hash, _sub=self, peer=targets[0])

        accepted = [False]
        refuse_count = [0]
        total = len(targets)

        for target in targets:
            peer_mid = MessageId.random()

            def cb(verb: int, body: bytes, _peer: crypto.PublicKey = target) -> None:
                pv = self._lc._peer_view(_peer)
                pv.last_activity = now_ms()
                pv.consecutive_failures = 0
                if accepted[0]:
                    return
                if verb == Verb.ACCEPTED:
                    accepted[0] = True
                    handle.peer = _peer
                    handle.resolve(verb, body)
                elif verb == Verb.REFUSED:
                    refuse_count[0] += 1
                    if refuse_count[0] >= total:
                        handle.resolve(verb, body)

            self._lc._submit_callbacks[peer_mid.correlation_id] = cb
            self._lc.postman.send_raw(
                target,
                Verb.SUBMIT,
                signed.raw,
                self._lc.tunables.ttl_exchange,
                mid=peer_mid,
            )

        return handle

    def settled(self, op_hash: crypto.Digest) -> SubmitResult | None:
        peer = self._pick_peer()
        mid = MessageId.random()
        handle = _TxStatusHandle(mid=mid, peer=peer)
        self._lc._inflight[mid.correlation_id] = handle
        self._lc.postman.send(peer, TxStatus(op_hash=op_hash), self._lc.tunables.ttl_lite, mid=mid)
        deadline_ms = now_ms() + self._lc.tunables.ttl_lite
        with self._lc._commit_cond:
            while now_ms() < deadline_ms:
                if handle.result is not None:
                    if (
                        handle.result is TxStatusKind.SETTLED
                        and handle.block_num is not None
                        and handle.block_hash is not None
                    ):
                        return Settled(op_hash, handle.block_num, handle.block_hash)
                    return None
                remaining = Millis(deadline_ms - now_ms()).as_seconds
                if remaining <= 0:
                    break
                self._lc._commit_cond.wait(remaining)
        return None

    def evict_after_sec(self) -> float:
        return self._lc.tunables.evict_after.as_seconds

    def wait_for_commit(self, timeout: float) -> None:
        cap = self._lc.tunables.block_time.as_seconds
        with self._lc._commit_cond:
            self._lc._commit_cond.wait(min(timeout, cap))

    @property
    def commit_cond(self) -> threading.Condition:
        return self._lc._commit_cond

    def commit_generation(self) -> int:
        return self._lc._commit_seq

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


def _verify_bundle(  # noqa: C901, PLR0911
    anchor: crypto.PublicKey, bundle: RosterBundle
) -> bool:
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
