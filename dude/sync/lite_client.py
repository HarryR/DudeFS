from __future__ import annotations

import contextlib
import queue
import threading
from dataclasses import dataclass, field, replace
from enum import Enum, auto

from .. import quorum
from ..consensus.settle_round import SettledBlock, _settle_payload
from ..core import crypto
from ..core.errors import DudeError
from ..core.units import Millis, now_ms
from ..net.address import Endpoint
from ..net.envelope import Frame
from ..net.link import Listener
from ..net.postman import Postman
from ..net.session import Inbound, Session, SessionBindError
from ..store import smt
from ..store.management import (
    CERT_PURPOSE_ROSTER,
    CERT_PURPOSE_ROSTER_COMMITMENT,
    Authorization,
    Grant,
    Role,
    RosterCommitment,
)
from ..tunables import DEFAULT, Tunables
from . import chain
from .lite_adapter import (
    AnchorsReply,
    GetAnchors,
    GetProof,
    LiteAdapter,
    LiteAdapterError,
    LiteMsg,
    LiteRefused,
    ProofReply,
    RosterBundle,
    SyncRefusal,
    TrustedBlock,
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

    head: chain.TrustedHead


@dataclass(slots=True)
class GetResult:
    value: bytes
    absent: bool
    epoch: int
    """Which keyepoch opens `value`, carried under the proof rather than beside it."""
    block_num: int
    state_root: crypto.Digest


@dataclass(slots=True)
class Failed:
    reason: str


class _Pending: ...


PENDING = _Pending()


@dataclass(slots=True)
class _PendingRead:
    store_id: int
    name: bytes
    peer: crypto.PublicKey
    sent_at: Millis
    result: GetResult | Failed | None = None


@dataclass(slots=True)
class _BootstrapReply:
    fingerprint: crypto.Digest | None = None
    bundle: RosterBundle | None = None
    anchors_reply: AnchorsReply | None = None


type OutboxItem = tuple[crypto.PublicKey, bytes]


@dataclass(slots=True)
class LightClient:
    me: crypto.Keypair
    anchor: crypto.PublicKey
    postman: Postman
    tunables: Tunables = DEFAULT
    adapter: LiteAdapter = field(init=False)

    state: State = State.UNBOOTSTRAPPED
    trusted_state: TrustedState | None = None

    _bootstrap_peers: dict[crypto.PublicKey, _BootstrapReply] = field(default_factory=dict)
    _pending_reads: dict[bytes, _PendingRead] = field(default_factory=dict)
    _pending_bootstrap_mids: dict[bytes, crypto.PublicKey] = field(default_factory=dict)

    _inbox: queue.SimpleQueue[Inbound] = field(default_factory=queue.SimpleQueue, init=False)

    _stopping: threading.Event = field(default_factory=threading.Event, init=False)
    _thread: threading.Thread | None = field(default=None, init=False)
    _listeners: tuple[Listener, ...] = field(default=(), init=False)

    def __post_init__(self) -> None:
        self.adapter = LiteAdapter(self.me, self.postman, self.tunables.net.ttl)

    def add_bootstrap_peer(self, peer: crypto.PublicKey, endpoints: tuple[Endpoint, ...]) -> None:
        self.postman.add_peer(peer, endpoints)
        self._bootstrap_peers[peer] = _BootstrapReply()

    def bootstrap(self, now: Millis) -> None:
        if self.state is not State.UNBOOTSTRAPPED:
            raise LightClientError(f"bootstrap in state {self.state.name}; expected UNBOOTSTRAPPED")
        if not self._bootstrap_peers:
            raise LightClientError("no bootstrap peers registered")
        self.state = State.BOOTSTRAPPING
        req = GetAnchors(known_roster_fingerprint=None, known_trusted_block=None)
        for peer in self._bootstrap_peers:
            mid = self.adapter.send(peer, req, now)
            self._pending_bootstrap_mids[mid] = peer

    def bootstrapped(self) -> bool:
        return self.state is State.READY

    def request_get(self, store_id: int, name: bytes, peer: crypto.PublicKey, now: Millis) -> bytes:
        if self.state is not State.READY or self.trusted_state is None:
            raise LightClientError(f"request_get in state {self.state.name}; not READY")
        req = GetProof(
            store_id=store_id,
            name=name,
            block_num=self.trusted_state.head.block_num,
            known_roster_fingerprint=self.trusted_state.roster_fingerprint,
            known_trusted_block=TrustedBlock(
                self.trusted_state.head.block_num, self.trusted_state.head.block_hash
            ),
        )
        mid = self.adapter.send(peer, req, now)
        self._pending_reads[mid] = _PendingRead(
            store_id=store_id, name=name, peer=peer, sent_at=now
        )
        return mid

    def poll(self, request_id: bytes) -> GetResult | Failed | _Pending:
        entry = self._pending_reads.get(request_id)
        if entry is None:
            raise LightClientError(f"unknown request_id {request_id.hex()[:8]}")
        if entry.result is None:
            return PENDING
        result = entry.result
        del self._pending_reads[request_id]
        return result

    def receive(self, frame: Frame, now: Millis, session: Session | None = None) -> None:
        try:
            got = self.postman.deliver(frame, now)
            if session is not None:
                self._bind_session(session, got.envelope.frm)
        except DudeError:
            return
        env = got.envelope
        try:
            msg = LiteMsg.decode(env.env.verb, env.env.body)
        except (LiteAdapterError, DudeError):
            return
        reply_to = env.env.reply_to
        # A RESPONDER'S FRAME IS NOT ALLOWED TO RAISE PAST HERE. `Node.receive` puts its dispatch
        # inside this guard; this one did not, so a `DudeError` from verifying a header -- a
        # multisig bitmap of the wrong width was enough -- unwound through `_run`, which catches
        # only `queue.Empty`, and killed the thread. The listener kept accepting into an inbox
        # nobody drained, so the client looked alive and every read hung for ever.
        if reply_to in self._pending_bootstrap_mids:
            peer = self._pending_bootstrap_mids.pop(reply_to)
            try:
                self._on_bootstrap_reply(peer, msg, now)
            except DudeError:
                self._bootstrap_peers.pop(peer, None)
            return
        if reply_to in self._pending_reads:
            try:
                self._on_read_reply(reply_to, msg, now)
            except DudeError as e:
                # Resolved, not dropped: a read left PENDING never resolves, because nothing
                # times a pending read out.
                entry = self._pending_reads[reply_to]
                entry.result = Failed(reason=f"responder reply refused: {e}")
            return

    def tick(self, now: Millis) -> None:
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
            name=f"lite-{self.me.public.hex()[:8]}",
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
                with contextlib.suppress(DudeError):
                    self.receive(inbound.frame, now_ms(), session=inbound.session)
            except queue.Empty:
                pass
            now = now_ms()
            if now - last_tick >= tick_interval_ms:
                with contextlib.suppress(DudeError):
                    self.tick(now)
                last_tick = now

    def _bind_session(self, session: Session, frm: crypto.PublicKey) -> None:
        was_unbound = session.identity is None
        try:
            session.bind(frm)
        except SessionBindError:
            session.close()
            return
        if was_unbound:
            self.postman.register_session(session)

    def _on_bootstrap_reply(self, peer: crypto.PublicKey, msg: LiteMsg, now: Millis) -> None:
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
        self._check_bootstrap_convergence(now)

    def _check_bootstrap_convergence(self, now: Millis) -> None:
        """`f+1` agreeing AND LIVE. Agreement alone corroborates what the roster WAS; a set of
        stale responders can all agree perfectly about a cluster that has moved on."""
        agreed: dict[crypto.Digest, list[_BootstrapReply]] = {}
        for entry in self._bootstrap_peers.values():
            if entry.fingerprint is None or entry.anchors_reply is None:
                continue
            if chain.is_stale(entry.anchors_reply.head.block.bucket, now, self.tunables):
                continue
            agreed.setdefault(entry.fingerprint, []).append(entry)
        for fingerprint, entries in agreed.items():
            first = entries[0]
            assert first.bundle is not None and first.anchors_reply is not None  # noqa: S101 -- type narrowing for the checker; contract invariants above make this unreachable
            threshold = quorum.corroboration(len(first.bundle.commitment_members))
            if len(entries) >= threshold:
                self._promote_to_ready(fingerprint, entries[0])
                return

    def _promote_to_ready(self, fingerprint: crypto.Digest, corroborated: _BootstrapReply) -> None:
        assert corroborated.bundle is not None and corroborated.anchors_reply is not None  # noqa: S101 -- type narrowing for the checker; contract invariants above make this unreachable
        bundle = corroborated.bundle
        head = corroborated.anchors_reply.head
        self.trusted_state = TrustedState(
            roster=tuple(sorted(bundle.commitment_members)),
            managers=tuple(sorted(g.identity for g in bundle.managers)),
            node_endpoints={rec.identity: rec.endpoints for rec in bundle.entries},
            roster_fingerprint=fingerprint,
            head=chain.TrustedHead(
                head.anchors.block_num, head.block_hash, head.anchors.state_root, head.block.bucket
            ),
        )
        self.state = State.READY

    def _on_read_reply(self, reply_to: bytes, msg: LiteMsg, now: Millis) -> None:  # noqa: PLR0911 -- each return names a distinct way a reply fails to be a trustworthy answer
        entry = self._pending_reads[reply_to]
        if isinstance(msg, LiteRefused):
            entry.result = Failed(reason=msg.reason.value)
            if msg.reason is SyncRefusal.FORK_DETECTED:
                self.state = State.UNBOOTSTRAPPED
                self.trusted_state = None
            return
        if not isinstance(msg, ProofReply):
            entry.result = Failed(reason="unexpected reply verb")
            return
        assert self.trusted_state is not None  # noqa: S101 -- type narrowing for the checker; contract invariants above make this unreachable
        # A MOVED FINGERPRINT MEANS RE-BOOTSTRAP, never adopt-in-place. Adopting a roster from
        # one responder let a granted-then-revoked manager hand a client a roster of its own keys,
        # proven end-to-end. Corroboration is f+1 at bootstrap or it is nothing.
        if msg.roster_fingerprint != self.trusted_state.roster_fingerprint:
            entry.result = Failed(reason="roster changed; re-bootstrap")
            self.state = State.UNBOOTSTRAPPED
            self.trusted_state = None
            return
        if not self._advance_head(msg.headers, msg.head):
            entry.result = Failed(reason="header chain-link or settle_sigs verify failed")
            return
        assert self.trusted_state is not None  # noqa: S101 -- _advance_head keeps it non-None
        if self.trusted_state.head.block_hash != msg.head.block_hash:
            # More blocks behind than one reply carries headers for. We ADVANCED by what it did
            # carry, so a retry closes the gap; verifying this proof against a root we have not
            # walked to would be trusting the responder for the very thing the proof is for.
            entry.result = Failed(reason="behind the responder; retry")
            return
        if chain.is_stale(self.trusted_state.head.bucket, now, self.tunables):
            # Everything about this reply verifies. It is simply not CURRENT, and no signature
            # can say so -- an old quorum-signed head is a valid one.
            entry.result = Failed(reason="responder head is stale")
            return
        try:
            proof = smt.Proof.decode(msg.proof)
        except DudeError:
            entry.result = Failed(reason="malformed proof")
            return
        held = None if msg.absent else (msg.value, msg.credential, msg.epoch)
        assert self.trusted_state is not None  # noqa: S101 -- narrowing; _advance_head keeps it non-None on success
        if not smt.verify(
            self.trusted_state.head.state_root,
            entry.store_id,
            entry.name,
            held,
            proof,
        ):
            entry.result = Failed(reason="proof-verify-failed")
            return
        entry.result = GetResult(
            value=msg.value,
            absent=msg.absent,
            epoch=msg.epoch,
            block_num=msg.head.anchors.block_num,
            state_root=msg.head.anchors.state_root,
        )

    def _advance_head(
        self, headers: tuple[SettledBlock, ...], responder_head: SettledBlock
    ) -> bool:
        assert self.trusted_state is not None  # noqa: S101 -- type narrowing for the checker; contract invariants above make this unreachable
        ts = self.trusted_state
        above = _contiguous_from(ts.head.block_num, (*headers, responder_head))
        if not above:
            return True  # the responder is at our head or behind it; nothing to walk
        walked = chain.advance(ts.head.block_hash, above, ts.roster, self.anchor)
        if isinstance(walked, chain.ChainRefusal):
            return False
        self.trusted_state = replace(ts, head=walked)
        return True


def _contiguous_from(head_num: int, offered: tuple[SettledBlock, ...]) -> tuple[SettledBlock, ...]:
    """The unbroken run starting at `head_num + 1`, and nothing past the first gap. `headers` is
    capped, so on a far-behind client the responder's own head arrives detached from the run --
    walking it anyway is a BROKEN_LINK that fails the whole read instead of advancing by what
    actually arrived."""
    by_num = {b.anchors.block_num: b for b in offered}
    run: list[SettledBlock] = []
    n = head_num + 1
    while (b := by_num.get(n)) is not None:
        run.append(b)
        n += 1
    return tuple(run)


def _verify_bundle(  # noqa: C901, PLR0911 -- verification pipeline; each early-return names a distinct failure mode
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
    "State",
    "TrustedState",
]
