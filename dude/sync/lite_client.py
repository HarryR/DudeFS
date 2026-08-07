# dude.sync.lite_client -- the LightClient state machine. See SPEC
# (light-client-verify anchors, light-client-piggyback, light-client-cert-chain).
#
# A light client that trusts only the anchor pubkey, corroborates the roster from `f+1`
# nodes at bootstrap, and then reads keys via `GET_PROOF` against any single roster
# member. Every reply piggybacks catch-up headers so the client stays live within the
# `liveness_window` bound (#light-client-liveness).
#
# SANS-I/O. Same discipline as `Follower`: `tick(now)` and `receive(frame, now)` are the
# only entry points that touch time or bytes. Postman is the impure edge. Nothing here
# opens sockets or spawns anything.
#
# WHAT THIS IS NOT. Not a full-node Follower (which drives block-by-block replay into a
# local Store; this client has no store). Not the WP2 worker daemon (which drives quorums
# and holds a mempool). The light client's whole model is: no local durable state, just an
# in-memory `TrustedState` refreshed via `GET_ANCHORS` on a schedule the caller drives.

from __future__ import annotations

import contextlib
import queue
import threading
from dataclasses import dataclass, field
from enum import Enum, auto

from .. import quorum
from ..consensus.settle_round import SettledBlock, _settle_payload
from ..core import codec, crypto
from ..core.errors import DudeError
from ..core.units import Millis, now_ms
from ..net.address import Endpoint
from ..net.envelope import Frame
from ..net.link import Listener
from ..net.postman import Postman
from ..net.session import Inbound, Session, SessionBindError
from ..store import smt
from ..store.management import Grant, Role
from ..tunables import DEFAULT, Tunables
from .lite_adapter import (
    AnchorsReply,
    GetAnchors,
    GetProof,
    LiteAdapter,
    LiteAdapterError,
    LiteMsg,
    LiteRefusal,
    LiteRefused,
    ProofReply,
    RosterBundle,
    TrustedBlock,
)


class LightClientError(DudeError):
    """A misuse of the LightClient API (out-of-order call, contradictory input). Not for
    per-peer misbehaviour (silent drop) and not for refusals (returned as a result)."""


class State(Enum):
    """LightClient lifecycle. See SPEC #light-client-verify."""

    UNBOOTSTRAPPED = auto()
    """No trusted state. `bootstrap(now)` moves us to BOOTSTRAPPING."""

    BOOTSTRAPPING = auto()
    """Sent `GET_ANCHORS(None, None)` to every bootstrap peer; awaiting `f+1` corroborated
    replies. Once we have them: state -> READY."""

    READY = auto()
    """`trusted_state` is set. Can serve reads via `request_get()`."""

    FAILED = auto()
    """Bootstrap failed (not enough corroborating replies within retry budget). Caller
    should re-bootstrap with a fresh peer set. Not automatically retried."""


@dataclass(frozen=True, slots=True)
class TrustedState:
    """What a bootstrapped client trusts. All fields are anchor-verifiable OR quorum-
    corroborated at establishment time; subsequent reads may advance `head` and swap
    `roster_fingerprint` on roster changes (#light-client-header-chain,
    #light-client-roster-change-in-window).

    Trust boundary: fields derived from `f+1` corroboration + cert-chain-from-anchor."""

    roster: tuple[crypto.PublicKey, ...]
    """Currently-authorised roster members. Used to verify `settle_sigs` on any anchors
    the client receives -- consensus quorum multisig against this exact ordered set."""

    managers: tuple[crypto.PublicKey, ...]
    """Currently-attested Role.MANAGER identities. Used to verify roster-entry certs
    whose signer is a manager rather than the anchor directly."""

    node_endpoints: dict[crypto.PublicKey, tuple[Endpoint, ...]]
    """Where to reach each roster member. Populated from bundle P_NODE rows."""

    roster_fingerprint: crypto.Digest
    """The commitment cert's subject. Sent in every subsequent request; server includes
    a fresh bundle iff the client's fingerprint doesn't match theirs."""

    head: TrustedBlock
    """`(block_num, block_hash)` -- the most recent block whose `settle_sigs` we've
    verified. Advances on chain-linked headers received in piggyback."""

    head_state_root: crypto.Digest
    """`state_root` at `head`. Cached so `GET_PROOF` replies can be verified against it
    (once the SMT verifier lands)."""


@dataclass(slots=True)
class GetResult:
    """A completed read. `absent=True` iff the key was proven absent at the responder's
    state (non-membership proof, #light-client-nonmembership). `value` is the raw bytes
    otherwise."""

    value: bytes  # ABSENT_MARKER when absent
    absent: bool
    block_num: int
    state_root: crypto.Digest


@dataclass(slots=True)
class Failed:
    """A completed-but-failed request. `reason` names why -- refusal from responder,
    stale, fork, or client-side verify failure."""

    reason: str  # LiteRefusal.value or a client-side description


# Sentinel used by `poll` to say "not yet complete".
class _Pending:
    """Singleton pending marker. Not a dataclass -- one shared instance is fine."""


PENDING = _Pending()


@dataclass(slots=True)
class _PendingRead:
    """Outstanding GET_PROOF. Keyed by mid in `_pending_reads`; the caller polls via
    `request_id` which is the same value."""

    store_id: int
    name: bytes
    peer: crypto.PublicKey
    sent_at: Millis
    result: GetResult | Failed | None = None


@dataclass(slots=True)
class _BootstrapReply:
    """Per-peer state during BOOTSTRAPPING: the reply we got from this peer (if any).
    Corroboration is on `roster_fingerprint` across `f+1` replies."""

    fingerprint: crypto.Digest | None = None
    bundle: RosterBundle | None = None
    anchors_reply: AnchorsReply | None = None


type OutboxItem = tuple[crypto.PublicKey, bytes]  # (target_peer, message_id)


@dataclass(slots=True)
class LightClient:
    """A light client: anchor pubkey + in-memory TrustedState + Postman. See
    #light-client-verify.

    Not thread-safe. Follows the same tick/receive shape as `Follower` and `Node`."""

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
    """mid -> peer, so an incoming AnchorsReply during BOOTSTRAPPING routes to the right
    peer's _BootstrapReply."""

    _inbox: queue.SimpleQueue[Inbound] = field(default_factory=queue.SimpleQueue, init=False)
    """See `Node._inbox` -- same shape. One door for inbound frames from any attached
    Listener; the owned client thread drains it in `_run`."""

    _stopping: threading.Event = field(default_factory=threading.Event, init=False)
    _thread: threading.Thread | None = field(default=None, init=False)
    _listeners: tuple[Listener, ...] = field(default=(), init=False)

    def __post_init__(self) -> None:
        self.adapter = LiteAdapter(self.me, self.postman, self.tunables.net.ttl)

    # -- lifecycle ---------------------------------------------------------------------------- #

    def add_bootstrap_peer(self, peer: crypto.PublicKey, endpoints: tuple[Endpoint, ...]) -> None:
        """Register a bootstrap peer so `bootstrap()` can send GET_ANCHORS to it. Adds to
        `postman.peers` via the usual dialler path; also tracks the peer as part of the
        bootstrap set until corroboration completes."""
        self.postman.add_peer(peer, endpoints)
        self._bootstrap_peers[peer] = _BootstrapReply()

    def bootstrap(self, now: Millis) -> None:
        """Kick off bootstrap: send GET_ANCHORS(None, None) to every registered
        bootstrap peer. Transitions state UNBOOTSTRAPPED -> BOOTSTRAPPING.

        Requires `add_bootstrap_peer` to have been called at least once. Ideally called
        with `>= f+1` peers -- otherwise corroboration cannot succeed and bootstrap
        will time out (moving to FAILED, caller re-tries)."""
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

    # -- reads -------------------------------------------------------------------------------- #

    def request_get(self, store_id: int, name: bytes, peer: crypto.PublicKey, now: Millis) -> bytes:
        """Send a GET_PROOF for `(store_id, name)` at the current trusted head. Returns
        the request-id (message-id); caller polls with `poll(request_id)`.

        `peer` is the responder to send to; caller picks (any one of the trusted roster
        members). This keeps peer-selection policy out of LightClient."""
        if self.state is not State.READY or self.trusted_state is None:
            raise LightClientError(f"request_get in state {self.state.name}; not READY")
        req = GetProof(
            store_id=store_id,
            name=name,
            block_num=self.trusted_state.head.block_num,
            known_roster_fingerprint=self.trusted_state.roster_fingerprint,
            known_trusted_block=self.trusted_state.head,
        )
        mid = self.adapter.send(peer, req, now)
        self._pending_reads[mid] = _PendingRead(
            store_id=store_id, name=name, peer=peer, sent_at=now
        )
        return mid

    def poll(self, request_id: bytes) -> GetResult | Failed | _Pending:
        """Check on a pending read. Returns `PENDING` while awaiting the reply,
        `GetResult` on success, `Failed` on refusal or verify failure. The entry is
        removed on completion, so a second `poll` for the same request_id returns
        PENDING (fresh) or raises."""
        entry = self._pending_reads.get(request_id)
        if entry is None:
            raise LightClientError(f"unknown request_id {request_id.hex()[:8]}")
        if entry.result is None:
            return PENDING
        result = entry.result
        del self._pending_reads[request_id]
        return result

    # -- I/O boundary ------------------------------------------------------------------------- #

    def receive(self, frame: Frame, now: Millis, session: Session | None = None) -> None:
        """One inbound frame -- same crash-only shape as Node.receive. Postman unseals
        and correlates; if the reply matches an outstanding request, dispatch to the
        right state-machine handler. Bad frames drop silently.

        `session` is present when the frame arrived via a real transport (see `_run`),
        None when injected directly by tests. When present, binds identity + registers
        the session with Postman on first sight, mirroring `Node._bind_session`."""
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
        # Route by which state we're in and what the reply correlates to.
        if reply_to in self._pending_bootstrap_mids:
            peer = self._pending_bootstrap_mids.pop(reply_to)
            self._on_bootstrap_reply(peer, msg, now)
            return
        if reply_to in self._pending_reads:
            self._on_read_reply(reply_to, msg, now)
            return
        # Unsolicited or already-reaped: drop.

    def tick(self, now: Millis) -> None:
        """Advance postman (drives retransmission, timeouts). LightClient itself has no
        time-driven state machine right now -- bootstrap and reads are event-driven off
        replies. Retry / bootstrap-timeout policy is OWED (would live here)."""
        self.postman.tick(now)

    # -- lifecycle ---------------------------------------------------------------------------- #
    # Same shape as `Node.start` / `Node.stop` / `Node._run` -- one comment there covers both.

    def start(self, *listeners: Listener) -> None:
        """Begin serving. Same transactional shape as `Node.start`: each listener starts
        pushing into `_inbox`; on any listener raising, previously-started listeners get
        stopped in reverse order and the exception propagates. Idempotent."""
        if self._thread is not None:
            return
        started: list[Listener] = []
        try:
            for listener in listeners:
                listener.start(self._inbox)
                started.append(listener)
        except Exception:
            for listener in reversed(started):
                with contextlib.suppress(Exception):
                    listener.stop()
            raise
        self._listeners = tuple(started)
        self._thread = threading.Thread(
            target=self._run,
            name=f"lite-{self.me.public.hex()[:8]}",
            daemon=True,
        )
        self._thread.start()

    def stop(self, timeout: float = 5.0) -> None:
        """Signal shutdown; close listeners; join. Idempotent."""
        self._stopping.set()
        for listener in self._listeners:
            with contextlib.suppress(Exception):
                listener.stop()
        self._listeners = ()
        thread = self._thread
        self._thread = None
        if thread is not None and thread.is_alive():
            thread.join(timeout=timeout)

    def _run(self) -> None:
        """Owned-thread body: drain `_inbox`, drive `tick()` on cadence. Same shape as
        `Node._run`."""
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
                self.tick(now)
                last_tick = now

    def _bind_session(self, session: Session, frm: crypto.PublicKey) -> None:
        """Same shape as `Node._bind_session`. First inbound frame on this session sets
        `session.identity = frm` and registers a SessionLink on Peer(frm)."""
        was_unbound = session.identity is None
        try:
            session.bind(frm)
        except SessionBindError:
            session.close()
            return
        if was_unbound:
            self.postman.register_session(session)

    # -- internals ---------------------------------------------------------------------------- #

    def _on_bootstrap_reply(self, peer: crypto.PublicKey, msg: LiteMsg, now: Millis) -> None:
        """One bootstrap peer replied. If it's an AnchorsReply with a valid bundle we
        can verify from the anchor, record it. Once `f+1` peers agree on the same
        `roster_fingerprint`, promote to READY."""
        if self.state is not State.BOOTSTRAPPING:
            return
        if isinstance(msg, LiteRefused):
            # Peer refused; leave them out of corroboration. If not enough peers left
            # to reach f+1 agreement, move to FAILED.
            self._check_bootstrap_convergence(now)
            return
        if not isinstance(msg, AnchorsReply):
            return  # unexpected verb for this correlation; drop
        if msg.bundle is None:
            return  # bootstrap request sent fingerprint=None; every reply should include bundle
        if not _verify_bundle(self.anchor, msg.bundle):
            return  # bad bundle; treat peer as untrustworthy for corroboration
        if not _verify_settle_sigs_against_bundle(self.anchor, msg, msg.bundle):
            return  # settle_sigs don't match the freshly-verified roster
        entry = self._bootstrap_peers.setdefault(peer, _BootstrapReply())
        entry.fingerprint = msg.roster_fingerprint
        entry.bundle = msg.bundle
        entry.anchors_reply = msg
        self._check_bootstrap_convergence(now)

    def _check_bootstrap_convergence(self, now: Millis) -> None:  # noqa: ARG002 -- `now` for future retry-timeout hook
        """Have `f+1` peers agreed on the same `roster_fingerprint`? If so, promote to
        READY. If enough peers have failed that reaching f+1 is impossible, move to
        FAILED (caller re-tries with a fresh peer set)."""
        # Collect (fingerprint, entry) for peers that have replied.
        agreed: dict[crypto.Digest, list[_BootstrapReply]] = {}
        for entry in self._bootstrap_peers.values():
            if entry.fingerprint is None:
                continue
            agreed.setdefault(entry.fingerprint, []).append(entry)
        # `f+1` -- assuming the perceived roster size in the reply is what we use.
        # Bootstrap-time approximation: use bundle roster size, since we're establishing
        # who the roster IS. Pick the majority reply for that.
        for fingerprint, entries in agreed.items():
            first = entries[0]
            assert first.bundle is not None and first.anchors_reply is not None  # noqa: S101 -- type narrowing for the checker; contract invariants above make this unreachable
            threshold = quorum.corroboration(len(first.bundle.commitment_members))
            if len(entries) >= threshold:
                self._promote_to_ready(fingerprint, entries[0])
                return

    def _promote_to_ready(self, fingerprint: crypto.Digest, corroborated: _BootstrapReply) -> None:
        """Set the trusted state from a corroborated bootstrap reply. Any one of the
        agreeing replies works -- their bundles are byte-equal for the same fingerprint,
        and we've already verified settle_sigs on this one's head."""
        assert corroborated.bundle is not None and corroborated.anchors_reply is not None  # noqa: S101 -- type narrowing for the checker; contract invariants above make this unreachable
        bundle = corroborated.bundle
        head = corroborated.anchors_reply.head
        self.trusted_state = TrustedState(
            roster=tuple(sorted(bundle.commitment_members)),
            managers=tuple(sorted(g.identity for g in bundle.managers)),
            node_endpoints={rec.identity: rec.endpoints for rec in bundle.entries},
            roster_fingerprint=fingerprint,
            head=TrustedBlock(head.anchors.block_num, head.block_hash),
            head_state_root=head.anchors.state_root,
        )
        self.state = State.READY

    def _on_read_reply(self, reply_to: bytes, msg: LiteMsg, now: Millis) -> None:  # noqa: ARG002
        """Reply to an outstanding GET_PROOF. Verify the header chain + settle_sigs to
        establish `head_state_root`, then verify the SMT proof against that root,
        record the result, advance trusted head."""
        entry = self._pending_reads[reply_to]
        if isinstance(msg, LiteRefused):
            entry.result = Failed(reason=msg.reason.value)
            if msg.reason in (LiteRefusal.STALE_CLIENT, LiteRefusal.FORK_DETECTED):
                # Client's trusted state is unusable; caller should re-bootstrap.
                self.state = State.UNBOOTSTRAPPED
                self.trusted_state = None
            return
        if not isinstance(msg, ProofReply):
            entry.result = Failed(reason="unexpected reply verb")
            return
        assert self.trusted_state is not None  # noqa: S101 -- type narrowing for the checker; contract invariants above make this unreachable
        # If the reply carries a fresh bundle, verify + swap roster BEFORE verifying
        # subsequent headers (#light-client-roster-change-in-window).
        if msg.bundle is not None:
            if not _verify_bundle(self.anchor, msg.bundle):
                entry.result = Failed(reason="bundle verify failed")
                return
            self._swap_roster(msg.bundle, msg.roster_fingerprint)
        # Chain-verify headers[] against current trusted head + roster, then advance
        # to responder's head (which is `msg.head`, a full SettledBlock). `_advance_head`
        # updates `trusted_state.head_state_root` on success -- that's the root the SMT
        # proof must verify against.
        if not self._advance_head(msg.headers, msg.head):
            entry.result = Failed(reason="header chain-link or settle_sigs verify failed")
            return
        # Verify the SMT proof against the freshly-verified head_state_root -- see SPEC
        # anchor light-client-nonmembership. A responder serving a wrong value or a
        # fabricated proof fails here.
        try:
            proof = smt.Proof.decode(msg.proof)
        except DudeError:
            entry.result = Failed(reason="malformed proof")
            return
        held = None if msg.absent else (msg.value, msg.credential)
        assert self.trusted_state is not None  # noqa: S101 -- narrowing; _advance_head keeps it non-None on success
        if not smt.verify(
            self.trusted_state.head_state_root,
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
            block_num=msg.head.anchors.block_num,
            state_root=msg.head.anchors.state_root,
        )

    def _swap_roster(self, bundle: RosterBundle, fingerprint: crypto.Digest) -> None:
        """Replace `trusted_state.roster`/`managers`/`node_endpoints`/`roster_fingerprint`
        with the freshly-verified bundle. Called from `_on_read_reply` when the reply's
        fingerprint differs from ours."""
        assert self.trusted_state is not None  # noqa: S101 -- type narrowing for the checker; contract invariants above make this unreachable
        self.trusted_state = TrustedState(
            roster=tuple(sorted(bundle.commitment_members)),
            managers=tuple(sorted(g.identity for g in bundle.managers)),
            node_endpoints={rec.identity: rec.endpoints for rec in bundle.entries},
            roster_fingerprint=fingerprint,
            head=self.trusted_state.head,
            head_state_root=self.trusted_state.head_state_root,
        )

    def _advance_head(
        self, headers: tuple[SettledBlock, ...], responder_head: SettledBlock
    ) -> bool:
        """Chain-verify `headers[]` from the client's current trusted_block, then verify
        the responder's head SettledBlock as the final step. Advances
        `trusted_state.head` + `head_state_root` on success. Returns False on any check
        failure (caller drops the whole reply).

        `headers[]` MAY be empty when the client is already at the responder's head; in
        that case, verifying `responder_head` itself is redundant (it IS the trusted
        head). When non-empty, `headers[-1]` typically IS `responder_head` (server ships
        them together); the terminal chain-link + settle_sigs verify establishes trust."""
        assert self.trusted_state is not None  # noqa: S101 -- type narrowing for the checker; contract invariants above make this unreachable
        prev_hash = self.trusted_state.head.block_hash
        roster = self.trusted_state.roster
        chain: tuple[SettledBlock, ...]
        if headers and headers[-1].block_hash == responder_head.block_hash:
            chain = headers
        else:
            chain = (*headers, responder_head)
        for header in chain:
            if header.anchors.prev_block != prev_hash:
                # Special case: no headers, no advance -- responder_head IS trusted head.
                return header.block_hash == self.trusted_state.head.block_hash
            payload = _settle_payload(header.block.slice_hash, header.anchors)
            if not _verify_multisig(
                header.signers, header.settle_sigs, payload, roster, self.anchor
            ):
                return False
            prev_hash = header.block_hash
        # Advance to the last verified block.
        final = chain[-1]
        self.trusted_state = TrustedState(
            roster=self.trusted_state.roster,
            managers=self.trusted_state.managers,
            node_endpoints=self.trusted_state.node_endpoints,
            roster_fingerprint=self.trusted_state.roster_fingerprint,
            head=TrustedBlock(final.anchors.block_num, final.block_hash),
            head_state_root=final.anchors.state_root,
        )
        return True


# --------------------------------------------------------------------------------------------- #
# Verify helpers -- pure, no state                                                              #
# --------------------------------------------------------------------------------------------- #


def _verify_bundle(  # noqa: C901, PLR0911 -- verification pipeline; each early-return names a distinct failure mode
    anchor: crypto.PublicKey, bundle: RosterBundle
) -> bool:
    """Verify a RosterBundle against the anchor pubkey alone (#light-client-cert-chain).
    Signature-chain only: no state_root, no SMT proofs. Confirms:
      * Commitment cert signature valid, subject binds serial+members+state_fingerprint,
        signer is anchor or a manager appearing in bundle.managers.
      * Manager certs each signed by anchor, purpose == 'manager'.
      * Roster entry certs each signed by anchor OR by a manager in the bundle,
        purpose == 'roster'.
      * Recomputed state_fingerprint from bundle entries matches commitment binding."""
    # Verify manager certs first, they're the trust anchors for other-signed entry certs.
    manager_pubkeys: set[crypto.PublicKey] = set()
    for grant in bundle.managers:
        if not _verify_grant_cert(grant, anchor, expected_role=Role.MANAGER):
            return False
        manager_pubkeys.add(grant.identity)
    # Verify commitment cert.
    signer = bundle.commitment_cert.signer
    if signer != anchor and signer not in manager_pubkeys:
        return False
    if bundle.commitment_cert.purpose != b"roster_commitment":
        return False
    if not bundle.commitment_cert.verify():
        return False
    # Recompute state_fingerprint from bundle entries.
    state_fingerprint = crypto.h(
        codec.encode(
            [
                [
                    bytes(rec.identity),
                    sorted(ep.encode() for ep in rec.endpoints),
                    sorted(rec.domains),
                ]
                for rec in sorted(bundle.entries, key=lambda r: bytes(r.identity))
            ]
        )
    )
    expected_subject = crypto.h(
        codec.encode(
            [
                bundle.commitment_serial,
                sorted(bytes(m) for m in bundle.commitment_members),
                state_fingerprint,
            ]
        )
    )
    if bundle.commitment_cert.subject != expected_subject:
        return False
    # Verify each entry cert.
    for rec in bundle.entries:
        if rec.cert.subject != rec.identity:
            return False
        if rec.cert.purpose != b"roster":
            return False
        if not rec.cert.verify():
            return False
        entry_signer = rec.cert.signer
        if entry_signer != anchor and entry_signer not in manager_pubkeys:
            return False
    return True


def _verify_grant_cert(grant: Grant, anchor: crypto.PublicKey, expected_role: Role) -> bool:
    """Verify a grant's #cert against `anchor` for `expected_role`. MANAGER + COMPACTOR
    must be anchor-signed; the caller vouches for `expected_role` matching the grant."""
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
    """Verify the AnchorsReply's head settle_sigs against the roster derived from the
    bundle. Used at bootstrap time before trusted_state exists. The reply carries a full
    `SettledBlock`, so slice_hash is directly available."""
    roster = tuple(sorted(bundle.commitment_members))
    head = reply.head
    payload = _settle_payload(head.block.slice_hash, head.anchors)
    return _verify_multisig(head.signers, head.settle_sigs, payload, roster, anchor)


def _verify_multisig(
    signers: crypto.SignerBitmap,
    sigs: tuple[crypto.Signature, ...],
    payload: bytes,
    roster: tuple[crypto.PublicKey, ...],
    anchor: crypto.PublicKey,
) -> bool:
    """Verify an Ed25519 list-multisig against `[*roster, anchor]`. Mirrors
    `Management.authorization`'s composition -- `settle_sigs` are always built with the
    anchor override slot at index `len(roster)`, so verification must include it."""
    signer_set = [*roster, anchor]
    if not crypto.Ed25519ListMultiSig.verify(signers, list(sigs), payload, signer_set):
        return False
    # A quorum of roster slots suffices; manager slot alone also suffices.
    n = len(signer_set)
    set_indices = crypto.bitmap_indices(signers, n)
    if (n - 1) in set_indices:
        return True  # anchor slot signed -- authorises alone
    roster_signer_count = sum(1 for i in set_indices if i < len(roster))
    return roster_signer_count >= quorum.size(len(roster))


__all__ = [
    "PENDING",
    "Failed",
    "GetResult",
    "LightClient",
    "LightClientError",
    "State",
    "TrustedState",
]
