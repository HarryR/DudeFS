# dude.node — the gestalt: one storage node, with all the pieces joined.
#
# This is the first place the layers meet, and it exists to find out whether the seams are right.
# Everything below it has been built and tested in isolation; a node is what says whether isolation
# was the correct decomposition.
#
# WHAT IT OWNS, and nothing else:
#
#   store        the log                                      (dude.store)
#   coordinator  the consensus driver + the current mempool   (dude.coordinator)
#   postman      the wire, and the only clock                 (dude.net.postman)
#
# It contributes exactly one thing of its own: a `handle` mapping an inbound verb to an action, and
# a `tick` that advances the round. Anything more belongs in one of the parts.
#
# THE CONSENSUS ROUND LIVES IN `dude.round` and is DRIVEN by `dude.coordinator`. `Node.tick` calls
# `Coordinator.tick`; inbound `HELD`/`SIG` envelopes are handed to `Coordinator.on_round_msg`;
# client SUBMITs are handed to `Coordinator.submit`. The placeholder "everyone proposes their own
# batch, count endorsements, first-to-quorum wins" round that used to live here (methods `_propose`,
# `_count`, `_settle`, verbs `PROPOSE`/`ENDORSE`) has been deleted -- SPECv2 #round-lifecycle is
# now the settled shape.

from __future__ import annotations

from collections.abc import Callable
from dataclasses import dataclass, field

from .consensus import Coordinator, Mempool, RoundAdapter, SettleAdapter
from .core import crypto
from .core.errors import DudeError
from .core.units import Millis
from .net import Verb
from .net.envelope import Envelope, Frame, SignedEnvelope, new_message_id
from .net.postman import Postman
from .store import Store, ops
from .store.management import P_GRANT, Management, Role
from .sync.adapter import (
    GetBlock,
    Refused,
    SyncAdapter,
    SyncAdapterError,
    SyncMsg,
    SyncRefusal,
)
from .sync.follower import Follower, serve_getblock, serve_height
from .sync.lite import serve_get_anchors, serve_get_proof
from .sync.lite_adapter import (
    GetAnchors,
    GetProof,
    LiteAdapter,
    LiteAdapterError,
    LiteMsg,
    LiteRefusal,
    LiteRefused,
)
from .tunables import DEFAULT, Tunables

REPLIES = frozenset({Verb.PONG, Verb.BODIES, Verb.REFUSED})
"""Verbs that ANSWER something we sent. They need no handler: `Postman.deliver` has already
correlated them and retired the pending entry, so reaching `_handle` means the useful work is done.

Named so "no handler" is a statement rather than an omission — otherwise a reply looks exactly
like a verb somebody forgot."""

HANDLED = frozenset(
    {
        Verb.SUBMIT,
        Verb.HELD,
        Verb.SIG,
        Verb.SETTLE_SIG,
        Verb.HEIGHT,
        Verb.HEIGHT_REPLY,
        Verb.GETBLOCK,
        Verb.SETTLED_BLOCK,
        Verb.PING,
        Verb.GET_ANCHORS,
        Verb.GET_PROOF,
    }
)
"""Verbs this node acts on.

`HELD` and `SIG` are the Round protocol's own vocabulary (SPECv2 #round-lifecycle); handled by
delegating to `Coordinator.on_round_msg`. `PROPOSE` and `ENDORSE` were the placeholder round's
verbs; deleted as part of the Round pivot (Phase 6).

`HEIGHT`/`GETBLOCK` are inbound sync REQUESTS -- Node answers via `serve_*` (stateless). The
answers themselves (`HEIGHT_REPLY`/`SETTLED_BLOCK`) are correlated by Postman as replies but
ALSO carry state the Follower needs -- so they land in `HANDLED` too, and their handlers route
to `Follower.receive`. Different from `BODIES`/`PONG` where correlation IS the useful work."""

SOLICITED: frozenset[Verb] = frozenset()
"""Verbs that are only ever an ANSWER to something this node asked for.

An unsolicited one is dropped before dispatch. Without that, anyone at all could hand a node a run
of log entries and have them applied — which was demonstrable: a stranger holding no grant and no
roster seat added itself to a catching-up node's roster with one frame."""

UNIMPLEMENTED = frozenset(Verb) - HANDLED - REPLIES
"""Specified, not yet built. Derived rather than listed, so it cannot drift from the other two, and
so adding a `Verb` puts it here automatically instead of into a silent default branch."""


@dataclass(slots=True)
class Node:
    """A storage node. Sans-I/O apart from its postman: `tick(now)` is the only entry point that
    advances time, and inbound frames arrive by being handed to `receive`."""

    me: crypto.Keypair
    store: Store
    tunables: Tunables = DEFAULT
    postman: Postman = field(init=False)
    adapter: RoundAdapter = field(init=False)
    settle_adapter: SettleAdapter = field(init=False)
    sync_adapter: SyncAdapter = field(init=False)
    lite_adapter: LiteAdapter = field(init=False)
    coordinator: Coordinator = field(init=False)
    """Owns the current Mempool, the in-flight Rounds, and drives them on tick. See
    `dude.coordinator`. Node's role in consensus is: hand SUBMIT bodies to
    `coordinator.submit`, HELD/SIG envelopes to `coordinator.on_round_msg`, SETTLE_SIG
    envelopes to `coordinator.on_settle_msg`, and call `coordinator.tick(now)` from `tick`."""
    follower: Follower = field(init=False)
    """Owns the L6 catch-up state machine (`dude.sync`). Consumes SETTLED blocks pulled from
    peers; commits via `store.commit_block`, same durable path Coordinator uses. Coordinator
    and Follower share the Store as their only meeting point (#sync-in-its-own-module) --
    Coordinator PRODUCES blocks, Follower CONSUMES them, they never talk to each other."""

    _last_reconciled_serial: int = field(default=-1, init=False)
    """The last roster commitment serial `_reconcile_peers` acted on. -1 means never
    reconciled. Serial-gate for #roster-drives-peers: skip the full pass on tick unless the
    serial has advanced (roster has actually changed)."""

    _managed_peers: set[crypto.PublicKey] = field(default_factory=set, init=False)
    """Peers `_reconcile_peers` itself added -- roster members and CLIENT / COMPACTOR
    authors. The removal pass only revokes membership from THIS set, so manually-added
    peers (bootstrap-outside-the-roster, e.g. a joining node not yet in the roster --
    see `test_sync_e2e`) survive reconciliation."""

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
        self.coordinator = Coordinator(
            self.me,
            self.store,
            self.adapter,
            self.settle_adapter,
            self.tunables,
            reflood=lambda tx, now: self._flood(Verb.SUBMIT, tx.raw, now),
        )
        self.follower = Follower(
            me=self.me,
            store=self.store,
            mgmt=Management(self.store),
            tunables=self.tunables.sync,
        )

    @property
    def mempool(self) -> Mempool:
        """The currently-collecting Mempool. Kept as a `Node` property so tests and diagnostics
        that reach for `node.mempool` still work; the authoritative owner is `self.coordinator`,
        which swaps this instance at every bucket boundary."""
        return self.coordinator.mempool

    # -- membership ---------------------------------------------------------------------------- #

    @property
    def mgmt(self) -> Management:
        return Management(self.store)

    def _reconcile_peers(self, now: Millis) -> None:
        """Sync `postman.peers` against the current roster + author grants
        (#roster-drives-peers).

        Two passes, one call:
          * `_reconcile_roster` — gated on the roster commitment serial; adds roster
            members with their P_NODE endpoints and registers them with the Follower.
          * `_reconcile_grants` — runs every tick; adds CLIENT / COMPACTOR authors from
            their P_GRANT endpoints. No gate because grants don't touch the roster
            commitment, and the scan is O(authorised).

        REMOVALS at the end: any `_managed_peers` pubkey (a peer this reconciler itself
        added on some prior tick) that is no longer in the roster and no longer a valid
        author grant is dropped. Peers added outside reconciliation (bootstrap-out-of-
        roster wiring in `test_sync_e2e`) are left alone."""
        commitment = self.mgmt.roster_commitment()
        if commitment is None:
            return
        roster = set(self.mgmt.roster())
        self._reconcile_roster(commitment[0], roster, now)
        author_pubkeys = self._reconcile_grants()
        keep = roster | author_pubkeys
        for pubkey in list(self._managed_peers):
            if pubkey not in keep:
                if pubkey in self.postman.peers:
                    self.postman.remove_peer(pubkey)
                self._managed_peers.discard(pubkey)

    def _reconcile_roster(self, serial: int, roster: set[crypto.PublicKey], now: Millis) -> None:
        """Add any roster member missing from `postman.peers`, register with the Follower
        for sync polls. Gated: skip when the commitment serial hasn't advanced."""
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
                continue  # roster listed a member with no endpoints; skip until they show up
            self.postman.add_peer(pubkey, rec.endpoints)
            self.follower.add_peer(pubkey, now=now)
            self._managed_peers.add(pubkey)

    def _reconcile_grants(self) -> set[crypto.PublicKey]:
        """Add every CLIENT / COMPACTOR author (with declared endpoints) to `postman.peers`
        so replies can flow back to them. Returns the set of authored identities, for the
        caller's removal pass to spare. Follower is not touched -- authors are not
        consensus peers and don't get sync polls."""
        authors: set[crypto.PublicKey] = set()
        for name, _prov, _value, _ep in self.store.prefix(self.mgmt.store_id, P_GRANT):
            who = crypto.PublicKey(name[len(P_GRANT) :])
            grant = self.mgmt.grant_of(who)
            if grant is None:
                continue
            if grant.role not in (Role.CLIENT, Role.COMPACTOR):
                continue
            if not grant.endpoints:
                continue  # grant without endpoints; can't dial (auto-add on receive is OWED)
            authors.add(who)
            if who not in self.postman.peers:
                self.postman.add_peer(who, grant.endpoints)
                self._managed_peers.add(who)
        return authors

    def roster(self) -> tuple[crypto.PublicKey, ...]:
        """MANAGEMENT'S ANSWER, and nowhere else. `Management` owns everything about who is
        authorised; the roster is one such question. `Store.roster` used to shadow this call;
        deleted -- Store does not touch the roster. `store.mgmt.roster()` is the one path."""
        return self.store.mgmt.roster()

    # -- inbound ------------------------------------------------------------------------------- #

    def receive(self, frame: Frame, now: Millis) -> None:
        """One inbound frame, fully handled.

        CATCHES `DudeError` DELIBERATELY. This is the crash-only boundary the error review flagged:
        hostile bytes are an EXPECTED outcome at a decode boundary, so one peer sending garbage must
        cost it its frame and nothing else. Anything outside the tree still escapes and takes the
        process down, which is the contract `crashonly` relies on.

        THE HANDLER IS INSIDE THE CATCH, and it was not `[H]`. Only `deliver` used to be, so any
        typed error a handler raised escaped `receive` — and a handler's first act is usually to
        DECODE a peer-supplied body. A stranger with no grant and no roster seat could send `SUBMIT`
        with twelve bytes of non-bencode and the `CodecError` went straight past this boundary; with
        `crashonly` installed that is `os._exit`, i.e. the unauthenticated remote kill switch
        crashonly.py names as the one thing its precondition exists to prevent. Typed parsing was
        already right; the catch was in the wrong place. `InvariantError` is deliberately not a
        `DudeError`, so OUR bugs still take the process down (core/errors.py)."""
        try:
            got = self.postman.deliver(frame, now)
            if got.envelope.env.verb in SOLICITED and got.reply is None:
                return  # nobody asked; see `SOLICITED`
            self._handle(got.envelope, now)
        except DudeError:
            return  # their fault: drop the frame, keep serving

    def _handle(self, env: SignedEnvelope, now: Millis) -> None:
        """Dispatch by verb.

        A TABLE rather than a chain of cases: it is the same statement `HANDLED` already makes, and
        keeping the two in one place means a verb cannot be listed as handled while having nowhere
        to go. A missing entry is not a silent default — see `REPLIES` and `UNIMPLEMENTED`, which
        say which of the two kinds of nothing it is."""
        fn = _DISPATCH.get(env.env.verb)
        if fn is not None:
            fn(self, env, now)

    def _on_ping(self, env: SignedEnvelope, now: Millis) -> None:
        self._reply(env, Verb.PONG, b"", now)

    def _on_submit(self, env: SignedEnvelope, now: Millis) -> None:
        """A transaction offered by a client, or relayed by a peer.

        The author is the INNER signature; `env.frm` is merely who asked us to take it. That is the
        gate ruling in one line — a node carries an op it did not author, and authorises the
        requester, never the author."""
        tx = ops.SignedTransaction.decode(env.env.body)
        refusal = self.coordinator.submit(tx, now)
        if refusal is not None:
            self._reply(env, Verb.REFUSED, refusal.value.encode(), now)
            return
        self._reply(env, Verb.BODIES, tx.op_hash, now)
        # Re-flood the body so peers admit it too. Until gossip-by-hash + FETCH lands (SPECv2
        # #gossip-by-hash), this is what makes every node's mempool converge on the same set --
        # which is the input a Round's largest-intersection-over-quorum then acts on.
        self._flood(Verb.SUBMIT, env.env.body, now, skip=env.frm)

    def _on_held(self, env: SignedEnvelope, now: Millis) -> None:
        """A peer's HELD advertisement -- what transactions they claim to hold for some bucket.
        Round's own protocol vocabulary (SPECv2 #round-lifecycle); Coordinator routes by bucket
        to the right Round instance."""
        self.coordinator.on_round_msg(env, now)

    def _on_sig(self, env: SignedEnvelope, now: Millis) -> None:
        """A peer's signature over a slice they believe this bucket ratifies. Same handling as
        HELD -- routed to the Round for its bucket via the Coordinator."""
        self.coordinator.on_round_msg(env, now)

    def _on_settle_sig(self, env: SignedEnvelope, now: Millis) -> None:
        """A peer's signature over the post-apply anchors of a ratified block -- SettleRound's
        one message (SPECv2 #settlement-signs-post-anchors). Routed to the currently-settling
        block via the Coordinator, dropped if it does not match."""
        self.coordinator.on_settle_msg(env, now)

    def _on_height(self, env: SignedEnvelope, now: Millis) -> None:
        """A peer is asking for our current head. Answer with `HeightReply(block_num, tip_hash)`
        via the stateless `serve_height` helper (SPECv2 #height-poll-is-the-trigger)."""
        self.sync_adapter.reply(env, serve_height(self.store), now)

    def _on_height_reply(self, env: SignedEnvelope, now: Millis) -> None:
        """A peer's answer to our own HEIGHT poll. Decode, route to the Follower, which updates
        its `_heads` map and may fire fork detection or start a pull on the next tick."""
        try:
            msg = SyncMsg.decode(env.env.verb, env.env.body)
        except SyncAdapterError:
            return  # XXX: dropped -- malformed HEIGHT_REPLY body from this peer.
        self.follower.receive(msg, env.frm, now)

    def _on_getblock(self, env: SignedEnvelope, now: Millis) -> None:
        """A peer is asking for a SETTLED block. Answer via `serve_getblock` -- returns either
        `SettledBlockReply` (block + bodies) or `Refused` with a `SyncRefusal` reason. A
        malformed `GetBlock` body earns `Refused(UNKNOWN)` -- the requester's next-peer path
        is uniform regardless of failure mode."""
        try:
            req = SyncMsg.decode(env.env.verb, env.env.body)
        except SyncAdapterError:
            self.sync_adapter.reply(env, Refused(reason=SyncRefusal.UNKNOWN), now)
            return
        # verb-routed here, decode returns GetBlock; guard for the type checker.
        if not isinstance(req, GetBlock):
            return
        self.sync_adapter.reply(env, serve_getblock(self.store, req), now)

    def _on_settled_block(self, env: SignedEnvelope, now: Millis) -> None:
        """A peer's answer to our GETBLOCK. Decode, route to the Follower, which runs the full
        verify pipeline (chain link + settle_sigs + body-sig + preview-anchors-match) and
        commits on success -- or clears the in-flight pull on any failure
        (#sync-is-log-replay + #no-shun-only-priority). A decode failure means the peer served
        garbage; cancel the pull so next tick picks another peer."""
        try:
            msg = SyncMsg.decode(env.env.verb, env.env.body)
        except (SyncAdapterError, DudeError):
            # SettleError (from SettledBlockWithBodies.decode) is a DudeError; either shape of
            # decode failure means the pulling peer served garbage.
            self.follower.cancel_pull(env.frm)
            return
        self.follower.receive(msg, env.frm, now)

    def _lite_authorised(self, requester: crypto.PublicKey) -> bool:
        """Auth gate for light-client verbs (#light-client-verify, Harry's ruling that the
        cluster is strictly permissioned). `requester` MUST be one of:
          * The anchor (#anchor-is-the-axiom, always authorised).
          * A currently-attested Role.MANAGER (blanket authorship).
          * A currently-attested Role.CLIENT (the light client's own grant).
          * A currently-attested Role.COMPACTOR (for future compactor-side reads).
          * A currently-attested roster member (nodes reading each other, e.g. for sync).

        Uses `Management.may_send(requester, 0)` for grant checks -- MANAGER blanket
        makes it True; other roles fall back to the store roster membership check."""
        if requester == self.store.anchor():
            return True
        if requester in self.mgmt.roster():
            return True
        grant = self.mgmt.grant_of(requester)
        return grant is not None

    def _on_get_anchors(self, env: SignedEnvelope, now: Millis) -> None:
        """A light client (or another node) asks for our current anchors + optionally
        the identity chain (#light-client-piggyback). Auth: sender must be a known
        identity per #light-client-verify. Decode failure earns a LITE_REFUSED with
        MALFORMED_QUERY."""
        if not self._lite_authorised(env.frm):
            self.lite_adapter.reply(env, LiteRefused(LiteRefusal.MALFORMED_QUERY), now)
            return
        try:
            req = LiteMsg.decode(env.env.verb, env.env.body)
        except (LiteAdapterError, DudeError):
            self.lite_adapter.reply(env, LiteRefused(LiteRefusal.MALFORMED_QUERY), now)
            return
        if not isinstance(req, GetAnchors):
            return  # verb-routed here; type guard
        reply = serve_get_anchors(
            self.store, self.mgmt, req, self.tunables.light_client.liveness_window
        )
        self.lite_adapter.reply(env, reply, now)

    def _on_get_proof(self, env: SignedEnvelope, now: Millis) -> None:
        """A light client asks for a value + SMT proof at some block_num
        (#light-client-get). Same auth + decode shape as _on_get_anchors."""
        if not self._lite_authorised(env.frm):
            self.lite_adapter.reply(env, LiteRefused(LiteRefusal.MALFORMED_QUERY), now)
            return
        try:
            req = LiteMsg.decode(env.env.verb, env.env.body)
        except (LiteAdapterError, DudeError):
            self.lite_adapter.reply(env, LiteRefused(LiteRefusal.MALFORMED_QUERY), now)
            return
        if not isinstance(req, GetProof):
            return
        reply = serve_get_proof(
            self.store, self.mgmt, req, self.tunables.light_client.liveness_window
        )
        self.lite_adapter.reply(env, reply, now)

    # -- the round ----------------------------------------------------------------------------- #

    def tick(self, now: Millis) -> None:
        """Advance the consensus round, the sync loop, and the wire.

        Reconciles peers against the current roster first (#roster-drives-peers), so any
        `change_roster` that settled since our last tick flows to the transport layer
        before consensus tries to use it. The reconcile is serial-gated: a single roster-
        commitment read per tick, full pass only when the serial has advanced.

        Coordinator drives Round + SettleRound + commit. Follower drives sync polls, pull
        timeouts, and pull initiation; its outbox contains the HEIGHT / GETBLOCK envelopes to
        post via the mailbox."""
        self._reconcile_peers(now)
        self.coordinator.tick(now)
        self.follower.tick(now)
        self._flush_follower(now)
        self.postman.tick(now)

    def _flush_follower(self, now: Millis) -> None:
        """Post the Follower's outbox to the mailbox. Follower emits `(peer, SyncMsg)` pairs for
        outbound `HeightAsk` / `GetBlock` requests; the sync-adapter wraps them in signed
        envelopes and posts with `await_reply=True` so the mailbox correlates the answer
        (`HeightReply`, `SettledBlockReply`, `Refused`)."""
        for peer, msg in self.follower.outbox():
            if peer not in self.postman.peers:
                continue  # peer not reachable; drop rather than raise
            self.sync_adapter.send(peer, msg, now, await_reply=True)

    # -- outbound ------------------------------------------------------------------------------ #

    def _flood(
        self, verb: Verb, body: bytes, now: Millis, skip: crypto.PublicKey | None = None
    ) -> None:
        """Send to every peer. Flood announcements, pull bodies (#mempool) — at this size the
        announcement term is small and reconciliation would buy bandwidth at the cost of latency,
        which is the wrong trade when wave latency IS finality latency."""
        for who in self.postman.peers:
            if who in (self.me.public, skip):
                continue
            env = Envelope(who, verb, new_message_id(), body).sign(self.me, now)
            # An announcement, so no answer is awaited: `BODIES` and `REFUSED` are `REPLIES`, which
            # `deliver` retires without needing a registered question.
            self.postman.mailbox.post(env, now, self.tunables.net.ttl, await_reply=False)

    def _reply(self, to: SignedEnvelope, verb: Verb, body: bytes, now: Millis) -> None:
        if to.frm not in self.postman.peers:
            return
        self.postman.mailbox.post(
            to.answer(verb, body).sign(self.me, now), now, self.tunables.net.ttl, await_reply=False
        )


_DISPATCH: dict[Verb, Callable[[Node, SignedEnvelope, Millis], None]] = {
    v: getattr(Node, f"_on_{v.name.lower()}") for v in HANDLED
}
"""Verb to handler, DERIVED from `HANDLED` rather than listed beside it.

So the two cannot drift: a verb added to `HANDLED` without a matching `_on_<verb>` fails at import,
and a handler with no verb is unreachable and obvious. The convention is load-bearing, which is the
only kind worth having."""
