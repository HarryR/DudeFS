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

from .coordinator import Coordinator
from .core import codec, crypto
from .core.errors import DudeError
from .mempool import Mempool
from .net import Verb
from .net.address import Endpoint
from .net.envelope import Envelope, Frame, MessageId, SignedEnvelope, new_message_id
from .net.link import Peer, Transport
from .net.postman import Postman
from .net.round_adapter import RoundAdapter
from .net.transports import address_of
from .store import Commitment, Entry, Store, attest, ops
from .store.management import Management
from .store.witness import Witness
from .tunables import DEFAULT, Tunables

type Millis = int


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
        Verb.PING,
        Verb.FRONTIER,
        Verb.STANDING,
        Verb.PULL,
        Verb.ENTRIES,
    }
)
"""Verbs this node acts on.

`HELD` and `SIG` are the Round protocol's own vocabulary (SPECv2 #round-lifecycle); handled by
delegating to `Coordinator.on_round_msg`. `PROPOSE` and `ENDORSE` were the placeholder round's
verbs; deleted as part of the Round pivot (Phase 6)."""

SOLICITED = frozenset({Verb.ENTRIES})
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
    coordinator: Coordinator = field(init=False)
    """Owns the current Mempool, the in-flight Rounds, and drives them on tick. See
    `dude.coordinator`. Node's role in consensus is now just: hand SUBMIT bodies to
    `coordinator.submit`, hand HELD/SIG envelopes to `coordinator.on_round_msg`, and call
    `coordinator.tick(now)` from `tick`."""

    last_probe: Millis = 0
    """When this node last asked its peers where they were (#cross-attestation)."""

    def __post_init__(self) -> None:
        self.postman = Postman(self.me, window=self.tunables.net.window)
        self.adapter = RoundAdapter(self.me, self.postman, self.tunables.net.ttl)
        self.coordinator = Coordinator(self.me, self.store, self.adapter, self.tunables)

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

    @property
    def witness(self) -> Witness:
        """What peers have said about themselves, and what that has proved.

        Constructed per use like `mgmt`, and for the same reason: it holds nothing of its own, so
        there is no cached view to go stale."""
        return Witness(self.store)

    def connect(self, peer: crypto.PublicKey, transport: Transport) -> None:
        """Add a peer reachable in-process. A real deployment reads endpoints from the management
        store instead; this is the same `Peer` either way."""
        p = Peer(peer, lambda _e: transport, self.tunables.link)
        p.reconfigure((Endpoint(address_of(peer)),))
        self.postman.peers[peer] = p

    def roster(self) -> tuple[crypto.PublicKey, ...]:
        """THE STORE'S ANSWER, not a second one. This used to be `self.mgmt.node_set()` — the same
        expression `Store.roster` already evaluates, so two implementations of "who is the roster"
        sat on either side of the boundary because neither layer was sure it was allowed to ask."""
        return self.store.roster()

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

    # -- attestation (#monotonicity, #cross-attestation) ---------------------------------------- #

    def attestation(self, now: Millis) -> attest.SignedAttestation:
        """Sign one committed snapshot of this node's own store.

        Signed here and unsigned in `Store.attestation`, which is the whole division: the store
        holds the durable state and no key, the node holds the key and no state.

        The store bumps and commits the counter; this only signs what it returns. That ordering is
        the whole safety of it — see `Store.attestation`."""
        return attest.SignedAttestation.make(self.me, self.store.attestation(now))

    def probe(self, now: Millis) -> None:
        """Ask every peer where it is. Cheap, and the only thing that makes a rollback VISIBLE
        rather than merely provable-in-principle."""
        self.last_probe = now
        self._flood(Verb.FRONTIER, b"", now)

    def _on_frontier(self, env: SignedEnvelope, now: Millis) -> None:
        """Answer "where are you now" with everything needed to judge us and the cluster at once:
        our own signed position, and the latest we have heard of everyone else."""
        held = self.witness.convictions()
        reply = attest.Frontier(
            self.attestation(now), self.witness.sightings(), tuple(held.values())
        )
        self._reply(env, Verb.STANDING, reply.encode(), now)

    def _on_standing(self, env: SignedEnvelope, _now: Millis) -> None:
        """Take a peer's position and everything it has heard.

        The relayed sightings are witnessed too, which is what makes evidence TRANSITIVE: a node
        that never spoke to the culprit directly can still hold the pair that convicts it."""
        try:
            said = attest.Frontier.decode(env.env.body)
        except DudeError:
            return  # malformed bytes from a peer are routine, not exceptional
        for one in (said.own, *said.sightings):
            if one.by == self.me.public:
                continue  # our own statements come from our own store, never from a relay
            self.witness.heard(one)
        for claimed in said.convictions:
            if claimed.culprit != self.me.public:
                self.witness.judge(claimed)

    def shunned(self) -> frozenset[crypto.PublicKey]:
        """Keys proven to have contradicted themselves.

        A LOCAL READ POLICY (#cross-attestation): it does not touch the roster or the quorum
        arithmetic, so a heavily-shunned cluster stalls rather than proceeding on a thinned
        quorum. Ejection is a manager action on the evidence; there is no rehabilitation here,
        because recovery is re-join as a new identity."""
        return frozenset(self.witness.convictions())

    def gathered(self, now: Millis, me: bool = True) -> list[attest.SignedAttestation]:
        """Every statement this node can vouch for by holding: its own, plus every peer's, each
        still carrying the signature of whoever made it (#freshness-is-gathered).

        `me=False` DROPS OUR OWN, and the currency question needs that: asking "is my view current"
        and counting our own attestation toward the answer is asking ourselves. Worse at the size
        that matters — a bootstrapping node with one peer would reach `f+1` on its own statement
        plus that one peer, so a single responder would decide."""
        mine = [self.attestation(now)] if me else []
        return [*mine, *self.witness.sightings()]

    def head_vouched_by(self, need: int, now: Millis, include_self: bool = True) -> int | None:
        """The highest head at least `need` distinct FRESH responders vouch for, ignoring
        anyone convicted. Renamed from `floor` when compaction went (rip 2/3): without a
        ratified checkpoint there is no "floor" concept, just a signed head each peer stakes
        its identity on."""
        return attest.attested_head(
            self.gathered(now, me=include_self),
            need,
            now,
            self.tunables.attest.fresh_within,
            shunned=self.shunned(),
        )

    def staleness(self, now: Millis) -> Millis | None:
        """How long since this node last heard from ANYONE — `None` if nobody is inside the window.

        Peers only: a node's own statement is stamped with the clock it is asking about, so it is
        fresh by construction and would report zero forever. The question worth answering is about
        the view of the cluster, not about itself."""
        return attest.staleness(
            self.witness.sightings(), now, self.tunables.attest.fresh_within, self.shunned()
        )

    # -- log transfer ---------------------------------------------------------------------------- #

    def catch_up(self, now: Millis) -> None:
        """Ask the peer that claims the longest log for what we are missing.

        Driven by what the gossip already told us: a sighting carries that peer's head, so being
        behind is something a node NOTICES rather than something it has to be told. One peer, not
        all of them -- the reply is bulk, and asking everyone would multiply it by the roster.

        NO-COMPACTION SHAPE. In this world the log is retained forever, so the join / lag case is
        always resolvable by pulling from `head + 1`. The `behind_the_horizon` refusal that used
        to gate this went with compaction (rip 2/3). L6 will reshape this into "next SETTLED
        block after X" once settlement lands (SPECv2 #sync-is-log-replay)."""
        mine = self.store.head()
        ahead = [s for s in self.witness.sightings() if s.claim.head > mine]
        if not ahead:
            return
        best = max(ahead, key=lambda s: s.claim.head)
        env = Envelope(best.by, Verb.PULL, _mid(), codec.encode([mine + 1])).sign(self.me, now)
        # AWAITING A REPLY, and that is not bookkeeping: `ENTRIES` is in `SOLICITED`, so an answer
        # this node did not register as expected is dropped at the door.
        self.postman.mailbox.post(env, now, self.tunables.net.ttl, await_reply=True)

    def _on_pull(self, env: SignedEnvelope, now: Millis) -> None:
        """Serve a run of settled entries from `frm`.

        BOUNDED, because a joiner asking from 1 would otherwise pull the whole log into one
        message. The requester asks again from where it got to, so the bound costs round trips
        and never correctness."""
        frm = codec.as_int(codec.as_seq(codec.decode(env.env.body), 1)[0])
        run = []
        for e in self.store.entries(max(frm, 1)):
            if len(run) >= self.tunables.net.pull_max:
                break
            run.append([e.idx, e.item.raw])
        self._reply(env, Verb.ENTRIES, codec.encode(run), now)

    def _on_entries(self, env: SignedEnvelope, _now: Millis) -> None:
        """Replay what we were sent, at the indices it was settled at.

        Only what is strictly ahead of our head: `replay` preserves positions, so re-applying an
        entry we already hold would collide rather than be idempotent. Signatures are verified
        inside `replay` -- a bulk transfer is exactly where trusting the sender would be cheapest
        and worst.

        THE SHAPE IS CHECKED, NOT ONLY THE CONTENT. `_uncontiguous` is one predicate for three
        failures: a gap, a repeat and a reordering are each "this index is not the one owed"."""
        if env.frm not in self.roster():
            return  # bulk state from outside the roster is not a thing that happens
        want = self.store.head() + 1
        run: list[Entry] = []
        for row in codec.as_seq(codec.decode(env.env.body)):
            f = codec.as_seq(row, 2)
            idx, raw = codec.as_int(f[0]), codec.as_bytes(f[1])
            if idx < want:
                continue
            run.append(Entry(idx, ops.SignedTransaction.decode(raw)))
        if not run or _uncontiguous(run, want) is not None:
            return  # nothing owed, or a run that would not land where it says it does
        said = self.witness.sighting(env.frm)
        expect = (
            Commitment(said.claim.head, said.claim.acc_state, said.claim.acc_log, said.claim.root)
            if said is not None
            else None
        )
        self.store.replay(run, expect)

    # -- the round ----------------------------------------------------------------------------- #

    def tick(self, now: Millis) -> None:
        """Advance: gossip, catch up, drive the consensus round, drive the wire.

        Round advancement lives in `Coordinator.tick` -- it drives the current Mempool's
        eviction (via bucket-swap), opens Rounds at boundaries, ticks them, flushes their
        outboxes, and settles any that ratified."""
        if now - self.last_probe >= self.tunables.attest.probe_every:
            self.probe(now)
        self.catch_up(now)
        self.coordinator.tick(now)
        self.postman.tick(now)

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
            env = Envelope(who, verb, _mid(), body).sign(self.me, now)
            # An announcement, so no answer is awaited: `BODIES` and `REFUSED` are `REPLIES`, which
            # `deliver` retires without needing a registered question.
            self.postman.mailbox.post(env, now, self.tunables.net.ttl, await_reply=False)

    def _reply(self, to: SignedEnvelope, verb: Verb, body: bytes, now: Millis) -> None:
        if to.frm not in self.postman.peers:
            return
        self.postman.mailbox.post(
            to.answer(verb, body).sign(self.me, now), now, self.tunables.net.ttl, await_reply=False
        )


def _uncontiguous(run: list[Entry], frm: int) -> str | None:
    """`None` if `run` is exactly the indices `frm, frm+1, …`, else which index broke it.

    ONE predicate for three failures, because they are the same failure: an entry at the wrong
    position. A gap loses entries nothing authorised forgetting — only a quorum-ratified checkpoint
    can license an absence, and a `PULL` reply is not one. A repeat is two entries claiming one
    position. A reordering is both at once.

    Returned rather than raised: a peer sending a malformed run is THEIR fault and routine
    (core/errors.py)."""
    want = frm
    for e in run:
        if e.idx != want:
            return f"run is not contiguous from {frm}: expected {want}, got {e.idx}"
        want += 1
    return None


def _mid() -> MessageId:
    return new_message_id()


_DISPATCH: dict[Verb, Callable[[Node, SignedEnvelope, Millis], None]] = {
    v: getattr(Node, f"_on_{v.name.lower()}") for v in HANDLED
}
"""Verb to handler, DERIVED from `HANDLED` rather than listed beside it.

So the two cannot drift: a verb added to `HANDLED` without a matching `_on_<verb>` fails at import,
and a handler with no verb is unreachable and obvious. The convention is load-bearing, which is the
only kind worth having."""
