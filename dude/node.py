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

from . import quorum
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
from .store import Commitment, Entry, Store, StoreError, attest, ops
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
        Verb.COLLECT,
        Verb.RATIFY,
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

    collecting: dict[int, ops.Compaction] = field(default_factory=dict)
    collected: set[int] = field(default_factory=set)
    last_probe: Millis = 0
    """When this node last asked its peers where they were (#cross-attestation)."""
    last_housekept: int = -1
    """The last bucket in which this node did compaction housekeeping. See `housekeep`."""
    shares: dict[bytes, dict[crypto.PublicKey, crypto.Signature]] = field(default_factory=dict)
    """Shares keyed by CLAIM BYTES, not by segment: two nodes disagreeing about the fold produce
    two different claims, and neither may borrow the other's signatures."""

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

    # -- collection (#collection-is-driven-by-any-node) ----------------------------------------- #

    def drain(self, seg: int, now: Millis) -> bool:
        """Offer this segment's stragglers for relocation. Returns whether there was anything.

        SUBMITTED, not applied. A migration is a log entry like any other and has to be agreed by
        the quorum — a node applying its own would diverge the log from its peers' while leaving
        `A_state` and the head identical, which is precisely how that went unnoticed before."""
        txn = self.store.migration(seg, self.me, now, self.tunables.compaction.migrate_at_most)
        if txn is None:
            return False
        if self.mempool.admit(txn, now, self.store, self.mgmt) is not None:
            return False
        self._flood(Verb.SUBMIT, txn.raw, now)
        return True

    @property
    def dedup_window(self) -> Millis:
        """How long a segment must age before it may be collected.

        DERIVED from the mempool's own admission window rather than passed in. It used to be a
        parameter of `maybe_collect` stashed on the node for `_try_collect` to read later — so a
        collection driven by a PEER used whatever a local call had last left behind, which was
        usually zero. The floor exists because collection forgets `op_hash` and the mempool would
        then re-admit a transaction inside it; a floor that applies on one code path and not the
        other is not a floor."""
        t = self.tunables.mempool
        return t.w_admit + t.w_valid_margin

    def housekeep(self, now: Millis) -> None:
        """Migrate the frontier's stragglers, then offer a collection. ONCE PER BUCKET.

        THE DUTIES THIS PERFORMS HAD NO DRIVER. `drain` and `maybe_collect` were both correct,
        tested, and called by nothing, so no node ever migrated or collected: the log grew without
        bound while `#compaction-is-required` says compaction is not an optimisation.

        THE FRONTIER, and only the frontier. Collection is oldest-first, so the one segment worth
        draining is the lowest retained — draining any other reclaims nothing, because a blocked
        segment below it stops collection anyway.

        ONCE PER BUCKET, and for `drain` that is a correctness matter rather than politeness:
        `migration` signs with `now`, so authoring the same relocation twice yields two different
        op_hashes, both valid — a `Move` asserts nothing, so the second still applies — and both
        consume log entries. A collection claim is byte-identical every time and does not have that
        problem, but shares the gate for quietness.

        PRESSURE IS A THRESHOLD, NOT A MODE `[H]`: `migrate_when` at zero means "whenever there are
        stragglers", so always-on is the floor of the same dial rather than a second code path. The
        clamp is separate and lives with the work, in `Store.migration`.

        IT REFUSES TO DRAIN THE CURRENT SEGMENT, which the first version of this did. Migration
        writes at the head, so relocating a straggler out of the segment that contains the head puts
        it back in the same segment — pointless traffic every bucket, for the whole life of a young
        cluster. `Store.collect` refuses a current segment for the same reason."""
        bucket = self.tunables.mempool.bucket(now)
        if bucket <= self.last_housekept:
            return
        self.last_housekept = bucket
        seg = self.store.horizon()
        if seg >= self.store.segment_of(self.store.head() + 1):
            return  # the frontier is the CURRENT segment: draining it into itself is a no-op
        pressure = len(self.store.stragglers(seg))
        if pressure and pressure >= self.tunables.compaction.migrate_when:
            self.drain(seg, now)
        self.maybe_collect(now)

    def _commitment(
        self, seg: int
    ) -> tuple[int, Millis, crypto.Accumulator, crypto.Accumulator, crypto.Digest]:
        """This node's claim about a segment: everything a checkpoint commits to, in one place.

        One constructor for the claim a node PROPOSES and the one it RECOMPUTES to ratify, so the
        two cannot drift — a peer that built its comparison differently would refuse honest claims,
        or worse, accept dishonest ones."""
        return (
            seg,
            self.store.head(),
            self.store.accumulator(),
            self.store.log_accumulator(),
            self.store.state_root(),
        )

    def maybe_collect(self, now: Millis) -> int | None:
        """Offer a collection if some segment is ready. Returns the segment, or None.

        NO DISTINGUISHED PROPOSER. Any node that notices may say so, and two nodes noticing the same
        segment is harmless — the claim is a function of the segment and the fold, not of who spoke
        first, so both propose byte-identical bytes.

        IN ORDER, AND IT BREAKS RATHER THAN SKIPS `[H]`. A blocked segment used to be skipped so a
        later one could collect, which left interior holes — and a hole in the middle of the log can
        only be explained by a per-collection record that grows for ever. Collecting oldest-first
        makes the retained log a contiguous SUFFIX, so one ratified marker names the frontier and
        nothing unbounded is needed. The collector then points the same way the conveyor already
        does: both work the oldest end of the belt.

        The cost is real and is paid by migration: one undrained segment stalls collection
        everywhere, so `drain` is not optional housekeeping but the thing that lets space be
        reclaimed at all.

        RE-PROPOSING IS DELIBERATE. Skipping a segment already in `collecting` would stall for ever
        if its quorum never formed — the old `continue` hid that by moving to a later segment. The
        claim is byte-identical every time, so shares pool and a re-flood costs one message."""
        for seg in self.store.segments():
            if seg >= self.store.segment_of(self.store.head() + 1):
                break  # not collectable, and neither is anything above it
            if self.store.stragglers(seg):
                break  # in order: this one is migrated first, or nothing moves
            claim = ops.Compaction(*self._commitment(seg))
            self.collecting[seg] = claim
            self._ratify_locally(claim, now)
            self._flood(Verb.COLLECT, claim.attest_bytes(), now)
            return seg
        return None

    def _on_collect(self, env: SignedEnvelope, now: Millis) -> None:
        """A peer claims a segment is collectable. Recompute the fold and sign only if it agrees.

        This is the check that has to happen WHILE the evidence exists: after collection nobody can
        re-derive it, so a wrong fold is refusable now and never again."""
        claim = _claim_from(env.env.body)
        if claim is None:
            return
        mine = ops.Compaction(*self._commitment(claim.segment))
        if mine.attest_bytes() != claim.attest_bytes():
            return  # we disagree about the fold; silence IS the refusal
        self.collecting.setdefault(claim.segment, claim)
        self._ratify_locally(claim, now)
        share = self.me.sign(claim.attest_bytes())
        self._flood(Verb.RATIFY, codec.encode([claim.attest_bytes(), share]), now)

    def _on_ratify(self, env: SignedEnvelope, now: Millis) -> None:
        f = codec.as_seq(codec.decode(env.env.body), 2)
        body, sig = codec.as_bytes(f[0]), crypto.Signature(codec.as_bytes(f[1]))
        claim = _claim_from(body)
        if claim is None or claim.segment in self.collected:
            return
        if not env.frm.verify(body, sig):
            return
        self.shares.setdefault(body, {})[env.frm] = sig
        self._try_collect(claim, now)

    def _ratify_locally(self, claim: ops.Compaction, now: Millis) -> None:
        body = claim.attest_bytes()
        # `Keypair.sign` rather than `sign_share(seed, ...)`: identical ed25519 signature, and it
        # does not require reaching for the private seed to produce one.
        self.shares.setdefault(body, {})[self.me.public] = self.me.sign(body)
        self._try_collect(claim, now)

    def _try_collect(self, claim: ops.Compaction, now: Millis) -> None:
        """Collect once a quorum has signed the SAME claim; `dude.quorum` defines that."""
        roster = list(self.roster())
        got = self.shares.get(claim.attest_bytes(), {})
        if not roster or not quorum.satisfied(len(roster), len(got)):
            return
        idx = {roster.index(k): s for k, s in got.items() if k in roster}
        bitmap, sigs = crypto.Ed25519ListMultiSig.combine(idx, len(roster))
        attested = ops.Compaction(
            claim.segment,
            claim.height,
            claim.acc_state,
            claim.acc_log,
            claim.root,
            bitmap,
            tuple(sigs),
        )
        try:
            self.store.collect(claim.segment, attested, now=now, dedup_window=self.dedup_window)
        except StoreError:
            # NOT YET, rather than a fault. The dedup floor is a timing condition: the segment is
            # still young enough that the mempool would re-admit one of its transactions, and it
            # will collect once it has aged. Letting this escape would take the node down from a
            # frame handler, which is the same shape as the duplicate-settlement crash.
            return
        self.collected.add(claim.segment)
        self.collecting.pop(claim.segment, None)

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

    def floor(self, need: int, now: Millis, include_self: bool = True) -> int | None:
        """The height this node would rely on: the max over `need` distinct FRESH peers and itself,
        ignoring anyone convicted, and counting only floors whose quorum signatures verify.

        The roster comes from our own log, which is the only roster we have any reason to trust —
        and a checkpoint signed by a roster we no longer recognise is one we cannot check, which is
        a bootstrap problem (§1) rather than something to paper over here."""
        return attest.attested_floor(
            self.gathered(now, me=include_self),
            need,
            now,
            self.tunables.attest.fresh_within,
            roster=list(self.roster()),
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

    # -- log transfer (#collect-whole-segment) -------------------------------------------------- #

    def catch_up(self, now: Millis) -> None:
        """Ask the peer that claims the longest log for what we are missing.

        Driven by what the gossip already told us: a sighting carries that peer's head, so being
        behind is something a node NOTICES rather than something it has to be told. One peer, not
        all of them — the reply is bulk, and asking everyone would multiply it by the roster."""
        mine = self.store.head()
        if self.behind_the_horizon():
            return  # a PULL cannot be served; see `behind_the_horizon`
        ahead = [s for s in self.witness.sightings() if s.claim.head > mine]
        if not ahead:
            return
        best = max(ahead, key=lambda s: s.claim.head)
        env = Envelope(best.by, Verb.PULL, _mid(), codec.encode([mine + 1])).sign(self.me, now)
        # AWAITING A REPLY, and that is not bookkeeping: `ENTRIES` is in `SOLICITED`, so an answer
        # this node did not register as expected is dropped at the door. Posted without it, the
        # pending entry died the instant the bytes left and every correctly-served run was thrown
        # away unread — `catch_up` had never once caught anything up in a cluster.
        self.postman.mailbox.post(env, now, self.tunables.net.ttl, await_reply=True)

    def behind_the_horizon(self) -> bool:
        """Are the entries this node needs already collected everywhere?

        THE DECISION THE SYNC PATH DID NOT HAVE. `catch_up` asked from `head + 1` for ever, and a
        server answered from whatever it still held, so being too far behind to catch up was
        indistinguishable from being slightly behind. This is that distinction, and it is decidable
        from one ratified marker: if the frontier has passed our head, the range we need does not
        exist anywhere and no number of round trips will produce it.

        WHAT IT DECIDES AND WHAT IT DOES NOT. This stops a node asking for what cannot be served.
        It does NOT decide whether to bootstrap, and must not: it reads THIS node's checkpoint, and
        a node that was absent while the cluster collected holds no newer one — so the node that
        most needs a walk is exactly the node this returns False for. `bootstrap` asks the same
        question of the marker f+1 fresh peers vouch for (`Store.frontier`)."""
        return self.store.retained_from() > self.store.head() + 1

    def _on_pull(self, env: SignedEnvelope, now: Millis) -> None:
        """Serve a run of settled entries from `frm`.

        BOUNDED, because a joiner asking from 1 would otherwise pull the whole log into one message.
        The requester asks again from where it got to, so the bound costs round trips and never
        correctness.

        AND IT DOES NOT ANSWER WITH A HOLE. Below `retained_from` the entries are collected, and
        `entries(frm)` would happily begin at the first index still held — a run with a gap at the
        front, through no lie by anybody, which the requester then committed. Serving nothing is the
        honest answer: the requester cannot use a gapped run, and it learns the horizon from the
        ratified marker that gossip already carries, which is what tells it to bootstrap instead."""
        frm = codec.as_int(codec.as_seq(codec.decode(env.env.body), 1)[0])
        if frm < self.store.retained_from():
            self._reply(env, Verb.ENTRIES, codec.encode([]), now)
            return
        run = []
        for e in self.store.entries(max(frm, 1)):
            if len(run) >= self.tunables.net.pull_max:
                break
            kind = (
                ops.KIND_COMPACTION if isinstance(e.item, ops.Compaction) else ops.KIND_TRANSACTION
            )
            run.append([e.idx, kind, e.item.raw])
        self._reply(env, Verb.ENTRIES, codec.encode(run), now)

    def _on_entries(self, env: SignedEnvelope, _now: Millis) -> None:
        """Replay what we were sent, at the indices it was settled at.

        Only what is strictly ahead of our head: `replay` preserves positions, so re-applying an
        entry we already hold would collide rather than be idempotent. Signatures are verified
        inside `replay` — a bulk transfer is exactly where trusting the sender would be cheapest and
        worst.

        THE SHAPE IS CHECKED, NOT ONLY THE CONTENT. A run is applied at the indices it names, so a
        run that skips one leaves a permanent hole — `catch_up` asks from the NEW head and never
        looks back — and two rows naming ONE index used to reach `entry.idx PRIMARY KEY` and raise
        `sqlite3.IntegrityError`, which is not a `DudeError` and so was a crash rather than a
        refusal. `_uncontiguous` is one predicate for all three failures: a gap, a repeat and a
        reordering are each "this index is not the one owed"."""
        if env.frm not in self.roster():
            return  # bulk state from outside the roster is not a thing that happens
        want = self.store.head() + 1
        run: list[Entry] = []
        for row in codec.as_seq(codec.decode(env.env.body)):
            f = codec.as_seq(row, 3)
            idx, kind, raw = codec.as_int(f[0]), codec.as_int(f[1]), codec.as_bytes(f[2])
            if idx < want:
                continue
            item = (
                ops.Compaction.decode(raw)
                if kind == ops.KIND_COMPACTION
                else ops.SignedTransaction.decode(raw)
            )
            run.append(Entry(idx, item))
        if not run or _uncontiguous(run, want) is not None:
            return  # nothing owed, or a run that would not land where it says it does
        # Checked against what the sender SIGNED, and rolled back if it disagrees. `replay` verifies
        # signatures, which says an entry was authored and never that the quorum settled it.
        said = self.witness.sighting(env.frm)
        expect = (
            Commitment(said.claim.head, said.claim.acc_state, said.claim.acc_log, said.claim.root)
            if said is not None
            else None
        )
        # The refusal comes BACK now rather than being raised (#no-exceptions-for-control-flow).
        # Nothing to do with it here: the run did not land, our state is untouched, and `catch_up`
        # will ask again. That a node which can NEVER reconcile keeps asking forever is the open
        # step's missing decision, not something this handler can answer.
        self.store.replay(run, expect)

    # -- the round ----------------------------------------------------------------------------- #

    def tick(self, now: Millis) -> None:
        """Advance: gossip, catch up if we can, bootstrap if we cannot, drive the consensus
        round, drive housekeeping, drive the wire.

        Round advancement now lives in `Coordinator.tick` -- it drives the current Mempool's
        eviction (via bucket-swap), opens Rounds at boundaries, ticks them, flushes their
        outboxes, and settles any that ratified. What used to be `Node._propose`/`_count`/
        `_settle` (the placeholder round mechanism) is gone."""
        if now - self.last_probe >= self.tunables.attest.probe_every:
            self.probe(now)
        self.catch_up(now)
        self.coordinator.tick(now)
        self.housekeep(now)
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


def _claim_from(body: bytes) -> ops.Compaction | None:
    """Decode a collection claim, or None. Malformed bytes from a peer are routine."""
    try:
        return ops.Compaction.from_attest_bytes(body)
    except DudeError:
        return None


_DISPATCH: dict[Verb, Callable[[Node, SignedEnvelope, Millis], None]] = {
    v: getattr(Node, f"_on_{v.name.lower()}") for v in HANDLED
}
"""Verb to handler, DERIVED from `HANDLED` rather than listed beside it.

So the two cannot drift: a verb added to `HANDLED` without a matching `_on_<verb>` fails at import,
and a handler with no verb is unreachable and obvious. The convention is load-bearing, which is the
only kind worth having."""
