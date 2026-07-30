# dude.node — the gestalt: one storage node, with all the pieces joined.
#
# This is the first place the layers meet, and it exists to find out whether the seams are right.
# Everything below it has been built and tested in isolation; a node is what says whether isolation
# was the correct decomposition.
#
# WHAT IT OWNS, and nothing else:
#
#   store     the log                          (dude.store)
#   mempool   candidate transactions            (dude.mempool)
#   postman   the wire, and the only clock      (dude.net.postman)
#
# It contributes exactly one thing of its own: a `handle` mapping an inbound verb to an action, and
# a `tick` that advances the round. Anything more belongs in one of the parts.
#
# THE ROUND IS INCOMPLETE, NOT UNDECIDED — and the difference matters. #buckets specifies the
# mechanism (bucketing, observations, the `>= k` rule, the three-wave cadence); what is open is the
# **correctness argument** under partition and skew — a modelling task, not a missing design.
#
# What is implemented here: bucket arithmetic, one batch per node per bucket (MEMPOOL.md §4.1),
# endorsement counted by `dude.quorum` against a slice DIGEST, settlement through the one evaluator,
# rejects returned by `Mempool.reenter`.
#
# What is specified and NOT yet implemented: the `>= k` observation rule (#buckets) — this floods
# `PROPOSE` and counts endorsements instead of deriving the batch from who observed what — and the
# three-wave cadence, which is collapsed into one pass here. Both are known gaps against a written
# spec, and neither is waiting on a decision.

from __future__ import annotations

from collections.abc import Callable
from dataclasses import dataclass, field

from . import quorum
from .core import codec, crypto
from .core.errors import DudeError
from .mempool import Mempool
from .net import Verb
from .net.address import Endpoint
from .net.envelope import Envelope, Frame, MessageId, SignedEnvelope, new_message_id
from .net.link import LinkTunables, Peer, Transport
from .net.postman import Postman
from .net.transports import address_of
from .store import Commitment, Entry, Store, StoreError, attest, ops, settle
from .store.management import Management
from .tunables import DEFAULT, Tunables

_PULL_MAX = 256
"""Entries per `ENTRIES` reply. A bound on message size, not on how far a joiner may be behind."""

type Millis = int


REPLIES = frozenset({Verb.PONG, Verb.BODIES, Verb.REFUSED})
"""Verbs that ANSWER something we sent. They need no handler: `Postman.deliver` has already
correlated them and retired the pending entry, so reaching `_handle` means the useful work is done.

Named so "no handler" is a statement rather than an omission — otherwise a reply looks exactly
like a verb somebody forgot."""

HANDLED = frozenset(
    {
        Verb.SUBMIT,
        Verb.PROPOSE,
        Verb.ENDORSE,
        Verb.PING,
        Verb.COLLECT,
        Verb.RATIFY,
        Verb.FRONTIER,
        Verb.STANDING,
        Verb.PULL,
        Verb.ENTRIES,
    }
)
"""Verbs this node acts on."""

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
    mempool: Mempool = field(init=False)
    proposals: dict[int, dict[crypto.PublicKey, tuple[crypto.Digest, ...]]] = field(
        default_factory=dict
    )
    """Per bucket, what each node proposed. Keyed by proposer because §4.1 allows exactly one batch
    per node per bucket — a second is not a competing offer, it is equivocation."""

    endorsements: dict[tuple[int, crypto.Digest], set[crypto.PublicKey]] = field(
        default_factory=dict
    )
    """`(bucket, slice digest) -> who endorsed`. A SET, so a node endorsing twice counts once —
    otherwise one peer could manufacture a quorum by repeating itself."""

    settled_buckets: set[int] = field(default_factory=set)
    collecting: dict[int, ops.Compaction] = field(default_factory=dict)
    collected: set[int] = field(default_factory=set)
    last_probe: Millis = 0
    """When this node last asked its peers where they were (#cross-attestation)."""
    shares: dict[bytes, dict[crypto.PublicKey, crypto.Signature]] = field(default_factory=dict)
    """Shares keyed by CLAIM BYTES, not by segment: two nodes disagreeing about the fold produce
    two different claims, and neither may borrow the other's signatures."""

    def __post_init__(self) -> None:
        self.postman = Postman(self.me, window=self.tunables.net.window)
        self.mempool = Mempool(self.tunables.mempool)

    # -- membership ---------------------------------------------------------------------------- #

    @property
    def mgmt(self) -> Management:
        return Management(self.store)

    def connect(self, peer: crypto.PublicKey, transport: Transport) -> None:
        """Add a peer reachable in-process. A real deployment reads endpoints from the management
        store instead; this is the same `Peer` either way."""
        p = Peer(peer, lambda _e: transport, LinkTunables())
        p.reconfigure((Endpoint(address_of(peer)),))
        self.postman.peers[peer] = p

    def roster(self) -> tuple[crypto.PublicKey, ...]:
        return self.mgmt.node_set()

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
        refusal = self.mempool.admit(tx, now)
        if refusal is not None:
            self._reply(env, Verb.REFUSED, refusal.value.encode(), now)
            return
        self._reply(env, Verb.BODIES, tx.op_hash, now)
        self._flood(Verb.SUBMIT, env.env.body, now, skip=env.frm)

    def _on_propose(self, env: SignedEnvelope, now: Millis) -> None:
        bucket, ids = _decode_slice(env.env.body)
        seen = self.proposals.setdefault(bucket, {})
        if env.frm in seen:
            return  # one batch per node per bucket (§4.1); a second is equivocation, not an offer
        seen[env.frm] = ids
        self._flood(Verb.ENDORSE, env.env.body, now)
        self._count(bucket, _slice_digest(bucket, ids), self.me.public, now)

    def _on_endorse(self, env: SignedEnvelope, now: Millis) -> None:
        bucket, ids = _decode_slice(env.env.body)
        self._count(bucket, _slice_digest(bucket, ids), env.frm, now)

    # -- collection (#collection-is-driven-by-any-node) ----------------------------------------- #

    def drain(self, seg: int, now: Millis) -> bool:
        """Offer this segment's stragglers for relocation. Returns whether there was anything.

        SUBMITTED, not applied. A migration is a log entry like any other and has to be agreed by
        the quorum — a node applying its own would diverge the log from its peers' while leaving
        `A_state` and the head identical, which is precisely how that went unnoticed before."""
        txn = self.store.migration(seg, self.me, now)
        if txn is None:
            return False
        if self.mempool.admit(txn, now) is not None:
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
        first, so both propose byte-identical bytes."""
        for seg in self.store.segments():
            if seg in self.collecting or seg >= self.store.segment_of(self.store.head() + 1):
                continue
            if self.store.stragglers(seg):
                continue  # migrate first -- the caller's business, not a side effect of asking
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
        held = self.store.convictions()
        reply = attest.Frontier(self.attestation(now), self.store.sightings(), tuple(held.values()))
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
            self.store.witness(one)
        for claimed in said.convictions:
            if claimed.culprit != self.me.public:
                self.store.judge(claimed)

    def shunned(self) -> frozenset[crypto.PublicKey]:
        """Keys proven to have contradicted themselves.

        A LOCAL READ POLICY (#cross-attestation): it does not touch the roster or the quorum
        arithmetic, so a heavily-shunned cluster stalls rather than proceeding on a thinned
        quorum. Ejection is a manager action on the evidence; there is no rehabilitation here,
        because recovery is re-join as a new identity."""
        return frozenset(self.store.convictions())

    def gathered(self, now: Millis) -> list[attest.SignedAttestation]:
        """Every statement this node can vouch for by holding: its own, plus every peer's, each
        still carrying the signature of whoever made it (#freshness-is-gathered)."""
        return [self.attestation(now), *self.store.sightings()]

    def floor(self, need: int, now: Millis) -> int | None:
        """The height this node would rely on: the max over `need` distinct FRESH peers and itself,
        ignoring anyone convicted, and counting only floors whose quorum signatures verify.

        The roster comes from our own log, which is the only roster we have any reason to trust —
        and a checkpoint signed by a roster we no longer recognise is one we cannot check, which is
        a bootstrap problem (§1) rather than something to paper over here."""
        return attest.attested_floor(
            self.gathered(now),
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
            self.store.sightings(), now, self.tunables.attest.fresh_within, self.shunned()
        )

    # -- log transfer (#collect-whole-segment) -------------------------------------------------- #

    def catch_up(self, now: Millis) -> None:
        """Ask the peer that claims the longest log for what we are missing.

        Driven by what the gossip already told us: a sighting carries that peer's head, so being
        behind is something a node NOTICES rather than something it has to be told. One peer, not
        all of them — the reply is bulk, and asking everyone would multiply it by the roster."""
        mine = self.store.head()
        ahead = [s for s in self.store.sightings() if s.claim.head > mine]
        if not ahead:
            return
        best = max(ahead, key=lambda s: s.claim.head)
        env = Envelope(best.by, Verb.PULL, _mid(), codec.encode([mine + 1])).sign(self.me, now)
        self.postman.mailbox.post(env, now, self.tunables.net.ttl)

    def _on_pull(self, env: SignedEnvelope, now: Millis) -> None:
        """Serve a run of settled entries from `frm`.

        BOUNDED, because a joiner asking from 1 would otherwise pull the whole log into one message.
        The requester asks again from where it got to, so the bound costs round trips and never
        correctness."""
        frm = codec.as_int(codec.as_seq(codec.decode(env.env.body), 1)[0])
        run = []
        for e in self.store.entries(max(frm, 1)):
            if len(run) >= _PULL_MAX:
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
        said = self.store.sighting(env.frm)
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
        """Advance: send what is due, reap expiries, then propose for any closed bucket."""
        if now - self.last_probe >= self.tunables.attest.probe_every:
            self.probe(now)
        self.catch_up(now)
        self.postman.tick(now)
        self._propose(now)

    def _propose(self, now: Millis) -> None:
        """Offer this node's batch for the bucket that has just closed.

        PLACEHOLDER, see the module header — what is settled here is the bucket arithmetic, the
        one-batch-per-node rule and the screening; what is NOT settled is how nodes converge on one
        slice when their proposals differ — superseded by the rotating-leader ruling, under
        which the leader's proposal IS the slice and the question does not arise."""
        t = self.tunables.mempool
        bucket = t.bucket(now) - 1  # the bucket that just closed
        if bucket in self.settled_buckets or not self.mempool.may_propose(bucket):
            return
        batch = self.mempool.propose(bucket, self.store, self.mgmt)
        if not batch:
            return
        self.mempool.mark_proposed(bucket)
        ids = tuple(tx.op_hash for tx in batch)
        self.proposals.setdefault(bucket, {})[self.me.public] = ids
        body = _encode_slice(bucket, ids)
        self._flood(Verb.PROPOSE, body, now)
        self._count(bucket, _slice_digest(bucket, ids), self.me.public, now)

    def _count(
        self, bucket: int, digest: crypto.Digest, who: crypto.PublicKey, now: Millis
    ) -> None:
        """Record an endorsement and settle if it reaches a quorum.

        `dude.quorum` is asked, never reimplemented — the gate decides what consensus is and nothing
        here may depend on how it decides (#quorum-gate)."""
        if bucket in self.settled_buckets:
            return
        agreeing = self.endorsements.setdefault((bucket, digest), set())
        agreeing.add(who)
        n = len(self.roster()) or 1
        if not quorum.satisfied(n, len(agreeing)):
            return
        self._settle(bucket, digest, now)

    def _settle(self, bucket: int, digest: crypto.Digest, now: Millis) -> None:
        """Apply the agreed slice, then return the rejects to the mempool.

        The whole of MEMPOOL.md §0's loop, and it reuses the pieces rather than restating them:
        `Store.apply` drives `settle.evaluate`, and `Mempool.reenter` applies §5's finality
        distinction to whatever did not land."""
        ids = {i for prop in self.proposals.get(bucket, {}).values() for i in prop}
        held = {tx.op_hash: tx for tx in self._held(bucket)}
        batch = tuple(held[i] for i in sorted(ids) if i in held)
        if not batch:
            return
        applied = self.store.apply(batch, auth=self.mgmt)
        self.settled_buckets.add(bucket)
        landed = {op for op, _ in applied.settled}
        self.mempool.retire(tuple(tx for tx in batch if tx.op_hash in landed))
        self.mempool.reenter(
            tuple(
                settle.Reject(tx, settle.Verdict(why))
                for tx in batch
                for op, why in applied.dropped
                if tx.op_hash == op
            ),
            now,
        )
        _ = digest

    def _held(self, bucket: int) -> tuple[ops.SignedTransaction, ...]:
        return tuple(self.mempool.pending.get(bucket, {}).values())

    # -- outbound ------------------------------------------------------------------------------ #

    def _flood(
        self, verb: Verb, body: bytes, now: Millis, skip: crypto.PublicKey | None = None
    ) -> None:
        """Send to every peer. Flood announcements, pull bodies (MEMPOOL.md §3.2) — at this size the
        announcement term is small and reconciliation would buy bandwidth at the cost of latency,
        which is the wrong trade when wave latency IS finality latency."""
        for who in self.postman.peers:
            if who in (self.me.public, skip):
                continue
            env = Envelope(who, verb, _mid(), body).sign(self.me, now)
            self.postman.mailbox.post(env, now, self.tunables.net.ttl)

    def _reply(self, to: SignedEnvelope, verb: Verb, body: bytes, now: Millis) -> None:
        if to.frm not in self.postman.peers:
            return
        self.postman.mailbox.post(
            to.answer(verb, body).sign(self.me, now), now, self.tunables.net.ttl
        )


# --------------------------------------------------------------------------------------------- #
# Slice encoding — the only wire shape this module owns.                                        #
# --------------------------------------------------------------------------------------------- #


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


def _encode_slice(bucket: int, ids: tuple[crypto.Digest, ...]) -> bytes:
    return codec.encode([bucket, sorted(ids)])


def _decode_slice(raw: bytes) -> tuple[int, tuple[crypto.Digest, ...]]:
    f = codec.as_seq(codec.decode(raw), 2)
    return codec.as_int(f[0]), tuple(crypto.Digest(codec.as_bytes(x)) for x in codec.as_seq(f[1]))


def _slice_digest(bucket: int, ids: tuple[crypto.Digest, ...]) -> crypto.Digest:
    """What endorsement is counted against: the CONTENTS, not a proposer.

    Two nodes that independently assemble the same slice therefore endorse the same thing, which is
    what lets agreement happen with nobody in charge — and the open question was only what happens
    when they assemble DIFFERENT slices, which a rotating leader removes entirely."""
    return crypto.h(_encode_slice(bucket, ids))


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
