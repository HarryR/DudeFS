"""Height attestations and the evidence they produce (#monotonicity, #cross-attestation).

A node cannot prove it is current — that is #the-lemma, and no object in this module changes it.
What a node CAN do is make a statement that is falsifiable, and this is that statement plus the
pure predicate that convicts on two of them.

The split mirrors `Envelope` / `SignedEnvelope` for the same reason: an `Attestation` is a claim
and carries no author, so attributing one to a key that did not sign it is not constructible.
"""

from __future__ import annotations

import enum
from collections.abc import Container, Iterable
from dataclasses import dataclass

from dude.core import codec, crypto
from dude.core.errors import DudeError
from dude.store import smt

_KIND_ATTESTATION = 2
"""Domain tag. Distinct from the entry kinds in `ops` because an attestation is NOT a log entry:
it is a statement ABOUT a log, and the two must never decode as one another."""


class AttestError(DudeError):
    """Malformed attestation bytes."""


@dataclass(frozen=True, slots=True)
class Attestation:
    """What a node says about itself: one committed snapshot of its own store.

    Every field is read inside a single transaction (`Store.attest`), so this is a coherent view
    rather than five reads that raced each other."""

    seq: int
    """A durable counter, bumped and COMMITTED before the claim is signed.

    Separate from `head` on purpose. Ordering two claims by the quantity under dispute is circular:
    were `seq` the height, a regression would be unorderable and therefore unconvictable.

    Gaps are free and reuse is fatal, so the counter is committed first and a crash merely skips a
    value (#monotonicity)."""

    head: int
    """The node's own highest settled index. A HINT, never a floor — a private opinion of one's own
    height is forgeable upward at no cost, which is why the floor below carries a quorum instead."""

    acc_state: crypto.Accumulator
    acc_log: crypto.Accumulator
    """Signed so that two nodes claiming one head with different folds is DETECTABLE. That is
    divergence, not conviction: it proves something is wrong and nothing about who."""

    at: int = 0
    """What this node's OWN clock read when it signed (#freshness-is-gathered).

    An assertion, never a ratified fact: no peer can recompute somebody else's clock, so a timestamp
    only ever speaks for one key. It is worth having anyway, because an adversary holding fewer than
    `f+1` keys cannot manufacture recent ones — it can replay, and a replay looks old. That turns
    silent staleness into visible staleness, which is the whole gain: a DIAGNOSTIC, not an
    adversarial liveness guarantee.

    Deliberately absent from `contradiction`: a clock stepping backwards is an NTP correction, and
    conviction is terminal."""

    root: crypto.Digest = smt.EMPTY
    """The state root at this node's own head (#state-root).

    Signed, so a client can check a single key against a node's CURRENT state rather than only
    the last one. If the node lies about it, the statement is convictable like any other."""

    def encode(self) -> bytes:
        return codec.encode(
            [
                _KIND_ATTESTATION,
                self.seq,
                self.head,
                self.acc_state,
                self.acc_log,
                self.at,
                self.root,
            ]
        )

    @classmethod
    def decode(cls, raw: bytes) -> Attestation:
        p = codec.as_seq(codec.decode(raw), 7)
        if codec.as_int(p[0]) != _KIND_ATTESTATION:
            raise AttestError("not an attestation")
        return cls(
            codec.as_int(p[1]),
            codec.as_int(p[2]),
            crypto.Accumulator(codec.as_bytes(p[3])),
            crypto.Accumulator(codec.as_bytes(p[4])),
            codec.as_int(p[5]),
            crypto.Digest(codec.as_bytes(p[6])),
        )


@dataclass(frozen=True, slots=True)
class SignedAttestation:
    """A claim plus the key that made it. The unit that travels, and the unit that convicts."""

    by: crypto.PublicKey
    claim: Attestation
    sig: crypto.Signature

    @classmethod
    def make(cls, kp: crypto.Keypair, claim: Attestation) -> SignedAttestation:
        return cls(kp.public, claim, kp.sign(claim.encode()))

    def verify(self) -> bool:
        return self.by.verify(self.claim.encode(), self.sig)

    def encode(self) -> bytes:
        return codec.encode([self.by, self.claim.encode(), self.sig])

    @classmethod
    def decode(cls, raw: bytes) -> SignedAttestation:
        p = codec.as_seq(codec.decode(raw), 3)
        return cls(
            crypto.PublicKey(codec.as_bytes(p[0])),
            Attestation.decode(codec.as_bytes(p[1])),
            crypto.Signature(codec.as_bytes(p[2])),
        )


class Fault(enum.Enum):
    """What two statements from one key prove about it.

    Ordinal 0 is `INVALID` per #no-exceptions-for-control-flow, so a Go port's zero value lands on
    a named invalid rather than on a real verdict."""

    INVALID = 0
    EQUIVOCATION = 1
    """One counter value, two different claims. The node said two things at once."""
    REGRESSION = 2
    """The counter advanced and a height went backwards. The node lost state it had attested —
    a restored snapshot, an operator's rollback, a wiped disk brought back to life."""


@dataclass(frozen=True, slots=True)
class Evidence:
    """A conviction, complete in itself. Two signed statements and a public key are the whole
    proof — no clock, no third party, no surrounding state, and it stays valid forever."""

    fault: Fault
    earlier: SignedAttestation
    later: SignedAttestation

    @property
    def culprit(self) -> crypto.PublicKey:
        return self.later.by

    def encode(self) -> bytes:
        return codec.encode([self.fault.value, self.earlier.encode(), self.later.encode()])

    @classmethod
    def decode(cls, raw: bytes) -> Evidence:
        p = codec.as_seq(codec.decode(raw), 3)
        return cls(
            Fault(codec.as_int(p[0])),
            SignedAttestation.decode(codec.as_bytes(p[1])),
            SignedAttestation.decode(codec.as_bytes(p[2])),
        )


def contradiction(a: SignedAttestation, b: SignedAttestation) -> Evidence | None:
    """Do these two statements convict the key that signed them? Pure (#cross-attestation).

    Returns `None` for everything that is merely suspicious. Silence, staleness and divergence are
    NOT faults here: a partition makes an honest node look stalled, and a cluster that convicted on
    appearances would eat itself the first time a link dropped.

    Accumulators are deliberately absent from the test. They are unordered, so there is nothing for
    them to regress — comparing them across two heights would convict every node that made progress.
    """
    if a.by != b.by:
        return None  # two keys disagreeing is divergence at most, and never attributable
    if not a.verify() or not b.verify():
        return None  # unsigned bytes are not evidence, however incriminating they read
    earlier, later = (a, b) if a.claim.seq <= b.claim.seq else (b, a)
    if earlier.claim.seq == later.claim.seq:
        if earlier.claim.encode() == later.claim.encode():
            return None  # the same statement served twice is not a second statement
        return Evidence(Fault.EQUIVOCATION, earlier, later)
    if later.claim.head < earlier.claim.head:
        return Evidence(Fault.REGRESSION, earlier, later)
    return None


@dataclass(frozen=True, slots=True)
class Frontier:
    """A node's answer to "where are you now": itself, and the latest it has heard of everyone else.

    ONE LEVEL DEEP, deliberately. If a sighting carried its own sightings the structure would
    recurse without terminating, so a relayed attestation is bare — a node speaks for itself and
    couriers others verbatim."""

    own: SignedAttestation
    sightings: tuple[SignedAttestation, ...] = ()
    """Verbatim and signed by the peer they describe, never an opinion ABOUT a peer. A relay holds
    no key but its own, so it can neither forge a sighting nor alter one: it cannot frame a peer
    and cannot be framed by one. The only lie left is silence (#cross-attestation)."""

    convictions: tuple[Evidence, ...] = ()
    """Proven contradictions this node holds.

    Carried because sightings alone do NOT make evidence transitive: a peer that convicts keeps
    the earlier statement and refuses the later one, so relaying sightings would relay only the
    innocent half and the pair would never travel. A node cut off from the culprit would then keep
    talking to it forever. Evidence is self-verifying, so a relay adds nothing and risks nothing —
    and the receiver RECOMPUTES the verdict rather than believing it."""

    def encode(self) -> bytes:
        return codec.encode(
            [
                self.own.encode(),
                [s.encode() for s in self.sightings],
                [e.encode() for e in self.convictions],
            ]
        )

    @classmethod
    def decode(cls, raw: bytes) -> Frontier:
        p = codec.as_seq(codec.decode(raw), 3)
        return cls(
            SignedAttestation.decode(codec.as_bytes(p[0])),
            tuple(SignedAttestation.decode(codec.as_bytes(s)) for s in codec.as_seq(p[1])),
            tuple(Evidence.decode(codec.as_bytes(e)) for e in codec.as_seq(p[2])),
        )


def fresh(
    atts: Iterable[SignedAttestation],
    now: int,
    window: int,
    shunned: Container[crypto.PublicKey] = (),
) -> dict[crypto.PublicKey, SignedAttestation]:
    """The statements worth counting: verified, unshunned, and timestamped inside the window.

    The window is SYMMETRIC, though the two sides mean different things. Too old is ordinary — a
    slow or dead node. Too far ahead is a clock fault or an attempt to look permanently fresh, since
    a future timestamp would still read as recent when replayed tomorrow. One number covers both,
    which is what makes it a cluster-wide tunable rather than a per-client judgement call
    (#freshness-is-gathered).

    Excluding a node here is NOT a punishment. A bad clock degrades what a node contributes; it does
    not convict it, and `contradiction` never looks at time."""
    keep: dict[crypto.PublicKey, SignedAttestation] = {}
    for a in atts:
        if a.by in shunned or not a.verify() or abs(now - a.claim.at) > window:
            continue
        held = keep.get(a.by)
        if held is None or a.claim.seq > held.claim.seq:
            keep[a.by] = a
    return keep


def attested_head(
    atts: Iterable[SignedAttestation],
    need: int,
    now: int,
    window: int,
    *,
    shunned: Container[crypto.PublicKey] = (),
) -> int | None:
    """The highest head that at least `need` fresh distinct responders vouch for, or None.

    The head is signed by the responder, so a peer can WITHHOLD a higher head but not forge one
    upward -- the highest honest answer wins and a lagging peer cannot drag it down
    (#freshness-needs-many). `need` is `f+1`, which is why a lone responder does not answer this
    question at all.

    A single-link client can still satisfy `need`: a relay holds no key but its own, so it can
    withhold or replay but never forge, and one link is enough to GATHER `f+1` signed statements
    the client checks for itself. That is what returned cold single-link clients to scope.

    HEAD IS A HINT, not a currency floor. Without a compaction / settlement anchor, a claimed
    head is just each responder's private opinion of its own progress -- useful for detecting
    a lagging local view, not usable as a checkpoint. The joiner path in tentative L6 walks the
    log forward from genesis regardless (SPECv2 #no-trusted-frontier)."""
    keep = fresh(atts, now, window, shunned)
    if len(keep) < need:
        return None
    return max(a.claim.head for a in keep.values())


def staleness(
    atts: Iterable[SignedAttestation],
    now: int,
    window: int,
    shunned: Container[crypto.PublicKey] = (),
) -> int | None:
    """How far behind the client is, at worst: the age of the freshest statement it can verify.

    A NUMBER rather than an unknown, which is the whole point. It is an upper bound on staleness and
    never a proof of currency — between that timestamp and now, anything may have happened."""
    keep = fresh(atts, now, window, shunned)
    if not keep:
        return None
    return now - max(a.claim.at for a in keep.values())


@dataclass(frozen=True, slots=True)
class AttestTunables:
    """This module's dials (`dude.tunables` holds the instance)."""

    probe_every: int = 30_000
    """How often a node asks its peers where they are. Sets how quickly a rollback is SEEN, not
    whether it is provable — evidence keeps forever."""

    fresh_within: int = 120_000
    """How recent a statement must be to count toward `f+1` (#freshness-is-gathered).

    MUST EXCEED `probe_every`, and by a comfortable margin: gathered statements are as old as the
    last probe round, so a window at or below the probe interval makes every bundle stale by
    construction and the floor unanswerable. Cluster-wide, because two clients disagreeing about
    whether the same bundle is fresh is a defect.

    Also absorbs an NTP step, which is a road bump of tens of seconds rather than a fault."""
