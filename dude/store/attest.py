"""Height attestations and the evidence they produce (#monotonicity, #cross-attestation).

A node cannot prove it is current — that is #the-lemma, and no object in this module changes it.
What a node CAN do is make a statement that is falsifiable, and this is that statement plus the
pure predicate that convicts on two of them.

The split mirrors `Envelope` / `SignedEnvelope` for the same reason: an `Attestation` is a claim
and carries no author, so attributing one to a key that did not sign it is not constructible.
"""

from __future__ import annotations

import enum
from dataclasses import dataclass

from dude.core import codec, crypto
from dude.core.errors import DudeError
from dude.store import ops

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

    ratified: ops.Compaction | None = None
    """The highest quorum-ratified checkpoint the node holds — the actual floor.

    `None` before the first collection, when there is no floor at all and only `head` carries
    information. Carried whole rather than as a bare height, because the signatures are the entire
    reason a floor cannot be forged upward."""

    @property
    def floor(self) -> int:
        """The attested height a client may rely on. Zero until the first checkpoint exists."""
        return self.ratified.height if self.ratified is not None else 0

    def encode(self) -> bytes:
        ck = self.ratified.encode() if self.ratified is not None else b""
        return codec.encode(
            [_KIND_ATTESTATION, self.seq, self.head, self.acc_state, self.acc_log, ck]
        )

    @classmethod
    def decode(cls, raw: bytes) -> Attestation:
        p = codec.as_seq(codec.decode(raw), 6)
        if codec.as_int(p[0]) != _KIND_ATTESTATION:
            raise AttestError("not an attestation")
        ck = codec.as_bytes(p[5])
        return cls(
            codec.as_int(p[1]),
            codec.as_int(p[2]),
            crypto.Accumulator(codec.as_bytes(p[3])),
            crypto.Accumulator(codec.as_bytes(p[4])),
            ops.Compaction.decode(ck) if ck else None,
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
    if later.claim.head < earlier.claim.head or later.claim.floor < earlier.claim.floor:
        return Evidence(Fault.REGRESSION, earlier, later)
    return None
