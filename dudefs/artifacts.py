# DudeFS L1 — typed, self-authenticating artifacts.
#
# ARCHITECTURE.md L1 / DESIGN.md §5, §8, §9, §11, §12 / PROTOCOL.md §1.
#
# Two iron rules (ARCHITECTURE L1):
#   * encodings are injective (everything signed or PRF'd rests on it), and
#   * identity is the received bytes, never a re-serialization — so an Op holds
#     its `raw` bytes and re-serves them verbatim; `op_hash = h(raw)`.
#
# The signature over an Op covers every envelope field *except* `sig` itself
# (DESIGN §5, "sign(author_sk, ↑ all of the above)"). The AEAD AAD is the hash
# of the envelope *minus payload and sig* — the "envelope-minus-payload"
# binding of DESIGN §5.

from __future__ import annotations

from collections.abc import Iterable, Mapping
from dataclasses import dataclass, field
from enum import Enum, auto
from functools import total_ordering
from typing import Any, ClassVar, NamedTuple, Self

from . import codec, crypto
from .codec import Bencodable
from .errors import DudeFSError


class ArtifactError(DudeFSError):
    """The artifacts module's base error: valid bencode that is not a valid
    artifact. Catch this for any of the leaves below. (Bencode-shape failures
    surface as codec.CodecError; both are DudeFSError.)"""


class UnknownField(ArtifactError):
    """An envelope carried a key that is not a known Field. The offending key is
    a structured attribute, not a string flavour."""

    def __init__(self, key: bytes):
        self.key = key
        super().__init__(f"unknown envelope field {key!r}")


class MissingField(ArtifactError):
    """A required field is absent from a decoded artifact. `key` is `bytes` (the
    common type of all field-key enums — Field, TxnField, ReceiptField, … — whose
    members ARE bytes), since MissingField spans every artifact's key set."""

    def __init__(self, key: bytes):
        self.key = key
        super().__init__(f"missing required field {key!r}")


# NB: a tuple with the wrong arity (HLC/Ballot/slot) is a bencode *shape* error,
# not an artifact-key error — it raises codec.CodecError via `codec.as_seq(v, n)`,
# in the same family as as_int/as_bytes. There is deliberately no MalformedField.


def _require(d: dict[bytes, Bencodable], key: bytes) -> Bencodable:
    """Fetch a required artifact field, raising the typed MissingField (never a
    bare KeyError) so it stays within the DudeFS hierarchy."""
    try:
        return d[key]
    except KeyError:
        raise MissingField(key) from None


class HeadEntry(NamedTuple):
    """One author's frontier position: the head op's `seq` and `op_hash`. A NamedTuple —
    tuple-backed and wire-identical to the [seq, hash] pair it serializes as, so it stays a
    cheap value while gaining names and the per-author `dominates` comparison the cut rules
    compose (was a bare `tuple[int, bytes]` destructured `(seq, _h)` everywhere)."""

    seq: int
    op_hash: bytes

    def dominates(self, other: HeadEntry) -> bool:
        """Advance-or-hold: my seq is at least as far as `other`'s. A checkpoint cut may add
        authors / higher seqs but never take one BACKWARDS — GC past a cut is irreversible
        (WP-F(a)/#4)."""
        return self.seq >= other.seq


# Per-author frontier: author-fingerprint -> head (seq, op_hash).
type Heads = dict[bytes, HeadEntry]


class BytesEnum(bytes, Enum):
    """Base for byte-string enums. Members ARE `bytes` — they encode via the
    canonical codec, hash and compare equal to their raw value, and serve as
    dict keys interchangeably with plain bytes. Shared by the control plane
    (ControlKind, Cap) and the data vocabulary (OpClass, Guard, Mutation)."""

    def __repr__(self) -> str:  # `Guard.ABSENT`, not `<Guard.ABSENT: b'absent'>`
        return f"{type(self).__name__}.{self.name}"


# --------------------------------------------------------------------------- #
# Constants                                                                    #
# --------------------------------------------------------------------------- #

GENESIS_PREV = b"\x00" * 32  # `prev` sentinel for seq 0 (DESIGN §5)
VERSION_ABSENT = b""  # `⊥` — key never seen / creation CAS (§6,§7)


class OpClass(BytesEnum):
    """Envelope `class` — control ops are node-folded plaintext; data ops are
    opaque ciphertext (DESIGN §5)."""

    DATA = b"data"
    CONTROL = b"control"


class Field(BytesEnum):
    """Envelope field keys (DESIGN §5). Members ARE bytes, so they serve as
    keys of the canonical dict and encode identically to the raw strings; the
    codec sorts keys, so declaration order is irrelevant to the wire."""

    AUTHOR = b"author"
    CLASS = b"class"
    HLC = b"hlc"
    KEYEPOCH = b"keyepoch"
    PAYLOAD = b"payload"
    PREV = b"prev"
    PVER = b"pver"
    SEQ = b"seq"
    SIG = b"sig"
    SLOT_TAG = b"slot_tag"  # absent <=> null (blind write)


def fingerprint(pubkey: bytes) -> bytes:
    """Stable identity of a key/cert: the content hash of its bytes."""
    return crypto.h(pubkey)


def slot_priority(slot_tag: bytes, client_fp: bytes) -> bytes:
    """A proposer's per-slot ballot tiebreak: `h(slot_tag ‖ client_fp)`. Replaces
    the raw `client_fp` as a ballot's low-order component so that WHICH proposer
    wins same-round ties VARIES per slot (NOTES item 24d) — otherwise the
    higher-fingerprint client wins every tie and can starve a peer under sustained
    single-key contention. Deterministic and identical on every node (they all
    hold `slot_tag` and the fingerprints), so single-decree/quorum-intersection
    are untouched; it is *not* a VRF — honest clients compute it the same way and
    a Byzantine node never proposes, so there is nothing to grind (DESIGN §1)."""
    return crypto.h(slot_tag + client_fp)


class RetainedEntry(NamedTuple):
    """A per-author retained-set commitment (DESIGN §12 rev 6): how many op-hashes are
    retained below the cut, and a digest over them. A NamedTuple (still a tuple, so it
    compares equal to the wire pair) — named access beats `entry[0]`/`entry[1]`. (Field
    is `size`, not `count`, since `tuple.count` is a method.)"""

    size: int
    digest: bytes


def retained_commitment(retained: list[Op]) -> dict[bytes, RetainedEntry]:
    """The per-author `(count, digest)` over retained op-hashes (DESIGN §12 rev 6,
    NOTES 29c) — carried by a checkpoint's `retained` field and by gossip SUMMARY.
    Plaintext (hashes are public metadata). Below the cut it does double duty: the
    anti-entropy diff key (what to PULL) AND the completeness/commitment evidence
    (a manager-signed digest replaces the per-op QCs that were GC'd, NOTES 29d), so
    an omission is detectable and localizes to a single author."""
    by_author: dict[bytes, list[bytes]] = {}
    for op in retained:
        by_author.setdefault(op.author, []).append(op.op_hash)
    return {
        a: RetainedEntry(len(hs), crypto.h(b"".join(sorted(hs)))) for a, hs in by_author.items()
    }


def covered(op: Op, cut: Heads) -> bool:
    """At-or-below the pinned cut, per-author by seq (DESIGN §12) — the boundary between the
    sparse baseline and the dense tail. The canonical predicate; store and anti-entropy both
    use it so they agree on the boundary."""
    entry = cut.get(op.author)
    return entry is not None and op.seq <= entry[0]


@dataclass(frozen=True)
class Baseline:
    """The below-cut manifest a checkpoint pins (DESIGN §12 rev 6): the per-author `cut`, the
    `retained` (size, digest) commitment over the covered∖dead projection, and the `dead` band
    GC'd since the previous checkpoint. ONE object for the (cut, retained, dead) triple that
    used to travel as loose args through baseline_digest / verify_baseline / adopt_checkpoint /
    the Summary + Checkpoint wire. In-memory grouping only — the encoding is unchanged."""

    cut: Heads
    retained: dict[bytes, RetainedEntry]
    dead: frozenset[bytes] = frozenset()

    @classmethod
    def of(cls, ops: list[Op], cut: Heads, dead: frozenset[bytes] = frozenset()) -> Baseline:
        """The manifest a set of `ops` presents at `cut`: the retained commitment over the
        RETAINED projection (covered ∖ dead). Excluding `dead` is load-bearing (WP1.3) — a
        lazy-GC node and a GC'd node then present the SAME digest, so completeness compares
        equal and neither re-pulls the other's superseded envelopes."""
        winners = [o for o in ops if covered(o, cut) and o.op_hash not in dead]
        return cls(cut, retained_commitment(winners), frozenset(dead))

    def mismatched(self, held: list[Op]) -> set[bytes]:
        """The authors whose `held` retained projection ≠ my committed digest (empty = the
        holder has the FULL below-cut baseline). A tampered or partial baseline fails here,
        localized to one author; the checkpoint signature is verified separately."""
        have = Baseline.of(held, self.cut, self.dead).retained
        return {a for a in set(have) | set(self.retained) if have.get(a) != self.retained.get(a)}


def roster_slot_tag(epoch: int) -> bytes:
    """The public slot a roster change `epoch -> epoch+1` contends on (DESIGN §13):
    `h("roster" ‖ epoch)`. Plaintext — the roster is public, so this needs no PRF
    secrecy; it just serializes roster changes so at most one activates out of any
    epoch (B4). Contested on the OLD roster through the ordinary ballot machinery."""
    return crypto.h(b"roster" + codec.encode(int(epoch)))


def checkpoint_slot_tag(seq: int) -> bytes:
    """The public slot checkpoint `seq` contends on (WP-F(c)): `h("checkpoint" ‖ seq)`.
    Like `roster_slot_tag`, keyed by a MONOTONE SEQUENCE — never by the cut/content — so
    any two compactors racing to be checkpoint `seq` land on the SAME slot and the quorum
    decrees exactly one, whatever cut it chose in the finality window. Serializes the
    checkpoint chain through the ordinary ballot machinery; no PRF secrecy (all public)."""
    return crypto.h(b"checkpoint" + codec.encode(int(seq)))


def quorum_size(n: int) -> int:
    """Majority = floor(n/2)+1 = ceil((n+1)/2) (DESIGN §13).
    n=1->1, 3->2, 5->3, 7->4."""
    return (n // 2) + 1


# --------------------------------------------------------------------------- #
# HLC — hybrid logical clock (DESIGN §5, §9)                                   #
# --------------------------------------------------------------------------- #


@total_ordering
class HLC:
    """(wall_ms, counter). Total order is lexicographic. Per-author HLCs are
    strictly monotone along a chain (DESIGN §4)."""

    __slots__ = ("wall_ms", "counter")

    def __init__(self, wall_ms: int, counter: int = 0):
        self.wall_ms = int(wall_ms)
        self.counter = int(counter)

    def encode(self) -> tuple[int, int]:
        return (self.wall_ms, self.counter)

    @staticmethod
    def decode(v: Bencodable) -> HLC:
        items = codec.as_seq(v, 2)
        return HLC(codec.as_int(items[0]), codec.as_int(items[1]))

    def as_tuple(self):
        return (self.wall_ms, self.counter)

    def __eq__(self, o):
        return isinstance(o, HLC) and self.as_tuple() == o.as_tuple()

    def __lt__(self, o):
        return self.as_tuple() < o.as_tuple()

    def __le__(self, o):
        return self.as_tuple() <= o.as_tuple()

    def __hash__(self):
        return hash(self.as_tuple())

    def __repr__(self):
        return f"HLC({self.wall_ms},{self.counter})"


# --------------------------------------------------------------------------- #
# Ballot — (round, client_fp), lexicographic; blind writes are BLIND (§8)      #
# --------------------------------------------------------------------------- #


@total_ordering
class Ballot:
    """DESIGN §8: `ballot = (round, priority)`, ordered lexicographically. A
    slotted proposer sets `priority = slot_priority(slot_tag, client_fp)` so
    same-round ties are broken per-slot (NOTES item 24d), not by a fixed global
    fingerprint order. Blind writes carry the sentinel BLIND = (0, b'') — no slot,
    always receipted (subject to §9's skew window)."""

    __slots__ = ("round", "priority")

    def __init__(self, round_: int, priority: bytes):
        self.round = int(round_)
        self.priority = bytes(priority)

    def encode(self) -> tuple[int, bytes]:
        return (self.round, self.priority)

    @staticmethod
    def decode(v: Bencodable) -> Ballot:
        items = codec.as_seq(v, 2)
        return Ballot(codec.as_int(items[0]), codec.as_bytes(items[1]))

    def as_tuple(self):
        return (self.round, self.priority)

    def __eq__(self, o):
        return isinstance(o, Ballot) and self.as_tuple() == o.as_tuple()

    def __lt__(self, o):
        return self.as_tuple() < o.as_tuple()

    def __le__(self, o):
        return self.as_tuple() <= o.as_tuple()

    def __hash__(self):
        return hash(self.as_tuple())

    def is_blind(self):
        return self.round == 0 and self.priority == b""

    def __repr__(self):
        return f"Ballot({self.round},{self.priority.hex()[:8]})"


BLIND = Ballot(0, b"")


# --------------------------------------------------------------------------- #
# Slot tags & preimages (DESIGN §7)                                            #
# --------------------------------------------------------------------------- #


class Slot(NamedTuple):
    """A CAS coordinate — the injective preimage of a slot tag (DESIGN §6/§7): a key at a
    (version, attempt) lineage position. `version = VERSION_ABSENT` (empty) while the key is
    absent — a creation CAS is attempt 0 on ⊥. It owns its tag derivation, so a caller holding
    the epoch's `slot_secret` asks the coordinate for its tag instead of spreading three fields
    across a free function. This is the private half of a predicate; the public tag is opaque."""

    key: bytes
    version: bytes
    attempt: int

    def preimage(self) -> bytes:
        """Injective `key ‖ version ‖ attempt` as a bencoded 3-list (IMPLEMENTATION §2)."""
        return codec.encode([self.key, self.version, int(self.attempt)])

    def tag(self, slot_secret: bytes) -> bytes:
        """`E(k) = PRF(slot_secret[e], key ‖ version ‖ attempt)` (DESIGN §6/§7) — the public tag."""
        return crypto.prf_tag(slot_secret, self.preimage())


# --------------------------------------------------------------------------- #
# Op — the operation (envelope + payload), DESIGN §5                           #
# --------------------------------------------------------------------------- #


class _OpFields:
    """Cooperative-decode root. `_kwargs` chains via `super()` UP the op hierarchy
    — Op adds the envelope-common fields, `Slotted` adds `slot_tag`, `DataOp` adds
    keyepoch/payload — and bottoms out here. So decode lives ON the types (no free
    functions), each level owns exactly its own fields, and a leaf is built with
    `leaf(**leaf._kwargs(env, raw))` (HANDOFF-R8: the wrapping pattern)."""

    __slots__ = ()

    @classmethod
    def _kwargs(cls, env: dict[bytes, Bencodable], raw: bytes) -> dict[str, Any]:
        return {"raw": raw}


class Slotted(_OpFields):
    """Mixin adding a NON-optional `slot_tag` to the ops decided by single-decree
    agreement (CAS, roster, checkpoint) — mixed in ONLY there, so a non-slotted op
    has no `slot_tag` at all (ask `isinstance(op, Slotted)`; never probe a field for
    None). `quorum.Commit` takes a `Slotted`, so `slot_tag` is `bytes` by the type.
    Public slots bind the tag to the op's own fields (`expected_slot_tag`); CAS binds
    via a PRF over a node-invisible secret, checked in the fold by attribution."""

    __slots__ = ()
    slot_tag: bytes  # a dataclass field on each concrete slotted leaf

    @classmethod
    def _kwargs(cls, env: dict[bytes, Bencodable], raw: bytes) -> dict[str, Any]:
        return {
            **super()._kwargs(env, raw),
            "slot_tag": codec.as_bytes(_require(env, Field.SLOT_TAG)),
        }

    def expected_slot_tag(self) -> bytes | None:
        """The public slot binding, or None when it is secret (CAS)."""
        return None

    def slot_binding_ok(self) -> bool:
        exp = self.expected_slot_tag()
        return exp is None or self.slot_tag == exp


@dataclass(frozen=True, slots=True, kw_only=True)
class Op(_OpFields):
    """A self-authenticating operation, decoded ONCE into a concrete leaf. Identity
    is the received bytes (`raw`); `op_hash = h(raw)`. Ingest via `from_bytes`
    (dispatches on `class`); author via each leaf's own typed `build` — there is NO
    generic field-bag builder. The signature covers every envelope field but `sig`;
    the data AAD is envelope-minus-payload-minus-sig (DESIGN §5)."""

    author: crypto.PublicKey
    seq: int
    prev: bytes
    hlc: HLC
    pver: int
    sig: bytes
    raw: bytes
    op_hash: bytes = field(init=False, compare=False, repr=False)

    def __post_init__(self) -> None:
        object.__setattr__(self, "op_hash", crypto.h(self.raw))

    @property
    def is_control(self) -> bool:
        return False  # ControlOp overrides -> True (polymorphism, no forward ref)

    # ---- decode: each level owns its fields, chained via super() ----------- #
    @classmethod
    def _kwargs(cls, env: dict[bytes, Bencodable], raw: bytes) -> dict[str, Any]:
        return {
            **super(Op, cls)._kwargs(env, raw),  # explicit super — slots recreates the class
            "author": crypto.PublicKey(codec.as_bytes(_require(env, Field.AUTHOR))),
            "seq": codec.as_int(_require(env, Field.SEQ)),
            "prev": codec.as_bytes(_require(env, Field.PREV)),
            "hlc": HLC.decode(_require(env, Field.HLC)),
            "pver": codec.as_int(_require(env, Field.PVER)),
            "sig": codec.as_bytes(_require(env, Field.SIG)),
        }

    @staticmethod
    def _envelope(raw: bytes) -> dict[bytes, Bencodable]:
        """Canonical envelope bytes -> {Field: value}, rejecting unknown keys with
        the typed UnknownField (validation, not a cast)."""
        out: dict[bytes, Bencodable] = {}
        for k, v in codec.as_dict(codec.decode(raw)).items():
            try:
                out[Field(k)] = v
            except ValueError:
                raise UnknownField(k) from None
        return out

    @classmethod
    def from_bytes(cls, raw: bytes) -> Op:
        """Decode ONCE and return the concrete leaf (data op / control leaf /
        InvalidOp). Rejects non-canonical bytes and unknown envelope fields."""
        env = Op._envelope(raw)
        if env.get(Field.CLASS) == OpClass.CONTROL:
            return ControlOp._from_envelope(env, raw)
        return DataOp._from_envelope(env, raw)

    # ---- verification ------------------------------------------------------ #
    def verify_structure(self) -> bool:
        """Value-level structural checks over the typed fields (shape/canonicity are
        enforced by `from_bytes` — a mistyped field can't become an Op). Leaves
        extend it (DataOp: keyepoch >= 0)."""
        if self.seq < 0 or self.pver < 0:
            return False
        if len(self.prev) != 32:
            return False
        if self.seq == 0 and self.prev != GENESIS_PREV:
            return False
        return True

    def verify_sig(self, author_pubkey: crypto.PublicKey | None = None) -> bool:
        """Verify the signature over the RECEIVED bytes minus `sig` (identity is the
        received bytes; a control payload need not be canonical bencode internally,
        so we verify over what actually arrived — DESIGN §5)."""
        pk = self.author if author_pubkey is None else author_pubkey
        try:
            env = Op._envelope(self.raw)
        except ArtifactError:
            return False
        env.pop(Field.SIG, None)
        return pk.verify(codec.encode(env), self.sig)

    # ---- authoring core: each leaf `build` signs, then constructs itself --- #
    @staticmethod
    def _sign(author: crypto.Keypair, fields: dict[Field, Bencodable]) -> tuple[bytes, bytes]:
        """Sign `fields` (no SIG yet); return (raw, sig). A leaf's `build` assembles
        its own wire `fields`, signs here, then constructs itself DIRECTLY from its
        typed params + this raw/sig — no encode-then-decode round-trip."""
        sig = author.sign(codec.encode(fields))
        return codec.encode({**fields, Field.SIG: sig}), sig


# ---- data leaves ----------------------------------------------------------- #


@dataclass(frozen=True, slots=True, kw_only=True)
class DataOp(Op):
    """An opaque, encrypted data op (DESIGN §5). `payload` is AEAD ciphertext
    (`nonce ‖ ct ‖ tag`); only a key-holding client can `open_payload` it.
    `keyepoch` (envelope-level, DATA-ONLY) selects the group key."""

    keyepoch: int
    payload: bytes

    @classmethod
    def _kwargs(cls, env: dict[bytes, Bencodable], raw: bytes) -> dict[str, Any]:
        return {
            **super(DataOp, cls)._kwargs(env, raw),
            "keyepoch": codec.as_int(_require(env, Field.KEYEPOCH)),
            "payload": codec.as_bytes(_require(env, Field.PAYLOAD)),
        }

    @classmethod
    def _from_envelope(cls, env: dict[bytes, Bencodable], raw: bytes) -> DataOp:
        """A data op is a CasOp if it carries a slot_tag, else a BlindPutOp."""
        leaf = CasOp if Field.SLOT_TAG in env else BlindPutOp
        return leaf(**leaf._kwargs(env, raw))

    def _aad_fields(self) -> dict[Field, Bencodable]:
        f: dict[Field, Bencodable] = {
            Field.CLASS: OpClass.DATA,
            Field.AUTHOR: self.author,
            Field.SEQ: self.seq,
            Field.PREV: self.prev,
            Field.HLC: self.hlc.encode(),
            Field.PVER: self.pver,
            Field.KEYEPOCH: self.keyepoch,
        }
        if isinstance(self, Slotted):
            f[Field.SLOT_TAG] = self.slot_tag
        return f

    def aad_hash(self) -> bytes:
        # envelope-minus-payload-minus-sig, rebuilt from typed fields (payload
        # excluded -> no inner-canonicity concern; no re-decode).
        return crypto.h(codec.encode(self._aad_fields()))

    def open_payload(self, data_key: bytes) -> bytes | None:
        """Decrypt -> plaintext Txn bytes, or None on authentication failure (⊥)."""
        return crypto.AEAD.open(data_key, self.aad_hash(), self.payload)

    def read_txn(self, keyring: crypto.Keyring) -> Txn | Opaque:
        """Decode this data op's payload into a Txn, or an Opaque with a typed reason
        (undecryptable / malformed) — the client-side inverse of authoring (DESIGN §5/§6;
        was `handlers.data.decode`). Total over arbitrary envelopes: a missing keyepoch or
        an unreadable payload is Opaque, never a raised exception (NOTES item 17). A ZK
        storage node never calls this — it holds no keyring."""
        ring = keyring.get(self.keyepoch)
        if ring is None:
            return Opaque(OpaqueReason.NO_KEY)
        try:
            pt = self.open_payload(ring.data_key)
        except (ArtifactError, codec.CodecError):
            return Opaque(OpaqueReason.MALFORMED_TXN)  # unreadable envelope fields
        if pt is None:
            return Opaque(OpaqueReason.AEAD_OPEN_FAILED)  # authentication failure (⊥)
        try:
            return Txn.decode(pt)
        except Exception:
            return Opaque(OpaqueReason.MALFORMED_TXN)

    def verify_structure(self) -> bool:
        return super(DataOp, self).verify_structure() and self.keyepoch >= 0

    @staticmethod
    def _seal_and_sign(
        *,
        author: crypto.Keypair,
        seq: int,
        prev: bytes,
        hlc: HLC,
        pver: int,
        keyepoch: int,
        slot_tag: bytes | None,
        data_key: bytes,
        txn_bytes: bytes,
    ) -> tuple[bytes, bytes, bytes]:
        """Seal `txn_bytes` (AAD = envelope-minus-payload, computed before the payload
        exists — DESIGN §5) and sign; return (payload, raw, sig) so the data leaf
        constructs itself directly. Shared by both data builds."""
        f: dict[Field, Bencodable] = {
            Field.CLASS: OpClass.DATA,
            Field.AUTHOR: author.public,
            Field.SEQ: int(seq),
            Field.PREV: prev,
            Field.HLC: hlc.encode(),
            Field.PVER: int(pver),
            Field.KEYEPOCH: int(keyepoch),
        }
        if slot_tag is not None:
            f[Field.SLOT_TAG] = slot_tag
        payload = crypto.AEAD.seal(data_key, crypto.h(codec.encode(f)), txn_bytes)
        f[Field.PAYLOAD] = payload
        raw, sig = Op._sign(author, f)
        return payload, raw, sig


@dataclass(frozen=True, slots=True, kw_only=True)
class CasOp(DataOp, Slotted):
    """A slotted data op — CAS contended on `slot_tag` (guaranteed non-None) via the
    ballot machinery. The tag is `Slot(key, version, attempt).tag(secret)` over a secret
    the node cannot see, so its binding is verified in the fold by attribution (§7)."""

    slot_tag: bytes

    @classmethod
    def build(
        cls,
        *,
        author: crypto.Keypair,
        seq: int,
        prev: bytes,
        hlc: HLC,
        keyepoch: int,
        data_key: bytes,
        txn_bytes: bytes,
        slot_tag: bytes,
        pver: int = 0,
    ) -> Self:
        payload, raw, sig = DataOp._seal_and_sign(
            author=author,
            seq=seq,
            prev=prev,
            hlc=hlc,
            pver=pver,
            keyepoch=keyepoch,
            slot_tag=slot_tag,
            data_key=data_key,
            txn_bytes=txn_bytes,
        )
        return cls(
            author=author.public,
            seq=int(seq),
            prev=prev,
            hlc=hlc,
            pver=int(pver),
            sig=sig,
            raw=raw,
            keyepoch=int(keyepoch),
            payload=payload,
            slot_tag=slot_tag,
        )


@dataclass(frozen=True, slots=True, kw_only=True)
class BlindPutOp(DataOp):
    """A blind data write — no slot, always receipted at the BLIND ballot (§8)."""

    @classmethod
    def build(
        cls,
        *,
        author: crypto.Keypair,
        seq: int,
        prev: bytes,
        hlc: HLC,
        keyepoch: int,
        data_key: bytes,
        txn_bytes: bytes,
        pver: int = 0,
    ) -> Self:
        payload, raw, sig = DataOp._seal_and_sign(
            author=author,
            seq=seq,
            prev=prev,
            hlc=hlc,
            pver=pver,
            keyepoch=keyepoch,
            slot_tag=None,
            data_key=data_key,
            txn_bytes=txn_bytes,
        )
        return cls(
            author=author.public,
            seq=int(seq),
            prev=prev,
            hlc=hlc,
            pver=int(pver),
            sig=sig,
            raw=raw,
            keyepoch=int(keyepoch),
            payload=payload,
        )


@dataclass(frozen=True, slots=True, kw_only=True)
class ControlOp(Op):
    """A plaintext, node-folded control op (DESIGN §5 carve-out). Abstract base for
    the concrete control leaves (defined with the control section below, alongside
    the kind vocabulary they dispatch through). `from_bytes` never yields a bare
    ControlOp — a well-formed body -> its leaf, a malformed/unknown one -> InvalidOp."""

    KIND: ClassVar[ControlKind]  # each concrete leaf assigns its kind (InvalidOp has none)

    @property
    def is_control(self) -> bool:
        return True  # overrides Op.is_control; InvalidOp (a ControlOp) inherits this

    @classmethod
    def _from_envelope(cls, env: dict[bytes, Bencodable], raw: bytes) -> Op:
        """Decode the plaintext body ONCE, dispatch to the kind's leaf `_from_body`,
        or InvalidOp on any failure (totality — never raises on wire input, NOTES 17)."""
        invalid = InvalidOp(**InvalidOp._kwargs(env, raw))
        try:
            body = codec.decode(codec.as_bytes(_require(env, Field.PAYLOAD)))
        except (codec.CodecError, ArtifactError):
            return invalid
        if not isinstance(body, dict) or BK_KIND not in body:
            return invalid
        try:
            kind = ControlKind(body[BK_KIND])
        except ValueError:
            return invalid  # unknown kind — fail-closed (lane-3 gates new kinds)
        leaf = _CONTROL_LEAVES.get(kind)
        if leaf is None:
            return invalid
        try:
            return leaf._from_body(env, raw, body)
        except (codec.CodecError, ArtifactError, KeyError, TypeError):
            return invalid

    @classmethod
    def _from_body(
        cls, env: dict[bytes, Bencodable], raw: bytes, body: dict[bytes, Bencodable]
    ) -> Op:
        """Construct this leaf from the envelope + already-decoded body. Each concrete
        leaf overrides; the base is unreachable (dispatch only hits a known leaf)."""
        raise NotImplementedError

    @staticmethod
    def _control_raw(
        author: crypto.Keypair,
        *,
        seq: int,
        prev: bytes,
        hlc: HLC,
        pver: int,
        body: bytes,
        slot_tag: bytes | None = None,
    ) -> tuple[bytes, bytes]:
        """Assemble + sign a CONTROL envelope (no keyepoch — control carries it in the
        body); return (raw, sig). Each leaf's `build` encodes its body, calls this, then
        constructs itself directly."""
        f: dict[Field, Bencodable] = {
            Field.CLASS: OpClass.CONTROL,
            Field.AUTHOR: author.public,
            Field.SEQ: int(seq),
            Field.PREV: prev,
            Field.HLC: hlc.encode(),
            Field.PVER: int(pver),
            Field.PAYLOAD: body,
        }
        if slot_tag is not None:
            f[Field.SLOT_TAG] = slot_tag
        return Op._sign(author, f)


@dataclass(frozen=True, slots=True, kw_only=True)
class InvalidOp(ControlOp):
    """A well-formed envelope whose (control) body is unparseable or an unknown
    kind. An explicit variant so the fold treats it `invalid` BY TYPE (totality,
    NOTES 17), not a None sentinel."""


# --------------------------------------------------------------------------- #
# Control ops — the plaintext, node-folded leaves (DESIGN §5 carve-out, §12/13) #
# --------------------------------------------------------------------------- #
#
# The control-plane leaves live in the FORMAT LAYER (HANDOFF-R8 §3a): each is a
# concrete `ControlOp` subclass carrying its decoded body fields, so `from_bytes`
# dispatches natively (no registry). Node-folded semantics (roster/cert
# application) stay in the state machines (fold.ControlState) — this is structure
# and bytes only. `decode()` maps any malformed/unknown body to InvalidOp so the
# fold stays total (NOTES 17).

BK_KIND = b"kind"  # body discriminator (a field key, not a value vocabulary)


class ControlKind(BytesEnum):
    """The kind of a control-op body (DESIGN §12, §13, §15, §16). An unknown kind
    -> InvalidOp (fail-closed; new kinds are lane-3 gated, DESIGN §16)."""

    CERT_ISSUE = b"cert_issue"
    CERT_REVOKE = b"cert_revoke"
    ROSTER = b"roster"
    ROTATE = b"rotate"
    WRAP_SET = b"wrap_set"
    CHECKPOINT = b"checkpoint"
    PVER_ACTIVATE = b"pver_activate"
    ENDPOINT = b"endpoint"


class Cap(BytesEnum):
    """Capability certs grant (DESIGN §15)."""

    WRITE = b"write"
    STORE = b"store"
    COMPACT = b"compact"
    MANAGE_ROSTER = b"manage-roster"
    ISSUE_REVOKE = b"issue-revoke"


# small generic body-value parsers (codec-level, shared by the leaves' `_from_body`)
def _uint(v: Bencodable) -> int:
    n = codec.as_int(v)
    if n < 0:
        raise codec.CodecError("expected a non-negative integer")
    return n


def _heads(v: Bencodable) -> Heads:
    out: Heads = {}
    for author, entry in codec.as_dict(v).items():
        pair = codec.as_seq(entry, 2)
        out[author] = HeadEntry(_uint(pair[0]), codec.as_bytes(pair[1]))
    return out


def _retained(v: Bencodable) -> dict[bytes, RetainedEntry]:
    """Per-author retained-set commitment {author: (size, digest)} (DESIGN §12 rev 6,
    NOTES 29c). Plaintext — op-hashes are public metadata."""
    out: dict[bytes, RetainedEntry] = {}
    for author, entry in codec.as_dict(v).items():
        pair = codec.as_seq(entry, 2)
        out[author] = RetainedEntry(_uint(pair[0]), codec.as_bytes(pair[1]))
    return out


@dataclass(frozen=True, slots=True, kw_only=True)
class CertIssueOp(ControlOp):
    KIND: ClassVar[ControlKind] = ControlKind.CERT_ISSUE
    subject: bytes
    caps: list[bytes]
    epoch: int

    @classmethod
    def _from_body(
        cls, env: dict[bytes, Bencodable], raw: bytes, body: dict[bytes, Bencodable]
    ) -> Self:
        return cls(
            **cls._kwargs(env, raw),
            subject=codec.as_bytes(codec.field(body, b"subject")),
            caps=[codec.as_bytes(c) for c in codec.as_seq(codec.field(body, b"caps"))],
            epoch=_uint(codec.field(body, b"epoch")),
        )

    @classmethod
    def build(
        cls,
        *,
        author: crypto.Keypair,
        seq: int,
        prev: bytes,
        hlc: HLC,
        subject: bytes,
        caps: Iterable[bytes],
        epoch: int,
        pver: int = 0,
    ) -> Self:
        body = codec.encode(
            {
                BK_KIND: cls.KIND,
                b"subject": subject,
                b"caps": [bytes(c) for c in caps],
                b"epoch": int(epoch),
            }
        )
        raw, sig = ControlOp._control_raw(author, seq=seq, prev=prev, hlc=hlc, pver=pver, body=body)
        return cls(
            author=author.public,
            seq=int(seq),
            prev=prev,
            hlc=hlc,
            pver=int(pver),
            sig=sig,
            raw=raw,
            subject=subject,
            caps=[bytes(c) for c in caps],
            epoch=int(epoch),
        )


@dataclass(frozen=True, slots=True, kw_only=True)
class CertRevokeOp(ControlOp):
    KIND: ClassVar[ControlKind] = ControlKind.CERT_REVOKE
    subject: bytes

    @classmethod
    def _from_body(
        cls, env: dict[bytes, Bencodable], raw: bytes, body: dict[bytes, Bencodable]
    ) -> Self:
        return cls(**cls._kwargs(env, raw), subject=codec.as_bytes(codec.field(body, b"subject")))

    @classmethod
    def build(
        cls,
        *,
        author: crypto.Keypair,
        seq: int,
        prev: bytes,
        hlc: HLC,
        subject: bytes,
        pver: int = 0,
    ) -> Self:
        body = codec.encode({BK_KIND: cls.KIND, b"subject": subject})
        raw, sig = ControlOp._control_raw(author, seq=seq, prev=prev, hlc=hlc, pver=pver, body=body)
        return cls(
            author=author.public,
            seq=int(seq),
            prev=prev,
            hlc=hlc,
            pver=int(pver),
            sig=sig,
            raw=raw,
            subject=subject,
        )


@dataclass(frozen=True, slots=True, kw_only=True)
class RosterOp(ControlOp, Slotted):
    KIND: ClassVar[ControlKind] = ControlKind.ROSTER
    from_epoch: int
    roster: list[bytes]
    sync_frontier: Heads
    recovery: bytes | None  # NOTES 36a: an op_hash = the fiat recovery pairing; None = normal
    slot_tag: bytes  # (Slotted) contended on roster_slot_tag(from_epoch) (DESIGN §13, B4)

    def expected_slot_tag(self) -> bytes:
        return roster_slot_tag(self.from_epoch)

    @classmethod
    def _from_body(
        cls, env: dict[bytes, Bencodable], raw: bytes, body: dict[bytes, Bencodable]
    ) -> Self:
        roster = [codec.as_bytes(p) for p in codec.as_seq(codec.field(body, b"roster"))]
        # DESIGN §13: roster size is always odd — even voting counts enlarge quorums
        # without adding tolerance, so they are malformed.
        if len(roster) == 0 or len(roster) % 2 == 0:
            raise codec.CodecError("roster must have an odd, non-zero voting-member count")
        rec = body.get(b"recovery")  # present => the fiat recovery trigger (root-only)
        return cls(
            **cls._kwargs(env, raw),
            from_epoch=_uint(codec.field(body, b"from_epoch")),
            roster=roster,
            sync_frontier=_heads(codec.field(body, b"sync_frontier")),
            recovery=codec.as_bytes(rec) if rec is not None else None,
        )

    @classmethod
    def build(
        cls,
        *,
        author: crypto.Keypair,
        seq: int,
        prev: bytes,
        hlc: HLC,
        from_epoch: int,
        roster: list[bytes],
        sync_frontier: Heads,
        recovery: bytes | None = None,
        pver: int = 0,
    ) -> Self:
        d: dict[bytes, Any] = {
            BK_KIND: cls.KIND,
            b"from_epoch": int(from_epoch),
            b"roster": [bytes(p) for p in roster],
            b"sync_frontier": {a: [s, h] for a, (s, h) in sync_frontier.items()},
        }
        if recovery is not None:  # the fiat recovery pairing; omit for a normal roster
            d[b"recovery"] = recovery
        slot = roster_slot_tag(from_epoch)
        raw, sig = ControlOp._control_raw(
            author,
            seq=seq,
            prev=prev,
            hlc=hlc,
            pver=pver,
            body=codec.encode(d),
            slot_tag=slot,
        )
        return cls(
            author=author.public,
            seq=int(seq),
            prev=prev,
            hlc=hlc,
            pver=int(pver),
            sig=sig,
            raw=raw,
            from_epoch=int(from_epoch),
            roster=[bytes(p) for p in roster],
            sync_frontier=sync_frontier,
            recovery=recovery,
            slot_tag=slot,
        )


@dataclass(frozen=True, slots=True, kw_only=True)
class RotateOp(ControlOp):
    KIND: ClassVar[ControlKind] = ControlKind.ROTATE
    keyepoch: int

    @classmethod
    def _from_body(
        cls, env: dict[bytes, Bencodable], raw: bytes, body: dict[bytes, Bencodable]
    ) -> Self:
        return cls(**cls._kwargs(env, raw), keyepoch=_uint(codec.field(body, b"keyepoch")))

    @classmethod
    def build(
        cls,
        *,
        author: crypto.Keypair,
        seq: int,
        prev: bytes,
        hlc: HLC,
        keyepoch: int,
        pver: int = 0,
    ) -> Self:
        body = codec.encode({BK_KIND: cls.KIND, b"keyepoch": int(keyepoch)})
        raw, sig = ControlOp._control_raw(author, seq=seq, prev=prev, hlc=hlc, pver=pver, body=body)
        return cls(
            author=author.public,
            seq=int(seq),
            prev=prev,
            hlc=hlc,
            pver=int(pver),
            sig=sig,
            raw=raw,
            keyepoch=int(keyepoch),
        )


@dataclass(frozen=True, slots=True, kw_only=True)
class WrapSetOp(ControlOp):
    KIND: ClassVar[ControlKind] = ControlKind.WRAP_SET
    keyepoch: int
    wraps: dict[bytes, bytes]  # member_pub -> sealed group key

    @classmethod
    def _from_body(
        cls, env: dict[bytes, Bencodable], raw: bytes, body: dict[bytes, Bencodable]
    ) -> Self:
        return cls(
            **cls._kwargs(env, raw),
            keyepoch=_uint(codec.field(body, b"keyepoch")),
            wraps={
                k: codec.as_bytes(v) for k, v in codec.as_dict(codec.field(body, b"wraps")).items()
            },
        )

    @classmethod
    def build(
        cls,
        *,
        author: crypto.Keypair,
        seq: int,
        prev: bytes,
        hlc: HLC,
        keyepoch: int,
        group_key: bytes,
        members: list[bytes],
        pver: int = 0,
    ) -> Self:
        """Distribute `group_key` (K_epoch) to each member: an `sbx1` sealed box per
        member pubkey (DESIGN §3 / §15). Only that member's secret key opens its wrap;
        the control op's signature authenticates the distribution."""
        wraps = {m: crypto.seal_to(m, group_key) for m in members}
        body = codec.encode({BK_KIND: cls.KIND, b"keyepoch": int(keyepoch), b"wraps": wraps})
        raw, sig = ControlOp._control_raw(author, seq=seq, prev=prev, hlc=hlc, pver=pver, body=body)
        return cls(
            author=author.public,
            seq=int(seq),
            prev=prev,
            hlc=hlc,
            pver=int(pver),
            sig=sig,
            raw=raw,
            keyepoch=int(keyepoch),
            wraps=wraps,
        )

    def unwrap(self, member: crypto.Keypair) -> bytes | None:
        """Member-side: recover K_epoch, or None if this member has no wrap in the set
        (or it fails to open). The recovered master is a SYMMETRIC secret (`bytes`); only
        the unwrap itself — opening the sealed box — is asymmetric."""
        sealed = self.wraps.get(member.public)
        return None if sealed is None else member.open_sealed(sealed)


@dataclass(frozen=True, slots=True, kw_only=True)
class CheckpointOp(ControlOp, Slotted):
    KIND: ClassVar[ControlKind] = ControlKind.CHECKPOINT
    baseline: Baseline  # the below-cut manifest: cut + retained commitment + dead band
    state_acc: bytes
    attempts: bytes
    keyepoch: int
    horizon: HLC  # the finality frontier F the cut was sealed at (§9)
    # the monotone checkpoint sequence (the public slot it contends, WP-F(c)) — NOT
    # the envelope `seq` (this op's own chain position); distinct now they're fused.
    checkpoint_seq: int
    slot_tag: bytes  # (Slotted) contended on checkpoint_slot_tag(checkpoint_seq)

    def expected_slot_tag(self) -> bytes:
        return checkpoint_slot_tag(self.checkpoint_seq)

    @classmethod
    def _from_body(
        cls, env: dict[bytes, Bencodable], raw: bytes, body: dict[bytes, Bencodable]
    ) -> Self:
        # rev 6 (DESIGN §12): log-compaction — `dead` is the incremental GC delta,
        # `retained` commits the FULL retained set ≤ cut, `attempts` the sealed sidecar.
        return cls(
            **cls._kwargs(env, raw),
            baseline=Baseline(
                cut=_heads(codec.field(body, b"cut")),
                retained=_retained(codec.field(body, b"retained")),
                dead=frozenset(codec.as_bytes(h) for h in codec.as_seq(codec.field(body, b"dead"))),
            ),
            state_acc=codec.as_bytes(codec.field(body, b"state_acc")),
            attempts=codec.as_bytes(codec.field(body, b"attempts")),
            keyepoch=_uint(codec.field(body, b"keyepoch")),
            horizon=HLC.decode(codec.field(body, b"horizon")),
            checkpoint_seq=_uint(codec.field(body, b"seq")),
        )

    @classmethod
    def build(
        cls,
        *,
        author: crypto.Keypair,
        seq: int,
        prev: bytes,
        hlc: HLC,
        baseline: Baseline,
        state_acc: bytes,
        attempts: bytes,
        keyepoch: int,
        horizon: HLC,
        checkpoint_seq: int,
        pver: int = 0,
    ) -> Self:
        # `dead` is encoded SORTED — a set, so the wire is deterministic regardless of GC order.
        body = codec.encode(
            {
                BK_KIND: cls.KIND,
                b"cut": {a: [s, h] for a, (s, h) in baseline.cut.items()},
                b"state_acc": state_acc,
                b"dead": sorted(baseline.dead),
                b"retained": {a: [c, d] for a, (c, d) in baseline.retained.items()},
                b"attempts": attempts,
                b"keyepoch": int(keyepoch),
                b"horizon": list(horizon.encode()),
                b"seq": int(checkpoint_seq),
            }
        )
        slot = checkpoint_slot_tag(checkpoint_seq)
        raw, sig = ControlOp._control_raw(
            author,
            seq=seq,
            prev=prev,
            hlc=hlc,
            pver=pver,
            body=body,
            slot_tag=slot,
        )
        return cls(
            author=author.public,
            seq=int(seq),
            prev=prev,
            hlc=hlc,
            pver=int(pver),
            sig=sig,
            raw=raw,
            baseline=baseline,
            state_acc=state_acc,
            attempts=attempts,
            keyepoch=int(keyepoch),
            horizon=horizon,
            checkpoint_seq=int(checkpoint_seq),
            slot_tag=slot,
        )


@dataclass(frozen=True, slots=True, kw_only=True)
class PverActivateOp(ControlOp):
    KIND: ClassVar[ControlKind] = ControlKind.PVER_ACTIVATE
    activate_pver: int  # the target protocol version — NOT the envelope `pver`

    @classmethod
    def _from_body(
        cls, env: dict[bytes, Bencodable], raw: bytes, body: dict[bytes, Bencodable]
    ) -> Self:
        return cls(**cls._kwargs(env, raw), activate_pver=_uint(codec.field(body, b"pver")))

    @classmethod
    def build(
        cls,
        *,
        author: crypto.Keypair,
        seq: int,
        prev: bytes,
        hlc: HLC,
        activate_pver: int,
        pver: int = 0,
    ) -> Self:
        body = codec.encode({BK_KIND: cls.KIND, b"pver": int(activate_pver)})
        raw, sig = ControlOp._control_raw(author, seq=seq, prev=prev, hlc=hlc, pver=pver, body=body)
        return cls(
            author=author.public,
            seq=int(seq),
            prev=prev,
            hlc=hlc,
            pver=int(pver),
            sig=sig,
            raw=raw,
            activate_pver=int(activate_pver),
        )


@dataclass(frozen=True, slots=True, kw_only=True)
class EndpointOp(ControlOp):
    KIND: ClassVar[ControlKind] = ControlKind.ENDPOINT
    subject: bytes
    addrs: list[tuple[bytes, bytes, dict[bytes, bytes]]]  # (transport, uri, opts); empty = removal

    @classmethod
    def _from_body(
        cls, env: dict[bytes, Bencodable], raw: bytes, body: dict[bytes, Bencodable]
    ) -> Self:
        # Node reachability (PROTOCOL §7.1, NOTES 58): pubkey -> access methods.
        addrs: list[tuple[bytes, bytes, dict[bytes, bytes]]] = []
        for entry in codec.as_seq(codec.field(body, b"addrs")):
            e = codec.as_seq(entry, 3)
            opts = {k: codec.as_bytes(v) for k, v in codec.as_dict(e[2]).items()}
            addrs.append((codec.as_bytes(e[0]), codec.as_bytes(e[1]), opts))
        return cls(
            **cls._kwargs(env, raw),
            subject=codec.as_bytes(codec.field(body, b"subject")),
            addrs=addrs,
        )

    @classmethod
    def build(
        cls,
        *,
        author: crypto.Keypair,
        seq: int,
        prev: bytes,
        hlc: HLC,
        subject: bytes,
        addrs: list[tuple[bytes, bytes, dict[bytes, bytes]]],
        pver: int = 0,
    ) -> Self:
        """Latest-wins per subject; an EMPTY `addrs` removes the node."""
        body = codec.encode(
            {
                BK_KIND: cls.KIND,
                b"subject": subject,
                b"addrs": [[t, u, dict(o)] for (t, u, o) in addrs],
            }
        )
        raw, sig = ControlOp._control_raw(author, seq=seq, prev=prev, hlc=hlc, pver=pver, body=body)
        return cls(
            author=author.public,
            seq=int(seq),
            prev=prev,
            hlc=hlc,
            pver=int(pver),
            sig=sig,
            raw=raw,
            subject=subject,
            addrs=list(addrs),
        )


# kind -> leaf, the only dispatch `ControlOp._from_envelope` needs (each leaf owns
# its own decode/encode). A malformed body or a kind absent here -> InvalidOp.
_CONTROL_LEAVES: dict[ControlKind, type[ControlOp]] = {
    ControlKind.CERT_ISSUE: CertIssueOp,
    ControlKind.CERT_REVOKE: CertRevokeOp,
    ControlKind.ROSTER: RosterOp,
    ControlKind.ROTATE: RotateOp,
    ControlKind.WRAP_SET: WrapSetOp,
    ControlKind.CHECKPOINT: CheckpointOp,
    ControlKind.PVER_ACTIVATE: PverActivateOp,
    ControlKind.ENDPOINT: EndpointOp,
}


# --------------------------------------------------------------------------- #
# Txn — the decrypted, guarded transaction (DESIGN §5)                         #
# --------------------------------------------------------------------------- #


class Guard(BytesEnum):
    """Guard predicates — the private half of a predicate, evaluated in the fold
    (v1 vocabulary — DESIGN §17; extensible as a lane-2 handler add)."""

    ABSENT = b"absent"
    PRESENT = b"present"
    VALUE_EQ = b"value_eq"
    VERSION_EQ = b"version_eq"


class Mutation(BytesEnum):
    """Mutation ops applied all-or-nothing (DESIGN §5)."""

    SET = b"set"
    DEL = b"del"


class TxnField(BytesEnum):
    """Txn body field keys (DESIGN §5)."""

    SLOT = b"slot"
    GUARDS = b"guards"
    MUTATIONS = b"mutations"


def _rows(v: Bencodable | None) -> list[list[bytes]]:
    """Coerce a decoded guards/mutations value into rows of byte strings."""
    if v is None:
        return []
    return [[codec.as_bytes(e) for e in codec.as_seq(row)] for row in codec.as_seq(v)]


# Exact row arity per vocabulary member. Unknown kinds or wrong arities make
# the whole Txn malformed -> Opaque -> `rejected` with the slot consumed —
# never a silent partial apply (DESIGN §16 lane 2 / NOTES item 15).
_GUARD_ARITY: dict[bytes, int] = {
    Guard.ABSENT: 2,
    Guard.PRESENT: 2,
    Guard.VALUE_EQ: 3,
    Guard.VERSION_EQ: 3,
}
_MUTATION_ARITY: dict[bytes, int] = {Mutation.SET: 3, Mutation.DEL: 2}


def _validate_rows(rows: list[list[bytes]], arity: Mapping[bytes, int], what: str) -> None:
    for row in rows:
        if not row:
            raise ArtifactError(f"empty {what} row")
        expected = arity.get(row[0])
        if expected is None:
            raise ArtifactError(f"unknown {what} kind {row[0]!r}")
        if len(row) != expected:
            raise ArtifactError(f"{what} {row[0]!r} expects {expected} elements, got {len(row)}")


class Txn:
    """slot (preimage of slot_tag; None=blind), guards (the private predicate),
    mutations (applied all-or-nothing)."""

    __slots__ = ("slot", "guards", "mutations")

    def __init__(
        self,
        slot: Slot | None,
        guards: list[list[bytes]],
        mutations: list[list[bytes]],
    ):
        self.slot = slot  # None = blind write; else the CAS coordinate
        self.guards = list(guards)
        self.mutations = list(mutations)

    def encode(self) -> bytes:
        # fed only to codec.encode (accepts object), so the heterogeneous
        # guards/mutations/slot lists need no single element type.
        d: dict[bytes, object] = {
            TxnField.GUARDS: [list(g) for g in self.guards],
            TxnField.MUTATIONS: [list(m) for m in self.mutations],
        }
        if self.slot is not None:
            d[TxnField.SLOT] = [self.slot.key, self.slot.version, int(self.slot.attempt)]
        return codec.encode(d)

    @staticmethod
    def decode(data: bytes) -> Txn:
        """Parse AND validate a plaintext Txn: vocabulary and row arities are
        strict (see _validate_rows) — a Txn using unknown guard/mutation kinds
        is malformed, full stop. New vocabulary arrives behind a pver bump
        (DESIGN §16 lane 2), never as a silently-skipped row."""
        d = codec.as_dict(codec.decode(data))
        slot: Slot | None = None
        if TxnField.SLOT in d:
            s = codec.as_seq(d[TxnField.SLOT], 3)
            attempt = codec.as_int(s[2])
            if attempt < 0:
                raise ArtifactError("slot attempt must be non-negative")
            slot = Slot(codec.as_bytes(s[0]), codec.as_bytes(s[1]), attempt)
        guards = _rows(d.get(TxnField.GUARDS))
        mutations = _rows(d.get(TxnField.MUTATIONS))
        _validate_rows(guards, _GUARD_ARITY, "guard")
        _validate_rows(mutations, _MUTATION_ARITY, "mutation")
        return Txn(slot, guards, mutations)


class OpaqueReason(Enum):
    """Why a data payload could not be interpreted (diagnostic only — the fold
    attributes an Opaque purely by tag-equality, DESIGN §6)."""

    NO_KEY = auto()  # no group key held for the op's keyepoch
    AEAD_OPEN_FAILED = auto()  # authentication failure (⊥)
    MALFORMED_TXN = auto()  # decrypted, but not a well-formed Txn


class Opaque(NamedTuple):
    """A data payload `DataOp.read_txn` could not interpret (undecryptable, or malformed
    plaintext) — the alternative to a `Txn`. Carries a typed reason for diagnostics only."""

    reason: OpaqueReason


# --------------------------------------------------------------------------- #
# Receipt — a node's vote (DESIGN §8)                                          #
# --------------------------------------------------------------------------- #


def receipt_message(op_hash: bytes, config_epoch: int, ballot: Ballot, issue_seq: int) -> bytes:
    """The message a node signs: `op_hash ‖ config_epoch ‖ ballot ‖ issue_seq`
    (DESIGN §8, finding-17 fix). `issue_seq` is the signer's own monotone issuance
    counter — it puts every receipt on the node's ISSUANCE CHAIN, so a floor-perjury
    proof can carry the ordering the two artifacts otherwise lack (RESILIENCE §3.1).
    Canonical & injective."""
    return codec.encode([op_hash, int(config_epoch), ballot.encode(), int(issue_seq)])


class ReceiptField(BytesEnum):
    """Field keys of a stored Receipt's dict encoding (the signed form is the
    positional `receipt_message`)."""

    OP_HASH = b"op_hash"
    EPOCH = b"epoch"
    BALLOT = b"ballot"
    ISSUE_SEQ = b"seq"
    SIGNER = b"signer"
    SIG = b"sig"


class Receipt:
    __slots__ = ("op_hash", "config_epoch", "ballot", "issue_seq", "signer", "sig")

    def __init__(
        self,
        op_hash: bytes,
        config_epoch: int,
        ballot: Ballot,
        issue_seq: int,
        signer: crypto.PublicKey,
        sig: bytes,
    ):
        self.op_hash = op_hash
        self.config_epoch = int(config_epoch)
        self.ballot = ballot
        self.issue_seq = int(issue_seq)  # the signer's monotone issuance-chain position
        self.signer = signer  # node pubkey
        self.sig = sig

    @property
    def message(self):
        return receipt_message(self.op_hash, self.config_epoch, self.ballot, self.issue_seq)

    def verify(self) -> bool:
        return self.signer.verify(self.message, self.sig)

    @staticmethod
    def issue(
        node: crypto.Keypair,
        op_hash: bytes,
        config_epoch: int,
        ballot: Ballot,
        issue_seq: int,
    ) -> Receipt:
        msg = receipt_message(op_hash, config_epoch, ballot, issue_seq)
        return Receipt(
            op_hash,
            config_epoch,
            ballot,
            issue_seq,
            node.public,
            node.sign(msg),
        )

    def encode(self) -> bytes:
        return codec.encode(
            {
                ReceiptField.BALLOT: self.ballot.encode(),
                ReceiptField.EPOCH: self.config_epoch,
                ReceiptField.ISSUE_SEQ: self.issue_seq,
                ReceiptField.OP_HASH: self.op_hash,
                ReceiptField.SIG: self.sig,
                ReceiptField.SIGNER: self.signer,
            }
        )

    @staticmethod
    def decode(data: bytes) -> Receipt:
        d = codec.as_dict(codec.decode(data))
        return Receipt(
            codec.as_bytes(_require(d, ReceiptField.OP_HASH)),
            codec.as_int(_require(d, ReceiptField.EPOCH)),
            Ballot.decode(_require(d, ReceiptField.BALLOT)),
            codec.as_int(_require(d, ReceiptField.ISSUE_SEQ)),
            crypto.PublicKey(codec.as_bytes(_require(d, ReceiptField.SIGNER))),
            codec.as_bytes(_require(d, ReceiptField.SIG)),
        )


# --------------------------------------------------------------------------- #
# Promise — a signed prepare reply (PROTOCOL §1.1; promises ARE evidence)      #
# --------------------------------------------------------------------------- #


def promise_message(
    tag: bytes,
    ballot: Ballot,
    accepted_ballot: Ballot | None,
    accepted_op_hash: bytes | None,
    accepted_hlc: HLC | None,
) -> bytes:
    return codec.encode(
        [
            tag,
            ballot.encode(),
            accepted_ballot.encode() if accepted_ballot is not None else b"",
            accepted_op_hash if accepted_op_hash is not None else b"",
            list(accepted_hlc.encode()) if accepted_hlc is not None else b"",
        ]
    )


class Promise:
    """Reply to PREPARE(tag, ballot): the node has promised `ballot` and reports
    the highest op it has already accepted for `tag` (if any), WITH that op's
    `hlc` — so a proposer can apply the below-horizon guard (a promised accept
    with hlc below the client's checkpoint horizon is treated as no accept,
    DESIGN §8 / PROTOCOL §1.3 step 3; the belt-and-braces half of the NOTES-27
    reborn-tag void rule). Signed — a proposer's evidence of the promise."""

    __slots__ = (
        "tag",
        "ballot",
        "accepted_ballot",
        "accepted_op_hash",
        "accepted_hlc",
        "signer",
        "sig",
    )

    def __init__(
        self,
        tag: bytes,
        ballot: Ballot,
        accepted_ballot: Ballot | None,
        accepted_op_hash: bytes | None,
        accepted_hlc: HLC | None,
        signer: crypto.PublicKey,
        sig: bytes,
    ):
        self.tag = tag
        self.ballot = ballot
        self.accepted_ballot = accepted_ballot  # Ballot | None
        self.accepted_op_hash = accepted_op_hash  # bytes | None
        self.accepted_hlc = accepted_hlc  # HLC | None — the accepted op's hlc
        self.signer = signer
        self.sig = sig

    @property
    def message(self):
        return promise_message(
            self.tag, self.ballot, self.accepted_ballot, self.accepted_op_hash, self.accepted_hlc
        )

    def verify(self) -> bool:
        return self.signer.verify(self.message, self.sig)

    @staticmethod
    def issue(
        node: crypto.Keypair,
        tag: bytes,
        ballot: Ballot,
        accepted_ballot: Ballot | None,
        accepted_op_hash: bytes | None,
        accepted_hlc: HLC | None,
    ) -> Promise:
        msg = promise_message(tag, ballot, accepted_ballot, accepted_op_hash, accepted_hlc)
        return Promise(
            tag,
            ballot,
            accepted_ballot,
            accepted_op_hash,
            accepted_hlc,
            node.public,
            node.sign(msg),
        )

    def encode(self) -> bytes:
        return codec.encode(
            [
                self.tag,
                self.ballot.encode(),
                self.accepted_ballot.encode() if self.accepted_ballot is not None else b"",
                self.accepted_op_hash if self.accepted_op_hash is not None else b"",
                list(self.accepted_hlc.encode()) if self.accepted_hlc is not None else b"",
                self.signer,
                self.sig,
            ]
        )

    @staticmethod
    def decode(data: bytes) -> Promise:
        p = codec.as_seq(codec.decode(data))
        return Promise(
            codec.as_bytes(p[0]),
            Ballot.decode(p[1]),
            Ballot.decode(p[2]) if p[2] != b"" else None,
            b if (b := codec.as_bytes(p[3])) else None,
            None if p[4] == b"" else HLC.decode(p[4]),
            crypto.PublicKey(codec.as_bytes(p[5])),
            codec.as_bytes(p[6]),
        )


# --------------------------------------------------------------------------- #
# QC — quorum certificate (DESIGN §8)                                          #
# --------------------------------------------------------------------------- #


class QCField(BytesEnum):
    """Field keys of a QC's dict encoding."""

    OP_HASH = b"op_hash"
    EPOCH = b"epoch"
    BALLOT = b"ballot"
    BITMAP = b"bitmap"
    SIGS = b"sigs"
    ISSUE_SEQS = b"seqs"


class QC:
    """A quorum multi-signature plus a signer set. v1 instantiation: signer bitmap
    + Ed25519 signature list. Post-finding-17 each share signs over its own message
    (the signer's `issue_seq` differs), so the QC carries the per-signer `issue_seqs`
    list PARALLEL to `sigs`/the bitmap, and verification reconstructs each signer's
    message from its seq."""

    __slots__ = ("op_hash", "config_epoch", "ballot", "signer_bitmap", "sigs", "issue_seqs")

    def __init__(
        self,
        op_hash: bytes,
        config_epoch: int,
        ballot: Ballot,
        signer_bitmap: bytes,
        sigs: list[bytes],
        issue_seqs: list[int],
    ):
        self.op_hash = op_hash
        self.config_epoch = int(config_epoch)
        self.ballot = ballot
        self.signer_bitmap = signer_bitmap
        self.sigs = list(sigs)
        self.issue_seqs = [int(s) for s in issue_seqs]  # parallel to sigs (index order)

    def verify(self, roster_pubkeys: list[bytes]) -> bool:
        """Check the bitmap names a MAJORITY of the epoch roster, then verify every
        share against ITS signer's message (`op_hash‖epoch‖ballot‖issue_seq`, DESIGN
        §8 / finding-17). Bitmap is strict (NOTES item 18): exactly ceil(n/8) bytes,
        no set bits above n; a malformed wire QC is a False verdict, never a crash."""
        n = len(roster_pubkeys)
        bm = self.signer_bitmap
        if len(bm) != (n + 7) // 8:
            return False
        if n % 8 and bm and (bm[-1] & ((1 << (8 - n % 8)) - 1)):
            return False  # stray bits beyond roster size
        if crypto.bitmap_count(bm, n) < quorum_size(n):
            return False
        if len(self.issue_seqs) != len(self.sigs):
            return False
        msgs = [
            receipt_message(self.op_hash, self.config_epoch, self.ballot, s)
            for s in self.issue_seqs
        ]
        return crypto.MULTISIG.verify_each(bm, self.sigs, msgs, roster_pubkeys)

    @staticmethod
    def assemble(receipts: list[Receipt], n: int, roster_index: dict[bytes, int]) -> QC:
        """Assemble a QC from same-(op,epoch,ballot) receipts. `roster_index`
        maps a node pubkey -> its index in the epoch roster."""
        if not receipts:
            raise ValueError("no receipts")
        r0 = receipts[0]
        shares: dict[int, bytes] = {}
        seqs: dict[int, int] = {}
        for r in receipts:
            if (r.op_hash, r.config_epoch, r.ballot) != (r0.op_hash, r0.config_epoch, r0.ballot):
                raise ValueError("receipts disagree on (op,epoch,ballot)")
            idx = roster_index[r.signer]
            shares[idx] = r.sig
            seqs[idx] = r.issue_seq
        bitmap, sigs = crypto.MULTISIG.combine(shares, n)
        issue_seqs = [seqs[i] for i in sorted(shares)]  # index order — parallel to sigs
        return QC(r0.op_hash, r0.config_epoch, r0.ballot, bitmap, sigs, issue_seqs)

    def encode(self) -> bytes:
        return codec.encode(
            {
                QCField.BALLOT: self.ballot.encode(),
                QCField.BITMAP: self.signer_bitmap,
                QCField.EPOCH: self.config_epoch,
                QCField.ISSUE_SEQS: list(self.issue_seqs),
                QCField.OP_HASH: self.op_hash,
                QCField.SIGS: list(self.sigs),
            }
        )

    @staticmethod
    def decode(data: bytes) -> QC:
        d = codec.as_dict(codec.decode(data))
        return QC(
            codec.as_bytes(_require(d, QCField.OP_HASH)),
            codec.as_int(_require(d, QCField.EPOCH)),
            Ballot.decode(_require(d, QCField.BALLOT)),
            codec.as_bytes(_require(d, QCField.BITMAP)),
            [codec.as_bytes(x) for x in codec.as_seq(_require(d, QCField.SIGS))],
            [codec.as_int(x) for x in codec.as_seq(_require(d, QCField.ISSUE_SEQS))],
        )


# --------------------------------------------------------------------------- #
# Watermark — signed monotone floor (DESIGN §9)                               #
# --------------------------------------------------------------------------- #


def watermark_message(floor: HLC, config_epoch: int, issue_seq: int) -> bytes:
    """`floor ‖ config_epoch ‖ issue_seq` (DESIGN §9 / finding-17). The `issue_seq`
    puts the attestation on the signer's issuance chain so a floor-perjury proof can
    order it against a receipt."""
    return codec.encode([floor.encode(), int(config_epoch), int(issue_seq)])


class Watermark:
    __slots__ = ("floor", "config_epoch", "issue_seq", "signer", "sig")

    def __init__(
        self, floor: HLC, config_epoch: int, issue_seq: int, signer: crypto.PublicKey, sig: bytes
    ):
        self.floor = floor
        self.config_epoch = int(config_epoch)
        self.issue_seq = int(issue_seq)
        self.signer = signer
        self.sig = sig

    def verify(self) -> bool:
        return self.signer.verify(
            watermark_message(self.floor, self.config_epoch, self.issue_seq),
            self.sig,
        )

    @staticmethod
    def issue(node: crypto.Keypair, floor: HLC, config_epoch: int, issue_seq: int) -> Watermark:
        msg = watermark_message(floor, config_epoch, issue_seq)
        return Watermark(floor, config_epoch, issue_seq, node.public, node.sign(msg))

    def encode(self) -> bytes:
        return codec.encode(
            [list(self.floor.encode()), self.config_epoch, self.issue_seq, self.signer, self.sig]
        )

    @staticmethod
    def decode(data: bytes) -> Watermark:
        p = codec.as_seq(codec.decode(data))
        return Watermark(
            HLC.decode(p[0]),
            codec.as_int(p[1]),
            codec.as_int(p[2]),
            crypto.PublicKey(codec.as_bytes(p[3])),
            codec.as_bytes(p[4]),
        )


# --------------------------------------------------------------------------- #
# Frontier bundle — the read primitive (PROTOCOL §1, §7.3)                     #
# --------------------------------------------------------------------------- #


def frontier_message(
    heads: Heads, checkpoint_head: bytes | None, config_epoch: int, floor: HLC
) -> bytes:
    """`sign(node_sk, per-author heads ‖ checkpoint_head ‖ config_epoch ‖ floor)`.
    heads: {author_fp: (seq, head_hash)} — signed atomically so quorum reads
    are relay-safe (PROTOCOL §7.3)."""
    heads_enc = {a: [s, hh] for a, (s, hh) in heads.items()}
    return codec.encode([heads_enc, checkpoint_head or b"", int(config_epoch), floor.encode()])


class FrontierBundle:
    __slots__ = ("heads", "checkpoint_head", "config_epoch", "floor", "signer", "sig")

    def __init__(
        self,
        heads: Heads,
        checkpoint_head: bytes | None,
        config_epoch: int,
        floor: HLC,
        signer: crypto.PublicKey,
        sig: bytes,
    ):
        self.heads = heads
        self.checkpoint_head = checkpoint_head
        self.config_epoch = int(config_epoch)
        self.floor = floor
        self.signer = signer
        self.sig = sig

    def verify(self) -> bool:
        msg = frontier_message(self.heads, self.checkpoint_head, self.config_epoch, self.floor)
        return self.signer.verify(msg, self.sig)

    @staticmethod
    def issue(
        node: crypto.Keypair,
        heads: Heads,
        checkpoint_head: bytes | None,
        config_epoch: int,
        floor: HLC,
    ) -> FrontierBundle:
        msg = frontier_message(heads, checkpoint_head, config_epoch, floor)
        return FrontierBundle(
            heads, checkpoint_head, config_epoch, floor, node.public, node.sign(msg)
        )

    def encode(self) -> bytes:
        heads_enc = {a: [s, hh] for a, (s, hh) in self.heads.items()}
        return codec.encode(
            [
                heads_enc,
                self.checkpoint_head or b"",
                self.config_epoch,
                list(self.floor.encode()),
                self.signer,
                self.sig,
            ]
        )

    @staticmethod
    def decode(data: bytes) -> FrontierBundle:
        p = codec.as_seq(codec.decode(data))
        heads = {}
        for a, entry in codec.as_dict(p[0]).items():
            pair = codec.as_seq(entry, 2)
            heads[codec.as_bytes(a)] = HeadEntry(codec.as_int(pair[0]), codec.as_bytes(pair[1]))
        return FrontierBundle(
            heads,
            ch if (ch := codec.as_bytes(p[1])) else None,
            codec.as_int(p[2]),
            HLC.decode(p[3]),
            crypto.PublicKey(codec.as_bytes(p[4])),
            codec.as_bytes(p[5]),
        )
