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

from collections.abc import Mapping
from dataclasses import dataclass
from enum import Enum
from functools import total_ordering
from typing import NamedTuple, Self

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


# Per-author frontier: author-fingerprint -> (head seq, head op_hash).
type Heads = dict[bytes, tuple[int, bytes]]


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
    AUTHZ = b"authz"
    CLASS = b"class"
    DEPS = b"deps"
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


def slot_preimage(key: bytes, version: bytes, attempt: int) -> bytes:
    """Injective preimage `key ‖ version ‖ attempt` as a bencoded 3-list
    (IMPLEMENTATION §2). `version = VERSION_ABSENT` (empty) while the key is
    absent — creation CAS is attempt 0 on ⊥."""
    return codec.encode([key, version, int(attempt)])


def compute_slot_tag(slot_secret: bytes, key: bytes, version: bytes, attempt: int) -> bytes:
    """`E(k) = PRF(slot_secret[e], key ‖ version ‖ attempt)` (DESIGN §6/§7)."""
    return crypto.prf_tag(slot_secret, slot_preimage(key, version, attempt))


# --------------------------------------------------------------------------- #
# Op — the operation (envelope + payload), DESIGN §5                           #
# --------------------------------------------------------------------------- #


class Op:
    """A self-authenticating operation. Construct via `build()`; ingest a peer's
    bytes via `from_bytes()` (which rejects non-canonical encodings through the
    codec)."""

    __slots__ = ("raw", "fields", "op_hash")

    def __init__(self, raw: bytes, fields: dict[Field, Bencodable]):
        self.raw = raw
        self.fields = fields
        self.op_hash = crypto.h(raw)

    # ---- accessors (typed views over the canonical dict) ------------------ #
    # Each extracts a concrete type from the decoded envelope or raises
    # CodecError; verify_structure() is the up-front gate, these are the lens.
    @property
    def cls(self) -> bytes:
        return codec.as_bytes(self.fields[Field.CLASS])

    @property
    def author(self) -> bytes:
        return codec.as_bytes(self.fields[Field.AUTHOR])

    @property
    def seq(self) -> int:
        return codec.as_int(self.fields[Field.SEQ])

    @property
    def prev(self) -> bytes:
        return codec.as_bytes(self.fields[Field.PREV])

    @property
    def hlc(self) -> HLC:
        return HLC.decode(self.fields[Field.HLC])

    @property
    def deps(self) -> tuple[Bencodable, ...]:
        return codec.as_seq(self.fields[Field.DEPS])

    @property
    def authz(self) -> bytes:
        return codec.as_bytes(self.fields[Field.AUTHZ])

    @property
    def keyepoch(self) -> int:
        return codec.as_int(self.fields[Field.KEYEPOCH])

    @property
    def pver(self) -> int:
        return codec.as_int(self.fields[Field.PVER])

    @property
    def slot_tag(self) -> bytes | None:
        v = self.fields.get(Field.SLOT_TAG)  # None => blind write
        return None if v is None else codec.as_bytes(v)

    @property
    def payload(self) -> bytes:
        return codec.as_bytes(self.fields[Field.PAYLOAD])

    @property
    def sig(self) -> bytes:
        return codec.as_bytes(self.fields[Field.SIG])

    @property
    def is_control(self) -> bool:
        # .get(): an envelope missing CLASS (struct-invalid, folds `invalid`)
        # classifies as data — total, never a KeyError (NOTES item 17).
        return self.fields.get(Field.CLASS) == OpClass.CONTROL

    # ---- the three canonical byte views ----------------------------------- #
    # These only feed codec.encode (which accepts `object`), so they take the
    # broad Mapping — accepting both the stored fields and a freshly-built dict.
    @staticmethod
    def _fields_wo(fields: Mapping[Field, object], *drop: Field) -> dict[Field, object]:
        return {k: v for k, v in fields.items() if k not in drop}

    @classmethod
    def _signing_bytes(cls, fields: Mapping[Field, object]) -> bytes:
        # everything except the signature (DESIGN §5)
        return codec.encode(cls._fields_wo(fields, Field.SIG))

    @classmethod
    def _aad_bytes(cls, fields: Mapping[Field, object]) -> bytes:
        # envelope-minus-payload-minus-sig (DESIGN §5 AAD binding)
        return codec.encode(cls._fields_wo(fields, Field.SIG, Field.PAYLOAD))

    def aad_hash(self) -> bytes:
        return crypto.h(self._aad_bytes(self.fields))

    # ---- verification ----------------------------------------------------- #
    def verify_sig(self, author_pubkey: bytes) -> bool:
        return crypto.SIGNER.verify(author_pubkey, self._signing_bytes(self.fields), self.sig)

    def verify_structure(self) -> bool:
        """Local, key-independent structural checks (shape + canonicity).
        Canonicity is already guaranteed by from_bytes()'s decode; here we
        check field presence/typing. The codec extractors raise CodecError (a
        ValueError) on a mistyped field, caught below as a False verdict."""
        f = self.fields
        try:
            if codec.as_bytes(f[Field.CLASS]) not in (OpClass.DATA, OpClass.CONTROL):
                return False
            codec.as_bytes(f[Field.AUTHOR])
            if codec.as_int(f[Field.SEQ]) < 0:
                return False
            prev = codec.as_bytes(f[Field.PREV])
            if len(prev) != 32:
                return False
            HLC.decode(f[Field.HLC])
            for dep in codec.as_seq(f[Field.DEPS]):
                codec.as_bytes(dep)
            codec.as_bytes(f[Field.AUTHZ])
            if codec.as_int(f[Field.KEYEPOCH]) < 0:
                return False
            if codec.as_int(f[Field.PVER]) < 0:
                return False
            if Field.SLOT_TAG in f:
                codec.as_bytes(f[Field.SLOT_TAG])
            codec.as_bytes(f[Field.PAYLOAD])
            codec.as_bytes(f[Field.SIG])
            if codec.as_int(f[Field.SEQ]) == 0 and prev != GENESIS_PREV:
                return False
        except (KeyError, DudeFSError):
            return False
        return True

    # ---- data payload open (client-only; needs the group key) ------------- #
    def open_payload(self, data_key: bytes) -> bytes | None:
        """Decrypt a data op's payload -> plaintext Txn bytes, or None on
        authentication failure (⊥). Control ops carry plaintext payloads and
        must not be opened this way. AD = envelope-minus-payload, recomputed from
        the envelope; the SIV nonce travels inside the sealed blob (CRYPTO.md §2)."""
        return crypto.AEAD.open(data_key, self.aad_hash(), self.payload)

    # ---- construction ----------------------------------------------------- #
    @classmethod
    def from_bytes(cls, raw: bytes) -> Self:
        # Re-key the decoded envelope through Field(), which *rejects* an unknown
        # key — validation, not a cast. (This is stricter than DESIGN §16's
        # lane-3 unknown-field pass-through; relax when evolution lands, M8.)
        decoded = codec.as_dict(codec.decode(raw))
        fields: dict[Field, Bencodable] = {}
        for k, v in decoded.items():
            try:
                field = Field(k)
            except ValueError:
                raise UnknownField(k) from None  # typed leaf carrying the key
            fields[field] = v
        return cls(raw, fields)

    @classmethod
    def build(
        cls,
        *,
        author_sk: bytes,
        author_pub: bytes,
        cls_: bytes,
        seq: int,
        prev: bytes,
        hlc: HLC,
        deps: list[bytes],
        authz: bytes,
        keyepoch: int,
        payload: bytes,
        slot_tag: bytes | None = None,
        pver: int = 0,
    ) -> Self:
        """Build & sign an op with an already-materialized payload (control
        ops, or data ops whose payload was sealed via `seal_data_payload`)."""
        # tuple(deps) + the tuple-valued HLC.encode() are covariantly Bencodable,
        # so this annotates directly — no cast (see codec.Bencodable).
        fields: dict[Field, Bencodable] = {
            Field.CLASS: cls_,
            Field.AUTHOR: author_pub,
            Field.SEQ: int(seq),
            Field.PREV: prev,
            Field.HLC: hlc.encode(),
            Field.DEPS: tuple(deps),
            Field.AUTHZ: authz,
            Field.KEYEPOCH: int(keyepoch),
            Field.PVER: int(pver),
            Field.PAYLOAD: payload,
        }
        if slot_tag is not None:
            fields[Field.SLOT_TAG] = slot_tag
        sig = crypto.SIGNER.sign(author_sk, cls._signing_bytes(fields))
        fields[Field.SIG] = sig
        raw = codec.encode(fields)
        return cls(raw, fields)

    @classmethod
    def build_data(
        cls,
        *,
        author_sk: bytes,
        author_pub: bytes,
        seq: int,
        prev: bytes,
        hlc: HLC,
        deps: list[bytes],
        authz: bytes,
        keyepoch: int,
        data_key: bytes,
        txn_bytes: bytes,
        slot_tag: bytes | None = None,
        pver: int = 0,
    ) -> Self:
        """Build a data op: seal `txn_bytes` under the group key with
        AAD = envelope-minus-payload, then sign. The AAD is computed from the
        envelope fields *before* the payload exists (DESIGN §5)."""
        base = {  # only fed to codec.encode (accepts object) for the AAD hash
            Field.CLASS: OpClass.DATA,
            Field.AUTHOR: author_pub,
            Field.SEQ: int(seq),
            Field.PREV: prev,
            Field.HLC: hlc.encode(),
            Field.DEPS: list(deps),
            Field.AUTHZ: authz,
            Field.KEYEPOCH: int(keyepoch),
            Field.PVER: int(pver),
        }
        if slot_tag is not None:
            base[Field.SLOT_TAG] = slot_tag
        aad = crypto.h(codec.encode(base))  # envelope-minus-payload-minus-sig
        payload = crypto.AEAD.seal(data_key, aad, txn_bytes)  # nonce ‖ ct ‖ tag
        return cls.build(
            author_sk=author_sk,
            author_pub=author_pub,
            cls_=OpClass.DATA,
            seq=seq,
            prev=prev,
            hlc=hlc,
            deps=deps,
            authz=authz,
            keyepoch=keyepoch,
            payload=payload,
            slot_tag=slot_tag,
            pver=pver,
        )


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
        slot: tuple[bytes, bytes, int] | None,
        guards: list[list[bytes]],
        mutations: list[list[bytes]],
    ):
        # slot: None | (key, version, attempt)
        self.slot = slot
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
            k, ver, att = self.slot
            d[TxnField.SLOT] = [k, ver, int(att)]
        return codec.encode(d)

    @staticmethod
    def decode(data: bytes) -> Txn:
        """Parse AND validate a plaintext Txn: vocabulary and row arities are
        strict (see _validate_rows) — a Txn using unknown guard/mutation kinds
        is malformed, full stop. New vocabulary arrives behind a pver bump
        (DESIGN §16 lane 2), never as a silently-skipped row."""
        d = codec.as_dict(codec.decode(data))
        slot: tuple[bytes, bytes, int] | None = None
        if TxnField.SLOT in d:
            s = codec.as_seq(d[TxnField.SLOT], 3)
            attempt = codec.as_int(s[2])
            if attempt < 0:
                raise ArtifactError("slot attempt must be non-negative")
            slot = (codec.as_bytes(s[0]), codec.as_bytes(s[1]), attempt)
        guards = _rows(d.get(TxnField.GUARDS))
        mutations = _rows(d.get(TxnField.MUTATIONS))
        _validate_rows(guards, _GUARD_ARITY, "guard")
        _validate_rows(mutations, _MUTATION_ARITY, "mutation")
        return Txn(slot, guards, mutations)


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
        signer: bytes,
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
        return crypto.SIGNER.verify(self.signer, self.message, self.sig)

    @staticmethod
    def issue(
        node_sk: bytes,
        node_pub: bytes,
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
            node_pub,
            crypto.MULTISIG.sign_share(node_sk, msg),
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
            codec.as_bytes(_require(d, ReceiptField.SIGNER)),
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
        signer: bytes,
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
        return crypto.SIGNER.verify(self.signer, self.message, self.sig)

    @staticmethod
    def issue(
        node_sk: bytes,
        node_pub: bytes,
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
            node_pub,
            crypto.SIGNER.sign(node_sk, msg),
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
            codec.as_bytes(p[5]),
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

    def __init__(self, floor: HLC, config_epoch: int, issue_seq: int, signer: bytes, sig: bytes):
        self.floor = floor
        self.config_epoch = int(config_epoch)
        self.issue_seq = int(issue_seq)
        self.signer = signer
        self.sig = sig

    def verify(self) -> bool:
        return crypto.SIGNER.verify(
            self.signer,
            watermark_message(self.floor, self.config_epoch, self.issue_seq),
            self.sig,
        )

    @staticmethod
    def issue(
        node_sk: bytes, node_pub: bytes, floor: HLC, config_epoch: int, issue_seq: int
    ) -> Watermark:
        msg = watermark_message(floor, config_epoch, issue_seq)
        return Watermark(floor, config_epoch, issue_seq, node_pub, crypto.SIGNER.sign(node_sk, msg))

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
            codec.as_bytes(p[3]),
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
        signer: bytes,
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
        return crypto.SIGNER.verify(self.signer, msg, self.sig)

    @staticmethod
    def issue(
        node_sk: bytes,
        node_pub: bytes,
        heads: Heads,
        checkpoint_head: bytes | None,
        config_epoch: int,
        floor: HLC,
    ) -> FrontierBundle:
        msg = frontier_message(heads, checkpoint_head, config_epoch, floor)
        return FrontierBundle(
            heads, checkpoint_head, config_epoch, floor, node_pub, crypto.SIGNER.sign(node_sk, msg)
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
            heads[codec.as_bytes(a)] = (codec.as_int(pair[0]), codec.as_bytes(pair[1]))
        return FrontierBundle(
            heads,
            ch if (ch := codec.as_bytes(p[1])) else None,
            codec.as_int(p[2]),
            HLC.decode(p[3]),
            codec.as_bytes(p[4]),
            codec.as_bytes(p[5]),
        )
