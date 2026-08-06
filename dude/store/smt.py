"""The state root: a compressed sparse Merkle tree over live state (#state-root).

WHAT THIS BUYS that `A_state` cannot. An accumulator answers "do we hold the same state" in O(1) and
says nothing whatever about any individual key. This answers "does THIS key hold THIS value" — and,
which is the harder and more valuable half, "this key holds nothing at all". Absence is the
revocation (#absence-is-revocation), so a non-inclusion proof is a proof that a grant is gone.

SHAPE. A binary radix tree over `H(store ‖ name)`, in which a subtree holding exactly ONE leaf
hashes to that leaf regardless of how deep it sits. That single rule is the whole compression: the
tree is nominally 256 deep and actually ~log2(n), so a proof at 10⁷ keys is ~24 hashes, not 256.

CANONICITY, which everything else rests on: a subtree's hash is defined purely as a function of the
leaves in its range. There is no insert path and no delete path that could disagree, so a store
that wrote a key and deleted it is byte-identical to one that never saw it, and two nodes holding
the same state cannot arrive at different roots by having arrived differently.

That is also why there is no split/merge machinery here. The leaves ARE the `live` table, indexed by
path; internal nodes are a memo of a pure function, and dropping the memo table entirely changes
nothing but speed.
"""

from __future__ import annotations

import sqlite3
from dataclasses import dataclass

from dude.core import codec, crypto

MAX_DEPTH = 256
"""Bits in a path. `crypto.h` is 32 bytes, so a path can never run out before two keys diverge."""

EMPTY = crypto.Digest(bytes(crypto.DIGEST_SIZE))
"""An empty subtree, at EVERY depth — the constant that makes the structure sparse rather than
materialised.

Zeros rather than a derived constant, deliberately: a port writes `[0u8; 32]` and cannot get it
subtly wrong, whereas a derived sentinel has to be recomputed identically in every language. It
cannot be confused with a real node because every real node comes out of a personalised hash."""

# Domain names (BLAKE2b personalisation). A leaf, an internal node and a path are three different
# hash functions here, not one function over three tagged messages — see `crypto.h_domain`.
_PATH = b"dude.smt.path"
_LEAF = b"dude.smt.leaf"
_BRANCH = b"dude.smt.node"


def path_of(store: int, name: bytes) -> bytes:
    """Where a key lives in the tree.

    HASHED, not the key itself: it spreads keys uniformly so depth stays ~log2(n), and it denies an
    author the ability to choose its neighbours — with raw keys, a writer could stuff one subtree
    and drive proof length up for everyone else."""
    return bytes(crypto.h_domain(_PATH, codec.encode([store, name])))


def leaf_hash(path: bytes, vhash: crypto.Digest, chash: crypto.Digest) -> crypto.Digest:
    """Binds the leaf to its OWN path, so a leaf cannot be replayed at another position — and to
    the CREDENTIAL that authorised its value.

    `[H]` *"why not just put it in all leaves? It's an authenticated data store."* Without the
    credential the root commits to what every key holds and to nothing about who was permitted to
    put it there, so the only thing authenticating a data row is the quorum's say-so. A quorum at
    or above threshold could then commit arbitrary state and every check in this file would pass.
    With it, a proof answers "this key holds this value, and here is the signature that put it
    there" in one step, and a compromised quorum can still only carry writes some authorised client
    actually signed: it may omit, reorder or replay, but it cannot invent a value for a key.

    THE HASH OF THE CREDENTIAL, not the bytes, so a proof of a value stays small. A verifier that
    also wants the authorisation is handed the credential and checks it against this digest.

    All three fields are fixed width, so plain concatenation is injective and needs no framing."""
    return crypto.h_domain(_LEAF, path + vhash + chash)


def branch_hash(
    depth: int, prefix: bytes, left: crypto.Digest, right: crypto.Digest
) -> crypto.Digest:
    """Binds the node to WHERE IT IS — depth and prefix both — so the tree's shape is committed.

    The same reasoning as binding a leaf to its path, and it would be strange to do one and not the
    other. Without the position, `H(left ‖ right)` is the same bytes wherever it sits, and a node's
    hash is only anchored by the argument that the fold must reach the real root from the top. That
    argument holds, but it is global and has to be re-made for every new use of these hashes —
    subtree proofs, batched proofs, anything that quotes an internal node out of context. Binding
    the position makes every node self-describing instead: "I am the subtree at this prefix, at this
    depth, with these two children."

    BOTH are needed. A prefix is stored padded to full width, so the prefix bytes at depth 3 and at
    depth 4 with a zero next bit are identical; the depth is what tells them apart.

    The verifier never receives a prefix — it derives each one from the key it is asking about, so a
    proof can only ever be folded along that key's own path."""
    return crypto.h_domain(_BRANCH, depth.to_bytes(2, "big") + prefix + left + right)


def bit(path: bytes, i: int) -> int:
    return (path[i // 8] >> (7 - i % 8)) & 1


def with_bit(path: bytes, depth: int, bit: int) -> bytes:
    """`path` with the bit at `depth` set, so a caller can name either child of a prefix.

    Public because BOTH SIDES of a state walk need it: the server to answer about a child, the
    joiner to ask about one. A path operation belongs with the paths."""
    padded = bytes(path).ljust(crypto.DIGEST_SIZE, b"\x00")
    byte, off = divmod(depth, 8)
    mask = 1 << (7 - off)
    val = (padded[byte] | mask) if bit else (padded[byte] & ~mask & 0xFF)
    return padded[:byte] + bytes([val]) + padded[byte + 1 :]


def bounds(path: bytes, depth: int) -> tuple[bytes, bytes]:
    """The range of paths under `path`'s first `depth` bits — the lowest and highest possible.

    A subtree is a CONTIGUOUS RANGE in sorted-path order, which is why the leaves need no structure
    of their own: an index on `path` answers "what is under this prefix" directly."""
    full, rem = divmod(depth, 8)
    head = path[:full]
    if rem:
        mask = (0xFF << (8 - rem)) & 0xFF
        lo = head + bytes([path[full] & mask])
        hi = head + bytes([(path[full] & mask) | (~mask & 0xFF)])
    else:
        lo = hi = head
    pad = crypto.DIGEST_SIZE - len(lo)
    return lo + bytes(pad), hi + b"\xff" * pad


@dataclass(frozen=True, slots=True)
class Proof:
    """Everything needed to check one key against a root, and nothing else.

    The sibling list is dense from the top — every depth from 0 appears — so a depth is its index
    and no depth needs transmitting."""

    siblings: tuple[crypto.Digest, ...]
    occupant: tuple[bytes, crypto.Digest] | None = None
    """`(path, LEAF HASH)` of whatever leaf sits at the end of the walk, if any.

    For an inclusion proof that is the key itself. For an absence proof it is either `None` — the
    slot is empty — or a DIFFERENT key that happens to live where ours would have: both are proofs
    that ours is not there, and the second is the common case in a populated tree.

    THE LEAF HASH RATHER THAN THE VALUE HASH, because a leaf is no longer determined by its value
    alone. This field's job is to name the terminal the fold starts from, and that terminal is the
    leaf hash; carrying its ingredients instead would mean carrying two digests to rebuild one, and
    would tell the asker a neighbour's value hash for no reason. A presence claim recomputes this
    from the value and credential it was given, so nothing here is believed."""

    def encode(self) -> bytes:
        occ = [self.occupant[0], self.occupant[1]] if self.occupant else []
        return codec.encode([list(self.siblings), occ])

    @classmethod
    def decode(cls, raw: bytes) -> Proof:
        p = codec.as_seq(codec.decode(raw), 2)
        occ = codec.as_seq(p[1])
        return cls(
            tuple(crypto.Digest(codec.as_bytes(s)) for s in codec.as_seq(p[0])),
            (codec.as_bytes(occ[0]), crypto.Digest(codec.as_bytes(occ[1]))) if occ else None,
        )


def _fold(
    path: bytes, terminal: crypto.Digest, siblings: tuple[crypto.Digest, ...]
) -> crypto.Digest:
    """Rebuild the root from the bottom, taking each turn from `path`'s own bits."""
    node = terminal
    for depth in reversed(range(len(siblings))):
        sib, at = siblings[depth], bounds(path, depth)[0]
        node = (
            branch_hash(depth, at, node, sib)
            if bit(path, depth) == 0
            else branch_hash(depth, at, sib, node)
        )
    return node


def _present(root: crypto.Digest, path: bytes, held: tuple[bytes, bytes], proof: Proof) -> bool:
    if proof.occupant is None or proof.occupant[0] != path:
        return False  # a presence claim needs OUR leaf, not a neighbour's
    value, credential = held
    # RECOMPUTED from what the caller says the key holds, so the quoted terminal is checked rather
    # than used. A prover choosing this digest freely would prove any value it liked.
    term = leaf_hash(path, crypto.h(value), crypto.h(credential))
    if proof.occupant[1] != term:
        return False
    return _fold(path, term, proof.siblings) == root


def _absent(root: crypto.Digest, path: bytes, proof: Proof) -> bool:
    if proof.occupant is None:
        return _fold(path, EMPTY, proof.siblings) == root
    other, term = proof.occupant
    if other == path:
        return False  # that leaf IS ours; this proves presence, not absence
    if bounds(other, len(proof.siblings)) != bounds(path, len(proof.siblings)):
        # The occupant must sit where OUR key would have gone. A leaf from an unrelated part of the
        # tree proves nothing about ours, and the fold alone would not catch it.
        return False
    return _fold(path, term, proof.siblings) == root


def verify(
    root: crypto.Digest,
    store: int,
    name: bytes,
    held: tuple[bytes, bytes] | None,
    proof: Proof,
) -> bool:
    """Does `proof` show that `(store, name)` holds this `(value, credential)` — or, for
    `held=None`, holds nothing?

    PRESENCE IS A PAIR, deliberately: the leaf commits to both, so there is no way to ask this
    question about a value while declining to say who authorised it. A signature is not optional
    context in an authenticated data store.

    A total function over closed types (#no-exceptions-for-control-flow): every malformed,
    mismatched or simply wrong proof is `False`, and nothing here raises."""
    if len(proof.siblings) > MAX_DEPTH:
        return False
    path = path_of(store, name)
    if held is None:
        return _absent(root, path, proof)
    return _present(root, path, held, proof)


class Tree:
    """The tree over a store's `live` table. Holds no state of its own beyond a memo table."""

    def __init__(self, db: sqlite3.Connection):
        self.db = db

    def _leaves(self, path: bytes, depth: int) -> list[tuple[bytes, crypto.Digest]]:
        """The leaves under a prefix, at most two — which is all any decision here needs.

        Returns each as `(path, leaf hash)`, already hashed: every caller wants the terminal, and
        building it in one place is what keeps `hash_under` and `prove` agreeing about what a leaf
        is."""
        lo, hi = bounds(path, depth)
        rows = self.db.execute(
            "SELECT path, value, cred FROM live WHERE path>=? AND path<=? ORDER BY path LIMIT 2",
            (lo, hi),
        ).fetchall()
        return [(r[0], leaf_hash(r[0], crypto.h(r[1]), crypto.h(r[2]))) for r in rows]

    def hash_under(self, path: bytes, depth: int) -> crypto.Digest:
        """The hash of the subtree under `path`'s first `depth` bits.

        Recursive and memoised, but the memo is only ever a cache: this function's value is fixed by
        the leaves alone, so an empty memo table is slow and never wrong."""
        lo, _ = bounds(path, depth)
        row = self.db.execute(
            "SELECT hash FROM smt_memo WHERE depth=? AND prefix=?", (depth, lo)
        ).fetchone()
        if row is not None:
            return crypto.Digest(row[0])
        found = self._leaves(path, depth)
        if not found:
            return EMPTY
        if len(found) == 1:
            # THE COMPRESSION, in one line: a lone leaf hashes as itself however deep it sits, so
            # the walk stops here instead of descending to 256.
            return found[0][1]
        left, right = bounds(path, depth + 1)[0], bounds(_flip(path, depth), depth + 1)[0]
        if bit(path, depth) == 1:
            left, right = right, left
        node = branch_hash(
            depth, lo, self.hash_under(left, depth + 1), self.hash_under(right, depth + 1)
        )
        self.db.execute(
            "INSERT OR REPLACE INTO smt_memo (depth, prefix, hash) VALUES (?,?,?)",
            (depth, lo, node),
        )
        return node

    def root(self) -> crypto.Digest:
        return self.hash_under(bytes(crypto.DIGEST_SIZE), 0)

    def invalidate(self, path: bytes) -> None:
        """Drop every memo on this key's path. Called for each mutation, inside its transaction.

        Only the path's own ancestors can change: no other subtree's leaf set moved. Deleting a
        memo that was never there costs a primary-key miss, which is why this does not first ask
        which depths exist."""
        self.db.executemany(
            "DELETE FROM smt_memo WHERE depth=? AND prefix=?",
            [(d, bounds(path, d)[0]) for d in range(MAX_DEPTH + 1)],
        )

    def prove(self, store: int, name: bytes) -> Proof:
        """Walk to where the key belongs, collecting siblings. Proves presence or absence by the
        same walk — which is the property that makes absence checkable at all."""
        path = path_of(store, name)
        siblings: list[crypto.Digest] = []
        depth = 0
        while depth < MAX_DEPTH:
            found = self._leaves(path, depth)
            if len(found) <= 1:
                return Proof(tuple(siblings), found[0] if found else None)
            siblings.append(self.hash_under(_flip(path, depth), depth + 1))
            depth += 1
        return Proof(tuple(siblings), None)


def _flip(path: bytes, i: int) -> bytes:
    """The same path with bit `i` inverted — i.e. the sibling's side of the branch."""
    out = bytearray(path)
    out[i // 8] ^= 1 << (7 - i % 8)
    return bytes(out)
