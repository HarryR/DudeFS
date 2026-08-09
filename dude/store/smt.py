from __future__ import annotations

import sqlite3
from dataclasses import dataclass

from dude.core import codec, crypto

MAX_DEPTH = 256

type Held = tuple[bytes, bytes, int]
"""Everything the leaf commits to besides the path: value, credential, keyepoch. A TRIPLE so the
epoch cannot be forgotten -- as a separate argument it was one defaulted parameter away from being
left out of a root again."""

EMPTY = crypto.Digest(bytes(crypto.DIGEST_SIZE))

_PATH = b"dude.smt.path"
_LEAF = b"dude.smt.leaf"
_BRANCH = b"dude.smt.node"


def path_of(store: int, name: bytes) -> bytes:
    return bytes(crypto.h_domain(_PATH, codec.encode([store, name])))


def leaf_hash(path: bytes, vhash: crypto.Digest, chash: crypto.Digest, epoch: int) -> crypto.Digest:
    """THE EPOCH IS PART OF THE ROW, not a note beside it. Left out, two honest nodes could hold
    the same value under different keyepochs with identical roots, and a responder could serve any
    epoch it liked next to a valid proof -- steering a reader to the wrong key after a rotation.
    Fixed eight bytes, the same width `P_WRAP` keys use."""
    return crypto.h_domain(_LEAF, path + vhash + chash + epoch.to_bytes(8, "big"))


def branch_hash(
    depth: int, prefix: bytes, left: crypto.Digest, right: crypto.Digest
) -> crypto.Digest:
    return crypto.h_domain(_BRANCH, depth.to_bytes(2, "big") + prefix + left + right)


def bit(path: bytes, i: int) -> int:
    return (path[i // 8] >> (7 - i % 8)) & 1


def with_bit(path: bytes, depth: int, bit: int) -> bytes:
    padded = bytes(path).ljust(crypto.DIGEST_SIZE, b"\x00")
    byte, off = divmod(depth, 8)
    mask = 1 << (7 - off)
    val = (padded[byte] | mask) if bit else (padded[byte] & ~mask & 0xFF)
    return padded[:byte] + bytes([val]) + padded[byte + 1 :]


def bounds(path: bytes, depth: int) -> tuple[bytes, bytes]:
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
    siblings: tuple[crypto.Digest, ...]
    occupant: tuple[bytes, crypto.Digest] | None = None

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
    node = terminal
    for depth in reversed(range(len(siblings))):
        sib, at = siblings[depth], bounds(path, depth)[0]
        node = (
            branch_hash(depth, at, node, sib)
            if bit(path, depth) == 0
            else branch_hash(depth, at, sib, node)
        )
    return node


def _present(root: crypto.Digest, path: bytes, held: Held, proof: Proof) -> bool:
    if proof.occupant is None or proof.occupant[0] != path:
        return False
    value, credential, epoch = held
    term = leaf_hash(path, crypto.h(value), crypto.h(credential), epoch)
    if proof.occupant[1] != term:
        return False
    return _fold(path, term, proof.siblings) == root


def _absent(root: crypto.Digest, path: bytes, proof: Proof) -> bool:
    if proof.occupant is None:
        return _fold(path, EMPTY, proof.siblings) == root
    other, term = proof.occupant
    if other == path:
        return False
    if bounds(other, len(proof.siblings)) != bounds(path, len(proof.siblings)):
        return False
    return _fold(path, term, proof.siblings) == root


def verify(
    root: crypto.Digest,
    store: int,
    name: bytes,
    held: Held | None,
    proof: Proof,
) -> bool:
    if len(proof.siblings) > MAX_DEPTH:
        return False
    path = path_of(store, name)
    if held is None:
        return _absent(root, path, proof)
    return _present(root, path, held, proof)


class Tree:
    def __init__(self, db: sqlite3.Connection, memoize: bool = True):
        self.db = db
        self.memoize = memoize

    def _leaves(self, path: bytes, depth: int) -> list[tuple[bytes, crypto.Digest]]:
        lo, hi = bounds(path, depth)
        rows = self.db.execute(
            "SELECT path, value, cred, epoch FROM live"
            " WHERE path>=? AND path<=? ORDER BY path LIMIT 2",
            (lo, hi),
        ).fetchall()
        return [(r[0], leaf_hash(r[0], crypto.h(r[1]), crypto.h(r[2]), int(r[3]))) for r in rows]

    def hash_under(self, path: bytes, depth: int) -> crypto.Digest:
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
            return found[0][1]
        left, right = bounds(path, depth + 1)[0], bounds(_flip(path, depth), depth + 1)[0]
        if bit(path, depth) == 1:
            left, right = right, left
        node = branch_hash(
            depth, lo, self.hash_under(left, depth + 1), self.hash_under(right, depth + 1)
        )
        if self.memoize:
            self.db.execute(
                "INSERT OR REPLACE INTO smt_memo (depth, prefix, hash) VALUES (?,?,?)",
                (depth, lo, node),
            )
        return node

    def root(self) -> crypto.Digest:
        return self.hash_under(bytes(crypto.DIGEST_SIZE), 0)

    def invalidate(self, path: bytes) -> None:
        self.db.executemany(
            "DELETE FROM smt_memo WHERE depth=? AND prefix=?",
            [(d, bounds(path, d)[0]) for d in range(MAX_DEPTH + 1)],
        )

    def prove(self, store: int, name: bytes) -> Proof:
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
    out = bytearray(path)
    out[i // 8] ^= 1 << (7 - i % 8)
    return bytes(out)
