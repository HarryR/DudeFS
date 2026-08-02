# dude.sync -- catch-up-and-follow: L6 in the SPECv2 layering (#sync-layer-no-compaction).
#
# WHAT THIS PACKAGE OWNS. The follower that pulls SETTLED blocks from peers to bring a lagging
# node's Store to the cluster's current head, and the wire encoding for the four verbs sync
# needs: `HEIGHT`, `HEIGHT_REPLY`, `GETBLOCK`, `SETTLED_BLOCK`. Plus the sync-specific refusal
# reasons a `REFUSED` reply carries when a `GETBLOCK` cannot be served.
#
# WHAT IT DOES NOT OWN. Producing blocks (that is `dude.consensus.Coordinator`), any I/O beyond
# posting to the `Postman.mailbox` (that is the adapter's boundary), and any block persistence
# (that is `dude.store.Store.commit_block` on the producer side, `settled_at`/`head_block_hash`
# on the reader side).
#
# THE ONE MEETING POINT. Coordinator produces SETTLED blocks and persists them via
# `Store.commit_block`; Follower CONSUMES SETTLED blocks it fetches and persists them the same
# way. Neither module holds a reference to the other; they share the Store. Same discipline as
# Settlement-does-not-cross-Mempool (#settlement-does-not-cross-mempool) applied at the L4/L6
# boundary (#sync-in-its-own-module).

from __future__ import annotations

from .adapter import (
    SyncAdapter,
    SyncAdapterError,
    SyncRefusal,
    decode_getblock,
    decode_height_reply,
    decode_refusal,
    decode_settled_block,
    encode_getblock,
    encode_height,
    encode_height_reply,
    encode_refusal,
    encode_settled_block,
)

__all__ = [
    "SyncAdapter",
    "SyncAdapterError",
    "SyncRefusal",
    "decode_getblock",
    "decode_height_reply",
    "decode_refusal",
    "decode_settled_block",
    "encode_getblock",
    "encode_height",
    "encode_height_reply",
    "encode_refusal",
    "encode_settled_block",
]
