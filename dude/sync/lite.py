# dude.sync.lite -- server-side helpers for light-client verbs.
#
# WHAT THIS MODULE OWNS. Two pure functions -- `serve_get_anchors` and `serve_get_proof`
# -- that turn a decoded light-client request + Store + Management into the matching
# reply (or LiteRefused). Same shape as `dude.sync.follower.serve_getblock`: pure, no
# I/O, no state. Node's dispatcher calls them; the LiteAdapter posts the reply.
#
# WHAT IT DOES NOT OWN. The client-side `LightClient` state machine (deferred, arrives
# with the actual TEE-worker use case). The SMT proof machinery for GET_PROOF (deferred
# to the same wave -- Slice 2 in the plan). This module ships the wire shape and the
# stale/fork detection; the SMT walker plugs in when consumed.

from __future__ import annotations

from ..consensus.settle_round import SettledBlock
from ..core import crypto
from ..store import Store
from ..store.management import Management
from .lite_adapter import (
    ABSENT_MARKER,
    AnchorsReply,
    GetAnchors,
    GetProof,
    LiteRefusal,
    LiteRefused,
    ProofReply,
    RosterBundle,
)


def serve_get_anchors(  # noqa: PLR0911 -- each early-return maps to a distinct LiteRefusal reason
    store: Store,
    mgmt: Management,
    request: GetAnchors,
    liveness_window: int,
) -> AnchorsReply | LiteRefused:
    """Answer a `GET_ANCHORS`. Piggyback shape per #light-client-piggyback:
    - Always: current head anchors + settle_sigs + roster_fingerprint.
    - If `known_roster_fingerprint` doesn't match ours: a fresh `RosterBundle`.
    - If `known_trusted_block` names a block we hold: 0..liveness_window headers
      between (exclusive) trusted_block and (inclusive) current head.

    Refuses with:
      * NO_STATE -- no SETTLED block or no roster commitment yet.
      * STALE_CLIENT -- client's trusted_block is farther behind than liveness_window.
      * FORK_DETECTED -- client's trusted_block hash doesn't match our stored hash at
        that height."""
    head_num = store.head_block_num()
    if not head_num:
        return LiteRefused(LiteRefusal.NO_STATE)
    commitment = mgmt.roster_commitment_full()
    if commitment is None:
        return LiteRefused(LiteRefusal.NO_STATE)

    head_bytes = store.settled_at(head_num)
    if head_bytes is None:
        return LiteRefused(LiteRefusal.INTERNAL)
    head_block = SettledBlock.decode(head_bytes)

    # Client's cached-view check: fork-detected first, then stale-check. Fork trumps
    # stale because a stale client on a fork should still learn they're on a fork.
    tb = request.known_trusted_block
    if tb is not None:
        client_num, client_hash = tb
        if client_num <= head_num:
            client_bytes = store.settled_at(client_num)
            if client_bytes is None:
                return LiteRefused(LiteRefusal.INTERNAL)
            if SettledBlock.decode(client_bytes).block_hash != client_hash:
                return LiteRefused(LiteRefusal.FORK_DETECTED)
        if head_num - client_num > liveness_window:
            return LiteRefused(LiteRefusal.STALE_CLIENT)

    _, _, _, commitment_cert = commitment
    roster_fingerprint = crypto.Digest(commitment_cert.subject)

    bundle: RosterBundle | None = None
    if request.known_roster_fingerprint != roster_fingerprint:
        bundle = _build_bundle(mgmt, commitment)

    headers = _headers_since(store, tb, head_num)

    return AnchorsReply(
        head=head_block,
        roster_fingerprint=roster_fingerprint,
        bundle=bundle,
        headers=headers,
    )


def serve_get_proof(  # noqa: PLR0911, PLR0912, C901 -- each early-return names a distinct LiteRefusal; branches map 1:1 to reasons in the closed enum
    store: Store,
    mgmt: Management,
    request: GetProof,
    liveness_window: int,
) -> ProofReply | LiteRefused:
    """Answer a `GET_PROOF`. Same piggyback rules as `serve_get_anchors` for the reply
    envelope; the value+proof come from the store at the requested `block_num`.

    Refuses with:
      * NO_STATE -- no SETTLED block.
      * NOT_YET_SETTLED -- `block_num > head`.
      * UNKNOWN_STORE / MALFORMED_QUERY -- bad request.
      * STALE_CLIENT / FORK_DETECTED -- same rules as serve_get_anchors.
      * INTERNAL -- assemble failure.

    SMT PROOF SHAPE. Slice 1 lands the wire shape; the actual SMT-walker that
    produces the `proof: bytes` plugs in with the LightClient wave. For now, the
    proof field is empty -- server has the state but doesn't yet emit walks.
    Placeholder documented as OWED against #light-client-nonmembership."""
    head_num = store.head_block_num()
    if not head_num:
        return LiteRefused(LiteRefusal.NO_STATE)
    if request.block_num > head_num:
        return LiteRefused(LiteRefusal.NOT_YET_SETTLED)
    if request.block_num < 1:
        return LiteRefused(LiteRefusal.MALFORMED_QUERY)
    if not request.name:
        return LiteRefused(LiteRefusal.MALFORMED_QUERY)

    commitment = mgmt.roster_commitment_full()
    if commitment is None:
        return LiteRefused(LiteRefusal.NO_STATE)

    head_bytes = store.settled_at(head_num)
    if head_bytes is None:
        return LiteRefused(LiteRefusal.INTERNAL)
    head_block = SettledBlock.decode(head_bytes)

    # Client-state checks -- same as serve_get_anchors.
    tb = request.known_trusted_block
    if tb is not None:
        client_num, client_hash = tb
        if client_num <= head_num:
            client_bytes = store.settled_at(client_num)
            if client_bytes is None:
                return LiteRefused(LiteRefusal.INTERNAL)
            if SettledBlock.decode(client_bytes).block_hash != client_hash:
                return LiteRefused(LiteRefusal.FORK_DETECTED)
        if head_num - client_num > liveness_window:
            return LiteRefused(LiteRefusal.STALE_CLIENT)

    # Value at the requested block_num. In the no-compaction world the current live
    # view IS the state at head; for block_num < head we would need to reconstruct.
    # For Slice 1, only serve requests at head_num.
    if request.block_num != head_num:
        return LiteRefused(LiteRefusal.TOO_OLD)

    row = store.get(request.store_id, request.name)
    value = row[1] if row is not None else ABSENT_MARKER
    absent = row is None
    proof: bytes = b""  # OWED: SMT walker for #light-client-nonmembership

    _, _, _, commitment_cert = commitment
    roster_fingerprint = crypto.Digest(commitment_cert.subject)
    bundle: RosterBundle | None = None
    if request.known_roster_fingerprint != roster_fingerprint:
        bundle = _build_bundle(mgmt, commitment)
    headers = _headers_since(store, tb, head_num)

    return ProofReply(
        value=value,
        absent=absent,
        proof=proof,
        state_root=head_block.anchors.state_root,
        head=head_block,
        roster_fingerprint=roster_fingerprint,
        bundle=bundle,
        headers=headers,
    )


# --------------------------------------------------------------------------------------------- #
# Internal helpers                                                                              #
# --------------------------------------------------------------------------------------------- #


def _build_bundle(mgmt: Management, commitment) -> RosterBundle:
    """Assemble the identity chain a light client needs to verify from the anchor
    (#light-client-cert-chain). Contains commitment payload + per-entry P_NODE rows +
    per-manager P_GRANT rows, each with their #cert."""
    serial, members, _state_fingerprint, cert = commitment
    nodes = mgmt.nodes()
    # Sort entries by identity for deterministic bundle bytes across implementations.
    entries = tuple(
        sorted(
            (nodes[m] for m in members if m in nodes),
            key=lambda rec: bytes(rec.identity),
        )
    )
    managers = mgmt.manager_grants()
    return RosterBundle(
        commitment_serial=serial,
        commitment_members=members,
        commitment_cert=cert,
        entries=entries,
        managers=managers,
    )


def _headers_since(store: Store, known_trusted_block, head_num: int) -> tuple[SettledBlock, ...]:
    """0-to-N SettledBlocks between (exclusive) the client's known trusted block and
    (inclusive) our current head. Empty if the client is caught up or has no trusted
    block yet. Server-side clamp at `liveness_window` is applied by the caller before
    reaching this helper (fork/stale checks refuse first)."""
    if known_trusted_block is None:
        return ()
    from_num, _ = known_trusted_block
    if from_num >= head_num:
        return ()
    out: list[SettledBlock] = []
    for n in range(from_num + 1, head_num + 1):
        b = store.settled_at(n)
        if b is None:
            break
        out.append(SettledBlock.decode(b))
    return tuple(out)
