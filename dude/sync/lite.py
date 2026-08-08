from __future__ import annotations

from ..consensus.settle_round import SettledBlock
from ..core import crypto
from ..store import Store
from ..store.management import MgmtReader
from ..store.smt import Tree
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
    mgmt: MgmtReader,
    request: GetAnchors,
    liveness_window: int,
) -> AnchorsReply | LiteRefused:
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

    tb = request.known_trusted_block
    if tb is not None:
        client_num, client_hash = tb.block_num, tb.block_hash
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
    if request.known_roster_fingerprint is None:
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
    mgmt: MgmtReader,
    request: GetProof,
    liveness_window: int,
) -> ProofReply | LiteRefused:
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

    tb = request.known_trusted_block
    if tb is not None:
        client_num, client_hash = tb.block_num, tb.block_hash
        if client_num <= head_num:
            client_bytes = store.settled_at(client_num)
            if client_bytes is None:
                return LiteRefused(LiteRefusal.INTERNAL)
            if SettledBlock.decode(client_bytes).block_hash != client_hash:
                return LiteRefused(LiteRefusal.FORK_DETECTED)
        if head_num - client_num > liveness_window:
            return LiteRefused(LiteRefusal.STALE_CLIENT)

    if request.block_num != head_num:
        return LiteRefused(LiteRefusal.TOO_OLD)

    held = store.get(request.store_id, request.name)
    if held is None:
        value: bytes = ABSENT_MARKER
        credential: bytes = b""
        absent = True
    else:
        value = held.value
        credential = held.cred
        absent = False
    proof = Tree(store.db).prove(request.store_id, request.name).encode()

    _, _, _, commitment_cert = commitment
    roster_fingerprint = crypto.Digest(commitment_cert.subject)
    bundle: RosterBundle | None = None
    if request.known_roster_fingerprint is None:
        bundle = _build_bundle(mgmt, commitment)
    headers = _headers_since(store, tb, head_num)

    return ProofReply(
        value=value,
        credential=credential,
        absent=absent,
        proof=proof,
        head=head_block,
        roster_fingerprint=roster_fingerprint,
        bundle=bundle,
        headers=headers,
    )


def _build_bundle(mgmt: MgmtReader, commitment) -> RosterBundle:
    serial, members, _state_fingerprint, cert = commitment
    nodes = mgmt.nodes()
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
    if known_trusted_block is None:
        return ()
    from_num = known_trusted_block.block_num
    if from_num >= head_num:
        return ()
    out: list[SettledBlock] = []
    for n in range(from_num + 1, head_num + 1):
        b = store.settled_at(n)
        if b is None:
            break
        out.append(SettledBlock.decode(b))
    return tuple(out)
