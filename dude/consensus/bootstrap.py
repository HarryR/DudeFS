# dude.consensus.bootstrap -- manager-signed SettledBlock construction, shared across the two
# uses of the anchor override (#anchor-is-the-axiom + #manager-sig-overrides-quorum).
#
# TWO CALLERS, ONE CONSTRUCTION:
#   * `bootstrap(store, ...)` -- block 1 of a fresh cluster; prev_block is the genesis stamp
#     derived from the anchor pubkey. Called once at cluster init.
#   * `intervene(store, ...)` -- an emergency-intervention block that unsticks a hung cluster
#     or replaces a compromised roster (#manager-sig-overrides-quorum "emergency intervention"
#     use case); prev_block is the store's current head hash. Called at operator discretion.
#
# Both go through `_apply_manager_signed_block` so the wire shape, the bitmap layout, the
# signed payload, and the commit path are IDENTICAL. There is no separate "emergency-
# intervention" wire form or evaluator branch (#anchor-is-the-axiom's shared-code-path
# requirement). What differs between the two callers is only the state of the store (empty
# vs populated) at the moment of construction, plus the `prev_block` value that drops out of
# that state.
#
# WHY NOT IN COORDINATOR. Coordinator drives quorum-authorized settlement: it needs peers, it
# ratifies via Round, it exchanges SettleSigs. Manager-signed blocks skip all of that. Keeping
# them in a separate module makes the "one manager, no consensus" distinction visible.

from __future__ import annotations

from ..core import crypto
from ..core.errors import InvariantError
from ..store import Layer, Store, settle
from ..store.management import MgmtReader
from ..store.ops import SignedTransaction
from ..store.store import log_element
from .round import Block
from .settle_round import (
    Anchors,
    SettledBlock,
    SettledBlockWithBodies,
    _settle_payload,
    genesis_stamp,
)


def _apply_manager_signed_block(  # noqa: PLR0913 -- construction inputs, all required
    store: Store,
    manager: crypto.Keypair,
    bodies: tuple[SignedTransaction, ...],
    *,
    block_num: int,
    prev_block: crypto.Digest,
    bucket: int,
) -> SettledBlockWithBodies:
    """Build and commit a manager-signed SettledBlock. Shared by `bootstrap` and `intervene`.

    Previews `bodies` through a Layer using the ordinary MgmtReader evaluator (anchor is
    always authorised, #anchor-is-the-axiom, so the manager's own bootstrap grants pass
    naturally with no `auth=None` bypass anywhere). Computes anchors from the layer. Signs
    the settle payload with `manager`. Packs the sig into bitmap slot `len(roster)` (the
    reserved manager position, #manager-sig-overrides-quorum). Commits via
    `store.commit_block`.

    Returns the committed `SettledBlockWithBodies`.

    Raises `InvariantError` if the evaluator rejects any body -- a manager-signed block that
    can't apply cleanly is a caller mistake, not a routine failure."""
    mgmt = MgmtReader(store)
    layer = Layer(store)
    screened = settle.apply_to(layer, bodies, mgmt)
    if screened.rejects:
        raise InvariantError(
            f"manager-signed bodies rejected by the evaluator: {screened.rejects!r}"
        )
    layer.freeze()

    applied = screened.survivors
    base_head = store.head()
    height = base_head + len(applied)
    acc_log = store.log_accumulator()
    for i, tx in enumerate(applied):
        acc_log = crypto.acc_add(acc_log, log_element(base_head + i + 1, tx.op_hash))

    anchors = Anchors(
        block_num=block_num,
        height=height,
        prev_block=prev_block,
        state_root=layer.state_root(),
        acc_state=layer.accumulator(),
        acc_log=acc_log,
    )

    slice_hashes = tuple(sorted(tx.op_hash for tx in bodies))
    block = Block(
        bucket=bucket,
        hashes=slice_hashes,
        multisig=crypto.UNSIGNED,  # ratify sigs are transient and unused here
    )
    manager_sig = manager.sign(_settle_payload(block.slice_hash, anchors))

    # Bitmap: `len(roster) + 1` slots; the manager slot is position N (the last). At
    # bootstrap the roster is empty and N == 0. Both cases go through `combine` for a
    # uniform construction (#anchor-is-the-axiom's shared code path).
    roster = mgmt.roster()
    n = len(roster) + 1

    sb = SettledBlock(
        block=block,
        anchors=anchors,
        multisig=crypto.MultiSig.combine({n - 1: manager_sig}, n),
    )
    block_bytes = sb.encode()
    store.commit_block(
        anchors.block_num,
        first_height=base_head + 1,
        block_bytes=block_bytes,
        block_hash=sb.block_hash,
        batch=bodies,
        auth=mgmt,
    )
    return SettledBlockWithBodies(block=sb, bodies=bodies)


def bootstrap(
    store: Store,
    manager: crypto.Keypair,
    bodies: tuple[SignedTransaction, ...],
    *,
    bucket: int = 0,
) -> SettledBlockWithBodies:
    """Compute, sign, and commit block 1 to `store`.

    `store` MUST be freshly provisioned (`store.provision(manager.public)` already called) and
    have no prior settled blocks -- this asserts on `store.head_block_num()`. `bodies` are the
    signed transactions to include (typically manager-signed grants that establish the initial
    roster).

    Every node running `bootstrap` with identical `bodies` produces byte-equal blocks by
    construction, since everything is deterministic in the inputs -- so distribution of block 1
    across the initial cluster reduces to shipping the same bytes to every store.

    Raises `InvariantError` if the store already holds a block (bootstrap is one-shot per
    cluster) or if the manager pubkey isn't provisioned."""
    if store.head_block_num() is not None:
        raise InvariantError(
            f"bootstrap() called on store that already holds block "
            f"{store.head_block_num()}; bootstrap is one-shot per cluster"
        )
    anchor = store.anchor()
    if anchor is None:
        raise InvariantError("store is not provisioned; call store.provision(manager) first")
    if anchor != manager.public:
        raise InvariantError("bootstrap manager keypair does not match store's provisioned anchor")
    return _apply_manager_signed_block(
        store,
        manager,
        bodies,
        block_num=1,
        prev_block=genesis_stamp(manager.public),
        bucket=bucket,
    )


def intervene(
    store: Store,
    manager: crypto.Keypair,
    bodies: tuple[SignedTransaction, ...],
    *,
    bucket: int,
) -> SettledBlockWithBodies:
    """Manager-signed emergency-intervention block at `head_block_num() + 1`
    (#manager-sig-overrides-quorum's "emergency intervention" case). The anchor's signature
    authorises the block alone, bypassing quorum -- use case: unstick a cluster whose
    settlement is hung (#settlement-may-hang), replace a compromised roster, or otherwise
    take an action that the ordinary consensus path cannot execute.

    Follower verification is uniform: the block goes through `MgmtReader.authorises` and
    the manager slot check is the same as bootstrap. There is no "emergency" wire flag or
    evaluator bypass (#anchor-is-the-axiom).

    Requires the store to already hold at least one block (call `bootstrap` first) and the
    manager keypair to match the store's provisioned anchor. Raises `InvariantError`
    otherwise."""
    prev_num = store.head_block_num()
    if prev_num is None:
        raise InvariantError("intervene() on unbootstrapped store; call bootstrap() first")
    anchor = store.anchor()
    if anchor is None:
        raise InvariantError("store is not provisioned")
    if anchor != manager.public:
        raise InvariantError("intervene manager keypair does not match store's provisioned anchor")
    prev_hash = store.head_block_hash()
    if prev_hash is None:  # unreachable given head_block_num check, narrower for ty
        raise InvariantError("store has head_block_num but no head_block_hash")
    return _apply_manager_signed_block(
        store,
        manager,
        bodies,
        block_num=prev_num + 1,
        prev_block=prev_hash,
        bucket=bucket,
    )
