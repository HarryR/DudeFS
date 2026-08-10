from __future__ import annotations

from ..core import crypto
from ..core.errors import InvariantError
from ..store import Layer, Store, settle
from ..store.management import MgmtReader
from ..store.ops import SignedTransaction
from ..store.store import log_element
from .canonical import bodies_canonical, hashes_canonical
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
    # The follower replays a block's bodies sorted by op_hash (Follower._adopt), and the
    # consensus path slices sorted too. Applied here in caller order instead, a multi-tx
    # manager block carried an acc_log and state_root no peer's preview could reproduce:
    # every honest node refused it, and the intervened node was stranded on a chain nobody
    # would walk, with no reorg to heal it.
    bodies = bodies_canonical(bodies).txs
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

    slice_hashes = hashes_canonical(tx.op_hash for tx in bodies)
    block = Block(bucket=bucket, hashes=slice_hashes)
    manager_sig = manager.sign(_settle_payload(block.slice_hash, anchors))

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
    bucket: int,
) -> SettledBlockWithBodies:
    """`bucket` is REQUIRED. Defaulted to 0, every genesis block claimed 1970, and freshness is
    judged from the head's bucket -- a freshly bootstrapped cluster read as infinitely stale."""
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
    prev_num = store.head_block_num()
    if prev_num is None:
        raise InvariantError("intervene() on unbootstrapped store; call bootstrap() first")
    anchor = store.anchor()
    if anchor is None:
        raise InvariantError("store is not provisioned")
    if anchor != manager.public:
        raise InvariantError("intervene manager keypair does not match store's provisioned anchor")
    prev_hash = store.head_block_hash()
    if prev_hash is None:
        raise InvariantError("store has head_block_num but no head_block_hash")
    return _apply_manager_signed_block(
        store,
        manager,
        bodies,
        block_num=prev_num + 1,
        prev_block=prev_hash,
        bucket=bucket,
    )
