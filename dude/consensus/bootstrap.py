# dude.consensus.bootstrap -- build block 1 with a manager-override authorization.
#
# WHAT THIS DOES. Given a freshly-provisioned Store, a manager keypair, and the initial txs to
# include (grants for the initial roster, plus any other bootstrap state), previews through a
# Layer to compute anchors, signs those anchors with the manager, and commits a SettledBlock via
# `Store.commit_block`. Every node in a new cluster runs this once at init; the same bytes end
# up in every node's block table, so a fresh joiner can later fetch block 1 via GETBLOCK and
# verify it against nothing but the manager pubkey it holds out-of-band.
#
# WHY NOT IN COORDINATOR. Coordinator drives quorum-authorized settlement: it needs peers, it
# ratifies via Round, it exchanges SettleSigs. Bootstrap has no peers to talk to (the roster
# doesn't exist yet), no consensus to run, no quorum to reach. It is a one-shot construction
# that produces the same shape of block as Coordinator's settlement path but via
# #manager-sig-overrides-quorum. Keeping it in a separate module makes that distinction visible.
#
# WHAT IT DOES NOT DO. Sign the initial txs -- callers do that (the caller knows what grants
# to author). Distribute the resulting block -- the returned block bytes can be copied into
# every node's store via `commit_block`, but that distribution is deployment-tool territory
# (in tests, `Cluster` does it in-process).

from __future__ import annotations

from ..core import crypto
from ..core.errors import InvariantError
from ..store import Layer, Store, settle
from ..store.management import Management
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
    roster). Authority checks are skipped (`auth=None`) because the manager IS the anchor of
    authority -- there is no roster to authorize against yet, and the manager's signature over
    these bodies is what makes them trusted in the first place.

    Returns the `SettledBlockWithBodies` that was committed -- useful for tests to assert on
    what was written, and for a bootstrap tool to distribute the same bytes to other nodes
    (though each node running `bootstrap` with identical `bodies` will produce byte-equal
    blocks by construction, since everything is deterministic in the inputs).

    Raises `InvariantError` if the store already holds a block (bootstrap is one-shot per
    cluster) or if the manager pubkey isn't provisioned (nothing to sign against)."""
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

    # Preview via Layer, mirroring Coordinator._start_settling. Auth flows through the
    # ordinary Management pathway; `may_write` returns True unconditionally for the anchor
    # pubkey (SPECv2 #manager-sig-overrides-quorum), so the manager's own bootstrap grants
    # pass authority naturally -- no `auth=None` bypass anywhere.
    mgmt = Management(store)
    layer = Layer(store)
    screened = settle.apply_to(layer, bodies, mgmt)
    if screened.rejects:
        raise InvariantError(
            f"bootstrap bodies were rejected by the evaluator: {screened.rejects!r}"
        )
    layer.freeze()

    applied = screened.survivors
    base_head = store.head()  # normally 0 for a fresh store
    height = base_head + len(applied)
    acc_log = store.log_accumulator()
    for i, tx in enumerate(applied):
        acc_log = crypto.acc_add(acc_log, log_element(base_head + i + 1, tx.op_hash))

    anchors = Anchors(
        block_num=1,
        height=height,
        prev_block=genesis_stamp(manager.public),
        state_root=layer.state_root(),
        acc_state=layer.accumulator(),
        acc_log=acc_log,
    )

    # Bitmap layout: len(roster) + 1 slots. At bootstrap the roster is empty (log has nothing),
    # so N = 0 and the manager slot is position 0 -- the only slot. Set that one bit, provide
    # one sig (manager's, over the settle-payload of these anchors).
    slice_hashes = tuple(sorted(tx.op_hash for tx in bodies))
    block = Block(
        bucket=bucket,
        hashes=slice_hashes,
        signers=crypto.SignerBitmap(b""),  # ratify sigs are transient and unused for bootstrap
        sigs=(),
    )
    manager_sig = manager.sign(_settle_payload(block.slice_hash, anchors))
    # One-bit bitmap with the manager slot (position 0) set.
    signers = crypto.SignerBitmap(bytes([0b1000_0000]))
    sb = SettledBlock(
        block=block,
        anchors=anchors,
        signers=signers,
        settle_sigs=(manager_sig,),
    )

    # Commit: applies the bodies + persists the block bytes in one SQL transaction. Same
    # Management-driven auth as the preview above -- the anchor rule handles the manager's
    # own bootstrap grants.
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
