# dude.consensus -- the entire consensus mechanism, admission through commit.
#
# One package because the pieces are one thing: a client submission passes through Mempool
# admission, is gossiped by Round to peers, collected into a bucket, ratified by quorum-many
# Round signatures over the largest-intersection slice, then evaluated into a Layer whose
# post-apply anchors SettleRound gets a quorum to co-sign, at which point the Coordinator
# commits to Store. Every one of those steps consults the others; there is no useful
# decomposition that splits them across packages.
#
# WHAT LIVES HERE:
#   mempool        admission door (SPECv2 L3 -- one door, one predicate)
#   round          per-bucket slice-selection state machine (SPECv2 #round-lifecycle)
#   round_adapter  Round's wire encoding (HELD, SIG)
#   settle_round   per-block post-apply anchor-agreement state machine (SPECv2 L5)
#   settle_adapter SettleRound's wire encoding (SETTLE_SIG)
#   coordinator    the driver -- swaps mempools at bucket boundaries, drives rounds, promotes
#                  ratified blocks to settlement, commits on SETTLED
#
# QUORUM LIVES AT dude.quorum, NOT HERE. It is pure arithmetic and is consumed by both
# consensus and by `store.management` (for failure-domain checks on the roster). Keeping it
# outside the consensus package removes the cycle that would otherwise exist between store
# and consensus during package loading. Cite via `from dude import quorum`.
#
# WHAT IT DEPENDS ON:
#   dude.quorum    the quorum rule (shared with dude.store.management)
#   dude.core      crypto primitives, codec
#   dude.store     Store (the committed log + state), settle.evaluate, Layer, ops
#   dude.net       envelope, postman, transports (the adapters use these)
#   dude.tunables  Tunables (composed at the top level, threaded through)
#
# WHAT DEPENDS ON IT:
#   dude.node      composes Coordinator + Postman + adapters into a running node

from .coordinator import Coordinator
from .mempool import CANNOT_APPLY, DUPLICATE, TOO_NEW, TOO_OLD, UNSIGNED, Mempool, Refusal
from .mempool import Tunables as MempoolTunables
from .round import Block, Bucket, Round, RoundError, RoundMsg
from .round_adapter import RoundAdapter, RoundAdapterError
from .settle_adapter import SettleAdapter, SettleAdapterError
from .settle_round import Anchors, SettledBlock, SettleError, SettleRound, SettleSig, SettleState

__all__ = [
    "CANNOT_APPLY",
    "DUPLICATE",
    "TOO_NEW",
    "TOO_OLD",
    "UNSIGNED",
    "Anchors",
    "Block",
    "Bucket",
    "Coordinator",
    "Mempool",
    "MempoolTunables",
    "Refusal",
    "Round",
    "RoundAdapter",
    "RoundAdapterError",
    "RoundError",
    "RoundMsg",
    "SettleAdapter",
    "SettleAdapterError",
    "SettleError",
    "SettleRound",
    "SettleSig",
    "SettleState",
    "SettledBlock",
]
