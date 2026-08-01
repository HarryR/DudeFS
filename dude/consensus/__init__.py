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
#   quorum         quorum arithmetic (SPECv2 #quorum-gate)
#   mempool        admission door (SPECv2 L3 -- one door, one predicate)
#   round          per-bucket slice-selection state machine (SPECv2 #round-lifecycle)
#   round_adapter  Round's wire encoding (HELD, SIG)
#   settle_round   per-block post-apply anchor-agreement state machine (SPECv2 L5)
#   settle_adapter SettleRound's wire encoding (SETTLE_SIG)
#   coordinator    the driver -- swaps mempools at bucket boundaries, drives rounds, promotes
#                  ratified blocks to settlement, commits on SETTLED
#
# WHAT IT DEPENDS ON:
#   dude.core      crypto primitives, codec
#   dude.store     Store (the committed log + state), settle.evaluate, Layer, ops
#   dude.net       envelope, postman, transports (the adapters use these)
#   dude.tunables  Tunables (composed at the top level, threaded through)
#
# WHAT DEPENDS ON IT:
#   dude.node      composes Coordinator + Postman + adapters into a running node
#   dude.store.management  imports `quorum` for failure-domain arithmetic (only this leaf)
#
# WHY __init__.py IS DELIBERATELY SPARSE. `store.management` imports `quorum` from here, and
# store loads before consensus (Coordinator etc. depend on Store, not vice versa). Any eager
# import that transitively touches store would cycle: consensus/__init__ triggers store which
# triggers management which triggers consensus/__init__ which is still loading. `quorum` is a
# leaf module (only depends on `core.errors`); exposing it here is safe. Everything else --
# Coordinator, Round, Mempool, adapters -- must be imported by its submodule path,
# `from dude.consensus.coordinator import Coordinator`, so that only the machinery a caller
# actually uses gets loaded (and store has finished initialising by then).

from . import quorum
from .quorum import (
    MAJORITY,
    MAJORITY_PLUS,
    TWO_THIRDS,
    QuorumError,
    Rule,
    corroboration,
    satisfied,
    size,
)

__all__ = [
    "MAJORITY",
    "MAJORITY_PLUS",
    "TWO_THIRDS",
    "QuorumError",
    "Rule",
    "corroboration",
    "quorum",
    "satisfied",
    "size",
]
