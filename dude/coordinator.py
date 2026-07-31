# dude.coordinator -- the per-node lifecycle for Rounds, Mempools, and Settlement.
#
# WHAT IT OWNS. The currently-collecting Mempool, and a dict of in-flight Rounds -- each Round
# paired with the frozen Mempool it was seeded from, so bodies can be looked up when the Round
# ratifies a slice by hash. Also owns the swap: at bucket boundaries the current Mempool is frozen
# and handed to a new Round, and a fresh Mempool starts admitting for the next window.
#
# WHAT IT DOES NOT OWN. The Round protocol itself (`dude.round`), the wire encoding
# (`dude.net.round_adapter`), transports (`dude.net.postman`), and the log (`dude.store`). This
# module is glue -- it composes these into a working per-node consensus driver, and holds nothing
# of its own beyond the Mempool and Rounds map.
#
# LATE TICKS. If several bucket boundaries pass between two ticks, `tick` opens one Round per
# missed boundary; the intermediates each receive an empty local mempool (nothing was collected
# during their windows because we never swapped). This is a fault mode -- the round runs but this
# node contributes nothing. Ticks are expected to be regular in practice.
#
# BODIES MUST BE LOCAL. `_settle` looks up transaction bodies in the frozen Mempool by op_hash.
# In the current codebase every node holds every tx (SUBMIT is re-flooded), so every ratified
# hash resolves locally. When gossip-by-hash + FETCH lands, this assumption becomes a real
# lookup path; for now, a missing body raises `InvariantError`.

from __future__ import annotations

from dataclasses import dataclass, field

from .core import crypto
from .core.errors import InvariantError
from .mempool import Mempool, Refusal
from .net.envelope import SignedEnvelope
from .net.round_adapter import RoundAdapter, RoundAdapterError, bucket_of
from .round import Block, Bucket, Round
from .store import Store
from .store.management import Management
from .store.ops import SignedTransaction
from .tunables import Tunables

type Millis = int


@dataclass(slots=True)
class Coordinator:
    """One node's consensus driver.

    Constructed once per node. Node hands it inbound HELD/SIG envelopes (via `on_round_msg`),
    inbound SUBMITs (via `submit`), and a tick every round (via `tick`)."""

    me: crypto.Keypair
    store: Store
    adapter: RoundAdapter
    tunables: Tunables

    mempool: Mempool = field(init=False)
    rounds: dict[Bucket, tuple[Mempool, Round]] = field(init=False, default_factory=dict)
    current_bucket: Bucket = field(init=False, default=-1)
    """The bucket the currently-collecting mempool is for. `-1` means "no bucket yet" -- the
    first `tick` initialises it to the bucket that `now` falls in."""

    def __post_init__(self) -> None:
        self.mempool = Mempool(self.tunables.mempool)

    @property
    def mgmt(self) -> Management:
        """Fresh per call: the store may have moved since last time. Same pattern as `Node.mgmt`."""
        return Management(self.store)

    def _bucket_of(self, now: Millis) -> Bucket:
        return self.tunables.mempool.bucket(now)

    def _close_by(self, now: Millis) -> Millis:
        """When the Round opening at `now` should stop collecting and finalize.

        One bucket width ahead -- enough for the Held emitted on `_open_round` to reach every
        peer via the wire before finalize triggers on the next tick. Sig exchange happens after
        finalize on subsequent ticks; there is no strict deadline for that, just for the
        collect->finalize transition.

        This will move onto the timing tunables in Phase 7 when Mempool is reshaped."""
        return now + self.tunables.mempool.delta

    # -- inbound ----------------------------------------------------------------------------- #

    def submit(self, tx: SignedTransaction, now: Millis) -> Refusal | None:
        """A client transaction offered to this node. Admits to the currently-live Mempool."""
        return self.mempool.admit(tx, now, self.store, self.mgmt)

    def on_round_msg(self, env: SignedEnvelope, now: Millis) -> None:
        """A HELD or SIG envelope from a peer. Route to the Round for its bucket, dropping
        anything for a bucket this node is not currently running."""
        try:
            bucket = bucket_of(env.env.body)
        except RoundAdapterError:
            return  # XXX: malformed body, dropped by the adapter's decode.
        entry = self.rounds.get(bucket)
        if entry is None:
            # XXX: dropped -- unknown bucket. Either it settled already (Round is `gone`, dict
            # entry removed) or the message is for a bucket this node has not opened yet. Neither
            # is a fault: gossip and reordering routinely produce such messages.
            return
        _frozen, r = entry
        try:
            self.adapter.deliver(env, r, now)
        except RoundAdapterError:
            return  # XXX: malformed body, dropped by the adapter's decode.

    # -- the driver -------------------------------------------------------------------------- #

    def tick(self, now: Millis) -> None:
        """Advance every open Round; open new Rounds for any bucket boundary crossed since the
        last tick; flush outbound messages; settle any Round that ratified."""
        if self.current_bucket < 0:
            self.current_bucket = self._bucket_of(now)

        # Swap on bucket boundaries. One Round per boundary crossed; intermediates get whatever
        # was in the mempool at that moment (usually empty, since the same tick opens them all).
        while self.current_bucket < self._bucket_of(now):
            frozen = self.mempool
            self.mempool = Mempool(self.tunables.mempool)
            self._open_round(self.current_bucket, frozen, now)
            self.current_bucket += 1

        # Drive open Rounds. Copy the keys before iterating because `_settle` mutates the dict.
        for bucket in list(self.rounds):
            _frozen, r = self.rounds[bucket]
            r.tick(now)
            self.adapter.flush(r, now)
            block = r.ratified()
            if block is not None:
                self._settle(bucket, block, _frozen, now)

    def _open_round(self, bucket: Bucket, frozen: Mempool, now: Millis) -> None:
        """Instantiate a Round for `bucket`, seed it with what the frozen Mempool held."""
        r = Round(
            bucket=bucket,
            me=self.me,
            roster=self.mgmt.node_set(),
            now=now,
            close_by=self._close_by(now),
        )
        r.add_local(_all_hashes(frozen))
        self.rounds[bucket] = (frozen, r)
        # Emit the initial Held immediately so peers see this node's holdings even if the next
        # tick is delayed.
        self.adapter.flush(r, now)

    def _settle(self, bucket: Bucket, block: Block, frozen: Mempool, now: Millis) -> None:
        """A Round has ratified. Apply the block via Store, re-admit surviving to the current
        Mempool, retire this Round from the map."""
        bodies_by_hash = {
            tx.op_hash: tx for _b, txs in frozen.pending.items() for tx in txs.values()
        }
        # Every ratified hash must resolve locally -- see the module header for the assumption
        # this rests on.
        missing = [h for h in block.hashes if h not in bodies_by_hash]
        if missing:
            raise InvariantError(
                f"bucket {bucket} ratified {len(missing)} tx(s) this node does not hold locally; "
                f"gossip-by-hash + FETCH not yet implemented"
            )
        ordered = tuple(bodies_by_hash[h] for h in block.hashes)
        if ordered:
            self.store.apply(ordered, auth=self.mgmt)

        # Push surviving back through the one admission door.
        for op_hash, tx in bodies_by_hash.items():
            if op_hash in block.hashes:
                continue
            self.mempool.admit(tx, now, self.store, self.mgmt)

        del self.rounds[bucket]


def _all_hashes(m: Mempool) -> frozenset[crypto.Digest]:
    """Every op_hash currently in the mempool, across whatever internal bucket keys it holds
    them under. Round takes a single set -- bucket labelling is the Coordinator's concern."""
    return frozenset(op_hash for txs in m.pending.values() for op_hash in txs)
