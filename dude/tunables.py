# dude.tunables — every dial in one place. See ../MEMPOOL.md §7.5, ../LINKS.md §5.
#
# THE RULING THIS FILE SERVES [H]: *"having any tunables deep within code is just going to linger."*
#
# So: a module DECLARES the shape of its own dials — it alone knows what they mean — and this file
# holds the single instance everything is handed. Nothing constructs a `*Tunables` group ad hoc, and
# no literal timing value appears anywhere outside a group's field defaults.
#
# DELIBERATELY NOT IN THE MANAGEMENT STORE YET [H]: *"as long as they're somewhere together we
# can figure out how to make them either adjustable or tunable on a per-link basis or configurable
# by the manager."* Consolidation first, distribution second. When it does land there it becomes a
# consensus-agreed value at a log position, so every node uses the same delta at the same position
# rather than each holding a local file that can silently drift — which a file cannot rule out.
#
# THE PER-LINK CAVEAT, worth stating before anyone wires it: a mixnet hop and a unix socket want
# different numbers, so `link` and `plan` are the groups most likely to become per-endpoint
# overrides rather than globals. `Endpoint.options` is where such an override would arrive from the
# manager, which is why options are opaque bytes rather than a closed schema.

from __future__ import annotations

from dataclasses import dataclass, field

from .mempool import Tunables as MempoolTunables
from .net.link import LinkTunables
from .net.plan import PlanTunables
from .store.attest import AttestTunables

type Millis = int


@dataclass(frozen=True, slots=True)
class NetTunables:
    """Dials that belong to the framing layer itself rather than to a link or a message."""

    window: Millis = 5_000
    """The conversation window (`SignedEnvelope.fresh`). A PARTICIPATION gate, not a DoS filter: a
    node outside it cannot hold a conversation at all, and because both ends check, it
    self-partitions. Measures "are we in sync right now", so it is tight — a transaction's admission
    window measures content age instead, and is looser.

    FLOOR: `timing.CONVERSATION_FLOOR` (550 ms) — skew plus one trip, below which two honest nodes
    cannot converse."""

    ttl: Millis = 10_000
    """Default deadline for a posted message: how long the mailbox keeps trying. NEVER transmitted —
    the envelope carries no TTL, because a second expiry with no consumer on the wire is exactly the
    declared-but-unwired shape.

    The retry schedule MUST fit inside this: see `PlanTunables.max_attempts`."""

    pull_max: int = 256
    """Entries per `ENTRIES` reply — a bound on message size, never on how far behind a joiner is.

    Here rather than as a constant in `node.py`, because this file's ruling is that a dial deep in
    code lingers. A SIZE bound, so nothing in `timing` derives it: the requester asks again from
    where it got to, which costs round trips and never correctness."""


@dataclass(frozen=True, slots=True)
class Tunables:
    """The one surface. Pass this down; do not reach for a group's defaults directly."""

    net: NetTunables = field(default_factory=NetTunables)
    link: LinkTunables = field(default_factory=LinkTunables)
    plan: PlanTunables = field(default_factory=PlanTunables)
    mempool: MempoolTunables = field(default_factory=MempoolTunables)
    attest: AttestTunables = field(default_factory=AttestTunables)


DEFAULT = Tunables()
"""A well-connected deployment. Named rather than inlined so a reader can see that a default was
chosen, and so a deployment overrides ONE symbol."""
