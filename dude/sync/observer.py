from __future__ import annotations

import logging
from dataclasses import dataclass, field

from ..consensus.settle_round import SettledBlock
from ..core import crypto
from ..net.address import Endpoint
from ..net.postman import LinkStatus
from .lite_client import LightClient, TrustedState

log = logging.getLogger(__name__)


@dataclass(frozen=True, slots=True)
class NodeStatus:
    identity: crypto.PublicKey
    endpoints: tuple[Endpoint, ...]
    links: tuple[LinkStatus, ...]
    connected: bool


@dataclass(frozen=True, slots=True)
class ClusterStatus:
    block_num: int | None
    block_hash: crypto.Digest | None
    roster: tuple[crypto.PublicKey, ...]
    managers: tuple[crypto.PublicKey, ...]
    nodes: dict[crypto.PublicKey, NodeStatus]
    bootstrapped: bool


@dataclass(slots=True)
class ClusterObserver:
    lc: LightClient
    _known_endpoints: dict[crypto.PublicKey, tuple[Endpoint, ...]] = field(
        init=False,
        default_factory=dict,
    )

    def __post_init__(self) -> None:
        self.lc.on_ready = self._on_ready
        self.lc.on_block = self._on_block
        self.lc.on_trust_lost = self._on_trust_lost

    def _on_ready(self, ts: TrustedState) -> None:
        old_keys = set(self._known_endpoints)
        new_keys = set(ts.node_endpoints)
        for pub in old_keys - new_keys:
            log.info("roster: removed %s", pub.hex()[:16])
            self.lc.postman.remove_peer(pub)
        for pub in new_keys:
            self.lc.postman.add_peer(pub, ts.node_endpoints[pub])
            if pub not in old_keys:
                log.info("roster: added %s", pub.hex()[:16])
        self._known_endpoints = dict(ts.node_endpoints)
        log.info(
            "ready: block %d, %d node(s)",
            ts.head.anchors.block_num,
            len(ts.roster),
        )

    def _on_block(self, head: SettledBlock) -> None:
        log.debug("block %d", head.anchors.block_num)

    def _on_trust_lost(self) -> None:
        log.warning("trust lost — awaiting re-bootstrap")

    def status(self) -> ClusterStatus:
        ts = self.lc.trusted_state
        peer_map = self.lc.postman.peer_status()

        nodes: dict[crypto.PublicKey, NodeStatus] = {}
        for pub, endpoints in self._known_endpoints.items():
            ps = peer_map.get(pub)
            nodes[pub] = NodeStatus(
                identity=pub,
                endpoints=endpoints,
                links=ps.links if ps is not None else (),
                connected=ps.connected if ps is not None else False,
            )

        return ClusterStatus(
            block_num=ts.head.anchors.block_num if ts else None,
            block_hash=ts.head.block_hash if ts else None,
            roster=ts.roster if ts else (),
            managers=ts.managers if ts else (),
            nodes=nodes,
            bootstrapped=ts is not None,
        )
