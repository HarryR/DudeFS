import logging
from dataclasses import dataclass

from ..consensus.settle_round import SettledBlock
from ..core import crypto
from ..core.errors import DudeError
from ..introspect import NodeStatusReply
from ..net.address import Endpoint
from ..net.envelope import Verb
from ..net.postman import LinkStatus
from ..session import InflightHandle
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


@dataclass(frozen=True, slots=True)
class TopologySnapshot:
    cluster: ClusterStatus
    nodes: dict[crypto.PublicKey, NodeStatusReply]


@dataclass(slots=True)
class _StatusHandle(InflightHandle):
    observer: "ClusterObserver"
    peer: crypto.PublicKey

    def on_reply(self, verb: Verb, body: bytes) -> None:
        if verb is not Verb.NODE_STATUS_REPLY:
            return
        try:
            snapshot = NodeStatusReply.decode(body)
        except (DudeError, ValueError, KeyError):
            log.warning("bad NODE_STATUS_REPLY from %s", self.peer.hex()[:16])
            return
        self.observer.note_node_status(self.peer, snapshot)

    def on_expired(self) -> None:
        pass


class ClusterObserver:
    def __init__(self, lc: LightClient) -> None:
        self.lc = lc
        self._known_endpoints: dict[crypto.PublicKey, tuple[Endpoint, ...]] = {}
        self._node_snapshots: dict[crypto.PublicKey, NodeStatusReply] = {}
        lc.on_ready = self._on_ready
        lc.on_block = self._on_block
        lc.on_trust_lost = self._on_trust_lost

    def _on_ready(self, ts: TrustedState) -> None:
        old_keys = set(self._known_endpoints)
        new_keys = set(ts.node_endpoints)
        for pub in old_keys - new_keys:
            log.info("roster: removed %s", pub.hex()[:16])
            self.lc.postman.remove_peer(pub)
            self._node_snapshots.pop(pub, None)
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

    def note_node_status(self, peer: crypto.PublicKey, snapshot: NodeStatusReply) -> None:
        self._node_snapshots[peer] = snapshot

    def query_topology(self) -> None:
        ttl = self.lc.tunables.ttl_exchange
        for pub in self._known_endpoints:
            self.lc.request_raw(
                pub,
                Verb.NODE_STATUS,
                b"",
                ttl,
                _StatusHandle(observer=self, peer=pub),
            )

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

    def topology(self) -> TopologySnapshot:
        return TopologySnapshot(
            cluster=self.status(),
            nodes=dict(self._node_snapshots),
        )
