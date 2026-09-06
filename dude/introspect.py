from dataclasses import dataclass
from typing import ClassVar

from .core import crypto, serde
from .core.units import Millis
from .net.envelope import Verb
from .net.link import LinkDirection
from .net.postman import Encodable, Postman
from .store import Store


@dataclass(frozen=True, slots=True)
class NodeLinkInfo:
    address: str
    rtt_ms: float | None
    msgs_sent: int
    msgs_recv: int
    bytes_sent: int
    bytes_recv: int
    bad_frames: int
    established_at: Millis
    breaker_open: bool
    available: bool
    direction: LinkDirection
    listener_addr: str | None


@dataclass(frozen=True, slots=True)
class NodePeerInfo:
    identity: crypto.PublicKey
    connected: bool
    links: list[NodeLinkInfo]


@dataclass(frozen=True, slots=True)
class ListenerInfo:
    scheme: str
    address: str
    extra: dict[str, int | str | float]


@dataclass(frozen=True, slots=True)
class NodeStatusReply(Encodable):
    verb: ClassVar[Verb] = Verb.NODE_STATUS_REPLY

    head_block: int
    head_hash: crypto.Digest
    roster_size: int
    mempool_size: int | None
    peers: list[NodePeerInfo]
    listeners: list[ListenerInfo]

    def encode(self) -> tuple[Verb, bytes]:
        return self.verb, serde.dump(self)

    @classmethod
    def decode(cls, body: bytes) -> "NodeStatusReply":
        return serde.load(cls, body)


def serve_node_status(
    store: Store,
    postman: Postman,
    mempool_size: int | None = None,
) -> NodeStatusReply:
    peer_map = postman.peer_status()
    peers = []
    for pk, ps in peer_map.items():
        links = [
            NodeLinkInfo(
                address=str(ls.address),
                rtt_ms=ls.rtt_ms,
                msgs_sent=ls.msgs_sent,
                msgs_recv=ls.msgs_recv,
                bytes_sent=ls.bytes_sent,
                bytes_recv=ls.bytes_recv,
                bad_frames=ls.bad_frames,
                established_at=ls.established_at,
                breaker_open=ls.breaker_open,
                available=ls.available,
                direction=ls.direction,
                listener_addr=str(ls.listener_addr) if ls.listener_addr else None,
            )
            for ls in ps.links
        ]
        peers.append(NodePeerInfo(identity=pk, connected=ps.connected, links=links))

    listeners = [
        ListenerInfo(
            scheme=ls.scheme.value.decode(),
            address=str(ls.address),
            extra=ls.extra,
        )
        for ls in postman.listener_stats()
    ]

    return NodeStatusReply(
        head_block=store.head_block_num() or 0,
        head_hash=store.head_block_hash() or crypto.Digest(b"\x00" * 32),
        roster_size=len(store.mgmt_reader.roster()),
        mempool_size=mempool_size,
        peers=peers,
        listeners=listeners,
    )
