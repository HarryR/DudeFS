from __future__ import annotations

import logging
import tomllib
from dataclasses import dataclass
from pathlib import Path

import dacite

from ..core.units import Millis
from ..net.link import Acceptor
from ..net.postman import Postman
from ..net.transports.tcp import TCPListener
from ..node import Node, ReplicaNode
from ..store import Store
from ..sync.lite_client import LightClient, LightClientError
from ..tunables import DEFAULT, Tunables
from .state import (
    GENESIS_DATA,
    BootstrapSeed,
    CLIError,
    load_anchor,
    load_keypair,
    open_store_with_genesis,
    socket_path,
    store_path,
)

log = logging.getLogger(__name__)


@dataclass(slots=True)
class TCPListenConfig:
    host: str = "0.0.0.0"
    port: int = 9000

    def acceptor(self, tunables: Tunables) -> Acceptor:
        return TCPListener(tunables, listen_host=self.host, listen_port=self.port)


@dataclass(slots=True)
class OnionListenConfig:
    host: str
    port: int = 9000

    def acceptor(self, tunables: Tunables) -> Acceptor:
        return TCPListener(tunables, listen_host=self.host, listen_port=self.port)


@dataclass(slots=True)
class NodeListenConfig:
    tcp: list[TCPListenConfig]
    onion: list[OnionListenConfig]

    def __init__(
        self,
        tcp: list[TCPListenConfig] | None = None,
        onion: list[OnionListenConfig] | None = None,
    ) -> None:
        self.tcp = tcp or []
        self.onion = onion or []

    def acceptors(self, tunables: Tunables) -> tuple[Acceptor, ...]:
        return tuple(c.acceptor(tunables) for c in (*self.tcp, *self.onion))


@dataclass(slots=True)
class RoleConfig:
    socket: str | None = None


_DACITE_CONFIG = dacite.Config(
    type_hooks={Millis: Millis},
    cast=[tuple],
)


@dataclass(slots=True)
class DudeConfig:
    home: Path
    tunables: Tunables = DEFAULT
    node_listen: NodeListenConfig | None = None
    node_cfg: RoleConfig | None = None
    manager_cfg: RoleConfig | None = None
    client_cfg: RoleConfig | None = None
    compactor_cfg: RoleConfig | None = None

    @property
    def anchor_dir(self) -> Path:
        return self.home / "anchor"

    @property
    def node_dir(self) -> Path:
        return self.home / "node"

    @property
    def client_dir(self) -> Path:
        return self.home / "client"

    @property
    def manager_dir(self) -> Path:
        return self.home / "manager"

    @property
    def compactor_dir(self) -> Path:
        return self.home / "compactor"

    def _role_socket(self, role_cfg: RoleConfig | None, role_dir: Path) -> str:
        if role_cfg is not None and role_cfg.socket is not None:
            return role_cfg.socket
        return socket_path(role_dir)

    def node(self) -> Node:
        node_dir = self.node_dir
        kp = load_keypair(node_dir)

        if (node_dir / GENESIS_DATA).exists():
            store = open_store_with_genesis(node_dir)
        else:
            anchor_pub = load_anchor(node_dir)
            store = Store(store_path(node_dir))
            if store.head_block_num() is None:
                store.provision(anchor_pub)

        listen = self.node_listen or NodeListenConfig()
        acceptors = listen.acceptors(self.tunables)
        if not acceptors:
            acceptors = (TCPListenConfig().acceptor(self.tunables),)

        n = Node(kp, store, self.tunables)
        for a in acceptors:
            n.add_acceptor(a)
        n.add_socket(self._role_socket(self.node_cfg, node_dir))
        return n

    def replica(self, role_dir: Path, role_cfg: RoleConfig | None = None) -> ReplicaNode:
        kp = load_keypair(role_dir)
        store = open_store_with_genesis(role_dir)
        rn = ReplicaNode(kp, store, self.tunables)
        rn.add_socket(self._role_socket(role_cfg, role_dir))
        return rn

    def light_client(self, role_dir: Path, role_cfg: RoleConfig | None = None) -> LightClient:
        kp = load_keypair(role_dir)
        seed = BootstrapSeed.load(role_dir)
        postman = Postman(kp, self.tunables)
        lc = LightClient(me=kp, anchor=seed.anchor, postman=postman)
        for pub, endpoints in seed.peers:
            lc.add_bootstrap_peer(pub, endpoints)
        lc.add_socket(self._role_socket(role_cfg, role_dir))
        lc.start()
        log.info("bootstrapping...")
        try:
            lc.bootstrap()
        except LightClientError:
            lc.stop()
            raise CLIError("failed to bootstrap") from None
        if lc.trusted_state is None:
            lc.stop()
            raise CLIError("bootstrap completed but no trusted state")
        log.info("bootstrapped at block %d", lc.trusted_state.head.anchors.block_num)
        return lc

    @classmethod
    def load(cls, home: Path) -> DudeConfig:
        config_path = home / "config.toml"
        if not config_path.exists():
            return cls(home=home)
        with open(config_path, "rb") as f:
            raw = tomllib.load(f)
        tunables = _load_section(Tunables, raw.get("tunables"))
        node_raw = raw.get("node", {})
        node_listen = _load_section(NodeListenConfig, node_raw.get("listen"))
        return cls(
            home=home,
            tunables=tunables or DEFAULT,
            node_listen=node_listen,
            node_cfg=_load_section(RoleConfig, raw.get("node")),
            manager_cfg=_load_section(RoleConfig, raw.get("manager")),
            client_cfg=_load_section(RoleConfig, raw.get("client")),
            compactor_cfg=_load_section(RoleConfig, raw.get("compactor")),
        )


def _load_section[T](cls: type[T], raw: dict | None) -> T | None:
    if not raw:
        return None
    return dacite.from_dict(cls, raw, config=_DACITE_CONFIG)
