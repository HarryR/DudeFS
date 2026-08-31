from __future__ import annotations

import tomllib
from dataclasses import dataclass
from pathlib import Path

import dacite

from ..core.units import Millis
from ..net.link import Acceptor
from ..net.transports.tcp import TCPListener
from ..node import Node
from ..store import Store
from ..tunables import DEFAULT, Tunables
from .state import (
    GENESIS_DATA,
    load_anchor,
    load_keypair,
    open_store_with_genesis,
    store_path,
)


@dataclass(slots=True)
class TCPListenConfig:
    host: str = "0.0.0.0"  # noqa: S104
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


_DACITE_CONFIG = dacite.Config(
    type_hooks={Millis: Millis},
    cast=[tuple],
)


@dataclass(slots=True)
class DudeConfig:
    home: Path
    tunables: Tunables = DEFAULT
    node_listen: NodeListenConfig | None = None

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
        return n

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
        )


def _load_section[T](cls: type[T], raw: dict | None) -> T | None:
    if not raw:
        return None
    return dacite.from_dict(cls, raw, config=_DACITE_CONFIG)
