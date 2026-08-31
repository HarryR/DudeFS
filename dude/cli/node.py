from __future__ import annotations

import logging
import signal
import threading
from collections.abc import Generator
from contextlib import contextmanager
from dataclasses import dataclass
from pathlib import Path

import click

from ..core import crypto
from ..net.link import Acceptor, Dialer
from ..net.transports.tcp import TCPListener
from ..node import Node
from ..store import Store
from ..tunables import DEFAULT, Tunables
from .config import DudeConfig
from .params import ACCEPTOR, PUBKEY
from .state import (
    GENESIS_DATA,
    load_anchor,
    load_keypair,
    open_store_with_genesis,
    save_anchor,
    save_keypair,
    store_path,
)

log = logging.getLogger(__name__)


@dataclass(frozen=True, slots=True)
class NodeConfig:
    dir: Path
    acceptors: tuple[Acceptor, ...] = ()
    dialers: tuple[Dialer, ...] = ()
    tunables: Tunables = DEFAULT


@contextmanager
def node_serve(cfg: NodeConfig) -> Generator[Node]:
    kp = load_keypair(cfg.dir)

    if (cfg.dir / GENESIS_DATA).exists():
        store = open_store_with_genesis(cfg.dir)
    else:
        anchor_pub = load_anchor(cfg.dir)
        store = Store(store_path(cfg.dir))
        if store.head_block_num() is None:
            store.provision(anchor_pub)

    n = Node(kp, store, cfg.tunables)
    for a in cfg.acceptors:
        n.add_acceptor(a)
    for d in cfg.dialers:
        n.add_dialer(d)
    n.start()
    try:
        yield n
    finally:
        n.stop()
        store.close()


@click.group("node")
def group() -> None:
    pass


@group.command()
@click.option("--anchor", required=True, type=PUBKEY, help="anchor public key (hex)")
@click.pass_obj
def init(cfg: DudeConfig, anchor: crypto.PublicKey) -> None:
    dir_path = cfg.node_dir
    kp = crypto.Keypair.generate()
    save_keypair(dir_path, kp)
    save_anchor(dir_path, anchor)
    pop = kp.prove_possession()
    click.echo(f"node identity created in {dir_path}")
    click.echo(f"  public key: {kp.public.hex()}")
    click.echo(f"  possession: {pop.hex()}")
    click.echo(f"  anchor:     {anchor.hex()[:16]}...")


@group.command()
@click.option("--listen", type=ACCEPTOR, default=None, help="listen address (tcp:host:port)")
@click.pass_obj
def serve(cfg: DudeConfig, listen: Acceptor | None) -> None:
    acceptor = listen or TCPListener(cfg.tunables)
    node_cfg = NodeConfig(
        dir=cfg.node_dir,
        acceptors=(acceptor,),
        tunables=cfg.tunables,
    )
    with node_serve(node_cfg) as n:
        if n.store.head_block_num() is None:
            log.info("unprovisioned — waiting for genesis from anchor")
        else:
            log.info("node %s running", n.me.public.hex()[:16])

        stop = threading.Event()
        signal.signal(signal.SIGINT, lambda *_: stop.set())
        signal.signal(signal.SIGTERM, lambda *_: stop.set())
        stop.wait()
        log.info("shutting down")
