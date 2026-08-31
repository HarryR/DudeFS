from __future__ import annotations

import logging

import click

from ..core import crypto
from .config import DudeConfig, NodeListenConfig, TCPListenConfig
from .params import LISTEN, PUBKEY
from .state import save_anchor, save_keypair, until_terminated

log = logging.getLogger(__name__)


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
@click.option("--listen", type=LISTEN, default=None, help="additional listen address")
@click.pass_obj
def serve(cfg: DudeConfig, listen: TCPListenConfig | None) -> None:
    if listen:
        if cfg.node_listen is None:
            cfg.node_listen = NodeListenConfig()
        cfg.node_listen.tcp.append(listen)
    with cfg.node() as n:
        if n.store.head_block_num() is None:
            log.info("unprovisioned — waiting for genesis from anchor")
        else:
            log.info("node %s running", n.me.public.hex()[:16])
        with until_terminated():
            log.info("shutting down")
