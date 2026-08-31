from __future__ import annotations

import logging
import time

import click

from ..consensus.bootstrap import bootstrap, compose_genesis
from ..core import codec, crypto
from ..core.units import Millis, now_ms
from ..net.address import Address, Endpoint
from ..net.envelope import Verb
from ..net.postman import Postman
from ..store import Store
from .config import DudeConfig
from .state import (
    BootstrapSeed,
    CLIError,
    load_keypair,
    save_genesis,
    save_keypair,
    store_path,
)

log = logging.getLogger(__name__)


def _parse_node_specs(raw: tuple[str, ...]) -> list[tuple[crypto.PublicKey, tuple[Endpoint, ...]]]:
    specs: list[tuple[crypto.PublicKey, tuple[Endpoint, ...]]] = []
    current_pub: crypto.PublicKey | None = None
    current_eps: list[Endpoint] = []
    for arg in raw:
        if len(arg) == 64 and all(c in "0123456789abcdef" for c in arg.lower()):
            if current_pub is not None:
                if not current_eps:
                    raise CLIError(f"node {current_pub.hex()[:16]}... has no endpoints")
                specs.append((current_pub, tuple(current_eps)))
            current_pub = crypto.PublicKey(bytes.fromhex(arg))
            current_eps = []
        else:
            if current_pub is None:
                raise CLIError(f"endpoint {arg} before any pubkey")
            current_eps.append(Endpoint(Address.parse(arg.encode())))
    if current_pub is not None:
        if not current_eps:
            raise CLIError(f"node {current_pub.hex()[:16]}... has no endpoints")
        specs.append((current_pub, tuple(current_eps)))
    if not specs:
        raise CLIError("no nodes specified")
    return specs


def _wait_for_verb(
    postman: Postman, pub: crypto.PublicKey, verb: Verb, timeout_ms: Millis,
) -> bool:
    deadline = time.monotonic() + timeout_ms.as_seconds
    while time.monotonic() < deadline:
        for output in postman.drain_output(timeout=0.1):
            for d in output.delivered:
                if d.frm == pub and d.verb == verb:
                    return True
    return False


@click.group("anchor")
def group() -> None:
    pass


@group.command()
@click.pass_obj
def init(cfg: DudeConfig) -> None:
    dir_path = cfg.anchor_dir
    kp = crypto.Keypair.generate()
    save_keypair(dir_path, kp)
    click.echo(f"anchor identity created in {dir_path}")
    click.echo(f"  public key: {kp.public.hex()}")


@group.command()
@click.argument("nodes", nargs=-1, required=True)
@click.option("--dry-run", is_flag=True, help="verify liveness without provisioning")
@click.pass_obj
def genesis(cfg: DudeConfig, nodes: tuple[str, ...], dry_run: bool) -> None:
    dir_path = cfg.anchor_dir
    anchor = load_keypair(dir_path)
    node_specs = _parse_node_specs(nodes)

    postman = Postman(anchor, cfg.tunables)
    for pub, endpoints in node_specs:
        postman.add_peer(pub, endpoints)
    postman.start()

    log.info("verifying node liveness...")
    for pub, _eps in node_specs:
        postman.send_raw(pub, Verb.PING, b"", cfg.tunables.ttl_exchange)
        if not _wait_for_verb(postman, pub, Verb.PONG, cfg.tunables.ttl_exchange):
            postman.stop()
            raise CLIError(f"node {pub.hex()[:16]}... did not respond to PING")
        log.info("  %s alive", pub.hex()[:16])

    if dry_run:
        postman.stop()
        click.echo("dry run complete — all nodes reachable")
        return

    now = now_ms()
    genesis_bodies = compose_genesis(
        anchor=anchor,
        node_endpoints=node_specs,
        ts=now,
    )

    store = Store(store_path(dir_path))
    store.provision(anchor.public)
    settled = bootstrap(store, anchor, genesis_bodies, bucket=cfg.tunables.bucket(now))

    genesis_wire = codec.encode([settled.block.encode(), [tx.raw for tx in settled.bodies]])

    log.info("provisioning nodes...")
    for pub, _eps in node_specs:
        postman.send_raw(pub, Verb.PROVISION, genesis_wire, cfg.tunables.ttl_exchange)
        if not _wait_for_verb(postman, pub, Verb.ACCEPTED, cfg.tunables.ttl_exchange):
            postman.stop()
            raise CLIError(f"node {pub.hex()[:16]}... did not acknowledge PROVISION")
        log.info("  %s provisioned", pub.hex()[:16])

    postman.stop()

    seed = BootstrapSeed(
        anchor=anchor.public,
        peers=tuple(node_specs),
    )
    seed.save(dir_path)
    save_genesis(dir_path, settled.block.encode(), settled.bodies)

    click.echo(f"genesis created: {len(node_specs)} node(s) seated")
    click.echo(f"  bootstrap seed: {dir_path / 'bootstrap.json'}")
    click.echo(f"  genesis data:   {dir_path / 'genesis.bin'}")
