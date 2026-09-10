from __future__ import annotations

import dataclasses
import json
import logging
import time

import click

from ..consensus.bootstrap import bootstrap, compose_genesis
from ..core import codec, crypto
from ..core.serde import json_safe
from ..core.units import Millis
from ..net.address import Address, Endpoint
from ..net.envelope import Verb
from ..net.link import LinkDirection
from ..net.postman import OutputQueue, PeerStatus, Postman
from ..store.store import Store
from ..sync.lite_client import LightClient
from ..sync.observer import ClusterObserver
from .config import DudeConfig
from .state import (
    BootstrapSeed,
    CLIError,
    load_keypair,
    load_pubkey,
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


def _peer_alive(status: dict[crypto.PublicKey, PeerStatus], pub: crypto.PublicKey) -> bool:
    ps = status.get(pub)
    return ps is not None and ps.connected


def _wait_all_connected(
    postman: Postman,
    pubs: list[crypto.PublicKey],
    timeout: Millis,
) -> None:
    deadline = time.monotonic() + timeout.as_seconds
    while time.monotonic() < deadline:
        status = postman.peer_status()
        if all(_peer_alive(status, pub) for pub in pubs):
            return
        time.sleep(0.05)
    status = postman.peer_status()
    for pub in pubs:
        if not _peer_alive(status, pub):
            raise CLIError(f"node {pub.hex()[:16]}... not reachable")


def _wait_for_verb(
    replies: OutputQueue,
    pub: crypto.PublicKey,
    verb: Verb,
    timeout_ms: Millis,
) -> bool:
    deadline = time.monotonic() + timeout_ms.as_seconds
    while time.monotonic() < deadline:
        out = replies.get(timeout=0.1)
        if out is not None:
            for d in out.delivered:
                if d.frm == pub and d.verb == verb:
                    return True
    return False


@click.group("anchor", help="Cluster anchor — genesis, provisioning, observation.")
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
@click.pass_obj
def pubkey(cfg: DudeConfig) -> None:
    click.echo(load_pubkey(cfg.anchor_dir).hex())


@group.command()
@click.argument("nodes", nargs=-1, required=True)
@click.option("--dry-run", is_flag=True, help="verify liveness without provisioning")
@click.pass_obj
def genesis(cfg: DudeConfig, nodes: tuple[str, ...], dry_run: bool) -> None:
    dir_path = cfg.anchor_dir
    anchor = load_keypair(dir_path)
    node_specs = _parse_node_specs(nodes)

    replies = OutputQueue()
    postman = Postman(anchor, cfg.tunables, on_output=replies)
    for pub, endpoints in node_specs:
        postman.add_peer(pub, endpoints)
    postman.start()

    log.info("verifying node liveness...")
    pubs = [pub for pub, _ in node_specs]
    _wait_all_connected(postman, pubs, cfg.tunables.ttl_exchange)
    for pub in pubs:
        log.info("  %s alive", pub.hex()[:16])

    if dry_run:
        postman.stop()
        click.echo("dry run complete — all nodes reachable")
        return

    now = Millis.now()
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
        if not _wait_for_verb(replies, pub, Verb.ACCEPTED, cfg.tunables.ttl_exchange):
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


def _render_topology(obs: ClusterObserver) -> None:
    topo = obs.topology()
    cs = topo.cluster

    if not cs.bootstrapped:
        click.echo("not bootstrapped")
        return

    click.echo(f"Block: {cs.block_num}  Roster: {len(cs.roster)} nodes")
    click.echo()

    for pub, ns in topo.nodes.items():
        click.echo(f"  {pub.hex()[:16]}  block={ns.head_block}  mempool={ns.mempool_size or 0}")
        for link in ns.peers:
            arrow = "  " + link.identity.hex()[:16]
            click.echo(f"    {arrow}  connected={link.connected}  links={len(link.links)}")
            for ln in link.links:
                d = "out" if ln.direction == LinkDirection.OUTBOUND.value else " in"
                rtt = f"{ln.rtt_ms:.1f}ms" if ln.rtt_ms is not None else "—"
                click.echo(
                    f"      {d}  rtt={rtt}  sent={ln.msgs_sent}/{ln.bytes_sent}b"
                    f"  recv={ln.msgs_recv}/{ln.bytes_recv}b"
                )
        for ls in ns.listeners:
            click.echo(f"    listen {ls.address}  {ls.extra}")
        click.echo()

    for pub, ns in cs.nodes.items():
        if pub not in topo.nodes:
            status = "connected" if ns.connected else "unreachable"
            click.echo(f"  {pub.hex()[:16]}  {status} (no status reply)")


def _render_json(obs: ClusterObserver, compact: bool = False) -> None:
    topo = obs.topology()
    data = {
        "block_num": topo.cluster.block_num,
        "roster": [pk.hex() for pk in topo.cluster.roster],
        "managers": [pk.hex() for pk in topo.cluster.managers],
        "bootstrapped": topo.cluster.bootstrapped,
        "nodes": {pk.hex(): json_safe(dataclasses.asdict(ns)) for pk, ns in topo.nodes.items()},
    }
    click.echo(json.dumps(data) if compact else json.dumps(data, indent=2))


@group.command()
@click.option("--watch", is_flag=True, help="continuously refresh")
@click.option("--interval", type=float, default=2.0, help="refresh interval (seconds)")
@click.option("--timeout", type=float, default=10.0, help="max wait time for oneshot mode")
@click.option("--json", "as_json", is_flag=True, help="output as JSON")
@click.pass_obj
def observe(cfg: DudeConfig, watch: bool, interval: float, timeout: float, as_json: bool) -> None:
    kp = load_keypair(cfg.anchor_dir)
    seed = BootstrapSeed.load(cfg.anchor_dir)
    postman = Postman(kp, cfg.tunables, on_output=OutputQueue())
    lc = LightClient(me=kp, anchor=seed.anchor, postman=postman)
    for pub, endpoints in seed.peers:
        lc.add_bootstrap_peer(pub, endpoints)

    obs = ClusterObserver(lc)
    lc.start()
    lc.bootstrap(timeout=timeout)

    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        obs.query_topology()
        topo = obs.topology()
        if topo.nodes:
            break
        time.sleep(0.5)

    if watch:
        try:
            while True:
                if as_json:
                    _render_json(obs, compact=True)
                else:
                    click.clear()
                    _render_topology(obs)
                obs.query_topology()
                time.sleep(interval)
        except KeyboardInterrupt:
            pass
    elif as_json:
        _render_json(obs)
    else:
        _render_topology(obs)

    lc.stop()
