from __future__ import annotations

import logging
import signal
import threading

import click

from ..core import crypto
from ..session import Settled
from ..store import ops
from ..store.checkpoint import CheckpointMeta
from ..store.management import Cert, MgmtWriter
from ..sync.checkpoint_server import CheckpointServer
from .config import DudeConfig
from .state import (
    CLIError,
    load_keypair,
    save_keypair,
    start_light_client,
    start_replica,
)

log = logging.getLogger(__name__)


@click.group("compactor")
def group() -> None:
    pass


@group.command()
@click.pass_obj
def init(cfg: DudeConfig) -> None:
    dir_path = cfg.compactor_dir
    kp = crypto.Keypair.generate()
    save_keypair(dir_path, kp)
    pop = kp.prove_possession()
    click.echo(f"compactor identity created in {dir_path}")
    click.echo(f"  public key: {kp.public.hex()}")
    click.echo(f"  possession: {pop.hex()}")


@group.command()
@click.pass_obj
def run(cfg: DudeConfig) -> None:
    dir_path = cfg.compactor_dir
    lc = start_light_client(dir_path)

    head = lc.trusted_state.head
    block_num = head.anchors.block_num

    s = lc.session(store_id=ops.STORE_MANAGEMENT)
    result = s.submit(MgmtWriter(s).compact(block_num)).wait()
    if not isinstance(result, Settled):
        lc.stop()
        raise CLIError(f"compact transaction did not settle: {result!r}")

    click.echo(f"compaction pivot at block {block_num} settled")
    lc.stop()
    click.echo("done")


@group.command()
@click.option("--interval", type=int, default=86400, help="seconds between compaction runs")
@click.pass_obj
def serve(cfg: DudeConfig, interval: int) -> None:
    dir_path = cfg.compactor_dir
    rn, store = start_replica(dir_path)
    kp = load_keypair(dir_path)

    log.info("compactor %s running (interval=%ds)", kp.public.hex()[:16], interval)

    stop = threading.Event()
    signal.signal(signal.SIGINT, lambda *_: stop.set())
    signal.signal(signal.SIGTERM, lambda *_: stop.set())

    while not stop.is_set():
        _run_compaction_cycle(rn, kp)
        stop.wait(timeout=interval)

    log.info("shutting down")
    rn.stop()
    store.close()


def _run_compaction_cycle(rn, kp: crypto.Keypair) -> None:
    head_num = rn.store.head_block_num()
    if head_num is None or head_num < 2:
        return

    s = rn.session(store_id=ops.STORE_MANAGEMENT)
    result = s.submit(MgmtWriter(s).compact(head_num)).wait()
    if not isinstance(result, Settled):
        log.warning("compact did not settle: %r", result)
        return

    log.info("pivot at block %d settled", head_num)

    grant_cert = _find_grant_cert_from_store(rn.store, kp)
    with rn.store.snapshot() as reader:
        sb_bytes = reader.settled_at(reader.head_block_num())
        meta = CheckpointMeta.create(
            settled_block_bytes=sb_bytes,
            anchor=rn.store.anchor(),
            compactor=kp,
            grant_cert=grant_cert,
        )

    srv = CheckpointServer.create_and_persist(rn.store, meta)
    rn.checkpoint_server = srv
    log.info("checkpoint persisted (%d chunks)", rn.store.checkpoint_chunk_count())


def _find_grant_cert_from_store(store, kp: crypto.Keypair) -> Cert:
    grant = store.mgmt_reader.grant_of(kp.public)
    if grant is None:
        raise CLIError("compactor grant not found")
    return grant.cert
