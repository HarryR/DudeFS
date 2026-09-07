from __future__ import annotations

import logging
import sys

import click

from ..core import crypto
from ..session import SessionRW, Settled
from ..store import ops
from .config import DudeConfig
from .state import (
    CLIError,
    load_pubkey,
    pidfile,
    save_keypair,
    until_terminated,
)

log = logging.getLogger(__name__)


@click.group("client")
def group() -> None:
    pass


@group.command()
@click.pass_obj
def init(cfg: DudeConfig) -> None:
    dir_path = cfg.client_dir
    kp = crypto.Keypair.generate()
    save_keypair(dir_path, kp)
    pop = kp.prove_possession()
    click.echo(f"client identity created in {dir_path}")
    click.echo(f"  public key: {kp.public.hex()}")
    click.echo(f"  possession: {pop.hex()}")


@group.command()
@click.pass_obj
def pubkey(cfg: DudeConfig) -> None:
    click.echo(load_pubkey(cfg.client_dir).hex())


@group.command()
@click.pass_obj
def serve(cfg: DudeConfig) -> None:
    with cfg.light_client(cfg.client_dir, cfg.client_cfg) as lc, pidfile(cfg.client_dir):
        log.info("client %s running", lc.me.public.hex()[:16])
        with until_terminated():
            log.info("shutting down")


@group.command()
@click.argument("key")
@click.pass_obj
def get(cfg: DudeConfig, key: str) -> None:
    with cfg.substrate(cfg.client_dir, cfg.client_cfg) as sub:
        session = SessionRW(sub, ops.STORE_DATA)
        rec = session.get(key)
        if rec.absent:
            click.echo(f"{key}: not found")
            sys.exit(1)
        sys.stdout.buffer.write(rec.value)
        sys.stdout.buffer.write(b"\n")


@group.command()
@click.argument("key")
@click.argument("value")
@click.pass_obj
def put(cfg: DudeConfig, key: str, value: str) -> None:
    with cfg.substrate(cfg.client_dir, cfg.client_cfg) as sub:
        session = SessionRW(sub, ops.STORE_DATA)
        result = session.put(key, value.encode()).wait()
        if not isinstance(result, Settled):
            raise CLIError(f"put failed: {result!r}")
        click.echo(f"{key}: written (block {result.block_num})")


@group.command("del")
@click.argument("key")
@click.pass_obj
def delete(cfg: DudeConfig, key: str) -> None:
    with cfg.substrate(cfg.client_dir, cfg.client_cfg) as sub:
        session = SessionRW(sub, ops.STORE_DATA)
        result = session.delete(key).wait()
        if not isinstance(result, Settled):
            raise CLIError(f"delete failed: {result!r}")
        click.echo(f"{key}: deleted (block {result.block_num})")
