from __future__ import annotations

import sys

import click

from ..core import crypto
from ..session import Settled
from ..sync.lite_client import _LiteSubstrate
from .config import DudeConfig
from .state import (
    CLIError,
    connect_socket,
    save_keypair,
    serve_with_socket,
    start_light_client,
)


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
def serve(cfg: DudeConfig) -> None:
    dir_path = cfg.client_dir
    lc = start_light_client(dir_path)
    sub = _LiteSubstrate(lc)
    label = f"client {lc.me.public.hex()[:16]}..."
    serve_with_socket(label, dir_path, sub, lc.stop)


@group.command()
@click.argument("key")
@click.pass_obj
def get(cfg: DudeConfig, key: str) -> None:
    sub, session = connect_socket(cfg.client_dir)
    try:
        rec = session.get(key)
        if rec.absent:
            click.echo(f"{key}: not found")
            sys.exit(1)
        sys.stdout.buffer.write(rec.value)
        sys.stdout.buffer.write(b"\n")
    finally:
        sub.close()


@group.command()
@click.argument("key")
@click.argument("value")
@click.pass_obj
def put(cfg: DudeConfig, key: str, value: str) -> None:
    sub, session = connect_socket(cfg.client_dir)
    try:
        result = session.put(key, value.encode()).wait()
        if not isinstance(result, Settled):
            raise CLIError(f"put failed: {result!r}")
        click.echo(f"{key}: written (block {result.block_num})")
    finally:
        sub.close()


@group.command("del")
@click.argument("key")
@click.pass_obj
def delete(cfg: DudeConfig, key: str) -> None:
    sub, session = connect_socket(cfg.client_dir)
    try:
        result = session.delete(key).wait()
        if not isinstance(result, Settled):
            raise CLIError(f"delete failed: {result!r}")
        click.echo(f"{key}: deleted (block {result.block_num})")
    finally:
        sub.close()
