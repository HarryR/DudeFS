from __future__ import annotations

import logging

import click

from ..core import crypto
from ..net.socket_substrate import SocketSubstrate
from ..session import SessionRW, Settled
from ..store import ops
from ..store.management import Cert, MgmtWriter, Role
from .config import DudeConfig
from .params import PUBKEY, ROLE, SIGNATURE
from .state import (
    CLIError,
    load_keypair,
    save_keypair,
    socket_path,
    until_terminated,
)

log = logging.getLogger(__name__)


@click.group("mgr")
def group() -> None:
    pass


@group.command()
@click.pass_obj
def init(cfg: DudeConfig) -> None:
    dir_path = cfg.manager_dir
    kp = crypto.Keypair.generate()
    save_keypair(dir_path, kp)
    pop = kp.prove_possession()
    click.echo(f"manager identity created in {dir_path}")
    click.echo(f"  public key: {kp.public.hex()}")
    click.echo(f"  possession: {pop.hex()}")


@group.command()
@click.pass_obj
def serve(cfg: DudeConfig) -> None:
    with cfg.replica(cfg.manager_dir, cfg.manager_cfg) as rn:
        log.info("manager %s running", rn.me.public.hex()[:16])
        with until_terminated():
            log.info("shutting down")


@group.command()
@click.argument("pub", type=PUBKEY, metavar="PUBKEY")
@click.argument("pop", type=SIGNATURE, metavar="POP")
@click.argument("role", type=ROLE)
@click.pass_obj
def grant(cfg: DudeConfig, pub: crypto.PublicKey, pop: crypto.Signature, role: Role) -> None:
    dir_path = cfg.manager_dir
    signer = load_keypair(dir_path)

    if not pub.verify_possession(pop):
        raise CLIError("proof of possession does not verify")

    cert = Cert.sign_grant(signer, pub, role)
    stores = frozenset({ops.STORE_MANAGEMENT, ops.STORE_DATA})

    with SocketSubstrate(socket_path(dir_path), cfg.tunables) as sub:
        session = SessionRW(sub, ops.STORE_MANAGEMENT)
        w = MgmtWriter(session)
        tx = w.authorise(pub, role, stores=stores, pop=pop, cert=cert)
        result = session.submit(tx).wait()
        if not isinstance(result, Settled):
            raise CLIError(f"grant failed: {result!r}")
        click.echo(f"granted {role.name} to {pub.hex()[:16]}... (block {result.block_num})")


@group.command()
@click.argument("pub", type=PUBKEY, metavar="PUBKEY")
@click.pass_obj
def revoke(cfg: DudeConfig, pub: crypto.PublicKey) -> None:
    dir_path = cfg.manager_dir
    signer = load_keypair(dir_path)

    with SocketSubstrate(socket_path(dir_path), cfg.tunables) as sub:
        session = SessionRW(sub, ops.STORE_MANAGEMENT)
        w = MgmtWriter(session)
        tx = w.revoke(pub, reissue_signer=signer)
        result = session.submit(tx).wait()
        if not isinstance(result, Settled):
            raise CLIError(f"revoke failed: {result!r}")
        click.echo(f"revoked {pub.hex()[:16]}... (block {result.block_num})")
