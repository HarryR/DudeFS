from __future__ import annotations

import click

from ..core import crypto
from ..node import _ReplicaSubstrate
from ..session import Settled
from ..store import ops
from ..store.management import Cert, MgmtWriter, Role
from .config import DudeConfig
from .params import PUBKEY, ROLE, SIGNATURE
from .state import (
    CLIError,
    connect_socket,
    load_keypair,
    save_keypair,
    serve_with_socket,
    start_replica,
)


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
    dir_path = cfg.manager_dir
    rn, store = start_replica(dir_path)
    sub = _ReplicaSubstrate(rn)
    label = f"manager {rn.me.public.hex()[:16]}..."

    def stop_fn() -> None:
        rn.stop()
        store.close()

    serve_with_socket(label, dir_path, sub, stop_fn)


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

    sub, session = connect_socket(dir_path, ops.STORE_MANAGEMENT)
    try:
        w = MgmtWriter(session)
        tx = w.authorise(pub, role, stores=stores, pop=pop, cert=cert)
        result = session.submit(tx).wait()
        if not isinstance(result, Settled):
            raise CLIError(f"grant failed: {result!r}")
        click.echo(
            f"granted {role.name} to {pub.hex()[:16]}... (block {result.block_num})"
        )
    finally:
        sub.close()


@group.command()
@click.argument("pub", type=PUBKEY, metavar="PUBKEY")
@click.pass_obj
def revoke(cfg: DudeConfig, pub: crypto.PublicKey) -> None:
    dir_path = cfg.manager_dir
    signer = load_keypair(dir_path)

    sub, session = connect_socket(dir_path, ops.STORE_MANAGEMENT)
    try:
        w = MgmtWriter(session)
        tx = w.revoke(pub, reissue_signer=signer)
        result = session.submit(tx).wait()
        if not isinstance(result, Settled):
            raise CLIError(f"revoke failed: {result!r}")
        click.echo(f"revoked {pub.hex()[:16]}... (block {result.block_num})")
    finally:
        sub.close()
