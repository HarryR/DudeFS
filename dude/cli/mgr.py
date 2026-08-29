import argparse
from pathlib import Path

from ..core import crypto
from ..node import _ReplicaSubstrate
from ..session import Settled
from ..store import ops
from ..store.management import Cert, MgmtWriter, Role
from .state import (
    CLIError,
    add_dir_arg,
    cmd_init,
    connect_socket,
    load_keypair,
    serve_with_socket,
    start_replica,
)


def register(sub: argparse._SubParsersAction) -> None:
    mgr = sub.add_parser("mgr", aliases=["m", "manager"], help="manager commands")
    mgr_sub = mgr.add_subparsers(dest="mgr_command")

    init = mgr_sub.add_parser("init", help="mint manager identity")
    add_dir_arg(init, required=True, help="manager home directory")
    init.set_defaults(func=lambda args: cmd_init(args, "manager"))

    serve = mgr_sub.add_parser("serve", help="run the manager daemon")
    add_dir_arg(serve, required=True, help="manager home directory")
    serve.set_defaults(func=cmd_serve)

    grant = mgr_sub.add_parser("grant", help="authorise an identity")
    add_dir_arg(grant, required=True)
    grant.add_argument("pub", help="subject public key (hex)")
    grant.add_argument("pop", help="subject proof of possession (hex)")
    grant.add_argument("role", choices=[r.name.lower() for r in Role], help="role to grant")
    grant.set_defaults(func=cmd_grant)

    revoke = mgr_sub.add_parser("revoke", help="revoke an identity")
    add_dir_arg(revoke, required=True)
    revoke.add_argument("pub", help="subject public key (hex)")
    revoke.set_defaults(func=cmd_revoke)

    mgr.set_defaults(func=lambda _args: mgr.print_help())


def cmd_serve(args: argparse.Namespace) -> None:
    dir_path: Path = args.dir
    rn, store = start_replica(dir_path)
    sub = _ReplicaSubstrate(rn)
    label = f"manager {rn.me.public.hex()[:16]}..."

    def stop_fn():
        rn.stop()
        store.close()

    serve_with_socket(label, dir_path, sub, stop_fn)


def cmd_grant(args: argparse.Namespace) -> None:
    dir_path: Path = args.dir
    signer = load_keypair(dir_path)

    subject = crypto.PublicKey(bytes.fromhex(args.pub))
    pop = crypto.Signature(bytes.fromhex(args.pop))
    if not subject.verify_possession(pop):
        raise CLIError("proof of possession does not verify")

    role = Role[args.role.upper()]
    cert = Cert.sign_grant(signer, subject, role)
    stores = frozenset({ops.STORE_MANAGEMENT, ops.STORE_DATA})

    sub, session = connect_socket(dir_path, ops.STORE_MANAGEMENT)
    try:
        w = MgmtWriter(session)
        tx = w.authorise(subject, role, stores=stores, pop=pop, cert=cert)
        result = session.submit(tx).wait()
        if not isinstance(result, Settled):
            raise CLIError(f"grant failed: {result!r}")
        print(f"granted {role.name} to {subject.hex()[:16]}... (block {result.block_num})")
    finally:
        sub.close()


def cmd_revoke(args: argparse.Namespace) -> None:
    dir_path: Path = args.dir
    signer = load_keypair(dir_path)
    subject = crypto.PublicKey(bytes.fromhex(args.pub))

    sub, session = connect_socket(dir_path, ops.STORE_MANAGEMENT)
    try:
        w = MgmtWriter(session)
        tx = w.revoke(subject, reissue_signer=signer)
        result = session.submit(tx).wait()
        if not isinstance(result, Settled):
            raise CLIError(f"revoke failed: {result!r}")
        print(f"revoked {subject.hex()[:16]}... (block {result.block_num})")
    finally:
        sub.close()
