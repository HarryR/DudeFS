import argparse
from pathlib import Path

from ..core import crypto
from .state import CLIError, save_keypair


def register(sub: argparse._SubParsersAction) -> None:
    client = sub.add_parser("client", help="client daemon commands")
    client_sub = client.add_subparsers(dest="client_command")

    init = client_sub.add_parser("init", help="mint client identity")
    init.add_argument("--dir", type=Path, required=True, help="client home directory")
    init.set_defaults(func=cmd_init)

    serve = client_sub.add_parser("serve", help="run the client daemon")
    serve.add_argument("--dir", type=Path, required=True, help="client home directory")
    serve.set_defaults(func=cmd_serve)

    client.set_defaults(func=lambda _args: client.print_help())


def cmd_init(args: argparse.Namespace) -> None:
    dir_path: Path = args.dir
    kp = crypto.Keypair.generate()
    save_keypair(dir_path, kp)
    pop = kp.prove_possession()
    print(f"client identity created in {dir_path}")
    print(f"  public key: {kp.public.hex()}")
    print(f"  possession: {pop.hex()}")


def cmd_serve(_args: argparse.Namespace) -> None:
    raise CLIError("client serve not yet implemented")
