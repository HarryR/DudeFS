import argparse
from pathlib import Path

from ..consensus.bootstrap import bootstrap, compose_genesis
from ..core import crypto
from ..core.units import now_ms
from ..net.address import Address, Endpoint
from ..store import Store
from ..tunables import DEFAULT
from .state import (
    BootstrapSeed,
    CLIError,
    add_dir_arg,
    load_keypair,
    save_genesis,
    save_keypair,
    store_path,
)


def register(sub: argparse._SubParsersAction) -> None:
    anchor = sub.add_parser("anchor", aliases=["a"], help="cluster anchor commands")
    anchor_sub = anchor.add_subparsers(dest="anchor_command")

    init = anchor_sub.add_parser("init", help="create the anchor identity")
    add_dir_arg(init, default=Path(".dude"), help="anchor home")
    init.set_defaults(func=cmd_init)

    genesis = anchor_sub.add_parser("genesis", help="create the cluster genesis")
    add_dir_arg(genesis, default=Path(".dude"))
    genesis.add_argument("pub", help="founding node public key (hex)")
    genesis.add_argument("pop", help="founding node proof of possession (hex)")
    genesis.add_argument("endpoints", nargs="+", help="node dial addresses (scheme:value)")
    genesis.set_defaults(func=cmd_genesis)

    anchor.set_defaults(func=lambda _args: anchor.print_help())


def cmd_init(args: argparse.Namespace) -> None:
    dir_path: Path = args.dir
    kp = crypto.Keypair.generate()
    save_keypair(dir_path, kp)
    print(f"anchor identity created in {dir_path}")
    print(f"  public key: {kp.public.hex()}")


def cmd_genesis(args: argparse.Namespace) -> None:
    dir_path: Path = args.dir
    anchor = load_keypair(dir_path)

    node_pub = crypto.PublicKey(bytes.fromhex(args.pub))
    pop = crypto.Signature(bytes.fromhex(args.pop))
    if not node_pub.verify_possession(pop):
        raise CLIError("proof of possession does not verify")

    endpoints = tuple(Endpoint(Address.parse(e.encode())) for e in args.endpoints)

    genesis_bodies = compose_genesis(
        anchor=anchor,
        node_endpoints=[(node_pub, endpoints)],
        ts=now_ms(),
    )

    store = Store(store_path(dir_path))
    store.provision(anchor.public)
    settled = bootstrap(
        store,
        anchor,
        genesis_bodies,
        bucket=DEFAULT.bucket(now_ms()),
    )

    seed = BootstrapSeed(
        anchor=anchor.public,
        peers=((node_pub, endpoints),),
    )
    seed.save(dir_path)
    save_genesis(dir_path, settled.block.encode(), settled.bodies)

    print("genesis created: 1 node seated")
    print(f"  node: {node_pub.hex()[:16]}...")
    print(f"  bootstrap seed: {dir_path / 'bootstrap.json'}")
    print(f"  genesis data:   {dir_path / 'genesis.bin'}")
    print("copy both files to the node's --dir before running 'node serve'")
