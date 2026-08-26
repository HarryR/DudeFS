import argparse
import signal
import threading
from pathlib import Path

from ..consensus.canonical import bodies_canonical
from ..consensus.settle_round import SettledBlock
from ..core import crypto
from ..net.address import Address, Scheme
from ..net.transports.tcp import TCPDialer, TCPListener, TCPTiming
from ..node import Node
from ..store import Store

from ..tunables import DEFAULT
from .state import (
    BootstrapSeed,
    load_genesis,
    load_keypair,
    save_keypair,
    store_path,
)


def register(sub: argparse._SubParsersAction) -> None:
    node = sub.add_parser("node", help="storage node commands")
    node_sub = node.add_subparsers(dest="node_command")

    init = node_sub.add_parser("init", help="mint node identity")
    init.add_argument("--dir", type=Path, required=True, help="node home directory")
    init.set_defaults(func=cmd_init)

    serve = node_sub.add_parser("serve", help="run the storage node")
    serve.add_argument("--dir", type=Path, required=True, help="node home directory")
    serve.add_argument("--listen", default=None, help="listen address (e.g. tcp:0.0.0.0:9000)")
    serve.set_defaults(func=cmd_serve)

    node.set_defaults(func=lambda _args: node.print_help())


def cmd_init(args: argparse.Namespace) -> None:
    dir_path: Path = args.dir
    kp = crypto.Keypair.generate()
    save_keypair(dir_path, kp)
    pop = kp.prove_possession()
    print(f"node identity created in {dir_path}")
    print(f"  public key: {kp.public.hex()}")
    print(f"  possession: {pop.hex()}")


def cmd_serve(args: argparse.Namespace) -> None:
    dir_path: Path = args.dir
    kp = load_keypair(dir_path)
    seed = BootstrapSeed.load(dir_path)
    db_path = store_path(dir_path)

    store = Store(db_path)

    if store.head_block_num() is None:
        block_bytes, bodies = load_genesis(dir_path)
        store.provision(seed.anchor)
        sb = SettledBlock.decode(block_bytes)
        ordered = bodies_canonical(bodies).txs
        store.commit_block(
            sb.anchors.block_num,
            first_height=1,
            block_bytes=block_bytes,
            block_hash=sb.block_hash,
            batch=ordered,
            auth=store.mgmt_reader,
        )
        print(f"genesis block applied (block 1, {len(ordered)} transactions)")

    timing = TCPTiming.for_deployment(DEFAULT)
    n = Node(kp, store, DEFAULT)

    if args.listen:
        addr = Address.parse(args.listen.encode())
        if addr.scheme is Scheme.TCP:
            host, _, port_s = addr.value.partition(":")
            listener = TCPListener(listen_host=host, listen_port=int(port_s), timing=timing)
            n.add_listener(listener)
            print(f"listening on {listener.bound_address}")
    else:
        listener = TCPListener(timing=timing)
        n.add_listener(listener)
        print(f"listening on {listener.bound_address}")

    n.add_listener(TCPDialer(timing=timing))
    n.start()

    print(f"node {kp.public.hex()[:16]}... running")

    stop = threading.Event()
    signal.signal(signal.SIGINT, lambda *_: stop.set())
    signal.signal(signal.SIGTERM, lambda *_: stop.set())
    stop.wait()

    print("shutting down...")
    n.stop()
    store.close()
