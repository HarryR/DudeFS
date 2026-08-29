import argparse
import signal
import threading
from pathlib import Path

from ..net.address import Address, Scheme
from ..net.transports.tcp import TCPDialer, TCPListener, TCPTiming
from ..node import Node
from ..tunables import DEFAULT
from .state import (
    add_dir_arg,
    cmd_init,
    load_keypair,
    open_store_with_genesis,
)


def register(sub: argparse._SubParsersAction) -> None:
    node = sub.add_parser("node", help="storage node commands")
    node_sub = node.add_subparsers(dest="node_command")

    init = node_sub.add_parser("init", help="mint node identity")
    add_dir_arg(init, required=True, help="node home directory")
    init.set_defaults(func=lambda args: cmd_init(args, "node"))

    serve = node_sub.add_parser("serve", help="run the storage node")
    add_dir_arg(serve, required=True, help="node home directory")
    serve.add_argument("--listen", default=None, help="listen address (e.g. tcp:0.0.0.0:9000)")
    serve.set_defaults(func=cmd_serve)

    node.set_defaults(func=lambda _args: node.print_help())


def cmd_serve(args: argparse.Namespace) -> None:
    dir_path: Path = args.dir
    kp = load_keypair(dir_path)
    store = open_store_with_genesis(dir_path)

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
