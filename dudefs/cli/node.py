# `node` — the storage node running itself. `init` mints its identity; `serve` launches the
# daemon from --dir (durable store + bootstrap.json). Manager AUTHORITY over nodes lives in
# cli/mgr.py. `status` (local reader) lands in Phase 4.

from __future__ import annotations

import argparse
import os
import threading
import time

from .. import crypto as C
from ..daemon import NodeDaemon
from . import _util as U
from ._args import dir_arg
from .bootstrap import Bootstrap

GOSSIP_PERIOD_S = 1.0


def cmd_init(args: argparse.Namespace) -> int:
    from ..manager import mint_identity

    pub, keyfile, pop = mint_identity(args.dir, "node")
    U.print_minted(
        "node",
        pub,
        keyfile,
        pop,
        f"founding:  dude mgr node genesis {pub.hex()} {pop.hex()} <addr>",
        f"or join:   dude mgr node authorize {pub.hex()} {pop.hex()}  (then add + promote)",
    )
    return U.OK


def cmd_serve(args: argparse.Namespace) -> int:
    with open(os.path.join(args.dir, "node.key"), "rb") as f:
        sk = f.read()
    pub = C.SIGNER.public(sk)
    b = Bootstrap.read(args.dir)
    d = NodeDaemon(
        sk,
        pub,
        store_path=os.path.join(args.dir, "store.sqlite"),
        roster=b.roster,
        manager_pub=b.manager_pub,
        control_ops=b.control_ops,
        clock=lambda: int(time.time() * 1000),
        epoch=b.epoch,
    )
    d.refresh_peers()  # dial peers from the ENDPOINT records in the seeded control chain
    stop = threading.Event()
    threading.Thread(target=d.run_periodic, args=(GOSSIP_PERIOD_S, stop), daemon=True).start()
    print(f"node {pub.hex()[:16]}… serving on {args.listen} (epoch {b.epoch})")
    try:
        d.serve_forever(args.listen)
    except KeyboardInterrupt:
        pass
    finally:
        stop.set()
        d.close()
    return U.OK


def register(sub: argparse._SubParsersAction) -> None:
    node = sub.add_parser("node", help="run a storage node")
    nsub = node.add_subparsers(dest="node_verb", required=True)
    dir_arg(nsub.add_parser("init", help="mint this node's identity keyfile")).set_defaults(
        fn=cmd_init
    )
    srv = dir_arg(nsub.add_parser("serve", help="run the storage-node daemon"))
    srv.add_argument("--listen", required=True, help="this node's own listen address")
    srv.set_defaults(fn=cmd_serve)
