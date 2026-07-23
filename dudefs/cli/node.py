# `node` — the storage node running itself. `init` mints its identity keyfile in `--dir`;
# `serve`/`status` land in later phases. (Manager AUTHORITY over nodes lives in cli/mgr.py.)

from __future__ import annotations

import argparse

from ..manager import mint_identity
from . import _util as U
from ._args import dir_arg


def cmd_init(args: argparse.Namespace) -> int:
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


def register(sub: argparse._SubParsersAction) -> None:
    node = sub.add_parser("node", help="run a storage node")
    nsub = node.add_subparsers(dest="node_verb", required=True)
    dir_arg(nsub.add_parser("init", help="mint this node's identity keyfile")).set_defaults(
        fn=cmd_init
    )
