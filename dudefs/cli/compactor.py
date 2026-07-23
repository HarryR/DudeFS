# `compactor` — the compaction daemon running itself. `init` mints its identity keyfile;
# `run`/`once` land in Phase 5 (they wrap R6's compactor driver). Manager AUTHORITY over
# compactors (authorize/revoke) lives in cli/mgr.py.

from __future__ import annotations

import argparse

from ..manager import mint_identity
from . import _util as U
from ._args import dir_arg


def cmd_init(args: argparse.Namespace) -> int:
    pub, keyfile, pop = mint_identity(args.dir, "compactor")
    U.print_minted(
        "compactor",
        pub,
        keyfile,
        pop,
        f"authorize it:  dude mgr compactor authorize {pub.hex()} {pop.hex()}",
    )
    return U.OK


def register(sub: argparse._SubParsersAction) -> None:
    c = sub.add_parser("compactor", help="run the compaction daemon")
    csub = c.add_subparsers(dest="compactor_verb", required=True)
    dir_arg(csub.add_parser("init", help="mint this compactor's identity keyfile")).set_defaults(
        fn=cmd_init
    )
