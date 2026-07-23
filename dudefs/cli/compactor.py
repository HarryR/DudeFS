# `compactor` — the compaction daemon running itself. `init` mints its identity; `once`/`run`
# drive real checkpoints (R6 WP-G) from --dir + bootstrap.json; `status` is a local store read.
# Manager AUTHORITY over compactors (authorize/revoke) lives in cli/mgr.py.

from __future__ import annotations

import argparse
import os

from .. import crypto as C
from ..compactor_daemon import CompactorDaemon
from ..manager import mint_identity
from . import _util as U
from ._args import dir_arg
from .bootstrap import Bootstrap


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


def _daemon(args: argparse.Namespace) -> CompactorDaemon:
    with open(os.path.join(args.dir, "compactor.key"), "rb") as f:
        sk = f.read()
    b = Bootstrap.read(args.dir)
    return CompactorDaemon(
        sk,
        C.SIGNER.public(sk),
        roster=b.roster,
        roster_addrs=b.dial_addrs(),
        manager_pub=b.manager_pub,
        control_ops=b.control_ops,
        store_path=os.path.join(args.dir, "store.sqlite"),
        epoch=b.epoch,
    )


def cmd_once(args: argparse.Namespace) -> int:
    comp = _daemon(args)
    try:
        ck = comp.compact_once()
    finally:
        comp.close()
    print(f"checkpoint committed: {ck.hex()}" if ck else "no checkpoint (nothing final to seal)")
    return U.OK


def cmd_run(args: argparse.Namespace) -> int:
    comp = _daemon(args)
    print(f"compactor {comp.pub.hex()[:16]}… running (interval {args.interval}s)")
    try:
        comp.run(args.interval)
    except KeyboardInterrupt:
        pass
    finally:
        comp.close()
    return U.OK


def cmd_status(args: argparse.Namespace) -> int:
    s = U.store_stats(args.dir)
    print(f"compactor  ops held: {s['ops']}   cut: {'set' if s['cut'] else 'none'}")
    return U.OK


def register(sub: argparse._SubParsersAction) -> None:
    c = sub.add_parser("compactor", help="run the compaction daemon")
    csub = c.add_subparsers(dest="compactor_verb", required=True)
    dir_arg(csub.add_parser("init", help="mint this compactor's identity keyfile")).set_defaults(
        fn=cmd_init
    )
    dir_arg(csub.add_parser("once", help="drive a single compaction pass")).set_defaults(
        fn=cmd_once
    )
    run = dir_arg(csub.add_parser("run", help="drive compaction continuously"))
    run.add_argument("--interval", type=float, default=300.0, help="seconds between passes")
    run.set_defaults(fn=cmd_run)
    dir_arg(csub.add_parser("status", help="local view from the durable store")).set_defaults(
        fn=cmd_status
    )
