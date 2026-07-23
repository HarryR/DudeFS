# The `dude` entry point: assemble the command tree by asking each top-level verb group
# to register itself, then dispatch on the resolved `fn`. One file per top-level verb
# (mgr / client / …); this module only wires them together.

from __future__ import annotations

import argparse
import sys

from ..manager import ManagerError
from . import client, mgr
from ._util import ERR


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(prog="dude", description="DudeFS control + client CLI")
    sub = p.add_subparsers(dest="cmd", required=True)
    mgr.register(sub)
    client.register(sub)
    return p


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    fn = getattr(args, "fn", None)
    if fn is None:
        print("no command", file=sys.stderr)
        return ERR
    try:
        return fn(args)
    except (ManagerError, RuntimeError, OSError, KeyError, ValueError) as e:
        print(f"error: {e}", file=sys.stderr)
        return ERR
