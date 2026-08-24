import argparse
import sys

from . import client, compactor, mgr, node


def main(argv: list[str] | None = None) -> None:
    p = argparse.ArgumentParser(prog="dude", description="DudeFS cluster management")
    sub = p.add_subparsers(dest="command")

    mgr.register(sub)
    node.register(sub)
    client.register(sub)
    compactor.register(sub)

    args = p.parse_args(argv)
    if args.command is None:
        p.print_help()
        sys.exit(1)

    args.func(args)
