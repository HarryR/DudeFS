# Reusable argparse fragments + env defaults, hoisted so every verb group reuses the
# same `--dir` / `--sock` / positional shapes (no per-parser drift). Kept tiny on
# purpose — extract more here as duplication appears across the growing verb tree.

from __future__ import annotations

import argparse
import os


def dir_default() -> str:
    return os.environ.get("DUDE_DIR", ".dude")


def sock_default() -> str:
    return os.environ.get("DUDE_SOCK", "worker.sock")


def dir_arg(sp: argparse.ArgumentParser) -> argparse.ArgumentParser:
    """The manager home. Carried by every `mgr` leaf so it may follow the subcommand."""
    sp.add_argument("--dir", default=dir_default())
    return sp


def sock_arg(sp: argparse.ArgumentParser) -> argparse.ArgumentParser:
    """The client worker socket (client/top-level verbs dial it)."""
    sp.add_argument("--sock", default=sock_default())
    return sp


def pubkey(sp: argparse.ArgumentParser, name: str = "pubkey") -> argparse.ArgumentParser:
    sp.add_argument(name, help="hex pubkey")
    return sp


def pop(sp: argparse.ArgumentParser) -> argparse.ArgumentParser:
    sp.add_argument("pop", help="subject's proof-of-possession (from `<role> init`)")
    return sp
