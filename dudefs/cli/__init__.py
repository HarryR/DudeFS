# The `dude` CLI (MANAGER.md / CLI.md). A THIN parse-and-delegate shell: manager verbs
# call the tested `manager.Manager` library (which owns every delicate, protocol-specific
# decision), and client verbs pass through to a running client daemon's JSON-RPC worker
# socket. Any programmatic automation calls the same libraries — the logic is never
# CLI-only. No stubs (NOTES 51): every wired subcommand is implemented and reviewed.
#
# Organised by TOP-LEVEL verb (one module per command noun): `mgr` (control plane +
# authority over subjects), `client` (worker verbs), `main` (tree assembly + dispatch).
# This package re-exports the stable entry points so `from dudefs.cli import …` and
# `python -m dudefs` are unaffected as the tree grows.

from __future__ import annotations

from ..manager import ManagerState
from ._util import _floor_probe
from .main import build_parser, main

__all__ = ["ManagerState", "_floor_probe", "build_parser", "main"]
