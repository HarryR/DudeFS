# `python3 -m dudefs` — the package entry point. Delegates to the `dude` CLI
# (dudefs.cli), which is the single command surface over the manager library and
# the client daemon's worker socket. No logic lives here: the module is a shim so
# the CLI is reachable without an installed console-script.

from __future__ import annotations

from .cli import main

if __name__ == "__main__":
    raise SystemExit(main())
