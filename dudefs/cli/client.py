# `client` — the client running itself: worker verbs that pass through to a running
# `client serve` daemon's JSON-RPC socket. (init/serve land in Phase 3.) The four
# hot verbs are also mounted at the TOP LEVEL (`dude get/set/cas/del`) dialing
# $DUDE_SOCK, since they are what an operator types constantly.

from __future__ import annotations

import argparse

from . import _util as U
from ._args import sock_arg


def cmd_set(args: argparse.Namespace) -> int:
    r = U.worker_call(args.sock, "PUT", {"path": args.path, "value": args.value})
    print(f"submitted {r['op']}")
    return U.OK


def cmd_get(args: argparse.Namespace) -> int:
    r = U.worker_call(args.sock, "GET", {"path": args.path, "level": args.level})
    if not r["present"]:
        print(f"{args.path}: (absent)")
        return U.OK
    print(f"{args.path} = {r['value']!r}  [tier={r['tier']} version={r['version']}]")
    return U.OK


def cmd_cas(args: argparse.Namespace) -> int:
    expect: object = "absent" if args.expect in (None, "absent") else {"version": args.expect}
    params = {
        "path": args.path,
        "expect": expect,
        "mutations": [{"set": args.path, "value": args.value}],
    }
    r = U.worker_call(args.sock, "CAS", params)
    print(f"submitted {r['op']}")
    return U.OK


def cmd_del(args: argparse.Namespace) -> int:
    r = U.worker_call(args.sock, "TXN", {"slot": None, "mutations": [{"del": args.path}]})
    print(f"submitted {r['op']}")
    return U.OK


def cmd_wheres(args: argparse.Namespace) -> int:
    """Human `where is my thing`: joins args with `/` and renders INSPECT for people
    (present/value, tier + finality, fencing token, pending ops with intent)."""
    path = "/".join(args.words)
    r = U.worker_call(args.sock, "INSPECT", {"path": path})
    prov, fin = r["provisional"], r["final"]
    print(f"where is {path}:")
    if prov["present"]:
        frozen = fin["present"] and fin["version"] == prov["version"]
        finality = (
            "final (frozen)"
            if frozen
            else ("provisional, may flip" if r["may_flip"] else "provisional")
        )
        print(f"  value: {prov['value']!r}   finality: {finality}")
        print(f"  fence: version={prov['version']} attempt={prov['attempt']}")
    else:
        print("  value: (absent)" + ("  may still flip" if r["may_flip"] else ""))
    if r["pending"]:
        print("  pending ops:")
        for e in r["pending"]:
            print(f"    {e['op'][:12]}…  {e['phase']:<10}  would {', '.join(e['would'])}")
    else:
        print("  no pending ops")
    return U.OK


# --------------------------------------------------------------------------- #
# argparse wiring — mounted twice: under `client` and (the hot four) top-level #
# --------------------------------------------------------------------------- #
def _worker_leaves(sub, *, top: bool) -> None:
    """Attach the worker verbs to `sub`. `top` = the top-level mount (only get/set/cas/del)."""
    setp = sock_arg(sub.add_parser("set", help="PUT a value"))
    setp.add_argument("path")
    setp.add_argument("value")
    setp.set_defaults(fn=cmd_set)
    getp = sock_arg(sub.add_parser("get", help="GET a value"))
    getp.add_argument("path")
    getp.add_argument("--level", choices=["local", "final"], default="local")
    getp.set_defaults(fn=cmd_get)
    casp = sock_arg(sub.add_parser("cas", help="guarded write"))
    casp.add_argument("path")
    casp.add_argument("value")
    casp.add_argument("--expect", default="absent", help="expected version (hex), or 'absent'")
    casp.set_defaults(fn=cmd_cas)
    delp = sock_arg(sub.add_parser("del", help="delete a key"))
    delp.add_argument("path")
    delp.set_defaults(fn=cmd_del)
    if top:
        return
    wp = sock_arg(sub.add_parser("wheres", help="human key-status renderer (INSPECT)"))
    wp.add_argument("words", nargs="+")
    wp.set_defaults(fn=cmd_wheres)


def register(sub: argparse._SubParsersAction) -> None:
    client = sub.add_parser("client", help="client worker verbs (dial a running `client serve`)")
    _worker_leaves(client.add_subparsers(dest="client_verb", required=True), top=False)
    _worker_leaves(sub, top=True)  # top-level get/set/cas/del shortcuts
