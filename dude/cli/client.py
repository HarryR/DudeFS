import argparse
import sys
from pathlib import Path

from ..session import Settled
from ..sync.lite_client import _LiteSubstrate
from .state import (
    CLIError,
    add_dir_arg,
    cmd_init,
    connect_socket,
    serve_with_socket,
    start_light_client,
)


def register(sub: argparse._SubParsersAction) -> None:
    client = sub.add_parser("client", help="client commands")
    client_sub = client.add_subparsers(dest="client_command")

    init = client_sub.add_parser("init", help="mint client identity")
    add_dir_arg(init, required=True, help="client home directory")
    init.set_defaults(func=lambda args: cmd_init(args, "client"))

    serve = client_sub.add_parser("serve", help="run the client daemon")
    add_dir_arg(serve, required=True, help="client home directory")
    serve.set_defaults(func=cmd_serve)

    get = client_sub.add_parser("get", help="read a key")
    add_dir_arg(get, required=True)
    get.add_argument("key", help="key name")
    get.set_defaults(func=cmd_get)

    put = client_sub.add_parser("put", help="write a key")
    add_dir_arg(put, required=True)
    put.add_argument("key", help="key name")
    put.add_argument("value", help="value (bytes)")
    put.set_defaults(func=cmd_put)

    delete = client_sub.add_parser("del", help="delete a key")
    add_dir_arg(delete, required=True)
    delete.add_argument("key", help="key name")
    delete.set_defaults(func=cmd_del)

    client.set_defaults(func=lambda _args: client.print_help())


def cmd_serve(args: argparse.Namespace) -> None:
    dir_path: Path = args.dir
    lc = start_light_client(dir_path)
    sub = _LiteSubstrate(lc)
    label = f"client {lc.me.public.hex()[:16]}..."
    serve_with_socket(label, dir_path, sub, lc.stop)


def cmd_get(args: argparse.Namespace) -> None:
    sub, session = connect_socket(args.dir)
    try:
        rec = session.get(args.key)
        if rec.absent:
            print(f"{args.key}: not found")
            sys.exit(1)
        sys.stdout.buffer.write(rec.value)
        sys.stdout.buffer.write(b"\n")
    finally:
        sub.close()


def cmd_put(args: argparse.Namespace) -> None:
    sub, session = connect_socket(args.dir)
    try:
        result = session.put(args.key, args.value.encode()).wait()
        if not isinstance(result, Settled):
            raise CLIError(f"put failed: {result!r}")
        print(f"{args.key}: written (block {result.block_num})")
    finally:
        sub.close()


def cmd_del(args: argparse.Namespace) -> None:
    sub, session = connect_socket(args.dir)
    try:
        result = session.delete(args.key).wait()
        if not isinstance(result, Settled):
            raise CLIError(f"delete failed: {result!r}")
        print(f"{args.key}: deleted (block {result.block_num})")
    finally:
        sub.close()
