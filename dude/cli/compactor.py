import argparse
import signal
import threading
from pathlib import Path

from ..core import crypto
from ..session import Settled
from ..store import ops
from ..store.checkpoint import CheckpointMeta
from ..store.management import Cert, MgmtWriter
from ..sync.checkpoint_server import CheckpointServer
from .state import (
    CLIError,
    add_dir_arg,
    cmd_init,
    load_keypair,
    start_light_client,
    start_replica,
)


def register(sub: argparse._SubParsersAction) -> None:
    comp = sub.add_parser("compactor", aliases=["c"], help="compactor commands")
    comp_sub = comp.add_subparsers(dest="compactor_command")

    init = comp_sub.add_parser("init", help="mint compactor identity")
    add_dir_arg(init, required=True, help="compactor home directory")
    init.set_defaults(func=lambda args: cmd_init(args, "compactor"))

    run = comp_sub.add_parser("run", help="one-shot compaction (light client)")
    add_dir_arg(run, required=True, help="compactor home directory")
    run.set_defaults(func=cmd_run)

    serve = comp_sub.add_parser("serve", help="run persistent compactor (replica node)")
    add_dir_arg(serve, required=True, help="compactor home directory")
    serve.add_argument(
        "--interval",
        type=int,
        default=86400,
        help="seconds between compaction runs (default: 86400)",
    )
    serve.set_defaults(func=cmd_serve)

    comp.set_defaults(func=lambda _args: comp.print_help())


def cmd_run(args: argparse.Namespace) -> None:
    dir_path: Path = args.dir
    lc = start_light_client(dir_path)

    head = lc.trusted_state.head
    block_num = head.anchors.block_num

    s = lc.session(store_id=ops.STORE_MANAGEMENT)
    result = s.submit(MgmtWriter(s).compact(block_num)).wait()
    if not isinstance(result, Settled):
        lc.stop()
        raise CLIError(f"compact transaction did not settle: {result!r}")

    print(f"compaction pivot at block {block_num} settled")
    lc.stop()
    print("done")


def cmd_serve(args: argparse.Namespace) -> None:
    dir_path: Path = args.dir
    interval = args.interval
    rn, store = start_replica(dir_path)
    kp = load_keypair(dir_path)

    print(f"compactor {kp.public.hex()[:16]}... running (interval={interval}s)")

    stop = threading.Event()
    signal.signal(signal.SIGINT, lambda *_: stop.set())
    signal.signal(signal.SIGTERM, lambda *_: stop.set())

    while not stop.is_set():
        _run_compaction_cycle(rn, kp)
        stop.wait(timeout=interval)

    print("shutting down...")
    rn.stop()
    store.close()


def _run_compaction_cycle(rn, kp: crypto.Keypair) -> None:
    head_num = rn.store.head_block_num()
    if head_num is None or head_num < 2:
        return

    s = rn.session(store_id=ops.STORE_MANAGEMENT)
    result = s.submit(MgmtWriter(s).compact(head_num)).wait()
    if not isinstance(result, Settled):
        print(f"compact did not settle: {result!r}")
        return

    print(f"pivot at block {head_num} settled")

    grant_cert = _find_grant_cert_from_store(rn.store, kp)
    with rn.store.snapshot() as reader:
        sb_bytes = reader.settled_at(reader.head_block_num())
        meta = CheckpointMeta.create(
            settled_block_bytes=sb_bytes,
            anchor=rn.store.anchor(),
            compactor=kp,
            grant_cert=grant_cert,
        )

    srv = CheckpointServer.create_and_persist(rn.store, meta)
    rn.checkpoint_server = srv
    print(f"checkpoint persisted ({rn.store.checkpoint_chunk_count()} chunks)")


def _find_grant_cert_from_store(store, kp: crypto.Keypair) -> Cert:
    grant = store.mgmt_reader.grant_of(kp.public)
    if grant is None:
        raise CLIError("compactor grant not found")
    return grant.cert
