import argparse
import signal
import threading
import time
from pathlib import Path

from ..consensus.canonical import bodies_canonical
from ..consensus.settle_round import SettledBlock
from ..core import crypto
from ..core.units import now_ms
from ..net.address import Address, Scheme
from ..net.postman import Postman
from ..net.transports.tcp import TCPDialer, TCPListener, TCPTiming
from ..node import ReplicaNode
from ..session import Settled
from ..store import Store
from ..store.checkpoint import CheckpointMeta
from ..store.management import GRANTS_MAP, Cert, Grant, MgmtReader, Role
from ..sync.checkpoint_server import CheckpointServer
from ..sync.lite_client import LightClient
from ..tunables import DEFAULT
from .state import (
    BootstrapSeed,
    CLIError,
    load_genesis,
    load_keypair,
    save_keypair,
    store_path,
)


def register(sub: argparse._SubParsersAction) -> None:
    comp = sub.add_parser("compactor", aliases=["c"], help="compactor commands")
    comp_sub = comp.add_subparsers(dest="compactor_command")

    init = comp_sub.add_parser("init", help="mint compactor identity")
    init.add_argument("--dir", type=Path, required=True, help="compactor home directory")
    init.set_defaults(func=cmd_init)

    run = comp_sub.add_parser("run", help="one-shot compaction (light client)")
    run.add_argument("--dir", type=Path, required=True, help="compactor home directory")
    run.set_defaults(func=cmd_run)

    serve = comp_sub.add_parser("serve", help="run persistent compactor (replica node)")
    serve.add_argument("--dir", type=Path, required=True, help="compactor home directory")
    serve.add_argument("--listen", default=None, help="listen address")
    serve.add_argument(
        "--interval", type=int, default=86400,
        help="seconds between compaction runs (default: 86400)",
    )
    serve.set_defaults(func=cmd_serve)

    comp.set_defaults(func=lambda _args: comp.print_help())


def cmd_init(args: argparse.Namespace) -> None:
    dir_path: Path = args.dir
    kp = crypto.Keypair.generate()
    save_keypair(dir_path, kp)
    pop = kp.prove_possession()
    print(f"compactor identity created in {dir_path}")
    print(f"  public key: {kp.public.hex()}")
    print(f"  possession: {pop.hex()}")


def cmd_run(args: argparse.Namespace) -> None:
    dir_path: Path = args.dir
    kp = load_keypair(dir_path)
    seed = BootstrapSeed.load(dir_path)

    timing = TCPTiming.for_deployment(DEFAULT)
    postman = Postman(kp, DEFAULT)
    postman.add_listener(TCPDialer(timing=timing))
    lc = LightClient(me=kp, anchor=seed.anchor, postman=postman)
    for pub, endpoints in seed.peers:
        lc.add_bootstrap_peer(pub, endpoints)
    lc.start()
    lc.bootstrap(now_ms())

    print("bootstrapping...")
    deadline = time.monotonic() + 30.0
    while not lc.bootstrapped() and time.monotonic() < deadline:
        time.sleep(0.1)
    if not lc.bootstrapped():
        lc.stop()
        raise CLIError("failed to bootstrap within 30s")

    head = lc.trusted_state.head
    block_num = head.anchors.block_num
    print(f"bootstrapped at block {block_num}")

    s = lc.session()
    result = s.compact(block_num).wait()
    if not isinstance(result, Settled):
        lc.stop()
        raise CLIError(f"compact transaction did not settle: {result!r}")

    print(f"compaction pivot at block {block_num} settled")

    mgmt_s = lc.session(store_id=0)
    grant_cert = _find_grant_cert(mgmt_s, kp)
    meta = CheckpointMeta.create(
        settled_block_bytes=head.encode(),
        anchor=seed.anchor,
        compactor=kp,
        grant_cert=grant_cert,
    )
    meta_path = dir_path / "checkpoint_meta.bin"
    meta_path.write_bytes(meta.encode())
    print(f"checkpoint metadata written to {meta_path}")

    lc.stop()
    print("done")


def _find_grant_cert(mgmt_session, kp: crypto.Keypair) -> Cert:
    rec = mgmt_session.get(GRANTS_MAP.entry_name(kp.public))
    if rec.absent:
        raise CLIError("compactor grant not found in management store")
    grant = Grant.decode_row(kp.public, rec.value)
    if grant.role is not Role.COMPACTOR:
        raise CLIError(f"grant role is {grant.role.name}, not COMPACTOR")
    return grant.cert


def cmd_serve(args: argparse.Namespace) -> None:
    dir_path: Path = args.dir
    kp = load_keypair(dir_path)
    seed = BootstrapSeed.load(dir_path)
    db_path = store_path(dir_path)
    interval = args.interval

    store = Store(db_path)

    if store.head_block_num() is None:
        block_bytes, bodies = load_genesis(dir_path)
        store.provision(seed.anchor)
        sb = SettledBlock.decode(block_bytes)
        ordered = bodies_canonical(bodies).txs
        mgmt = MgmtReader(store)
        store.commit_block(
            sb.anchors.block_num,
            first_height=1,
            block_bytes=block_bytes,
            block_hash=sb.block_hash,
            batch=ordered,
            auth=mgmt,
        )
        print(f"genesis block applied (block {sb.anchors.block_num})")

    timing = TCPTiming.for_deployment(DEFAULT)
    rn = ReplicaNode(kp, store, DEFAULT)

    if args.listen:
        addr = Address.parse(args.listen.encode())
        if addr.scheme is Scheme.TCP:
            host, _, port_s = addr.value.partition(":")
            listener = TCPListener(
                listen_host=host, listen_port=int(port_s), timing=timing,
            )
            rn.add_listener(listener)
            print(f"listening on {listener.bound_address}")
    else:
        listener = TCPListener(timing=timing)
        rn.add_listener(listener)
        print(f"listening on {listener.bound_address}")

    rn.add_listener(TCPDialer(timing=timing))
    rn.start()
    print(f"compactor {kp.public.hex()[:16]}... running (interval={interval}s)")

    stop = threading.Event()
    signal.signal(signal.SIGINT, lambda *_: stop.set())
    signal.signal(signal.SIGTERM, lambda *_: stop.set())

    while not stop.is_set():
        _run_compaction_cycle(rn, kp, seed.anchor)
        stop.wait(timeout=interval)

    print("shutting down...")
    rn.stop()
    store.close()


def _run_compaction_cycle(
    rn: ReplicaNode, kp: crypto.Keypair, anchor: crypto.PublicKey,
) -> None:
    head_num = rn.store.head_block_num()
    if head_num is None or head_num < 2:
        return

    s = rn.session()
    result = s.compact(head_num).wait()
    if not isinstance(result, Settled):
        print(f"compact did not settle: {result!r}")
        return

    print(f"pivot at block {head_num} settled")

    grant_cert = _find_grant_cert_from_store(rn.store, kp)
    with rn.store.snapshot() as reader:
        sb_bytes = reader.settled_at(reader.head_block_num())
        meta = CheckpointMeta.create(
            settled_block_bytes=sb_bytes,
            anchor=anchor,
            compactor=kp,
            grant_cert=grant_cert,
        )

    srv = CheckpointServer.create_and_persist(rn.store, meta)
    rn.checkpoint_server = srv
    print(f"checkpoint persisted ({rn.store.checkpoint_chunk_count()} chunks)")


def _find_grant_cert_from_store(store: Store, kp: crypto.Keypair) -> Cert:
    held = store.get(0, GRANTS_MAP.entry_name(kp.public))
    if held is None:
        raise CLIError("compactor grant not found")
    grant = Grant.decode_row(kp.public, held.value)
    return grant.cert
