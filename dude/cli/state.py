import argparse
import json
import signal
import threading
import time
from dataclasses import dataclass
from pathlib import Path

from ..consensus.canonical import bodies_canonical
from ..consensus.settle_round import SettledBlock
from ..core import codec, crypto
from ..core.errors import DudeError
from ..core.units import now_ms
from ..net.address import Address, Endpoint
from ..net.postman import Postman
from ..net.socket_server import SocketServer
from ..net.socket_substrate import SocketSubstrate
from ..net.transports.tcp import TCPDialer, TCPTiming
from ..node import ReplicaNode
from ..session import SessionRW
from ..store import Store, ops
from ..store.ops import SignedTransaction
from ..sync.lite_client import LightClient
from ..tunables import DEFAULT


class CLIError(DudeError): ...


KEYFILE = "identity.key"
STORE_DB = "store.sqlite"
BOOTSTRAP_SEED = "bootstrap.json"
GENESIS_DATA = "genesis.bin"
SOCKET = "dude.sock"


def ensure_dir(path: Path) -> Path:
    path.mkdir(parents=True, exist_ok=True)
    return path


def save_keypair(dir_path: Path, kp: crypto.Keypair) -> None:
    ensure_dir(dir_path)
    target = dir_path / KEYFILE
    if target.exists():
        raise CLIError(f"identity already exists: {target}")
    target.write_bytes(bytes(kp.seed))
    target.chmod(0o600)


def load_keypair(dir_path: Path) -> crypto.Keypair:
    target = dir_path / KEYFILE
    if not target.exists():
        raise CLIError(f"no identity at {target}; run init first")
    seed = crypto.Seed(target.read_bytes())
    return crypto.Keypair.from_seed(seed)


def store_path(dir_path: Path) -> str:
    return str(dir_path / STORE_DB)


def socket_path(dir_path: Path) -> str:
    return str(dir_path / SOCKET)


@dataclass(frozen=True, slots=True)
class BootstrapSeed:
    anchor: crypto.PublicKey
    peers: tuple[tuple[crypto.PublicKey, tuple[Endpoint, ...]], ...]

    def save(self, dir_path: Path) -> None:
        ensure_dir(dir_path)
        target = dir_path / BOOTSTRAP_SEED
        data = {
            "anchor": self.anchor.hex(),
            "peers": [
                {"pubkey": pk.hex(), "endpoints": [str(ep.address) for ep in eps]}
                for pk, eps in self.peers
            ],
        }
        target.write_text(json.dumps(data, indent=2))

    @classmethod
    def load(cls, dir_path: Path) -> "BootstrapSeed":
        target = dir_path / BOOTSTRAP_SEED
        if not target.exists():
            raise CLIError(f"no bootstrap seed at {target}")
        data = json.loads(target.read_text())
        anchor = crypto.PublicKey(bytes.fromhex(data["anchor"]))
        peers = tuple(
            (
                crypto.PublicKey(bytes.fromhex(p["pubkey"])),
                tuple(Endpoint(Address.parse(e.encode())) for e in p["endpoints"]),
            )
            for p in data["peers"]
        )
        return cls(anchor=anchor, peers=peers)


def save_genesis(
    dir_path: Path,
    block_bytes: bytes,
    bodies: tuple[SignedTransaction, ...],
) -> None:
    target = dir_path / GENESIS_DATA
    target.write_bytes(codec.encode([block_bytes, [tx.raw for tx in bodies]]))


def load_genesis(dir_path: Path) -> tuple[bytes, tuple[SignedTransaction, ...]]:
    target = dir_path / GENESIS_DATA
    if not target.exists():
        raise CLIError(f"no genesis data at {target}")
    outer = codec.as_seq(codec.decode(target.read_bytes()), 2)
    block_bytes = codec.as_bytes(outer[0])
    bodies = tuple(
        SignedTransaction.decode(codec.as_bytes(item)) for item in codec.as_seq(outer[1])
    )
    return block_bytes, bodies


def add_dir_arg(parser: argparse.ArgumentParser, **kwargs) -> None:
    parser.add_argument("--dir", type=Path, **kwargs)


def cmd_init(args: argparse.Namespace, label: str) -> None:
    dir_path: Path = args.dir
    kp = crypto.Keypair.generate()
    save_keypair(dir_path, kp)
    pop = kp.prove_possession()
    print(f"{label} identity created in {dir_path}")
    print(f"  public key: {kp.public.hex()}")
    print(f"  possession: {pop.hex()}")


def open_store_with_genesis(dir_path: Path) -> Store:
    seed = BootstrapSeed.load(dir_path)
    store = Store(store_path(dir_path))
    if store.head_block_num() is None:
        block_bytes, bodies = load_genesis(dir_path)
        store.provision(seed.anchor)
        sb = SettledBlock.decode(block_bytes)
        ordered = bodies_canonical(bodies).txs
        store.commit_block(
            sb.anchors.block_num,
            first_height=1,
            block_bytes=block_bytes,
            block_hash=sb.block_hash,
            batch=ordered,
            auth=store.mgmt_reader,
        )
        print(f"genesis block applied (block {sb.anchors.block_num})")
    return store


def start_replica(dir_path: Path) -> tuple[ReplicaNode, Store]:
    kp = load_keypair(dir_path)
    store = open_store_with_genesis(dir_path)
    timing = TCPTiming.for_deployment(DEFAULT)
    rn = ReplicaNode(kp, store, DEFAULT)
    rn.add_listener(TCPDialer(timing=timing))
    rn.start()
    return rn, store


def start_light_client(dir_path: Path) -> LightClient:
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
    print(f"bootstrapped at block {lc.trusted_state.head.anchors.block_num}")
    return lc


def serve_with_socket(label: str, dir_path: Path, sub, stop_fn) -> None:
    sock = socket_path(dir_path)
    server = SocketServer(sock, sub)
    server.start()
    print(f"{label} serving on {sock}")
    stop = threading.Event()
    signal.signal(signal.SIGINT, lambda *_: stop.set())
    signal.signal(signal.SIGTERM, lambda *_: stop.set())
    stop.wait()
    print("shutting down...")
    server.stop()
    stop_fn()


def connect_socket(
    dir_path: Path, store_id: int = ops.STORE_DATA
) -> tuple[SocketSubstrate, SessionRW]:
    sub = SocketSubstrate(socket_path(dir_path), DEFAULT)
    return sub, SessionRW(sub, store_id)
