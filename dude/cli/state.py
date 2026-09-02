from __future__ import annotations

import json
import logging
import signal as _signal
import threading
from collections.abc import Generator
from contextlib import contextmanager
from dataclasses import dataclass
from pathlib import Path

from ..consensus.canonical import bodies_canonical
from ..consensus.settle_round import SettledBlock
from ..core import codec, crypto
from ..core.errors import DudeError
from ..net.address import Address, Endpoint
from ..store import Store
from ..store.ops import SignedTransaction

log = logging.getLogger(__name__)


class CLIError(DudeError): ...


KEYFILE = "identity.key"
ANCHOR_PUBKEY = "anchor.pub"
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


def save_anchor(dir_path: Path, anchor: crypto.PublicKey) -> None:
    ensure_dir(dir_path)
    target = dir_path / ANCHOR_PUBKEY
    target.write_bytes(bytes(anchor))


def load_anchor(dir_path: Path) -> crypto.PublicKey:
    target = dir_path / ANCHOR_PUBKEY
    if not target.exists():
        raise CLIError(f"no anchor pubkey at {target}; run 'node init --anchor' first")
    return crypto.PublicKey(target.read_bytes())


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
    def load(cls, dir_path: Path) -> BootstrapSeed:
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
        log.info("genesis block applied (block %d)", sb.anchors.block_num)
    return store


@contextmanager
def until_terminated() -> Generator[threading.Event]:
    stop = threading.Event()
    prev_int = _signal.signal(_signal.SIGINT, lambda *_: stop.set())
    prev_term = _signal.signal(_signal.SIGTERM, lambda *_: stop.set())
    try:
        yield stop
        stop.wait()
    finally:
        _signal.signal(_signal.SIGINT, prev_int)
        _signal.signal(_signal.SIGTERM, prev_term)
