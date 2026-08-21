import json
from dataclasses import dataclass
from pathlib import Path

from ..core import codec, crypto
from ..core.errors import DudeError
from ..net.address import Address, Endpoint
from ..store.ops import SignedTransaction


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
