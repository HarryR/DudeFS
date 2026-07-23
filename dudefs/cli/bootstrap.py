# bootstrap.json — the non-secret projection a daemon needs to cold-start: the trust
# anchor (`manager_pub`), the current `epoch`, the roster (pubkey + dial endpoint per
# voting node), and the authorization chain (control ops as hex). NEVER carries a master
# or a private key. `mgr bootstrap` emits it; `<role> serve` reads it from its --dir.

from __future__ import annotations

import json
import os

from .. import transports
from ..artifacts import Op
from ..manager import ManagerState

BOOTSTRAP = "bootstrap.json"


def _ep_json(ep: transports.Endpoint | None) -> dict | None:
    if ep is None:
        return None
    return {"transport": ep.transport.decode(), "uri": ep.uri, "sealed": ep.sealed}


def _ep_from_json(j: dict | None) -> transports.Endpoint | None:
    if j is None:
        return None
    return transports.Endpoint(j["transport"].encode(), j["uri"], j["sealed"])


def emit(st: ManagerState) -> dict:
    """The non-secret cold-start projection of the manager state."""
    with st.store.read_txn() as tx:
        control_ops = [o.raw.hex() for o in sorted(tx.all_ops(), key=lambda o: o.seq)]
    roster = [{"pub": p.hex(), "ep": _ep_json(st.dial(p.hex()))} for p in st.roster]
    return {
        "manager_pub": st.manager_pub.hex(),
        "epoch": st.epoch,
        "roster": roster,
        "control_ops": control_ops,
    }


class Bootstrap:
    """A parsed bootstrap.json — the cold-start inputs a `serve` shell hands to a daemon."""

    def __init__(self, raw: dict):
        self.manager_pub = bytes.fromhex(raw["manager_pub"])
        self.epoch = int(raw["epoch"])
        self.roster = [bytes.fromhex(r["pub"]) for r in raw["roster"]]
        self.roster_addrs = [_ep_from_json(r.get("ep")) for r in raw["roster"]]
        self.control_ops = [Op.from_bytes(bytes.fromhex(h)) for h in raw["control_ops"]]

    @classmethod
    def read(cls, d: str) -> Bootstrap:
        path = os.path.join(d, BOOTSTRAP)
        if not os.path.exists(path):
            raise FileNotFoundError(f"no {BOOTSTRAP} in {d} (emit it with `dude mgr bootstrap`)")
        with open(path) as f:
            return cls(json.load(f))

    def dial_addrs(self) -> list[transports.Endpoint]:
        """The roster dial endpoints, in roster order (a missing one is a placeholder that
        simply never answers — the daemon tolerates an unreachable peer)."""
        placeholder = transports.Endpoint(transports.UNIX, "/nonexistent.sock")
        return [ep or placeholder for ep in self.roster_addrs]
