# Shared CLI plumbing: exit codes, the worker-socket JSON-RPC round trip, and the
# manager's enveloped node probes (status / recover / roster-change drive I/O). No
# protocol logic lives here — that is the `manager.Manager` library; this is marshalling.

from __future__ import annotations

import json
import socket
import time

from .. import artifacts as A
from .. import lmsg, transports, wire
from ..artifacts import HLC
from ..link import Link
from ..manager import ManagerState
from ..node import FrontierReq, Request, Response

# ---- exit codes -------------------------------------------------------------- #
OK = 0
ERR = 1  # usage / runtime error (incl. ManagerError preconditions)
REFUSE_EXISTING = 2  # init over existing state
REFUSE_RECOVER = 3  # recover while a quorum answers (the load-bearing interlock)


def worker_call(sock_path: str, method: str, params: dict) -> dict:
    """One JSON-RPC 2.0 round trip against the client daemon's worker socket."""
    with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as s:
        s.settimeout(10.0)
        s.connect(sock_path)
        req = {"jsonrpc": "2.0", "id": 1, "method": method, "params": params}
        s.sendall((json.dumps(req) + "\n").encode())
        buf = b""
        while not buf.endswith(b"\n"):
            chunk = s.recv(4096)
            if not chunk:
                break
            buf += chunk
    resp = json.loads(buf)
    if "error" in resp:
        raise RuntimeError(f"{method} failed: {resp['error']['message']}")
    return resp["result"]


def mgr_send(
    st: ManagerState,
    to_pub: bytes,
    ep: transports.Endpoint | None,
    req: Request,
    timeout: float = 5.0,
) -> Response | None:
    """One enveloped node RPC as the ROOT manager (PROTOCOL §7.5): sign `req` from the
    manager identity to `to_pub` and Link it over the node's Endpoint (any carrier the
    ENDPOINT record named — the manager connects like everything else). The gate admits
    root, so the drive passes. None if the node has no known endpoint."""
    if ep is None:
        return None
    match Link(st.root_key, st.manager_pub, to_pub, ep).request(
        b"", wire.encode_request(req), epoch=st.epoch, ts=int(time.time() * 1000), timeout=timeout
    ):
        case lmsg.Reply(env):
            return wire.decode_response(env.body)
        case _fault:  # NoReply / MalformedReply / WrongPeer — the why is here to log later
            return None


def probe(
    st: ManagerState, pub: bytes, ep: transports.Endpoint | None, timeout: float = 1.0
) -> A.FrontierBundle | None:
    """A signed frontier read from node `pub` over its Endpoint, or None if unreachable."""
    resp = mgr_send(st, pub, ep, FrontierReq(), timeout)
    return resp if isinstance(resp, A.FrontierBundle) else None


def floor_probe(st: ManagerState):
    """A `probe(pub, endpoint) -> floor | None` bound to the manager identity, for
    probe_roster's dwell loop (the manager signs each FRONTIER read)."""

    def _p(pub: bytes, ep: transports.Endpoint) -> HLC | None:
        fb = probe(st, pub, ep)
        return fb.floor if fb is not None else None

    return _p


def node_rpc(st: ManagerState):
    """A `rpc(node_pub, req) -> Response | None` over the p2p wire — the manager's
    roster-change drive (findings 23/24) talks to nodes by pubkey, enveloped as root."""

    def _rpc(node_pub: bytes, req: Request) -> Response | None:
        return mgr_send(st, node_pub, st.dial(node_pub.hex()), req)

    return _rpc


def print_cert_inventory(st: ManagerState) -> None:
    # roster/rotate commands must show the live inventory first (MANAGER §3 / NOTES
    # 36c): rotation expires NO capability, so a distrust change needs explicit
    # revokes — put the list in front of the operator.
    print("cert inventory (rotation expires nothing — revoke explicitly to distrust):")
    if not st.certs:
        print("  (none)")
    for c in st.certs:
        flag = " REVOKED" if c["revoked"] else ""
        print(f"  {c['subject'][:16]}…  caps={','.join(c['caps'])}  epoch={c['epoch']}{flag}")


def print_minted(role: str, pub: bytes, keyfile: str, pop: bytes, *next_steps: str) -> None:
    """The shared `<role> init` report: the freshly-minted identity + how to authorize it."""
    print(f"minted {role} identity -> {keyfile}")
    print(f"  pub: {pub.hex()}")
    print(f"  pop: {pop.hex()}")
    for step in next_steps:
        print(f"  {step}")


# Back-compat alias: test_demo imports `_floor_probe` from dudefs.cli.
_floor_probe = floor_probe
