# DudeFS — the `dude` CLI (M7 WP3, MANAGER.md). A THIN parse-and-delegate shell:
# manager verbs call the tested `manager.Manager` library (which owns all the
# delicate, protocol-specific logic — authoring control ops, revoke→rotate staging,
# wrap-sets, roster validation, the recovery interlock decision + fence authoring),
# and client verbs pass through to a running client daemon's JSON-RPC worker socket.
# Any programmatic automation calls the same libraries — the logic is never CLI-only.
#
# The CLI's own job is argparse, socket probing (status/recover I/O), human
# formatting (the `wheres` renderer), and mapping ManagerError/decisions to exit
# codes. No stubs (NOTES 51): every subcommand is implemented and reviewed.

from __future__ import annotations

import argparse
import json
import os
import socket
import sys
import time

from . import artifacts as A
from . import lmsg, transports, wire
from .artifacts import HLC, quorum_size
from .link import Link
from .manager import Manager, ManagerError, ManagerState, RecoverDecision, recover_decision
from .node import FrontierReq, Request, Response

# ---- exit codes -------------------------------------------------------------- #
OK = 0
ERR = 1  # usage / runtime error (incl. ManagerError preconditions)
REFUSE_EXISTING = 2  # init over existing state
REFUSE_RECOVER = 3  # recover while a quorum answers (the load-bearing interlock)


# --------------------------------------------------------------------------- #
# Worker-socket passthrough (client verbs -> the daemon's JSON-RPC)            #
# --------------------------------------------------------------------------- #


def _worker_call(sock_path: str, method: str, params: dict) -> dict:
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


# --------------------------------------------------------------------------- #
# Node probes (status / recover reachability, over the p2p wire)              #
# --------------------------------------------------------------------------- #


def _mgr_send(
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


def _probe(
    st: ManagerState, pub: bytes, ep: transports.Endpoint | None, timeout: float = 1.0
) -> A.FrontierBundle | None:
    """A signed frontier read from node `pub` over its Endpoint, or None if unreachable."""
    resp = _mgr_send(st, pub, ep, FrontierReq(), timeout)
    return resp if isinstance(resp, A.FrontierBundle) else None


def _floor_probe(st: ManagerState):
    """A `probe(pub, endpoint) -> floor | None` bound to the manager identity, for
    probe_roster's dwell loop (the manager signs each FRONTIER read)."""

    def probe(pub: bytes, ep: transports.Endpoint) -> HLC | None:
        fb = _probe(st, pub, ep)
        return fb.floor if fb is not None else None

    return probe


def _node_rpc(st: ManagerState):
    """A `rpc(node_pub, req) -> Response | None` over the p2p wire — the manager's
    roster-change drive (findings 23/24) talks to nodes by pubkey, enveloped as root."""

    def rpc(node_pub: bytes, req: Request) -> Response | None:
        return _mgr_send(st, node_pub, st.node_addrs.get(node_pub.hex()), req)

    return rpc


def _print_cert_inventory(st: ManagerState) -> None:
    # roster/rotate commands must show the live inventory first (MANAGER §3 / NOTES
    # 36c): rotation expires NO capability, so a distrust change needs explicit
    # revokes — put the list in front of the operator.
    print("cert inventory (rotation expires nothing — revoke explicitly to distrust):")
    if not st.certs:
        print("  (none)")
    for c in st.certs:
        flag = " REVOKED" if c["revoked"] else ""
        print(f"  {c['subject'][:16]}…  caps={','.join(c['caps'])}  epoch={c['epoch']}{flag}")


# --------------------------------------------------------------------------- #
# Commands — manager (thin wrappers over Manager)                              #
# --------------------------------------------------------------------------- #


def cmd_init(args: argparse.Namespace) -> int:
    try:
        m = Manager.init(args.dir, node_addr=args.node_addr)
    except ManagerError as e:
        print(f"refusing: {e}", file=sys.stderr)
        return REFUSE_EXISTING
    print(f"initialized dudefs at {args.dir}")
    print(f"  manager (root): {m.state.manager_pub.hex()}")
    print(f"  node0:          {m.state.roster[0].hex()}")
    return OK


def cmd_cert_issue(args: argparse.Namespace) -> int:
    m = Manager.load(args.dir)
    try:
        op = m.cert_issue(args.kind, bytes.fromhex(args.pubkey), bytes.fromhex(args.pop))
    except ManagerError as e:
        print(f"refusing: {e}", file=sys.stderr)
        return ERR
    caps = ", ".join(m.state.certs[-1]["caps"])
    print(f"issued {args.kind} cert to {args.pubkey} (caps: {caps})")
    print(f"  control op: {op.op_hash.hex()}")
    return OK


def cmd_cert_revoke(args: argparse.Namespace) -> int:
    m = Manager.load(args.dir)
    subject = bytes.fromhex(args.fingerprint)
    ops = m.cert_revoke(subject, rotate=not args.no_rotate)
    print(f"revoked {args.fingerprint}")
    print(f"  revoke op: {ops[0].op_hash.hex()}")
    if args.no_rotate:
        print("  WARNING: --no-rotate given; the revoked key still opens the current group key")
        print("           until you `dude rotate` (revocation without rotation is a foot-gun)")
        return OK
    print(f"  staged rotate -> keyepoch {m.state.keyepoch}: wrap-set {ops[1].op_hash.hex()}")
    return OK


def cmd_rotate(args: argparse.Namespace) -> int:
    m = Manager.load(args.dir)
    _print_cert_inventory(m.state)
    ops = m.rotate()
    n_members = len(m.state.members())
    print(f"rotated to keyepoch {m.state.keyepoch}: sealed group key to {n_members} member(s)")
    print(f"  wrap-set op: {ops[0].op_hash.hex()}   rotate op: {ops[1].op_hash.hex()}")
    return OK


def cmd_node(args: argparse.Namespace) -> int:
    m = Manager.load(args.dir)
    try:
        if args.node_cmd == "spawn":
            pub, keyfile, pop = m.node_spawn()
            print(f"spawned node identity {pub.hex()} (key: {keyfile})")
            print(f"  add it as a learner:  dude node add {pub.hex()} --addr <endpoint>")
            print(f"  then certify it:      dude cert issue node {pub.hex()} --pop {pop.hex()}")
            return OK
        if args.node_cmd == "add":
            pub = bytes.fromhex(args.pubkey)
            m.node_add(pub, args.addr)
            print(f"added learner {pub.hex()} (promote it once it has caught up)")
            return OK
        if args.node_cmd == "promote":
            _print_cert_inventory(m.state)
            change = m.node_promote(bytes.fromhex(args.pubkey), _node_rpc(m.state))
            size = len(m.state.roster)
            print(f"promoted {args.pubkey} -> epoch {m.state.epoch}, roster size {size}")
            print(f"  roster op:  {change.op.op_hash.hex()} (on the public roster slot)")
            print("  joint certificate: old-roster QC + possession-gated new-roster QC")
            return OK
    except ManagerError as e:
        print(f"refusing: {e}", file=sys.stderr)
        return ERR
    print(f"unknown node subcommand {args.node_cmd!r}", file=sys.stderr)
    return ERR


def cmd_status(args: argparse.Namespace) -> int:
    st = ManagerState.load(args.dir)
    print(f"epoch {st.epoch}  keyepoch {st.keyepoch}  roster {len(st.roster)} voting")
    frontier = A.HLC(0, 0)
    reachable = 0
    for i, pub in enumerate(st.roster):
        fb = _probe(st, pub, st.node_addrs.get(pub.hex()))
        if fb is None:
            print(f"  node{i} {pub.hex()[:16]}…  UNREACHABLE")
            continue
        reachable += 1
        frontier = max(frontier, fb.floor, key=lambda h: h.as_tuple())
        print(f"  node{i} {pub.hex()[:16]}…  floor={fb.floor.as_tuple()}  epoch={fb.config_epoch}")
    print(f"reachable: {reachable}/{len(st.roster)} (quorum {quorum_size(len(st.roster))})")
    print(f"finality frontier (max attested floor): {frontier.as_tuple()}")
    return OK


def cmd_recover(args: argparse.Namespace) -> int:
    """A thin wrapper: probe the roster (I/O here), then let the LIBRARY's pure
    `recover_decision` rule the interlock and author the fence. The delicate
    decision is tested directly in test_manager, not just through this path."""
    m = Manager.load(args.dir)
    print(f"recovery reachability probe — dwell {args.dwell}s over {len(m.state.roster)} endpoints")
    print("(a parked system is SAFE; recovery is never urgent, and dwell is free.)")
    report = m.probe_roster(_floor_probe(m.state), args.dwell, time.sleep)
    print(f"reachable: {len(report.reachable)}/{report.n}  (quorum {report.quorum})")
    dead = ", ".join(f"node{i}" for i in report.presumed_dead) or "(none)"
    print(f"presumed-dead nodes: {dead}")
    print(f"blast radius: salvage frontier {report.salvage.as_tuple()} vs last-known finality")

    decision = recover_decision(report, args.i_understand_data_loss)
    if decision is RecoverDecision.REFUSE_QUORUM:
        print(
            f"\nREFUSING recovery: a quorum ({len(report.reachable)} ≥ {report.quorum}) still "
            "answers.\nThe cluster is not dead. Recovery would fork it. Park and wait — "
            "recovery is never urgent (RESILIENCE §2.3).",
            file=sys.stderr,
        )
        return REFUSE_RECOVER
    if decision is RecoverDecision.NEED_ACK:
        print(
            "\nA quorum is NOT answering, so recovery is possible — but it DISCARDS "
            "everything above the salvage frontier.\nRe-run with --i-understand-data-loss "
            "once you have confirmed the presumed-dead nodes are truly gone.",
            file=sys.stderr,
        )
        return ERR
    ckpt, rop = m.author_recovery_fence(report)
    print("\ndata-loss acknowledged — recovery fence AUTHORED:")
    print(f"  recovery checkpoint: {ckpt.op_hash.hex()}  (horizon {report.salvage.as_tuple()})")
    print(f"  recovery roster op:  {rop.op_hash.hex()}  -> epoch {m.state.epoch}")
    print("  distribute control.log to the survivors; they park the old epoch on sight.")
    return OK


# --------------------------------------------------------------------------- #
# Commands — plain client verbs (worker-socket passthrough)                    #
# --------------------------------------------------------------------------- #


def cmd_set(args: argparse.Namespace) -> int:
    r = _worker_call(args.sock, "PUT", {"path": args.path, "value": args.value})
    print(f"submitted {r['op']}")
    return OK


def cmd_get(args: argparse.Namespace) -> int:
    r = _worker_call(args.sock, "GET", {"path": args.path, "level": args.level})
    if not r["present"]:
        print(f"{args.path}: (absent)")
        return OK
    print(f"{args.path} = {r['value']!r}  [tier={r['tier']} version={r['version']}]")
    return OK


def cmd_cas(args: argparse.Namespace) -> int:
    expect: object = "absent" if args.expect in (None, "absent") else {"version": args.expect}
    params = {
        "path": args.path,
        "expect": expect,
        "mutations": [{"set": args.path, "value": args.value}],
    }
    r = _worker_call(args.sock, "CAS", params)
    print(f"submitted {r['op']}")
    return OK


def cmd_del(args: argparse.Namespace) -> int:
    r = _worker_call(args.sock, "TXN", {"slot": None, "mutations": [{"del": args.path}]})
    print(f"submitted {r['op']}")
    return OK


def cmd_wheres(args: argparse.Namespace) -> int:
    """Human `where is my thing`: joins args with `/` and renders INSPECT for people
    (present/value, tier + finality, fencing token, pending ops with intent)."""
    path = "/".join(args.words)
    r = _worker_call(args.sock, "INSPECT", {"path": path})
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
    return OK


# --------------------------------------------------------------------------- #
# argparse wiring                                                              #
# --------------------------------------------------------------------------- #


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(prog="dude", description="DudeFS control + client CLI")
    sub = p.add_subparsers(dest="cmd", required=True)

    def mgr(name, fn, help):
        sp = sub.add_parser(name, help=help)
        sp.add_argument("--dir", default=os.environ.get("DUDE_DIR", ".dude"))
        sp.set_defaults(fn=fn)
        return sp

    def cli(name, fn, help):
        sp = sub.add_parser(name, help=help)
        sp.add_argument("--sock", default=os.environ.get("DUDE_SOCK", "worker.sock"))
        sp.set_defaults(fn=fn)
        return sp

    init = mgr("init", cmd_init, "mint root key + genesis (refuses over existing state)")
    init.add_argument("--node-addr", default="", help="endpoint for the genesis node")

    ci = sub.add_parser("cert", help="issue/revoke capability certs")
    csub = ci.add_subparsers(dest="cert_cmd", required=True)
    issue = csub.add_parser("issue", help="issue a cert")
    issue.add_argument("kind", choices=["client", "node", "compactor"])
    issue.add_argument("pubkey")
    issue.add_argument(
        "--pop", required=True, help="subject's proof-of-possession (from `dude node spawn`)"
    )
    issue.add_argument("--dir", default=os.environ.get("DUDE_DIR", ".dude"))
    issue.set_defaults(fn=cmd_cert_issue)
    rev = csub.add_parser("revoke", help="revoke a cert (stages rotate)")
    rev.add_argument("fingerprint")
    rev.add_argument("--no-rotate", action="store_true", help="skip the staged rotate (loud)")
    rev.add_argument("--dir", default=os.environ.get("DUDE_DIR", ".dude"))
    rev.set_defaults(fn=cmd_cert_revoke)

    mgr("rotate", cmd_rotate, "new group key + wrap-set + keyepoch bump")

    node = mgr("node", cmd_node, "roster membership (spawn/add/promote)")
    nsub = node.add_subparsers(dest="node_cmd", required=True)

    def node_leaf(name, help):  # each leaf carries --dir so it may follow the subcmd
        sp = nsub.add_parser(name, help=help)
        sp.add_argument("--dir", default=os.environ.get("DUDE_DIR", ".dude"))
        sp.set_defaults(fn=cmd_node)
        return sp

    node_leaf("spawn", "mint a node identity")
    nadd = node_leaf("add", "add a learner")
    nadd.add_argument("pubkey")
    nadd.add_argument("--addr", default="")
    npro = node_leaf("promote", "promote a learner to voting")
    npro.add_argument("pubkey")

    mgr("status", cmd_status, "roster/floors/finality health")

    rec = mgr("recover", cmd_recover, "disaster recovery (heavily interlocked)")
    rec.add_argument("--dwell", type=float, default=2.0, help="reachability dwell window (s)")
    rec.add_argument("--i-understand-data-loss", action="store_true")

    setp = cli("set", cmd_set, "PUT a value")
    setp.add_argument("path")
    setp.add_argument("value")
    getp = cli("get", cmd_get, "GET a value")
    getp.add_argument("path")
    getp.add_argument("--level", choices=["local", "final"], default="local")
    casp = cli("cas", cmd_cas, "guarded write")
    casp.add_argument("path")
    casp.add_argument("value")
    casp.add_argument("--expect", default="absent", help="expected version (hex), or 'absent'")
    delp = cli("del", cmd_del, "delete a key")
    delp.add_argument("path")
    wp = cli("wheres", cmd_wheres, "human key-status renderer (INSPECT)")
    wp.add_argument("words", nargs="+")

    return p


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    fn = getattr(args, "fn", None)
    if fn is None:
        print("no command", file=sys.stderr)
        return ERR
    try:
        return fn(args)
    except (RuntimeError, OSError, KeyError, ValueError) as e:
        print(f"error: {e}", file=sys.stderr)
        return ERR


if __name__ == "__main__":
    raise SystemExit(main())
