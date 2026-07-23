# `mgr` │ `m` │ `manager` — the control plane. Its own verbs (init/status/recover/rotate)
# plus AUTHORITY over each subject (node/client/compactor authorize/revoke/…). Every
# handler is a thin wrapper over the tested `manager.Manager` library; the CLI's job is
# argparse, socket probing (status/recover I/O), rendering, and ManagerError -> exit code.

from __future__ import annotations

import argparse
import sys
import time

from .. import artifacts as A
from .. import transports
from ..artifacts import quorum_size
from ..manager import Manager, ManagerError, ManagerState, RecoverDecision, recover_decision
from . import _util as U
from ._args import dir_arg, pop, pubkey


# --------------------------------------------------------------------------- #
# mgr's own verbs                                                             #
# --------------------------------------------------------------------------- #
def cmd_init(args: argparse.Namespace) -> int:
    try:
        m = Manager.init(args.dir, node_addr=args.node_addr)
    except ManagerError as e:
        print(f"refusing: {e}", file=sys.stderr)
        return U.REFUSE_EXISTING
    print(f"initialized dudefs at {args.dir}")
    print(f"  manager (root): {m.state.manager_pub.hex()}")
    print(f"  node0:          {m.state.roster[0].hex()}")
    return U.OK


def cmd_rotate(args: argparse.Namespace) -> int:
    m = Manager.load(args.dir)
    U.print_cert_inventory(m.state)
    ops = m.rotate()
    n_members = len(m.state.members())
    print(f"rotated to keyepoch {m.state.keyepoch}: sealed group key to {n_members} member(s)")
    print(f"  wrap-set op: {ops[0].op_hash.hex()}   rotate op: {ops[1].op_hash.hex()}")
    return U.OK


def cmd_status(args: argparse.Namespace) -> int:
    st = ManagerState.load(args.dir)
    print(f"epoch {st.epoch}  keyepoch {st.keyepoch}  roster {len(st.roster)} voting")
    frontier = A.HLC(0, 0)
    reachable = 0
    for i, pub in enumerate(st.roster):
        fb = U.probe(st, pub, st.dial(pub.hex()))
        if fb is None:
            print(f"  node{i} {pub.hex()[:16]}…  UNREACHABLE")
            continue
        reachable += 1
        frontier = max(frontier, fb.floor, key=lambda h: h.as_tuple())
        print(f"  node{i} {pub.hex()[:16]}…  floor={fb.floor.as_tuple()}  epoch={fb.config_epoch}")
    print(f"reachable: {reachable}/{len(st.roster)} (quorum {quorum_size(len(st.roster))})")
    print(f"finality frontier (max attested floor): {frontier.as_tuple()}")
    return U.OK


def cmd_recover(args: argparse.Namespace) -> int:
    """A thin wrapper: probe the roster (I/O here), then let the LIBRARY's pure
    `recover_decision` rule the interlock and author the fence. The delicate decision is
    tested directly in test_manager, not just through this path."""
    m = Manager.load(args.dir)
    print(f"recovery reachability probe — dwell {args.dwell}s over {len(m.state.roster)} endpoints")
    print("(a parked system is SAFE; recovery is never urgent, and dwell is free.)")
    report = m.probe_roster(U.floor_probe(m.state), args.dwell, time.sleep)
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
        return U.REFUSE_RECOVER
    if decision is RecoverDecision.NEED_ACK:
        print(
            "\nA quorum is NOT answering, so recovery is possible — but it DISCARDS "
            "everything above the salvage frontier.\nRe-run with --i-understand-data-loss "
            "once you have confirmed the presumed-dead nodes are truly gone.",
            file=sys.stderr,
        )
        return U.ERR
    ckpt, rop = m.author_recovery_fence(report)
    print("\ndata-loss acknowledged — recovery fence AUTHORED:")
    print(f"  recovery checkpoint: {ckpt.op_hash.hex()}  (horizon {report.salvage.as_tuple()})")
    print(f"  recovery roster op:  {rop.op_hash.hex()}  -> epoch {m.state.epoch}")
    print("  gossip the recovery ops to the survivors; they park the old epoch on sight.")
    return U.OK


# --------------------------------------------------------------------------- #
# Authority over subjects — authorize / revoke (kind = the namespace)         #
# --------------------------------------------------------------------------- #
def cmd_authorize(args: argparse.Namespace) -> int:
    """`mgr <kind> authorize <pub> <pop>` — one PoP-checked cert; a key-holder (client/
    compactor) is also back-wrapped the full live keyepoch set (issue #2 gap 3)."""
    m = Manager.load(args.dir)
    try:
        op = m.cert_issue(args.kind, bytes.fromhex(args.pubkey), bytes.fromhex(args.pop))
    except ManagerError as e:
        print(f"refusing: {e}", file=sys.stderr)
        return U.ERR
    caps = ", ".join(m.state.certs[-1]["caps"])
    print(f"authorized {args.kind} {args.pubkey} (caps: {caps})")
    print(f"  control op: {op.op_hash.hex()}")
    if args.kind in Manager._KEY_HOLDERS:
        print(f"  back-wrapped the group key for keyepochs {sorted(m.state.masters)}")
    return U.OK


def cmd_revoke(args: argparse.Namespace) -> int:
    m = Manager.load(args.dir)
    ops = m.cert_revoke(bytes.fromhex(args.pubkey), rotate=not args.no_rotate)
    print(f"revoked {args.pubkey}")
    print(f"  revoke op: {ops[0].op_hash.hex()}")
    if args.no_rotate:
        print("  WARNING: --no-rotate given; the revoked key still opens the current group key")
        print("           until you `dude mgr rotate` (revocation without rotation is a foot-gun)")
        return U.OK
    print(f"  staged rotate -> keyepoch {m.state.keyepoch}: wrap-set {ops[1].op_hash.hex()}")
    return U.OK


# --------------------------------------------------------------------------- #
# mgr node — roster membership + reachability                                 #
# --------------------------------------------------------------------------- #
def cmd_node_spawn(args: argparse.Namespace) -> int:
    # transitional (moves to self-side `node init` in Phase 2, keys-generate-where-they-live)
    m = Manager.load(args.dir)
    pub, keyfile, pp = m.node_spawn()
    print(f"spawned node identity {pub.hex()} (key: {keyfile})")
    print(f"  authorize it:  dude mgr node authorize {pub.hex()} {pp.hex()}")
    print(f"  add it:        dude mgr node add {pub.hex()} <addr>")
    return U.OK


def cmd_node_add(args: argparse.Namespace) -> int:
    m = Manager.load(args.dir)
    pub = bytes.fromhex(args.pubkey)
    try:
        m.node_add(pub, args.addr or "")
    except ManagerError as e:
        print(f"refusing: {e}", file=sys.stderr)
        return U.ERR
    print(f"added learner {pub.hex()} (promote it once it has caught up)")
    return U.OK


def cmd_node_promote(args: argparse.Namespace) -> int:
    m = Manager.load(args.dir)
    U.print_cert_inventory(m.state)
    try:
        change = m.node_promote(bytes.fromhex(args.pubkey), U.node_rpc(m.state))
    except ManagerError as e:
        print(f"refusing: {e}", file=sys.stderr)
        return U.ERR
    print(f"promoted {args.pubkey} -> epoch {m.state.epoch}, roster size {len(m.state.roster)}")
    print(f"  roster op:  {change.op.op_hash.hex()} (on the public roster slot)")
    print("  joint certificate: old-roster QC + possession-gated new-roster QC")
    return U.OK


def cmd_node_replace(args: argparse.Namespace) -> int:
    m = Manager.load(args.dir)
    try:
        change = m.node_replace(
            bytes.fromhex(args.old), bytes.fromhex(args.new), U.node_rpc(m.state)
        )
    except ManagerError as e:
        print(f"refusing: {e}", file=sys.stderr)
        return U.ERR
    print(f"replaced {args.old} -> {args.new} (count-preserving; epoch {m.state.epoch})")
    print(f"  roster op: {change.op.op_hash.hex()}  (revoke the old cert separately)")
    return U.OK


def cmd_node_list(args: argparse.Namespace) -> int:
    st = ManagerState.load(args.dir)
    print(f"roster ({len(st.roster)} voting), epoch {st.epoch}:")
    for i, pub in enumerate(st.roster):
        eps = ", ".join(f"{e.transport.decode()}:{e.uri}" for e in st.node_addrs.get(pub.hex(), []))
        print(f"  node{i} {pub.hex()[:16]}…  [{eps or 'no endpoint'}]")
    if st.learners:
        print("learners (non-voting, catching up):")
        for pub in st.learners:
            eps = ", ".join(
                f"{e.transport.decode()}:{e.uri}" for e in st.node_addrs.get(pub.hex(), [])
            )
            print(f"  {pub.hex()[:16]}…  [{eps or 'no endpoint'}]")
    return U.OK


def cmd_node_endpoint(args: argparse.Namespace) -> int:
    m = Manager.load(args.dir)
    pub = bytes.fromhex(args.pubkey)
    if args.ep_cmd == "list":
        eps = m.endpoint_list(pub)
        print(f"{pub.hex()[:16]}… endpoints:")
        for e in eps:
            print(f"  {e.transport.decode()}:{e.uri}{'  (sealed)' if e.sealed else ''}")
        if not eps:
            print("  (none)")
        return U.OK
    if args.ep_cmd == "add":
        op = m.endpoint_add(pub, args.addr)
    elif args.ep_cmd == "remove":
        op = m.endpoint_remove(pub, args.addr or "")
    else:  # set — replace-all
        recs = [transports.parse_endpoint(a) for a in args.addrs]
        op = m.set_endpoint(pub, recs)
    print(f"endpoint {args.ep_cmd} {pub.hex()[:16]}…  op {op.op_hash.hex()}")
    return U.OK


# --------------------------------------------------------------------------- #
# mgr client — writer authorization                                          #
# --------------------------------------------------------------------------- #
def cmd_client_list(args: argparse.Namespace) -> int:
    st = ManagerState.load(args.dir)
    clients = [c for c in st.certs if "write" in c["caps"]]
    print(f"authorized clients ({len(clients)}):")
    for c in clients:
        flag = " REVOKED" if c["revoked"] else ""
        print(f"  {c['subject'][:16]}…  epoch={c['epoch']}{flag}")
    if not clients:
        print("  (none)")
    return U.OK


# --------------------------------------------------------------------------- #
# argparse wiring                                                            #
# --------------------------------------------------------------------------- #
def _authorize_leaf(sub, kind: str) -> None:
    sp = sub.add_parser("authorize", help=f"cert a {kind} (+ back-wrap keys)")
    pubkey(sp)
    pop(sp)
    dir_arg(sp)
    sp.set_defaults(fn=cmd_authorize, kind=kind)


def _revoke_leaf(sub, kind: str) -> None:
    sp = sub.add_parser("revoke", help=f"revoke a {kind} cert (stages rotate)")
    pubkey(sp)
    sp.add_argument("--no-rotate", action="store_true", help="skip the staged rotate (loud)")
    dir_arg(sp)
    sp.set_defaults(fn=cmd_revoke, kind=kind)


def register(sub: argparse._SubParsersAction) -> None:
    mgr = sub.add_parser("mgr", aliases=["m", "manager"], help="control plane (manager authority)")
    msub = mgr.add_subparsers(dest="mgr_cmd", required=True)

    init = dir_arg(msub.add_parser("init", help="mint root key + genesis"))
    init.add_argument("--node-addr", default="", help="endpoint for the genesis node")
    init.set_defaults(fn=cmd_init)
    dir_arg(msub.add_parser("status", help="roster/floors/finality health")).set_defaults(
        fn=cmd_status
    )
    rec = dir_arg(msub.add_parser("recover", help="disaster recovery (heavily interlocked)"))
    rec.add_argument("--dwell", type=float, default=2.0, help="reachability dwell window (s)")
    rec.add_argument("--i-understand-data-loss", action="store_true")
    rec.set_defaults(fn=cmd_recover)
    dir_arg(
        msub.add_parser("rotate", help="new group key + wrap-set + keyepoch bump")
    ).set_defaults(fn=cmd_rotate)

    # mgr node …
    node = msub.add_parser("node", help="roster membership + reachability")
    nsub = node.add_subparsers(dest="node_cmd", required=True)
    dir_arg(nsub.add_parser("spawn", help="mint a node identity")).set_defaults(fn=cmd_node_spawn)
    _authorize_leaf(nsub, "node")
    nadd = dir_arg(nsub.add_parser("add", help="add a learner with its endpoint"))
    pubkey(nadd)
    nadd.add_argument("addr", nargs="?", default="", help="dial address")
    nadd.set_defaults(fn=cmd_node_add)
    npro = dir_arg(nsub.add_parser("promote", help="promote a learner to voting"))
    pubkey(npro)
    npro.set_defaults(fn=cmd_node_promote)
    nrep = dir_arg(nsub.add_parser("replace", help="swap a voting node (count-preserving)"))
    pubkey(nrep, "old")
    pubkey(nrep, "new")
    nrep.set_defaults(fn=cmd_node_replace)
    dir_arg(nsub.add_parser("list", help="show roster + learners + endpoints")).set_defaults(
        fn=cmd_node_list
    )
    ep = nsub.add_parser("endpoint", help="manage a node's dial addresses (multi-homed)")
    epsub = ep.add_subparsers(dest="ep_cmd", required=True)
    for name, addr_spec in (("add", "one"), ("remove", "opt"), ("list", "none"), ("set", "many")):
        lf = dir_arg(epsub.add_parser(name, help=f"{name} endpoint(s)"))
        pubkey(lf)
        if addr_spec == "one":
            lf.add_argument("addr")
        elif addr_spec == "opt":
            lf.add_argument("addr", nargs="?", default="", help="omit to remove the whole record")
        elif addr_spec == "many":
            lf.add_argument("addrs", nargs="+")
        lf.set_defaults(fn=cmd_node_endpoint)

    # mgr client …
    client = msub.add_parser("client", help="writer authorization")
    csub = client.add_subparsers(dest="client_cmd", required=True)
    _authorize_leaf(csub, "client")
    _revoke_leaf(csub, "client")
    dir_arg(csub.add_parser("list", help="show authorized clients")).set_defaults(
        fn=cmd_client_list
    )

    # mgr compactor …
    compactor = msub.add_parser("compactor", help="compactor authorization")
    ksub = compactor.add_subparsers(dest="compactor_cmd", required=True)
    _authorize_leaf(ksub, "compactor")
    _revoke_leaf(ksub, "compactor")
