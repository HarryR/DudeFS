# DudeFS — the `dude` CLI (M7 WP3, MANAGER.md). Manager powers come from WHICH
# KEYS are present, not which binary: the same tool authors root-signed control ops
# (init/cert/rotate/node) against an on-disk state dir AND passes plain worker verbs
# (get/set/cas/wheres/status) through to a running client daemon's JSON-RPC socket.
#
# The interlocks (MANAGER §3) are load-bearing, not decoration — `recover` HARD-
# REFUSES while a quorum still answers (RESILIENCE §2.3, the self-inflicted gorilla),
# `init` refuses over existing state, `revoke` stages `rotate`. These are tested.
#
# No stubs (NOTES 51): every subcommand below is implemented and reviewed.

from __future__ import annotations

import argparse
import json
import os
import socket
import sys
import time
from dataclasses import dataclass

from . import artifacts as A
from . import crypto as C
from . import wire
from .artifacts import quorum_size
from .handlers import control as ctl
from .node import FrontierReq

# ---- exit codes -------------------------------------------------------------- #
OK = 0
ERR = 1  # usage / runtime error
REFUSE_EXISTING = 2  # init over existing state
REFUSE_RECOVER = 3  # recover while a quorum answers (the load-bearing interlock)


# --------------------------------------------------------------------------- #
# Manager state — the on-disk durable set (MANAGER §1)                         #
# --------------------------------------------------------------------------- #


@dataclass
class ManagerState:
    """The manager's durable set under a state dir: the root key, genesis identity,
    the roster + endpoints, per-keyepoch group masters, the issued-cert inventory,
    and the manager's own control-chain head. Everything is idempotent + resumable
    (MANAGER §2): the control log is the append-only record."""

    dir: str
    root_key: bytes
    manager_pub: bytes
    epoch: int
    keyepoch: int
    mseq: int
    mprev: bytes
    mhlc: int
    roster: list[bytes]  # voting node pubkeys
    learners: list[bytes]  # added, not yet promoted
    node_addrs: dict[str, str]  # node pubkey hex -> endpoint (unix socket path)
    masters: dict[int, bytes]  # keyepoch -> 32-byte group master
    certs: list[dict]  # [{subject hex, caps [str], epoch, revoked bool}]

    # ---- persistence ---------------------------------------------------- #
    @staticmethod
    def _paths(d: str) -> tuple[str, str, str]:
        return (
            os.path.join(d, "state.json"),
            os.path.join(d, "root.key"),
            os.path.join(d, "control.log"),
        )

    @staticmethod
    def exists(d: str) -> bool:
        return os.path.exists(ManagerState._paths(d)[0])

    @classmethod
    def load(cls, d: str) -> ManagerState:
        state_p, key_p, _ = cls._paths(d)
        with open(key_p, "rb") as f:
            root_key = f.read()
        with open(state_p) as f:
            s = json.load(f)
        return cls(
            dir=d,
            root_key=root_key,
            manager_pub=bytes.fromhex(s["manager_pub"]),
            epoch=s["epoch"],
            keyepoch=s["keyepoch"],
            mseq=s["mseq"],
            mprev=bytes.fromhex(s["mprev"]),
            mhlc=s["mhlc"],
            roster=[bytes.fromhex(h) for h in s["roster"]],
            learners=[bytes.fromhex(h) for h in s["learners"]],
            node_addrs=dict(s["node_addrs"]),
            masters={int(k): bytes.fromhex(v) for k, v in s["masters"].items()},
            certs=s["certs"],
        )

    def save(self) -> None:
        state_p, key_p, _ = self._paths(self.dir)
        if not os.path.exists(key_p):
            with open(os.open(key_p, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600), "wb") as f:
                f.write(self.root_key)
        blob = {
            "manager_pub": self.manager_pub.hex(),
            "epoch": self.epoch,
            "keyepoch": self.keyepoch,
            "mseq": self.mseq,
            "mprev": self.mprev.hex(),
            "mhlc": self.mhlc,
            "roster": [p.hex() for p in self.roster],
            "learners": [p.hex() for p in self.learners],
            "node_addrs": self.node_addrs,
            "masters": {str(k): v.hex() for k, v in self.masters.items()},
            "certs": self.certs,
        }
        tmp = state_p + ".tmp"
        with open(tmp, "w") as f:
            json.dump(blob, f, indent=2)
        os.replace(tmp, state_p)  # atomic

    # ---- control-op authoring (root-signed) ----------------------------- #
    def author_control(self, payload: bytes) -> A.Op:
        """Build, persist, and record one root-signed control op, advancing the
        manager chain. Appended to control.log (the distribution/audit record)."""
        self.mhlc += 1
        op = A.Op.build(
            author_sk=self.root_key,
            author_pub=self.manager_pub,
            cls_=A.OpClass.CONTROL,
            seq=self.mseq,
            prev=self.mprev,
            hlc=A.HLC(self.mhlc, 0),
            deps=[],
            authz=b"root",
            keyepoch=self.keyepoch,
            payload=payload,
        )
        self.mseq += 1
        self.mprev = op.op_hash
        with open(self._paths(self.dir)[2], "a") as f:
            f.write(op.raw.hex() + "\n")
        return op

    def members(self) -> list[bytes]:
        """Everyone a wrap-set must reach: voting nodes, learners, and un-revoked
        cert subjects (DESIGN §3)."""
        subs = [bytes.fromhex(c["subject"]) for c in self.certs if not c["revoked"]]
        seen: dict[bytes, None] = {}
        for m in [*self.roster, *self.learners, *subs]:
            seen.setdefault(m, None)
        return list(seen)


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


def _probe(addr: str, timeout: float = 1.0) -> A.FrontierBundle | None:
    """A signed frontier read from one node endpoint, or None if unreachable."""
    try:
        with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as s:
            s.settimeout(timeout)
            s.connect(addr)
            s.sendall(wire.frame(wire.encode_request(FrontierReq())))
            payload = wire.read_frame(s.recv)
        if payload is None:
            return None
        resp = wire.decode_response(payload)
        return resp if isinstance(resp, A.FrontierBundle) else None
    except OSError:
        return None


# --------------------------------------------------------------------------- #
# Commands — manager (control-op authoring)                                    #
# --------------------------------------------------------------------------- #


def cmd_init(args: argparse.Namespace) -> int:
    d = args.dir
    os.makedirs(d, exist_ok=True)
    if ManagerState.exists(d):  # interlock: never clobber a genesis (MANAGER §3)
        print(f"refusing: state already exists at {d} (init is genesis-only)", file=sys.stderr)
        return REFUSE_EXISTING
    root_key = os.urandom(32)
    manager_pub = C.SIGNER.public(root_key)
    node_key = os.urandom(32)
    node_pub = C.SIGNER.public(node_key)
    with open(os.open(os.path.join(d, "node0.key"), os.O_WRONLY | os.O_CREAT, 0o600), "wb") as f:
        f.write(node_key)
    st = ManagerState(
        dir=d,
        root_key=root_key,
        manager_pub=manager_pub,
        epoch=0,
        keyepoch=0,
        mseq=0,
        mprev=A.GENESIS_PREV,
        mhlc=0,
        roster=[node_pub],  # n=1 genesis roster
        learners=[],
        node_addrs={node_pub.hex(): args.node_addr or ""},
        masters={0: os.urandom(32)},  # the epoch-0 group master (finding 21 derives from it)
        certs=[],
    )
    st.save()
    print(f"initialized dudefs at {d}")
    print(f"  manager (root): {manager_pub.hex()}")
    print(f"  node0:          {node_pub.hex()}")
    print(f"  zero-knowledge: {'ON' if C.zero_knowledge_active() else 'OFF'}")
    return OK


_CAP_FOR = {"client": [ctl.Cap.WRITE], "node": [ctl.Cap.STORE], "compactor": [ctl.Cap.COMPACT]}


def cmd_cert_issue(args: argparse.Namespace) -> int:
    st = ManagerState.load(args.dir)
    kind = args.kind
    subject = bytes.fromhex(args.pubkey)
    caps = _CAP_FOR[kind]
    op = st.author_control(ctl.cert_issue_body(subject, caps, st.epoch))
    st.certs.append(
        {
            "subject": subject.hex(),
            "caps": [c.decode() for c in caps],
            "epoch": st.epoch,
            "revoked": False,
        }
    )
    st.save()
    print(f"issued {kind} cert to {subject.hex()} (caps: {', '.join(c.decode() for c in caps)})")
    print(f"  control op: {op.op_hash.hex()}")
    return OK


def _print_cert_inventory(st: ManagerState) -> None:
    # roster commands must show the live inventory first (MANAGER §3 / NOTES 36c):
    # rotation expires NO capability, so a distrust change needs explicit revokes.
    print("cert inventory (rotation expires nothing — revoke explicitly to distrust):")
    if not st.certs:
        print("  (none)")
    for c in st.certs:
        flag = " REVOKED" if c["revoked"] else ""
        print(f"  {c['subject'][:16]}…  caps={','.join(c['caps'])}  epoch={c['epoch']}{flag}")


def cmd_cert_revoke(args: argparse.Namespace) -> int:
    st = ManagerState.load(args.dir)
    subject = bytes.fromhex(args.fingerprint)
    op = st.author_control(ctl.cert_revoke_body(subject))
    for c in st.certs:
        if c["subject"] == subject.hex():
            c["revoked"] = True
    st.save()
    print(f"revoked {subject.hex()}")
    print(f"  control op: {op.op_hash.hex()}")
    if args.no_rotate:
        print("  WARNING: --no-rotate given; the revoked key still opens the current group key")
        print("           until you `dude rotate` (revocation without rotation is a foot-gun)")
        return OK
    print("  staging rotate (revocation without rotation is a foot-gun — MANAGER §2):")
    return _do_rotate(st)


def _do_rotate(st: ManagerState) -> int:
    new_ke = st.keyepoch + 1
    master = os.urandom(32)
    members = st.members()
    st.masters[new_ke] = master
    wrap_op = st.author_control(ctl.sealed_wrap_set_body(new_ke, master, members))
    st.keyepoch = new_ke
    rot_op = st.author_control(ctl.rotate_body(new_ke))
    st.save()
    print(f"  rotated to keyepoch {new_ke}: sealed group key to {len(members)} member(s)")
    print(f"    wrap-set op: {wrap_op.op_hash.hex()}")
    print(f"    rotate op:   {rot_op.op_hash.hex()}")
    return OK


def cmd_rotate(args: argparse.Namespace) -> int:
    st = ManagerState.load(args.dir)
    _print_cert_inventory(st)
    return _do_rotate(st)


def cmd_node(args: argparse.Namespace) -> int:
    st = ManagerState.load(args.dir)
    if args.node_cmd == "spawn":
        key = os.urandom(32)
        pub = C.SIGNER.public(key)
        keyfile = os.path.join(args.dir, f"node-{pub.hex()[:8]}.key")
        with open(os.open(keyfile, os.O_WRONLY | os.O_CREAT, 0o600), "wb") as f:
            f.write(key)
        print(f"spawned node identity {pub.hex()} (key: {keyfile})")
        print(f"  add it as a learner:  dude node add {pub.hex()} --addr <endpoint>")
        return OK
    if args.node_cmd == "add":  # learner-add (not yet a voting member)
        pub = bytes.fromhex(args.pubkey)
        if pub in st.roster or pub in st.learners:
            print("already a member/learner", file=sys.stderr)
            return ERR
        st.learners.append(pub)
        if args.addr:
            st.node_addrs[pub.hex()] = args.addr
        st.save()
        print(f"added learner {pub.hex()} (promote it once it has caught up)")
        return OK
    if args.node_cmd == "promote":
        _print_cert_inventory(st)
        pub = bytes.fromhex(args.pubkey)
        if pub not in st.learners:
            print("not a learner — add it first", file=sys.stderr)
            return ERR
        new_roster = [*st.roster, pub]
        if len(new_roster) % 2 == 0:  # client-side pre-check (fail near the operator)
            print(
                f"refusing: promoting yields an EVEN voting roster ({len(new_roster)}); "
                "quorum intersection needs odd n (MANAGER §3)",
                file=sys.stderr,
            )
            return ERR
        op = st.author_control(ctl.roster_body(st.epoch, new_roster, {}))
        st.roster = new_roster
        st.learners.remove(pub)
        st.epoch += 1
        st.save()
        print(f"promoted {pub.hex()} -> epoch {st.epoch}, roster size {len(new_roster)}")
        print(f"  roster op: {op.op_hash.hex()}")
        return OK
    print(f"unknown node subcommand {args.node_cmd!r}", file=sys.stderr)
    return ERR


# --------------------------------------------------------------------------- #
# Commands — telemetry + recovery (probe the cluster)                          #
# --------------------------------------------------------------------------- #


def cmd_status(args: argparse.Namespace) -> int:
    st = ManagerState.load(args.dir)
    print(f"epoch {st.epoch}  keyepoch {st.keyepoch}  roster {len(st.roster)} voting")
    print(f"zero-knowledge: {'ON' if C.zero_knowledge_active() else 'OFF'}")
    frontier = A.HLC(0, 0)
    reachable = 0
    for i, pub in enumerate(st.roster):
        addr = st.node_addrs.get(pub.hex(), "")
        fb = _probe(addr) if addr else None
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
    """The most interlocked verb (MANAGER §3 / RESILIENCE §2.3). Dwell-probe every
    roster endpoint; HARD-REFUSE while a quorum answers; name the presumed-dead;
    print the blast radius; and remind the operator that a parked system is safe."""
    st = ManagerState.load(args.dir)
    n = len(st.roster)
    q = quorum_size(n)
    print(f"recovery reachability probe — dwell {args.dwell}s over {n} roster endpoints")
    print("(a parked system is SAFE; recovery is never urgent, and dwell is free.)")

    answered: dict[int, A.HLC] = {}
    deadline = time.monotonic() + args.dwell
    while True:
        for i, pub in enumerate(st.roster):
            if i in answered:
                continue
            fb = _probe(st.node_addrs.get(pub.hex(), ""))
            if fb is not None:
                answered[i] = fb.floor
        if time.monotonic() >= deadline or len(answered) == n:
            break
        time.sleep(min(0.2, max(0.0, deadline - time.monotonic())))

    presumed_dead = [i for i in range(n) if i not in answered]
    salvage = max((f for f in answered.values()), default=A.HLC(0, 0), key=lambda h: h.as_tuple())
    print(f"reachable: {len(answered)}/{n}  (quorum {q})")
    print("presumed-dead nodes: " + (", ".join(f"node{i}" for i in presumed_dead) or "(none)"))
    print(
        f"blast radius: salvage frontier {salvage.as_tuple()} vs last-known finality (see status)"
    )

    if len(answered) >= q:  # THE load-bearing interlock — hard refusal
        print(
            f"\nREFUSING recovery: a quorum ({len(answered)} ≥ {q}) still answers.\n"
            "The cluster is not dead. Recovery would fork it. Park and wait — "
            "recovery is never urgent (RESILIENCE §2.3).",
            file=sys.stderr,
        )
        return REFUSE_RECOVER

    if not args.i_understand_data_loss:
        print(
            "\nA quorum is NOT answering, so recovery is possible — but it DISCARDS "
            "everything above the salvage frontier.\nRe-run with --i-understand-data-loss "
            "once you have confirmed the presumed-dead nodes are truly gone.",
            file=sys.stderr,
        )
        return ERR

    # data-loss acknowledged AND no quorum answers -> AUTHOR the fence for real (no
    # placeholder once every interlock has passed). The pair is a fiat recovery
    # checkpoint + a recovery-marked roster op naming it — exactly what a node's
    # on_recovery_fence recognizes to park the old epoch and activate the new one
    # (NOTES 36a / RESILIENCE §2.2). The salvage frontier is the fiat cut's horizon.
    survivors = [st.roster[i] for i in sorted(answered)] or st.roster
    ckpt = st.author_control(ctl.checkpoint_body({}, b"", [], {}, b"", st.keyepoch, salvage))
    rop = st.author_control(ctl.roster_body(st.epoch, survivors, {}, recovery=ckpt.op_hash))
    st.epoch += 1
    st.roster = survivors
    st.save()
    print("\ndata-loss acknowledged — recovery fence AUTHORED:")
    print(f"  recovery checkpoint: {ckpt.op_hash.hex()}  (horizon {salvage.as_tuple()})")
    print(f"  recovery roster op:  {rop.op_hash.hex()}  -> epoch {st.epoch}")
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

    ci = mgr("cert", None, "issue/revoke capability certs")
    csub = ci.add_subparsers(dest="cert_cmd", required=True)
    issue = csub.add_parser("issue", help="issue a cert")
    issue.add_argument("kind", choices=["client", "node", "compactor"])
    issue.add_argument("pubkey")
    issue.add_argument("--dir", default=os.environ.get("DUDE_DIR", ".dude"))
    issue.set_defaults(fn=cmd_cert_issue)
    rev = csub.add_parser("revoke", help="revoke a cert (stages rotate)")
    rev.add_argument("fingerprint")
    rev.add_argument(
        "--no-rotate", action="store_true", help="skip the staged rotate (loud foot-gun)"
    )
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

    mgr("status", cmd_status, "roster/floors/finality + zero-knowledge banner")

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
    # `dude cert` with no sub-subcommand handled by required=True; `node` dispatches
    # on node_cmd inside cmd_node.
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
