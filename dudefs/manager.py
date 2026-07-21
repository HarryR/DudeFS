# DudeFS — the manager library (MANAGER.md). The protocol-specific, delicate half
# of the control plane lives HERE, not in the CLI: authoring root-signed control
# ops, the revoke→rotate staging, wrap-set distribution, roster validation, and the
# recovery interlock decision + fence authoring. `dude` (cli.py) is a thin parse-
# and-delegate shell over this; any programmatic automation calls the same library,
# so the logic is written and tested ONCE (Harry's rule: no CLI-only protocol logic).

from __future__ import annotations

import json
import os
from collections.abc import Callable
from dataclasses import dataclass
from enum import Enum, auto

from . import artifacts as A
from . import crypto as C
from .artifacts import HLC, Op, quorum_size
from .handlers import control as ctl


class ManagerError(Exception):
    """An operator-facing precondition failure (bad roster change, missing learner,
    init over existing state). Typed so callers branch on it instead of parsing
    strings; the CLI maps it to an exit code."""


# --------------------------------------------------------------------------- #
# Manager state — the on-disk durable set (MANAGER §1)                         #
# --------------------------------------------------------------------------- #


@dataclass
class ManagerState:
    """The manager's durable set under a state dir: the root key, genesis identity,
    the roster + endpoints, per-keyepoch group masters, the issued-cert inventory,
    and the manager's own control-chain head. Idempotent + resumable (MANAGER §2):
    the control log is the append-only record."""

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

    def author_control(self, payload: bytes) -> Op:
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
# Recovery interlock — the decision is a PURE function, unit-tested directly   #
# --------------------------------------------------------------------------- #


@dataclass(frozen=True)
class RecoverReport:
    """The outcome of dwell-probing the roster (MANAGER §3 / RESILIENCE §2.3)."""

    n: int
    quorum: int
    reachable: list[int]  # roster indices that answered
    presumed_dead: list[int]  # indices that did not
    salvage: HLC  # highest floor among reachable (the fiat cut's horizon)

    @property
    def quorum_answers(self) -> bool:
        return len(self.reachable) >= self.quorum


class RecoverDecision(Enum):
    REFUSE_QUORUM = auto()  # a quorum still answers — the cluster is not dead
    NEED_ACK = auto()  # recovery is possible but --i-understand-data-loss is required
    PROCEED = auto()  # safe + acknowledged: author the fence


def recover_decision(report: RecoverReport, data_loss_ack: bool) -> RecoverDecision:
    """The load-bearing interlock, as a pure function (RESILIENCE §2.3). A quorum
    answering ALWAYS refuses — recovery would fork a live cluster; only a genuinely
    dead quorum, with data loss explicitly acknowledged, proceeds."""
    if report.quorum_answers:
        return RecoverDecision.REFUSE_QUORUM
    if not data_loss_ack:
        return RecoverDecision.NEED_ACK
    return RecoverDecision.PROCEED


# --------------------------------------------------------------------------- #
# The Manager — protocol operations over the durable state                     #
# --------------------------------------------------------------------------- #


class Manager:
    """The control-plane operations, each authoring real root-signed ops and
    persisting the state. Precondition failures raise ManagerError; the CLI is a
    thin wrapper that formats results and maps exceptions to exit codes."""

    def __init__(self, state: ManagerState):
        self.state = state

    @classmethod
    def init(cls, d: str, node_addr: str = "") -> Manager:
        """Mint the root key, genesis identity, an n=1 node, and the epoch-0 group
        master (DESIGN §14). Refuses over existing state (the genesis-only interlock)."""
        os.makedirs(d, exist_ok=True)
        if ManagerState.exists(d):
            raise ManagerError(f"state already exists at {d} (init is genesis-only)")
        root_key = os.urandom(32)
        node_key = os.urandom(32)
        node_pub = C.SIGNER.public(node_key)
        with open(
            os.open(os.path.join(d, "node0.key"), os.O_WRONLY | os.O_CREAT, 0o600), "wb"
        ) as f:
            f.write(node_key)
        st = ManagerState(
            dir=d,
            root_key=root_key,
            manager_pub=C.SIGNER.public(root_key),
            epoch=0,
            keyepoch=0,
            mseq=0,
            mprev=A.GENESIS_PREV,
            mhlc=0,
            roster=[node_pub],
            learners=[],
            node_addrs={node_pub.hex(): node_addr},
            masters={0: os.urandom(32)},  # epoch-0 group master (finding 21 derives from it)
            certs=[],
        )
        st.save()
        return cls(st)

    @classmethod
    def load(cls, d: str) -> Manager:
        return cls(ManagerState.load(d))

    # ---- identity ------------------------------------------------------- #
    _CAP_FOR = {"client": [ctl.Cap.WRITE], "node": [ctl.Cap.STORE], "compactor": [ctl.Cap.COMPACT]}

    def cert_issue(self, kind: str, subject: bytes) -> Op:
        if kind not in self._CAP_FOR:
            raise ManagerError(f"unknown cert kind {kind!r}")
        caps = self._CAP_FOR[kind]
        op = self.state.author_control(ctl.cert_issue_body(subject, caps, self.state.epoch))
        self.state.certs.append(
            {
                "subject": subject.hex(),
                "caps": [c.decode() for c in caps],
                "epoch": self.state.epoch,
                "revoked": False,
            }
        )
        self.state.save()
        return op

    def cert_revoke(self, subject: bytes, *, rotate: bool = True) -> list[Op]:
        """Revoke a cert; STAGE a rotation by default (revocation without rotation is
        a foot-gun — the revoked key still opens the current group key, MANAGER §2)."""
        ops = [self.state.author_control(ctl.cert_revoke_body(subject))]
        for c in self.state.certs:
            if c["subject"] == subject.hex():
                c["revoked"] = True
        self.state.save()
        if rotate:
            ops += self.rotate()
        return ops

    def rotate(self) -> list[Op]:
        """New group key + a sealed wrap-set to every remaining member + a keyepoch
        bump — the wrap-set op then the rotate op (PROTOCOL §3.3)."""
        new_ke = self.state.keyepoch + 1
        master = os.urandom(32)
        members = self.state.members()
        self.state.masters[new_ke] = master
        wrap_op = self.state.author_control(ctl.sealed_wrap_set_body(new_ke, master, members))
        self.state.keyepoch = new_ke
        rot_op = self.state.author_control(ctl.rotate_body(new_ke))
        self.state.save()
        return [wrap_op, rot_op]

    # ---- membership ----------------------------------------------------- #
    def node_spawn(self) -> tuple[bytes, str]:
        """Mint a node identity, returning (pubkey, keyfile path)."""
        key = os.urandom(32)
        pub = C.SIGNER.public(key)
        keyfile = os.path.join(self.state.dir, f"node-{pub.hex()[:8]}.key")
        with open(os.open(keyfile, os.O_WRONLY | os.O_CREAT, 0o600), "wb") as f:
            f.write(key)
        return pub, keyfile

    def node_add(self, pub: bytes, addr: str = "") -> None:
        if pub in self.state.roster or pub in self.state.learners:
            raise ManagerError("already a member/learner")
        self.state.learners.append(pub)
        if addr:
            self.state.node_addrs[pub.hex()] = addr
        self.state.save()

    def node_promote(self, pub: bytes) -> Op:
        """Promote a learner to voting. Refuses an even voting roster client-side
        (quorum intersection needs odd n — fail near the operator, MANAGER §3)."""
        if pub not in self.state.learners:
            raise ManagerError("not a learner — add it first")
        new_roster = [*self.state.roster, pub]
        if len(new_roster) % 2 == 0:
            raise ManagerError(
                f"promoting yields an EVEN voting roster ({len(new_roster)}); "
                "quorum intersection needs odd n"
            )
        op = self.state.author_control(ctl.roster_body(self.state.epoch, new_roster, {}))
        self.state.roster = new_roster
        self.state.learners.remove(pub)
        self.state.epoch += 1
        self.state.save()
        return op

    def node_replace(self, old: bytes, new: bytes) -> Op:
        """Retire a node and swap in a replacement in ONE roster op — the voting
        count is UNCHANGED (stays odd), so it never trips the even-roster guard. Used
        for disk-wipe identity retirement (the old key is untrusted; revoke its cert
        separately). One atomic membership change (MANAGER §2 `replace`)."""
        if old not in self.state.roster:
            raise ManagerError("not a voting member")
        if new in self.state.roster or new in self.state.learners:
            raise ManagerError("replacement is already a member/learner")
        new_roster = [new if p == old else p for p in self.state.roster]
        op = self.state.author_control(ctl.roster_body(self.state.epoch, new_roster, {}))
        self.state.roster = new_roster
        self.state.epoch += 1
        self.state.save()
        return op

    # ---- recovery (interlocked) ----------------------------------------- #
    def probe_roster(
        self, probe: Callable[[str], HLC | None], dwell: float, sleep: Callable[[float], None]
    ) -> RecoverReport:
        """Dwell-probe every roster endpoint via the injected `probe(addr) -> floor
        | None` (I/O is the caller's — the CLI passes a real FRONTIER probe; tests
        pass a synthetic map). Returns the reachability report."""
        import time

        answered: dict[int, HLC] = {}
        deadline = time.monotonic() + dwell
        n = len(self.state.roster)
        while True:
            for i, pub in enumerate(self.state.roster):
                if i in answered:
                    continue
                floor = probe(self.state.node_addrs.get(pub.hex(), ""))
                if floor is not None:
                    answered[i] = floor
            if time.monotonic() >= deadline or len(answered) == n:
                break
            sleep(min(0.2, max(0.0, deadline - time.monotonic())))
        salvage = max(
            (f for f in answered.values()), default=A.HLC(0, 0), key=lambda h: h.as_tuple()
        )
        return RecoverReport(
            n=n,
            quorum=quorum_size(n),
            reachable=sorted(answered),
            presumed_dead=[i for i in range(n) if i not in answered],
            salvage=salvage,
        )

    def author_recovery_fence(self, report: RecoverReport) -> list[Op]:
        """Author the fiat recovery pair — a recovery checkpoint (fiat cut, horizon =
        salvage frontier) + a recovery-marked roster op naming it (what a node's
        on_recovery_fence recognizes to park the old epoch, NOTES 36a / RESILIENCE
        §2.2). Callers MUST pass the recover_decision() interlock first."""
        survivors = [self.state.roster[i] for i in report.reachable] or self.state.roster
        ckpt = self.state.author_control(
            ctl.checkpoint_body({}, b"", [], {}, b"", self.state.keyepoch, report.salvage)
        )
        rop = self.state.author_control(
            ctl.roster_body(self.state.epoch, survivors, {}, recovery=ckpt.op_hash)
        )
        self.state.epoch += 1
        self.state.roster = survivors
        self.state.save()
        return [ckpt, rop]
