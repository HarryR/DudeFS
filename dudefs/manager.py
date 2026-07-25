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
from typing import TypedDict, Unpack

from . import artifacts as A
from . import crypto as C
from . import fold, transports
from .artifacts import HLC, QC, FrontierBundle, Heads, Op, Receipt, quorum_size
from .node import AcceptReq, FrontierReq, PutQCReq, Request, Response, RosterAcceptReq
from .store import ChainStore, ReadTxn

# rpc(node_pub, req) -> the node's response (or None if unreachable) — the injected
# node transport (the CLI wires sockets over node_addrs; tests wire in-process
# acceptors). Keying by pubkey, not index, lets old and new rosters differ.
type NodeRPC = Callable[[bytes, Request], Response | None]


class ManagerMeta(TypedDict, total=False):
    """The manager's non-derivable persisted state (store meta, JSON). NOT log-derived:
    `masters` are the per-keyepoch group secrets (keyepoch-as-str -> hex, finding 21);
    `learners`/`roster_seed` are local membership intent (pubkey hex). `total=False` —
    a write sets one or a few keys at a time."""

    masters: dict[str, str]
    learners: list[str]
    roster_seed: list[str]


class CertView(TypedDict):
    """One row of the manager's human-facing cert inventory (re-derived from the log
    each refold). Hex/decoded for display, not the wire form."""

    subject: str
    caps: list[str]
    epoch: int
    revoked: bool


class ManagerError(Exception):
    """An operator-facing precondition failure (bad roster change, missing learner,
    init over existing state). Typed so callers branch on it instead of parsing
    strings; the CLI maps it to an exit code."""


def mint_identity(d: str, role: str = "node") -> tuple[C.PublicKey, str, bytes]:
    """Mint a principal's identity keyfile in its OWN dir (`<role>.key`, 0600) and return
    (pub, keyfile, proof-of-possession). Keys generate where they live (NOTES 58): the sk
    never leaves this dir — only `pub` + `pop` travel to `mgr <role> authorize`. This is the
    `<role> init` primitive; the manager never sees the key."""
    os.makedirs(d, exist_ok=True)
    seed = os.urandom(32)
    kp = C.SoftwareKeypair.from_seed(seed)
    keyfile = os.path.join(d, f"{role}.key")
    with open(os.open(keyfile, os.O_WRONLY | os.O_CREAT, 0o600), "wb") as f:
        f.write(seed)
    return kp.public, keyfile, kp.prove_possession()


# --------------------------------------------------------------------------- #
# Manager state — the on-disk durable set (MANAGER §1)                         #
# --------------------------------------------------------------------------- #


class ManagerState:
    """The manager's durable set under a state dir. The control log lives in a
    `ChainStore` (`control.db`) — the authoritative, transactional, append-only record
    (WP-0). The VIEW (roster/epoch/keyepoch/certs/node_addrs/chain-head) is DERIVED by
    folding that log with the same `ControlState` nodes use, so it can never hand-
    diverge from the log. Only the non-derivable state persists outside the fold:
    `masters` (secret) and `learners` (local intent) in the store's `meta` table
    (transactional with the log), and `root_key` in a 0600 file. Idempotent + resumable
    (MANAGER §2): reload re-folds the log to the same view."""

    def __init__(self, dir: str, store: ChainStore, root: C.Keypair):
        self.dir = dir
        self.store = store
        # `root` is the manager's sole identity: it signs every control op, authenticates
        # the root's L_msg drive, and its `.public` is the `manager_pub`. No raw seed held.
        self.root = root
        self._refold()

    @staticmethod
    def _paths(d: str) -> tuple[str, str]:
        return os.path.join(d, "control.db"), os.path.join(d, "root.key")

    @staticmethod
    def exists(d: str) -> bool:
        return os.path.exists(ManagerState._paths(d)[1])

    @classmethod
    def load(cls, d: str) -> ManagerState:
        db_p, key_p = cls._paths(d)
        with open(key_p, "rb") as f:
            root_key = f.read()
        return cls(d, ChainStore(db_p), C.SoftwareKeypair.from_seed(root_key))

    # ---- non-derivable persistence (secrets + local intent) in store meta --- #
    @staticmethod
    def _meta[T](tx: ReadTxn, key: str, default: T) -> T:
        raw = tx.get_meta(key)
        return json.loads(raw) if raw else default

    def _set_meta(self, **kv: Unpack[ManagerMeta]) -> None:
        """Persist one or more meta values (JSON) in a single transaction, then
        re-derive the view."""
        with self.store.write_txn() as tx:
            for k, v in kv.items():
                tx.set_meta(k, json.dumps(v).encode())
        self._refold()

    # ---- the folded view (never hand-mutated) ----------------------------- #
    def _refold(self) -> None:
        cs = fold.ControlState(self.root.public)
        certs: list[CertView] = []
        with self.store.read_txn() as tx:
            # the manager is the sole author, so its ops fold in hlc (= authoring) order.
            ops = sorted(tx.all_ops(), key=lambda o: (o.hlc.as_tuple(), o.op_hash))
            for op in ops:
                if not op.is_control or isinstance(op, A.InvalidOp):
                    continue
                cs.apply_control(op)
                if isinstance(op, A.CertIssueOp):
                    certs.append(
                        {
                            "subject": op.subject.hex(),
                            "caps": [c.decode() for c in op.caps],
                            "epoch": op.epoch,
                            "revoked": False,
                        }
                    )
                elif isinstance(op, A.CertRevokeOp):
                    for c in certs:
                        if c["subject"] == op.subject.hex():
                            c["revoked"] = True
            roster_seed = self._meta(tx, "roster_seed", [])
            self.masters = {
                int(k): bytes.fromhex(v) for k, v in self._meta(tx, "masters", {}).items()
            }
            self.learners = [bytes.fromhex(h) for h in self._meta(tx, "learners", [])]
            head = max(ops, key=lambda o: o.seq, default=None)
        # roster comes from ROSTER ops once any exist; before that, the genesis seed.
        self.roster = (
            list(cs.roster) if cs.roster is not None else [bytes.fromhex(h) for h in roster_seed]
        )
        self.epoch = cs.epoch
        self.keyepoch = cs.active_keyepoch
        self.certs = certs
        # node_addrs: the FULL advertised dial-Endpoint list per node (multi-homed, PROTOCOL
        # §7.1), keyed by pubkey hex. Dialers take the first (`dial()`); the list is retained
        # so a failover address is never silently dropped and `endpoint list` can render it.
        self.node_addrs: dict[str, list[transports.Endpoint]] = {
            pub.hex(): list(eps) for pub, eps in cs.endpoints.items() if eps
        }
        if head is not None:
            self.mseq, self.mprev, self.mhlc = head.seq + 1, head.op_hash, head.hlc.wall_ms
        else:
            self.mseq, self.mprev, self.mhlc = 0, A.GENESIS_PREV, 0

    def dial(self, pub_hex: str) -> transports.Endpoint | None:
        """The primary dial Endpoint for a node — the first of its multi-homed list
        (no failover yet). None when the node advertises no address."""
        eps = self.node_addrs.get(pub_hex)
        return eps[0] if eps else None

    def _head(self) -> dict:
        """The current chain-head envelope kwargs every leaf `build` needs (author, seq,
        prev, hlc). Splatted into `A.<Leaf>.build(**self._head(), ...)` — the format layer
        signs + constructs the op, so an unratified roster change is just a built-but-unpersisted
        op (a crash-retry rebuilds the identical op; the head is unchanged until persist)."""
        return {
            "author": self.root,
            "seq": self.mseq,
            "prev": self.mprev,
            "hlc": A.HLC(self.mhlc + 1, 0),
        }

    def persist(self, op: Op, *, meta: ManagerMeta | None = None) -> None:
        """Commit an op to the log — plus any `meta` (secret/intent that must land
        atomically with it, e.g. a rotate's new master) — in ONE write transaction, then
        re-derive the view. A crash leaves log and view consistent because the view IS
        the log."""
        with self.store.write_txn() as tx:
            tx.put_op_raw(op)
            for k, v in (meta or {}).items():
                tx.set_meta(k, json.dumps(v).encode())
        self._refold()

    def author_control(self, op: Op, *, meta: ManagerMeta | None = None) -> Op:
        """Persist an already-built root-signed control op (the common case: the op is
        effective the moment it is authored — certs, endpoints, rotate, fiat recovery).
        The caller builds the typed leaf via `A.<Leaf>.build(**self._head(), ...)`."""
        self.persist(op, meta=meta)
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


@dataclass(frozen=True)
class RosterChange:
    """The joint certificate of a roster change (DESIGN §13): the slotted roster op,
    the OLD-roster QC (agreement, epoch e), and the possession-gated NEW-roster QC
    (epoch e+1). Both QCs together authorize activation."""

    op: Op
    old_qc: QC
    new_qc: QC


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
    def init(cls, d: str) -> Manager:
        """Manager genesis (CLI.md §3): mint the root key + the epoch-0 group master. The
        founding node is seated by `node_genesis` (keys generate where they live). Refuses
        over existing state (the genesis-only interlock)."""
        os.makedirs(d, exist_ok=True)
        if ManagerState.exists(d):
            raise ManagerError(f"state already exists at {d} (init is genesis-only)")
        root_seed = os.urandom(32)
        db_p, key_p = ManagerState._paths(d)
        with open(os.open(key_p, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600), "wb") as f:
            f.write(root_seed)
        store = ChainStore(db_p)
        with store.write_txn() as tx:  # seed the non-derivable genesis state (one txn)
            tx.set_meta("masters", json.dumps({"0": os.urandom(32).hex()}).encode())  # finding 21
            tx.set_meta("learners", json.dumps([]).encode())
            tx.set_meta("roster_seed", json.dumps([]).encode())
        return cls(ManagerState(d, store, C.SoftwareKeypair.from_seed(root_seed)))

    def node_genesis(self, pub: bytes, pop: bytes, addrs: list[str]) -> Op:
        """Seat the founding voting node at cluster genesis (CLI.md §3), unilaterally — no
        prior quorum exists to run the §13 joint-cert ladder against. PoP-checked Cap.STORE
        cert (synced) + its dial endpoint(s) + seat as the sole voting member via the roster
        seed. Genesis-only: refuses once a node is seated (thereafter it's the
        authorize -> add -> promote ladder)."""
        if self.state.roster:
            raise ManagerError("founding node already seated (use authorize -> add -> promote)")
        cert = self.cert_issue("node", pub, pop)  # verifies PoP; ZK node -> no wrap
        if addrs:
            self.set_endpoint(pub, [transports.parse_endpoint(a) for a in addrs])
        self.state._set_meta(roster_seed=[pub.hex()])
        return cert

    @classmethod
    def load(cls, d: str) -> Manager:
        return cls(ManagerState.load(d))

    # ---- identity ------------------------------------------------------- #
    _CAP_FOR = {"client": [A.Cap.WRITE], "node": [A.Cap.STORE], "compactor": [A.Cap.COMPACT]}
    _KEY_HOLDERS = {"client", "compactor"}  # decrypt the dataset; nodes are zero-knowledge

    def cert_issue(self, kind: str, subject: bytes, pop: bytes) -> Op:
        """Certify `subject`'s capability — after verifying its PROOF-OF-POSSESSION
        (NOTES 58): the manager signs pubkeys only and never certifies an unheld
        key, so an invalid/missing pop is refused before any op is authored. For a
        key-holder (client / compactor) it ALSO back-wraps the FULL live keyepoch set to
        `subject` (issue #2 gap 3): a member's fold spans every keyepoch, so without every
        live key it can't decrypt the dataset. Existing members accumulated these wraps
        incrementally via `rotate`; a newcomer holds none, so authorize seals them all in
        one shot. Nodes are zero-knowledge and get no wrap."""
        if kind not in self._CAP_FOR:
            raise ManagerError(f"unknown cert kind {kind!r}")
        if not C.verify_possession(subject, pop):
            raise ManagerError("proof-of-possession failed: subject does not hold the key")
        caps = self._CAP_FOR[kind]
        # the CERT_ISSUE op IS the record; the certs view re-derives from the log.
        op = self.state.author_control(
            A.CertIssueOp.build(
                **self.state._head(), subject=subject, caps=caps, epoch=self.state.epoch
            )
        )
        if kind in self._KEY_HOLDERS:
            for ke, master in sorted(self.state.masters.items()):
                self.state.author_control(
                    A.WrapSetOp.build(
                        **self.state._head(), keyepoch=ke, group_key=master, members=[subject]
                    )
                )
        return op

    def cert_revoke(self, subject: bytes, *, rotate: bool = True) -> list[Op]:
        """Revoke a cert; STAGE a rotation by default (revocation without rotation is
        a foot-gun — the revoked key still opens the current group key, MANAGER §2)."""
        ops = [
            self.state.author_control(A.CertRevokeOp.build(**self.state._head(), subject=subject))
        ]
        if rotate:
            ops += self.rotate()
        return ops

    def rotate(self) -> list[Op]:
        """New group key + a sealed wrap-set to every remaining member + a keyepoch
        bump — the wrap-set op then the rotate op (PROTOCOL §3.3)."""
        new_ke = self.state.keyepoch + 1
        master = os.urandom(32)
        members = self.state.members()
        masters = {str(k): v.hex() for k, v in {**self.state.masters, new_ke: master}.items()}
        # the new master (secret) lands ATOMICALLY with its wrap-set op — a crash never
        # leaves a wrap-set whose master the manager forgot (or vice versa).
        wrap_op = self.state.author_control(
            A.WrapSetOp.build(
                **self.state._head(), keyepoch=new_ke, group_key=master, members=members
            ),
            meta={"masters": masters},
        )
        rot_op = self.state.author_control(
            A.RotateOp.build(**self.state._head(), keyepoch=new_ke)  # keyepoch derives from it
        )
        return [wrap_op, rot_op]

    # ---- membership ----------------------------------------------------- #
    def node_add(self, pub: bytes, addr: str = "") -> None:
        if pub in self.state.roster or pub in self.state.learners:
            raise ManagerError("already a member/learner")
        # learners are local intent (no control op); node_addrs derives from the
        # ENDPOINT op published below.
        self.state._set_meta(learners=[p.hex() for p in [*self.state.learners, pub]])
        rec = transports.parse_endpoint(addr) if addr else None  # decompose ONCE
        if rec is not None:  # publish a control-plane reachability record (PROTOCOL §7)
            self.set_endpoint(pub, [rec])

    def set_endpoint(
        self, subject: bytes, addrs: list[tuple[bytes, bytes, dict[bytes, bytes]]]
    ) -> Op:
        """Author a root-signed ENDPOINT record for `subject` (PROTOCOL §7 / NOTES
        58): latest-wins per subject; empty `addrs` removes the node. Root-only. The
        deliberate replace-all clobber — `endpoint_add`/`_remove` edit the list instead."""
        return self.state.author_control(
            A.EndpointOp.build(**self.state._head(), subject=subject, addrs=addrs)
        )

    def _addr_records(self, subject: bytes) -> list[tuple[bytes, bytes, dict[bytes, bytes]]]:
        """The node's current advertised addrs as ENDPOINT records — the settable form of
        the derived dial-Endpoint list (a faithful round-trip; opts is just the L_msg flag)."""
        return [ep.to_record() for ep in self.state.node_addrs.get(subject.hex(), [])]

    def endpoint_list(self, subject: bytes) -> list[transports.Endpoint]:
        """A node's current dial addresses (multi-homed)."""
        return list(self.state.node_addrs.get(subject.hex(), []))

    def endpoint_add(self, subject: bytes, addr: str) -> Op:
        """Append one dial address to the node's record (read-modify-write); a re-add of an
        address it already advertises is a no-op replay, not a duplicate."""
        rec = transports.parse_endpoint(addr)
        cur = self._addr_records(subject)
        return self.set_endpoint(subject, cur if rec in cur else [*cur, rec])

    def endpoint_remove(self, subject: bytes, addr: str = "") -> Op:
        """Drop one dial address from the node's record; an empty `addr` (or removing the
        last one) removes the whole record — retiring the node's reachability."""
        cur = self._addr_records(subject)
        remaining = [r for r in cur if r != transports.parse_endpoint(addr)] if addr else []
        return self.set_endpoint(subject, remaining)

    def node_promote(self, pub: bytes, rpc: NodeRPC) -> RosterChange:
        """Promote a learner to voting. Refuses an even voting roster client-side
        (quorum intersection needs odd n — fail near the operator, MANAGER §3), then
        DRIVES the §13 joint-certificate flow (findings 23/24)."""
        if pub not in self.state.learners:
            raise ManagerError("not a learner — add it first")
        new_roster = [*self.state.roster, pub]
        if len(new_roster) % 2 == 0:
            raise ManagerError(
                f"promoting yields an EVEN voting roster ({len(new_roster)}); "
                "quorum intersection needs odd n"
            )
        change = self.change_roster(new_roster, rpc)
        self.state._set_meta(learners=[p.hex() for p in self.state.learners if p != pub])
        return change

    def node_replace(self, old: bytes, new: bytes, rpc: NodeRPC) -> RosterChange:
        """Retire a node and swap in a replacement — the voting count is UNCHANGED
        (stays odd), so it never trips the even-roster guard. Used for disk-wipe
        identity retirement (the old key is untrusted; revoke its cert separately).
        Drives the §13 joint flow like any roster change."""
        if old not in self.state.roster:
            raise ManagerError("not a voting member")
        if new in self.state.roster or new in self.state.learners:
            raise ManagerError("replacement is already a member/learner")
        new_roster = [new if p == old else p for p in self.state.roster]
        return self.change_roster(new_roster, rpc)

    # ---- the §13 roster-change drive (findings 23/24) ------------------- #
    def read_sync_frontier(self, roster: list[bytes], rpc: NodeRPC) -> Heads:
        """The §3.1 final quorum read (finding 23): read signed FRONTIERs from a
        quorum of the OLD roster and union their heads into the sync frontier a
        joining node must possess before its receipt counts — an empty SF makes the
        possession barrier vacuous, which is exactly the bug this closes."""
        bundles: list[FrontierBundle] = []
        for pub in roster:
            r = rpc(pub, FrontierReq())
            if isinstance(r, FrontierBundle):
                bundles.append(r)
        if len(bundles) < quorum_size(len(roster)):
            raise ManagerError("could not read a quorum frontier for the sync barrier")
        sf: Heads = {}
        for fb in bundles:
            for author, entry in fb.heads.items():
                if author not in sf or entry.seq > sf[author].seq:
                    sf[author] = entry
        return sf

    def change_roster(self, new_roster: list[bytes], rpc: NodeRPC) -> RosterChange:
        """Drive a roster change through the §13 joint-certificate flow (findings
        23+24): read the sync frontier, author the roster op ON THE PUBLIC ROSTER
        SLOT (B4 serialization — a crash-retry contends the same slot and the old
        roster decides at most one), get it DECIDED on the OLD roster (old QC, epoch
        e), and gather POSSESSION-GATED receipts from the NEW roster (new QC, epoch
        e+1). Raises if either roster fails to ratify — e.g. a new node that has not
        caught up to the frontier is refused by the barrier."""
        old_roster = self.state.roster
        epoch, new_epoch = self.state.epoch, self.state.epoch + 1
        sf = self.read_sync_frontier(old_roster, rpc)
        tag = A.roster_slot_tag(epoch)
        # BUILD the op for ratification; persist to the manager log only once BOTH QCs
        # assemble — an unratified change must not flip the derived roster/epoch view.
        op = A.RosterOp.build(
            **self.state._head(), from_epoch=epoch, roster=new_roster, sync_frontier=sf
        )
        ballot = A.Ballot(1, A.slot_priority(tag, self.state.root.public))

        old_qc = self._gather(
            old_roster,
            lambda pub: rpc(pub, AcceptReq(tag, ballot, op)),
            "old roster did not ratify the roster change",
        )
        new_qc = self._gather(
            new_roster,
            lambda pub: rpc(pub, RosterAcceptReq(tag, ballot, op, sf, new_epoch)),
            "new roster did not ratify (possession barrier / unreachable)",
        )
        for pub in {*old_roster, *new_roster}:  # distribute the joint certificate
            rpc(pub, PutQCReq(new_qc))
        self.state.persist(op)  # ratified: NOW record it -> roster + epoch derive from it
        return RosterChange(op, old_qc, new_qc)

    @staticmethod
    def _gather(roster: list[bytes], accept: Callable[[bytes], Response | None], err: str) -> QC:
        idx = {p: i for i, p in enumerate(roster)}
        recs: list[Receipt] = []
        for pub in roster:
            r = accept(pub)
            if isinstance(r, Receipt):
                recs.append(r)
        if len(recs) < quorum_size(len(roster)):
            raise ManagerError(err)
        return QC.assemble(recs, len(roster), idx)

    # ---- recovery (interlocked) ----------------------------------------- #
    def probe_roster(
        self,
        probe: Callable[[bytes, transports.Endpoint], HLC | None],
        dwell: float,
        sleep: Callable[[float], None],
    ) -> RecoverReport:
        """Dwell-probe every roster endpoint via the injected `probe(pub, endpoint) ->
        floor | None` (I/O is the caller's — the CLI passes a real enveloped FRONTIER
        probe over the node's Endpoint; tests pass a synthetic map). A roster node with no
        known endpoint is unreachable *by definition* — it never gets a probe call and
        falls straight into `presumed_dead`, so the callback is only ever handed a real
        Endpoint. Returns the reachability report."""
        import time

        answered: dict[int, HLC] = {}
        deadline = time.monotonic() + dwell
        n = len(self.state.roster)
        while True:
            for i, pub in enumerate(self.state.roster):
                if i in answered:
                    continue
                ep = self.state.dial(pub.hex())
                if ep is None:
                    continue  # no address -> unreachable; leave unanswered (presumed dead)
                floor = probe(pub, ep)
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
            A.CheckpointOp.build(
                **self.state._head(),
                baseline=A.Baseline({}, {}),
                state_acc=b"",
                attempts=b"",
                keyepoch=self.state.keyepoch,
                horizon=report.salvage,
                checkpoint_seq=0,
            )
        )
        rop = self.state.author_control(
            A.RosterOp.build(
                **self.state._head(),
                from_epoch=self.state.epoch,
                roster=survivors,
                sync_frontier={},
                recovery=ckpt.op_hash,
            )
        )
        # epoch + roster derive from the recovery ROSTER op — no hand-set.
        return [ckpt, rop]
