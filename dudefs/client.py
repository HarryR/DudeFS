# DudeFS L5 — the resident client daemon (WP2, CLIENT.md).
#
# The client daemon is THE identity + keyring holder. Workers (keyless) submit
# through it over a local JSON-RPC socket (workerapi.py); the daemon authors the
# ops, DRIVES the storage quorum to a QC itself (hedged fanout — never hand an op
# to one node and disconnect, PROTOCOL §1.4 struck, NOTES 52), pursues §9 finality,
# and answers the honestly-labelled ladder (in-flight → committed/lost → provisional
# → final) by folding the committed set it holds. Everything a worker asks is
# DERIVED from the store per poll (ticket = op_hash, NOTES 51) — no session state,
# restart loses nothing.
#
# The quorum I/O here is the real-socket twin of transports/memory.ClientRunner:
# it pumps a sans-io quorum.Commit / quorum.Finalize machine, executing Sends as
# node RPCs and Wakes as timers, until the machine says Done.

from __future__ import annotations

import queue
import socket
import threading
import time
from dataclasses import dataclass

from . import artifacts as A
from . import fold, lmsg, wire
from .artifacts import BLIND, HLC, QC, Op, Receipt, Txn, compute_slot_tag
from .handlers import data as data_handler
from .node import FetchOpReq, FrontierReq, GetQCReq, PutQCReq, Request, Response, SubmitReq
from .quorum import (
    Commit,
    Committed,
    Done,
    Final,
    Finalize,
    LostSlot,
    QuorumConfig,
    Reply,
    Send,
    Tick,
    Wake,
)
from .store import ChainStore

# A driver deadline: the sans-io machine terminates itself on max_rounds/max_polls,
# but a hopeless drive (no quorum reachable at all) needs a wall-clock backstop.
DRIVE_DEADLINE_MS = 30_000
BLIND_DEADLINE_S = 5.0  # blind SUBMIT retransmit budget (idempotent — PROTOCOL §0)
REFRESH_MS = 500  # background read-side sync cadence (local/INSPECT freshness, lane 1)


type Slot = tuple[bytes, bytes, int]  # (path, version, attempt)


@dataclass(frozen=True)
class Ladder:
    """One op's honestly-labelled life (CLIENT.md §2). `phase` is the decided
    event; `provisional`/`final` are fold verdicts (only meaningful once
    committed). `may_flip` is true while the provisional verdict can still change
    (not yet frozen by finality)."""

    phase: str  # in-flight | committed | lost | unknown
    provisional: str | None = None  # applied | rejected | stale
    final: str | None = None  # applied | rejected | stale (frozen)
    may_flip: bool = False
    winner: bytes | None = None  # the rival op_hash, when phase == lost


# --------------------------------------------------------------------------- #
# The real-socket driver — pumps one sans-io machine to its outcome.           #
# --------------------------------------------------------------------------- #


def _drive(
    machine,
    rpc,
    *,
    stop: threading.Event | None = None,
    deadline_ms: int = DRIVE_DEADLINE_MS,
) -> object:
    """Run a sans-io quorum machine (Commit/Finalize) over real node RPCs. Sends
    fan out on worker threads (node verbs are idempotent, PROTOCOL §0); Wakes arm
    timers; the single drive loop is the only feeder of the machine, so the machine
    itself is never touched concurrently. `rpc(node, req) -> Response | None`
    (None = unreachable this attempt; the machine's own timeout escalates). `stop`
    aborts the drive on daemon shutdown."""
    t0 = time.monotonic()

    def now() -> int:
        return int((time.monotonic() - t0) * 1000)

    evq: queue.Queue = queue.Queue()
    done = threading.Event()
    outcome: list[object] = [None]
    timers: list[threading.Timer] = []

    def do_send(node: int, req: Request) -> None:
        r = rpc(node, req)
        if r is not None and not done.is_set():
            evq.put(Reply(node, req, r, now()))

    def process(cmds: list) -> None:
        for c in cmds:
            if isinstance(c, Done):
                outcome[0] = c.outcome
                done.set()
            elif isinstance(c, Wake):
                delay = max(0.0, (c.at_ms - now()) / 1000.0)
                t = threading.Timer(delay, lambda: (not done.is_set()) and evq.put(Tick(now())))
                t.daemon = True
                timers.append(t)
                t.start()
            elif isinstance(c, Send):
                threading.Thread(target=do_send, args=(c.node, c.req), daemon=True).start()

    process(machine.start(now()))
    while not done.is_set():
        if stop is not None and stop.is_set():
            break
        remaining = min((deadline_ms - now()) / 1000.0, 0.5)  # wake to re-check `stop`
        if (deadline_ms - now()) <= 0:
            break
        try:
            ev = evq.get(timeout=max(0.0, remaining))
        except queue.Empty:
            continue
        if done.is_set():
            break
        process(machine.feed(ev))
    for t in timers:
        t.cancel()
    return outcome[0]


# --------------------------------------------------------------------------- #
# The client daemon                                                            #
# --------------------------------------------------------------------------- #


class ClientDaemon:
    """One client identity's daemon: authors ops, drives quorums, folds the held
    committed set into the CLIENT.md ladder. `masters` are per-keyepoch 32-byte
    master secrets (finding 21) — the working keyring DERIVES from them here, the
    client never receives the working keys over the wire."""

    def __init__(
        self,
        sk: bytes,
        pub: bytes,
        *,
        roster: list[bytes],
        roster_addrs: list[str],
        manager_pub: bytes,
        masters: dict[int, bytes],
        control_ops: list[Op] | None = None,
        store_path: str = ":memory:",
        epoch: int = 0,
        keyepoch: int = 0,
    ):
        self.sk = sk
        self.pub = pub
        self.manager_pub = manager_pub
        self.keyepoch = keyepoch
        self.keyring = fold.keyring_from_masters(masters)  # finding 21: derive, never distribute
        self.roster_addrs = roster_addrs
        self.store = ChainStore(store_path)
        self.genesis: fold.Genesis = {"manager_pub": manager_pub}
        self.cfg = QuorumConfig(roster=roster, epoch=epoch, client_fp=pub)
        self._lock = threading.Lock()  # guards store + chain head + frontier
        self._exhausted: set[bytes] = set()  # ops whose drive gave up -> `unknown`
        self._lost: dict[bytes, bytes] = {}  # our_op -> winner (a rival took the slot)
        self._closing = threading.Event()
        self._final_frontier = HLC(0, 0)
        self._hlc_wall = 0
        self._hlc_ctr = 0
        for op in control_ops or []:  # the authorization chain (certs/genesis)
            self.store.put_op_raw(op)
        self._seq, self._prev = self._chain_head()
        # read-side freshness (finding 22): a background quorum-read pull keeps
        # `local`/`INSPECT` current with OTHER clients' committed writes; `final`
        # reads sync on demand (below). Correctness never depends on the cadence.
        threading.Thread(target=self._refresh_loop, daemon=True).start()

    # ---- chain head + clock ------------------------------------------------ #
    def _chain_head(self) -> tuple[int, bytes]:
        """This client's next (seq, prev) — derived from its own ops in the store
        so a restart resumes the lineage (no session state)."""
        mine = [o for o in self.store.all_ops() if o.author == self.pub]
        if not mine:
            return 0, A.GENESIS_PREV
        head = max(mine, key=lambda o: o.seq)
        return head.seq + 1, head.op_hash

    def _next_hlc(self) -> HLC:
        """A strictly-monotone HLC for this client's authored ops: wall-clock ms,
        with the counter breaking ties (and carrying a stalled/backwards clock)."""
        wall = int(time.time() * 1000)
        if wall > self._hlc_wall:
            self._hlc_wall, self._hlc_ctr = wall, 0
        else:
            self._hlc_ctr += 1
        return HLC(self._hlc_wall, self._hlc_ctr)

    # ---- node RPC (real sockets; the p2p wire) ----------------------------- #
    def _rpc(self, node: int, req: Request) -> Response | None:
        """Send `req` to a node inside a signed L_msg envelope and return its verified
        reply (PROTOCOL §7.5). The transport owns the socket I/O; `lmsg` does the pure
        encode/verify. A reply that isn't signed by the addressed node is no reply —
        `None` here means 'no usable response from this node this round' (the reason is
        available for logging in a later pass, but the quorum driver needs only that)."""
        if self._closing.is_set():
            return None
        path, to_pub = self.roster_addrs[node], self.cfg.roster[node]
        out = lmsg.author(
            self.sk,
            to_pub,
            b"",
            wire.encode_request(req),
            epoch=self.cfg.epoch,
            ts=int(time.time() * 1000),
        ).encode()
        try:
            with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as s:
                s.settimeout(5.0)
                s.connect(path)
                s.sendall(wire.frame(out))
                raw = wire.read_frame(s.recv) or b""
        except OSError:
            return None
        match lmsg.classify_reply(raw, expect_from=to_pub, expect_to=self.pub):
            case lmsg.Reply(env):
                return wire.decode_response(env.body)
            case lmsg.Unusable(_reason):
                return None

    def _push_qc(self, qc: QC) -> None:
        for node in self.cfg.fanout_order:
            self._rpc(node, PutQCReq(qc))  # best-effort durability of the commit proof

    # ---- authoring --------------------------------------------------------- #
    def _author(
        self,
        slot: Slot | None,
        guards: list[list[bytes]],
        mutations: list[list[bytes]],
    ) -> Op:
        ring = self.keyring[self.keyepoch]
        slot_tag = None
        if slot is not None:
            path, version, attempt = slot
            slot_tag = compute_slot_tag(ring["slot_secret"], path, version, attempt)
        txn = Txn(slot=slot, guards=guards, mutations=mutations)
        with self._lock:
            op = A.Op.build_data(
                author_sk=self.sk,
                author_pub=self.pub,
                seq=self._seq,
                prev=self._prev,
                hlc=self._next_hlc(),
                deps=[],
                authz=b"cert",
                keyepoch=self.keyepoch,
                data_key=ring["data_key"],
                txn_bytes=txn.encode(),
                slot_tag=slot_tag,
            )
            self._seq += 1
            self._prev = op.op_hash
            self.store.put_op_raw(op)  # hold our own op so the ladder can see in-flight
        return op

    # ---- the public submit path (returns immediately, drives in bg) -------- #
    def submit(
        self,
        slot: Slot | None,
        guards: list[list[bytes]],
        mutations: list[list[bytes]],
    ) -> bytes:
        """Author a TXN and start driving it to a QC in the background. Returns the
        op_hash ticket immediately (CLIENT.md §1: nothing blocks)."""
        op = self._author(slot, guards, mutations)
        threading.Thread(target=self._drive_to_final, args=(op,), daemon=True).start()
        return op.op_hash

    def _drive_to_final(self, op: Op) -> None:
        if op.slot_tag is not None:
            outcome = _drive(Commit(self.cfg, op), self._rpc, stop=self._closing)
            if isinstance(outcome, Committed):
                self._store_qc(outcome.qc)
                self._finalize(op.hlc)  # we won -> finish the job to `final`
            elif isinstance(outcome, LostSlot):
                self._store_qc(outcome.qc)  # hold the rival's proof
                self._lost[op.op_hash] = outcome.winner  # definitive: retry fresh lineage
            else:
                self._exhausted.add(op.op_hash)  # unreachable/exhausted -> `unknown`
            return
        qc = self._commit_blind(op)
        if qc is None:
            self._exhausted.add(op.op_hash)
            return
        self._store_qc(qc)
        self._finalize(op.hlc)

    def _store_qc(self, qc: QC) -> None:
        with self._lock:
            self.store.put_qc(qc)
        self._push_qc(qc)  # best-effort: durability of the commit proof (outside the lock)

    def _commit_blind(self, op: Op) -> QC | None:
        """Slotless (blind) writes race no slot: SUBMIT to the roster, assemble a QC
        from a quorum of BLIND receipts. No PREPARE/ACCEPT — there is nothing to
        contend. RETRANSMITS to still-unanswered nodes until a quorum answers or the
        budget expires (SUBMIT is idempotent, PROTOCOL §0 — the slotted path retries
        via its machine, so the blind path must too, NOTES 54 nit)."""
        receipts: dict[int, Receipt] = {}
        lock = threading.Lock()

        def one(node: int) -> None:
            r = self._rpc(node, SubmitReq(op))
            if isinstance(r, Receipt) and r.op_hash == op.op_hash and r.ballot == BLIND:
                with lock:
                    receipts[node] = r

        deadline = time.monotonic() + BLIND_DEADLINE_S
        while time.monotonic() < deadline and not self._closing.is_set():
            pending = [n for n in self.cfg.fanout_order if n not in receipts]
            threads = [threading.Thread(target=one, args=(n,), daemon=True) for n in pending]
            for t in threads:
                t.start()
            for t in threads:
                t.join(timeout=2.0)
            if len(receipts) >= self.cfg.quorum:
                chosen = list(receipts.values())[: self.cfg.quorum]
                return QC.assemble(chosen, self.cfg.n, self.cfg.roster_index)
            time.sleep(0.05)  # brief backoff before retransmitting to non-responders
        return None

    def _finalize(self, target: HLC) -> None:
        outcome = _drive(Finalize(self.cfg, target), self._rpc, stop=self._closing)
        if isinstance(outcome, Final):
            with self._lock:
                if outcome.frontier > self._final_frontier:
                    self._final_frontier = outcome.frontier

    # ---- read-side sync — the §1.2 quorum read (finding 22) ---------------- #
    def sync(self) -> None:
        """Read a quorum of signed FRONTIERs, PULL every committed op they name that
        we lack (walking each author's chain, fetching op + QC), and advance the
        finality frontier to the one a quorum attests. This is what lets client B
        see client A's committed writes — the daemon's fold ranges over ops it
        HOLDS, so it must pull the rest (PROTOCOL §1.2)."""
        bundles = self._quorum_frontiers()
        if len(bundles) < self.cfg.quorum:
            return  # couldn't read a quorum — leave the view as-is (never guess)
        heads: dict[bytes, tuple[int, bytes]] = {}
        for fb in bundles:
            for author, (seq, hh) in fb.heads.items():
                if author not in heads or seq > heads[author][0]:
                    heads[author] = (seq, hh)
        for _, head_hash in heads.values():
            self._pull_chain(head_hash)
        # the highest hlc a quorum attests final = the q-th highest floor (DESIGN §9)
        floors = sorted((fb.floor for fb in bundles), key=lambda h: h.as_tuple(), reverse=True)
        qfloor = floors[self.cfg.quorum - 1]
        with self._lock:
            if qfloor > self._final_frontier:
                self._final_frontier = qfloor

    def _quorum_frontiers(self) -> list:
        bundles: list = []
        lock = threading.Lock()

        def one(node: int) -> None:
            r = self._rpc(node, FrontierReq())
            if isinstance(r, A.FrontierBundle):
                with lock:
                    bundles.append(r)

        threads = [
            threading.Thread(target=one, args=(n,), daemon=True) for n in self.cfg.fanout_order
        ]
        for t in threads:
            t.start()
        for t in threads:
            t.join(timeout=2.0)
        return bundles

    def _pull_chain(self, head_hash: bytes) -> None:
        """Walk an author's chain back from `head_hash`, fetching each op + its QC we
        lack, until we reach an op we already hold (below is present) or GENESIS."""
        h = head_hash
        while h and h != A.GENESIS_PREV:
            with self._lock:
                op = self.store.get_op(h)
            have = op is not None
            if op is None:
                fetched = self._one_of(FetchOpReq(h))
                if not isinstance(fetched, Op):
                    return  # gap we can't fill now; a later round retries
                op = fetched
                with self._lock:
                    self.store.put_op_raw(op)
            with self._lock:
                have_qc = self.store.get_qc(h) is not None
            if not have_qc:
                qc = self._one_of(GetQCReq(h))
                if isinstance(qc, QC):
                    with self._lock:
                        self.store.put_qc(qc)
            if have:
                return  # we already held this op — the rest of the chain is present
            h = op.prev

    def _one_of(self, req: Request) -> Response | None:
        """Try each reachable node in fanout order; return the first real response."""
        for node in self.cfg.fanout_order:
            r = self._rpc(node, req)
            if r is not None:
                return r
        return None

    def _refresh_loop(self) -> None:
        while not self._closing.wait(REFRESH_MS / 1000.0):
            try:
                self.refresh_addrs()  # pick up ENDPOINT records for the roster
                self.sync()
            except OSError:
                pass  # a transient unreachability; the next tick retries

    # ---- the folded read model (STATUS/GET/LIST/INSPECT derive from here) --- #
    def _committed_ops(self, *, final_only: bool = False) -> list[Op]:
        """The committed set the daemon holds: all control ops (the authorization
        chain) + every data op that carries a QC. `final_only` keeps only data ops
        at/under the finality frontier (the frozen view)."""
        out: list[Op] = []
        for o in self.store.all_ops():
            if o.is_control:
                out.append(o)
            elif self.store.get_qc(o.op_hash) is not None:
                if final_only and o.hlc > self._final_frontier:
                    continue
                out.append(o)
        return out

    def _fold(self, *, final_only: bool = False) -> fold.FoldResult:
        return fold.fold(self._committed_ops(final_only=final_only), self.keyring, self.genesis)

    def _slot_winner(self, slot_tag: bytes) -> bytes | None:
        """The op_hash committed (QC'd) for a slot tag, if any."""
        for o in self.store.all_ops():
            if o.slot_tag == slot_tag and self.store.get_qc(o.op_hash) is not None:
                return o.op_hash
        return None

    def status(self, op_hash: bytes) -> Ladder:
        with self._lock:
            qc = self.store.get_qc(op_hash)
            if qc is not None:
                prov = self._fold().verdicts.get(op_hash)
                is_final = qc.op_hash == op_hash and self._is_final(op_hash)
                pv = prov.value if prov is not None else None
                return Ladder(
                    phase="committed",
                    provisional=pv,
                    final=pv if is_final else None,
                    may_flip=not is_final,
                )
            lost_to = self._lost.get(op_hash)
            if lost_to is not None:
                return Ladder(phase="lost", winner=lost_to)
            op = self.store.get_op(op_hash)
            if op is not None and op.slot_tag is not None:
                winner = self._slot_winner(op.slot_tag)
                if winner is not None and winner != op_hash:
                    return Ladder(phase="lost", winner=winner)
            if op_hash in self._exhausted:
                return Ladder(phase="unknown")
            return Ladder(phase="in-flight")

    def _is_final(self, op_hash: bytes) -> bool:
        op = self.store.get_op(op_hash)
        return op is not None and op.hlc <= self._final_frontier

    def get(self, path: bytes, *, level: str = "local") -> dict:
        """The value at `path` + its (version, attempt) fencing token + tier.
        `level=final` folds only the frozen (≤ frontier) set — and syncs a quorum
        read FIRST, so the frozen view is linearizable, not frozen-but-partial."""
        if level == "final":
            self.sync()  # on-demand §1.2 read (outside the lock — it takes it itself)
        with self._lock:
            final_only = level == "final"
            res = self._fold(final_only=final_only)
            version, attempt = res.lineage(path)
            present = path in res.state
            tier = "final" if (present and self._version_final(version)) else "local"
            return {
                "value": res.state.get(path),
                "version": version,
                "attempt": attempt,
                "present": present,
                "as_of": self._final_frontier if final_only else self._held_frontier(),
                "tier": tier,
            }

    def _version_final(self, version: bytes) -> bool:
        if version == A.VERSION_ABSENT:
            return False
        setter = self.store.get_op(version)
        return setter is not None and setter.hlc <= self._final_frontier

    def _held_frontier(self) -> HLC:
        hi = HLC(0, 0)
        for o in self.store.all_ops():
            if not o.is_control and self.store.get_qc(o.op_hash) is not None and o.hlc > hi:
                hi = o.hlc
        return hi

    def list_keys(
        self, prefix: bytes, *, delimiter: bytes | None = None, level: str = "local"
    ) -> list[dict]:
        if level == "final":
            self.sync()  # linearizable prefix scan (ZK: enumeration is fold-local)
        with self._lock:
            res = self._fold(final_only=(level == "final"))
            seen: dict[bytes, dict] = {}
            for key in res.state:
                if not key.startswith(prefix):
                    continue
                name = key
                if delimiter is not None:
                    rest = key[len(prefix) :]
                    idx = rest.find(delimiter)
                    if idx >= 0:  # S3-style common prefix (immediate child group)
                        name = prefix + rest[: idx + 1]
                        seen.setdefault(name, {"key": name, "prefix": True})
                        continue
                version, attempt = res.lineage(key)
                seen[name] = {
                    "key": key,
                    "prefix": False,
                    "version": version,
                    "attempt": attempt,
                    "pending": not self._version_final(version),
                }
            return [seen[k] for k in sorted(seen)]

    def inspect(self, path: bytes) -> dict:
        """Key-centric recovery view (CLIENT.md §3): the frozen `final` verdict, the
        live `provisional` value (+may_flip), and every known not-yet-final op
        touching the key WITH DECODED INTENT (the daemon holds the keyring)."""
        with self._lock:
            res = self._fold()
            version, attempt = res.lineage(path)
            present = path in res.state
            final_res = self._fold(final_only=True)
            fpresent = path in final_res.state
            pending = self._pending_for(path)
            return {
                "final": {
                    "present": fpresent,
                    "value": final_res.state.get(path),
                    "version": final_res.lineage(path)[0],
                },
                "provisional": {
                    "present": present,
                    "value": res.state.get(path),
                    "version": version,
                    "attempt": attempt,
                },
                # may_flip is TRUE whenever the view isn't frozen — including an
                # ABSENT key with a not-yet-final op that could make it present (an
                # uncommitted-displaceable delete flips absence, NOTES 54 nit), not
                # only a present-but-unfrozen value.
                "may_flip": bool(pending) or (present and not self._version_final(version)),
                "pending": pending,
            }

    def _pending_for(self, path: bytes) -> list[dict]:
        """Every held op touching `path` that is not yet final, with decoded intent.
        Complete for ops authored through this daemon; foreign in-flight arrives via
        gossip (not wired in WP2 — the daemon still decodes whatever it holds)."""
        out: list[dict] = []
        for o in self.store.all_ops():
            if o.is_control:
                continue
            if self._is_final(o.op_hash):
                continue
            intent = self._decode_intent(o, path)
            if intent is None:
                continue
            out.append({"op": o.op_hash, "phase": self._phase_nolock(o), "would": intent})
        return out

    def _phase_nolock(self, op: Op) -> str:
        if self.store.get_qc(op.op_hash) is not None:
            return "committed"
        if op.slot_tag is not None:
            w = self._slot_winner(op.slot_tag)
            if w is not None and w != op.op_hash:
                return "lost"
        return "unknown" if op.op_hash in self._exhausted else "in-flight"

    def _decode_intent(self, op: Op, path: bytes) -> list[list[bytes]] | None:
        """Decode op's Txn (keyring-privileged) and return the mutations touching
        `path`, or None if it does not touch the key / cannot be read."""
        d = data_handler.decode(op, self.keyring)
        if isinstance(d, data_handler.Opaque):
            return None
        touching = [m for m in d.mutations if len(m) >= 2 and m[1] == path]
        return touching or None

    def refresh_addrs(self, transport: bytes = b"unix") -> None:
        """Derive `roster_addrs` from the ENDPOINT control ops I hold (PROTOCOL §7 /
        NOTES 58) — the control plane is the node registry. Keeps the existing entry
        for any roster member with no endpoint record yet (bootstrap fallback)."""
        with self._lock:
            book = fold.endpoints_of(self.store.all_ops(), self.manager_pub)
            new = list(self.roster_addrs)
            for i, pub in enumerate(self.cfg.roster):
                uri = next((u.decode() for (t, u, _o) in book.get(pub, []) if t == transport), None)
                if uri is not None and i < len(new):
                    new[i] = uri
            self.roster_addrs = new

    def close(self) -> None:
        """Signal in-flight drives to abort, let them wind down, then close the
        store (so a lingering finalize thread never touches a closed DB)."""
        self._closing.set()
        time.sleep(0.15)
        self.store.close()
