# Test scenario builder — deterministic, seeded worlds and committed-set
# "soups" for the A-hypothesis property tests (IMPLEMENTATION.md §6).
#
# Everything here is pure and reproducible from a seed; a failing property
# test replays from its seed.

from __future__ import annotations

import random
import time
from collections.abc import Callable, Mapping
from dataclasses import dataclass

from dudefs import artifacts as A
from dudefs import crypto as C
from dudefs import fold
from dudefs.handlers import control as ctl

# --------------------------------------------------------------------------- #
# Shared test helpers (NOTES 57 item 4) — consolidated so the refactor touches  #
# one place instead of a copy per file.                                        #
# --------------------------------------------------------------------------- #


def now_ms() -> int:
    """Wall-clock ms — the real clock socket/daemon tests inject as `now_ms`."""
    return int(time.time() * 1000)


def poll_until(pred: Callable[[], object], timeout: float = 6.0, step: float = 0.02):
    """Poll `pred()` until truthy (returns it) or timeout (returns the last value) —
    the socket tests' async settle loop."""
    deadline = time.monotonic() + timeout
    val = pred()
    while not val and time.monotonic() < deadline:
        time.sleep(step)
        val = pred()
    return val


def unix_ep(path: str):
    """A local-unix dial Endpoint — the common test address since the transport seam."""
    from dudefs import transports

    return transports.Endpoint(transports.UNIX, path)


def unix_eps(paths) -> list:
    return [unix_ep(p) for p in paths]


def unix_peer(pub: bytes, path: str):
    """A gossip Peer over a local unix socket (identity + Endpoint)."""
    from dudefs.daemon import Peer

    return Peer(pub, unix_ep(path))


def enveloped(sk: bytes, to_pub: bytes, req, *, epoch: int = 0, ts: int | None = None) -> bytes:
    """Wrap a node Request in a signed L_msg envelope — the cluster wire since the
    §7.5 cutover (a bare request no longer reaches a gated daemon)."""
    from dudefs import lmsg, wire

    return lmsg.author(
        sk,
        to_pub,
        b"",
        wire.encode_request(req),
        epoch=epoch,
        ts=ts if ts is not None else now_ms(),
    ).encode()


def call_node(daemon, sk: bytes, req, *, epoch: int = 0, ts: int | None = None):
    """Drive one enveloped node RPC in-process: sign `req` from `sk` to `daemon.pub`,
    serve it, and return the verified Response (or None if refused / silently dropped)."""
    from dudefs import lmsg, wire

    ts = daemon._clock() if ts is None else ts  # stamp within the target's freshness window
    reply = daemon.serve(enveloped(sk, daemon.pub, req, epoch=epoch, ts=ts))
    if reply is None:
        return None
    match lmsg.classify_reply(reply, expect_from=daemon.pub, expect_to=C.SIGNER.public(sk)):
        case lmsg.Reply(env):
            return wire.decode_response(env.body)
        case _fault:  # NoReply / MalformedReply / WrongPeer
            return None


def cut_of(w: World) -> A.Heads:
    """The frontier of everything authored so far (per-author (seq, prev))."""
    cut = {c.pub: (c.seq - 1, c.prev) for c in w.clients if c.seq > 0}
    cut[w.mgr_pub] = (w._mseq - 1, w._mprev)
    return cut


def create(w: World, ci: int, key: bytes, val: bytes) -> A.Op:
    """A creation CAS (absent -> val) on `key` by client `ci`."""
    return w.cas(
        ci, key, A.VERSION_ABSENT, 0, [[A.Guard.ABSENT, key]], [[A.Mutation.SET, key, val]]
    )


def _seed_keypair(rng: random.Random) -> tuple[bytes, bytes]:
    sk = bytes(rng.getrandbits(8) for _ in range(32))
    return sk, C.SIGNER.public(sk)


@dataclass
class Client:
    """A client's signing identity + its mutable chain head (seq/prev)."""

    sk: bytes
    pub: bytes
    seq: int = 0
    prev: bytes = A.GENESIS_PREV


class World:
    """A manager, some authorized clients, and a multi-epoch keyring. Tracks
    per-client chain heads so generated chains are structurally valid."""

    def __init__(self, seed: int = 0, n_clients: int = 2, epochs: tuple[int, ...] = (0,)):
        self.rng = random.Random(seed)
        self.mgr_sk, self.mgr_pub = _seed_keypair(self.rng)
        self.genesis: fold.Genesis = {"manager_pub": self.mgr_pub}
        # a per-epoch master; the working keyring DERIVES from it (finding 21), and the same
        # master is back-wrapped to each client below so a ClientDaemon reconstructs the very
        # same keyring from the log — no hand-delivered keys.
        self.masters: dict[int, bytes] = {
            e: bytes(self.rng.getrandbits(8) for _ in range(32)) for e in epochs
        }
        self.keyring: fold.Keyring = fold.keyring_from_masters(self.masters)
        self.clients: list[Client] = [Client(*_seed_keypair(self.rng)) for _ in range(n_clients)]
        # manager control chain: a cert per client + its full-live-set wraps (issue #2 gap 3)
        self._mseq = 0
        self._mprev = A.GENESIS_PREV
        self._hlc = 1
        self.control_ops: list[A.Op] = []
        for c in self.clients:
            self.control_ops.append(self._mgr_op(ctl.cert_issue_body(c.pub, [ctl.Cap.WRITE], 0)))
            for e, m in sorted(self.masters.items()):
                self.control_ops.append(self._mgr_op(ctl.sealed_wrap_set_body(e, m, [c.pub])))

    # ---- clocks ---------------------------------------------------------- #
    def tick(self) -> A.HLC:
        self._hlc += 1
        return A.HLC(self._hlc, 0)

    # ---- manager (control) ops ------------------------------------------- #
    def _mgr_op(self, payload: bytes, keyepoch: int = 0) -> A.Op:
        op = A.Op.build(
            author_sk=self.mgr_sk,
            author_pub=self.mgr_pub,
            cls_=A.OpClass.CONTROL,
            seq=self._mseq,
            prev=self._mprev,
            hlc=self.tick(),
            deps=[],
            authz=b"root",
            keyepoch=keyepoch,
            payload=payload,
        )
        self._mseq += 1
        self._mprev = op.op_hash
        return op

    def rotate(self, keyepoch: int) -> A.Op:
        op = self._mgr_op(ctl.rotate_body(keyepoch))
        self.control_ops.append(op)
        return op

    def revoke(self, client_index: int) -> A.Op:
        op = self._mgr_op(ctl.cert_revoke_body(self.clients[client_index].pub))
        self.control_ops.append(op)
        return op

    def checkpoint(
        self,
        cut: A.Heads | None = None,
        state_acc: bytes = b"",
        dead: list[bytes] | None = None,
        retained: Mapping[bytes, tuple[int, bytes]] | None = None,
        attempts: bytes = b"",
        keyepoch: int = 0,
        horizon: A.HLC | None = None,
    ) -> A.Op:
        op = self._mgr_op(
            ctl.checkpoint_body(
                cut or {},
                state_acc,
                dead or [],
                retained or {},
                attempts,
                keyepoch,
                horizon or A.HLC(0, 0),
            )
        )
        self.control_ops.append(op)
        return op

    # ---- client (data) ops ----------------------------------------------- #
    def data_op(
        self,
        ci: int,
        *,
        txn: A.Txn,
        slot_tag: bytes | None,
        keyepoch: int = 0,
        hlc: A.HLC | None = None,
    ) -> A.Op:
        c = self.clients[ci]
        op = A.Op.build_data(
            author_sk=c.sk,
            author_pub=c.pub,
            seq=c.seq,
            prev=c.prev,
            hlc=hlc or self.tick(),
            deps=[],
            authz=b"cert",
            keyepoch=keyepoch,
            data_key=self.keyring[keyepoch]["data_key"],
            txn_bytes=txn.encode(),
            slot_tag=slot_tag,
        )
        c.seq += 1
        c.prev = op.op_hash
        return op

    def cas(
        self,
        ci: int,
        key: bytes,
        version: bytes,
        attempt: int,
        guards: list[list[bytes]],
        mutations: list[list[bytes]],
        keyepoch: int = 0,
    ) -> A.Op:
        secret = self.keyring[keyepoch]["slot_secret"]
        tag = A.compute_slot_tag(secret, key, version, attempt)
        txn = A.Txn(slot=(key, version, attempt), guards=guards, mutations=mutations)
        return self.data_op(ci, txn=txn, slot_tag=tag, keyepoch=keyepoch)

    def blind(
        self, ci: int, guards: list[list[bytes]], mutations: list[list[bytes]], keyepoch: int = 0
    ) -> A.Op:
        txn = A.Txn(slot=None, guards=guards, mutations=mutations)
        return self.data_op(ci, txn=txn, slot_tag=None, keyepoch=keyepoch)

    def opaque(self, ci: int, slot_tag: bytes, keyepoch: int = 0) -> A.Op:
        """A data op whose payload will not AEAD-open (garbage) — an
        undecryptable op that participates only by tag-equality (DESIGN §6)."""
        c = self.clients[ci]
        garbage = bytes(self.rng.getrandbits(8) for _ in range(48))  # tag||ct that won't auth
        op = A.Op.build(
            author_sk=c.sk,
            author_pub=c.pub,
            cls_=A.OpClass.DATA,
            seq=c.seq,
            prev=c.prev,
            hlc=self.tick(),
            deps=[],
            authz=b"cert",
            keyepoch=keyepoch,
            payload=garbage,
            slot_tag=slot_tag,
        )
        c.seq += 1
        c.prev = op.op_hash
        return op

    def all_control(self) -> list[A.Op]:
        return list(self.control_ops)
