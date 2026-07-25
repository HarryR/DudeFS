# Test scenario builder — deterministic, seeded worlds and committed-set
# "soups" for the A-hypothesis property tests (IMPLEMENTATION.md §6).
#
# Everything here is pure and reproducible from a seed; a failing property
# test replays from its seed.

from __future__ import annotations

import random
import time
from collections.abc import Callable
from dataclasses import dataclass, field
from functools import partial

from dudefs import artifacts as A
from dudefs import codec, fold
from dudefs import crypto as C

# --------------------------------------------------------------------------- #
# Shared test helpers (NOTES 57 item 4) — consolidated so the refactor touches  #
# one place instead of a copy per file.                                        #
# --------------------------------------------------------------------------- #


def now_ms() -> int:
    """Wall-clock ms — the real clock socket/daemon tests inject as `now_ms`."""
    return int(time.time() * 1000)


def poll_until[T](pred: Callable[[], T], timeout: float = 6.0, step: float = 0.02) -> T:
    """Poll `pred()` until truthy (returns it) or timeout (returns the last value) —
    the socket tests' async settle loop. Generic in `pred`'s result so a `-> bool`
    predicate stays `bool` at the call site (no `object` widening)."""
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
    §7.5 cutover (a bare request no longer reaches a gated daemon). Takes a raw seed at
    this test boundary and lifts it to a Keypair (the sole seed→identity conversion)."""
    from dudefs import lmsg, wire

    return lmsg.author(
        C.SoftwareKeypair.from_seed(sk),
        C.PublicKey(to_pub),
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
    expect_to = C.SoftwareKeypair.from_seed(sk).public
    match lmsg.classify_reply(reply, expect_from=daemon.pub, expect_to=expect_to):
        case lmsg.Reply(env):
            return wire.decode_response(env.body)
        case _fault:  # NoReply / MalformedReply / WrongPeer
            return None


def cut_of(w: World) -> A.Heads:
    """The frontier of everything authored so far (per-author (seq, prev))."""
    cut: A.Heads = {c.pub: (c.seq - 1, c.prev) for c in w.clients if c.seq > 0}
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
    """A client's signing identity + its mutable chain head (seq/prev). `key` is the
    typed authoring identity; the raw `sk` is retained for the forging helpers (which
    hand-sign arbitrary/garbage envelopes the typed builds refuse to author)."""

    sk: bytes
    pub: bytes
    seq: int = 0
    prev: bytes = A.GENESIS_PREV
    key: C.Keypair = field(init=False)

    def __post_init__(self) -> None:
        self.key = C.SoftwareKeypair.from_seed(self.sk)


class World:
    """A manager, some authorized clients, and a multi-epoch keyring. Tracks
    per-client chain heads so generated chains are structurally valid."""

    def __init__(self, seed: int = 0, n_clients: int = 2, epochs: tuple[int, ...] = (0,)):
        self.rng = random.Random(seed)
        self.mgr_sk, self.mgr_pub = _seed_keypair(self.rng)
        self.mgr_key: C.Keypair = C.SoftwareKeypair.from_seed(self.mgr_sk)
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
            self.control_ops.append(
                self._mgr_op(
                    partial(A.CertIssueOp.build, subject=c.pub, caps=[A.Cap.WRITE], epoch=0)
                )
            )
            for e, m in sorted(self.masters.items()):
                self.control_ops.append(
                    self._mgr_op(
                        partial(A.WrapSetOp.build, keyepoch=e, group_key=m, members=[c.pub])
                    )
                )

    # ---- clocks ---------------------------------------------------------- #
    def tick(self) -> A.HLC:
        self._hlc += 1
        return A.HLC(self._hlc, 0)

    # ---- manager (control) ops ------------------------------------------- #
    def _mgr_op(self, build: Callable[..., A.Op]) -> A.Op:
        """Author the next manager control op. `build` is a leaf `build` classmethod
        pre-bound with its typed body kwargs (via functools.partial); this supplies the
        envelope position (seq/prev/hlc) and advances the manager chain head. The built
        op is re-ingested via `from_bytes` so its LEAF identity comes from its bytes (a
        malformed body — e.g. an even roster — resolves to InvalidOp, mirroring the wire)."""
        built = build(
            author=self.mgr_key,
            seq=self._mseq,
            prev=self._mprev,
            hlc=self.tick(),
        )
        op = A.Op.from_bytes(built.raw)
        self._mseq += 1
        self._mprev = op.op_hash
        return op

    def _mgr_raw(self, body: bytes) -> A.Op:
        """Author a manager control op carrying an ARBITRARY raw `body` — for malformed or
        unknown-kind bodies that must fold `invalid`. Signed as a CONTROL envelope and
        re-ingested via `from_bytes` (yielding the InvalidOp leaf its bytes decode to)."""
        f: dict[A.Field, A.Bencodable] = {
            A.Field.CLASS: A.OpClass.CONTROL,
            A.Field.AUTHOR: self.mgr_pub,
            A.Field.SEQ: int(self._mseq),
            A.Field.PREV: self._mprev,
            A.Field.HLC: self.tick().encode(),
            A.Field.PVER: 0,
            A.Field.PAYLOAD: body,
        }
        f[A.Field.SIG] = C.SIGNER.sign(self.mgr_sk, codec.encode(f))
        op = A.Op.from_bytes(codec.encode(f))
        self._mseq += 1
        self._mprev = op.op_hash
        return op

    def _reslot(self, op: A.Op, slot_tag: bytes) -> A.Op:
        """Re-sign `op` with a DIFFERENT envelope slot_tag — used only to forge a
        seq/slot MISMATCH (a validly-signed checkpoint that contends a slot its declared
        seq does not bind). Public builds bind the slot to the seq, so the forgery must
        go through the raw envelope."""
        env = codec.as_dict(codec.decode(op.raw))
        env.pop(A.Field.SIG, None)
        env[A.Field.SLOT_TAG] = slot_tag
        env[A.Field.SIG] = C.SIGNER.sign(self.mgr_sk, codec.encode(env))
        return A.Op.from_bytes(codec.encode(env))

    def rotate(self, keyepoch: int) -> A.Op:
        op = self._mgr_op(partial(A.RotateOp.build, keyepoch=keyepoch))
        self.control_ops.append(op)
        return op

    def revoke(self, client_index: int) -> A.Op:
        op = self._mgr_op(partial(A.CertRevokeOp.build, subject=self.clients[client_index].pub))
        self.control_ops.append(op)
        return op

    def checkpoint(
        self,
        cut: A.Heads | None = None,
        state_acc: bytes = b"",
        dead: list[bytes] | None = None,
        retained: dict[bytes, A.RetainedEntry] | None = None,
        attempts: bytes = b"",
        keyepoch: int = 0,
        horizon: A.HLC | None = None,
        seq: int = 0,
        slot_seq: int | None = None,
    ) -> A.Op:
        # slot_seq defaults to seq (the correct binding); a test may set it apart to forge a
        # seq/slot MISMATCH — an op that claims one sequence but contends another's slot.
        baseline = A.Baseline(cut or {}, retained or {}, frozenset(dead or []))
        cseq = seq  # the checkpoint (body) sequence — distinct from the envelope seq below

        def _build(*, author: C.Keypair, seq: int, prev: bytes, hlc: A.HLC) -> A.Op:
            op = A.CheckpointOp.build(
                author=author,
                seq=seq,
                prev=prev,
                hlc=hlc,
                baseline=baseline,
                state_acc=state_acc,
                attempts=attempts,
                keyepoch=keyepoch,
                horizon=horizon or A.HLC(0, 0),
                checkpoint_seq=cseq,
            )
            if slot_seq is not None and slot_seq != cseq:
                op = self._reslot(op, A.checkpoint_slot_tag(slot_seq))
            return op

        op = self._mgr_op(_build)
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
        hlc = hlc or self.tick()
        data_key = self.keyring[keyepoch].data_key
        txn_bytes = txn.encode()
        op: A.Op
        if slot_tag is None:
            op = A.BlindPutOp.build(
                author=c.key,
                seq=c.seq,
                prev=c.prev,
                hlc=hlc,
                keyepoch=keyepoch,
                data_key=data_key,
                txn_bytes=txn_bytes,
            )
        else:
            op = A.CasOp.build(
                author=c.key,
                seq=c.seq,
                prev=c.prev,
                hlc=hlc,
                keyepoch=keyepoch,
                data_key=data_key,
                txn_bytes=txn_bytes,
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
        secret = self.keyring[keyepoch].slot_secret
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
        op = self._forged_data(
            c.sk,
            c.pub,
            seq=c.seq,
            prev=c.prev,
            hlc=self.tick(),
            keyepoch=keyepoch,
            payload=garbage,
            slot_tag=slot_tag,
        )
        c.seq += 1
        c.prev = op.op_hash
        return op

    @staticmethod
    def _forged_data(
        sk: bytes,
        pub: bytes,
        *,
        seq: int,
        prev: bytes,
        hlc: A.HLC,
        keyepoch: int,
        payload: bytes,
        slot_tag: bytes | None,
        pver: int = 0,
    ) -> A.Op:
        """A hand-signed DATA op carrying an ARBITRARY (here: garbage) payload. The public
        data builds seal real txn bytes, so an un-openable payload must go through the raw
        envelope (DESIGN §6 — participates only by tag-equality)."""
        f: dict[A.Field, A.Bencodable] = {
            A.Field.CLASS: A.OpClass.DATA,
            A.Field.AUTHOR: pub,
            A.Field.SEQ: int(seq),
            A.Field.PREV: prev,
            A.Field.HLC: hlc.encode(),
            A.Field.PVER: int(pver),
            A.Field.KEYEPOCH: int(keyepoch),
            A.Field.PAYLOAD: payload,
        }
        if slot_tag is not None:
            f[A.Field.SLOT_TAG] = slot_tag
        f[A.Field.SIG] = C.SIGNER.sign(sk, codec.encode(f))
        return A.Op.from_bytes(codec.encode(f))

    def all_control(self) -> list[A.Op]:
        return list(self.control_ops)
