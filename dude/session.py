
import time
import unicodedata
from dataclasses import dataclass, field
from typing import Protocol

from .core import codec, crypto
from .core.errors import DudeError
from .core.units import now_ms
from .net.envelope import MessageId, Verb
from .store import ops
from .store.layer import Held
from .store.management import blind_key, epoch_key, wrap_key


class SessionError(DudeError): ...


@dataclass(frozen=True, slots=True)
class Record:
    name: str | bytes
    store_id: int
    token: bytes
    value: bytes
    raw: bytes
    epoch: int
    absent: bool


from .store.layer import Settled


@dataclass(frozen=True, slots=True)
class Refused:
    reason: str


@dataclass(frozen=True, slots=True)
class Dropped:
    pass


type SubmitResult = Settled | Refused | Dropped


@dataclass(slots=True)
class SubmitHandle:
    mid: MessageId
    op_hash: crypto.Digest
    _sub: "Substrate"
    peer: crypto.PublicKey | None = None
    _accepted: bool = False
    _refused_reason: str | None = None

    def resolve(self, verb: int, body: bytes) -> None:
        if verb == Verb.ACCEPTED:
            self._accepted = True
        elif verb == Verb.REFUSED:
            self._refused_reason = body.decode("utf-8", errors="replace")

    def expire(self) -> None:
        if not self._accepted and self._refused_reason is None:
            self._refused_reason = "expired"

    def wait(self) -> SubmitResult:
        if self._refused_reason is not None:
            return Refused(self._refused_reason)
        evict = self._sub.evict_after_sec()
        deadline = time.monotonic() + evict
        while time.monotonic() < deadline:
            if self._refused_reason is not None:
                return Refused(self._refused_reason)
            result = self._sub.settled(self.op_hash, self.peer)
            if result is not None:
                return result
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                break
            self._sub.wait_for_commit(min(remaining, evict))
        return Dropped()


class Substrate(Protocol):
    def get(self, store_id: int, name: bytes) -> Held | None: ...
    def submit(self, tx: ops.SignedTransaction) -> SubmitHandle: ...
    def settled(self, op_hash: crypto.Digest, peer: crypto.PublicKey | None = None) -> Settled | None: ...
    def evict_after_sec(self) -> float: ...
    def wait_for_commit(self, timeout: float) -> None: ...


@dataclass(slots=True)
class _StoreKeys:
    blinding: crypto.Master | None = None
    name_key: crypto.NameKey | None = None
    masters: dict[int, crypto.Master] = field(default_factory=dict)
    current_epoch: int | None = None


class KeyCache:
    __slots__ = ("_kp", "_stores", "_sub")

    def __init__(self, kp: crypto.Keypair, sub: Substrate) -> None:
        self._kp = kp
        self._sub = sub
        self._stores: dict[int, _StoreKeys] = {}

    def _keys(self, store_id: int) -> _StoreKeys:
        sk = self._stores.get(store_id)
        if sk is None:
            sk = _StoreKeys()
            self._stores[store_id] = sk
        return sk

    def ensure_blinding(self, store_id: int) -> crypto.NameKey:
        sk = self._keys(store_id)
        if sk.name_key is not None:
            return sk.name_key
        raw = self._sub.get(ops.STORE_MANAGEMENT, blind_key(store_id, self._kp.public))
        if raw is None:
            raise SessionError(
                f"{self._kp.public.hex()[:8]} has no blinding key for store {store_id}"
            )
        sk.blinding = crypto.Master(self._kp.open_sealed_raw(crypto.SealedBlob(raw.value)))
        sk.name_key = crypto.derive_name_key(sk.blinding)
        return sk.name_key

    def value_key(self, store_id: int, epoch: int) -> crypto.ValueKey:
        sk = self._keys(store_id)
        if epoch not in sk.masters:
            raw = self._sub.get(
                ops.STORE_MANAGEMENT, wrap_key(store_id, epoch, self._kp.public),
            )
            if raw is None:
                raise SessionError(
                    f"{self._kp.public.hex()[:8]} has no wrap for store {store_id} epoch {epoch}"
                )
            sk.masters[epoch] = crypto.Master(
                self._kp.open_sealed_raw(crypto.SealedBlob(raw.value))
            )
        return crypto.EpochKeys.derive(sk.masters[epoch]).value_key

    def current_epoch(self, store_id: int) -> int:
        sk = self._keys(store_id)
        if sk.current_epoch is not None:
            return sk.current_epoch
        raw = self._sub.get(ops.STORE_MANAGEMENT, epoch_key(store_id))
        if raw is None:
            raise SessionError(f"no epoch for store {store_id}")
        sk.current_epoch = codec.as_int(codec.decode(raw.value))
        return sk.current_epoch


class Session:
    __slots__ = ("_keys", "_kp", "_store_id", "_sub")

    def __init__(self, sub: Substrate, kp: crypto.Keypair, store_id: int, keys: KeyCache) -> None:
        self._sub = sub
        self._kp = kp
        self._store_id = store_id
        self._keys = keys

    @property
    def store_id(self) -> int:
        return self._store_id

    def token(self, name: str | bytes) -> bytes:
        if self._store_id == ops.STORE_MANAGEMENT:
            return name if isinstance(name, bytes) else name.encode()
        if not isinstance(name, str):
            raise SessionError("data store keys must be str, not bytes")
        nk = self._keys.ensure_blinding(self._store_id)
        return crypto.derive_name_token(nk, _name_bytes(name))

    def _aad(self, token: bytes, epoch: int) -> bytes:
        return codec.encode([self._store_id, bytes(token), epoch])

    def _decrypt(self, name: str | bytes, ciphertext: bytes, epoch: int) -> bytes:
        if self._store_id == ops.STORE_MANAGEMENT:
            return ciphertext
        nt = crypto.NameToken(self.token(name))
        vk = self._keys.value_key(self._store_id, epoch)
        item = crypto.derive_item_key(vk, nt)
        return crypto.AeadXcs1.open(item, self._aad(nt, epoch), crypto.AeadBlob(ciphertext))

    def seal(self, name: str | bytes, value: bytes) -> tuple[bytes, bytes, int]:
        if self._store_id == ops.STORE_MANAGEMENT:
            return self.token(name), value, ops.EPOCH_NONE
        epoch = self._keys.current_epoch(self._store_id)
        nt = crypto.NameToken(self.token(name))
        vk = self._keys.value_key(self._store_id, epoch)
        item = crypto.derive_item_key(vk, nt)
        return nt, bytes(crypto.AeadXcs1.seal(item, self._aad(nt, epoch), value)), epoch

    # -- public interface ---------------------------------------------------

    def get(self, name: str | bytes) -> Record:
        token = self.token(name)
        raw = self._sub.get(self._store_id, token)
        if raw is None:
            return Record(
                name=name, store_id=self._store_id, token=token,
                value=b"", raw=b"", epoch=0, absent=True,
            )
        plaintext = self._decrypt(name, raw.value, raw.epoch)
        return Record(
            name=name, store_id=self._store_id, token=token,
            value=plaintext, raw=raw.value, epoch=raw.epoch, absent=False,
        )

    def put(
        self,
        name: str,
        value: bytes,
        *predicates: ops.Predicate | Record,
        expect: Record | None = None,
        absent: bool = False,
    ) -> SubmitHandle:
        token, sealed, epoch = self.seal(name, value)
        guards = _collect_guards(self._store_id, token, predicates, expect, absent)
        tx = ops.Transaction((ops.Step(guards, ops.Set(self._store_id, token, sealed, epoch)),))
        return self.submit(tx)

    def delete(
        self,
        name: str,
        *predicates: ops.Predicate | Record,
        expect: Record | None = None,
    ) -> SubmitHandle:
        token = self.token(name)
        guards = _collect_guards(self._store_id, token, predicates, expect, False)
        tx = ops.Transaction((ops.Step(guards, ops.Del(self._store_id, token)),))
        return self.submit(tx)

    def compact(self, block_num: int) -> SubmitHandle:
        from .store.management import P_COMPACT  # noqa: PLC0415
        held = self._sub.get(ops.STORE_MANAGEMENT, P_COMPACT)
        guard: ops.Predicate
        if held is None:
            guard = ops.Absent(ops.STORE_MANAGEMENT, P_COMPACT)
        else:
            guard = ops.Holds(ops.STORE_MANAGEMENT, P_COMPACT, ops.value_digest(held.value))
        value = block_num.to_bytes(8, "big")
        tx = ops.Transaction((ops.Step((guard,), ops.Set(ops.STORE_MANAGEMENT, P_COMPACT, value)),))
        return self.submit(tx)

    def begin(self) -> "TxBuilder":
        return TxBuilder(self)

    def submit(self, tx: ops.Transaction) -> SubmitHandle:
        signed = tx.sign(self._kp, now_ms())
        return self._sub.submit(signed)


class TxBuilder:
    def __init__(self, session: Session) -> None:
        self._session = session
        self._steps: list[ops.Step] = []

    def put(
        self,
        name: str,
        value: bytes,
        *predicates: ops.Predicate | Record,
        expect: Record | None = None,
        absent: bool = False,
    ) -> "TxBuilder":
        s = self._session
        token, sealed, epoch = s.seal(name, value)
        guards = _collect_guards(s.store_id, token, predicates, expect, absent)
        self._steps.append(ops.Step(guards, ops.Set(s.store_id, token, sealed, epoch)))
        return self

    def delete(
        self,
        name: str,
        *predicates: ops.Predicate | Record,
        expect: Record | None = None,
    ) -> "TxBuilder":
        s = self._session
        token = s.token(name)
        guards = _collect_guards(s.store_id, token, predicates, expect, False)
        self._steps.append(ops.Step(guards, ops.Del(s.store_id, token)))
        return self

    def submit(self) -> SubmitHandle:
        if not self._steps:
            raise SessionError("empty transaction")
        tx = ops.Transaction(tuple(self._steps))
        return self._session.submit(tx)


def _collect_guards(
    store_id: int,
    token: bytes,
    predicates: tuple[ops.Predicate | Record, ...],
    expect: Record | None,
    absent: bool,
) -> tuple[ops.Predicate, ...]:
    out: list[ops.Predicate] = []
    for p in predicates:
        if isinstance(p, Record):
            if p.absent:
                raise SessionError("cannot use an absent record as a dependency")
            out.append(ops.Holds(p.store_id, p.token, ops.value_digest(p.raw)))
        else:
            out.append(p)
    if expect is not None:
        if expect.absent:
            raise SessionError("expected record is absent; use absent=True instead")
        out.append(ops.Holds(store_id, token, ops.value_digest(expect.raw)))
    if absent:
        out.append(ops.Absent(store_id, token))
    return tuple(out)


def _name_bytes(name: str) -> bytes:
    return unicodedata.normalize("NFC", name).encode("utf-8")
