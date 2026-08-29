import threading
import time
import unicodedata
from abc import ABC, abstractmethod
from dataclasses import dataclass, field

from .core import codec, crypto
from .core.errors import DudeError
from .net.envelope import MessageId, Verb
from .store import ops
from .store.layer import BlockHead, Reader
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


from .store.layer import Index


class SubmitResult(ABC):
    @abstractmethod
    def encode(self) -> bytes: ...

    @classmethod
    def decode(cls, raw: bytes) -> "SubmitResult":
        parts = codec.as_seq(codec.decode(raw))
        tag = codec.as_bytes(parts[0])
        if tag == b"S":
            return Settled(
                crypto.Digest(codec.as_bytes(parts[1])),
                codec.as_int(parts[2]),
                crypto.Digest(codec.as_bytes(parts[3])),
            )
        if tag == b"R":
            return Refused(codec.as_bytes(parts[1]).decode())
        if tag == b"D":
            return Dropped()
        raise DudeError(f"unknown SubmitResult tag: {tag!r}")


@dataclass(frozen=True, slots=True)
class Settled(SubmitResult):
    op_hash: crypto.Digest
    block_num: Index
    block_hash: crypto.Digest

    def encode(self) -> bytes:
        return codec.encode([b"S", self.op_hash, self.block_num, self.block_hash])


@dataclass(frozen=True, slots=True)
class Refused(SubmitResult):
    reason: str

    def encode(self) -> bytes:
        return codec.encode([b"R", self.reason.encode()])


@dataclass(frozen=True, slots=True)
class Dropped(SubmitResult):
    def encode(self) -> bytes:
        return codec.encode([b"D"])


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

    def poll(self) -> SubmitResult | None:
        if self._refused_reason is not None:
            return Refused(self._refused_reason)
        return self._sub.settled(self.op_hash)

    def wait(self) -> SubmitResult:
        evict = self._sub.evict_after_sec()
        deadline = time.monotonic() + evict
        while time.monotonic() < deadline:
            result = self.poll()
            if result is not None:
                return result
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                break
            self._sub.wait_for_commit(min(remaining, evict))
        return Dropped()


class Substrate(Reader, ABC):
    @abstractmethod
    def submit(self, tx: ops.Transaction) -> "SubmitHandle": ...
    @abstractmethod
    def settled(self, op_hash: crypto.Digest) -> "SubmitResult | None": ...
    @abstractmethod
    def evict_after_sec(self) -> float: ...
    @abstractmethod
    def wait_for_commit(self, timeout: float) -> None: ...
    @property
    @abstractmethod
    def commit_cond(self) -> "threading.Condition": ...
    @abstractmethod
    def commit_generation(self) -> int: ...
    @abstractmethod
    def head(self) -> BlockHead | None: ...
    @abstractmethod
    def token(self, store_id: int, name: str) -> bytes: ...
    @abstractmethod
    def seal(self, store_id: int, name: str, value: bytes) -> tuple[bytes, bytes, int]: ...
    @abstractmethod
    def decrypt(self, store_id: int, name: str, ciphertext: bytes, epoch: int) -> bytes: ...


@dataclass(slots=True)
class _StoreKeys:
    blinding: crypto.Master | None = None
    name_key: crypto.NameKey | None = None
    masters: dict[int, crypto.Master] = field(default_factory=dict)
    current_epoch: int | None = None


class KeyCache:
    __slots__ = ("_kp", "_reader", "_stores")

    def __init__(self, kp: crypto.Keypair, reader: Reader) -> None:
        self._kp = kp
        self._reader = reader
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
        raw = self._reader.get(ops.STORE_MANAGEMENT, blind_key(store_id, self._kp.public))
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
            raw = self._reader.get(
                ops.STORE_MANAGEMENT,
                wrap_key(store_id, epoch, self._kp.public),
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
        raw = self._reader.get(ops.STORE_MANAGEMENT, epoch_key(store_id))
        if raw is None:
            raise SessionError(f"no epoch for store {store_id}")
        sk.current_epoch = codec.as_int(codec.decode(raw.value))
        return sk.current_epoch

    def token(self, store_id: int, name: str) -> bytes:
        nk = self.ensure_blinding(store_id)
        return crypto.derive_name_token(nk, unicodedata.normalize("NFC", name).encode())

    def seal(self, store_id: int, name: str, value: bytes) -> tuple[bytes, bytes, int]:
        epoch = self.current_epoch(store_id)
        nt = crypto.NameToken(self.token(store_id, name))
        vk = self.value_key(store_id, epoch)
        item = crypto.derive_item_key(vk, nt)
        aad = codec.encode([store_id, bytes(nt), epoch])
        return nt, bytes(crypto.AeadXcs1.seal(item, aad, value)), epoch

    def decrypt(self, store_id: int, name: str, ciphertext: bytes, epoch: int) -> bytes:
        nt = crypto.NameToken(self.token(store_id, name))
        vk = self.value_key(store_id, epoch)
        item = crypto.derive_item_key(vk, nt)
        aad = codec.encode([store_id, bytes(nt), epoch])
        return crypto.AeadXcs1.open(item, aad, crypto.AeadBlob(ciphertext))


class Session:
    __slots__ = ("_reader", "_store_id")

    def __init__(self, reader: Reader, store_id: int) -> None:
        self._reader = reader
        self._store_id = store_id

    @property
    def anchor(self) -> crypto.PublicKey:
        return self._reader.anchor()

    @property
    def store_id(self) -> int:
        return self._store_id

    def token(self, name: str | bytes) -> bytes:
        if self._store_id == ops.STORE_MANAGEMENT:
            return name if isinstance(name, bytes) else name.encode()
        if not isinstance(name, str):
            raise SessionError("data store keys must be str, not bytes")
        raise SessionError("data store token requires a Substrate with crypto")

    def seal(self, name: str | bytes, value: bytes) -> tuple[bytes, bytes, int]:
        if self._store_id == ops.STORE_MANAGEMENT:
            return self.token(name), value, ops.EPOCH_NONE
        raise SessionError("data store seal requires a Substrate with crypto")

    def _decrypt(self, name: str | bytes, ciphertext: bytes, epoch: int) -> bytes:
        if self._store_id == ops.STORE_MANAGEMENT:
            return ciphertext
        raise SessionError("data store decrypt requires a Substrate with crypto")

    def get(self, name: str | bytes) -> Record:
        token = self.token(name)
        raw = self._reader.get(self._store_id, token)
        if raw is None:
            return Record(
                name=name,
                store_id=self._store_id,
                token=token,
                value=b"",
                raw=b"",
                epoch=0,
                absent=True,
            )
        plaintext = self._decrypt(name, raw.value, raw.epoch)
        return Record(
            name=name,
            store_id=self._store_id,
            token=token,
            value=plaintext,
            raw=raw.value,
            epoch=raw.epoch,
            absent=False,
        )


class SessionRW(Session):
    __slots__ = ("_sub",)

    def __init__(self, sub: Substrate, store_id: int) -> None:
        super().__init__(sub, store_id)
        self._sub = sub

    def token(self, name: str | bytes) -> bytes:
        if self._store_id == ops.STORE_MANAGEMENT:
            return name if isinstance(name, bytes) else name.encode()
        if not isinstance(name, str):
            raise SessionError("data store keys must be str, not bytes")
        return self._sub.token(self._store_id, name)

    def seal(self, name: str | bytes, value: bytes) -> tuple[bytes, bytes, int]:
        if self._store_id == ops.STORE_MANAGEMENT:
            return self.token(name), value, ops.EPOCH_NONE
        if not isinstance(name, str):
            raise SessionError("data store keys must be str, not bytes")
        return self._sub.seal(self._store_id, name, value)

    def _decrypt(self, name: str | bytes, ciphertext: bytes, epoch: int) -> bytes:
        if self._store_id == ops.STORE_MANAGEMENT:
            return ciphertext
        if not isinstance(name, str):
            raise SessionError("data store keys must be str, not bytes")
        return self._sub.decrypt(self._store_id, name, ciphertext, epoch)

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

    def begin(self) -> "TxBuilder":
        return TxBuilder(self)

    def submit(self, tx: ops.Transaction) -> SubmitHandle:
        return self._sub.submit(tx)


class TxBuilder:
    def __init__(self, session: SessionRW) -> None:
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
