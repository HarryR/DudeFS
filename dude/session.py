import threading
import time
import unicodedata
from abc import ABC, abstractmethod
from dataclasses import dataclass, field

from .core import codec, crypto
from .core.errors import DudeError
from .net.envelope import MessageId, Verb
from .store.layer import BlockHead, Index, Reader
from .store.management import blind_key, epoch_key, wrap_key
from .store.ops import (
    EPOCH_NONE,
    STORE_DATA,
    STORE_MANAGEMENT,
    Absent,
    Del,
    Held,
    Holds,
    Predicate,
    Sealed,
    Set,
    Step,
    Transaction,
    value_digest,
)


class SessionError(DudeError): ...


class SessionTimeoutError(SessionError): ...


class AckTimeoutError(SessionTimeoutError): ...


class SettleTimeoutError(SessionTimeoutError): ...


class TxStatusTimeoutError(SessionTimeoutError): ...


@dataclass(frozen=True, slots=True)
class Record:
    name: str | bytes
    store_id: int
    token: bytes
    value: bytes
    raw: bytes
    epoch: int
    absent: bool


# -- result type hierarchies ------------------------------------------------


class AckResult: ...


@dataclass(frozen=True, slots=True)
class Accepted(AckResult):
    op_hash: crypto.Digest


@dataclass(frozen=True, slots=True)
class SubmitRefused(AckResult):
    reason: str

    def encode(self) -> bytes:
        return codec.encode([b"R", self.reason.encode()])


class SettleResult:
    def encode(self) -> bytes:
        raise NotImplementedError

    @staticmethod
    def decode(raw: bytes) -> "Settled | Pending | Unknown":
        parts = codec.as_seq(codec.decode(raw))
        tag = codec.as_bytes(parts[0])
        if tag == b"settled":
            p = codec.as_seq(codec.decode(raw), 4)
            return Settled(
                crypto.Digest(codec.as_bytes(p[1])),
                codec.as_int(p[2]),
                crypto.Digest(codec.as_bytes(p[3])),
            )
        if tag == b"pending":
            return Pending()
        if tag == b"unknown":
            return Unknown()
        raise SessionError(f"unknown settle tag: {tag!r}")


@dataclass(frozen=True, slots=True)
class Settled(SettleResult):
    op_hash: crypto.Digest
    block_num: Index
    block_hash: crypto.Digest

    def encode(self) -> bytes:
        return codec.encode([b"settled", self.op_hash, self.block_num, self.block_hash])


@dataclass(frozen=True, slots=True)
class Pending(SettleResult):
    def encode(self) -> bytes:
        return codec.encode([b"pending"])


@dataclass(frozen=True, slots=True)
class Unknown(SettleResult):
    def encode(self) -> bytes:
        return codec.encode([b"unknown"])


# -- inflight tracking ------------------------------------------------------


class InflightHandle(ABC):
    @abstractmethod
    def on_reply(self, verb: Verb, body: bytes) -> None: ...
    @abstractmethod
    def on_expired(self) -> None: ...


class Inflight:
    __slots__ = ("_lock", "_pending")

    def __init__(self) -> None:
        self._pending: dict[bytes, InflightHandle] = {}
        self._lock = threading.Lock()

    def register(self, mid: MessageId, handle: InflightHandle) -> None:
        with self._lock:
            self._pending[mid.correlation_id] = handle

    def on_reply(self, correlation_id: bytes, verb: Verb, body: bytes) -> bool:
        with self._lock:
            handle = self._pending.pop(correlation_id, None)
        if handle is None:
            return False
        handle.on_reply(verb, body)
        return True

    def on_expired(self, correlation_id: bytes) -> None:
        with self._lock:
            handle = self._pending.pop(correlation_id, None)
        if handle is not None:
            handle.on_expired()

    def pending_of_type[T](self, cls: type[T]) -> list[T]:
        with self._lock:
            return [h for h in self._pending.values() if isinstance(h, cls)]


@dataclass(slots=True)
class SubmitHandle(InflightHandle):
    op_hash: crypto.Digest
    _sub: "Substrate"
    peer: crypto.PublicKey | None = None
    _accepted: bool = False
    _refused_reason: str | None = None
    _expired: bool = False
    _ack: threading.Event = field(default_factory=threading.Event)

    def on_reply(self, verb: Verb, body: bytes) -> None:
        if verb == Verb.ACCEPTED:
            self._accepted = True
        elif verb == Verb.REFUSED:
            self._refused_reason = body.decode("utf-8", errors="replace")
        self._ack.set()

    def mark_accepted(self) -> None:
        self._accepted = True
        self._ack.set()

    def on_expired(self) -> None:
        if not self._accepted and self._refused_reason is None:
            self._expired = True
        self._ack.set()

    def wait_ack(self) -> AckResult:
        evict = self._sub.evict_after_sec()
        if not self._ack.wait(evict):
            raise AckTimeoutError("no reply from node")
        if self._refused_reason is not None:
            return SubmitRefused(self._refused_reason)
        if self._expired:
            raise AckTimeoutError("message expired")
        return Accepted(self.op_hash)

    def wait_settled(self) -> SettleResult:
        evict = self._sub.evict_after_sec()
        deadline = time.monotonic() + evict
        while time.monotonic() < deadline:
            gen = self._sub.commit_seq
            status = self._sub.tx_status(self.op_hash)
            if not isinstance(status, Pending):
                return status
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                break
            self._sub.wait_for_commit(min(remaining, evict), since=gen)
        raise SettleTimeoutError("settlement not observed within timeout")

    def poll(self) -> AckResult | SettleResult:
        if self._refused_reason is not None:
            return SubmitRefused(self._refused_reason)
        return self._sub.tx_status(self.op_hash)

    def wait(self) -> AckResult | SettleResult:
        ack = self.wait_ack()
        if not isinstance(ack, Accepted):
            return ack
        return self.wait_settled()


class Substrate(Reader, ABC):
    @abstractmethod
    def submit(self, tx: Transaction) -> "SubmitHandle": ...
    @abstractmethod
    def tx_status(self, op_hash: crypto.Digest) -> SettleResult: ...
    @abstractmethod
    def evict_after_sec(self) -> float: ...
    @abstractmethod
    def wait_for_commit(self, timeout: float, since: int = -1) -> None: ...
    @property
    @abstractmethod
    def commit_cond(self) -> "threading.Condition": ...
    @property
    @abstractmethod
    def commit_seq(self) -> int: ...
    @abstractmethod
    def head(self) -> BlockHead | None: ...
    @abstractmethod
    def token(self, store_id: int, name: str, *, plaintext: bool = False) -> bytes: ...
    @abstractmethod
    def seal(
        self, store_id: int, name: str, value: bytes, *, plaintext: bool = False
    ) -> Sealed: ...
    @abstractmethod
    def decrypt(self, store_id: int, name: str, ciphertext: bytes, epoch: int) -> bytes: ...

    def close(self) -> None: ...

    def __enter__(self):
        return self

    def __exit__(self, *_: object) -> None:
        self.close()


class SessionProvider(ABC):
    @abstractmethod
    def substrate(self) -> Substrate: ...

    @abstractmethod
    def session_rw(self, store_id: int = STORE_DATA) -> "SessionRW": ...

    def session_ro(self, store_id: int = STORE_DATA) -> "Session":
        return self.session_rw(store_id)


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
        raw = self._reader.get(STORE_MANAGEMENT, blind_key(store_id, self._kp.public))
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
                STORE_MANAGEMENT,
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
        raw = self._reader.get(STORE_MANAGEMENT, epoch_key(store_id))
        if raw is None:
            return EPOCH_NONE
        sk.current_epoch = codec.as_int(codec.decode(raw.value))
        return sk.current_epoch

    def token(self, store_id: int, name: str, *, plaintext: bool = False) -> bytes:
        if plaintext:
            return unicodedata.normalize("NFC", name).encode()
        nk = self.ensure_blinding(store_id)
        return crypto.derive_name_token(nk, unicodedata.normalize("NFC", name).encode())

    def seal(self, store_id: int, name: str, value: bytes, *, plaintext: bool = False) -> Sealed:
        if plaintext:
            return Sealed(unicodedata.normalize("NFC", name).encode(), value, EPOCH_NONE)
        epoch = self.current_epoch(store_id)
        nt = crypto.NameToken(self.token(store_id, name))
        vk = self.value_key(store_id, epoch)
        item = crypto.derive_item_key(vk, nt)
        aad = codec.encode([store_id, bytes(nt), epoch])
        return Sealed(nt, bytes(crypto.AeadXcs1.seal(item, aad, value)), epoch)

    def decrypt(self, store_id: int, name: str, ciphertext: bytes, epoch: int) -> bytes:
        if epoch == EPOCH_NONE:
            return ciphertext
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

    def token(self, name: str | bytes, *, plaintext: bool = False) -> bytes:
        if self._store_id == STORE_MANAGEMENT or plaintext:
            return name if isinstance(name, bytes) else name.encode()
        if not isinstance(name, str):
            raise SessionError("data store keys must be str, not bytes")
        raise SessionError("data store token requires a Substrate with crypto")

    def seal(self, name: str | bytes, value: bytes, *, plaintext: bool = False) -> Sealed:
        if self._store_id == STORE_MANAGEMENT or plaintext:
            return Sealed(self.token(name, plaintext=True), value, EPOCH_NONE)
        raise SessionError("data store seal requires a Substrate with crypto")

    def _decrypt(self, name: str | bytes, ciphertext: bytes, epoch: int) -> bytes:  # noqa: ARG002
        if self._store_id == STORE_MANAGEMENT or epoch == EPOCH_NONE:
            return ciphertext
        raise SessionError("data store decrypt requires a Substrate with crypto")

    def get(self, name: str | bytes, *, plaintext: bool = False) -> Record:
        token = self.token(name, plaintext=plaintext)
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
        decrypted = self._decrypt(name, raw.value, raw.epoch)
        return Record(
            name=name,
            store_id=self._store_id,
            token=token,
            value=decrypted,
            raw=raw.value,
            epoch=raw.epoch,
            absent=False,
        )

    def count_prefix(self, prefix: bytes) -> int:
        return self._reader.count_prefix(self._store_id, prefix)

    def nth_prefix(
        self, prefix: bytes, n: int, *, descending: bool = False
    ) -> tuple[bytes, Held] | None:
        return self._reader.nth_prefix(self._store_id, prefix, n, descending=descending)


class SessionRW(Session):
    __slots__ = ("_sub",)

    def __init__(self, sub: Substrate, store_id: int) -> None:
        super().__init__(sub, store_id)
        self._sub = sub

    def token(self, name: str | bytes, *, plaintext: bool = False) -> bytes:
        if self._store_id == STORE_MANAGEMENT or plaintext:
            return name if isinstance(name, bytes) else name.encode()
        if not isinstance(name, str):
            raise SessionError("data store keys must be str, not bytes")
        return self._sub.token(self._store_id, name)

    def seal(self, name: str | bytes, value: bytes, *, plaintext: bool = False) -> Sealed:
        if self._store_id == STORE_MANAGEMENT or plaintext:
            return Sealed(self.token(name, plaintext=True), value, EPOCH_NONE)
        if not isinstance(name, str):
            raise SessionError("data store keys must be str, not bytes")
        return self._sub.seal(self._store_id, name, value)

    def _decrypt(self, name: str | bytes, ciphertext: bytes, epoch: int) -> bytes:
        if self._store_id == STORE_MANAGEMENT or epoch == EPOCH_NONE:
            return ciphertext
        if not isinstance(name, str):
            raise SessionError("data store keys must be str, not bytes")
        return self._sub.decrypt(self._store_id, name, ciphertext, epoch)

    def put(
        self,
        name: str,
        value: bytes,
        *predicates: Predicate | Record,
        expect: Record | None = None,
        absent: bool = False,
        plaintext: bool = False,
    ) -> SubmitHandle:
        token, sealed, epoch = self.seal(name, value, plaintext=plaintext)
        guards = collect_guards(self._store_id, token, predicates, expect, absent)
        tx = Transaction((Step(guards, Set(self._store_id, token, sealed, epoch)),))
        return self.submit(tx)

    def delete(
        self,
        name: str,
        *predicates: Predicate | Record,
        expect: Record | None = None,
        plaintext: bool = False,
    ) -> SubmitHandle:
        token = self.token(name, plaintext=plaintext)
        guards = collect_guards(self._store_id, token, predicates, expect, False)
        tx = Transaction((Step(guards, Del(self._store_id, token)),))
        return self.submit(tx)

    def begin(self) -> "TxBuilder":
        return TxBuilder(self)

    def submit(self, tx: Transaction) -> SubmitHandle:
        return self._sub.submit(tx)

    def wait_for_commit(self, timeout: float, since: int = -1) -> None:
        self._sub.wait_for_commit(timeout, since=since)


class TxBuilder:
    def __init__(self, session: SessionRW) -> None:
        self._session = session
        self._steps: list[Step] = []

    def put(
        self,
        name: str,
        value: bytes,
        *predicates: Predicate | Record,
        expect: Record | None = None,
        absent: bool = False,
        plaintext: bool = False,
    ) -> "TxBuilder":
        s = self._session
        token, sealed, epoch = s.seal(name, value, plaintext=plaintext)
        guards = collect_guards(s.store_id, token, predicates, expect, absent)
        self._steps.append(Step(guards, Set(s.store_id, token, sealed, epoch)))
        return self

    def delete(
        self,
        name: str,
        *predicates: Predicate | Record,
        expect: Record | None = None,
        plaintext: bool = False,
    ) -> "TxBuilder":
        s = self._session
        token = s.token(name, plaintext=plaintext)
        guards = collect_guards(s.store_id, token, predicates, expect, False)
        self._steps.append(Step(guards, Del(s.store_id, token)))
        return self

    def as_tx(self) -> Transaction:
        if not self._steps:
            raise SessionError("empty transaction")
        return Transaction(tuple(self._steps))

    def submit(self) -> SubmitHandle:
        return self._session.submit(self.as_tx())


def collect_guards(
    store_id: int,
    token: bytes,
    predicates: tuple[Predicate | Record, ...],
    expect: Record | None,
    absent: bool,
) -> tuple[Predicate, ...]:
    out: list[Predicate] = []
    for p in predicates:
        if isinstance(p, Record):
            if p.absent:
                raise SessionError("cannot use an absent record as a dependency")
            out.append(Holds(p.store_id, p.token, value_digest(p.raw)))
        else:
            out.append(p)
    if expect is not None:
        if expect.absent:
            raise SessionError("expected record is absent; use absent=True instead")
        out.append(Holds(store_id, token, value_digest(expect.raw)))
    if absent:
        out.append(Absent(store_id, token))
    return tuple(out)
