import threading
from collections.abc import Callable
from dataclasses import dataclass
from typing import NamedTuple

from ..core import codec, serde
from ..core.units import Millis, Seconds
from ..session import SessionRW
from ..store.ops import Transaction
from .plaintext_map import PlaintextMap
from .queue import Claim, Queue, gen_id


class Job[T](NamedTuple):
    job_id: bytes
    payload: T
    worker_id: bytes


@dataclass(slots=True)
class BoundQueue[T]:
    name: bytes
    queue: Queue
    payload_type: type[T]
    handler: Callable[[Job[T]], None]
    _group: bytes
    _session: SessionRW

    def _data_key(self, job_id: bytes) -> str:
        return (self._group + b"d/" + job_id).decode()

    def submit(self, payload: T, job_id: bytes | None = None) -> Transaction:
        jid = job_id or gen_id()
        data_key = self._data_key(jid)
        data_tx = self._session.begin().put(data_key, serde.dump(payload)).as_tx()
        return data_tx + self.queue.submit(jid, data_key.encode())


def _encode_worker(ts: int, queues: tuple[bytes, ...]) -> bytes:
    return codec.encode([ts, sorted(queues)])


def _decode_worker(raw: bytes) -> tuple[int, tuple[bytes, ...]]:
    parts = codec.as_seq(codec.decode(raw), 2)
    return codec.as_int(parts[0]), tuple(codec.as_bytes(q) for q in codec.as_seq(parts[1]))


class Worker:
    __slots__ = (
        "_bindings",
        "_current_claim",
        "_current_queue",
        "_group",
        "_heartbeat_interval",
        "_lease_duration",
        "_qw",
        "_session",
        "_stale_threshold",
        "_stopping",
        "_workers",
        "worker_id",
    )

    def __init__(
        self,
        group: bytes,
        session: SessionRW,
        lease_duration: Seconds,
        heartbeat_interval: Seconds,
    ) -> None:
        self.worker_id = gen_id()
        self._group = group
        self._session = session
        self._lease_duration = lease_duration
        self._heartbeat_interval = heartbeat_interval
        self._stale_threshold = Millis(lease_duration.as_millis * 3)
        self._stopping = threading.Event()
        self._current_claim: Claim | None = None
        self._current_queue: bytes | None = None
        self._bindings: dict[bytes, BoundQueue] = {}
        self._qw: dict[bytes, PlaintextMap] = {}
        self._workers = PlaintextMap(group + b"w/", session)

    def bind[T](
        self,
        name: bytes,
        payload_type: type[T],
        handler: Callable[[Job[T]], None],
    ) -> BoundQueue[T]:
        queue = Queue(self._group + name + b"/", self._session)
        bq = BoundQueue(name, queue, payload_type, handler, self._group, self._session)
        self._bindings[name] = bq
        self._qw[name] = PlaintextMap(self._group + b"qw/" + name + b"/", self._session)
        return bq

    @property
    def _queue_names(self) -> tuple[bytes, ...]:
        return tuple(sorted(self._bindings))

    def _submit(self, tx: Transaction) -> None:
        self._session.submit(tx).wait()

    def _deadline(self) -> int:
        return int(Millis.now().as_seconds + self._lease_duration)

    # -- registry --------------------------------------------------------------

    def register(self) -> None:
        value = _encode_worker(Millis.now(), self._queue_names)
        tx = self._workers.tx_put(self.worker_id, value, absent=True)
        for name in self._queue_names:
            tx = tx + self._qw[name].tx_put(self.worker_id, b"", absent=True)
        self._submit(tx)

    def deregister(self) -> None:
        rec = self._workers.get(self.worker_id)
        if rec.absent:
            return
        tx = self._workers.tx_delete(self.worker_id, expect=rec)
        for name in self._queue_names:
            qw_rec = self._qw[name].get(self.worker_id)
            if not qw_rec.absent:
                tx = tx + self._qw[name].tx_delete(self.worker_id, expect=qw_rec)
        self._submit(tx)

    def heartbeat(self) -> None:
        rec = self._workers.get(self.worker_id)
        if rec.absent:
            return
        value = _encode_worker(Millis.now(), self._queue_names)
        tx = self._workers.tx_put(self.worker_id, value, expect=rec)
        for name in self._queue_names:
            qw_rec = self._qw[name].get(self.worker_id)
            if not qw_rec.absent:
                job_id = (
                    self._current_claim.job_id
                    if (self._current_claim and self._current_queue == name)
                    else b""
                )
                tx = tx + self._qw[name].tx_put(self.worker_id, job_id, expect=qw_rec)
        self._submit(tx)

    # -- stale cleanup ---------------------------------------------------------

    def cleanup_stale(self) -> int:
        now = Millis.now()
        cleaned = 0
        for wid, rec in self._workers.records():
            if wid == self.worker_id:
                continue
            ts, queue_names = _decode_worker(rec.value)
            if now - ts <= self._stale_threshold:
                continue
            tx = self._workers.tx_delete(wid, expect=rec)
            for qname in queue_names:
                qw = PlaintextMap(self._group + b"qw/" + qname + b"/", self._session)
                qw_rec = qw.get(wid)
                if not qw_rec.absent:
                    tx = tx + qw.tx_delete(wid, expect=qw_rec)
            self._submit(tx)
            cleaned += 1
        return cleaned

    # -- work loop -------------------------------------------------------------

    def run(self) -> None:
        self.register()
        try:
            while not self._stopping.is_set():
                self.heartbeat()
                now = int(Millis.now().as_seconds)
                for bq in self._bindings.values():
                    ejected, tx = bq.queue.reclaim_expired(now, limit=1)
                    if ejected:
                        self._submit(tx)
                claimed = False
                for bq in self._bindings.values():
                    result = bq.queue.claim_random(self.worker_id, self._deadline())
                    if result is not None:
                        claim, tx = result
                        self._submit(tx)
                        self._current_claim = claim
                        self._current_queue = bq.name
                        self._run_with_renewal(claim, bq)
                        self._current_claim = None
                        self._current_queue = None
                        claimed = True
                        break
                if not claimed:
                    self._session.wait_for_commit(self._heartbeat_interval)
        finally:
            self.deregister()

    def stop(self) -> None:
        self._stopping.set()

    def _run_with_renewal(self, claim: Claim, bq: BoundQueue) -> None:
        done = threading.Event()
        latest = [claim]
        renewal = threading.Thread(
            target=self._renew_loop, args=(latest, bq.queue, done), daemon=True
        )
        renewal.start()
        try:
            data_key = claim.payload.decode()
            rec = self._session.get(data_key)
            payload = serde.load(bq.payload_type, rec.value)
            bq.handler(Job(claim.job_id, payload, claim.worker))
        finally:
            done.set()
            renewal.join()
            self._submit(bq.queue.complete(latest[0]))

    def _renew_loop(self, latest: list[Claim], queue: Queue, done: threading.Event) -> None:
        while not done.wait(self._heartbeat_interval):
            new_deadline = self._deadline()
            latest[0], tx = queue.renew_lease(latest[0], new_deadline)
            self._submit(tx)
