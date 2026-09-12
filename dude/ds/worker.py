import logging
import threading
from collections.abc import Callable
from dataclasses import dataclass, field

from ..core import codec, serde
from ..core.units import Millis, Seconds
from ..session import SessionProvider, SessionRW
from ..store.ops import Transaction
from .plaintext_map import PlaintextMap
from .queue import Claim, Queue, gen_id

log = logging.getLogger(__name__)


@dataclass(slots=True)
class Job[T]:
    job_id: bytes
    payload: T
    worker_id: bytes
    cancelled: threading.Event = field(default_factory=threading.Event)


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


@dataclass(slots=True)
class _ActiveJob:
    claim: Claim
    bq: BoundQueue
    job: Job
    thread: threading.Thread | None = None
    error: BaseException | None = None


def _encode_worker(ts: int, queues: tuple[bytes, ...]) -> bytes:
    return codec.encode([ts, sorted(queues)])


def _decode_worker(raw: bytes) -> tuple[int, tuple[bytes, ...]]:
    parts = codec.as_seq(codec.decode(raw), 2)
    return codec.as_int(parts[0]), tuple(codec.as_bytes(q) for q in codec.as_seq(parts[1]))


class Worker:
    __slots__ = (
        "_active",
        "_bindings",
        "_group",
        "_heartbeat_interval",
        "_lease_duration",
        "_provider",
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
        provider: SessionProvider,
        lease_duration: Seconds,
        heartbeat_interval: Seconds,
    ) -> None:
        self.worker_id = gen_id()
        self._group = group
        self._provider = provider
        self._session = provider.session_rw()
        self._lease_duration = lease_duration
        self._heartbeat_interval = heartbeat_interval
        self._stale_threshold = Millis(int(lease_duration * 3000))
        self._stopping = threading.Event()
        self._active: _ActiveJob | None = None
        self._bindings: dict[bytes, BoundQueue] = {}
        self._qw: dict[bytes, PlaintextMap] = {}
        self._workers = PlaintextMap(group + b"w/", self._session)

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
        log.info("worker %s registering on queues %s", self.worker_id.decode(), self._queue_names)
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
        log.info("worker %s deregistered", self.worker_id.decode())

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
                    self._active.claim.job_id
                    if (self._active and self._active.bq.name == name)
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
            log.info("cleaned stale worker %s", wid.decode())
            cleaned += 1
        return cleaned

    # -- handler thread --------------------------------------------------------

    def _handler_target(self, active: _ActiveJob) -> None:
        log.debug(
            "handler started for job %s on queue %s",
            active.claim.job_id.decode(),
            active.bq.name.decode(),
        )
        try:
            handler_session = self._provider.session_rw()
            data_key = active.claim.payload.decode()
            rec = handler_session.get(data_key)
            active.job.payload = serde.load(active.bq.payload_type, rec.value)
            active.bq.handler(active.job)
        except Exception as exc:
            log.exception("handler crashed for job %s", active.claim.job_id.decode())
            active.error = exc

    def _finish_handler(self) -> None:
        if self._active is None or self._active.thread is None:
            return
        self._active.thread.join(timeout=0)
        if self._active.thread.is_alive():
            return

        a = self._active
        if a.error is not None:
            log.warning("reclaiming job %s after handler error", a.claim.job_id.decode())
            self._submit(a.bq.queue.reclaim(a.claim))
        else:
            log.debug("completed job %s", a.claim.job_id.decode())
            self._submit(a.bq.queue.complete(a.claim))

        self._active = None

    # -- supervisor loop -------------------------------------------------------

    def run(self) -> None:
        self.register()
        try:
            while not self._stopping.is_set():
                self.heartbeat()

                now = int(Millis.now().as_seconds)
                for bq in self._bindings.values():
                    ejected, tx = bq.queue.reclaim_expired(now, limit=1)
                    if ejected:
                        log.info(
                            "reclaimed %d expired jobs from queue %s",
                            len(ejected),
                            bq.name.decode(),
                        )
                        self._submit(tx)

                if self._active and self._active.thread and self._active.thread.is_alive():
                    self._renew_lease()
                else:
                    self._finish_handler()
                    self._try_claim()

                self._stopping.wait(self._heartbeat_interval)
        finally:
            self._shutdown_handler()
            self.deregister()

    def stop(self) -> None:
        log.info("worker %s stopping", self.worker_id.decode())
        self._stopping.set()
        if self._active is not None:
            self._active.job.cancelled.set()

    def _try_claim(self) -> None:
        for bq in self._bindings.values():
            result = bq.queue.claim_random(self.worker_id, self._deadline())
            if result is not None:
                claim, tx = result
                self._submit(tx)
                job: Job = Job(claim.job_id, None, claim.worker)
                active = _ActiveJob(claim=claim, bq=bq, job=job)
                active.thread = threading.Thread(
                    target=self._handler_target, args=(active,), daemon=True
                )
                active.thread.start()
                self._active = active
                log.info("claimed job %s from queue %s", claim.job_id.decode(), bq.name.decode())
                return

    def _renew_lease(self) -> None:
        if self._active is None:
            return
        new_deadline = self._deadline()
        self._active.claim, tx = self._active.bq.queue.renew_lease(self._active.claim, new_deadline)
        self._submit(tx)

    def _shutdown_handler(self) -> None:
        if self._active is not None:
            self._active.job.cancelled.set()
            if self._active.thread is not None:
                self._active.thread.join(timeout=float(self._lease_duration))
        self._finish_handler()
