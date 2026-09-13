import logging
import threading
from collections.abc import Callable, Iterator
from dataclasses import dataclass, field

from ..core import codec, serde
from ..core.units import Millis, Seconds
from ..session import SessionProvider, SessionRW
from ..store.ops import Transaction
from .plaintext_map import PlaintextMap
from .queue import Claim, Queue, gen_id

log = logging.getLogger(__name__)


class JobID(bytes): ...
class WorkerID(bytes): ...


def gen_job_id() -> JobID:
    return JobID(gen_id())


def gen_worker_id() -> WorkerID:
    return WorkerID(gen_id())


@dataclass(slots=True)
class Job[T]:
    job_id: JobID
    payload: T
    worker_id: WorkerID
    cancelled: threading.Event = field(default_factory=threading.Event)
    error: BaseException | None = None


@dataclass(slots=True)
class BoundQueue[T]:
    name: bytes
    queue: Queue
    payload_type: type[T]
    handler: Callable[[Job[T]], None]
    _group: bytes

    def _data_key(self, job_id: bytes) -> str:
        return (self._group + b"d/" + job_id).decode()

    def submit(
        self, payload: T, session: SessionRW, job_id: bytes | None = None
    ) -> tuple[bytes, Transaction]:
        jid = job_id or gen_id()
        data_key = self._data_key(jid)
        data_tx = session.begin().put(data_key, serde.dump(payload)).as_tx()
        return jid, data_tx + self.queue.submit(jid, data_key.encode())


@dataclass(slots=True)
class _ActiveJob:
    claim: Claim
    bq: BoundQueue
    job: Job
    thread: threading.Thread | None = None


def _encode_worker(ts: int, queues: tuple[bytes, ...]) -> bytes:
    return codec.encode([ts, sorted(queues)])


def _decode_worker(raw: bytes) -> tuple[int, tuple[bytes, ...]]:
    parts = codec.as_seq(codec.decode(raw), 2)
    return codec.as_int(parts[0]), tuple(codec.as_bytes(q) for q in codec.as_seq(parts[1]))


class WorkerMembership:
    __slots__ = ("_queue_names", "_registry", "_session", "worker_id")

    def __init__(
        self,
        registry: "WorkerRegistry",
        session: SessionRW,
        worker_id: WorkerID,
        queue_names: tuple[bytes, ...],
    ) -> None:
        self.worker_id: WorkerID = worker_id
        self._registry = registry
        self._session = session
        self._queue_names = queue_names

    def heartbeat(
        self, active_queue: bytes | None = None, active_job_id: bytes | None = None
    ) -> Transaction:
        workers = self._registry._workers(self._session)
        rec = workers.get(self.worker_id)
        if rec.absent:
            return Transaction(())
        value = _encode_worker(Millis.now(), self._queue_names)
        tx = workers.tx_put(self.worker_id, value, expect=rec)
        for name in self._queue_names:
            qw = self._registry._qw(name, self._session)
            qw_rec = qw.get(self.worker_id)
            if not qw_rec.absent:
                job_id = active_job_id if (active_queue == name and active_job_id) else b""
                tx = tx + qw.tx_put(self.worker_id, job_id, expect=qw_rec)
        return tx

    def leave(self) -> Transaction:
        tx = self._registry._deregister_tx(self.worker_id, self._queue_names, self._session)
        if tx.steps:
            log.info("worker %s deregistered", self.worker_id.decode())
        return tx


class WorkerRegistry:
    __slots__ = ("_group", "_provider")

    def __init__(self, group: bytes, provider: SessionProvider) -> None:
        self._group = group
        self._provider = provider

    def _workers(self, session: SessionRW) -> PlaintextMap:
        return PlaintextMap(self._group + b"w/", session)

    def _qw(self, queue_name: bytes, session: SessionRW) -> PlaintextMap:
        return PlaintextMap(self._group + b"qw/" + queue_name + b"/", session)

    def _deregister_tx(
        self, wid: bytes, queue_names: tuple[bytes, ...], session: SessionRW
    ) -> Transaction:
        workers = self._workers(session)
        rec = workers.get(wid)
        if rec.absent:
            return Transaction(())
        tx = workers.tx_delete(wid, expect=rec)
        for name in queue_names:
            qw = self._qw(name, session)
            qw_rec = qw.get(wid)
            if not qw_rec.absent:
                tx = tx + qw.tx_delete(wid, expect=qw_rec)
        return tx

    def register(
        self, worker_id: WorkerID, queue_names: tuple[bytes, ...]
    ) -> tuple[WorkerMembership, Transaction]:
        log.info("worker %s registering on queues %s", worker_id.decode(), queue_names)
        session = self._provider.session_rw()
        workers = self._workers(session)
        value = _encode_worker(Millis.now(), queue_names)
        tx = workers.tx_put(worker_id, value, absent=True)
        for name in queue_names:
            tx = tx + self._qw(name, session).tx_put(worker_id, b"", absent=True)
        return WorkerMembership(self, session, worker_id, queue_names), tx

    def cleanup_stale(
        self, threshold: Millis, *, limit: int | None = None
    ) -> tuple[int, Transaction]:
        session = self._provider.session_rw()
        workers = self._workers(session)
        now = Millis.now()
        tx = Transaction(())
        cleaned = 0
        for wid, rec in workers.records():
            if limit is not None and cleaned >= limit:
                break
            ts, queue_names = _decode_worker(rec.value)
            if now - ts <= threshold:
                continue
            tx = tx + self._deregister_tx(wid, queue_names, session)
            log.info("cleaned stale worker %s", wid.decode())
            cleaned += 1
        return cleaned, tx

    def list_workers(self) -> Iterator[tuple[bytes, int, tuple[bytes, ...]]]:
        session = self._provider.session_rw()
        for wid, rec in self._workers(session).records():
            ts, queue_names = _decode_worker(rec.value)
            yield wid, ts, queue_names

    def workers_for_queue(self, queue_name: bytes) -> Iterator[tuple[bytes, bytes]]:
        session = self._provider.session_rw()
        yield from self._qw(queue_name, session).items()


class Worker:
    __slots__ = (
        "_active",
        "_bindings",
        "_group",
        "_heartbeat_interval",
        "_lease_duration",
        "_membership",
        "_provider",
        "_registry",
        "_session",
        "_stopping",
        "worker_id",
    )

    def __init__(
        self,
        group: bytes,
        provider: SessionProvider,
        lease_duration: Seconds,
        heartbeat_interval: Seconds,
        registry: WorkerRegistry | None = None,
    ) -> None:
        self.worker_id: WorkerID = gen_worker_id()
        self._group = group
        self._provider = provider
        self._session = provider.session_rw()
        self._lease_duration = lease_duration
        self._heartbeat_interval = heartbeat_interval
        self._registry = registry or WorkerRegistry(group, provider)
        self._stopping = threading.Event()
        self._active: _ActiveJob | None = None
        self._bindings: dict[bytes, BoundQueue] = {}
        self._membership: WorkerMembership | None = None

    def bind[T](
        self,
        name: bytes,
        payload_type: type[T],
        handler: Callable[[Job[T]], None],
    ) -> BoundQueue[T]:
        queue = Queue(self._group + name + b"/", self._session)
        bq = BoundQueue(name, queue, payload_type, handler, self._group)
        self._bindings[name] = bq
        return bq

    @property
    def _queue_names(self) -> tuple[bytes, ...]:
        return tuple(sorted(self._bindings))

    def _submit(self, tx: Transaction) -> None:
        if tx.steps:
            self._session.submit(tx).wait()

    def _deadline(self) -> int:
        return int(Millis.now().as_seconds + self._lease_duration)

    def register(self) -> None:
        self._membership, tx = self._registry.register(self.worker_id, self._queue_names)
        self._submit(tx)

    def deregister(self) -> None:
        if self._membership is not None:
            self._submit(self._membership.leave())
            self._membership = None

    def _heartbeat_tx(self) -> Transaction:
        if self._membership is None:
            return Transaction(())
        active_queue = self._active.bq.name if self._active else None
        active_job_id = self._active.claim.job_id if self._active else None
        return self._membership.heartbeat(active_queue, active_job_id)

    def heartbeat(self) -> None:
        self._submit(self._heartbeat_tx())

    def cleanup_stale(self) -> int:
        count, tx = self._registry.cleanup_stale(Millis(int(self._lease_duration * 3000)))
        self._submit(tx)
        return count

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
            active.job.error = exc

    def _finish_handler(self) -> None:
        if self._active is None or self._active.thread is None:
            return
        self._active.thread.join(timeout=0)
        if self._active.thread.is_alive():
            return

        a = self._active
        if a.job.error is not None:
            log.warning("reclaiming job %s after handler error", a.claim.job_id.decode())
            self._submit(a.bq.queue.reclaim(a.claim))
        else:
            log.debug("completed job %s", a.claim.job_id.decode())
            self._submit(a.bq.queue.complete(a.claim))

        self._active = None

    # -- lifecycle -------------------------------------------------------------

    def tick(self) -> None:
        tx = self._heartbeat_tx()

        now = int(Millis.now().as_seconds)
        for bq in self._bindings.values():
            ejected, reclaim_tx = bq.queue.reclaim_expired(now, limit=1)
            if ejected:
                log.info(
                    "reclaimed %d expired jobs from queue %s",
                    len(ejected),
                    bq.name.decode(),
                )
                tx = tx + reclaim_tx

        if self._active and self._active.thread and self._active.thread.is_alive():
            new_deadline = self._deadline()
            self._active.claim, renew_tx = self._active.bq.queue.renew_lease(
                self._active.claim, new_deadline
            )
            tx = tx + renew_tx
        else:
            self._submit(tx)
            self._finish_handler()
            self._try_claim()
            return

        self._submit(tx)

    def run(self) -> None:
        self.register()
        try:
            while not self._stopping.is_set():
                self.tick()
                self._stopping.wait(self._heartbeat_interval)
        finally:
            self._shutdown_handler()
            self.deregister()

    def stop(self) -> None:
        log.info("worker %s stopping", self.worker_id.decode())
        self._stopping.set()
        active = self._active
        if active is not None:
            active.job.cancelled.set()

    def _try_claim(self) -> None:
        for bq in self._bindings.values():
            result = bq.queue.claim_random(self.worker_id, self._deadline())
            if result is not None:
                claim, tx = result
                self._submit(tx)
                job: Job = Job(JobID(claim.job_id), None, WorkerID(claim.worker))
                active = _ActiveJob(claim=claim, bq=bq, job=job)
                active.thread = threading.Thread(
                    target=self._handler_target, args=(active,), daemon=True
                )
                active.thread.start()
                self._active = active
                log.info("claimed job %s from queue %s", claim.job_id.decode(), bq.name.decode())
                return

    def _shutdown_handler(self) -> None:
        if self._active is not None:
            self._active.job.cancelled.set()
            if self._active.thread is not None:
                self._active.thread.join(timeout=float(self._lease_duration))
        self._finish_handler()
