import threading
import time
import unittest
from collections.abc import Callable
from dataclasses import dataclass

from ..core.units import Millis, Seconds
from ..ds.plaintext_map import PlaintextMap
from ..ds.worker import Job, Worker, WorkerRegistry, _decode_worker
from ..store import ops
from .cluster import Cluster

GROUP = b"g/"


@dataclass
class TaskPayload:
    target: str
    amount: int


class TestWorkerWorkflow(unittest.TestCase):
    def setUp(self) -> None:
        self.c = Cluster(nodes=3, mgmt=1)
        self.rn = self.c.replicas[0]
        self.session = self.rn.session_rw()

    def tearDown(self) -> None:
        self.c.close()

    def _submit(self, tx: ops.Transaction) -> None:
        self.c.wait_settled(self.session.submit(tx).wait())

    def _wait_for(self, pred: Callable[[], bool], timeout: float = 10) -> None:
        deadline = time.monotonic() + timeout
        while time.monotonic() < deadline:
            if pred():
                return
            time.sleep(0.1)
        self.fail("timed out waiting for condition")

    def test_submit_claim_process_complete(self) -> None:
        completed: list[Job[TaskPayload]] = []

        def handler(job: Job[TaskPayload]) -> None:
            completed.append(job)

        w = Worker(GROUP, self.rn, Seconds(60), Seconds(1))
        bq = w.bind(b"jobs", TaskPayload, handler)

        job_id, tx = bq.submit(TaskPayload(target="0xabc", amount=42), self.session)
        self._submit(tx)

        self.assertFalse(bq.queue.pending.get(job_id).absent)
        self.assertEqual(bq.queue.pending_count(), 1)

        t = threading.Thread(target=w.run)
        t.start()

        self._wait_for(lambda: len(completed) == 1)

        self.assertEqual(completed[0].job_id, job_id)
        self.assertEqual(completed[0].payload.target, "0xabc")
        self.assertEqual(completed[0].payload.amount, 42)
        self.assertIsInstance(completed[0].payload, TaskPayload)

        w.stop()
        t.join(timeout=10)

        self.assertEqual(bq.queue.pending_count(), 0)
        self.assertEqual(bq.queue.active_count(w.worker_id), 0)

        workers = PlaintextMap(GROUP + b"w/", self.session)
        self.assertTrue(workers.get(w.worker_id).absent)

    def test_handler_crash_reclaims_to_pending(self) -> None:
        def crashing_handler(_job: Job[TaskPayload]) -> None:
            raise RuntimeError("boom")

        w = Worker(GROUP, self.rn, Seconds(60), Seconds(1))
        bq = w.bind(b"jobs", TaskPayload, crashing_handler)

        job_id, tx = bq.submit(TaskPayload(target="crash", amount=0), self.session)
        self._submit(tx)

        self.assertFalse(bq.queue.pending.get(job_id).absent)

        t = threading.Thread(target=w.run)
        t.start()

        self._wait_for(lambda: bq.queue.active_count(w.worker_id) == 0 and bq.queue.pending.get(job_id).absent is False)

        time.sleep(1)

        self.assertEqual(bq.queue.pending_count(), 1)
        self.assertFalse(bq.queue.pending.get(job_id).absent)

        w.stop()
        t.join(timeout=10)

    def test_cancellation_on_stop(self) -> None:
        seen_cancelled = threading.Event()

        def blocking_handler(job: Job[TaskPayload]) -> None:
            job.cancelled.wait(10)
            if job.cancelled.is_set():
                seen_cancelled.set()

        w = Worker(GROUP, self.rn, Seconds(60), Seconds(1))
        bq = w.bind(b"jobs", TaskPayload, blocking_handler)

        job_id, tx = bq.submit(TaskPayload(target="cancel", amount=0), self.session)
        self._submit(tx)

        t = threading.Thread(target=w.run)
        t.start()

        self._wait_for(lambda: bq.queue.active_count(w.worker_id) > 0)

        w.stop()
        t.join(timeout=10)

        self.assertTrue(seen_cancelled.is_set())

    def test_heartbeat_during_long_handler(self) -> None:
        handler_running = threading.Event()

        def slow_handler(job: Job[TaskPayload]) -> None:
            handler_running.set()
            job.cancelled.wait(10)

        w = Worker(GROUP, self.rn, Seconds(60), Seconds(1))
        bq = w.bind(b"jobs", TaskPayload, slow_handler)

        _, tx = bq.submit(TaskPayload(target="slow", amount=0), self.session)
        self._submit(tx)

        t = threading.Thread(target=w.run)
        t.start()

        handler_running.wait(10)
        workers = PlaintextMap(GROUP + b"w/", self.session)
        ts1, _ = _decode_worker(workers.get(w.worker_id).value)

        time.sleep(2)
        ts2, _ = _decode_worker(workers.get(w.worker_id).value)
        self.assertGreater(ts2, ts1)

        w.stop()
        t.join(timeout=10)

    def test_registry_lifecycle_and_cleanup(self) -> None:
        lease = Seconds(1)
        registry = WorkerRegistry(GROUP, self.rn)

        w = Worker(GROUP, self.rn, lease, Seconds(10), registry=registry)
        w.bind(b"jobs", TaskPayload, lambda _j: None)

        w.heartbeat()
        w.deregister()

        stale = Worker(GROUP, self.rn, lease, Seconds(10), registry=registry)
        stale.bind(b"jobs", TaskPayload, lambda _j: None)
        stale.register()

        w.register()

        self.assertEqual(len(list(registry.list_workers())), 2)
        self.assertEqual(len(list(registry.workers_for_queue(b"jobs"))), 2)

        threshold = Millis(int(lease * 3000))
        time.sleep(threshold / 1000 + 0.1)
        w.heartbeat()

        cleaned, tx = registry.cleanup_stale(threshold)
        self._submit(tx)
        self.assertEqual(cleaned, 1)

        remaining = list(registry.list_workers())
        self.assertEqual(len(remaining), 1)
        self.assertEqual(remaining[0][0], w.worker_id)
        self.assertEqual(len(list(registry.workers_for_queue(b"jobs"))), 1)

        stale.heartbeat()
        stale.deregister()

        self.assertEqual(w.cleanup_stale(), 0)

        bq = w.bind(b"jobs", TaskPayload, lambda _: None)
        _, submit_tx = bq.submit(TaskPayload(target="expire", amount=0), self.session)
        self._submit(submit_tx)
        result = bq.queue.claim_random(stale.worker_id, 0)
        assert result is not None
        _, claim_tx = result
        self._submit(claim_tx)
        self.assertEqual(bq.queue.active_count(stale.worker_id), 1)
        w.tick()
        self.assertEqual(bq.queue.active_count(stale.worker_id), 0)

        w.deregister()
        self.assertEqual(len(list(registry.list_workers())), 0)

    def test_multiple_jobs_processed_sequentially(self) -> None:
        order: list[bytes] = []
        done = threading.Event()

        def handler(job: Job[TaskPayload]) -> None:
            order.append(job.job_id)
            if len(order) >= 3:
                done.set()

        w = Worker(GROUP, self.rn, Seconds(60), Seconds(1))
        bq = w.bind(b"jobs", TaskPayload, handler)

        ids = []
        for i in range(3):
            jid, tx = bq.submit(TaskPayload(target=f"job-{i}", amount=i), self.session)
            self._submit(tx)
            ids.append(jid)

        self.assertEqual(bq.queue.pending_count(), 3)

        t = threading.Thread(target=w.run)
        t.start()

        self._wait_for(lambda: done.is_set())

        w.stop()
        t.join(timeout=10)

        self.assertEqual(len(order), 3)
        self.assertEqual(set(order), set(ids))
        self.assertEqual(bq.queue.pending_count(), 0)


if __name__ == "__main__":
    unittest.main()
