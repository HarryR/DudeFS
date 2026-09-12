import threading
import time
import unittest
from dataclasses import dataclass

from ..core import serde
from ..core.units import Millis, Seconds
from ..ds.plaintext_map import PlaintextMap
from ..ds.queue import gen_id
from ..ds.worker import BoundQueue, Job, Worker, _decode_worker
from ..store import ops
from .cluster import Cluster

GROUP = b"g/"


@dataclass
class TaskPayload:
    target: str
    amount: int


class TestWorkerRegistry(unittest.TestCase):
    def setUp(self) -> None:
        self.c = Cluster(nodes=3, mgmt=1)
        self.session = self.c.replicas[0].session_rw()

    def tearDown(self) -> None:
        self.c.close()

    def test_register_and_deregister(self) -> None:
        w = Worker(GROUP, self.session, Seconds(60), Seconds(10))
        w.bind(b"jobs", TaskPayload, lambda _j: None)
        w.register()

        workers = PlaintextMap(GROUP + b"w/", self.session)
        rec = workers.get(w.worker_id)
        self.assertFalse(rec.absent)
        ts, queues = _decode_worker(rec.value)
        self.assertEqual(queues, (b"jobs",))
        self.assertGreater(ts, 0)

        qw = PlaintextMap(GROUP + b"qw/jobs/", self.session)
        self.assertFalse(qw.get(w.worker_id).absent)

        w.deregister()
        self.assertTrue(workers.get(w.worker_id).absent)
        self.assertTrue(qw.get(w.worker_id).absent)

    def test_multi_queue_registration(self) -> None:
        w = Worker(GROUP, self.session, Seconds(60), Seconds(10))
        w.bind(b"a", TaskPayload, lambda _j: None)
        w.bind(b"b", TaskPayload, lambda _j: None)
        w.register()

        _, queues = _decode_worker(PlaintextMap(GROUP + b"w/", self.session).get(w.worker_id).value)
        self.assertEqual(queues, (b"a", b"b"))

        qw_a = PlaintextMap(GROUP + b"qw/a/", self.session)
        qw_b = PlaintextMap(GROUP + b"qw/b/", self.session)
        self.assertFalse(qw_a.get(w.worker_id).absent)
        self.assertFalse(qw_b.get(w.worker_id).absent)

        w.deregister()

    def test_heartbeat_updates_timestamp(self) -> None:
        w = Worker(GROUP, self.session, Seconds(60), Seconds(10))
        w.bind(b"jobs", TaskPayload, lambda _j: None)
        w.register()

        workers = PlaintextMap(GROUP + b"w/", self.session)
        ts1, _ = _decode_worker(workers.get(w.worker_id).value)

        time.sleep(0.01)
        w.heartbeat()

        ts2, _ = _decode_worker(workers.get(w.worker_id).value)
        self.assertGreater(ts2, ts1)

        w.deregister()

    def test_cleanup_stale_worker(self) -> None:
        stale = Worker(GROUP, self.session, Seconds(60), Seconds(10))
        stale.bind(b"jobs", TaskPayload, lambda _j: None)
        stale._stale_threshold = Millis.ZERO
        stale.register()

        live = Worker(GROUP, self.session, Seconds(60), Seconds(10))
        live.bind(b"jobs", TaskPayload, lambda _j: None)
        live._stale_threshold = Millis.ZERO
        live.register()

        time.sleep(0.01)
        live.heartbeat()

        cleaned = live.cleanup_stale()
        self.assertEqual(cleaned, 1)

        workers = PlaintextMap(GROUP + b"w/", self.session)
        self.assertTrue(workers.get(stale.worker_id).absent)
        self.assertFalse(workers.get(live.worker_id).absent)

        qw = PlaintextMap(GROUP + b"qw/jobs/", self.session)
        self.assertTrue(qw.get(stale.worker_id).absent)
        self.assertFalse(qw.get(live.worker_id).absent)

        live.deregister()


class TestBoundQueueSubmit(unittest.TestCase):
    def setUp(self) -> None:
        self.c = Cluster(nodes=3, mgmt=1)
        self.session = self.c.replicas[0].session_rw()

    def tearDown(self) -> None:
        self.c.close()

    def _submit(self, tx: ops.Transaction) -> None:
        self.c.wait_settled(self.session.submit(tx).wait())

    def test_typed_submit_and_claim(self) -> None:
        w = Worker(GROUP, self.session, Seconds(60), Seconds(10))
        bq: BoundQueue[TaskPayload] = w.bind(b"jobs", TaskPayload, lambda _j: None)

        self._submit(bq.submit(TaskPayload(target="0xabc", amount=42)))
        self.assertEqual(bq.queue.pending_count(), 1)

        result = bq.queue.claim_random(w.worker_id, 9999)
        assert result is not None
        claim, _tx = result
        data_key = claim.payload.decode()
        rec = self.session.get(data_key)
        self.assertFalse(rec.absent)
        payload = serde.load(TaskPayload, rec.value)
        self.assertEqual(payload.target, "0xabc")
        self.assertEqual(payload.amount, 42)


class TestWorkerRunLoop(unittest.TestCase):
    def setUp(self) -> None:
        self.c = Cluster(nodes=3, mgmt=1)
        self.session = self.c.replicas[0].session_rw()

    def tearDown(self) -> None:
        self.c.close()

    def _submit(self, tx: ops.Transaction) -> None:
        self.c.wait_settled(self.session.submit(tx).wait())

    def test_worker_claims_and_completes_typed_job(self) -> None:
        results: list[Job[TaskPayload]] = []

        def handler(job: Job[TaskPayload]) -> None:
            results.append(job)

        w = Worker(GROUP, self.session, Seconds(60), Seconds(1))
        bq = w.bind(b"jobs", TaskPayload, handler)
        self._submit(bq.submit(TaskPayload(target="0xdef", amount=100)))

        t = threading.Thread(target=w.run)
        t.start()

        deadline = time.monotonic() + 10
        while time.monotonic() < deadline:
            if results:
                break
            time.sleep(0.1)

        w.stop()
        t.join(timeout=5)

        self.assertEqual(len(results), 1)
        self.assertEqual(results[0].payload.target, "0xdef")
        self.assertEqual(results[0].payload.amount, 100)
        self.assertIsInstance(results[0].payload, TaskPayload)
        self.assertEqual(bq.queue.pending_count(), 0)
        self.assertEqual(bq.queue.active_count(w.worker_id), 0)

    def test_worker_deregisters_on_stop(self) -> None:
        w = Worker(GROUP, self.session, Seconds(60), Seconds(1))
        w.bind(b"jobs", TaskPayload, lambda _j: None)

        t = threading.Thread(target=w.run)
        t.start()

        workers = PlaintextMap(GROUP + b"w/", self.session)
        deadline = time.monotonic() + 10
        while time.monotonic() < deadline:
            if not workers.get(w.worker_id).absent:
                break
            time.sleep(0.1)
        self.assertFalse(workers.get(w.worker_id).absent)

        w.stop()
        t.join(timeout=10)

        self.assertTrue(workers.get(w.worker_id).absent)


class TestWorkerEdgeCases(unittest.TestCase):
    def setUp(self) -> None:
        self.c = Cluster(nodes=3, mgmt=1)
        self.session = self.c.replicas[0].session_rw()

    def tearDown(self) -> None:
        self.c.close()

    def test_deregister_when_absent(self) -> None:
        w = Worker(GROUP, self.session, Seconds(60), Seconds(10))
        w.bind(b"jobs", TaskPayload, lambda _j: None)
        w.deregister()

    def test_heartbeat_when_absent(self) -> None:
        w = Worker(GROUP, self.session, Seconds(60), Seconds(10))
        w.bind(b"jobs", TaskPayload, lambda _j: None)
        w.heartbeat()

    def test_lease_renewal_fires_during_long_handler(self) -> None:
        renewed = threading.Event()

        def slow_handler(_job: Job[TaskPayload]) -> None:
            renewed.wait(10)

        w = Worker(GROUP, self.session, Seconds(60), Seconds(1))
        bq = w.bind(b"jobs", TaskPayload, slow_handler)
        tx = bq.submit(TaskPayload(target="x", amount=1))
        self.c.wait_settled(self.session.submit(tx).wait())

        t = threading.Thread(target=w.run)
        t.start()

        time.sleep(2)
        self.assertEqual(bq.queue.lease.count(), 1)
        renewed.set()

        w.stop()
        t.join(timeout=10)


class TestGenId(unittest.TestCase):
    def test_length_and_uniqueness(self) -> None:
        ids = {gen_id() for _ in range(100)}
        self.assertEqual(len(ids), 100)
        for i in ids:
            self.assertEqual(len(i), 11)
            self.assertTrue(i.isalnum())


if __name__ == "__main__":
    unittest.main()
