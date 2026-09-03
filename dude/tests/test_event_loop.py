import threading
import time
import unittest
from dataclasses import dataclass

from dude.core.event_loop import Event, EventLoop
from dude.core.units import Millis


class Ping(Event):
    __slots__ = ()


@dataclass(frozen=True, slots=True)
class Tagged(Event):
    label: str


class TestEventLoop(unittest.TestCase):
    def setUp(self) -> None:
        self.loop = EventLoop()

    def tearDown(self) -> None:
        self.loop.stop()

    def test_post_delivers_to_handler(self) -> None:
        got = threading.Event()
        results: list[str] = []

        def on_ping(_: Ping) -> None:
            results.append("ping")
            got.set()

        self.loop.register(Ping, on_ping)
        self.loop.start()
        self.loop.post(Ping())
        assert got.wait(timeout=1)
        assert results == ["ping"]

    def test_unregistered_event_raises(self) -> None:
        self.loop.register(Ping, lambda _: None)
        self.loop.start()
        self.loop.post(Tagged("boom"))
        time.sleep(0.05)
        assert self.loop._thread is None or not self.loop._thread.is_alive()

    def test_scheduled_fires_after_delay(self) -> None:
        got = threading.Event()
        fired_at: list[int] = []

        def on_ping(_: Ping) -> None:
            fired_at.append(int(Millis.now()))
            got.set()

        self.loop.register(Ping, on_ping)
        self.loop.start()
        before = int(Millis.now())
        self.loop.schedule(Millis.now() + Millis(100), Ping())
        assert got.wait(timeout=1)
        elapsed = fired_at[0] - before
        assert elapsed >= 80, f"fired too early: {elapsed}ms"

    def test_immediate_before_scheduled(self) -> None:
        gate = threading.Event()
        order: list[str] = []

        def on_tagged(e: Tagged) -> None:
            order.append(e.label)
            if len(order) == 2:
                gate.set()

        self.loop.register(Tagged, on_tagged)
        self.loop.schedule(Millis.now() + Millis(200), Tagged("scheduled"))
        self.loop.post(Tagged("immediate"))
        self.loop.start()
        assert gate.wait(timeout=1)
        assert order == ["immediate", "scheduled"]

    def test_fifo_at_same_deadline(self) -> None:
        gate = threading.Event()
        order: list[str] = []

        def on_tagged(e: Tagged) -> None:
            order.append(e.label)
            if len(order) == 3:
                gate.set()

        self.loop.register(Tagged, on_tagged)
        self.loop.start()
        self.loop.post(Tagged("a"))
        self.loop.post(Tagged("b"))
        self.loop.post(Tagged("c"))
        assert gate.wait(timeout=1)
        assert order == ["a", "b", "c"]

    def test_cancel_prevents_delivery(self) -> None:
        results: list[str] = []
        gate = threading.Event()

        def on_tagged(e: Tagged) -> None:
            results.append(e.label)
            gate.set()

        self.loop.register(Tagged, on_tagged)
        self.loop.start()
        handle = self.loop.schedule(Millis.now() + Millis(50), Tagged("doomed"))
        handle.cancel()
        self.loop.schedule(Millis.now() + Millis(100), Tagged("survivor"))
        assert gate.wait(timeout=1)
        assert results == ["survivor"]

    def test_reschedule_cancels_old_and_schedules_new(self) -> None:
        fired_at: list[int] = []
        gate = threading.Event()

        def on_ping(_: Ping) -> None:
            fired_at.append(int(Millis.now()))
            gate.set()

        self.loop.register(Ping, on_ping)
        self.loop.start()
        before = int(Millis.now())
        handle = self.loop.schedule(Millis.now() + Millis(500), Ping())
        new_handle = handle.reschedule(Millis.now() + Millis(50))
        assert handle.cancelled
        assert not new_handle.cancelled
        assert gate.wait(timeout=1)
        elapsed = fired_at[0] - before
        assert elapsed < 300, f"old timer fired instead of rescheduled: {elapsed}ms"
        assert len(fired_at) == 1

    def test_post_from_handler_does_not_deadlock(self) -> None:
        gate = threading.Event()
        results: list[str] = []

        def on_ping(_: Ping) -> None:
            results.append("ping")
            self.loop.post(Tagged("from_handler"))

        def on_tagged(e: Tagged) -> None:
            results.append(e.label)
            gate.set()

        self.loop.register(Ping, on_ping)
        self.loop.register(Tagged, on_tagged)
        self.loop.start()
        self.loop.post(Ping())
        assert gate.wait(timeout=1)
        assert results == ["ping", "from_handler"]

    def test_schedule_from_handler(self) -> None:
        gate = threading.Event()
        results: list[str] = []

        def on_ping(_: Ping) -> None:
            results.append("ping")
            self.loop.schedule(Millis.now() + Millis(30), Tagged("deferred"))

        def on_tagged(e: Tagged) -> None:
            results.append(e.label)
            gate.set()

        self.loop.register(Ping, on_ping)
        self.loop.register(Tagged, on_tagged)
        self.loop.start()
        self.loop.post(Ping())
        assert gate.wait(timeout=1)
        assert results == ["ping", "deferred"]

    def test_post_from_external_thread(self) -> None:
        gate = threading.Event()
        results: list[str] = []

        def on_tagged(e: Tagged) -> None:
            results.append(e.label)
            if len(results) == 3:
                gate.set()

        self.loop.register(Tagged, on_tagged)
        self.loop.start()

        def poster(label: str) -> None:
            self.loop.post(Tagged(label))

        threads = [threading.Thread(target=poster, args=(f"t{i}",)) for i in range(3)]
        for t in threads:
            t.start()
        for t in threads:
            t.join()
        assert gate.wait(timeout=1)
        assert len(results) == 3
        assert set(results) == {"t0", "t1", "t2"}

    def test_stop_is_clean(self) -> None:
        self.loop.register(Ping, lambda _: None)
        self.loop.start()
        self.loop.schedule(Millis.now() + Millis(10_000), Ping())
        self.loop.stop()
        assert self.loop._thread is None

    def test_cancelled_entries_are_garbage_collected(self) -> None:
        self.loop.register(Ping, lambda _: None)
        handles = [self.loop.schedule(Millis.now() + Millis(10_000), Ping()) for _ in range(10)]
        for h in handles:
            h.cancel()
        self.loop.start()
        self.loop.post(Ping())
        time.sleep(0.05)
        assert self.loop.pending() == 0

    def test_duplicate_registration_raises(self) -> None:
        self.loop.register(Ping, lambda _: None)
        with self.assertRaises(TypeError):
            self.loop.register(Ping, lambda _: None)

    def test_register_then_post(self) -> None:
        got = threading.Event()
        loop: EventLoop[Event] = EventLoop()
        loop.register(Ping, lambda _: got.set())
        loop.start()
        loop.post(Ping())
        assert got.wait(timeout=1)
        loop.stop()


if __name__ == "__main__":
    unittest.main()
