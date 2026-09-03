from __future__ import annotations

import heapq
import threading
from collections.abc import Callable
from dataclasses import dataclass, field

from .units import Millis


class Event:
    __slots__ = ()


@dataclass(slots=True, order=False)
class Scheduled[E: Event]:
    at: int
    seq: int
    event: E
    cancelled: bool = False
    _requeue: Callable[[Millis, E], Scheduled[E]] | None = field(default=None, repr=False)

    def __lt__(self, other: Scheduled[E]) -> bool:
        return (self.at, self.seq) < (other.at, other.seq)

    def cancel(self) -> None:
        self.cancelled = True

    def reschedule(self, at: Millis) -> Scheduled[E]:
        self.cancel()
        if self._requeue is None:
            raise RuntimeError("cannot reschedule an immediate event")
        return self._requeue(at, self.event)


class EventLoop[E: Event]:
    __slots__ = ("_cond", "_handlers", "_heap", "_seq", "_stopping", "_thread")

    def __init__(self) -> None:
        self._heap: list[Scheduled[E]] = []
        self._seq = 0
        self._handlers: dict[type, Callable] = {}
        self._cond = threading.Condition()
        self._thread: threading.Thread | None = None
        self._stopping = False

    def register[T: Event](self, event_type: type[T], handler: Callable[[T], None]) -> None:
        if event_type in self._handlers:
            raise TypeError(f"duplicate handler for {event_type.__name__}")
        self._handlers[event_type] = handler

    def post(self, event: E) -> None:
        with self._cond:
            heapq.heappush(self._heap, Scheduled(0, self._seq, event))
            self._seq += 1
            self._cond.notify()

    def schedule(self, at: Millis, event: E) -> Scheduled[E]:
        s = Scheduled(int(at), self._seq, event, _requeue=self.schedule)
        with self._cond:
            self._seq += 1
            heapq.heappush(self._heap, s)
            self._cond.notify()
        return s

    def pending(self) -> int:
        with self._cond:
            return sum(1 for e in self._heap if not e.cancelled)

    def start(self) -> None:
        if self._thread is not None:
            return
        self._stopping = False
        self._thread = threading.Thread(target=self._run, daemon=True)
        self._thread.start()

    def stop(self) -> None:
        with self._cond:
            self._stopping = True
            self._cond.notify()
        t = self._thread
        self._thread = None
        if t is not None:
            t.join()

    def _next_entry(self) -> Scheduled[E] | None:
        with self._cond:
            while not self._stopping:
                while self._heap and self._heap[0].cancelled:
                    heapq.heappop(self._heap)

                if not self._heap:
                    self._cond.wait()
                    continue

                entry = self._heap[0]
                now_ms = int(Millis.now())

                if entry.at > now_ms:
                    self._cond.wait(timeout=(entry.at - now_ms) / 1000)
                    continue

                return heapq.heappop(self._heap)

            return None

    def _run(self) -> None:
        while True:
            entry = self._next_entry()
            if entry is None:
                return
            handler = self._handlers.get(type(entry.event))
            if handler is None:
                raise TypeError(f"no handler for {type(entry.event).__name__}")
            handler(entry.event)
