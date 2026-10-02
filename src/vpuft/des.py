from __future__ import annotations

import heapq
import itertools
from dataclasses import dataclass, field
from typing import Callable, Any


class CausalityError(RuntimeError):
    """Raised when code tries to schedule work before the current simulation time."""


@dataclass(order=True)
class _Event:
    time: float
    generation: int
    phase_rank: int
    case_order_index: int
    key: str
    attempt: int
    sequence: int
    callback: Callable[[], Any] = field(compare=False)


class Scheduler:
    """Small deterministic discrete-event scheduler.

    Independent events are ordered by simulation time and stable semantic keys.
    Events created causally at the current timestamp are placed in the next
    generation so they always run after their parent without adding fake time.
    """

    def __init__(self) -> None:
        self.now = 0.0
        self._heap: list[_Event] = []
        self._sequence = itertools.count()
        self._running = False
        self._generation = 0

    def schedule(
        self,
        time: float,
        callback: Callable[[], Any],
        *,
        phase_rank: int = 50,
        case_order_index: int = 0,
        key: str = "",
        attempt: int = 0,
    ) -> None:
        when = float(time)
        if self._running and when < self.now - 1e-12:
            raise CausalityError(
                f"Cannot schedule event in the past: now={self.now:.12f}, requested={when:.12f}, key={key}"
            )
        generation = self._generation + 1 if self._running and abs(when - self.now) <= 1e-12 else 0
        heapq.heappush(
            self._heap,
            _Event(
                when,
                generation,
                int(phase_rank),
                int(case_order_index),
                str(key),
                int(attempt),
                next(self._sequence),
                callback,
            ),
        )

    def run(self) -> None:
        while self._heap:
            event = heapq.heappop(self._heap)
            if event.time < self.now - 1e-12:
                raise CausalityError(
                    f"Scheduler time regressed: now={self.now:.12f}, event={event.time:.12f}, key={event.key}"
                )
            self.now = event.time
            self._generation = event.generation
            self._running = True
            try:
                event.callback()
            finally:
                self._running = False
                self._generation = 0

    @property
    def pending(self) -> int:
        return len(self._heap)
