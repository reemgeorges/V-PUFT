from __future__ import annotations

import hashlib
import itertools
import random
from dataclasses import dataclass
from typing import Callable

from .config import NetworkConfig
from .des import CausalityError, Scheduler
from .domain import NetworkMessage


@dataclass
class TransportStats:
    messages: list[NetworkMessage]

    @property
    def delivered(self) -> int:
        return sum(not m.dropped for m in self.messages)

    @property
    def dropped(self) -> int:
        return sum(m.dropped for m in self.messages)

    @property
    def total_bytes(self) -> int:
        return sum(m.size_bytes for m in self.messages)


def audit_link_order(
    messages: list[NetworkMessage],
    queue_rate_bytes_per_second: float = 2_000_000.0,
) -> dict[str, float | int]:
    """Audit chronological request order and serialization overlap per directed link."""
    inversions = 0
    overlaps = 0
    last_requested: dict[tuple[str, str], float] = {}
    intervals: dict[tuple[str, str], list[tuple[float, float]]] = {}
    queue_delays = []
    for message in messages:
        link = (message.sender, message.receiver)
        previous = last_requested.get(link)
        if previous is not None and message.sent_at < previous - 1e-12:
            inversions += 1
        last_requested[link] = message.sent_at
        start = message.sent_at + message.queue_delay_ms / 1000.0
        end = start + message.size_bytes / max(float(queue_rate_bytes_per_second), 1.0)
        intervals.setdefault(link, []).append((start, end))
        queue_delays.append(message.queue_delay_ms)
    for values in intervals.values():
        values.sort()
        for (_, prev_end), (next_start, _) in zip(values, values[1:]):
            if next_start < prev_end - 1e-12:
                overlaps += 1
    return {
        "temporal_inversions": inversions,
        "serialization_overlaps": overlaps,
        "mean_queue_delay_ms": (sum(queue_delays) / len(queue_delays)) if queue_delays else 0.0,
        "max_queue_delay_ms": max(queue_delays, default=0.0),
    }


class SimulatedTransport:
    """Seeded transport with loss, retry, propagation jitter and per-link serialization queues.

    ``send`` is retained as the legacy synchronous API for older experiments.
    Corrected Scenario 5 uses ``send_async`` on a shared ``Scheduler`` so every
    directed-link request is processed in simulation-time order.
    """

    def __init__(self, config: NetworkConfig, seed: int, scheduler: Scheduler | None = None) -> None:
        self.config = config
        self.seed = int(seed)
        self.scheduler = scheduler
        self.rng = random.Random(seed)
        self._counter = itertools.count(1)
        self.messages: list[NetworkMessage] = []
        self._link_free_at: dict[tuple[str, str], float] = {}
        self._last_requested_at: dict[tuple[str, str], float] = {}

    def _keyed_rng(
        self,
        *,
        random_key: str,
        attempt: int,
        random_stream_seed: int | str | None = None,
    ) -> random.Random:
        stream_seed = self.seed if random_stream_seed is None else random_stream_seed
        digest = hashlib.sha256(
            f"{stream_seed}|{random_key}|attempt={attempt}".encode("utf-8")
        ).digest()
        return random.Random(int.from_bytes(digest[:8], "big"))

    def _default_random_key(
        self,
        *,
        message_type: str,
        sender: str,
        receiver: str,
        case_id: str,
        sent_at: float,
        size_bytes: int,
    ) -> str:
        return (
            f"{message_type}|{case_id}|{sender}|{receiver}|"
            f"t={float(sent_at):.12f}|bytes={int(size_bytes)}"
        )

    def send(
        self,
        *,
        message_type: str,
        sender: str,
        receiver: str,
        case_id: str,
        sent_at: float,
        size_bytes: int,
        random_key: str | None = None,
    ) -> NetworkMessage:
        """Legacy synchronous send; preserved for non-corrected experiments/tests."""
        if size_bytes <= 0:
            raise ValueError("Network message size must be positive")
        attempt = 0
        requested_time = sent_at
        while True:
            link = (sender, receiver)
            queue_start = max(requested_time, self._link_free_at.get(link, requested_time))
            serialization_seconds = size_bytes / max(self.config.queue_rate_bytes_per_second, 1.0)
            self._link_free_at[link] = queue_start + serialization_seconds
            queue_delay_ms = max(0.0, queue_start - requested_time) * 1000.0
            draw_rng = self.rng
            if self.config.evidence_crn_seed is not None and random_key is not None:
                draw_rng = self._keyed_rng(
                    random_key=random_key,
                    attempt=attempt,
                    random_stream_seed=self.config.evidence_crn_seed,
                )
            delivered = draw_rng.random() <= self.config.packet_delivery_ratio
            propagation_ms = max(0.1, draw_rng.gauss(self.config.base_latency_ms, self.config.jitter_ms))
            if receiver == "central-server":
                propagation_ms += self.config.central_backhaul_extra_latency_ms
            delivered_at = queue_start + serialization_seconds + propagation_ms / 1000.0 if delivered else None
            message = NetworkMessage(
                message_id=f"net-{next(self._counter)}",
                message_type=message_type,
                sender=sender,
                receiver=receiver,
                case_id=case_id,
                sent_at=requested_time,
                size_bytes=size_bytes,
                delivered_at=delivered_at,
                dropped=not delivered,
                retransmission=attempt,
                queue_delay_ms=queue_delay_ms,
            )
            self.messages.append(message)
            if delivered or attempt >= self.config.max_retries:
                return message
            attempt += 1
            requested_time = queue_start + serialization_seconds + self.config.retry_backoff_ms / 1000.0

    def send_async(
        self,
        *,
        message_type: str,
        sender: str,
        receiver: str,
        case_id: str,
        sent_at: float,
        size_bytes: int,
        on_complete: Callable[[NetworkMessage, float], None],
        case_order_index: int = 0,
        random_key: str | None = None,
        random_stream_seed: int | str | None = None,
        phase_rank: int = 10,
    ) -> None:
        if self.scheduler is None:
            raise ValueError("send_async requires a shared Scheduler")
        if size_bytes <= 0:
            raise ValueError("Network message size must be positive")
        logical_key = random_key or self._default_random_key(
            message_type=message_type,
            sender=sender,
            receiver=receiver,
            case_id=case_id,
            sent_at=sent_at,
            size_bytes=size_bytes,
        )

        def schedule_attempt(requested_time: float, attempt: int) -> None:
            def execute_attempt() -> None:
                link = (sender, receiver)
                previous_request = self._last_requested_at.get(link)
                if previous_request is not None and requested_time < previous_request - 1e-12:
                    raise CausalityError(
                        f"Out-of-order request on {link}: {requested_time:.12f} < {previous_request:.12f}"
                    )
                self._last_requested_at[link] = requested_time
                queue_start = max(requested_time, self._link_free_at.get(link, requested_time))
                serialization_seconds = size_bytes / max(self.config.queue_rate_bytes_per_second, 1.0)
                self._link_free_at[link] = queue_start + serialization_seconds
                queue_delay_ms = max(0.0, queue_start - requested_time) * 1000.0
                draw_rng = self._keyed_rng(
                    random_key=logical_key,
                    attempt=attempt,
                    random_stream_seed=random_stream_seed,
                )
                delivered = draw_rng.random() <= self.config.packet_delivery_ratio
                propagation_ms = max(0.1, draw_rng.gauss(self.config.base_latency_ms, self.config.jitter_ms))
                if receiver == "central-server":
                    propagation_ms += self.config.central_backhaul_extra_latency_ms
                delivered_at = (
                    queue_start + serialization_seconds + propagation_ms / 1000.0
                    if delivered
                    else None
                )
                message = NetworkMessage(
                    message_id=f"net-{next(self._counter)}",
                    message_type=message_type,
                    sender=sender,
                    receiver=receiver,
                    case_id=case_id,
                    sent_at=requested_time,
                    size_bytes=size_bytes,
                    delivered_at=delivered_at,
                    dropped=not delivered,
                    retransmission=attempt,
                    queue_delay_ms=queue_delay_ms,
                )
                self.messages.append(message)
                serialization_end = queue_start + serialization_seconds
                if delivered:
                    self.scheduler.schedule(
                        delivered_at,
                        lambda m=message, t=delivered_at: on_complete(m, t),
                        phase_rank=phase_rank + 5,
                        case_order_index=case_order_index,
                        key=f"deliver:{logical_key}",
                        attempt=attempt,
                    )
                    return
                if attempt < self.config.max_retries:
                    retry_at = serialization_end + self.config.retry_backoff_ms / 1000.0
                    schedule_attempt(retry_at, attempt + 1)
                    return
                self.scheduler.schedule(
                    serialization_end,
                    lambda m=message, t=serialization_end: on_complete(m, t),
                    phase_rank=phase_rank + 5,
                    case_order_index=case_order_index,
                    key=f"drop-final:{logical_key}",
                    attempt=attempt,
                )

            self.scheduler.schedule(
                requested_time,
                execute_attempt,
                phase_rank=phase_rank,
                case_order_index=case_order_index,
                key=f"send:{logical_key}",
                attempt=attempt,
            )

        schedule_attempt(float(sent_at), 0)

    def broadcast(
        self,
        *,
        message_type: str,
        sender: str,
        receivers: list[str],
        case_id: str,
        sent_at: float,
        size_bytes: int,
    ) -> list[NetworkMessage]:
        return [
            self.send(
                message_type=message_type,
                sender=sender,
                receiver=receiver,
                case_id=case_id,
                sent_at=sent_at,
                size_bytes=size_bytes,
            )
            for receiver in receivers
            if receiver != sender
        ]
