from __future__ import annotations

import itertools
import random
from dataclasses import dataclass

from .config import NetworkConfig
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


class SimulatedTransport:
    """Seeded transport with loss, retry, propagation jitter and per-link serialization queues."""

    def __init__(self, config: NetworkConfig, seed: int) -> None:
        self.config = config
        self.rng = random.Random(seed)
        self._counter = itertools.count(1)
        self.messages: list[NetworkMessage] = []
        self._link_free_at: dict[tuple[str, str], float] = {}

    def send(
        self,
        *,
        message_type: str,
        sender: str,
        receiver: str,
        case_id: str,
        sent_at: float,
        size_bytes: int,
    ) -> NetworkMessage:
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
            delivered = self.rng.random() <= self.config.packet_delivery_ratio
            propagation_ms = max(0.1, self.rng.gauss(self.config.base_latency_ms, self.config.jitter_ms))
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
