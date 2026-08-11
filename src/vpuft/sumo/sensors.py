from __future__ import annotations

import math
from dataclasses import dataclass
from hashlib import sha256

from ..config import DetectorConfig
from ..domain import MobilitySnapshot, SourceKind, V2XMessage


@dataclass(frozen=True, slots=True)
class KinematicObservation:
    """Noisy independent observation of the sender at reception time.

    SUMO mobility truth is used only here, as a simulator input for generating
    a reproducible sensor measurement. The trust detector consumes only this
    observation plus the V2X-reported values.
    """

    x: float
    y: float
    speed_mps: float
    acceleration_mps2: float


def _uniform01(key: str) -> float:
    raw = int(sha256(key.encode("utf-8")).hexdigest()[:16], 16)
    return (raw + 0.5) / float(16**16)


def _normal(key: str) -> float:
    # Deterministic Box-Muller draw. Clamp away from zero for log stability.
    u1 = max(1e-15, _uniform01(key + "|u1"))
    u2 = _uniform01(key + "|u2")
    return math.sqrt(-2.0 * math.log(u1)) * math.cos(2.0 * math.pi * u2)


def emulate_kinematic_observation(
    *,
    target: MobilitySnapshot,
    message: V2XMessage,
    observer_id: str,
    source_kind: SourceKind,
    config: DetectorConfig,
) -> KinematicObservation:
    """Generate a deterministic noisy sensor observation.

    The noise key contains seed, reception-time snapshot, message identity,
    observer identity and source type. Thus runs are reproducible while RSU and
    witness observations remain independent across observers/messages.
    """

    if source_kind == SourceKind.RSU:
        pos_sigma = config.rsu_position_sigma_m
        speed_sigma = config.rsu_speed_sigma_mps
        accel_sigma = config.rsu_acceleration_sigma_mps2
    else:
        pos_sigma = config.witness_position_sigma_m
        speed_sigma = config.witness_speed_sigma_mps
        accel_sigma = config.witness_acceleration_sigma_mps2

    base = (
        f"{target.seed}|{target.simulation_time:.6f}|{message.message_id}|"
        f"{observer_id}|{source_kind.value}"
    )
    return KinematicObservation(
        x=target.x + pos_sigma * _normal(base + "|x"),
        y=target.y + pos_sigma * _normal(base + "|y"),
        speed_mps=max(0.0, target.speed_mps + speed_sigma * _normal(base + "|speed")),
        acceleration_mps2=target.acceleration_mps2 + accel_sigma * _normal(base + "|accel"),
    )
