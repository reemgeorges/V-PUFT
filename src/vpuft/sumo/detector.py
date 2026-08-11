from __future__ import annotations

import math
from collections import defaultdict
from dataclasses import dataclass
from hashlib import sha256
from typing import Iterable

from ..config import DetectorConfig, SecurityConfig
from ..domain import (
    DetectionEvent,
    EvidenceDirection,
    MobilitySnapshot,
    SourceKind,
    V2XMessage,
)
from ..inference import infer_attack_type_from_reasons
from .sensors import KinematicObservation, emulate_kinematic_observation


@dataclass(frozen=True)
class RSU:
    rsu_id: str
    x: float
    y: float
    domain: str
    reliability: float


def distance(a_x: float, a_y: float, b_x: float, b_y: float) -> float:
    return math.hypot(a_x - b_x, a_y - b_y)


def geographic_cell(x: float, y: float, cell_size: float = 250.0) -> str:
    return f"cell-{int(x // cell_size)}-{int(y // cell_size)}"


def _clip(value: float, low: float = 0.01, high: float = 0.99) -> float:
    return min(high, max(low, float(value)))


def _hash_score(value: str) -> float:
    raw = int(sha256(value.encode("utf-8")).hexdigest()[:12], 16)
    return raw / float(16**12 - 1)


class DetectionEngine:
    """Label-blind local detector consuming independent sensor observations.

    The detector never compares a V2X report to SUMO oracle fields. SUMO truth
    is used only outside this decision logic by the sensor-emulation layer to
    generate a noisy observation of the sender at reception time.
    """

    def __init__(self, config: DetectorConfig, security: SecurityConfig, seed: int) -> None:
        self.config = config
        self.security = security
        self.seed = seed
        self.seen_nonce: dict[str, dict[str, float]] = defaultdict(dict)
        self.message_count: dict[tuple[str, int, str], int] = defaultdict(int)
        self.root_observers: dict[str, set[str]] = defaultdict(set)

    def _factors(
        self,
        *,
        message: V2XMessage,
        observation: KinematicObservation,
        observer_id: str,
        source_reliability: float,
        now: float,
        supports: bool,
        reasons: list[str],
    ) -> tuple[float, float, float, float, float]:
        age = max(0.0, now - message.generated_at)
        freshness = math.exp(-age / max(self.config.freshness_tau_seconds, 1e-9))
        if any(reason in {"certificate_tamper", "replay_nonce", "replay_age"} for reason in reasons):
            verifiability = 0.98
        elif reasons:
            verifiability = 0.86
        else:
            verifiability = 0.76
        previous_observers = len(self.root_observers[message.observation_root_id])
        independence = 0.92 if previous_observers == 0 else max(0.35, 0.80 - 0.12 * previous_observers)
        self.root_observers[message.observation_root_id].add(observer_id)
        if supports:
            confidence = 0.62
            position_severity = distance(
                observation.x,
                observation.y,
                message.reported_x,
                message.reported_y,
            ) / max(self.config.position_error_threshold_m, 1e-9)
            speed_severity = abs(observation.speed_mps - message.reported_speed_mps) / max(
                self.config.speed_error_threshold_mps, 1e-9
            )
            confidence += 0.18 * min(1.5, position_severity) + 0.18 * min(1.5, speed_severity)
            confidence += 0.08 if "certificate_tamper" in reasons or "replay_nonce" in reasons else 0.0
        else:
            confidence = self.config.benign_clean_confidence
        return (
            _clip(confidence),
            _clip(source_reliability),
            _clip(freshness),
            _clip(verifiability),
            _clip(independence),
        )

    def _reason_codes(
        self,
        message: V2XMessage,
        observation: KinematicObservation,
        observer_id: str,
        now: float,
    ) -> list[str]:
        reasons: list[str] = []
        if not message.certificate_valid:
            reasons.append("certificate_tamper")
        position_error = distance(
            observation.x,
            observation.y,
            message.reported_x,
            message.reported_y,
        )
        if position_error > self.config.position_error_threshold_m:
            reasons.append("position_inconsistency")
        if abs(observation.speed_mps - message.reported_speed_mps) > self.config.speed_error_threshold_mps:
            reasons.append("speed_inconsistency")
        nonce_seen_at = self.seen_nonce[observer_id].get(message.nonce)
        if nonce_seen_at is not None:
            reasons.append("replay_nonce")
        if now - message.generated_at > self.config.replay_max_age_seconds:
            reasons.append("replay_age")
        self.seen_nonce[observer_id][message.nonce] = now
        second_bucket = int(now)
        counter_key = (observer_id, second_bucket, message.sender_vehicle_id)
        self.message_count[counter_key] += 1
        if self.message_count[counter_key] > self.config.flood_messages_per_second:
            reasons.append("flood_rate")
        if (
            message.denm_claimed
            and observation.acceleration_mps2 > self.config.false_denm_deceleration_threshold_mps2
        ):
            reasons.append("false_denm_physical_mismatch")
        return sorted(set(reasons))

    @staticmethod
    def _direction_for_observation(reasons: list[str]) -> EvidenceDirection:
        # A clean observation is initially opposing evidence. If the surrounding
        # runtime case is later inferred as false-DENM/mixed, the case builder
        # reclassifies a clean non-DENM CAM as NEUTRAL from observed message flags.
        return EvidenceDirection.SUPPORTS if reasons else EvidenceDirection.OPPOSES

    @staticmethod
    def _compromised_direction(direction: EvidenceDirection) -> EvidenceDirection:
        if direction == EvidenceDirection.SUPPORTS:
            return EvidenceDirection.OPPOSES
        return EvidenceDirection.SUPPORTS

    def _observe(
        self,
        *,
        message: V2XMessage,
        target: MobilitySnapshot,
        observer_id: str,
        source_kind: SourceKind,
        source_reliability: float,
        validator_rsu_id: str,
        administrative_domain_id: str,
        geographic_cell_id: str,
        sensor_modality: str,
        compromised: bool,
        compromise_reason: str,
        now: float,
        observation_root_id: str,
        event_prefix: str,
        payload_extra: dict,
    ) -> DetectionEvent:
        observation = emulate_kinematic_observation(
            target=target,
            message=message,
            observer_id=observer_id,
            source_kind=source_kind,
            config=self.config,
        )
        reasons = self._reason_codes(message, observation, observer_id, now)
        direction = self._direction_for_observation(reasons)
        effective_reliability = source_reliability
        if compromised:
            direction = self._compromised_direction(direction)
            reasons = [compromise_reason]
            effective_reliability *= 0.45 if source_kind == SourceKind.RSU else 0.55
        supports = direction == EvidenceDirection.SUPPORTS
        confidence, reliability, freshness, verifiability, independence = self._factors(
            message=message,
            observation=observation,
            observer_id=observer_id,
            source_reliability=effective_reliability,
            now=now,
            supports=supports,
            reasons=reasons,
        )
        if source_kind == SourceKind.VEHICLE_WITNESS:
            independence = _clip(0.80 + 0.15 * _hash_score(f"{observation_root_id}|independence"))
        event_id = f"{event_prefix}-{sha256(f'{message.message_id}|{observer_id}|{now}'.encode()).hexdigest()[:24]}"
        observed_attack = infer_attack_type_from_reasons(reasons)
        runtime_stream_id = f"stream-{message.seed}-{message.sender_vehicle_id}"
        payload = {
            **payload_extra,
            "denm_claimed": bool(message.denm_claimed),
            "message_type": message.message_type,
            # Keep noisy sensor outputs for audit/reproducibility. These are the
            # exact kinematic values consumed by the detector.
            "observed_x": observation.x,
            "observed_y": observation.y,
            "observed_speed_mps": observation.speed_mps,
            "observed_acceleration_mps2": observation.acceleration_mps2,
        }
        return DetectionEvent(
            event_id=event_id,
            case_id=runtime_stream_id,
            observation_root_id=observation_root_id,
            seed=message.seed,
            vehicle_id=message.sender_vehicle_id,
            pseudonym=message.pseudonym,
            message_id=message.message_id,
            attack_type=observed_attack,
            detected_by=observer_id,
            source_kind=source_kind,
            validator_rsu_id=validator_rsu_id,
            detected_at=now,
            ground_truth_malicious=False,
            direction=direction,
            detector_confidence=confidence,
            source_reliability=reliability,
            freshness=freshness,
            verifiability=verifiability,
            independence=independence,
            raw_evidence_hash=sha256(
                f"{message.message_id}|{observation_root_id}|{observer_id}|{'|'.join(reasons)}|"
                f"{observation.x:.6f}|{observation.y:.6f}|{observation.speed_mps:.6f}|"
                f"{observation.acceleration_mps2:.6f}".encode()
            ).hexdigest(),
            geographic_cell=geographic_cell_id,
            administrative_domain_id=administrative_domain_id,
            sensor_modality=sensor_modality,
            reason_codes=tuple(
                reasons
                or (["not_applicable_observation"] if direction == EvidenceDirection.NEUTRAL else ["clean_observation"])
            ),
            payload=payload,
        )

    def observe_rsu(
        self,
        message: V2XMessage,
        rsu: RSU,
        now: float,
        target: MobilitySnapshot,
    ) -> DetectionEvent:
        compromised = rsu.rsu_id in set(self.security.compromised_rsus)
        return self._observe(
            message=message,
            target=target,
            observer_id=rsu.rsu_id,
            source_kind=SourceKind.RSU,
            source_reliability=rsu.reliability,
            validator_rsu_id=rsu.rsu_id,
            administrative_domain_id=rsu.domain,
            geographic_cell_id=geographic_cell(rsu.x, rsu.y),
            sensor_modality="rsu_cam_plausibility",
            compromised=compromised,
            compromise_reason="compromised_rsu_false_attestation",
            now=now,
            observation_root_id=message.observation_root_id,
            event_prefix="det",
            payload_extra={
                "observer_distance_m": distance(target.x, target.y, rsu.x, rsu.y),
                "compromised_rsu": compromised,
            },
        )

    def observe_witness(
        self,
        message: V2XMessage,
        target: MobilitySnapshot,
        witness: MobilitySnapshot,
        validator: RSU,
        now: float,
    ) -> DetectionEvent:
        witness_id = witness.vehicle_id
        source_reliability = 0.62 + 0.34 * _hash_score(f"{self.seed}|{witness_id}|reliability")
        compromised = _hash_score(f"{self.seed}|{witness_id}|compromised") < self.security.compromised_witness_ratio
        witness_root = f"wroot-{sha256(f'{message.observation_root_id}|{witness_id}'.encode()).hexdigest()[:24]}"
        return self._observe(
            message=message,
            target=target,
            observer_id=witness_id,
            source_kind=SourceKind.VEHICLE_WITNESS,
            source_reliability=source_reliability,
            validator_rsu_id=validator.rsu_id,
            administrative_domain_id=validator.domain,
            geographic_cell_id=geographic_cell(witness.x, witness.y),
            sensor_modality="vehicle_witness_observation",
            compromised=compromised,
            compromise_reason="compromised_witness_false_report",
            now=now,
            observation_root_id=witness_root,
            event_prefix="wdet",
            payload_extra={
                "witness_distance_m": distance(target.x, target.y, witness.x, witness.y),
                "compromised_witness": compromised,
            },
        )

    def reassess_event(
        self,
        *,
        message: V2XMessage,
        target: MobilitySnapshot,
        legacy_event: DetectionEvent,
        now: float,
    ) -> DetectionEvent:
        """Rebuild a stored detection event with the current sensor model.

        This is used by campaign upgrades so expensive SUMO mobility runs do not
        need to be repeated. Observer selection/topology metadata are reused, but
        reason codes, direction, confidence and sensor audit values are recomputed
        from generated messages plus reception-time mobility snapshots.
        """
        payload = dict(legacy_event.payload)
        if legacy_event.source_kind == SourceKind.RSU:
            compromised = bool(payload.get("compromised_rsu", False)) or (
                legacy_event.detected_by in set(self.security.compromised_rsus)
            )
            final_rel = float(legacy_event.source_reliability)
            raw_rel = final_rel / 0.45 if compromised else final_rel
            raw_rel = min(0.99, max(0.01, raw_rel))
            prefix = "det"
            compromise_reason = "compromised_rsu_false_attestation"
            payload_extra = {
                "observer_distance_m": payload.get("observer_distance_m"),
                "compromised_rsu": compromised,
            }
        else:
            compromised = bool(payload.get("compromised_witness", False)) or (
                _hash_score(f"{self.seed}|{legacy_event.detected_by}|compromised")
                < self.security.compromised_witness_ratio
            )
            raw_rel = 0.62 + 0.34 * _hash_score(f"{self.seed}|{legacy_event.detected_by}|reliability")
            prefix = "wdet"
            compromise_reason = "compromised_witness_false_report"
            payload_extra = {
                "witness_distance_m": payload.get("witness_distance_m"),
                "compromised_witness": compromised,
            }

        rebuilt = self._observe(
            message=message,
            target=target,
            observer_id=legacy_event.detected_by,
            source_kind=legacy_event.source_kind,
            source_reliability=raw_rel,
            validator_rsu_id=legacy_event.validator_rsu_id,
            administrative_domain_id=legacy_event.administrative_domain_id,
            geographic_cell_id=legacy_event.geographic_cell,
            sensor_modality=legacy_event.sensor_modality,
            compromised=compromised,
            compromise_reason=compromise_reason,
            now=now,
            observation_root_id=legacy_event.observation_root_id,
            event_prefix=prefix,
            payload_extra=payload_extra,
        )
        # Preserve stable stored event identity and evaluation-only truth metadata.
        merged_payload = dict(rebuilt.payload)
        for key in (
            "ground_truth_attack_type",
            "ground_truth_message_malicious",
            "ground_truth_case_attack_type",
            "ground_truth_case_malicious",
            "ground_truth_malicious_fraction",
        ):
            if key in payload:
                merged_payload[key] = payload[key]
        return DetectionEvent(
            event_id=legacy_event.event_id,
            case_id=rebuilt.case_id,
            observation_root_id=rebuilt.observation_root_id,
            seed=rebuilt.seed,
            vehicle_id=rebuilt.vehicle_id,
            pseudonym=rebuilt.pseudonym,
            message_id=rebuilt.message_id,
            attack_type=rebuilt.attack_type,
            detected_by=rebuilt.detected_by,
            source_kind=rebuilt.source_kind,
            validator_rsu_id=rebuilt.validator_rsu_id,
            detected_at=rebuilt.detected_at,
            ground_truth_malicious=legacy_event.ground_truth_malicious,
            direction=rebuilt.direction,
            detector_confidence=rebuilt.detector_confidence,
            source_reliability=rebuilt.source_reliability,
            freshness=rebuilt.freshness,
            verifiability=rebuilt.verifiability,
            independence=rebuilt.independence,
            raw_evidence_hash=rebuilt.raw_evidence_hash,
            geographic_cell=rebuilt.geographic_cell,
            administrative_domain_id=rebuilt.administrative_domain_id,
            sensor_modality=rebuilt.sensor_modality,
            reason_codes=rebuilt.reason_codes,
            payload=merged_payload,
        )


def rsus_in_range(x: float, y: float, rsus: Iterable[RSU], radius: float) -> list[RSU]:
    """Physical connectivity helper; x/y come from SUMO mobility, not trust logic."""
    return [rsu for rsu in rsus if distance(x, y, rsu.x, rsu.y) <= radius]


def nearest_rsu(x: float, y: float, rsus: Iterable[RSU]) -> RSU:
    candidates = list(rsus)
    if not candidates:
        raise ValueError("At least one RSU is required")
    return min(candidates, key=lambda rsu: distance(x, y, rsu.x, rsu.y))
