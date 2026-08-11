from __future__ import annotations

import random
from dataclasses import dataclass
from hashlib import sha256

from .config import ResearchConfig
from .crypto import KeyRegistry
from .domain import AttackType, DetectionEvent, EvidenceDirection, SourceKind
from .trace import TraceBundle, build_trace_bundle


ScenarioBundle = TraceBundle

_ATTACKS = [
    AttackType.POSITION_OFFSET,
    AttackType.SPEED_OFFSET,
    AttackType.REPLAY,
    AttackType.CERTIFICATE_TAMPER,
    AttackType.FLOOD,
    AttackType.FALSE_DENM,
    AttackType.MIXED,
]


def _hash_text(text: str) -> str:
    return sha256(text.encode("utf-8")).hexdigest()


def _bounded(rng: random.Random, mean: float, spread: float = 0.08) -> float:
    return min(0.99, max(0.01, rng.gauss(mean, spread)))


def _direction(rng: random.Random, malicious: bool, source_reliability: float) -> EvidenceDirection:
    correctness = 0.55 + 0.43 * source_reliability
    correct = rng.random() < correctness
    if malicious:
        return EvidenceDirection.SUPPORTS if correct else EvidenceDirection.OPPOSES
    return EvidenceDirection.OPPOSES if correct else EvidenceDirection.SUPPORTS


def _event(
    *,
    rng: random.Random,
    seed: int,
    case_id: str,
    root_id: str,
    vehicle_id: str,
    pseudonym: str,
    attack: AttackType,
    malicious: bool,
    source_id: str,
    source_kind: SourceKind,
    validator: str,
    observed_at: float,
    index: int,
    correlated: bool,
    reliability: float,
) -> DetectionEvent:
    direction = _direction(rng, malicious, reliability)
    confidence_base = 0.88 if direction == EvidenceDirection.SUPPORTS else 0.80
    event_id = f"evt-{_hash_text(f'{case_id}|{root_id}|{source_id}|{index}')[:24]}"
    return DetectionEvent(
        event_id=event_id,
        case_id=case_id,
        observation_root_id=root_id,
        seed=seed,
        vehicle_id=vehicle_id,
        pseudonym=pseudonym,
        message_id=f"msg-{case_id}-{index}",
        attack_type=attack,
        detected_by=source_id,
        source_kind=source_kind,
        validator_rsu_id=validator,
        detected_at=observed_at,
        ground_truth_malicious=malicious,
        direction=direction,
        detector_confidence=_bounded(rng, confidence_base),
        source_reliability=_bounded(rng, reliability, 0.05),
        freshness=_bounded(rng, 0.94),
        verifiability=_bounded(rng, 0.96 if attack in {AttackType.REPLAY, AttackType.CERTIFICATE_TAMPER} else 0.84),
        independence=_bounded(rng, 0.38 if correlated else 0.88, 0.05),
        raw_evidence_hash=_hash_text(f"{case_id}|{root_id}|{source_id}|{direction.value}"),
        geographic_cell=f"cell-{index % 4}-{(index // 4) % 4}",
        administrative_domain_id=f"domain-{(index % 3) + 1}",
        sensor_modality="vehicle_witness_observation" if source_kind == SourceKind.VEHICLE_WITNESS else (
            "rsu_cam_plausibility" if index % 2 == 0 else "trajectory_consistency"
        ),
        reason_codes=("synthetic_support",) if direction == EvidenceDirection.SUPPORTS else ("synthetic_clean",),
        payload={"synthetic": True, "case_opened_at": observed_at - index * 0.03},
    )


def generate_scenario(config: ResearchConfig, keys: KeyRegistry, seed: int) -> ScenarioBundle:
    rng = random.Random(seed)
    events: list[DetectionEvent] = []
    base_time = seed * 0.01
    for case_index in range(config.simulation.cases_per_seed):
        malicious = rng.random() < config.simulation.malicious_ratio
        attack = rng.choice(_ATTACKS) if malicious else AttackType.BENIGN
        vehicle_id = f"veh-{seed}-{case_index:04d}"
        pseudonym = f"ps-{_hash_text(vehicle_id)[:12]}"
        case_id = f"case-{seed}-{case_index:04d}"
        event_time = base_time + case_index * 0.25

        rsu_reports = max(2, int(rng.gauss(4.0, 1.0)))
        unique_roots = 1 if rng.random() < 0.18 else min(rsu_reports, max(2, int(rng.gauss(3.0, 0.8))))
        roots = [f"root-{case_id}-{i}" for i in range(unique_roots)]
        for i in range(rsu_reports):
            source = f"rsu-{(i % config.simulation.rsu_count) + 1}"
            root = roots[i % len(roots)]
            events.append(_event(
                rng=rng,
                seed=seed,
                case_id=case_id,
                root_id=root,
                vehicle_id=vehicle_id,
                pseudonym=pseudonym,
                attack=attack,
                malicious=malicious,
                source_id=source,
                source_kind=SourceKind.RSU,
                validator=source,
                observed_at=event_time + i * 0.03,
                index=i,
                correlated=i >= unique_roots,
                reliability=0.91 if source != "rsu-6" else 0.68,
            ))

        witness_count = max(2, int(rng.gauss(config.simulation.witness_count_mean, 1.0)))
        for i in range(witness_count):
            witness = f"wit-{seed}-{case_index}-{i}"
            events.append(_event(
                rng=rng,
                seed=seed,
                case_id=case_id,
                root_id=f"wroot-{case_id}-{i}",
                vehicle_id=vehicle_id,
                pseudonym=pseudonym,
                attack=attack,
                malicious=malicious,
                source_id=witness,
                source_kind=SourceKind.VEHICLE_WITNESS,
                validator=f"rsu-{(i % config.simulation.rsu_count) + 1}",
                observed_at=event_time + i * 0.04,
                index=i,
                correlated=False,
                reliability=_bounded(rng, 0.78, 0.10),
            ))
    return build_trace_bundle(events, keys)
