from __future__ import annotations

import csv
import json
import math
from collections import Counter, defaultdict
from dataclasses import asdict, dataclass, replace
from hashlib import sha256
from pathlib import Path
from typing import Iterable

from .crypto import KeyRegistry
from .domain import (
    AttackType,
    DetectionEvent,
    EvidenceAttestation,
    EvidenceCase,
    EvidenceDirection,
    SourceKind,
)
from .evidence import sign_attestation
from .inference import infer_attack_type_from_reasons, infer_attack_type_from_root_reasons


DEFAULT_CASE_WINDOW_SECONDS = 15.0


@dataclass(frozen=True)
class TraceBundle:
    seed: int
    events: list[DetectionEvent]
    rsu_cases: list[EvidenceCase]
    witness_cases: list[EvidenceCase]


def _hash_text(value: str) -> str:
    return sha256(value.encode("utf-8")).hexdigest()


def event_to_dict(event: DetectionEvent) -> dict:
    data = asdict(event)
    data["attack_type"] = event.attack_type.value
    data["source_kind"] = event.source_kind.value
    data["direction"] = int(event.direction)
    data["reason_codes"] = list(event.reason_codes)
    data["payload"] = dict(event.payload)
    return data


def event_from_dict(data: dict) -> DetectionEvent:
    raw = dict(data)
    raw["attack_type"] = AttackType(raw["attack_type"])
    raw["source_kind"] = SourceKind(raw["source_kind"])
    raw["direction"] = EvidenceDirection(int(raw["direction"]))
    raw["reason_codes"] = tuple(raw.get("reason_codes", []))
    raw["payload"] = raw.get("payload", {})
    return DetectionEvent(**raw)


def write_events_jsonl(events: Iterable[DetectionEvent], path: str | Path) -> Path:
    destination = Path(path)
    destination.parent.mkdir(parents=True, exist_ok=True)
    with destination.open("w", encoding="utf-8", newline="\n") as handle:
        for event in sorted(events, key=lambda item: (item.detected_at, item.event_id)):
            handle.write(json.dumps(event_to_dict(event), sort_keys=True, ensure_ascii=False) + "\n")
    return destination


def read_events_jsonl(path: str | Path) -> list[DetectionEvent]:
    events: list[DetectionEvent] = []
    with Path(path).open("r", encoding="utf-8") as handle:
        for line_number, line in enumerate(handle, start=1):
            if not line.strip():
                continue
            try:
                events.append(event_from_dict(json.loads(line)))
            except Exception as exc:
                raise ValueError(f"Invalid trace line {line_number}: {exc}") from exc
    return events


def write_events_csv(events: Iterable[DetectionEvent], path: str | Path) -> Path:
    destination = Path(path)
    destination.parent.mkdir(parents=True, exist_ok=True)
    rows = []
    for event in events:
        row = event_to_dict(event)
        row["reason_codes"] = "|".join(event.reason_codes)
        row["payload"] = json.dumps(event.payload, sort_keys=True, ensure_ascii=False)
        rows.append(row)
    if not rows:
        destination.write_text("", encoding="utf-8")
        return destination
    with destination.open("w", encoding="utf-8", newline="") as handle:
        writer = csv.DictWriter(handle, fieldnames=list(rows[0].keys()))
        writer.writeheader()
        writer.writerows(rows)
    return destination


def _is_synthetic(events: list[DetectionEvent]) -> bool:
    return bool(events) and all(bool(event.payload.get("synthetic")) for event in events)


def _truth_attack_value(event: DetectionEvent) -> str:
    # New traces keep the injected label in explicit evaluation-only metadata.
    # Legacy traces stored it in event.attack_type; the upgrader uses this
    # fallback only before the event is sanitized.
    value = event.payload.get("ground_truth_attack_type")
    if value is None:
        value = event.attack_type.value
    return str(value)


def _case_truth_metadata(group: list[DetectionEvent]) -> tuple[bool, str, float]:
    """Evaluation label from observed time occupancy, not traffic volume.

    Runtime windows are already fixed before this function is called. For
    scoring only, each observed simulation timestamp gets one vote so a flood
    burst cannot make a boundary window look more malicious merely because it
    emitted more packets.
    """
    by_time: dict[float, list[DetectionEvent]] = defaultdict(list)
    for event in group:
        by_time[round(float(event.detected_at), 6)].append(event)
    if not by_time:
        return False, AttackType.BENIGN.value, 0.0

    malicious_time_attacks: list[str] = []
    malicious_times = 0
    for time_key in sorted(by_time):
        at_time = by_time[time_key]
        malicious_events = [event for event in at_time if bool(event.ground_truth_malicious)]
        if not malicious_events:
            continue
        malicious_times += 1
        counts = Counter(_truth_attack_value(event) for event in malicious_events)
        malicious_time_attacks.append(
            sorted(counts.items(), key=lambda item: (-item[1], item[0]))[0][0]
        )

    malicious_fraction = malicious_times / len(by_time)
    # The >= 0.5 rule is used only after label-free case formation.
    case_malicious = malicious_fraction >= 0.5
    if not case_malicious or not malicious_time_attacks:
        return False, AttackType.BENIGN.value, malicious_fraction
    attack_counts = Counter(malicious_time_attacks)
    ground_truth_attack = sorted(attack_counts.items(), key=lambda item: (-item[1], item[0]))[0][0]
    return True, ground_truth_attack, malicious_fraction

def _runtime_case_id(seed: int, vehicle_id: str, window_index: int, namespace: str | None) -> str:
    prefix = f"{namespace}-" if namespace else ""
    return f"case-{prefix}{seed}-{vehicle_id}-w{window_index:04d}"


def sanitize_runtime_events(
    events: Iterable[DetectionEvent],
    *,
    window_seconds: float = DEFAULT_CASE_WINDOW_SECONDS,
    namespace: str | None = None,
) -> list[DetectionEvent]:
    """Build runtime evidence cases without using attack labels or schedules.

    Cases are deterministic fixed surveillance windows grouped by seed + vehicle.
    Attack type is inferred from detector ``reason_codes`` only. Ground truth is
    copied into explicitly named evaluation metadata only after case formation.

    Existing events already carrying ``runtime_case_formed`` are returned as-is;
    synthetic traces keep their original case semantics so the synthetic unit
    campaign remains backward compatible.
    """
    event_list = sorted(list(events), key=lambda item: (item.detected_at, item.event_id))
    if not event_list:
        return []
    if window_seconds <= 0:
        raise ValueError("window_seconds must be positive")
    if _is_synthetic(event_list):
        return event_list
    if all(bool(event.payload.get("runtime_case_formed")) for event in event_list):
        return event_list

    grouped: dict[tuple[int, str, int], list[DetectionEvent]] = defaultdict(list)
    for event in event_list:
        window_index = int(math.floor(max(0.0, float(event.detected_at)) / float(window_seconds)))
        grouped[(int(event.seed), str(event.vehicle_id), window_index)].append(event)

    sanitized: list[DetectionEvent] = []
    for (seed, vehicle_id, window_index), group in sorted(grouped.items(), key=lambda item: item[0]):
        # Preserve observation-root provenance during runtime case inference.
        reasons_by_root: dict[str, set[str]] = {}
        for event in group:
            root_reasons = reasons_by_root.setdefault(
                str(event.observation_root_id), set()
            )
            root_reasons.update(reason for reason in event.reason_codes if reason)

        inferred_attack = infer_attack_type_from_root_reasons(
            reasons_by_root.values()
        )
        case_malicious, ground_truth_attack, malicious_fraction = _case_truth_metadata(group)
        runtime_case_id = _runtime_case_id(seed, vehicle_id, window_index, namespace)
        window_opened_at = window_index * float(window_seconds)

        for event in group:
            payload = dict(event.payload)
            message_truth = bool(payload.get("ground_truth_message_malicious", event.ground_truth_malicious))
            original_truth_attack = str(payload.get("ground_truth_attack_type", _truth_attack_value(event)))
            denm_claimed = payload.get("denm_claimed")

            direction = event.direction
            reasons = tuple(event.reason_codes)
            # A clean CAM does not test an intermittent DENM claim. This rewrite
            # is driven by the *inferred* surrounding case type plus the observed
            # message denm_claimed flag; no injected attack label is consulted.
            if (
                inferred_attack in {AttackType.FALSE_DENM, AttackType.MIXED}
                and denm_claimed is False
                and direction == EvidenceDirection.OPPOSES
                and set(reasons).issubset({"clean_observation", "not_applicable_observation"})
            ):
                direction = EvidenceDirection.NEUTRAL
                reasons = ("not_applicable_observation",)

            payload.pop("case_opened_at", None)
            payload.pop("attack_ended_at", None)
            payload.update({
                "runtime_case_formed": True,
                "runtime_case_opened_at": window_opened_at,
                "runtime_window_index": window_index,
                "runtime_case_window_seconds": float(window_seconds),
                "inferred_attack_type": inferred_attack.value,
                # Evaluation-only fields. They are never used for case formation,
                # attack inference, policy selection, or qualification.
                "ground_truth_message_malicious": int(message_truth),
                "ground_truth_attack_type": original_truth_attack,
                "ground_truth_case_malicious": int(case_malicious),
                "ground_truth_case_attack_type": ground_truth_attack,
                "ground_truth_malicious_fraction": malicious_fraction,
            })

            sanitized.append(replace(
                event,
                case_id=runtime_case_id,
                attack_type=inferred_attack,
                ground_truth_malicious=case_malicious,
                direction=direction,
                reason_codes=reasons,
                payload=payload,
            ))

    return sorted(sanitized, key=lambda item: (item.detected_at, item.event_id))


def _case_metadata(events: list[DetectionEvent]) -> tuple[str, str, AttackType, float, bool]:
    first = min(events, key=lambda event: event.detected_at)
    return (
        first.vehicle_id,
        first.pseudonym,
        first.attack_type,
        min(
            float(
                event.payload.get(
                    "runtime_case_opened_at",
                    event.payload.get("case_opened_at", event.detected_at),
                )
            )
            for event in events
        ),
        first.ground_truth_malicious,
    )


def events_to_cases(events: Iterable[DetectionEvent], keys: KeyRegistry) -> tuple[list[EvidenceCase], list[EvidenceCase]]:
    grouped: dict[tuple[str, SourceKind], list[DetectionEvent]] = defaultdict(list)
    for event in events:
        grouped[(event.case_id, event.source_kind)].append(event)

    rsu_cases: list[EvidenceCase] = []
    witness_cases: list[EvidenceCase] = []
    for (case_id, source_kind), group in sorted(grouped.items(), key=lambda item: item[0]):
        vehicle_id, pseudonym, attack_type, opened_at, malicious = _case_metadata(group)
        if any(event.attack_type != attack_type for event in group):
            raise ValueError(f"Runtime case {case_id} contains inconsistent inferred attack types")
        case = EvidenceCase(
            case_id=case_id,
            vehicle_id=vehicle_id,
            pseudonym=pseudonym,
            attack_type=attack_type,
            opened_at=opened_at,
            ground_truth_malicious=malicious,
        )
        for event in sorted(group, key=lambda item: (item.detected_at, item.event_id)):
            attestation = EvidenceAttestation(
                attestation_id=f"att-{_hash_text(event.event_id + '|' + event.detected_by)[:24]}",
                case_id=event.case_id,
                observation_root_id=event.observation_root_id,
                source_id=event.detected_by,
                source_kind=event.source_kind.value,
                validator_rsu_id=event.validator_rsu_id,
                administrative_domain_id=event.administrative_domain_id,
                sensor_modality=event.sensor_modality,
                geographic_cell=event.geographic_cell,
                attack_type=attack_type,
                direction=event.direction,
                detector_confidence=event.detector_confidence,
                source_reliability=event.source_reliability,
                freshness=event.freshness,
                verifiability=event.verifiability,
                independence=event.independence,
                observed_at=event.detected_at,
                evidence_hash=event.raw_evidence_hash,
                signature="",
                public_key_id="",
                validity=1,
                reason_codes=event.reason_codes,
            )
            case.add(sign_attestation(attestation, keys, event.detected_by))
        if source_kind == SourceKind.RSU:
            rsu_cases.append(case)
        else:
            witness_cases.append(case)
    return rsu_cases, witness_cases


def build_trace_bundle(
    events: Iterable[DetectionEvent],
    keys: KeyRegistry,
    *,
    window_seconds: float = DEFAULT_CASE_WINDOW_SECONDS,
    namespace: str | None = None,
) -> TraceBundle:
    raw_events = sorted(list(events), key=lambda event: (event.detected_at, event.event_id))
    if not raw_events:
        raise ValueError("Cannot build a trace bundle from an empty event list")
    seeds = {event.seed for event in raw_events}
    if len(seeds) != 1:
        raise ValueError("A TraceBundle must contain exactly one seed")
    event_list = sanitize_runtime_events(raw_events, window_seconds=window_seconds, namespace=namespace)
    rsu_cases, witness_cases = events_to_cases(event_list, keys)
    return TraceBundle(seed=next(iter(seeds)), events=event_list, rsu_cases=rsu_cases, witness_cases=witness_cases)


def calibration_rows(events: Iterable[DetectionEvent]) -> list[dict]:
    """Architecture-independent rows used for V-PUFT weight sensitivity."""
    rows = []
    for event in events:
        rows.append({
            "case_id": event.case_id,
            "observation_root_id": event.observation_root_id,
            "seed": event.seed,
            # Runtime/inferred type: this is the only type used for policy selection.
            "attack_type": event.attack_type.value,
            # Evaluation-only label. Sensitivity uses it only to score candidates,
            # never to form cases or choose a policy.
            "label": int(event.ground_truth_malicious),
            "ground_truth_attack_type": str(event.payload.get("ground_truth_case_attack_type", "unknown")),
            "validity": 1,
            "direction": int(event.direction),
            "source_id": event.detected_by,
            "source_kind": event.source_kind.value,
            "validator_rsu_id": event.validator_rsu_id,
            "administrative_domain_id": event.administrative_domain_id,
            "geographic_cell": event.geographic_cell,
            "sensor_modality": event.sensor_modality,
            "detector_confidence": event.detector_confidence,
            "source_reliability": event.source_reliability,
            "freshness": event.freshness,
            "verifiability": event.verifiability,
            "independence": event.independence,
            "observed_at": event.detected_at,
            "reason_codes": "|".join(event.reason_codes),
        })
    return rows
