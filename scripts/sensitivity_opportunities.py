"""Offline helpers for fixed attack-opportunity evaluation in Scenario 5."""
from __future__ import annotations

import math
import re
from collections import defaultdict
from typing import Iterable, Mapping

CAM_ID = re.compile(r"^cam-(?P<seed>\d+)-(?P<vehicle>.+)-(?P<index>\d{6})$")
MESSAGE_ID = re.compile(r"^cam-(?P<seed>\d+)-(?P<vehicle>.+)-(?P<index>\d{6})(?:-[fm]\d+)?$")


def _finite_timestamp(value: object, label: str) -> float:
    try:
        result = float(value)
    except (TypeError, ValueError) as exc:
        raise ValueError(f"Missing or invalid {label} timestamp") from exc
    if not math.isfinite(result):
        raise ValueError(f"Missing or invalid {label} timestamp")
    return result


def _truth(value: object) -> bool:
    if isinstance(value, bool):
        return value
    return str(value).strip().lower() in {"1", "true", "yes"}


def build_base_emission_times(
    mobility_rows: Iterable[Mapping[str, object]], *, seed: int
) -> dict[str, float]:
    """Map each per-vehicle CAM counter ID to its actual mobility timestamp."""
    grouped: dict[str, list[float]] = defaultdict(list)
    seen: set[tuple[str, float]] = set()
    for row in mobility_rows:
        vehicle = str(row["vehicle_id"])
        timestamp = _finite_timestamp(row.get("simulation_time"), "mobility")
        key = (vehicle, timestamp)
        if key in seen:
            raise ValueError(f"Duplicate mobility frame: {key}")
        seen.add(key)
        grouped[vehicle].append(timestamp)
    return {
        f"cam-{int(seed)}-{vehicle}-{index:06d}": timestamp
        for vehicle, times in grouped.items()
        for index, timestamp in enumerate(sorted(times))
    }


def emission_time_for_message(
    message: Mapping[str, object], base_emission_times: Mapping[str, float]
) -> float:
    """Return transmission time; replay payload time is not replay send time."""
    message_id = str(message.get("message_id", ""))
    seed = int(message["seed"])
    vehicle = str(message["sender_vehicle_id"])
    if message_id.startswith("replay-"):
        base_id = message_id[len("replay-"):]
        match = CAM_ID.fullmatch(base_id)
        if match is None:
            raise ValueError(f"Invalid replay transmission ID: {message_id}")
        if int(match.group("seed")) != seed or match.group("vehicle") != vehicle:
            raise ValueError(f"Replay ID does not match seed/vehicle: {message_id}")
        if base_id not in base_emission_times:
            raise ValueError(f"Replay current-send ID is missing from mobility map: {base_id}")
        return _finite_timestamp(base_emission_times[base_id], "replay transmission")
    match = MESSAGE_ID.fullmatch(message_id)
    if match is None:
        raise ValueError(f"Invalid emitted CAM message ID: {message_id}")
    if int(match.group("seed")) != seed or match.group("vehicle") != vehicle:
        raise ValueError(f"Message ID does not match seed/vehicle: {message_id}")
    return _finite_timestamp(message.get("generated_at"), "message emission")


def opportunity_case_id(
    seed: int,
    vehicle_id: str,
    timestamp: object,
    *,
    window_seconds: float = 15.0,
    namespace: str = "urban_roundabout",
) -> str:
    try:
        window = float(window_seconds)
    except (TypeError, ValueError) as exc:
        raise ValueError("window_seconds must be positive and finite") from exc
    if not math.isfinite(window) or window <= 0:
        raise ValueError("window_seconds must be positive and finite")
    t = max(0.0, _finite_timestamp(timestamp, "opportunity"))
    index = int(math.floor(t / window))
    return f"case-{namespace}-{int(seed)}-{vehicle_id}-w{index:04d}"


def first_committed_revocations(
    decision_rows: Iterable[Mapping[str, object]],
) -> dict[str, float]:
    """Return earliest finalized_at for each vehicle with a committed REVOKED state."""
    result: dict[str, float] = {}
    for row in decision_rows:
        if not _truth(row.get("committed")) or str(row.get("new_state", "")).lower() != "revoked":
            continue
        vehicle = str(row["vehicle_id"])
        timestamp = _finite_timestamp(row.get("finalized_at"), "committed revocation")
        result[vehicle] = min(timestamp, result.get(vehicle, math.inf))
    return result


def evaluate_attack_opportunities(
    attack_rows: Iterable[Mapping[str, object]],
    observation_rows: Iterable[Mapping[str, object]],
    decision_rows: Iterable[Mapping[str, object]],
    base_emission_times: Mapping[str, float],
    *,
    seed: int,
    window_seconds: float = 15.0,
    namespace: str = "urban_roundabout",
) -> dict[str, int | float]:
    """Evaluate emitted malicious message IDs on a fixed denominator.

    Observed means at least one detection event names the emitted ID. Detected
    means observed and its mapped case committed revocation. Protected means the
    vehicle's first committed revocation finalized strictly before transmission.
    Repeated observations and roots never multiply a message opportunity.
    """
    attacks = list(attack_rows)
    observations_input = list(observation_rows)
    decisions_input = list(decision_rows)
    message_ids = [str(row.get("message_id", "")) for row in attacks]
    if any(not mid for mid in message_ids):
        raise ValueError("Attack opportunity is missing message ID")
    if len(set(message_ids)) != len(message_ids):
        raise ValueError("duplicate emitted attack opportunity message ID")
    attack_by_id = {str(row["message_id"]): row for row in attacks}
    emission_times = {
        str(row["message_id"]): emission_time_for_message(row, base_emission_times)
        for row in attacks
    }

    decisions: dict[str, Mapping[str, object]] = {}
    for row in decisions_input:
        case_id = str(row["case_id"])
        if case_id in decisions:
            raise ValueError(f"Duplicate case decision: {case_id}")
        decisions[case_id] = row
    first_revocations = first_committed_revocations(decisions_input)

    observations: dict[str, set[str]] = defaultdict(set)
    rsu_message_ids: set[str] = set()
    for row in observations_input:
        mid = str(row.get("message_id", ""))
        if not mid:
            raise ValueError("Detection observation is missing message ID")
        detected_at = _finite_timestamp(row.get("detected_at"), "detection observation")
        attack = attack_by_id.get(mid)
        if attack is not None:
            if detected_at < emission_times[mid]:
                raise ValueError(f"Detection observation precedes emission for {mid}")
            if int(row.get("seed", seed)) != int(attack.get("seed", seed)):
                raise ValueError(f"Detection event seed mismatch for {mid}")
            if str(row.get("vehicle_id", attack["sender_vehicle_id"])) != str(attack["sender_vehicle_id"]):
                raise ValueError(f"Detection event vehicle mismatch for {mid}")
        observations[mid].add(str(row["case_id"]))
        if str(row.get("source_kind", "")).lower() == "rsu":
            rsu_message_ids.add(mid)

    observed = detected = protected = rsu_observed = 0
    for message in attacks:
        if "ground_truth_malicious" in message and not _truth(message["ground_truth_malicious"]):
            raise ValueError("Non-malicious row included in attack opportunity denominator")
        row_seed = int(message.get("seed", seed))
        if row_seed != int(seed):
            raise ValueError(f"Attack opportunity seed mismatch: {row_seed} != {seed}")
        vehicle = str(message["sender_vehicle_id"])
        mid = str(message["message_id"])
        emission = emission_times[mid]
        case_id = opportunity_case_id(seed, vehicle, emission,
                                      window_seconds=window_seconds, namespace=namespace)
        cases = observations.get(mid, set())
        if cases and cases != {case_id}:
            raise ValueError(
                f"Observed message case mismatch for {mid}: {sorted(cases)} != {case_id}"
            )
        is_observed = bool(cases)
        observed += int(is_observed)
        rsu_observed += int(mid in rsu_message_ids)
        decision = decisions.get(case_id)
        if (is_observed and decision is not None and _truth(decision.get("committed"))
                and str(decision.get("new_state", "")).lower() == "revoked"):
            detected += 1
        if vehicle in first_revocations and first_revocations[vehicle] < emission:
            protected += 1

    total = len(attacks)
    return {
        "attack_message_opportunities": total,
        "observed_attack_messages": observed,
        "rsu_observed_attack_messages": rsu_observed,
        "unobserved_attack_messages": total - observed,
        "successfully_detected_attack_messages": detected,
        "missed_attack_messages": total - detected,
        "opportunity_detection_recall": detected / total if total else 0.0,
        "protected_attack_messages": protected,
        "protected_opportunity_fraction": protected / total if total else 0.0,
    }
