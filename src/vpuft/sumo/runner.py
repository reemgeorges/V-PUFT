from __future__ import annotations

import importlib
import json
import os
import sys
from dataclasses import asdict, replace
from hashlib import sha256
from pathlib import Path
from typing import Any

import pandas as pd

from ..config import ResearchConfig
from ..domain import AttackType, MobilitySnapshot, V2XMessage
from ..trace import calibration_rows, sanitize_runtime_events, write_events_csv, write_events_jsonl
from .attacks import AttackInjector, load_attack_schedules
from .detector import DetectionEngine, RSU, distance, nearest_rsu, rsus_in_range
from .doctor import resolve_binary
from .prepare import prepare_sumo_scenario, scenario_prefix


def _load_traci():
    try:
        return importlib.import_module("traci")
    except ModuleNotFoundError:
        sumo_home = os.environ.get("SUMO_HOME")
        if sumo_home:
            tools = str(Path(sumo_home) / "tools")
            if tools not in sys.path:
                sys.path.append(tools)
            try:
                return importlib.import_module("traci")
            except ModuleNotFoundError:
                pass
        raise RuntimeError(
            "Python module 'traci' is unavailable. Install SUMO and add SUMO_HOME/tools to PYTHONPATH, "
            "or install the official PyPI package with 'pip install traci'."
        )


def _load_rsus(path: Path) -> list[RSU]:
    raw = json.loads(path.read_text(encoding="utf-8"))
    return [
        RSU(
            rsu_id=item["id"],
            x=float(item["x"]),
            y=float(item["y"]),
            domain=item.get("domain", "domain-1"),
            reliability=float(item.get("reliability", 0.9)),
        )
        for item in raw
    ]


def _message_row(message: V2XMessage) -> dict[str, Any]:
    row = asdict(message)
    row["attack_type"] = message.attack_type.value
    row["payload"] = json.dumps(dict(message.payload), sort_keys=True, ensure_ascii=False)
    return row


def _attach_evaluation_truth(event, message: V2XMessage):
    """Attach injected labels only after local detection has completed."""
    payload = dict(event.payload)
    payload["ground_truth_attack_type"] = message.attack_type.value
    payload["ground_truth_message_malicious"] = int(message.ground_truth_malicious)
    return replace(
        event,
        ground_truth_malicious=bool(message.ground_truth_malicious),
        payload=payload,
    )


def _hash_file(path: Path) -> str:
    return sha256(path.read_bytes()).hexdigest()


def run_sumo_trace(
    config: ResearchConfig,
    *,
    scenario_directory: str | Path,
    output_directory: str | Path,
    seed: int | None = None,
    force_prepare: bool = False,
) -> dict[str, Any]:
    seed = int(config.sumo.deterministic_seed if seed is None else seed)
    scenario = Path(scenario_directory).resolve()
    output = Path(output_directory).resolve()
    output.mkdir(parents=True, exist_ok=True)
    network_path = prepare_sumo_scenario(scenario, netconvert_binary=config.sumo.netconvert_binary, force=force_prepare)
    prefix = scenario_prefix(scenario)
    sumo_binary_name = "sumo-gui" if config.sumo.use_gui else "sumo"
    sumo_binary = resolve_binary(sumo_binary_name, config.sumo.sumo_binary)
    if not sumo_binary:
        raise RuntimeError(
            f"{sumo_binary_name} was not found. Install SUMO, add SUMO/bin to PATH, "
            "or configure sumo.sumo_binary."
        )
    traci = _load_traci()
    sumocfg = scenario / f"{prefix}.sumocfg"
    rsu_path = scenario / config.sumo.rsu_file
    attack_path = scenario / config.sumo.attack_file
    if not sumocfg.exists() or not rsu_path.exists() or not attack_path.exists():
        raise FileNotFoundError("The SUMO scenario is incomplete: sumocfg, RSU JSON, or attack JSON is missing")

    rsus = _load_rsus(rsu_path)
    schedules = load_attack_schedules(attack_path)
    injector = AttackInjector(seed, schedules, scenario_id=prefix)
    detector = DetectionEngine(config.detector, config.security, seed)
    mobility_rows: list[dict] = []
    message_rows: list[dict] = []
    events = []
    previous_speed: dict[str, tuple[float, float]] = {}
    observed_truth_meta: dict[str, dict[str, Any]] = {}
    observed_vehicle_ids: set[str] = set()
    peak_concurrent_vehicles = 0
    label = f"vpuft-{seed}"
    tripinfo = output / "sumo_tripinfo.xml"
    command = [
        sumo_binary,
        "-c", str(sumocfg),
        "--seed", str(seed),
        "--step-length", str(config.sumo.step_length_seconds),
        "--end", str(config.sumo.end_time_seconds),
        "--no-step-log", "true",
        "--duration-log.statistics", "true",
        "--tripinfo-output", str(tripinfo),
    ]

    traci.start(command, label=label)
    conn = traci.getConnection(label)
    try:
        while conn.simulation.getMinExpectedNumber() > 0:
            conn.simulationStep()
            now = float(conn.simulation.getTime())
            if now > config.sumo.end_time_seconds:
                break
            snapshots: dict[str, MobilitySnapshot] = {}
            for vehicle_id in sorted(conn.vehicle.getIDList()):
                observed_vehicle_ids.add(vehicle_id)
                x, y = map(float, conn.vehicle.getPosition(vehicle_id))
                speed = float(conn.vehicle.getSpeed(vehicle_id))
                old_time, old_speed = previous_speed.get(vehicle_id, (now - config.sumo.step_length_seconds, speed))
                dt = max(1e-9, now - old_time)
                acceleration = (speed - old_speed) / dt
                previous_speed[vehicle_id] = (now, speed)
                snapshot = MobilitySnapshot(
                    seed=seed,
                    simulation_time=now,
                    vehicle_id=vehicle_id,
                    x=x,
                    y=y,
                    speed_mps=speed,
                    acceleration_mps2=acceleration,
                    lane_id=str(conn.vehicle.getLaneID(vehicle_id)),
                    lane_position_m=float(conn.vehicle.getLanePosition(vehicle_id)),
                    road_id=str(conn.vehicle.getRoadID(vehicle_id)),
                )
                snapshots[vehicle_id] = snapshot
                mobility_rows.append(asdict(snapshot))
            peak_concurrent_vehicles = max(peak_concurrent_vehicles, len(snapshots))

            for vehicle_id, snapshot in snapshots.items():
                messages = injector.generate(snapshot, now)
                for message in messages:
                    message_rows.append(_message_row(message))
                    # Ground truth is maintained in a separate evaluation-only
                    # table. The message/runtime stream id is label-free.
                    truth_case_id = (
                        f"truth-{prefix}-{seed}-{message.sender_vehicle_id}-{message.attack_type.value}"
                    )
                    meta = observed_truth_meta.setdefault(truth_case_id, {
                        "case_id": truth_case_id,
                        "vehicle_id": message.sender_vehicle_id,
                        "attack_type": message.attack_type.value,
                        "ground_truth_malicious": int(message.ground_truth_malicious),
                        "first_message_at": now,
                        "last_message_at": now,
                    })
                    meta["first_message_at"] = min(meta["first_message_at"], now)
                    meta["last_message_at"] = max(meta["last_message_at"], now)

                    observers = rsus_in_range(snapshot.x, snapshot.y, rsus, config.detector.rsu_range_m)
                    for rsu in observers:
                        local_event = detector.observe_rsu(message, rsu, now, snapshot)
                        events.append(_attach_evaluation_truth(local_event, message))

                    witnesses = [
                        other for other_id, other in snapshots.items()
                        if other_id != vehicle_id
                        and distance(snapshot.x, snapshot.y, other.x, other.y) <= config.detector.witness_range_m
                    ]
                    witnesses.sort(key=lambda item: (distance(snapshot.x, snapshot.y, item.x, item.y), item.vehicle_id))
                    for witness in witnesses[:8]:
                        validator = nearest_rsu(witness.x, witness.y, rsus)
                        local_event = detector.observe_witness(message, snapshot, witness, validator, now)
                        events.append(_attach_evaluation_truth(local_event, message))
    finally:
        try:
            conn.close()
        except Exception:
            pass

    mobility_df = pd.DataFrame(mobility_rows)
    messages_df = pd.DataFrame(message_rows)
    event_rows = [
        {
            **asdict(event),
            "attack_type": event.attack_type.value,
            "source_kind": event.source_kind.value,
            "direction": int(event.direction),
            "reason_codes": "|".join(event.reason_codes),
            "payload": json.dumps(dict(event.payload), sort_keys=True, ensure_ascii=False),
        }
        for event in events
    ]
    detection_df = pd.DataFrame(event_rows)
    truth_df = pd.DataFrame(sorted(observed_truth_meta.values(), key=lambda row: row["case_id"]))
    runtime_events = sanitize_runtime_events(
        events,
        window_seconds=config.detector.case_window_seconds,
        namespace=prefix,
    )
    evidence_df = pd.DataFrame(calibration_rows(runtime_events))

    mobility_df.to_csv(output / "mobility_trace.csv", index=False)
    messages_df.to_csv(output / "generated_messages.csv", index=False)
    truth_df.to_csv(output / "attack_ground_truth.csv", index=False)
    detection_df.to_csv(output / "local_detections.csv", index=False)
    evidence_df.to_csv(output / "evidence_campaign.csv", index=False)
    write_events_jsonl(runtime_events, output / "shared_detection_trace.jsonl")
    write_events_csv(runtime_events, output / "shared_detection_trace.csv")

    manifest = {
        "mode": "sumo_traci",
        "seed": seed,
        "sumo_binary": sumo_binary,
        "scenario_directory": str(scenario),
        "scenario_files": {
            path.name: _hash_file(path)
            for path in [
                network_path,
                scenario / f"{prefix}.rou.xml",
                sumocfg,
                rsu_path,
                attack_path,
            ]
            if path.exists()
        },
        "counts": {
            "mobility_snapshots": len(mobility_rows),
            "v2x_messages": len(message_rows),
            "detection_events": len(events),
            "cases": len({event.case_id for event in runtime_events}),
            "rsu_events": sum(event.source_kind.value == "rsu" for event in events),
            "witness_events": sum(event.source_kind.value == "vehicle_witness" for event in events),
            "unique_vehicles_observed": len(observed_vehicle_ids),
            "peak_concurrent_vehicles": peak_concurrent_vehicles,
        },
        "outputs": [
            "mobility_trace.csv",
            "generated_messages.csv",
            "attack_ground_truth.csv",
            "local_detections.csv",
            "shared_detection_trace.jsonl",
            "shared_detection_trace.csv",
            "evidence_campaign.csv",
            "sumo_tripinfo.xml",
        ],
    }
    (output / "scenario_manifest.json").write_text(json.dumps(manifest, indent=2), encoding="utf-8")
    summary = {
        "seed": seed,
        "completed": True,
        "case_count": len({event.case_id for event in runtime_events}),
        "malicious_case_count": int(truth_df["ground_truth_malicious"].sum()) if not truth_df.empty else 0,
        "benign_case_count": int((truth_df["ground_truth_malicious"] == 0).sum()) if not truth_df.empty else 0,
        "detection_event_count": len(events),
    }
    (output / "run_summary.json").write_text(json.dumps(summary, indent=2), encoding="utf-8")
    return manifest
