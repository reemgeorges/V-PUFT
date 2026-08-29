from __future__ import annotations

import argparse
import bisect
import json
from dataclasses import replace
from pathlib import Path

import pandas as pd

from vpuft.config import WeightConfig, load_config
from vpuft.domain import AttackType, MobilitySnapshot, V2XMessage
from vpuft.runner import run_trace_campaign
from vpuft.sensitivity import select_weights
from vpuft.sumo.detector import DetectionEngine
from vpuft.trace import calibration_rows, read_events_jsonl, sanitize_runtime_events, write_events_jsonl


TOPOLOGIES = ("smoke", "corridor", "intersection", "grid")


def _as_bool(value) -> bool:
    if isinstance(value, bool):
        return value
    if isinstance(value, (int, float)) and not pd.isna(value):
        return bool(value)
    text = str(value).strip().lower()
    if text in {"true", "1", "yes", "y"}:
        return True
    if text in {"false", "0", "no", "n", "", "nan", "none"}:
        return False
    raise ValueError(f"Cannot interpret boolean value: {value!r}")


def _json_object(value) -> dict:
    if isinstance(value, dict):
        return dict(value)
    if value is None or (isinstance(value, float) and pd.isna(value)):
        return {}
    text = str(value).strip()
    if not text or text.lower() == "nan":
        return {}
    parsed = json.loads(text)
    return dict(parsed) if isinstance(parsed, dict) else {}


def _load_messages(seed_dir: Path) -> dict[str, V2XMessage]:
    path = seed_dir / "generated_messages.csv"
    if not path.exists():
        raise FileNotFoundError(f"Missing {path}")
    frame = pd.read_csv(path)
    result: dict[str, V2XMessage] = {}
    for row in frame.to_dict(orient="records"):
        message = V2XMessage(
            message_id=str(row["message_id"]),
            original_message_id=str(row["original_message_id"]),
            case_id=str(row["case_id"]),
            observation_root_id=str(row["observation_root_id"]),
            seed=int(row["seed"]),
            sender_vehicle_id=str(row["sender_vehicle_id"]),
            pseudonym=str(row["pseudonym"]),
            message_type=str(row["message_type"]),
            generated_at=float(row["generated_at"]),
            true_x=float(row["true_x"]),
            true_y=float(row["true_y"]),
            true_speed_mps=float(row["true_speed_mps"]),
            true_acceleration_mps2=float(row["true_acceleration_mps2"]),
            reported_x=float(row["reported_x"]),
            reported_y=float(row["reported_y"]),
            reported_speed_mps=float(row["reported_speed_mps"]),
            reported_acceleration_mps2=float(row["reported_acceleration_mps2"]),
            nonce=str(row["nonce"]),
            certificate_valid=_as_bool(row["certificate_valid"]),
            denm_claimed=_as_bool(row["denm_claimed"]),
            attack_type=AttackType(str(row["attack_type"])),
            ground_truth_malicious=_as_bool(row["ground_truth_malicious"]),
            retransmission_index=int(row.get("retransmission_index", 0) or 0),
            payload=_json_object(row.get("payload")),
        )
        result[message.message_id] = message
    return result


class _MobilityIndex:
    def __init__(self, seed_dir: Path) -> None:
        path = seed_dir / "mobility_trace.csv"
        if not path.exists():
            raise FileNotFoundError(f"Missing {path}")
        frame = pd.read_csv(path)
        self.exact: dict[tuple[str, float], MobilitySnapshot] = {}
        self.times: dict[str, list[float]] = {}
        self.rows: dict[str, list[MobilitySnapshot]] = {}
        for row in frame.to_dict(orient="records"):
            snap = MobilitySnapshot(
                seed=int(row["seed"]),
                simulation_time=float(row["simulation_time"]),
                vehicle_id=str(row["vehicle_id"]),
                x=float(row["x"]),
                y=float(row["y"]),
                speed_mps=float(row["speed_mps"]),
                acceleration_mps2=float(row["acceleration_mps2"]),
                lane_id=str(row["lane_id"]),
                lane_position_m=float(row["lane_position_m"]),
                road_id=str(row["road_id"]),
            )
            key = (snap.vehicle_id, round(snap.simulation_time, 6))
            self.exact[key] = snap
            self.times.setdefault(snap.vehicle_id, []).append(snap.simulation_time)
            self.rows.setdefault(snap.vehicle_id, []).append(snap)
        for vehicle_id in self.times:
            paired = sorted(zip(self.times[vehicle_id], self.rows[vehicle_id]), key=lambda item: item[0])
            self.times[vehicle_id] = [item[0] for item in paired]
            self.rows[vehicle_id] = [item[1] for item in paired]

    def get(self, vehicle_id: str, observed_at: float) -> MobilitySnapshot:
        exact = self.exact.get((str(vehicle_id), round(float(observed_at), 6)))
        if exact is not None:
            return exact
        times = self.times.get(str(vehicle_id), [])
        rows = self.rows.get(str(vehicle_id), [])
        if not times:
            raise KeyError(f"No mobility for vehicle {vehicle_id}")
        idx = bisect.bisect_left(times, float(observed_at))
        choices = []
        if idx < len(times):
            choices.append((abs(times[idx] - observed_at), rows[idx]))
        if idx > 0:
            choices.append((abs(times[idx - 1] - observed_at), rows[idx - 1]))
        delta, snap = min(choices, key=lambda item: item[0])
        if delta > 1e-4:
            raise KeyError(f"No reception-time mobility for {vehicle_id} at {observed_at}; nearest delta={delta}")
        return snap


def _rebuild_seed_events(seed_dir: Path, cfg):
    trace_path = seed_dir / "shared_detection_trace.jsonl"
    if not trace_path.exists():
        raise FileNotFoundError(f"Missing {trace_path}")
    messages = _load_messages(seed_dir)
    mobility = _MobilityIndex(seed_dir)
    legacy = read_events_jsonl(trace_path)
    if not legacy:
        return []
    seed = int(legacy[0].seed)
    detector = DetectionEngine(cfg.detector, cfg.security, seed)
    rebuilt = []
    unresolved = 0
    for event in sorted(legacy, key=lambda item: (item.detected_at, item.message_id, item.detected_by, item.event_id)):
        message = messages.get(str(event.message_id))
        if message is None:
            unresolved += 1
            continue
        target = mobility.get(event.vehicle_id, event.detected_at)
        new_event = detector.reassess_event(
            message=message,
            target=target,
            legacy_event=event,
            now=float(event.detected_at),
        )
        payload = dict(new_event.payload)
        payload["ground_truth_attack_type"] = message.attack_type.value
        payload["ground_truth_message_malicious"] = int(message.ground_truth_malicious)
        rebuilt.append(replace(
            new_event,
            ground_truth_malicious=bool(message.ground_truth_malicious),
            payload=payload,
        ))
    if unresolved:
        raise RuntimeError(f"{seed_dir}: {unresolved} events could not be matched to generated_messages.csv")
    return rebuilt


def _case_count(events) -> int:
    return len({event.case_id for event in events})


def _inference_audit(events) -> pd.DataFrame:
    rows = {}
    for event in events:
        rows[event.case_id] = {
            "case_id": event.case_id,
            "seed": event.seed,
            "vehicle_id": event.vehicle_id,
            "inferred_attack_type": event.attack_type.value,
            "ground_truth_attack_type": str(event.payload.get("ground_truth_case_attack_type", "unknown")),
            "ground_truth_malicious": int(event.ground_truth_malicious),
            "malicious_fraction": float(event.payload.get("ground_truth_malicious_fraction", 0.0)),
        }
    frame = pd.DataFrame(rows.values())
    if not frame.empty:
        frame["attack_type_correct"] = (
            frame["inferred_attack_type"].astype(str) == frame["ground_truth_attack_type"].astype(str)
        ).astype(int)
    return frame


def _is_architecture_complete(path: Path) -> bool:
    return (path / "run_manifest.json").exists() and (path / "metrics_by_seed.csv").exists()


def main() -> None:
    parser = argparse.ArgumentParser(
        description=(
            "Upgrade an existing V-PUFT SUMO campaign to independent noisy sensor observations, "
            "ground-truth-free case formation and reason-code attack inference without rerunning SUMO."
        )
    )
    parser.add_argument("--input", default="results/full_campaign")
    parser.add_argument("--output", default="results/full_campaign_v4")
    parser.add_argument("--config", default="configs/full_experiment.json")
    parser.add_argument("--candidates", type=int, default=1200)
    parser.add_argument("--bootstrap-repeats", type=int, default=200)
    parser.add_argument("--permutation-repeats", type=int, default=50)
    parser.add_argument("--min-recall", type=float, default=0.95)
    parser.add_argument("--max-frr", type=float, default=0.05)
    parser.add_argument("--jobs", type=int, default=2)
    parser.add_argument("--checkpoint-every", type=int, default=25)
    parser.add_argument("--resume", action="store_true")
    args = parser.parse_args()

    source = Path(args.input).resolve()
    output = Path(args.output).resolve()
    if source == output:
        raise ValueError("--output must differ from --input")
    output.mkdir(parents=True, exist_ok=True)
    cfg = load_config(args.config)
    window_seconds = float(cfg.detector.case_window_seconds)

    all_calibration = []
    all_inference_audit = []
    runtime_trace_paths: dict[str, Path] = {}
    correction_audit = []

    print("[v4] rebuilding detector evidence from reception-time noisy sensor observations ...", flush=True)
    print(
        "[v4] sensor sigmas: "
        f"RSU pos={cfg.detector.rsu_position_sigma_m:g}m speed={cfg.detector.rsu_speed_sigma_mps:g}m/s "
        f"accel={cfg.detector.rsu_acceleration_sigma_mps2:g}m/s^2; "
        f"witness pos={cfg.detector.witness_position_sigma_m:g}m speed={cfg.detector.witness_speed_sigma_mps:g}m/s "
        f"accel={cfg.detector.witness_acceleration_sigma_mps2:g}m/s^2",
        flush=True,
    )

    for topology in TOPOLOGIES:
        trace_root = source / topology / "traces"
        if not trace_root.exists():
            raise FileNotFoundError(f"Missing topology trace directory: {trace_root}")
        seed_dirs = sorted(trace_root.glob("seed_*"), key=lambda p: int(p.name.split("_")[-1]))
        if not seed_dirs:
            raise FileNotFoundError(f"No seed directories found under {trace_root}")

        sensor_events = []
        for seed_dir in seed_dirs:
            sensor_events.extend(_rebuild_seed_events(seed_dir, cfg))

        runtime_events = sanitize_runtime_events(
            sensor_events,
            window_seconds=window_seconds,
            namespace=topology,
        )

        topology_dir = output / topology
        topology_dir.mkdir(parents=True, exist_ok=True)
        runtime_trace = topology_dir / "runtime_sensor_trace_all_seeds.jsonl"
        write_events_jsonl(runtime_events, runtime_trace)
        runtime_trace_paths[topology] = runtime_trace

        rows = calibration_rows(runtime_events)
        for row in rows:
            row["topology"] = topology
        all_calibration.extend(rows)

        inference = _inference_audit(runtime_events)
        if not inference.empty:
            inference.insert(0, "topology", topology)
            all_inference_audit.append(inference)

        correction_audit.append({
            "topology": topology,
            "events": len(runtime_events),
            "runtime_window_cases": _case_count(runtime_events),
            "case_window_seconds": window_seconds,
            "rsu_position_sigma_m": cfg.detector.rsu_position_sigma_m,
            "witness_position_sigma_m": cfg.detector.witness_position_sigma_m,
            "rsu_speed_sigma_mps": cfg.detector.rsu_speed_sigma_mps,
            "witness_speed_sigma_mps": cfg.detector.witness_speed_sigma_mps,
            "rsu_acceleration_sigma_mps2": cfg.detector.rsu_acceleration_sigma_mps2,
            "witness_acceleration_sigma_mps2": cfg.detector.witness_acceleration_sigma_mps2,
        })
        print(
            f"[v4] {topology}: events={len(runtime_events):,}; runtime_cases={_case_count(runtime_events):,}",
            flush=True,
        )

    pd.DataFrame(correction_audit).to_csv(output / "sensor_oracle_isolation_audit.csv", index=False)
    inference_audit = pd.concat(all_inference_audit, ignore_index=True) if all_inference_audit else pd.DataFrame()
    inference_audit.to_csv(output / "attack_inference_audit.csv", index=False)

    evidence_path = output / "all_topologies_evidence_campaign.csv"
    pd.DataFrame(all_calibration).to_csv(evidence_path, index=False)
    print(f"[v4] sensor-isolated calibration rows={len(all_calibration):,}", flush=True)

    malicious_accuracy = 0.0
    if not inference_audit.empty:
        malicious = inference_audit[inference_audit["ground_truth_malicious"] == 1]
        malicious_accuracy = float(malicious["attack_type_correct"].mean()) if not malicious.empty else 0.0
        print(
            f"[v4] attack-type inference audit: cases={len(inference_audit):,}; "
            f"malicious-case classification accuracy={malicious_accuracy:.4f}",
            flush=True,
        )

    sensitivity_dir = output / "sensitivity_fast"
    selected_path = sensitivity_dir / "selected_weights.json"
    complete_path = sensitivity_dir / "sensitivity_complete.json"
    if args.resume and selected_path.exists() and complete_path.exists():
        selected = json.loads(selected_path.read_text(encoding="utf-8"))
        print("[resume] completed v4 sensitivity found; reusing selected weights", flush=True)
    else:
        print("[v4] policy-aligned weight-only sensitivity on sensor-isolated runtime cases ...", flush=True)
        selected = select_weights(
            evidence_path,
            sensitivity_dir,
            cfg,
            candidates=args.candidates,
            bootstrap_repeats=args.bootstrap_repeats,
            permutation_repeats=args.permutation_repeats,
            min_recall=args.min_recall,
            max_frr=args.max_frr,
            jobs=args.jobs,
            checkpoint_every=args.checkpoint_every,
            resume=args.resume,
        )

    calibrated_cfg = replace(cfg, weights=WeightConfig(**selected["weights"]))
    print(f"[v4] selected weights={selected['weights']}", flush=True)
    print("[v4] replaying sensor-isolated runtime traces through all three architectures ...", flush=True)

    combined_metrics = []
    combined_decisions = []
    combined_attack = []
    combined_inference = []
    combined_messages = []
    combined_consensus = []
    topology_summaries = []

    for topology in TOPOLOGIES:
        arch_dir = output / topology / "architecture_campaign_selected"
        if args.resume and _is_architecture_complete(arch_dir):
            print(f"[resume] {topology}: architecture replay already complete", flush=True)
        else:
            print(f"[v4] {topology}: architecture replay", flush=True)
            run_trace_campaign(calibrated_cfg, runtime_trace_paths[topology], arch_dir)

        for filename, collector in [
            ("metrics_by_seed.csv", combined_metrics),
            ("decisions.csv", combined_decisions),
            ("metrics_by_attack.csv", combined_attack),
            ("attack_inference_cases.csv", combined_inference),
            ("network_messages.csv", combined_messages),
            ("consensus_outcomes.csv", combined_consensus),
        ]:
            path = arch_dir / filename
            if path.exists():
                frame = pd.read_csv(path)
                if not frame.empty:
                    frame.insert(0, "topology", topology)
                    collector.append(frame)
        summary_path = arch_dir / "architecture_summary.csv"
        if summary_path.exists():
            frame = pd.read_csv(summary_path)
            if not frame.empty:
                frame.insert(0, "topology", topology)
                topology_summaries.append(frame)

    def _concat(items):
        return pd.concat(items, ignore_index=True) if items else pd.DataFrame()

    metrics = _concat(combined_metrics)
    decisions = _concat(combined_decisions)
    attacks = _concat(combined_attack)
    inferences = _concat(combined_inference)
    messages = _concat(combined_messages)
    consensus = _concat(combined_consensus)
    topology_summary = _concat(topology_summaries)

    metrics.to_csv(output / "final_metrics_by_seed.csv", index=False)
    decisions.to_csv(output / "final_decisions.csv", index=False)
    attacks.to_csv(output / "final_metrics_by_attack.csv", index=False)
    inferences.to_csv(output / "final_attack_inference_cases.csv", index=False)
    messages.to_csv(output / "final_network_messages.csv", index=False)
    consensus.to_csv(output / "final_consensus_outcomes.csv", index=False)
    topology_summary.to_csv(output / "final_topology_architecture_summary.csv", index=False)

    if not metrics.empty and "architecture" in metrics.columns:
        numeric = metrics.select_dtypes(include="number").columns.tolist()
        group_cols = ["architecture"]
        global_summary = metrics.groupby(group_cols, as_index=False)[numeric].mean()
    else:
        global_summary = pd.DataFrame()
    global_summary.to_csv(output / "final_global_architecture_summary.csv", index=False)

    summary = {
        "source_campaign": str(source),
        "output_campaign": str(output),
        "topologies": list(TOPOLOGIES),
        "selected_weights": selected["weights"],
        "selection_feasible": bool(selected.get("selection_feasible", selected.get("feasible", False))),
        "holdout_metrics": selected.get("holdout_metrics", {}),
        "attack_inference_malicious_case_accuracy": malicious_accuracy,
        "sensor_model": {
            "method": "deterministic zero-mean Gaussian independent observer measurements",
            "reception_time_target_state": True,
            "detector_uses_message_true_kinematics": False,
            "rsu_position_sigma_m": cfg.detector.rsu_position_sigma_m,
            "witness_position_sigma_m": cfg.detector.witness_position_sigma_m,
            "rsu_speed_sigma_mps": cfg.detector.rsu_speed_sigma_mps,
            "witness_speed_sigma_mps": cfg.detector.witness_speed_sigma_mps,
            "rsu_acceleration_sigma_mps2": cfg.detector.rsu_acceleration_sigma_mps2,
            "witness_acceleration_sigma_mps2": cfg.detector.witness_acceleration_sigma_mps2,
        },
        "ground_truth_usage": "SUMO truth only generates sensor measurements and scores results; it is not compared directly by the detector",
        "runtime_case_formation": {
            "method": "fixed surveillance windows by seed + vehicle + observed time",
            "window_seconds": window_seconds,
            "uses_injected_case_id": False,
            "uses_attack_schedule_boundaries": False,
        },
        "attack_inference": {
            "source": "detector reason_codes from noisy sensor observations plus protocol/crypto checks",
            "uses_ground_truth_attack_type": False,
        },
        "sumo_rerun_required": False,
        "outputs": {
            "sensor_audit": str(output / "sensor_oracle_isolation_audit.csv"),
            "attack_inference_audit": str(output / "attack_inference_audit.csv"),
            "sensitivity": str(sensitivity_dir),
            "global_architecture_summary": str(output / "final_global_architecture_summary.csv"),
            "topology_architecture_summary": str(output / "final_topology_architecture_summary.csv"),
            "metrics_by_seed": str(output / "final_metrics_by_seed.csv"),
            "metrics_by_attack": str(output / "final_metrics_by_attack.csv"),
            "decisions": str(output / "final_decisions.csv"),
        },
    }
    (output / "v4_upgrade_summary.json").write_text(json.dumps(summary, indent=2), encoding="utf-8")
    print("[v4] COMPLETE", flush=True)
    print(json.dumps(summary, indent=2), flush=True)


if __name__ == "__main__":
    main()
