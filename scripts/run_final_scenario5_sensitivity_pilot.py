from __future__ import annotations

import argparse
import hashlib
import json
import math
import os
import sys
import time
from dataclasses import asdict, replace
from pathlib import Path

import pandas as pd

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))
os.chdir(ROOT)

from vpuft.architectures import CentralizedVPUFT, DistributedRSUExtendedVPUFT
from vpuft.config import load_config, save_config
from vpuft.crypto import KeyRegistry
from vpuft.density_campaign import _assert_transport_causality, _run_measured
from vpuft.metrics import decision_metrics
from vpuft.sumo.density import build_density_scenario
from vpuft.sumo.runner import run_sumo_trace
from vpuft.state_aware_evaluation import state_aware_first_revocation_metrics
from vpuft.trace import build_trace_bundle, read_events_jsonl


BASE_CONFIG = Path("results/urban_roundabout_campaign_corrected_final/effective_config.json")
OUT = Path("results/final_scenario5_sensitivity/pilot_2026-11-16")
DENSITIES = (20, 100)
SEEDS = (7001, 7002)
WINDOW = 15.0
MAX_WALL_SECONDS = 3600.0
MAX_OUTPUT_BYTES = 2_000_000_000


def sha(path: Path) -> str:
    h = hashlib.sha256()
    with path.open("rb") as f:
        for block in iter(lambda: f.read(1024 * 1024), b""):
            h.update(block)
    return h.hexdigest()


def save_rows(path: Path, rows: list[dict]) -> None:
    if rows:
        pd.DataFrame(rows).to_csv(path, index=False)


def tree_bytes(path: Path) -> int:
    return sum(p.stat().st_size for p in path.rglob("*") if p.is_file())


def variants(base):
    result = [("baseline", "baseline", "baseline", base)]
    for seconds in (12.0, 30.0):
        policies = {name: replace(policy, freshness_window_seconds=seconds)
                    for name, policy in base.policies.items()}
        result.append((f"freshness_{int(seconds)}s", "freshness_window_seconds",
                       str(seconds), replace(base, policies=policies)))
    for sources in (1, 3):
        policies = dict(base.policies)
        policies["position_offset"] = replace(
            policies["position_offset"], required_sources=sources)
        result.append((f"position_sources_{sources}", "position_offset.required_sources",
                       str(sources), replace(base, policies=policies)))
    for pdr in (0.95, 1.0):
        network = replace(base.network, packet_delivery_ratio=pdr)
        result.append((f"pdr_{pdr:.2f}", "packet_delivery_ratio",
                       str(pdr), replace(base, network=network)))
    for delay in (20.0, 200.0):
        result.append((f"c100_backhaul_{int(delay)}ms", "C100_backhaul_ms",
                       str(delay), base))
    return result


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--verify-only", action="store_true")
    args = parser.parse_args()
    out = ROOT / OUT
    out.mkdir(parents=True, exist_ok=False)
    base = load_config(ROOT / BASE_CONFIG)
    base.validate()
    if abs(base.network.packet_delivery_ratio - 0.98) > 1e-12:
        raise RuntimeError("Unexpected Dataset B baseline packet delivery setting")
    if abs(base.detector.case_window_seconds - WINDOW) > 1e-12:
        raise RuntimeError("Unexpected Dataset B runtime case window")
    if any(abs(p.freshness_window_seconds - 15.0) > 1e-12 for p in base.policies.values()):
        raise RuntimeError("Unexpected Dataset B evidence freshness setting")
    if base.policies["position_offset"].required_sources != 2:
        raise RuntimeError("Unexpected position_offset source threshold")
    if base.pbft.validators != ("rsu-1", "rsu-2", "rsu-3", "rsu-4"):
        raise RuntimeError("Unexpected validator membership")
    if base.pbft.max_byzantine != 1:
        raise RuntimeError("Unexpected Byzantine fault budget")

    frozen_rel = [
        "results/urban_roundabout_campaign_corrected_final/effective_config.json",
        "results/urban_roundabout_campaign_corrected_final/combined/density_metrics_by_seed.csv",
        "results/urban_roundabout_campaign_corrected_final/combined/density_decisions.csv",
        "docs/final_scenario5_evidence_package/METHOD_B_CORRECTED_FINAL/SCENARIO5_METHOD_B_VERIFIED_METRICS.csv",
        "sumo/urban_roundabout/rsus.json",
        "sumo/urban_roundabout/attacks.json",
        "sumo/urban_roundabout/urban_roundabout.sumocfg",
        "sumo/urban_roundabout/urban_roundabout.nod.xml",
        "sumo/urban_roundabout/urban_roundabout.edg.xml",
        "sumo/urban_roundabout/urban_roundabout.rou.xml",
    ]
    (out / "FROZEN_INPUT_HASHES.json").write_text(json.dumps({
        "accepted_commit": "c1878e8d6bef7a44830d8b44d5f55d47d5810f3c",
        "branch": "research/final-scenario5",
        "sha256": {name: sha(ROOT / name) for name in frozen_rel},
    }, indent=2), encoding="utf-8")

    config_rows = {}
    for variant_id, factor, level, cfg in variants(base):
        config_rows[variant_id] = {
            "factor": factor,
            "level": level,
            "base_config_sha256": sha(ROOT / BASE_CONFIG),
            "effective_config": asdict(cfg),
            "architecture_scope": "C100 only" if factor == "C100_backhaul_ms" else "C100 and Distributed",
        }
    config_rows["baseline"]["baseline_values"] = {
        "freshness_window_seconds": 15.0,
        "position_offset_required_sources": 2,
        "packet_delivery_ratio": 0.98,
        "C100_backhaul_ms": 100.0,
        "Distributed_backhaul_ms": 0.0,
    }
    (out / "SENSITIVITY_EFFECTIVE_CONFIGS.json").write_text(
        json.dumps(config_rows, indent=2), encoding="utf-8")

    manifest_rows = []
    metric_rows = []
    decision_rows = []
    opportunity_rows = []
    trace_records = []
    started = time.monotonic()
    run_count = 0
    status = "running"
    (out / "pilot_status.json").write_text(json.dumps({
        "status": status, "expected_architecture_runs": 64,
        "expected_trace_generations": 4, "completed_runs": 0,
    }, indent=2), encoding="utf-8")

    scenario_base = ROOT / "sumo/urban_roundabout"
    for density in DENSITIES:
        generated = out / "shared_inputs" / "generated_scenarios" / f"vehicles_{density}"
        density_manifest = build_density_scenario(
            scenario_base, generated, vehicle_count=density,
            attack_vehicle_ratio=base.density_campaign.attack_vehicle_ratio,
            departure_window_seconds=base.density_campaign.departure_window_seconds,
            end_time_seconds=base.sumo.end_time_seconds,
        )
        for seed in SEEDS:
            if time.monotonic() - started > MAX_WALL_SECONDS:
                raise TimeoutError("60-minute operational wall-time cap reached")
            trace_dir = out / "shared_inputs" / "traces" / f"density_{density}" / f"seed_{seed}"
            trace_start = time.monotonic()
            trace_manifest = run_sumo_trace(
                base, scenario_directory=generated, output_directory=trace_dir, seed=seed)
            elapsed = time.monotonic() - trace_start
            if int(trace_manifest["counts"]["unique_vehicles_observed"]) != density:
                raise RuntimeError(f"Density mismatch in trace {density}/{seed}")
            trace_path = trace_dir / "shared_detection_trace.jsonl"
            trace_records.append({
                "density": density, "seed": seed,
                "trace_sha256": sha(trace_path),
                "generated_messages_sha256": sha(trace_dir / "generated_messages.csv"),
                "attack_ground_truth_sha256": sha(trace_dir / "attack_ground_truth.csv"),
                "mobility_trace_sha256": sha(trace_dir / "mobility_trace.csv"),
                "scenario_manifest_sha256": sha(trace_dir / "scenario_manifest.json"),
                "unique_vehicles": trace_manifest["counts"]["unique_vehicles_observed"],
                "cases_in_raw_detection_trace": trace_manifest["counts"]["cases"],
                "v2x_messages": trace_manifest["counts"]["v2x_messages"],
                "detection_events": trace_manifest["counts"]["detection_events"],
                "trace_wall_seconds": elapsed,
            })
            (out / "SENSITIVITY_TRACE_MANIFEST.json").write_text(
                json.dumps({"generated_scenario": asdict(density_manifest),
                            "traces": trace_records}, indent=2), encoding="utf-8")
            if tree_bytes(out) > MAX_OUTPUT_BYTES:
                raise RuntimeError("2 GB output cap reached after trace generation")

    key_registry = KeyRegistry(base.security.deterministic_master_seed)
    variant_list = variants(base)
    for density in DENSITIES:
        namespace = f"urban_roundabout-vehicles-{density}"
        for seed in SEEDS:
            if time.monotonic() - started > MAX_WALL_SECONDS:
                raise TimeoutError("60-minute operational wall-time cap reached")
            trace_dir = out / "shared_inputs" / "traces" / f"density_{density}" / f"seed_{seed}"
            events = read_events_jsonl(trace_dir / "shared_detection_trace.jsonl")
            bundle = build_trace_bundle(
                events, key_registry, window_seconds=WINDOW, namespace=namespace)
            cases = bundle.rsu_cases
            if not cases:
                raise RuntimeError(f"No RSU cases in trace {density}/{seed}")
            truth = {case.case_id: case.ground_truth_malicious for case in cases}
            opened = {case.case_id: case.opened_at for case in cases}
            case_by_id = {case.case_id: case for case in cases}
            raw_messages = pd.read_csv(trace_dir / "generated_messages.csv")
            mobility = pd.read_csv(trace_dir / "mobility_trace.csv")
            base_emission_time = {}
            for vehicle, frames in mobility.groupby("vehicle_id"):
                for index, frame in enumerate(frames.sort_values("simulation_time").itertuples(index=False)):
                    base_emission_time[f"cam-{seed}-{vehicle}-{index:06d}"] = float(frame.simulation_time)
            attack_messages = raw_messages[
                raw_messages["ground_truth_malicious"].astype(str).str.lower().isin(["true", "1"])
            ].copy()
            observed_ids = {event.message_id for event in bundle.events}
            opportunities_by_case = {}
            for row in attack_messages.to_dict("records"):
                idx = int(math.floor(max(0.0, float(row["generated_at"])) / WINDOW))
                case_id = f"case-urban_roundabout-{seed}-{row['sender_vehicle_id']}-w{idx:04d}"
                opportunities_by_case.setdefault(case_id, []).append(row)

            for variant_id, factor, level, cfg in variant_list:
                arch_specs = []
                if factor != "C100_backhaul_ms":
                    dist_cfg = replace(
                        cfg, network=replace(cfg.network, central_backhaul_extra_latency_ms=0.0))
                    c100_cfg = replace(
                        cfg, network=replace(cfg.network, central_backhaul_extra_latency_ms=100.0))
                    arch_specs = [
                        ("Distributed", DistributedRSUExtendedVPUFT(dist_cfg, key_registry), dist_cfg),
                        ("C100", CentralizedVPUFT(c100_cfg, key_registry), c100_cfg),
                    ]
                else:
                    delay = float(level)
                    c100_cfg = replace(
                        cfg, network=replace(cfg.network, central_backhaul_extra_latency_ms=delay))
                    arch_specs = [("C100", CentralizedVPUFT(c100_cfg, key_registry), c100_cfg)]

                for architecture, instance, run_cfg in arch_specs:
                    if time.monotonic() - started > MAX_WALL_SECONDS:
                        raise TimeoutError("60-minute operational wall-time cap reached")
                    run_count += 1
                    run_started = time.monotonic()
                    try:
                        result, cpu_seconds, peak_kb = _run_measured(
                            instance, cases, seed, architecture)
                        _assert_transport_causality(
                            result,
                            queue_rate_bytes_per_second=run_cfg.network.queue_rate_bytes_per_second)
                        metric = decision_metrics(result, truth, opened)
                        metric.update({
                            "variant_id": variant_id, "factor": factor, "level": level,
                            "density": density, "seed": seed, "architecture": architecture,
                            "backhaul_extra_latency_ms": run_cfg.network.central_backhaul_extra_latency_ms,
                            "cpu_time_seconds": cpu_seconds, "peak_memory_kb": peak_kb,
                            "case_count": len(result.decisions),
                            "trace_sha256": sha(trace_dir / "shared_detection_trace.jsonl"),
                        })
                        metric_rows.append(metric)

                        local_decisions = []
                        for decision in result.decisions:
                            case = case_by_id[decision.case_id]
                            local_decisions.append({
                                "variant_id": variant_id, "factor": factor, "level": level,
                                "density": density, "seed": seed, "architecture": architecture,
                                "case_id": decision.case_id, "vehicle_id": decision.vehicle_id,
                                "attack_type": case.attack_type.value,
                                "ground_truth_malicious": int(case.ground_truth_malicious),
                                "committed": int(decision.committed),
                                "predicted_revoked": int(
                                    decision.committed and decision.new_state.value == "revoked"),
                                "new_state": decision.new_state.value,
                                "reason": decision.reason,
                                "opened_at": case.opened_at,
                                "detected_at": decision.detected_at,
                                "qualified_at": decision.qualified_at,
                                "finalized_at": decision.finalized_at,
                                "ledger_available_at": decision.ledger_available_at,
                            })
                        decision_rows.extend(local_decisions)

                        temp = pd.DataFrame([{
                            "case_id": row["case_id"], "vehicle_id": row["vehicle_id"],
                            "seed": seed, "architecture": architecture,
                            "ground_truth_malicious": row["ground_truth_malicious"],
                            "committed": row["committed"], "new_state": row["new_state"],
                            "topology": "urban_roundabout", "vehicle_count": density,
                            "backhaul_extra_latency_ms": metric["backhaul_extra_latency_ms"],
                        } for row in local_decisions])
                        independent = state_aware_first_revocation_metrics(
                            temp, window_seconds=WINDOW)
                        if len(independent) != 1:
                            raise RuntimeError("Method B evaluator did not produce one run row")
                        check = independent.iloc[0]
                        for name in ("TP", "FP", "TN", "FN",
                                     "excluded_post_revocation_windows"):
                            expected_name = "excluded_post_revocation_cases" if name.startswith("excluded") else name
                            expected = int(metric[expected_name])
                            actual = int(check["excluded_post_revocation_windows"] if name.startswith("excluded") else check[name])
                            if expected != actual:
                                raise RuntimeError(f"Method B mismatch {name}: {expected} != {actual}")

                        first_revocation = {}
                        for decision in result.decisions:
                            if decision.committed and decision.new_state.value == "revoked" and decision.finalized_at is not None:
                                old = first_revocation.get(decision.vehicle_id)
                                if old is None or decision.finalized_at < old:
                                    first_revocation[decision.vehicle_id] = decision.finalized_at
                        detected = protected = observed = 0
                        rsu_observed = 0
                        event_by_message = {}
                        for event in bundle.events:
                            event_by_message.setdefault(event.message_id, set()).add(event.source_kind.value)
                        for msg in attack_messages.to_dict("records"):
                            msg_id = str(msg["message_id"])
                            msg_time = float(msg["generated_at"])
                            if msg_id.startswith("replay-"):
                                base_id = msg_id[len("replay-"):]
                                if base_id not in base_emission_time: raise RuntimeError(f"Cannot recover replay emission time: {msg_id}")
                                msg_time = base_emission_time[base_id]
                            vehicle = str(msg["sender_vehicle_id"])
                            case_idx = int(math.floor(max(0.0, msg_time) / WINDOW))
                            cid = f"case-urban_roundabout-{seed}-{vehicle}-w{case_idx:04d}"
                            sources = event_by_message.get(msg_id, set())
                            is_observed = bool(sources)
                            observed += int(is_observed)
                            rsu_observed += int("rsu" in sources)
                            decision = next((d for d in result.decisions if d.case_id == cid), None)
                            if (is_observed and decision is not None and decision.committed
                                    and decision.new_state.value == "revoked"):
                                detected += 1
                            if vehicle in first_revocation and first_revocation[vehicle] < msg_time:
                                protected += 1
                        opportunity_rows.append({
                            "variant_id": variant_id, "factor": factor, "level": level,
                            "density": density, "seed": seed, "architecture": architecture,
                            "attack_message_opportunities": len(attack_messages),
                            "observed_attack_messages": observed,
                            "rsu_observed_attack_messages": rsu_observed,
                            "unobserved_attack_messages": len(attack_messages) - observed,
                            "successfully_detected_attack_messages": detected,
                            "missed_attack_messages": len(attack_messages) - detected,
                            "opportunity_detection_recall": detected / len(attack_messages) if len(attack_messages) else 0.0,
                            "protected_attack_messages": protected,
                            "protected_opportunity_fraction": protected / len(attack_messages) if len(attack_messages) else 0.0,
                            "trace_sha256": sha(trace_dir / "shared_detection_trace.jsonl"),
                        })

                        elapsed = time.monotonic() - run_started
                        manifest_rows.append({
                            "variant_id": variant_id, "factor": factor, "level": level,
                            "density": density, "seed": seed, "architecture": architecture,
                            "status": "completed", "case_count": len(result.decisions),
                            "trace_sha256": sha(trace_dir / "shared_detection_trace.jsonl"),
                            "cpu_time_seconds": cpu_seconds, "wall_seconds": elapsed,
                            "messages_total": metric["messages_total"],
                            "bytes_total": metric["bytes_total"],
                            "pdr": metric["packet_delivery_ratio"],
                            "failure": "",
                        })
                    except Exception as exc:
                        manifest_rows.append({
                            "variant_id": variant_id, "factor": factor, "level": level,
                            "density": density, "seed": seed, "architecture": architecture,
                            "status": "failed", "case_count": 0,
                            "trace_sha256": sha(trace_dir / "shared_detection_trace.jsonl"),
                            "failure": repr(exc),
                        })
                        save_rows(out / "SENSITIVITY_RUN_MANIFEST.csv", manifest_rows)
                        (out / "pilot_status.json").write_text(json.dumps({
                            "status": "failed", "completed_runs": run_count - 1,
                            "failed_cell": manifest_rows[-1], "expected_architecture_runs": 64,
                        }, indent=2), encoding="utf-8")
                        raise

                    save_rows(out / "SENSITIVITY_METRICS_BY_SEED.csv", metric_rows)
                    save_rows(out / "SENSITIVITY_CASE_DECISIONS.csv", decision_rows)
                    save_rows(out / "SENSITIVITY_FIXED_OPPORTUNITIES.csv", opportunity_rows)
                    save_rows(out / "SENSITIVITY_RUN_MANIFEST.csv", manifest_rows)
                    if tree_bytes(out) > MAX_OUTPUT_BYTES:
                        raise RuntimeError("2 GB output cap reached")
                    (out / "pilot_status.json").write_text(json.dumps({
                        "status": "running", "completed_runs": run_count,
                        "expected_architecture_runs": 64, "elapsed_seconds": time.monotonic() - started,
                        "output_bytes": tree_bytes(out),
                    }, indent=2), encoding="utf-8")

    (out / "SENSITIVITY_TRACE_MANIFEST.json").write_text(
        json.dumps({"traces": trace_records}, indent=2), encoding="utf-8")
    (out / "pilot_status.json").write_text(json.dumps({
        "status": "completed", "completed_runs": run_count,
        "expected_architecture_runs": 64, "elapsed_seconds": time.monotonic() - started,
        "output_bytes": tree_bytes(out),
    }, indent=2), encoding="utf-8")
    print(json.dumps({"status": "completed", "runs": run_count, "output": str(out)}, indent=2))


if __name__ == "__main__":
    main()
