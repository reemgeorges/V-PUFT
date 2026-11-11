from __future__ import annotations

import argparse
import cProfile
import hashlib
import json
import pstats
import time
import tracemalloc
from dataclasses import asdict, replace
from pathlib import Path

import matplotlib.pyplot as plt
import numpy as np
import pandas as pd

from vpuft.architectures import DistributedRSUExtendedVPUFT
from vpuft.config import WeightConfig, load_config, save_config
from vpuft.crypto import KeyRegistry
from vpuft.evidence_acquisition import merge_existing_witness_evidence
from vpuft.metrics import decision_metrics
from vpuft.state_aware_evaluation import first_revocation_timing
from vpuft.sumo.density import build_density_scenario
from vpuft.sumo.runner import run_sumo_trace
from vpuft.trace import build_trace_bundle, read_events_jsonl


VARIANTS = {
    "B0_baseline": {"witness": False, "diverse": False, "coordinator": "first_observer_then_hash", "cache": False},
    "B1_evidence_acquisition": {"witness": False, "diverse": True, "coordinator": "first_observer_then_hash", "cache": False},
    "B4_combined_evidence": {"witness": True, "diverse": True, "coordinator": "first_observer_then_hash", "cache": False},
    "B5_case_hash_coordinator": {"witness": False, "diverse": False, "coordinator": "case_hash", "cache": False},
    "B6_cpu_optimization": {"witness": False, "diverse": False, "coordinator": "first_observer_then_hash", "cache": True},
    "B7_full_candidate": {"witness": False, "diverse": True, "coordinator": "case_hash", "cache": True},
}


def effective_config(config_path: Path, weights_path: Path):
    config = load_config(config_path)
    selected = json.loads(weights_path.read_text(encoding="utf-8"))
    policies = dict(config.policies)
    for name, overrides in selected.get("attack_policies", {}).items():
        policies[name] = replace(policies[name], **overrides)
    config = replace(config, weights=WeightConfig(**selected["weights"]), policies=policies)
    config.validate()
    return config


def sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for block in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(block)
    return digest.hexdigest()


def ensure_traces(config, output: Path, scenario: Path, densities, seeds) -> pd.DataFrame:
    frozen_audit_path = Path(
        "results/urban_roundabout_campaign_corrected_final/combined/density_trace_audit.csv"
    )
    frozen = pd.read_csv(frozen_audit_path).set_index(["vehicle_count", "seed"])
    rows = []
    for density in densities:
        generated = output / "generated_scenarios" / "urban_roundabout" / f"vehicles_{density}"
        density_manifest = build_density_scenario(
            scenario, generated, vehicle_count=density,
            attack_vehicle_ratio=config.density_campaign.attack_vehicle_ratio,
            departure_window_seconds=config.density_campaign.departure_window_seconds,
            end_time_seconds=config.sumo.end_time_seconds,
        )
        for seed in seeds:
            trace_dir = output / "traces" / "urban_roundabout" / f"vehicles_{density}" / f"seed_{seed}"
            trace = trace_dir / "shared_detection_trace.jsonl"
            manifest_path = trace_dir / "scenario_manifest.json"
            if not trace.exists() or not manifest_path.exists():
                print(f"[trace] generate density={density} seed={seed}", flush=True)
                run_sumo_trace(
                    config, scenario_directory=generated, output_directory=trace_dir, seed=seed
                )
            manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
            counts = manifest["counts"]
            reference = frozen.loc[(density, seed)]
            count_match = all(
                int(counts[current]) == int(reference[frozen_name])
                for current, frozen_name in (
                    ("unique_vehicles_observed", "observed_vehicle_count"),
                    ("peak_concurrent_vehicles", "peak_concurrent_vehicles"),
                    ("cases", "cases"),
                    ("v2x_messages", "v2x_messages"),
                    ("detection_events", "detection_events"),
                )
            )
            rows.append({
                "density": density, "seed": seed, "trace_path": str(trace),
                "sha256": sha256(trace), "bytes": trace.stat().st_size,
                "count_match_to_frozen": int(count_match),
                "observed_vehicle_count": counts["unique_vehicles_observed"],
                "cases": counts["cases"], "v2x_messages": counts["v2x_messages"],
                "detection_events": counts["detection_events"],
                "attack_vehicle_count": density_manifest.attack_vehicle_count,
            })
    frame = pd.DataFrame(rows)
    if not frame["count_match_to_frozen"].all():
        print("[trace] exact count reproduction not established; paired rerun remains valid", flush=True)
    return frame


def measured_run(config, cases, seed):
    tracemalloc.start()
    cpu_start = time.process_time()
    wall_start = time.perf_counter()
    result = DistributedRSUExtendedVPUFT(config, KeyRegistry(config.security.deterministic_master_seed)).run(cases, seed)
    cpu = time.process_time() - cpu_start
    wall = time.perf_counter() - wall_start
    _, peak = tracemalloc.get_traced_memory()
    tracemalloc.stop()
    return result, cpu, wall, peak / 1024.0


def decision_frame(result, cases, *, density, seed, variant):
    by_case = {case.case_id: case for case in cases}
    rows = []
    for decision in result.decisions:
        case = by_case[decision.case_id]
        rows.append({
            "topology": "urban_roundabout", "vehicle_count": density, "seed": seed,
            "architecture": variant, "case_id": decision.case_id,
            "vehicle_id": decision.vehicle_id, "attack_type": case.attack_type.value,
            "ground_truth_malicious": int(case.ground_truth_malicious),
            "predicted_revoked": int(decision.committed and decision.new_state.value == "revoked"),
            "committed": int(decision.committed), "new_state": decision.new_state.value,
            "reason": decision.reason, "detected_at": decision.detected_at,
            "qualified_at": decision.qualified_at, "finalized_at": decision.finalized_at,
            "ledger_available_at": decision.ledger_available_at,
            "decision_margin": decision.decision_margin,
            "metadata_json": json.dumps(dict(decision.metadata), sort_keys=True),
        })
    return pd.DataFrame(rows)


def diagnostics_rows(decisions: pd.DataFrame) -> list[dict]:
    rows = []
    for row in decisions.itertuples(index=False):
        metadata = json.loads(row.metadata_json)
        rows.append({
            "variant": row.architecture, "density": row.vehicle_count, "seed": row.seed,
            "case_id": row.case_id, "vehicle_id": row.vehicle_id, "attack_type": row.attack_type,
            "ground_truth_malicious": row.ground_truth_malicious,
            "qualified": int(bool(metadata.get("qualification_outcome", False))),
            "reason": metadata.get("qualification_reason", row.reason),
            "failed_constraints": "|".join(metadata.get("failed_constraints", [])),
            "independent_roots": metadata.get("independent_roots"),
            "required_roots": metadata.get("required_roots"),
            "distinct_sources": metadata.get("distinct_sources"),
            "required_sources": metadata.get("required_sources"),
            "distinct_zones": metadata.get("distinct_zones"),
            "required_zones": metadata.get("required_zones"),
            "distinct_modalities": metadata.get("distinct_modalities"),
            "required_modalities": metadata.get("required_modalities"),
            "supporting_strength": metadata.get("supporting_strength"),
            "opposing_strength": metadata.get("opposing_strength"),
            "actual_margin": metadata.get("qualification_margin", row.decision_margin),
            "required_margin": metadata.get("required_margin"),
            "evidence_observed_at": json.dumps(metadata.get("evidence_observed_at", [])),
            "evidence_arrival_times": json.dumps(metadata.get("evidence_arrival_times", [])),
            "evidence_ages_seconds": json.dumps(metadata.get("evidence_ages_seconds", [])),
            "excluded_duplicate_roots": metadata.get("excluded_duplicate_roots", 0),
        })
    return rows


def metric_row(result, cases, decisions, *, density, seed, variant, cpu, wall, peak, acquisition):
    truth = {case.case_id: case.ground_truth_malicious for case in cases}
    opened = {case.case_id: case.opened_at for case in cases}
    metrics = decision_metrics(result, truth, opened)
    malicious_vehicles = decisions.loc[decisions.ground_truth_malicious.eq(1), "vehicle_id"].unique()
    revoked = decisions.loc[
        decisions.ground_truth_malicious.eq(1) & decisions.predicted_revoked.eq(1), "vehicle_id"
    ].unique()
    timing = first_revocation_timing(decisions)
    valid_timing = timing.loc[timing.first_revocation_observed_after_malicious_case.eq(1)]
    return {
        "variant": variant, "density": density, "seed": seed,
        "TP": metrics["TP"], "FP": metrics["FP"], "TN": metrics["TN"], "FN": metrics["FN"],
        "recall": metrics["malicious_revocation_recall"], "precision": metrics["trust_precision"],
        "frr": metrics["false_revocation_rate"], "f1": metrics["trust_f1"], "mcc": metrics["mcc"],
        "eventual_malicious_vehicles": len(malicious_vehicles),
        "eventually_revoked_vehicles": len(revoked),
        "time_to_first_revocation_p95_ms": float(np.percentile(valid_timing.time_to_first_revocation_ms, 95)) if len(valid_timing) else np.nan,
        "p95_e2e_ms": metrics["latency_p95_ms"],
        "pure_pbft_p95_ms": metrics["consensus_latency_p95_ms"],
        "p95_ledger_consistency_ms": metrics["ledger_consistency_delay_p95_ms"],
        "cpu_time_seconds": cpu, "wall_time_seconds": wall, "peak_memory_kb": peak,
        "messages_per_case": metrics["messages_per_decision"],
        "total_transmission_attempts": len(result.messages), "pdr": metrics["packet_delivery_ratio"],
        "ledger_consistent": int(result.ledger_consistent),
        "safety_violations": sum(outcome.safety_violation for outcome in result.consensus),
        "view_changes": sum(outcome.view_changes for outcome in result.consensus),
        "witness_attestations_added": acquisition.get("witness_attestations_added", 0),
    }


def plot_results(metrics: pd.DataFrame, output: Path) -> None:
    summary = metrics.groupby(["variant", "density"], as_index=False).agg(
        recall=("recall", "mean"), frr=("frr", "mean"),
        cpu=("cpu_time_seconds", "mean"), p95=("p95_e2e_ms", "mean"),
    )
    for column, ylabel, filename in (
        ("recall", "Recall", "recall_by_density.png"),
        ("cpu", "CPU time (s)", "cpu_by_density.png"),
        ("p95", "P95 E2E (ms)", "p95_e2e_by_density.png"),
    ):
        fig, axis = plt.subplots(figsize=(9, 5))
        for variant, group in summary.groupby("variant"):
            axis.plot(group.density, group[column], marker="o", label=variant)
        axis.set_xlabel("Vehicle density")
        axis.set_ylabel(ylabel)
        axis.grid(alpha=0.25)
        axis.legend(fontsize=8)
        fig.tight_layout()
        fig.savefig(output / filename, dpi=160)
        plt.close(fig)


def select_profile_trace(traces: pd.DataFrame):
    if traces.empty:
        raise ValueError("Cannot profile an empty trace manifest")
    highest_density = traces["density"].max()
    return traces.loc[traces["density"].eq(highest_density)].sort_values("seed").iloc[0]


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--output", type=Path, default=Path("results/post_seminar_phase2"))
    parser.add_argument("--config", type=Path, default=Path("configs/urban_roundabout_campaign.json"))
    parser.add_argument("--weights", type=Path, default=Path("results/full_campaign_v7/sensitivity_shared_views_mixedfix/selected_weights.json"))
    parser.add_argument("--densities", default="20,40,60,80,100")
    parser.add_argument("--seeds", default="1001,1002,1003,1004,1005,1006,1007,1008,1009,1010")
    args = parser.parse_args()
    densities = [int(value) for value in args.densities.split(",")]
    seeds = [int(value) for value in args.seeds.split(",")]
    args.output.mkdir(parents=True, exist_ok=True)
    config = effective_config(args.config, args.weights)
    save_config(config, args.output / "phase2_effective_baseline_config.json")

    trace_output = args.output / "baseline_regenerated"
    traces = ensure_traces(config, trace_output, Path("sumo/urban_roundabout"), densities, seeds)
    traces.to_csv(args.output / "trace_manifest.csv", index=False)

    metric_rows, decision_frames, diagnostic = [], [], []
    for trace_row in traces.itertuples(index=False):
        events = read_events_jsonl(trace_row.trace_path)
        bundle = build_trace_bundle(
            events, KeyRegistry(config.security.deterministic_master_seed),
            window_seconds=config.detector.case_window_seconds,
            namespace=f"urban_roundabout-vehicles-{trace_row.density}",
        )
        merged, acquisition = merge_existing_witness_evidence(bundle.rsu_cases, bundle.witness_cases)
        for variant, spec in VARIANTS.items():
            cases = merged if spec["witness"] else bundle.rsu_cases
            ext = replace(
                config.distributed_extension,
                coordinator_strategy=spec["coordinator"],
                cache_verified_evidence_bundle=spec["cache"],
                diversity_aware_root_assignment=spec["diverse"],
            )
            variant_config = replace(config, distributed_extension=ext)
            print(f"[ablation] {variant} density={trace_row.density} seed={trace_row.seed}", flush=True)
            result, cpu, wall, peak = measured_run(variant_config, cases, trace_row.seed)
            decisions = decision_frame(
                result, cases, density=trace_row.density, seed=trace_row.seed, variant=variant
            )
            decision_frames.append(decisions)
            diagnostic.extend(diagnostics_rows(decisions))
            metric_rows.append(metric_row(
                result, cases, decisions, density=trace_row.density, seed=trace_row.seed,
                variant=variant, cpu=cpu, wall=wall, peak=peak,
                acquisition=acquisition if spec["witness"] else {},
            ))

    metrics = pd.DataFrame(metric_rows)
    decisions = pd.concat(decision_frames, ignore_index=True)
    diagnostics = pd.DataFrame(diagnostic)
    metrics.to_csv(args.output / "ablation_metrics_by_seed.csv", index=False)
    decisions.to_csv(args.output / "ablation_decisions.csv.gz", index=False, compression="gzip")
    diagnostics.to_csv(args.output / "qualification_diagnostics.csv.gz", index=False, compression="gzip")
    diagnostics.groupby(
        ["variant", "density", "attack_type", "failed_constraints"], dropna=False
    ).size().rename("cases").reset_index().to_csv(
        args.output / "qualification_failures_by_density_attack.csv", index=False
    )
    metrics.groupby(["variant", "density"], as_index=False).mean(numeric_only=True).to_csv(
        args.output / "ablation_summary.csv", index=False
    )
    plot_results(metrics, args.output)

    representative_trace = select_profile_trace(traces)
    events = read_events_jsonl(representative_trace.trace_path)
    bundle = build_trace_bundle(
        events, KeyRegistry(config.security.deterministic_master_seed),
        window_seconds=config.detector.case_window_seconds,
        namespace=f"urban_roundabout-vehicles-{int(representative_trace.density)}",
    )
    profiler = cProfile.Profile()
    profiler.enable()
    DistributedRSUExtendedVPUFT(config, KeyRegistry()).run(bundle.rsu_cases, int(representative_trace.seed))
    profiler.disable()
    profiler.dump_stats(args.output / "baseline_density100.prof")
    with (args.output / "baseline_density100_profile.txt").open("w", encoding="utf-8") as handle:
        stats = pstats.Stats(profiler, stream=handle).strip_dirs().sort_stats("cumulative")
        stats.print_stats(40)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
