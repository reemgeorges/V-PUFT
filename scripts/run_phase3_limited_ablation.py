"""Paired B0/B1/B8 replay over selected, already-generated Scenario 5 traces."""
from __future__ import annotations

import argparse
import hashlib
import json
from dataclasses import replace
from pathlib import Path

import pandas as pd

from run_phase2_ablation import decision_frame, measured_run, metric_row
from vpuft.architectures import DistributedRSUExtendedVPUFT
from vpuft.crypto import KeyRegistry
from vpuft.trace import build_trace_bundle, read_events_jsonl


CELLS = ((20, 1001), (60, 1001), (100, 1001))
VARIANTS = {
    "B0_frozen_baseline": (False, False),
    "B1_previous_best": (True, False),
    "B8_provenance_safe_observer_diversity": (False, True),
}


def file_sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for block in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(block)
    return digest.hexdigest()


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--output", type=Path, default=Path("results/post_seminar_phase3/limited"))
    parser.add_argument("--trace-root", type=Path, default=Path("results/post_seminar_phase2/baseline_regenerated/traces/urban_roundabout"))
    parser.add_argument("--config", type=Path, default=Path("results/post_seminar_phase2/phase2_effective_baseline_config.json"))
    args = parser.parse_args()
    args.output.mkdir(parents=True, exist_ok=True)
    # The saved effective config contains the frozen, selected policy and weights.
    from vpuft.config import load_config
    config = load_config(args.config)
    trace_rows, metric_rows, decision_rows = [], [], []
    for density, seed in CELLS:
        cell_dir = args.output / f"density_{density}_seed_{seed}"
        if (cell_dir / "cell_complete.json").is_file():
            print(f"skip completed density={density} seed={seed}", flush=True)
            metric_rows.extend(pd.read_csv(cell_dir / "metrics.csv").to_dict("records"))
            decision_rows.append(pd.read_csv(cell_dir / "decisions.csv.gz"))
            saved_trace = pd.read_csv(cell_dir / "trace_manifest.csv").iloc[0].to_dict()
            saved_path = Path(saved_trace["trace"])
            saved_trace["sha256"] = file_sha256(saved_path)
            trace_rows.append(saved_trace)
            continue
        cell_dir.mkdir(parents=True, exist_ok=True)
        trace = args.trace_root / f"vehicles_{density}" / f"seed_{seed}" / "shared_detection_trace.jsonl"
        if not trace.is_file():
            raise FileNotFoundError(trace)
        trace_rows.append({
            "density": density, "seed": seed, "trace": str(trace),
            "bytes": trace.stat().st_size, "sha256": file_sha256(trace),
        })
        events = read_events_jsonl(trace)
        bundle = build_trace_bundle(
            events, KeyRegistry(config.security.deterministic_master_seed),
            window_seconds=config.detector.case_window_seconds,
            namespace=f"urban_roundabout-vehicles-{density}",
        )
        cell_metrics, cell_decisions = [], []
        for name, (diverse_assignment, observer_diversity) in VARIANTS.items():
            ext = replace(
                config.distributed_extension,
                coordinator_strategy="first_observer_then_hash",
                cache_verified_evidence_bundle=False,
                diversity_aware_root_assignment=diverse_assignment,
                provenance_safe_observer_diversity=observer_diversity,
            )
            run_config = replace(config, distributed_extension=ext)
            result, cpu, wall, peak_kb = measured_run(run_config, bundle.rsu_cases, seed)
            decisions = decision_frame(result, bundle.rsu_cases, density=density, seed=seed, variant=name)
            cell_decisions.append(decisions)
            cell_metrics.append(metric_row(
                result, bundle.rsu_cases, decisions, density=density, seed=seed,
                variant=name, cpu=cpu, wall=wall, peak=peak_kb, acquisition={},
            ))
            print(f"completed {name} density={density} seed={seed} cases={len(bundle.rsu_cases)}", flush=True)
        cell_metric_frame = pd.DataFrame(cell_metrics)
        cell_decision_frame = pd.concat(cell_decisions, ignore_index=True)
        cell_metric_frame.to_csv(cell_dir / "metrics.csv", index=False)
        cell_decision_frame.to_csv(cell_dir / "decisions.csv.gz", index=False, compression="gzip")
        pd.DataFrame([trace_rows[-1]]).to_csv(cell_dir / "trace_manifest.csv", index=False)
        (cell_dir / "cell_complete.json").write_text(json.dumps({"density": density, "seed": seed}, indent=2), encoding="utf-8")
        metric_rows.extend(cell_metrics)
        decision_rows.append(cell_decision_frame)
    metrics = pd.DataFrame(metric_rows)
    decisions = pd.concat(decision_rows, ignore_index=True)
    metrics.to_csv(args.output / "metrics.csv", index=False)
    decisions.to_csv(args.output / "decisions.csv.gz", index=False, compression="gzip")
    pd.DataFrame(trace_rows).to_csv(args.output / "shared_trace_manifest.csv", index=False)
    baseline_fp = decisions.loc[
        decisions.architecture.eq("B0_frozen_baseline") & decisions.ground_truth_malicious.eq(0)
        & decisions.predicted_revoked.eq(1), ["vehicle_count", "seed", "case_id"]
    ]
    candidate_fp = decisions.loc[
        decisions.architecture.eq("B8_provenance_safe_observer_diversity")
        & decisions.ground_truth_malicious.eq(0) & decisions.predicted_revoked.eq(1),
        ["vehicle_count", "seed", "case_id", "reason", "metadata_json"]
    ]
    prior = set(zip(baseline_fp.vehicle_count, baseline_fp.seed, baseline_fp.case_id))
    new_fp = candidate_fp.loc[
        [(row.vehicle_count, row.seed, row.case_id) not in prior for row in candidate_fp.itertuples(index=False)]
    ]
    new_fp.to_csv(args.output / "new_b8_false_positives.csv", index=False)
    summary = metrics.groupby(["variant", "density"], as_index=False).agg(
        TP=("TP", "sum"), FP=("FP", "sum"), TN=("TN", "sum"), FN=("FN", "sum"),
        recall=("recall", "mean"), precision=("precision", "mean"), frr=("frr", "mean"),
        f1=("f1", "mean"), p95_e2e_ms=("p95_e2e_ms", "mean"),
        cpu_time_seconds=("cpu_time_seconds", "mean"), messages_per_case=("messages_per_case", "mean"),
    )
    summary.to_csv(args.output / "summary.csv", index=False)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
