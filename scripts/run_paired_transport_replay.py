from __future__ import annotations

import argparse
import json
from dataclasses import replace
from pathlib import Path

import pandas as pd

from vpuft.architectures import CentralizedVPUFT, DistributedRSUExtendedVPUFT
from vpuft.config import WeightConfig, load_config
from vpuft.crypto import KeyRegistry
from vpuft.density_campaign import (
    _decision_rows,
    _message_rows,
    _read_completed_cell,
    _run_measured,
    _write_cell_frames,
)
from vpuft.metrics import decision_metrics
from vpuft.trace import build_trace_bundle, read_events_jsonl


DIST = "distributed_crn_honest"
CENTRAL_AVAILABLE = "central_crn_available_0ms"
CENTRAL_OPERATIONAL = "central_crn_operational_0ms"


def _weights(path: Path) -> WeightConfig:
    raw = json.loads(path.read_text(encoding="utf-8"))
    values = raw.get("weights", raw)
    return WeightConfig(
        **{key: float(values[key]) for key in ("C", "rho", "F", "Q", "eta")}
    )


def main() -> None:
    parser = argparse.ArgumentParser(
        description="Replay saved density traces with evidence-level common random numbers."
    )
    parser.add_argument(
        "--source-root", default=str(Path.home() / "VPUFT_density_results")
    )
    parser.add_argument(
        "--output-dir", default=str(Path.home() / "VPUFT_density_paired_replay")
    )
    parser.add_argument("--config", default="configs/full_experiment.json")
    parser.add_argument(
        "--weights",
        default="results/full_campaign_v7/sensitivity_shared_views_mixedfix/selected_weights.json",
    )
    parser.add_argument(
        "--topologies",
        nargs="+",
        default=["smoke", "corridor", "intersection", "grid"],
    )
    parser.add_argument(
        "--vehicle-counts", nargs="+", type=int, default=[20, 40, 60, 80, 100]
    )
    parser.add_argument(
        "--seeds", nargs="+", type=int, default=list(range(1001, 1011))
    )
    parser.add_argument("--resume", action="store_true")
    args = parser.parse_args()

    source = Path(args.source_root).resolve()
    output = Path(args.output_dir).resolve()
    output.mkdir(parents=True, exist_ok=True)
    config = replace(load_config(args.config), weights=_weights(Path(args.weights)))
    keys = KeyRegistry(config.security.deterministic_master_seed)

    all_metrics: list[pd.DataFrame] = []
    all_decisions: list[pd.DataFrame] = []
    all_messages: list[pd.DataFrame] = []
    executed = resumed = 0

    for topology in args.topologies:
        for vehicle_count in args.vehicle_counts:
            for seed in args.seeds:
                trace_path = (
                    source
                    / "traces"
                    / topology
                    / f"vehicles_{vehicle_count}"
                    / f"seed_{seed}"
                    / "shared_detection_trace.jsonl"
                )
                if not trace_path.exists():
                    raise SystemExit(f"Missing saved trace: {trace_path}")
                cell_dir = (
                    output
                    / "cells"
                    / topology
                    / f"vehicles_{vehicle_count}"
                    / f"seed_{seed}"
                )
                cached = _read_completed_cell(cell_dir) if args.resume else None
                if cached is not None:
                    print(
                        f"[paired-resume] {topology}/{vehicle_count}/{seed}",
                        flush=True,
                    )
                    all_metrics.append(cached["metrics.csv"])
                    all_decisions.append(cached["decisions.csv"])
                    all_messages.append(cached["message_summary.csv"])
                    resumed += 1
                    continue

                print(
                    f"[paired] {topology} vehicles={vehicle_count} seed={seed}",
                    flush=True,
                )
                events = read_events_jsonl(trace_path)
                bundle = build_trace_bundle(
                    events,
                    keys,
                    window_seconds=config.detector.case_window_seconds,
                    namespace=f"{topology}-vehicles-{vehicle_count}",
                )
                cases = bundle.rsu_cases
                truth = {
                    case.case_id: case.ground_truth_malicious for case in cases
                }
                opened = {case.case_id: case.opened_at for case in cases}
                context = {
                    "topology": topology,
                    "vehicle_count": vehicle_count,
                    "seed": seed,
                }

                paired_network = replace(
                    config.network,
                    central_backhaul_extra_latency_ms=0.0,
                    evidence_crn_seed=seed,
                )
                distributed_config = replace(config, network=paired_network)
                available_config = replace(
                    config,
                    network=paired_network,
                    central=replace(config.central, availability=1.0),
                )
                operational_config = replace(config, network=paired_network)

                runs = []
                for label, architecture in (
                    (
                        DIST,
                        DistributedRSUExtendedVPUFT(distributed_config, keys),
                    ),
                    (
                        CENTRAL_AVAILABLE,
                        CentralizedVPUFT(available_config, keys),
                    ),
                    (
                        CENTRAL_OPERATIONAL,
                        CentralizedVPUFT(operational_config, keys),
                    ),
                ):
                    result, cpu, peak = _run_measured(
                        architecture, cases, seed, label
                    )
                    metric = decision_metrics(result, truth, opened)
                    metric.update(
                        {
                            **context,
                            "backhaul_extra_latency_ms": 0.0,
                            "cpu_time_seconds": cpu,
                            "peak_memory_kb": peak,
                        }
                    )
                    runs.append((result, metric))

                metrics = pd.DataFrame(metric for _, metric in runs)
                decisions = pd.DataFrame(
                    row
                    for result, _ in runs
                    for row in _decision_rows(
                        result,
                        cases,
                        {
                            **context,
                            "architecture": result.architecture,
                            "backhaul_extra_latency_ms": 0.0,
                        },
                    )
                )
                messages = pd.DataFrame(
                    row
                    for result, _ in runs
                    for row in _message_rows(
                        result,
                        {
                            **context,
                            "architecture": result.architecture,
                            "backhaul_extra_latency_ms": 0.0,
                        },
                    )
                )
                frames = {
                    "metrics.csv": metrics,
                    "decisions.csv": decisions,
                    "message_summary.csv": messages,
                }
                _write_cell_frames(cell_dir, frames)
                all_metrics.append(metrics)
                all_decisions.append(decisions)
                all_messages.append(messages)
                executed += 1

    combined = output / "combined"
    combined.mkdir(parents=True, exist_ok=True)
    pd.concat(all_metrics, ignore_index=True).to_csv(
        combined / "paired_metrics_by_seed.csv", index=False
    )
    pd.concat(all_decisions, ignore_index=True).to_csv(
        combined / "paired_decisions.csv", index=False
    )
    pd.concat(all_messages, ignore_index=True).to_csv(
        combined / "paired_message_type_summary.csv", index=False
    )
    manifest = {
        "campaign": "post_hoc_evidence_crn_paired_transport_replay",
        "source_root": str(source),
        "output_root": str(output),
        "sumo_rerun": False,
        "saved_detection_traces_reused": True,
        "topologies": args.topologies,
        "vehicle_counts": args.vehicle_counts,
        "seeds": args.seeds,
        "expected_cells": len(args.topologies)
        * len(args.vehicle_counts)
        * len(args.seeds),
        "executed_cells": executed,
        "resumed_cells": resumed,
        "architecture_runs_per_cell": 3,
        "evidence_common_random_numbers": True,
        "paired_scope": "loss/jitter/retry draw keyed by evidence attestation; queueing and architecture-only traffic remain architecture-specific",
        "central_available_ablation": 1.0,
        "central_operational_availability": config.central.availability,
        "backhaul_levels_derived_after_0ms_replay": list(
            config.density_campaign.backhaul_extra_latency_ms
        ),
        "weights": {
            "C": config.weights.C,
            "rho": config.weights.rho,
            "F": config.weights.F,
            "Q": config.weights.Q,
            "eta": config.weights.eta,
        },
        "analysis_family": "post_hoc_supplementary_sensitivity",
    }
    (combined / "paired_replay_manifest.json").write_text(
        json.dumps(manifest, indent=2), encoding="utf-8"
    )
    print(
        json.dumps(
            {
                "completed_cells": executed + resumed,
                "expected_cells": manifest["expected_cells"],
                "combined": str(combined),
            },
            indent=2,
        ),
        flush=True,
    )


if __name__ == "__main__":
    main()
