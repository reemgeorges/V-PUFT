from __future__ import annotations

import argparse
import json
from pathlib import Path

import pandas as pd


ARCHITECTURES = (
    "distributed_density_honest",
    "centralized_remote_0ms_control",
    "centralized_remote_100ms",
)

DISPLAY_COLUMNS = (
    "vehicle_count",
    "architecture",
    "trust_precision",
    "malicious_revocation_recall",
    "false_revocation_rate",
    "trust_f1",
    "mcc",
    "latency_p95_ms",
    "messages_per_decision",
    "bytes_per_decision",
    "cpu_time_seconds",
    "peak_memory_kb",
)


def summarize(campaign: Path) -> str:
    combined = campaign / "combined"
    metrics_path = combined / "density_metrics_by_seed.csv"
    traces_path = combined / "density_trace_audit.csv"
    manifest_path = combined / "density_campaign_manifest.json"
    for path in (metrics_path, traces_path, manifest_path):
        if not path.exists():
            raise FileNotFoundError(path)

    metrics = pd.read_csv(metrics_path)
    traces = pd.read_csv(traces_path)
    manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    metrics = metrics[metrics["topology"] == "urban_roundabout"].copy()
    traces = traces[traces["topology"] == "urban_roundabout"].copy()

    completed_traces = len(traces.drop_duplicates(["vehicle_count", "seed"]))
    completed_evaluations = len(metrics)
    counts_match = bool(
        not traces.empty
        and (traces["vehicle_count"] == traces["observed_vehicle_count"]).all()
    )
    architectures = tuple(sorted(metrics["architecture"].dropna().unique()))
    expected_architectures = tuple(sorted(ARCHITECTURES))
    integrity_ok = (
        completed_traces == 50
        and completed_evaluations == 150
        and counts_match
        and architectures == expected_architectures
    )

    summary = (
        metrics.groupby(["vehicle_count", "architecture"], as_index=False)
        [list(DISPLAY_COLUMNS[2:])]
        .mean()
        .sort_values(["vehicle_count", "architecture"])
    )
    formatted = summary[list(DISPLAY_COLUMNS)].copy()
    for column in (
        "trust_precision",
        "malicious_revocation_recall",
        "false_revocation_rate",
        "trust_f1",
        "mcc",
    ):
        formatted[column] = formatted[column].map(lambda value: f"{value:.6f}")
    for column in (
        "latency_p95_ms",
        "messages_per_decision",
        "bytes_per_decision",
        "cpu_time_seconds",
        "peak_memory_kb",
    ):
        formatted[column] = formatted[column].map(lambda value: f"{value:.3f}")

    lines = [
        "=" * 88,
        "V-PUFT SCENARIO 5 - URBAN ROUNDABOUT - TERMINAL AUDIT",
        "=" * 88,
        f"Campaign                 : {manifest.get('campaign')}",
        f"Topology                 : {manifest.get('topologies')}",
        f"Vehicle counts           : {manifest.get('vehicle_counts')}",
        f"Seeds                    : {manifest.get('seeds')}",
        f"Backhaul levels (ms)     : {manifest.get('backhaul_extra_latency_ms')}",
        f"Completed SUMO traces    : {completed_traces}/50",
        f"Architecture evaluations : {completed_evaluations}/150",
        f"Vehicle counts match     : {counts_match}",
        f"Architectures match      : {architectures == expected_architectures}",
        f"INTEGRITY STATUS         : {'PASS' if integrity_ok else 'FAIL'}",
        "",
        "MEAN RESULTS ACROSS 10 SEEDS",
        "-" * 88,
        formatted.to_string(index=False),
        "",
        "COPY EVERYTHING FROM THE FIRST ===== LINE TO THIS LINE AND SEND IT FOR REVIEW.",
    ]
    text = "\n".join(lines)
    output = campaign / "terminal_summary.txt"
    output.write_text(text + "\n", encoding="utf-8")
    if not integrity_ok:
        raise SystemExit(text)
    return text


def main() -> None:
    parser = argparse.ArgumentParser(description="Print the strict Scenario 5 terminal audit")
    parser.add_argument("--campaign", default="results/urban_roundabout_campaign")
    args = parser.parse_args()
    print(summarize(Path(args.campaign)))


if __name__ == "__main__":
    main()
