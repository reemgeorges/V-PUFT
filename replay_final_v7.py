from __future__ import annotations

import argparse
import json
from dataclasses import replace
from pathlib import Path

import pandas as pd

from vpuft.config import WeightConfig, load_config
from vpuft.runner import run_trace_campaign


TOPOLOGIES = ("smoke", "corridor", "intersection", "grid")


def _is_complete(path: Path) -> bool:
    required = (
        "metrics_by_seed.csv",
        "decisions.csv",
        "metrics_by_attack.csv",
        "network_messages.csv",
        "consensus_outcomes.csv",
        "architecture_summary.csv",
    )
    return path.exists() and all((path / name).exists() for name in required)


def _concat(items: list[pd.DataFrame]) -> pd.DataFrame:
    return pd.concat(items, ignore_index=True) if items else pd.DataFrame()


def main() -> None:
    parser = argparse.ArgumentParser(
        description="Replay the already-built v4 sensor-isolated runtime traces with transport-fair architectures."
    )
    parser.add_argument("--input-v4", default="results/full_campaign_v7")
    parser.add_argument("--output", default="reproduction_check/final_architectures")
    parser.add_argument("--config", default="configs/full_experiment.json")
    parser.add_argument("--weights", default="results/full_campaign_v7/sensitivity_shared_views_mixedfix/selected_weights.json")
    parser.add_argument("--resume", action="store_true")
    args = parser.parse_args()

    source = Path(args.input_v4).resolve()
    output = Path(args.output).resolve()
    if source == output:
        raise ValueError("--output must differ from --input-v4")
    if not source.exists():
        raise FileNotFoundError(f"Missing v4 campaign directory: {source}")

    selected_path = Path(args.weights).resolve()
    if not selected_path.exists():
        raise FileNotFoundError(f"Missing selected weights: {selected_path}")
    selected = json.loads(selected_path.read_text(encoding="utf-8"))
    if "weights" not in selected:
        raise ValueError("selected_weights.json does not contain a 'weights' object")

    cfg = load_config(args.config)
    calibrated_cfg = replace(cfg, weights=WeightConfig(**selected["weights"]))
    output.mkdir(parents=True, exist_ok=True)

    print("[v7-final] architecture-only replay with transport-fair evidence delivery ...", flush=True)
    print(f"[v7-final] using v1.0.9 shared-view weights={selected['weights']}", flush=True)
    print("[v7-final] SUMO rerun: NO; detector rebuild: NO; sensitivity rerun: NO", flush=True)

    combined_metrics: list[pd.DataFrame] = []
    combined_decisions: list[pd.DataFrame] = []
    combined_attack: list[pd.DataFrame] = []
    combined_inference: list[pd.DataFrame] = []
    combined_messages: list[pd.DataFrame] = []
    combined_consensus: list[pd.DataFrame] = []
    topology_summaries: list[pd.DataFrame] = []

    for topology in TOPOLOGIES:
        trace_path = source / topology / "sensor_detection_trace_all_seeds.jsonl"
        if not trace_path.exists():
            raise FileNotFoundError(f"Missing v4 runtime trace for {topology}: {trace_path}")

        arch_dir = output / topology / "architecture_campaign_transport_fair"
        if args.resume and _is_complete(arch_dir):
            print(f"[resume] {topology}: architecture replay already complete", flush=True)
        else:
            print(f"[v7-final] {topology}: architecture replay", flush=True)
            run_trace_campaign(calibrated_cfg, trace_path, arch_dir)

        for filename, collector in (
            ("metrics_by_seed.csv", combined_metrics),
            ("decisions.csv", combined_decisions),
            ("metrics_by_attack.csv", combined_attack),
            ("attack_inference_cases.csv", combined_inference),
            ("network_messages.csv", combined_messages),
            ("consensus_outcomes.csv", combined_consensus),
        ):
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
        global_summary = metrics.groupby("architecture", as_index=False)[numeric].mean()
    else:
        global_summary = pd.DataFrame()
    global_summary.to_csv(output / "final_global_architecture_summary.csv", index=False)

    if not messages.empty:
        transport_audit = (
            messages.groupby(["architecture", "message_type"], as_index=False)
            .agg(
                sent=("message_id", "count"),
                delivered=("dropped", lambda s: int((~s.astype(bool)).sum())),
                dropped=("dropped", "sum"),
                bytes_total=("size_bytes", "sum"),
                mean_queue_delay_ms=("queue_delay_ms", "mean"),
                mean_retransmission=("retransmission", "mean"),
            )
            .sort_values(["architecture", "message_type"])
        )
    else:
        transport_audit = pd.DataFrame()
    transport_audit.to_csv(output / "transport_fairness_audit.csv", index=False)

    observed_types = (
        messages.groupby("architecture")["message_type"].apply(lambda s: set(map(str, s))).to_dict()
        if not messages.empty else {}
    )
    required_types = {
        "centralized_vpuft": {"ATTESTATION_TO_SERVER"},
        "distributed_rsu_vpuft": {"RSU_EVIDENCE_EXCHANGE"},
        "ahmed_inspired_witness_vpuft": {"WITNESS_REPORT_TO_RSU", "RSU_WITNESS_EVIDENCE_FORWARD"},
    }
    instrumentation_checks = {
        architecture: sorted(required - observed_types.get(architecture, set()))
        for architecture, required in required_types.items()
    }

    summary = {
        "source_sensor_trace_campaign": str(source),
        "output_campaign": str(output),
        "selected_shared_weights_v1_0_9": selected["weights"],
        "selection_feasible_v1_0_9": bool(selected.get("selection_feasible", False)),
        "calibration_holdout_metrics_v1_0_9": selected.get("holdout_metrics", {}),
        "replay_scope": "architecture transport/finalization only",
        "sumo_rerun_required": False,
        "detector_rebuild_required": False,
        "sensitivity_rerun_required": False,
        "transport_semantics": {
            "centralized": "only ATTESTATION_TO_SERVER deliveries are qualified",
            "distributed": "coordinator-local evidence is local; remote RSU evidence must arrive via RSU_EVIDENCE_EXCHANGE before qualification",
            "ahmed_inspired": "witness reports must reach their validator RSU; remote validator evidence must then reach the coordinator before qualification",
            "network_model": "existing SimulatedTransport loss/retry/serialization/queue/jitter model",
        },
        "instrumentation_missing_required_message_types": instrumentation_checks,
        "outputs": {
            "global_architecture_summary": str(output / "final_global_architecture_summary.csv"),
            "topology_architecture_summary": str(output / "final_topology_architecture_summary.csv"),
            "metrics_by_seed": str(output / "final_metrics_by_seed.csv"),
            "metrics_by_attack": str(output / "final_metrics_by_attack.csv"),
            "decisions": str(output / "final_decisions.csv"),
            "network_messages": str(output / "final_network_messages.csv"),
            "transport_fairness_audit": str(output / "transport_fairness_audit.csv"),
        },
    }
    (output / "v7_final_architecture_summary.json").write_text(json.dumps(summary, indent=2), encoding="utf-8")

    print("[v7-final] COMPLETE", flush=True)
    print(json.dumps(summary, indent=2), flush=True)


if __name__ == "__main__":
    main()
