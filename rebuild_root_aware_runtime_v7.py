from __future__ import annotations

import argparse
import json
from collections import Counter
from pathlib import Path

import pandas as pd

from upgrade_existing_campaign_v4 import TOPOLOGIES, _rebuild_seed_events
from vpuft.config import load_config
from vpuft.trace import calibration_rows, sanitize_runtime_events, write_events_jsonl


def _case_count(events) -> int:
    return len({(int(event.seed), str(event.case_id)) for event in events})


def _inference_rows(events, topology: str) -> list[dict]:
    rows: list[dict] = []
    seen: set[tuple[int, str]] = set()

    for event in sorted(events, key=lambda item: (int(item.seed), str(item.case_id), float(item.detected_at))):
        key = (int(event.seed), str(event.case_id))
        if key in seen:
            continue
        seen.add(key)

        payload = dict(event.payload)
        truth_attack = str(payload.get("ground_truth_case_attack_type", "unknown"))
        truth_malicious = int(payload.get("ground_truth_case_malicious", int(event.ground_truth_malicious)))
        inferred = event.attack_type.value

        rows.append({
            "topology": topology,
            "seed": int(event.seed),
            "case_id": str(event.case_id),
            "ground_truth_attack_type": truth_attack,
            "ground_truth_malicious": truth_malicious,
            "inferred_attack_type": inferred,
            "attack_type_correct": int(truth_attack == inferred),
        })

    return rows


def main() -> None:
    parser = argparse.ArgumentParser(
        description=(
            "Rebuild sensor-isolated evidence from the original completed SUMO campaign, "
            "then perform exactly one root-aware runtime case formation pass. "
            "No SUMO, sensitivity, or architecture replay is run here."
        )
    )
    parser.add_argument("--input", default="results/full_campaign")
    parser.add_argument("--output", default="results/full_campaign_v7")
    parser.add_argument("--config", default="configs/full_experiment.json")
    args = parser.parse_args()

    source = Path(args.input).resolve()
    output = Path(args.output).resolve()
    if source == output:
        raise ValueError("--output must differ from --input")
    if not source.exists():
        raise FileNotFoundError(f"Missing source campaign: {source}")

    cfg = load_config(args.config)
    window_seconds = float(cfg.detector.case_window_seconds)
    output.mkdir(parents=True, exist_ok=True)

    all_calibration: list[dict] = []
    all_inference: list[dict] = []
    audit_rows: list[dict] = []

    print("[v7] rebuilding from original completed SUMO traces", flush=True)
    print("[v7] SUMO rerun: NO", flush=True)
    print("[v7] detector reassessment with existing sensor model: YES", flush=True)
    print("[v7] runtime case formation passes: EXACTLY ONE for calibration/audit", flush=True)
    print("[v7] architecture input will be UNSANITIZED sensor evidence so run_trace_campaign performs its one pass", flush=True)

    for topology in TOPOLOGIES:
        trace_root = source / topology / "traces"
        if not trace_root.exists():
            raise FileNotFoundError(f"Missing topology trace directory: {trace_root}")

        seed_dirs = sorted(
            trace_root.glob("seed_*"),
            key=lambda p: int(p.name.split("_")[-1]),
        )
        if not seed_dirs:
            raise FileNotFoundError(f"No seed directories found under {trace_root}")

        sensor_events = []
        for seed_dir in seed_dirs:
            sensor_events.extend(_rebuild_seed_events(seed_dir, cfg))

        topology_dir = output / topology
        topology_dir.mkdir(parents=True, exist_ok=True)

        # IMPORTANT:
        # This is the trace that must later be passed to run_trace_campaign.
        # It is sensor-isolated but NOT runtime-sanitized/windowed yet.
        architecture_input_trace = topology_dir / "sensor_detection_trace_all_seeds.jsonl"
        write_events_jsonl(sensor_events, architecture_input_trace)

        # Exactly one runtime formation pass for calibration/audit.
        runtime_events = sanitize_runtime_events(
            sensor_events,
            window_seconds=window_seconds,
            namespace=topology,
        )

        runtime_audit_trace = topology_dir / "runtime_root_aware_trace_audit_only.jsonl"
        write_events_jsonl(runtime_events, runtime_audit_trace)

        rows = calibration_rows(runtime_events)
        for row in rows:
            row["topology"] = topology
        all_calibration.extend(rows)

        inference_rows = _inference_rows(runtime_events, topology)
        all_inference.extend(inference_rows)

        malicious = [row for row in inference_rows if row["ground_truth_malicious"] == 1]
        malicious_accuracy = (
            sum(row["attack_type_correct"] for row in malicious) / len(malicious)
            if malicious else 0.0
        )

        audit_rows.append({
            "topology": topology,
            "sensor_events_before_runtime_formation": len(sensor_events),
            "runtime_events_after_one_formation_pass": len(runtime_events),
            "runtime_cases_after_one_formation_pass": _case_count(runtime_events),
            "malicious_attack_inference_accuracy": malicious_accuracy,
            "architecture_input_trace": str(architecture_input_trace),
            "runtime_audit_trace": str(runtime_audit_trace),
        })

        print(
            f"[v7] {topology}: sensor_events={len(sensor_events):,}; "
            f"runtime_events={len(runtime_events):,}; "
            f"runtime_cases={_case_count(runtime_events):,}; "
            f"malicious_inference_accuracy={malicious_accuracy:.4f}",
            flush=True,
        )

    evidence_path = output / "all_topologies_evidence_campaign.csv"
    pd.DataFrame(all_calibration).to_csv(evidence_path, index=False)

    inference_path = output / "attack_inference_audit.csv"
    inference_df = pd.DataFrame(all_inference)
    inference_df.to_csv(inference_path, index=False)

    audit_path = output / "runtime_rebuild_audit.csv"
    pd.DataFrame(audit_rows).to_csv(audit_path, index=False)

    print(f"[v7] calibration rows={len(all_calibration):,}", flush=True)

    print("[v7] selected ground-truth -> inferred audit:", flush=True)
    for truth in ("replay", "mixed", "flood"):
        subset = inference_df[inference_df["ground_truth_attack_type"] == truth]
        counts = Counter(subset["inferred_attack_type"].astype(str))
        print(f"  {truth}: {dict(sorted(counts.items()))}", flush=True)

    summary = {
        "source_campaign": str(source),
        "output_campaign": str(output),
        "sumo_rerun_required": False,
        "detector_reassessment_from_existing_traces": True,
        "root_aware_runtime_case_formation": True,
        "runtime_case_formation_passes_for_calibration": 1,
        "architecture_replay_rule": (
            "Pass sensor_detection_trace_all_seeds.jsonl to run_trace_campaign; "
            "do NOT pass runtime_root_aware_trace_audit_only.jsonl."
        ),
        "evidence_campaign": str(evidence_path),
        "attack_inference_audit": str(inference_path),
        "runtime_rebuild_audit": str(audit_path),
    }
    (output / "v7_runtime_rebuild_summary.json").write_text(
        json.dumps(summary, indent=2),
        encoding="utf-8",
    )

    print("[v7] COMPLETE", flush=True)
    print(json.dumps(summary, indent=2), flush=True)


if __name__ == "__main__":
    main()
