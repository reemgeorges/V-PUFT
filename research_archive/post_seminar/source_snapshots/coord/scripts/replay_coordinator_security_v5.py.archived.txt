from __future__ import annotations

import argparse
import hashlib
import json
import statistics
import time
from dataclasses import replace
from pathlib import Path

import pandas as pd

from vpuft.architectures import DistributedRSUExtendedVPUFT
from vpuft.config import load_config
from vpuft.crypto import KeyRegistry
from vpuft.trace import build_trace_bundle, read_events_jsonl
from run_phase2_ablation import decision_frame, metric_row


CELLS = ((20, 2101), (20, 2102), (60, 2101), (60, 2102), (100, 2101), (100, 2102))


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for block in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(block)
    return digest.hexdigest()


def completed_trace(root: Path, density: int, seed: int) -> Path:
    parent = root / "pilot" / "C3" / f"vehicles_{density}"
    primary = parent / f"seed_{seed}"
    if (primary / "run_summary.json").is_file():
        marker = json.loads((primary / "run_summary.json").read_text(encoding="utf-8"))
        if marker.get("completed") is True:
            return primary / "shared_detection_trace.jsonl"
    retries = [
        candidate / "shared_detection_trace.jsonl"
        for candidate in sorted(parent.glob(f"seed_{seed}_retry*"))
        if (candidate / "run_summary.json").is_file()
        and json.loads((candidate / "run_summary.json").read_text(encoding="utf-8")).get("completed") is True
    ]
    if len(retries) != 1:
        raise FileNotFoundError(f"expected a unique completed C3 trace for {density}/{seed}, got {retries}")
    return retries[0]


def configs(base):
    membership = ("rsu-1", "rsu-2", "rsu-3", "rsu-4", "rsu-5")
    historical = replace(
        base,
        pbft=replace(base.pbft, validators=membership, max_byzantine=1, quorum_size=4,
                     membership_epoch="v5-eight-rsu-committee-v1"),
        simulation=replace(base.simulation, rsu_count=8),
        distributed_extension=replace(
            base.distributed_extension,
            coordinator_strategy="first_observer_then_hash",
            coordinator_pool=("rsu-1", "rsu-2", "rsu-3", "rsu-4"),
            membership_epoch="v5-eight-rsu-committee-v1",
            sensing_only_rsu_ids=("rsu-6", "rsu-7", "rsu-8"),
        ),
    )
    deterministic = replace(
        historical,
        distributed_extension=replace(
            historical.distributed_extension,
            coordinator_strategy="canonical_case_epoch_hash",
            coordinator_pool=membership,
            membership_epoch="v5-coordinator-security-fixed-epoch-v1",
        ),
        pbft=replace(historical.pbft, membership_epoch="v5-coordinator-security-fixed-epoch-v1"),
    )
    historical.validate()
    deterministic.validate()
    return (("V5_historical_first_observer_pool4", historical),
            ("V5_deterministic_pool5", deterministic))


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--config", type=Path, required=True)
    parser.add_argument("--trace-root", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--repeats", type=int, default=3)
    args = parser.parse_args()
    if args.repeats < 1:
        raise ValueError("repeats must be at least one")

    base = load_config(args.config)
    variants = configs(base)
    rows, pairs, trace_manifest = [], [], []
    for density, seed in CELLS:
        trace = completed_trace(args.trace_root, density, seed)
        events = read_events_jsonl(trace)
        bundle = build_trace_bundle(
            events, KeyRegistry(base.security.deterministic_master_seed),
            window_seconds=base.detector.case_window_seconds,
            namespace=f"urban_roundabout-vehicles-{density}",
        )
        cases = bundle.rsu_cases
        case_ids = {case.case_id for case in cases}
        if len(case_ids) != len(cases):
            raise AssertionError(f"duplicate case identities at {density}/{seed}")
        trace_hash = sha256_file(trace)
        trace_manifest.append({"density": density, "seed": seed, "cases": len(cases),
                               "trace": str(trace), "sha256": trace_hash})
        paired_rows = []
        for label, config in variants:
            cpu_samples, result, frame, first_decisions = [], None, None, None
            for _ in range(args.repeats):
                start = time.process_time()
                result = DistributedRSUExtendedVPUFT(
                    config, KeyRegistry(config.security.deterministic_master_seed)
                ).run(cases, seed)
                cpu_samples.append(time.process_time() - start)
                frame = decision_frame(result, cases, density=density, seed=seed, variant=label)
                decisions = frame[["case_id", "new_state", "committed"]].sort_values("case_id").reset_index(drop=True)
                if first_decisions is None:
                    first_decisions = decisions
                else:
                    pd.testing.assert_frame_equal(first_decisions, decisions, check_dtype=False)
            assert result is not None and frame is not None
            row = metric_row(result, cases, frame, density=density, seed=seed, variant=label,
                             cpu=statistics.median(cpu_samples), wall=float("nan"), peak=float("nan"), acquisition={})
            message_types = [message.message_type for message in result.messages]
            row.update({
                "case_count": len(cases), "trace_sha256": trace_hash, "repeats": args.repeats,
                "cpu_median_s": statistics.median(cpu_samples), "cpu_mean_s": statistics.mean(cpu_samples),
                "cpu_stdev_s": statistics.stdev(cpu_samples) if len(cpu_samples) > 1 else 0.0,
                "cpu_min_s": min(cpu_samples), "cpu_max_s": max(cpu_samples),
                "all_message_count": len(message_types),
                "pbft_state_recovery_messages": sum(kind in {"PRE_PREPARE", "PREPARE", "COMMIT", "STATE_RECOVERY"} for kind in message_types),
                "evidence_transport_messages": sum(kind in {"RSU_EVIDENCE_EXCHANGE", "VPUFT_EVIDENCE_BUNDLE", "WITNESS_EVIDENCE_UPLINK"} for kind in message_types),
                "messages_per_input_case": len(message_types) / max(1, len(cases)),
                "successful_finalizations": sum(outcome.committed for outcome in result.consensus),
                "consensus_progress_failures": sum(not outcome.committed for outcome in result.consensus),
                "selected_coordinator_counts": json.dumps(result.extension_metrics.get("coordinator_counts", {}), sort_keys=True),
                "ledger_consistent": int(result.ledger_consistent),
                "trace_path_used": str(trace),
            })
            rows.append(row)
            paired_rows.append((label, row, first_decisions))
            print(f"{label} d={density} seed={seed} cases={len(cases)} TP={row['TP']} FP={row['FP']} CPU={row['cpu_median_s']:.6f}s", flush=True)
        (left_name, left, left_decisions), (right_name, right, right_decisions) = paired_rows
        pd.testing.assert_frame_equal(left_decisions, right_decisions, check_dtype=False)
        pairs.append({
            "density": density, "seed": seed, "cases": len(cases), "trace_sha256": trace_hash,
            "classification_identical": True,
            "old_TP": left["TP"], "new_TP": right["TP"], "old_FP": left["FP"], "new_FP": right["FP"],
            "old_TN": left["TN"], "new_TN": right["TN"], "old_FN": left["FN"], "new_FN": right["FN"],
            "old_recall": left["recall"], "new_recall": right["recall"],
            "old_cpu_s": left["cpu_median_s"], "new_cpu_s": right["cpu_median_s"],
            "old_p95_e2e_ms": left["p95_e2e_ms"], "new_p95_e2e_ms": right["p95_e2e_ms"],
            "old_messages_per_input_case": left["messages_per_input_case"],
            "new_messages_per_input_case": right["messages_per_input_case"],
            "old_pdr": left["pdr"], "new_pdr": right["pdr"],
            "old_ledger_delay_p95_ms": left["p95_ledger_consistency_ms"],
            "new_ledger_delay_p95_ms": right["p95_ledger_consistency_ms"],
            "old_finalizations": left["successful_finalizations"], "new_finalizations": right["successful_finalizations"],
        })

    args.output.mkdir(parents=True, exist_ok=True)
    pd.DataFrame(rows).to_csv(args.output / "coordinator_paired_metrics.csv", index=False)
    pd.DataFrame(pairs).to_csv(args.output / "coordinator_paired_differences.csv", index=False)
    manifest = {
        "baseline_config_sha256": sha256_file(args.config), "traces": trace_manifest,
        "variants": [{"name": name, "validators": list(cfg.pbft.validators), "quorum": cfg.pbft.resolved_quorum,
                      "membership_epoch": cfg.distributed_extension.membership_epoch,
                      "coordinator_strategy": cfg.distributed_extension.coordinator_strategy,
                      "coordinator_pool": list(cfg.distributed_extension.coordinator_pool)} for name, cfg in variants],
        "repeats": args.repeats, "sumo_rerun": False, "paired_inputs": True,
    }
    (args.output / "coordinator_replay_manifest.json").write_text(json.dumps(manifest, indent=2), encoding="utf-8")
    print(f"wrote {args.output}", flush=True)


if __name__ == "__main__":
    main()
