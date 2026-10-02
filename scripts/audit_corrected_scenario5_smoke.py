from __future__ import annotations

import argparse
import json
from dataclasses import replace
from pathlib import Path

import numpy as np
import pandas as pd

from vpuft.architectures import CentralizedVPUFT, DistributedRSUExtendedVPUFT
from vpuft.config import WeightConfig, load_config
from vpuft.crypto import KeyRegistry
from vpuft.metrics import decision_metrics
from vpuft.network import audit_link_order
from vpuft.trace import build_trace_bundle, read_events_jsonl


def _effective_config(config_path: Path, selected_path: Path):
    config = load_config(config_path)
    selected = json.loads(selected_path.read_text(encoding="utf-8"))
    policies = dict(config.policies)
    for name, overrides in selected.get("attack_policies", {}).items():
        policies[name] = replace(policies[name], **overrides)
    config = replace(config, weights=WeightConfig(**selected["weights"]), policies=policies)
    config.validate()
    return config


def _result_row(result, truth, opened, density, seed):
    metrics = decision_metrics(result, truth, opened)
    audit = audit_link_order(result.messages)
    expired = sum(int(d.metadata.get("expired_evidence", 0) or 0) for d in result.decisions)
    pbft_ms = [
        (o.committed_at - o.started_at) * 1000.0
        for o in result.consensus
        if o.committed and o.committed_at is not None
    ]
    seen_revoked = set()
    repeated_commits = 0
    terminal_noops = 0
    for decision in result.decisions:
        if decision.reason == "already_revoked_terminal_state":
            terminal_noops += 1
        if decision.committed and decision.new_state.value == "revoked":
            if decision.vehicle_id in seen_revoked:
                repeated_commits += 1
            else:
                seen_revoked.add(decision.vehicle_id)
    return {
        "density": density,
        "seed": seed,
        "architecture": result.architecture,
        "cases": len(result.decisions),
        "messages": len(result.messages),
        "temporal_inversions": int(audit["temporal_inversions"]),
        "serialization_overlaps": int(audit["serialization_overlaps"]),
        "mean_queue_delay_ms": float(audit["mean_queue_delay_ms"]),
        "max_queue_delay_ms": float(audit["max_queue_delay_ms"]),
        "expired_evidence": expired,
        "p95_e2e_ms": metrics["latency_p95_ms"],
        "p95_consensus_ms": metrics["consensus_latency_p95_ms"],
        "p95_ledger_delay_ms": metrics["ledger_consistency_delay_p95_ms"],
        "pure_pbft_p95_ms": float(np.percentile(pbft_ms, 95)) if pbft_ms else np.nan,
        "messages_per_case": metrics["messages_per_decision"],
        "pdr": metrics["packet_delivery_ratio"],
        "TP": metrics["TP"],
        "FP": metrics["FP"],
        "TN": metrics["TN"],
        "FN": metrics["FN"],
        "security_cases_evaluated": metrics["security_cases_evaluated"],
        "excluded_post_revocation_cases": metrics["excluded_post_revocation_cases"],
        "all_window_TP": metrics["all_window_TP"],
        "all_window_FP": metrics["all_window_FP"],
        "all_window_TN": metrics["all_window_TN"],
        "all_window_FN": metrics["all_window_FN"],
        "recall": metrics["malicious_revocation_recall"],
        "frr": metrics["false_revocation_rate"],
        "mcc": metrics["mcc"],
        "ledger_consistent": metrics["ledger_consistent"],
        "terminal_state_noops": terminal_noops,
        "repeated_committed_revocations": repeated_commits,
    }


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--output-root", default="results/urban_roundabout_smoke_corrected")
    parser.add_argument("--config", default="configs/urban_roundabout_campaign.json")
    parser.add_argument(
        "--weights",
        default="results/full_campaign_v7/sensitivity_shared_views_mixedfix/selected_weights.json",
    )
    parser.add_argument("--seed", type=int, default=1001)
    parser.add_argument("--densities", default="20,40,60,80,100")
    args = parser.parse_args()

    config = _effective_config(Path(args.config), Path(args.weights))
    if config.policies["mixed"].required_modalities != 1:
        raise RuntimeError("Corrected Scenario 5 requires mixed.required_modalities == 1")

    keys = KeyRegistry(config.security.deterministic_master_seed)
    root = Path(args.output_root)
    rows = []
    comparison_rows = []

    for density in [int(x) for x in args.densities.split(",") if x.strip()]:
        trace = root / "traces" / "urban_roundabout" / f"vehicles_{density}" / f"seed_{args.seed}" / "shared_detection_trace.jsonl"
        if not trace.exists():
            print(f"SKIP density={density}: missing {trace}")
            continue
        events = read_events_jsonl(trace)
        bundle = build_trace_bundle(
            events,
            keys,
            window_seconds=config.detector.case_window_seconds,
            namespace=f"urban_roundabout-vehicles-{density}",
        )
        cases = bundle.rsu_cases
        truth = {case.case_id: case.ground_truth_malicious for case in cases}
        opened = {case.case_id: case.opened_at for case in cases}

        dcfg = replace(config, network=replace(config.network, central_backhaul_extra_latency_ms=0.0))
        c0cfg = replace(config, network=replace(config.network, central_backhaul_extra_latency_ms=0.0))
        c100cfg = replace(config, network=replace(config.network, central_backhaul_extra_latency_ms=100.0))
        results = [
            DistributedRSUExtendedVPUFT(dcfg, keys).run(cases, args.seed),
            CentralizedVPUFT(c0cfg, keys).run(cases, args.seed),
            CentralizedVPUFT(c100cfg, keys).run(cases, args.seed),
        ]
        labels = ["distributed_density_honest", "centralized_remote_0ms_control", "centralized_remote_100ms"]
        for result, label in zip(results, labels):
            result = replace(
                result,
                architecture=label,
                decisions=[replace(decision, architecture=label) for decision in result.decisions],
            )
            row = _result_row(result, truth, opened, density, args.seed)
            rows.append(row)
            print(json.dumps(row, sort_keys=True))
            if row["temporal_inversions"] or row["serialization_overlaps"]:
                raise RuntimeError(f"Transport audit failed for {label} density={density}")
            if row["repeated_committed_revocations"]:
                raise RuntimeError(
                    f"Terminal-state guard failed for {label} density={density}: "
                    f"repeated_committed_revocations={row['repeated_committed_revocations']}"
                )

        distributed, c0, c100 = results
        d_by = {d.case_id: d for d in distributed.decisions}
        c0_by = {d.case_id: d for d in c0.decisions}
        c100_by = {d.case_id: d for d in c100.decisions}
        common = sorted(set(d_by) & set(c0_by) & set(c100_by))
        cd_agree = sum(
            (d_by[cid].committed, d_by[cid].new_state) == (c0_by[cid].committed, c0_by[cid].new_state)
            for cid in common
        )
        shifts = [
            (c100_by[cid].finalized_at - c0_by[cid].finalized_at) * 1000.0
            for cid in common
            if c100_by[cid].finalized_at is not None and c0_by[cid].finalized_at is not None
        ]
        comparison = {
            "density": density,
            "seed": args.seed,
            "common_cases": len(common),
            "c0_d_binary_state_agreement": cd_agree,
            "c0_d_binary_state_agreement_rate": cd_agree / len(common) if common else np.nan,
            "c100_minus_c0_finalized_median_ms": float(np.median(shifts)) if shifts else np.nan,
            "c100_minus_c0_finalized_min_ms": float(np.min(shifts)) if shifts else np.nan,
            "c100_minus_c0_finalized_max_ms": float(np.max(shifts)) if shifts else np.nan,
        }
        comparison_rows.append(comparison)
        print("COMPARE", json.dumps(comparison, sort_keys=True))

    combined = root / "combined"
    combined.mkdir(parents=True, exist_ok=True)
    pd.DataFrame(rows).to_csv(combined / "corrected_scheduler_smoke_audit.csv", index=False)
    pd.DataFrame(comparison_rows).to_csv(combined / "corrected_scheduler_smoke_comparison.csv", index=False)
    print(f"WROTE {combined / 'corrected_scheduler_smoke_audit.csv'}")
    print(f"WROTE {combined / 'corrected_scheduler_smoke_comparison.csv'}")


if __name__ == "__main__":
    main()
