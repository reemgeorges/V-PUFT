from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path

import numpy as np
import pandas as pd
from scipy.stats import rankdata, wilcoxon


METRICS = (
    "trust_precision",
    "malicious_revocation_recall",
    "false_revocation_rate",
    "trust_f1",
    "mcc",
    "detection_latency_p95_ms",
    "qualification_latency_p95_ms",
    "consensus_latency_p95_ms",
    "latency_p50_ms",
    "latency_p95_ms",
    "latency_p99_ms",
    "ledger_consistency_delay_p95_ms",
    "messages_per_decision",
    "bytes_per_decision",
    "retransmissions",
    "mean_queue_delay_ms",
    "packet_delivery_ratio",
    "consensus_success_rate",
    "consensus_liveness_failures",
    "safety_violations",
    "view_changes",
    "runtime_seconds",
    "cpu_time_seconds",
    "peak_memory_kb",
)

# Constant bookkeeping fields remain available in descriptive summaries but
# are not hypotheses. In particular safety_violations is a simulator invariant,
# not an empirical Byzantine-safety measurement.
INFERENTIAL_METRICS = tuple(
    metric
    for metric in METRICS
    if metric
    not in {
        "consensus_success_rate",
        "consensus_liveness_failures",
        "safety_violations",
        "view_changes",
    }
)


def _summary(metrics: pd.DataFrame) -> pd.DataFrame:
    numeric = [column for column in METRICS if column in metrics]
    keys = ["topology", "vehicle_count", "architecture", "backhaul_extra_latency_ms"]
    grouped = metrics.groupby(keys, dropna=False)
    mean = grouped[numeric].mean().add_suffix("__mean")
    median = grouped[numeric].median().add_suffix("__median")
    std = grouped[numeric].std(ddof=1).add_suffix("__std")
    count = grouped.size().rename("seed_count")
    return pd.concat([count, mean, median, std], axis=1).reset_index()


def _paired(metrics: pd.DataFrame) -> pd.DataFrame:
    distributed = metrics[metrics["architecture"] == "distributed_density_honest"].copy()
    central = metrics[metrics["architecture"].str.startswith("centralized_remote_")].copy()
    rows = []
    for (topology, count, delay), remote in central.groupby(
        ["topology", "vehicle_count", "backhaul_extra_latency_ms"], dropna=False
    ):
        local = distributed[
            (distributed["topology"] == topology)
            & (distributed["vehicle_count"] == count)
        ]
        merged = local.merge(remote, on="seed", suffixes=("__distributed", "__remote"))
        for metric in INFERENTIAL_METRICS:
            left = f"{metric}__distributed"
            right = f"{metric}__remote"
            if left not in merged or right not in merged:
                continue
            pairs = merged[[left, right]].dropna()
            if pairs.empty:
                continue
            differences = pairs[left] - pairs[right]
            difference_array = differences.to_numpy(dtype=float)
            nonzero = difference_array[difference_array != 0]
            if len(nonzero):
                raw_p = float(wilcoxon(nonzero, alternative="two-sided").pvalue)
                ranks = rankdata(np.abs(nonzero))
                positive = float(ranks[nonzero > 0].sum())
                negative = float(ranks[nonzero < 0].sum())
                rank_biserial = (positive - negative) / (positive + negative)
            else:
                raw_p = 1.0
                rank_biserial = np.nan
            digest = hashlib.sha256(
                f"{topology}|{count}|{delay}|{metric}".encode("utf-8")
            ).digest()
            rng = np.random.default_rng(int.from_bytes(digest[:8], "big"))
            bootstrap_means = rng.choice(
                difference_array,
                size=(2000, len(difference_array)),
                replace=True,
            ).mean(axis=1)
            rows.append(
                {
                    "topology": topology,
                    "vehicle_count": count,
                    "backhaul_extra_latency_ms": delay,
                    "metric": metric,
                    "paired_seed_count": len(pairs),
                    "distributed_mean": pairs[left].mean(),
                    "remote_mean": pairs[right].mean(),
                    "mean_difference_distributed_minus_remote": differences.mean(),
                    "median_difference_distributed_minus_remote": differences.median(),
                    "difference_std": differences.std(ddof=1),
                    "minimum_difference": differences.min(),
                    "maximum_difference": differences.max(),
                    "mean_difference_ci95_lower": float(np.percentile(bootstrap_means, 2.5)),
                    "mean_difference_ci95_upper": float(np.percentile(bootstrap_means, 97.5)),
                    "wilcoxon_raw_p": raw_p,
                    "rank_biserial": rank_biserial,
                }
            )
    result = pd.DataFrame(rows)
    if result.empty:
        return result
    result["holm_adjusted_p_within_metric"] = np.nan
    for metric, indices in result.groupby("metric").groups.items():
        ordered = sorted(indices, key=lambda index: result.at[index, "wilcoxon_raw_p"])
        family_size = len(ordered)
        running = 0.0
        for rank, index in enumerate(ordered):
            adjusted = min(1.0, (family_size - rank) * result.at[index, "wilcoxon_raw_p"])
            running = max(running, adjusted)
            result.at[index, "holm_adjusted_p_within_metric"] = running
    result["holm_reject_0_05"] = result["holm_adjusted_p_within_metric"] < 0.05
    result["holm_adjusted_p_within_metric_and_backhaul"] = np.nan
    for (_metric, _delay), indices in result.groupby(
        ["metric", "backhaul_extra_latency_ms"]
    ).groups.items():
        ordered = sorted(indices, key=lambda index: result.at[index, "wilcoxon_raw_p"])
        family_size = len(ordered)
        running = 0.0
        for rank, index in enumerate(ordered):
            adjusted = min(
                1.0,
                (family_size - rank) * result.at[index, "wilcoxon_raw_p"],
            )
            running = max(running, adjusted)
            result.at[index, "holm_adjusted_p_within_metric_and_backhaul"] = running
    result["holm_reject_0_05_within_metric_and_backhaul"] = (
        result["holm_adjusted_p_within_metric_and_backhaul"] < 0.05
    )
    result["analysis_family"] = "supplementary_exploratory_density"
    return result


def _breakeven(metrics: pd.DataFrame) -> pd.DataFrame:
    distributed = metrics[metrics["architecture"] == "distributed_density_honest"]
    central = metrics[metrics["architecture"].str.startswith("centralized_remote_")]
    rows = []
    for (topology, count), local in distributed.groupby(["topology", "vehicle_count"]):
        target = float(local["latency_p95_ms"].mean())
        remote = (
            central[
                (central["topology"] == topology)
                & (central["vehicle_count"] == count)
            ]
            .groupby("backhaul_extra_latency_ms", as_index=False)["latency_p95_ms"]
            .mean()
            .sort_values("backhaul_extra_latency_ms")
        )
        point = np.nan
        status = "outside_sweep"
        lower_delay = upper_delay = np.nan
        for (_, lower), (_, upper) in zip(remote.iloc[:-1].iterrows(), remote.iloc[1:].iterrows()):
            lower_delta = float(lower["latency_p95_ms"] - target)
            upper_delta = float(upper["latency_p95_ms"] - target)
            if lower_delta == 0:
                point = float(lower["backhaul_extra_latency_ms"])
                status = "observed_exact"
                lower_delay = upper_delay = point
                break
            if lower_delta * upper_delta <= 0:
                x0 = float(lower["backhaul_extra_latency_ms"])
                x1 = float(upper["backhaul_extra_latency_ms"])
                y0 = float(lower["latency_p95_ms"])
                y1 = float(upper["latency_p95_ms"])
                point = x0 + (target - y0) * (x1 - x0) / (y1 - y0)
                status = "linearly_interpolated"
                lower_delay, upper_delay = x0, x1
                break
        rows.append(
            {
                "topology": topology,
                "vehicle_count": count,
                "distributed_p95_mean_ms": target,
                "breakeven_one_way_extra_latency_ms": point,
                "model_implied_breakeven_one_way_extra_latency_ms": (
                    target - float(remote.iloc[0]["latency_p95_ms"])
                    if not remote.empty
                    else np.nan
                ),
                "status": status,
                "interpolation_lower_ms": lower_delay,
                "interpolation_upper_ms": upper_delay,
            }
        )
    return pd.DataFrame(rows)


def _case_agreement(decisions: pd.DataFrame) -> pd.DataFrame:
    distributed = decisions[
        decisions["architecture"] == "distributed_density_honest"
    ][["topology", "vehicle_count", "seed", "case_id", "predicted_revoked"]]
    rows = []
    central = decisions[decisions["architecture"].str.startswith("centralized_remote_")]
    for (topology, count, seed, architecture, delay), remote in central.groupby(
        ["topology", "vehicle_count", "seed", "architecture", "backhaul_extra_latency_ms"],
        dropna=False,
    ):
        local = distributed[
            (distributed["topology"] == topology)
            & (distributed["vehicle_count"] == count)
            & (distributed["seed"] == seed)
        ]
        merged = local.merge(remote[["case_id", "predicted_revoked"]], on="case_id", suffixes=("__distributed", "__remote"))
        changes = int(
            (merged["predicted_revoked__distributed"] != merged["predicted_revoked__remote"]).sum()
        )
        rows.append(
            {
                "topology": topology,
                "vehicle_count": count,
                "seed": seed,
                "remote_architecture": architecture,
                "backhaul_extra_latency_ms": delay,
                "shared_cases": len(merged),
                "classification_changes": changes,
                "agreement_rate": 1.0 - changes / max(1, len(merged)),
            }
        )
    return pd.DataFrame(rows)


def _density_steps(summary: pd.DataFrame) -> pd.DataFrame:
    rows = []
    group_keys = ["topology", "architecture", "backhaul_extra_latency_ms"]
    mean_columns = [column for column in summary if column.endswith("__mean")]
    for keys, group in summary.groupby(group_keys, dropna=False):
        ordered = group.sort_values("vehicle_count")
        for (_, previous), (_, current) in zip(ordered.iloc[:-1].iterrows(), ordered.iloc[1:].iterrows()):
            for column in mean_columns:
                old = previous[column]
                new = current[column]
                if pd.isna(old) or pd.isna(new):
                    continue
                absolute = new - old
                relative = absolute / abs(old) if old != 0 else np.nan
                rows.append(
                    {
                        "topology": keys[0],
                        "architecture": keys[1],
                        "backhaul_extra_latency_ms": keys[2],
                        "from_vehicle_count": previous["vehicle_count"],
                        "to_vehicle_count": current["vehicle_count"],
                        "metric": column.removesuffix("__mean"),
                        "previous_mean": old,
                        "current_mean": new,
                        "absolute_change": absolute,
                        "relative_change": relative,
                    }
                )
    return pd.DataFrame(rows)


def _attack_metrics_by_seed(decisions: pd.DataFrame) -> pd.DataFrame:
    """Keep attack-specific conclusions tied to the exact paired cells.

    Recall is defined for malicious attack rows.  FRR is defined for benign
    rows.  The unused rate remains NaN rather than being reported as a
    misleading zero.
    """

    keys = [
        "topology",
        "vehicle_count",
        "seed",
        "architecture",
        "backhaul_extra_latency_ms",
        "attack_type",
    ]
    rows = []
    for values, group in decisions.groupby(keys, dropna=False):
        actual = group["ground_truth_malicious"].astype(int)
        predicted = group["predicted_revoked"].astype(int)
        tp = int(((actual == 1) & (predicted == 1)).sum())
        fp = int(((actual == 0) & (predicted == 1)).sum())
        tn = int(((actual == 0) & (predicted == 0)).sum())
        fn = int(((actual == 1) & (predicted == 0)).sum())
        malicious_total = tp + fn
        benign_total = fp + tn
        rows.append(
            {
                **dict(zip(keys, values)),
                "cases": len(group),
                "TP": tp,
                "FP": fp,
                "TN": tn,
                "FN": fn,
                "attack_recall": tp / malicious_total if malicious_total else np.nan,
                "benign_false_revocation_rate": (
                    fp / benign_total if benign_total else np.nan
                ),
            }
        )
    return pd.DataFrame(rows)


def _attack_summary(by_seed: pd.DataFrame) -> pd.DataFrame:
    keys = [
        "topology",
        "vehicle_count",
        "architecture",
        "backhaul_extra_latency_ms",
        "attack_type",
    ]
    numeric = ["cases", "TP", "FP", "TN", "FN", "attack_recall", "benign_false_revocation_rate"]
    grouped = by_seed.groupby(keys, dropna=False)
    return pd.concat(
        [
            grouped.size().rename("seed_count"),
            grouped[numeric].mean().add_suffix("__mean"),
            grouped[numeric].median().add_suffix("__median"),
            grouped[numeric].std(ddof=1).add_suffix("__std"),
        ],
        axis=1,
    ).reset_index()


def _message_summary(messages: pd.DataFrame) -> pd.DataFrame:
    if messages.empty:
        return pd.DataFrame()
    keys = [
        "topology",
        "vehicle_count",
        "architecture",
        "backhaul_extra_latency_ms",
        "message_type",
    ]
    numeric = [
        "messages",
        "delivered",
        "dropped",
        "bytes_total",
        "retransmissions",
        "mean_queue_delay_ms",
    ]
    grouped = messages.groupby(keys, dropna=False)
    return pd.concat(
        [
            grouped.size().rename("seed_count"),
            grouped[numeric].mean().add_suffix("__mean"),
            grouped[numeric].median().add_suffix("__median"),
            grouped[numeric].std(ddof=1).add_suffix("__std"),
        ],
        axis=1,
    ).reset_index()


def _cache_steps(cache_summary: pd.DataFrame) -> pd.DataFrame:
    if cache_summary.empty:
        return pd.DataFrame()
    rows = []
    excluded = {"topology", "requested_vehicle_count", "ttl_seconds", "seed"}
    numeric = [
        column
        for column in cache_summary.select_dtypes(include=[np.number]).columns
        if column not in excluded
    ]
    for (topology, ttl), group in cache_summary.groupby(["topology", "ttl_seconds"]):
        ordered = group.sort_values("requested_vehicle_count")
        for (_, previous), (_, current) in zip(
            ordered.iloc[:-1].iterrows(), ordered.iloc[1:].iterrows()
        ):
            for metric in numeric:
                old, new = previous[metric], current[metric]
                if pd.isna(old) or pd.isna(new):
                    continue
                absolute = new - old
                rows.append(
                    {
                        "topology": topology,
                        "ttl_seconds": ttl,
                        "from_vehicle_count": previous["requested_vehicle_count"],
                        "to_vehicle_count": current["requested_vehicle_count"],
                        "metric": metric,
                        "previous_mean": old,
                        "current_mean": new,
                        "absolute_change": absolute,
                        "relative_change": absolute / abs(old) if old != 0 else np.nan,
                    }
                )
    return pd.DataFrame(rows)


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--input-dir", default="results/density_architecture_campaign/combined")
    args = parser.parse_args()
    root = Path(args.input_dir)
    metrics = pd.read_csv(root / "density_metrics_by_seed.csv")
    decisions = pd.read_csv(root / "density_decisions.csv")
    messages_path = root / "density_message_type_summary.csv"
    cache_path = root / "density_topology_v2v_cache.csv"
    summary = _summary(metrics)
    paired = _paired(metrics)
    breakeven = _breakeven(metrics)
    agreement = _case_agreement(decisions)
    steps = _density_steps(summary)
    attack_by_seed = _attack_metrics_by_seed(decisions)
    attack_summary = _attack_summary(attack_by_seed)
    messages = pd.read_csv(messages_path) if messages_path.exists() else pd.DataFrame()
    message_summary = _message_summary(messages)
    summary.to_csv(root / "density_architecture_summary.csv", index=False)
    paired.to_csv(root / "density_paired_comparisons.csv", index=False)
    breakeven.to_csv(root / "density_breakeven_by_topology_vehicle_count.csv", index=False)
    agreement.to_csv(root / "density_case_agreement.csv", index=False)
    steps.to_csv(root / "density_step_changes.csv", index=False)
    attack_by_seed.to_csv(root / "density_attack_metrics_by_seed.csv", index=False)
    attack_summary.to_csv(root / "density_attack_summary.csv", index=False)
    message_summary.to_csv(root / "density_message_type_architecture_summary.csv", index=False)

    if cache_path.exists() and cache_path.stat().st_size:
        try:
            cache = pd.read_csv(cache_path)
        except pd.errors.EmptyDataError:
            cache = pd.DataFrame()
        if cache.empty:
            cache_summary = pd.DataFrame()
        else:
            cache_group_keys = [
                "topology",
                "requested_vehicle_count",
                "ttl_seconds",
            ]
            cache_numeric = [
                column
                for column in cache.select_dtypes(include=[np.number]).columns
                if column not in {*cache_group_keys, "seed"}
            ]
            cache_grouped = cache.groupby(cache_group_keys)
            cache_summary = cache_grouped[cache_numeric].mean().reset_index()
            cache_summary.insert(
                len(cache_group_keys),
                "seed_count",
                cache_grouped["seed"].nunique().to_numpy(),
            )
    else:
        cache_summary = pd.DataFrame()
    cache_summary.to_csv(root / "density_topology_v2v_cache_summary.csv", index=False)
    _cache_steps(cache_summary).to_csv(root / "density_topology_v2v_cache_step_changes.csv", index=False)

    manifest = json.loads((root / "density_campaign_manifest.json").read_text(encoding="utf-8"))
    expected = int(manifest["expected_shared_traces"])
    trace_audit = pd.read_csv(root / "density_trace_audit.csv")
    complete_traces = len(trace_audit.drop_duplicates(["topology", "vehicle_count", "seed"]))
    all_counts_match = bool(
        (trace_audit["vehicle_count"] == trace_audit["observed_vehicle_count"]).all()
    )
    repeated_flips = int(agreement["classification_changes"].sum()) if not agreement.empty else 0
    backhaul_level_count = int(agreement["backhaul_extra_latency_ms"].nunique()) if not agreement.empty else 0
    holm_cells_per_metric = int(paired.groupby("metric").size().max()) if not paired.empty else 0
    holm_cells_per_metric_backhaul = (
        int(paired.groupby(["metric", "backhaul_extra_latency_ms"]).size().max())
        if not paired.empty
        else 0
    )
    zero_level = agreement[agreement["backhaul_extra_latency_ms"] == 0.0]
    unique_flips = int(zero_level["classification_changes"].sum()) if not zero_level.empty else 0
    unique_shared_cases = int(zero_level["shared_cases"].sum()) if not zero_level.empty else 0
    unique_agreement = 1.0 - unique_flips / max(1, unique_shared_cases)
    audit = f"""# Controlled Topology × Vehicle-Density Campaign — Audit

## Design integrity

- Expected shared SUMO traces: **{expected}**
- Completed unique shared traces: **{complete_traces}**
- Requested/observed vehicle counts match: **{all_counts_match}**
- Same trace paired across architectures: **{manifest['shared_trace_pairing']}**
- Frozen v7 modified: **{manifest['frozen_v7_modified']}**
- Unique Distributed vs Centralized classification changes: **{unique_flips}/{unique_shared_cases}**
- Unique agreement rate: **{unique_agreement:.6%}**
- Repeated total across all {backhaul_level_count} backhaul levels: **{repeated_flips}**
  (the same classification comparison is repeated at every latency level)

## Outputs

- `density_architecture_summary.csv`: every metric by topology, vehicle count and architecture.
- `density_paired_comparisons.csv`: seed-paired Distributed minus Remote differences.
  It includes a paired bootstrap CI, Wilcoxon p-value, rank-biserial effect and
  a {holm_cells_per_metric}-cell Holm adjustment within each metric and a
  {holm_cells_per_metric_backhaul}-cell adjustment within each metric/backhaul
  stratum. Both remain supplementary/exploratory.
- `density_step_changes.csv`: exact absolute and relative 20→40→60→80→100 changes.
- `density_breakeven_by_topology_vehicle_count.csv`: density-specific parametric break-even points.
- `density_case_agreement.csv`: decision agreement audit at every backhaul level.
- `density_attack_summary.csv`: attack-stratified results by topology, density and architecture.
- `density_message_type_architecture_summary.csv`: message-type counts, bytes, loss and queue delay.
- `density_topology_v2v_cache_summary.csv`: topology-aware light-cache results.
- `density_topology_v2v_cache_step_changes.csv`: exact cache changes between adjacent densities.

## Claim boundary

These are controlled simulation/model results. They support density-conditional
comparisons inside the implemented SUMO and transport models, not field-radio,
production-server or universal PBFT performance claims.
"""
    (root / "DENSITY_RESULTS_AUDIT.md").write_text(audit, encoding="utf-8")
    if complete_traces != expected or not all_counts_match:
        raise SystemExit("Density audit failed: missing trace cells or observed vehicle-count mismatch")


if __name__ == "__main__":
    main()
