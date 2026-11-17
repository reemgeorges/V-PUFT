from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path

import matplotlib.pyplot as plt
import numpy as np
import pandas as pd


COUNT_METRICS = ("TP", "FP", "TN", "FN")
RATIO_METRICS = (
    "trust_precision", "malicious_revocation_recall", "false_revocation_rate",
    "trust_f1", "mcc", "opportunity_detection_recall", "protected_opportunity_fraction",
)
COST_METRICS = (
    "cpu_time_seconds", "latency_p95_ms", "messages_per_decision", "bytes_per_decision",
    "packet_delivery_ratio", "ledger_consistency_delay_p95_ms",
)
REQUIRED_VARIANTS = ("baseline", "A_report_mass", "C_no_diversity_gates")


def pooled_confusion(group: pd.DataFrame) -> dict[str, float | int]:
    counts = {key: int(group[key].sum()) for key in COUNT_METRICS}
    tp, fp, tn, fn = (counts[key] for key in COUNT_METRICS)
    precision = tp / (tp + fp) if tp + fp else 0.0
    recall = tp / (tp + fn) if tp + fn else 0.0
    frr = fp / (fp + tn) if fp + tn else 0.0
    f1 = 2 * precision * recall / (precision + recall) if precision + recall else 0.0
    denominator = ((tp + fp) * (tp + fn) * (tn + fp) * (tn + fn)) ** 0.5
    mcc = ((tp * tn - fp * fn) / denominator) if denominator else 0.0
    return {
        **counts,
        "evaluated_windows": tp + fp + tn + fn,
        "excluded_post_revocation_windows": int(group["excluded_post_revocation_cases"].sum()),
        "pooled_precision": precision,
        "pooled_state_aware_recall": recall,
        "pooled_frr": frr,
        "pooled_f1": f1,
        "pooled_mcc": mcc,
    }


def pooled_opportunities(group: pd.DataFrame) -> dict[str, float | int]:
    opportunities = int(group["attack_message_opportunities"].sum())
    detected = int(group["successfully_detected_attack_messages"].sum())
    protected = int(group["protected_attack_messages"].sum())
    return {
        "pooled_attack_opportunities": opportunities,
        "pooled_successfully_detected_opportunities": detected,
        "pooled_protected_opportunities": protected,
        "pooled_opportunity_detection_recall": detected / opportunities if opportunities else 0.0,
        "pooled_protected_opportunity_fraction": protected / opportunities if opportunities else 0.0,
    }


def validate_complete(metrics: pd.DataFrame, decisions: pd.DataFrame, opportunities: pd.DataFrame) -> None:
    expected = {
        (variant, density, seed, architecture)
        for variant in REQUIRED_VARIANTS
        for density in (20, 100)
        for seed in (7003, 7004, 7005, 7006)
        for architecture in ("C100", "Distributed")
    }
    observed = set(map(tuple, metrics[["variant_id", "density", "seed", "architecture"]].itertuples(index=False, name=None)))
    if observed != expected or len(metrics) != 48:
        raise ValueError(f"Incomplete or duplicate metric cells: expected=48 observed={len(metrics)}")
    for frame, label in ((decisions, "case decisions"), (opportunities, "opportunities")):
        keys = set(map(tuple, frame[["variant_id", "density", "seed", "architecture"]].drop_duplicates().itertuples(index=False, name=None)))
        if keys != expected:
            raise ValueError(f"Missing {label} for one or more completed cells")
    if decisions.duplicated(["variant_id", "density", "seed", "architecture", "case_id"]).any():
        raise ValueError("Duplicate case decisions")
    if opportunities.duplicated(["variant_id", "density", "seed", "architecture"]).any():
        raise ValueError("Duplicate fixed-opportunity cell")
    for _, group in opportunities.groupby(["density", "seed"]):
        for column in ("attack_message_opportunities", "observed_attack_messages", "unobserved_attack_messages"):
            if group[column].nunique(dropna=False) != 1:
                raise ValueError(f"Fixed denominator or observation coverage changed in {column}")
    for (density, seed, architecture), group in decisions.groupby(["density", "seed", "architecture"]):
        baseline = set(group[group.variant_id == "baseline"].case_id)
        for variant in REQUIRED_VARIANTS[1:]:
            candidate = set(group[group.variant_id == variant].case_id)
            if candidate != baseline:
                raise ValueError(f"Case population mismatch {density}/{seed}/{architecture}/{variant}")


def aggregated_tables(metrics: pd.DataFrame, opportunities: pd.DataFrame) -> tuple[pd.DataFrame, pd.DataFrame, pd.DataFrame]:
    joined = metrics.merge(
        opportunities[[
            "variant_id", "density", "seed", "architecture",
            "attack_message_opportunities", "observed_attack_messages", "unobserved_attack_messages",
            "successfully_detected_attack_messages", "missed_attack_messages", "protected_attack_messages",
            "opportunity_detection_recall", "protected_opportunity_fraction",
        ]],
        on=["variant_id", "density", "seed", "architecture"],
        validate="one_to_one",
    )
    rows = []
    for key, group in joined.groupby(["variant_id", "density", "architecture"], sort=True):
        row = dict(zip(("variant_id", "density", "architecture"), key))
        row.update(pooled_confusion(group))
        row.update(pooled_opportunities(group))
        for column in dict.fromkeys((*RATIO_METRICS, *COST_METRICS, "latency_p95_ms", "messages_per_decision", "cpu_time_seconds")):
            if column in group:
                row[f"macro_seed_{column}"] = float(group[column].mean())
                row[f"sd_seed_{column}"] = float(group[column].std(ddof=1)) if len(group) > 1 else float("nan")
        for column in ("attack_message_opportunities", "observed_attack_messages", "unobserved_attack_messages", "successfully_detected_attack_messages", "missed_attack_messages", "protected_attack_messages"):
            if column in group:
                row[f"pooled_{column}"] = int(group[column].sum())
        rows.append(row)

    paired_rows = []
    numeric = [column for column in (
        *COUNT_METRICS, "excluded_post_revocation_cases", "attack_message_opportunities",
        "observed_attack_messages", "unobserved_attack_messages",
        "successfully_detected_attack_messages", "missed_attack_messages", "protected_attack_messages",
        *RATIO_METRICS, *COST_METRICS,
    ) if column in joined]
    for variant in REQUIRED_VARIANTS[1:]:
        left = joined[joined.variant_id == variant].set_index(["density", "seed", "architecture"])
        right = joined[joined.variant_id == "baseline"].set_index(["density", "seed", "architecture"])
        for key in left.index:
            candidate = left.loc[key]
            baseline = right.loc[key]
            for metric in numeric:
                before, after = float(baseline[metric]), float(candidate[metric])
                paired_rows.append({
                    "variant_id": variant,
                    "density": key[0],
                    "seed": key[1],
                    "architecture": key[2],
                    "metric": metric,
                    "baseline": before,
                    "candidate": after,
                    "paired_difference_candidate_minus_baseline": after - before,
                    "n_seed_pairs": 1,
                })
    per_seed = pd.DataFrame(paired_rows)
    summary_rows = []
    higher_is_better = {
        "TP", "TN", "trust_precision", "malicious_revocation_recall", "trust_f1", "mcc",
        "opportunity_detection_recall", "protected_opportunity_fraction", "packet_delivery_ratio",
    }
    lower_is_better = {
        "FP", "FN", "false_revocation_rate", "cpu_time_seconds", "latency_p95_ms",
        "messages_per_decision", "bytes_per_decision", "ledger_consistency_delay_p95_ms",
    }
    for key, group in per_seed.groupby(["variant_id", "density", "architecture", "metric"], sort=True):
        values = group["paired_difference_candidate_minus_baseline"].astype(float).dropna()
        if values.empty:
            continue
        direction = "higher" if key[3] in higher_is_better else "lower" if key[3] in lower_is_better else "descriptive_only"
        favorable = values > 1e-12 if direction == "higher" else values < -1e-12 if direction == "lower" else values.abs() > 1e-12
        unfavorable = values < -1e-12 if direction == "higher" else values > 1e-12 if direction == "lower" else values.abs() > 1e-12
        summary_rows.append({
            "variant_id": key[0], "density": key[1], "architecture": key[2], "metric": key[3],
            "n_paired_seeds": len(values),
            "mean_paired_difference": float(values.mean()),
            "median_paired_difference": float(values.median()),
            "expected_benefit_direction": direction,
            "improved_seed_count": int(favorable.sum()) if direction != "descriptive_only" else "N/A",
            "unchanged_seed_count": int((values.abs() <= 1e-12).sum()),
            "worsened_seed_count": int(unfavorable.sum()) if direction != "descriptive_only" else "N/A",
            "min_paired_difference": float(values.min()),
            "max_paired_difference": float(values.max()),
            "uncertainty_note": "Four paired seeds; descriptive range only, not a significance claim.",
        })
    return pd.DataFrame(rows), per_seed, pd.DataFrame(summary_rows)


def case_changes(decisions: pd.DataFrame) -> pd.DataFrame:
    base = decisions[decisions.variant_id == "baseline"].set_index(["density", "seed", "architecture", "case_id"])
    rows = []
    for variant in REQUIRED_VARIANTS[1:]:
        candidate = decisions[decisions.variant_id == variant].set_index(["density", "seed", "architecture", "case_id"])
        aligned = candidate.join(base[["predicted_revoked", "ground_truth_malicious", "reason"]], rsuffix="_baseline", validate="one_to_one")
        for idx, row in aligned.iterrows():
            if int(row["predicted_revoked"]) != int(row["predicted_revoked_baseline"]):
                rows.append({
                    "variant_id": variant,
                    "density": idx[0], "seed": idx[1], "architecture": idx[2], "case_id": idx[3],
                    "vehicle_id": row["vehicle_id"],
                    "ground_truth_malicious": int(row["ground_truth_malicious"]),
                    "baseline_revoked": int(row["predicted_revoked_baseline"]),
                    "candidate_revoked": int(row["predicted_revoked"]),
                    "baseline_reason": row["reason_baseline"],
                    "candidate_reason": row["reason"],
                })
    return pd.DataFrame(rows)


def render_figures(aggregated: pd.DataFrame, output: Path) -> None:
    output.mkdir(parents=True, exist_ok=True)
    labels = {"baseline": "Baseline", "A_report_mass": "A: report-level mass", "C_no_diversity_gates": "C: no diversity gates"}
    colors = {"baseline": "#334e68", "A_report_mass": "#d9822b", "C_no_diversity_gates": "#b83227"}
    for density in (20, 100):
        fig, axes = plt.subplots(1, 3, figsize=(18, 5.5), constrained_layout=True)
        for ax, metric, title, ylabel in (
            (axes[0], "macro_seed_malicious_revocation_recall", "State-aware first-revocation recall", "Recall (fraction)"),
            (axes[1], "macro_seed_opportunity_detection_recall", "Fixed-opportunity detection recall", "Recall (fraction)"),
            (axes[2], "macro_seed_protected_opportunity_fraction", "Fixed-opportunity protection", "Protected fraction"),
        ):
            subset = aggregated[aggregated.density.astype(int) == density]
            x = np.arange(2)
            width = 0.24
            for i, variant in enumerate(REQUIRED_VARIANTS):
                vals = [float(subset[(subset.variant_id == variant) & (subset.architecture == arch)][metric].iloc[0]) for arch in ("C100", "Distributed")]
                ax.bar(x + (i - 1) * width, vals, width, color=colors[variant], label=labels[variant] if ax is axes[0] else None)
            ax.set_xticks(x, ("C100", "Distributed"))
            ax.set_ylabel(ylabel)
            ax.set_title(title)
            ax.grid(axis="y", alpha=0.25)
        axes[0].legend(frameon=False)
        fig.suptitle(f"Scenario 5 component ablation — density {density}; four paired seeds; macro mean of seed metrics")
        fig.savefig(output / f"ablation_security_density_{density}.png", dpi=300)
        plt.close(fig)

        fig, axes = plt.subplots(1, 3, figsize=(18, 5.5), constrained_layout=True)
        subset = aggregated[aggregated.density.astype(int) == density]
        x = np.arange(2)
        width = 0.24
        for i, variant in enumerate(REQUIRED_VARIANTS):
            for ax, metric, title, ylabel in (
                (axes[0], "macro_seed_cpu_time_seconds", "Host CPU", "CPU seconds / run"),
                (axes[1], "macro_seed_latency_p95_ms", "P95 E2E latency", "Milliseconds / run"),
                (axes[2], "macro_seed_messages_per_decision", "Communication volume", "Messages / case"),
            ):
                vals = [float(subset[(subset.variant_id == variant) & (subset.architecture == arch)][metric].iloc[0]) for arch in ("C100", "Distributed")]
                ax.bar(x + (i - 1) * width, vals, width, color=colors[variant], label=labels[variant])
                ax.set_xticks(x, ("C100", "Distributed"))
                ax.set_ylabel(ylabel)
                ax.set_title(title)
                ax.grid(axis="y", alpha=0.25)
        axes[0].legend(frameon=False)
        fig.suptitle(f"Scenario 5 component ablation — density {density}; four paired seeds; macro mean of seed metrics")
        fig.savefig(output / f"ablation_cost_density_{density}.png", dpi=300)
        plt.close(fig)


def _write_analysis(output: Path, aggregated: pd.DataFrame, paired_summary: pd.DataFrame, changes: pd.DataFrame) -> None:
    lines = [
        "# Paired statistical analysis — Scenario 5 bounded component ablation",
        "",
        "All comparisons are paired by density, seed, and architecture. The experimental unit for uncertainty summaries is the SUMO seed, not the case window. Each density has four paired seeds; ranges are descriptive only and do not support a strong significance claim.",
        "",
        "State-aware metrics exclude post-first-revocation terminal windows. Fixed-opportunity detection Recall uses the emitted malicious-message universe from each matched trace. Protected-opportunity fraction separately counts malicious transmissions emitted strictly after the first committed vehicle revocation.",
        "",
        "The variants A and C are insecure counterfactuals. Their effect sizes are component diagnostics, not candidate configurations.",
        "",
        "## Paired differences",
        "",
        "`paired_comparison_summary.csv` contains mean and median candidate-minus-baseline differences, per-seed improvement/unchanged/worsened counts, and observed min/max paired ranges. The expected beneficial direction is recorded per metric; post-revocation exclusions are descriptive only.",
        "",
        "## Decision changes",
        "",
        f"Case-level revocation decisions changed in {len(changes)} paired cells/cases. See `case_level_changes.csv` for exact case identities and benign/malicious labels.",
        "",
        "## Aggregate tables",
        "",
        "Pooled confusion metrics are computed from summed TP/FP/TN/FN across the four seeds. Macro metrics are means of per-seed values. They are not interchangeable.",
        "",
        "See `aggregated_metrics.csv`, `paired_comparison_by_seed.csv`, and `paired_comparison_summary.csv` for numeric results.",
    ]
    (output / "STATISTICAL_ANALYSIS.md").write_text("\n".join(lines) + "\n", encoding="utf-8")


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--input-dir", type=Path, default=Path("results/final_scenario5_ablation"))
    args = parser.parse_args()
    output = args.input_dir.resolve()
    metrics = pd.read_csv(output / "ABLATION_METRICS_BY_SEED.csv")
    decisions = pd.read_csv(output / "ABLATION_CASE_DECISIONS.csv")
    opportunities = pd.read_csv(output / "ABLATION_FIXED_OPPORTUNITIES.csv")
    validate_complete(metrics, decisions, opportunities)
    aggregated, paired_by_seed, paired_summary = aggregated_tables(metrics, opportunities)
    changes = case_changes(decisions)
    aggregated.to_csv(output / "aggregated_metrics.csv", index=False)
    paired_by_seed.to_csv(output / "paired_comparison_by_seed.csv", index=False)
    paired_summary.to_csv(output / "paired_comparison_summary.csv", index=False)
    changes.to_csv(output / "case_level_changes.csv", index=False)
    # Full paired deltas are reconstructed from the summary inputs for transparency.
    joined = metrics.merge(opportunities, on=["variant_id", "density", "seed", "architecture"], suffixes=("", "_op"), validate="one_to_one")
    joined.to_csv(output / "metrics_and_opportunities_joined.csv", index=False)
    render_figures(aggregated, output / "figures")
    _write_analysis(output, aggregated, paired_summary, changes)
    files = sorted(path for path in output.rglob("*") if path.is_file() and path.name != "ABLATION_OUTPUT_HASHES.json")
    hashes = {path.relative_to(output).as_posix(): hashlib.sha256(path.read_bytes()).hexdigest() for path in files}
    (output / "ABLATION_OUTPUT_HASHES.json").write_text(json.dumps(hashes, indent=2, sort_keys=True), encoding="utf-8")
    print(json.dumps({"status": "analysis_complete", "cells": len(metrics), "changed_case_rows": len(changes), "hashes": len(hashes)}, indent=2))


if __name__ == "__main__":
    main()
