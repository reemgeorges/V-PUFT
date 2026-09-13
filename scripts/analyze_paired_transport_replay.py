from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path

import numpy as np
import pandas as pd
from scipy.stats import rankdata, wilcoxon


DIST = "distributed_crn_honest"
CENTRALS = (
    "central_crn_available_0ms",
    "central_crn_operational_0ms",
)
METRICS = (
    "trust_precision",
    "malicious_revocation_recall",
    "false_revocation_rate",
    "trust_f1",
    "mcc",
    "latency_p95_ms",
    "messages_per_decision",
    "bytes_per_decision",
    "mean_queue_delay_ms",
    "packet_delivery_ratio",
    "cpu_time_seconds",
    "peak_memory_kb",
)


def _holm(values: pd.Series) -> pd.Series:
    result = pd.Series(index=values.index, dtype=float)
    ordered = list(values.sort_values().index)
    running = 0.0
    total = len(ordered)
    for rank, index in enumerate(ordered):
        adjusted = min(1.0, (total - rank) * float(values.loc[index]))
        running = max(running, adjusted)
        result.loc[index] = running
    return result


def _summary(metrics: pd.DataFrame) -> pd.DataFrame:
    keys = ["topology", "vehicle_count", "architecture"]
    numeric = [column for column in METRICS if column in metrics]
    grouped = metrics.groupby(keys)
    return pd.concat(
        [
            grouped.size().rename("seed_count"),
            grouped[numeric].mean().add_suffix("__mean"),
            grouped[numeric].median().add_suffix("__median"),
            grouped[numeric].std(ddof=1).add_suffix("__std"),
        ],
        axis=1,
    ).reset_index()


def _paired(metrics: pd.DataFrame) -> pd.DataFrame:
    rows = []
    distributed = metrics[metrics.architecture.eq(DIST)]
    for central_name in CENTRALS:
        central = metrics[metrics.architecture.eq(central_name)]
        for (topology, count), remote in central.groupby(["topology", "vehicle_count"]):
            local = distributed[
                distributed.topology.eq(topology)
                & distributed.vehicle_count.eq(count)
            ]
            merged = local.merge(remote, on="seed", suffixes=("__distributed", "__central"))
            for metric in METRICS:
                left, right = f"{metric}__distributed", f"{metric}__central"
                pairs = merged[[left, right]].dropna()
                if pairs.empty:
                    continue
                differences = (pairs[left] - pairs[right]).to_numpy(float)
                nonzero = differences[differences != 0]
                if len(nonzero):
                    raw_p = float(wilcoxon(nonzero, alternative="two-sided").pvalue)
                    ranks = rankdata(np.abs(nonzero))
                    positive = float(ranks[nonzero > 0].sum())
                    negative = float(ranks[nonzero < 0].sum())
                    effect = (positive - negative) / (positive + negative)
                else:
                    raw_p, effect = 1.0, np.nan
                digest = hashlib.sha256(
                    f"paired|{central_name}|{topology}|{count}|{metric}".encode()
                ).digest()
                rng = np.random.default_rng(int.from_bytes(digest[:8], "big"))
                boot = rng.choice(
                    differences, size=(2000, len(differences)), replace=True
                ).mean(axis=1)
                rows.append(
                    {
                        "central_comparator": central_name,
                        "topology": topology,
                        "vehicle_count": count,
                        "metric": metric,
                        "paired_seed_count": len(pairs),
                        "distributed_mean": float(pairs[left].mean()),
                        "central_mean": float(pairs[right].mean()),
                        "mean_difference_distributed_minus_central": float(
                            differences.mean()
                        ),
                        "ci95_lower": float(np.percentile(boot, 2.5)),
                        "ci95_upper": float(np.percentile(boot, 97.5)),
                        "wilcoxon_raw_p": raw_p,
                        "rank_biserial": effect,
                    }
                )
    result = pd.DataFrame(rows)
    result["holm_adjusted_p_within_comparator_metric_20_cells"] = np.nan
    for _, indices in result.groupby(["central_comparator", "metric"]).groups.items():
        result.loc[indices, "holm_adjusted_p_within_comparator_metric_20_cells"] = _holm(
            result.loc[indices, "wilcoxon_raw_p"]
        )
    result["holm_reject_0_05"] = (
        result["holm_adjusted_p_within_comparator_metric_20_cells"] < 0.05
    )
    result["analysis_family"] = "post_hoc_supplementary_sensitivity"
    return result


def _agreement(decisions: pd.DataFrame) -> tuple[pd.DataFrame, pd.DataFrame]:
    keys = ["topology", "vehicle_count", "seed", "case_id"]
    local = decisions[decisions.architecture.eq(DIST)]
    rows, flips = [], []
    for central_name in CENTRALS:
        central = decisions[decisions.architecture.eq(central_name)]
        merged = local.merge(central, on=keys, suffixes=("__distributed", "__central"))
        changed = merged[
            merged.predicted_revoked__distributed.ne(
                merged.predicted_revoked__central
            )
        ].copy()
        changed.insert(0, "central_comparator", central_name)
        flips.append(changed)
        rows.append(
            {
                "central_comparator": central_name,
                "shared_cases": len(merged),
                "unique_classification_changes": len(changed),
                "agreement_rate": 1.0 - len(changed) / max(1, len(merged)),
                "distributed_only_revoked": int(
                    (
                        changed.predicted_revoked__distributed
                        > changed.predicted_revoked__central
                    ).sum()
                ),
                "central_only_revoked": int(
                    (
                        changed.predicted_revoked__central
                        > changed.predicted_revoked__distributed
                    ).sum()
                ),
            }
        )
    return pd.DataFrame(rows), pd.concat(flips, ignore_index=True)


def _pooled_confusion(decisions: pd.DataFrame) -> pd.DataFrame:
    rows = []
    for architecture, group in decisions.groupby("architecture"):
        actual = group.ground_truth_malicious.astype(int)
        predicted = group.predicted_revoked.astype(int)
        tp = int(((actual == 1) & (predicted == 1)).sum())
        fp = int(((actual == 0) & (predicted == 1)).sum())
        tn = int(((actual == 0) & (predicted == 0)).sum())
        fn = int(((actual == 1) & (predicted == 0)).sum())
        precision = tp / max(1, tp + fp)
        recall = tp / max(1, tp + fn)
        frr = fp / max(1, fp + tn)
        f1 = 2 * precision * recall / max(1e-15, precision + recall)
        denominator = np.sqrt((tp + fp) * (tp + fn) * (tn + fp) * (tn + fn))
        mcc = (tp * tn - fp * fn) / denominator if denominator else 0.0
        rows.append(
            {
                "architecture": architecture,
                "TP": tp,
                "FP": fp,
                "TN": tn,
                "FN": fn,
                "precision": precision,
                "recall": recall,
                "frr": frr,
                "f1": f1,
                "mcc": mcc,
            }
        )
    return pd.DataFrame(rows)


def _derived_remote(metrics: pd.DataFrame, delays: list[float]) -> pd.DataFrame:
    frames = []
    shifted = (
        "qualification_latency_p95_ms",
        "latency_p50_ms",
        "latency_p95_ms",
        "latency_p99_ms",
    )
    for central_name in CENTRALS:
        base = metrics[metrics.architecture.eq(central_name)].copy()
        for delay in delays:
            frame = base.copy()
            frame["source_architecture"] = central_name
            frame["architecture"] = central_name.replace("_0ms", f"_{delay:g}ms")
            frame["backhaul_extra_latency_ms"] = delay
            for column in shifted:
                if column in frame:
                    frame[column] = frame[column] + delay
            frame["derivation"] = "exact additive one-way backhaul shift; no architecture rerun"
            frames.append(frame)
    return pd.concat(frames, ignore_index=True)


def _breakeven(metrics: pd.DataFrame, max_delay: float) -> pd.DataFrame:
    rows = []
    distributed = metrics[metrics.architecture.eq(DIST)]
    for central_name in CENTRALS:
        central = metrics[metrics.architecture.eq(central_name)]
        for (topology, count), local in distributed.groupby(["topology", "vehicle_count"]):
            remote = central[
                central.topology.eq(topology) & central.vehicle_count.eq(count)
            ]
            difference = float(local.latency_p95_ms.mean() - remote.latency_p95_ms.mean())
            rows.append(
                {
                    "central_comparator": central_name,
                    "topology": topology,
                    "vehicle_count": count,
                    "model_implied_breakeven_one_way_ms": difference,
                    "inside_tested_0_to_max_delay": 0.0 <= difference <= max_delay,
                    "reporting_status": (
                        "inside_sweep_model_intersection"
                        if 0.0 <= difference <= max_delay
                        else "outside_sweep_model_extrapolation"
                    ),
                }
            )
    return pd.DataFrame(rows)


def _message_summaries(messages: pd.DataFrame) -> tuple[pd.DataFrame, pd.DataFrame]:
    """Aggregate queue delay without averaging incompatible group means.

    The raw file contains one mean queue delay for each
    topology/density/seed/architecture/message-type row.  A plain mean of
    those row means gives a tiny message type the same weight as millions of
    evidence messages.  Retain that diagnostic value under an explicit name,
    but use message counts for the descriptive per-message mean.

    The paired inferential metric in ``paired_metrics_by_seed.csv`` remains a
    per-run outcome and is intentionally not replaced here: seeds are the
    experimental units in that analysis.
    """
    frame = messages.copy()
    frame["queue_delay_message_ms"] = (
        frame["mean_queue_delay_ms"] * frame["messages"]
    )
    by_type = (
        frame.groupby(["architecture", "message_type"], as_index=False)
        .agg(
            messages=("messages", "sum"),
            delivered=("delivered", "sum"),
            dropped=("dropped", "sum"),
            bytes_total=("bytes_total", "sum"),
            retransmissions=("retransmissions", "sum"),
            queue_delay_message_ms=("queue_delay_message_ms", "sum"),
            unweighted_cell_mean_queue_delay_ms=("mean_queue_delay_ms", "mean"),
        )
    )
    by_type["message_weighted_mean_queue_delay_ms"] = (
        by_type["queue_delay_message_ms"] / by_type["messages"].clip(lower=1)
    )
    by_type["mean_bytes_per_message"] = (
        by_type["bytes_total"] / by_type["messages"].clip(lower=1)
    )
    by_type["delivery_rate"] = (
        by_type["delivered"] / by_type["messages"].clip(lower=1)
    )
    by_type = by_type.drop(columns="queue_delay_message_ms")

    architecture = (
        frame.groupby("architecture", as_index=False)
        .agg(
            messages=("messages", "sum"),
            delivered=("delivered", "sum"),
            dropped=("dropped", "sum"),
            bytes_total=("bytes_total", "sum"),
            retransmissions=("retransmissions", "sum"),
            queue_delay_message_ms=("queue_delay_message_ms", "sum"),
        )
    )
    architecture["message_weighted_mean_queue_delay_ms"] = (
        architecture["queue_delay_message_ms"]
        / architecture["messages"].clip(lower=1)
    )
    architecture["mean_bytes_per_message"] = (
        architecture["bytes_total"] / architecture["messages"].clip(lower=1)
    )
    architecture["delivery_rate"] = (
        architecture["delivered"] / architecture["messages"].clip(lower=1)
    )
    architecture = architecture.drop(columns="queue_delay_message_ms")
    return by_type, architecture


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument(
        "--input-dir", default=str(Path.home() / "VPUFT_density_paired_replay" / "combined")
    )
    args = parser.parse_args()
    root = Path(args.input_dir)
    metrics = pd.read_csv(root / "paired_metrics_by_seed.csv")
    decisions = pd.read_csv(root / "paired_decisions.csv")
    messages = pd.read_csv(root / "paired_message_type_summary.csv")
    manifest = json.loads((root / "paired_replay_manifest.json").read_text(encoding="utf-8"))

    summary = _summary(metrics)
    paired = _paired(metrics)
    agreement, flips = _agreement(decisions)
    pooled = _pooled_confusion(decisions)
    delays = [float(value) for value in manifest["backhaul_levels_derived_after_0ms_replay"]]
    derived = _derived_remote(metrics, delays)
    breakeven = _breakeven(metrics, max(delays))
    message_summary, communication_summary = _message_summaries(messages)

    summary.to_csv(root / "paired_architecture_summary.csv", index=False)
    paired.to_csv(root / "paired_core_comparisons.csv", index=False)
    agreement.to_csv(root / "paired_case_agreement.csv", index=False)
    flips.to_csv(root / "paired_classification_flips.csv", index=False)
    pooled.to_csv(root / "paired_pooled_confusion.csv", index=False)
    derived.to_csv(root / "paired_remote_derived_metrics.csv", index=False)
    breakeven.to_csv(root / "paired_breakeven.csv", index=False)
    message_summary.to_csv(
        root / "paired_message_type_architecture_summary.csv", index=False
    )
    communication_summary.to_csv(
        root / "paired_communication_architecture_summary.csv", index=False
    )

    expected = int(manifest["expected_cells"])
    observed = len(metrics[["topology", "vehicle_count", "seed"]].drop_duplicates())
    if observed != expected or len(metrics) != expected * 3:
        raise SystemExit(
            f"Incomplete paired replay: cells={observed}/{expected}, metrics={len(metrics)}/{expected * 3}"
        )

    agreement_lines = "\n".join(
        f"- {row.central_comparator}: {int(row.unique_classification_changes)} unique changes / "
        f"{int(row.shared_cases)} shared cases; agreement={row.agreement_rate:.6%}."
        for row in agreement.itertuples()
    )
    inside = breakeven[breakeven.inside_tested_0_to_max_delay]
    unique_inside = inside[["topology", "vehicle_count"]].drop_duplicates()
    family_count = paired[["central_comparator", "metric"]].drop_duplicates().shape[0]
    family_size = int(
        paired.groupby(["central_comparator", "metric"]).size().max()
    )
    significant = int(paired.holm_reject_0_05.sum())
    minimum_adjusted = float(
        paired.holm_adjusted_p_within_comparator_metric_20_cells.min()
    )
    communication_lines = "\n".join(
        f"- {row.architecture}: messages={int(row.messages)}, "
        f"bytes={int(row.bytes_total)}, message-weighted queue delay="
        f"{row.message_weighted_mean_queue_delay_ms:.4f} ms."
        for row in communication_summary.itertuples()
    )
    audit = f"""# Evidence-CRN Paired Transport Replay — Audit

## Integrity

- SUMO rerun: **NO**
- Saved density traces reused: **YES**
- Completed cells: **{observed}/{expected}**
- Architecture runs: **{len(metrics)}** (three per cell)
- Evidence loss/jitter/retry draws paired by attestation key: **YES**
- Queueing, local coordinator delivery and PBFT-only traffic remain architecture-specific: **YES**
- Analysis family: **post-hoc supplementary sensitivity**

## Classification agreement

{agreement_lines}

## Backhaul

- Central runs were executed once at 0 ms.
- The configured one-way backhaul levels were derived by the exact additive rule already implemented and verified in the original campaign: {delays}.
- Break-even points inside the tested 0–{max(delays):g} ms range: **{len(inside)}/{len(breakeven)} comparator cells**.
- Those rows represent **{len(unique_inside)} unique topology × density conditions** repeated across the two central comparators.
- Values outside that range are explicitly labeled model extrapolations.

## Statistical boundary

- Holm families: **{family_count}** comparator × metric families, each containing **{family_size}** topology × density comparisons.
- Holm rejections: **{significant}/{len(paired)}**; the smallest adjusted p-value is **{minimum_adjusted:.7f}**.
- With ten paired seeds, that value is the attainable boundary produced when all non-zero seed differences point in the same direction. The family remains post-hoc/supplementary and must not be relabeled confirmatory.

## Communication and queue delay

{communication_lines}

- The message-weighted descriptive queue delay is lower for the distributed path in this replay. Interpretation must remain conditional on message mix: Central uses one evidence-message type, whereas Distributed includes evidence exchange, evidence bundles, PBFT, ledger replication and read-cache synchronization.
- The per-seed paired ``mean_queue_delay_ms`` remains valid as a run-level outcome. The message-type table now separately reports both the unweighted cell mean and the message-count-weighted per-message mean.

## Interpretation boundary

This replay removes order-dependent transport RNG as an explanation for evidence-delivery differences. It does not make the architectures identical: coordinator-local evidence avoids a network hop in the distributed path, central queueing remains central, and validator requalification/PBFT/replication remain distributed costs. The availability=1.0 central ablation isolates architectural processing from the separate availability=0.995 operational stimulus. Timing remains simulated, and the analysis remains post-hoc/exploratory.
"""
    (root / "PAIRED_TRANSPORT_RESULTS_AUDIT.md").write_text(audit, encoding="utf-8")
    print(audit)


if __name__ == "__main__":
    main()
