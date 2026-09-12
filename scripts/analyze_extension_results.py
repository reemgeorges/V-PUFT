from __future__ import annotations

import argparse
from pathlib import Path

import pandas as pd


def _value(frame: pd.DataFrame, architecture: str, metric: str) -> float:
    return float(frame.loc[frame["architecture"] == architecture, metric].iloc[0])


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--input-dir", default="results/extension_frozen_replay/combined")
    args = parser.parse_args()
    root = Path(args.input_dir)
    metrics = pd.read_csv(root / "extension_global_summary.csv")
    agreement = pd.read_csv(root / "extension_case_agreement.csv")
    v2v = pd.read_csv(root / "v2v_trust_cache_sensitivity.csv")
    network = pd.read_csv(root / "extension_network_messages.csv")

    honest = "distributed_extension_honest"
    accusation = "distributed_extension_false_accusation_rsu"
    concealment = "distributed_extension_concealment_rsu"
    validator = "distributed_extension_malicious_validator"
    guard_honest = "distributed_extension_guard_honest"
    guard_attack = "distributed_extension_guard_false_accusation_rsu"

    comparisons = []
    for scenario, reference in [
        (accusation, honest),
        (concealment, honest),
        (validator, honest),
        (guard_attack, guard_honest),
        (guard_honest, honest),
    ]:
        row = {"scenario": scenario, "reference": reference}
        for metric in [
            "malicious_revocation_recall",
            "false_revocation_rate",
            "trust_precision",
            "mcc",
            "latency_p95_ms",
            "messages_per_decision",
            "bytes_per_decision",
        ]:
            row[f"delta_{metric}"] = _value(metrics, scenario, metric) - _value(metrics, reference, metric)
        # Compare the requested pair directly.  The precomputed
        # ``classification_changed__*`` columns use the honest extension as
        # their reference and are therefore not valid for guard-vs-guard
        # comparisons.
        if scenario in agreement.columns and reference in agreement.columns:
            row["classification_changes"] = int(
                (agreement[scenario] != agreement[reference]).sum()
            )
        else:
            change_col = f"classification_changed__{scenario}"
            row["classification_changes"] = (
                int(agreement[change_col].sum()) if change_col in agreement else 0
            )
        row["shared_cases"] = len(agreement)
        comparisons.append(row)
    comparison_frame = pd.DataFrame(comparisons)
    comparison_frame.to_csv(root / "extension_key_comparisons.csv", index=False)

    ttl = v2v.groupby("ttl_seconds", as_index=False).mean(numeric_only=True)
    vehicle = v2v.groupby("vehicle_count", as_index=False).mean(numeric_only=True)
    read_cache_sync = network.loc[network["message_type"] == "RSU_READ_CACHE_SYNC"]
    best_latency = ttl.loc[ttl["authorization_latency_mean_ms"].idxmin()]
    zero = ttl.loc[ttl["ttl_seconds"] == ttl["ttl_seconds"].min()].iloc[0]

    lines = [
        "# Post-Freeze V-PUFT Extension — Results Audit",
        "",
        "> Source: frozen v7 sensor traces replayed with selected v7 weights. SUMO and Centralized Near-Edge were not rerun.",
        "",
        "## Architectural results",
        "",
        "| Variant | Recall | FRR | Precision | MCC | P95 latency (ms) | Msg/decision | Bytes/decision |",
        "|---|---:|---:|---:|---:|---:|---:|---:|",
    ]
    for _, row in metrics.sort_values("architecture").iterrows():
        lines.append(
            f"| {row['architecture']} | {row['malicious_revocation_recall']:.6f} | "
            f"{row['false_revocation_rate']:.6f} | {row['trust_precision']:.6f} | {row['mcc']:.6f} | "
            f"{row['latency_p95_ms']:.2f} | {row['messages_per_decision']:.2f} | {row['bytes_per_decision']:.2f} |"
        )

    lines.extend(["", "## Controlled comparisons", ""])
    for row in comparisons:
        percentage = 100.0 * row["classification_changes"] / max(1, row["shared_cases"])
        lines.append(
            f"- `{row['scenario']}` versus `{row['reference']}`: "
            f"classification changes={row['classification_changes']}/{row['shared_cases']} ({percentage:.4f}%), "
            f"ΔRecall={row['delta_malicious_revocation_recall']:+.6f}, "
            f"ΔFRR={row['delta_false_revocation_rate']:+.6f}, "
            f"ΔP95={row['delta_latency_p95_ms']:+.2f} ms."
        )

    lines.extend([
        "",
        "## V2V cache/TTL sensitivity",
        "",
        "| TTL (s) | Cache hit rate | V2I queries avoided | Stale acceptance rate | Mean authorization latency (ms) | Bytes/interaction |",
        "|---:|---:|---:|---:|---:|---:|",
    ])
    for _, row in ttl.iterrows():
        lines.append(
            f"| {row['ttl_seconds']:.1f} | {row['cache_hit_rate']:.6f} | {row['v2i_queries_avoided']:.2f} | "
            f"{row['stale_acceptance_rate']:.6f} | {row['authorization_latency_mean_ms']:.4f} | "
            f"{row.get('bytes_per_interaction', float('nan')):.2f} |"
        )

    lines.extend([
        "",
        "## V2V density sensitivity",
        "",
        "| Vehicles | Cache hit rate | V2I queries avoided | Stale acceptance rate | Mean authorization latency (ms) | Bytes/interaction |",
        "|---:|---:|---:|---:|---:|---:|",
    ])
    for _, row in vehicle.iterrows():
        lines.append(
            f"| {int(row['vehicle_count'])} | {row['cache_hit_rate']:.6f} | "
            f"{row['v2i_queries_avoided']:.2f} | {row['stale_acceptance_rate']:.6f} | "
            f"{row['authorization_latency_mean_ms']:.4f} | "
            f"{row.get('bytes_per_interaction', float('nan')):.2f} |"
        )

    lines.extend([
        "",
        "## Six-RSU read-cache replication",
        "",
        f"- Read-only cache sync messages delivered to non-validator RSUs: {len(read_cache_sync)}.",
        f"- Modeled cache-sync traffic: {int(read_cache_sync['size_bytes'].sum())} bytes.",
        "- The read replica lets any RSU answer locally; only the four configured validators retain PBFT voting/write authority.",
    ])

    lines.extend([
        "",
        "## Audit conclusions",
        "",
        f"- Lowest modeled mean V2V authorization latency occurred at TTL={best_latency['ttl_seconds']:.1f}s, "
        f"but its stale-acceptance rate was {best_latency['stale_acceptance_rate']:.6f}.",
        f"- Relative to TTL={zero['ttl_seconds']:.1f}s, this is a modeled latency reduction of "
        f"{zero['authorization_latency_mean_ms'] - best_latency['authorization_latency_mean_ms']:.4f} ms per interaction on average.",
        "- A malicious-validator result is defensible only where `fault_activated`/`invalid_proposal_attempted` is recorded.",
        "- False-accusation and concealment are separate claims; one must not be generalized to the other.",
        "- Leave-one-source-out protects false-revocation safety at a measurable recall cost; it is an ablation, not a free improvement.",
        "- Timing remains simulated/parametric and must not be described as field latency.",
    ])
    (root / "EXTENSION_RESULTS_AUDIT.md").write_text("\n".join(lines) + "\n", encoding="utf-8")


if __name__ == "__main__":
    main()
