from __future__ import annotations

import hashlib
import json
from pathlib import Path

import pandas as pd


ROOT = Path(__file__).resolve().parents[1]
EXPERIMENTS = ROOT / "results"
PILOT = Path(r"C:\Users\reemg\OneDrive\Desktop\master\6\v10-recall-70-feasibility\results\rsu8_pilot")
OUTPUT = EXPERIMENTS / "provenance_evidence_optimization_final"


def sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for block in iter(lambda: stream.read(1 << 20), b""):
            digest.update(block)
    return digest.hexdigest()


def main() -> None:
    initial = pd.read_csv(EXPERIMENTS / "provenance_evidence_optimization" / "offline_b0_b1_metrics.csv")
    corrected = pd.read_csv(EXPERIMENTS / "provenance_evidence_optimization_corrected" / "offline_b0_b1_metrics.csv")
    b1 = pd.read_csv(EXPERIMENTS / "provenance_evidence_b1_opportunities" / "offline_b0_b1_metrics.csv")
    # The initial exploratory pass read an incomplete C3 density-100/seed-2102
    # directory. Keep it in place but explicitly exclude and replace that row.
    initial = initial.loc[~((initial.variant == "C3_B0") & (initial.density == 100) & (initial.seed == 2102))]
    metrics = pd.concat([initial, corrected, b1], ignore_index=True)
    metrics = metrics.drop_duplicates(["variant", "density", "seed"], keep="last")
    expected = {f"{layout}_{variant}" for layout in ("C1", "C3") for variant in ("B0", "B1")}
    if set(metrics.variant.unique()) != expected:
        raise AssertionError(f"variant set mismatch: {metrics.variant.unique()}")
    counts = metrics.groupby("variant").size().to_dict()
    if any(value != 6 for value in counts.values()):
        raise AssertionError(f"expected six cells per variant: {counts}")
    corrected_c3 = metrics.loc[metrics.variant.eq("C3_B0") & metrics.density.eq(100) & metrics.seed.eq(2102)]
    if len(corrected_c3) != 1 or int(corrected_c3.iloc[0].case_count) != 575:
        raise AssertionError("C3 100/2102 must use the completed retry1 artifact (575 cases)")

    pilot = pd.read_csv(PILOT / "pilot_metrics.csv")
    b0 = pilot.loc[pilot.variant.isin(["C1_B0", "C3_B0"])].copy()
    b0 = b0.rename(columns={
        "variant": "variant", "attack_opportunities": "attack_opportunities",
        "observed_attack_opportunities": "observed_opportunities",
        "unobserved_attack_opportunities": "unobserved_opportunities",
        "successfully_detected_opportunities": "detected_opportunities",
        "opportunity_detection_recall_fixed_denominator": "opportunity_detection_recall",
        "terminal_opportunities": "terminal_opportunities",
        "protected_opportunities_including_terminal": "protected_opportunities",
        "protected_opportunity_fraction_fixed_denominator": "protected_opportunity_fraction",
    })
    b0["layout"] = b0.variant.str[:2]
    b0["algorithm"] = "B0"
    b0 = b0[["layout", "algorithm", "density", "seed", "attack_opportunities", "observed_opportunities",
             "unobserved_opportunities", "detected_opportunities", "opportunity_detection_recall",
             "terminal_opportunities", "protected_opportunities", "protected_opportunity_fraction"]]
    b1opp = pd.read_csv(EXPERIMENTS / "provenance_evidence_b1_opportunities" / "opportunity_metrics.csv")
    b1opp = b1opp.rename(columns={"variant": "algorithm"})
    opportunity = pd.concat([b0, b1opp[b0.columns]], ignore_index=True)
    opp_counts = opportunity.groupby(["layout", "algorithm"]).size().to_dict()
    if any(value != 6 for value in opp_counts.values()):
        raise AssertionError(f"opportunity cells incomplete: {opp_counts}")

    audit = pd.read_csv(EXPERIMENTS / "provenance_evidence_b1_case_audit" / "case_delta_v2" / "b1_case_differences.csv")
    transitions = pd.read_csv(EXPERIMENTS / "provenance_evidence_b1_case_audit" / "case_delta_v2" / "b1_case_transitions.csv")
    false_positives = pd.read_csv(EXPERIMENTS / "provenance_evidence_b1_case_audit" / "case_delta_v2" / "b1_new_false_positives.csv")
    profiles = pd.read_csv(EXPERIMENTS / "provenance_evidence_optimization" / "cprofile_stage_attribution.csv")
    paired_manifest_path = PILOT / "paired_manifests.json"
    paired_manifests = json.loads(paired_manifest_path.read_text(encoding="utf-8"))
    if len(paired_manifests) != 6 or not all(
        all(item.get(key) is True for key in ("mobility_identical", "emitted_messages_identical", "ground_truth_identical"))
        for item in paired_manifests
    ):
        raise AssertionError("paired input manifests do not certify identical mobility/messages/ground truth")
    if not audit.same_delivered_evidence_counts_and_nonterminal_arrival_times.all():
        raise AssertionError("B0/B1 evidence delivery/provenance checks failed")
    if len(false_positives):
        raise AssertionError(f"B1 introduced false-positive cases: {len(false_positives)}")

    if OUTPUT.exists():
        raise FileExistsError(f"Refusing to overwrite existing result directory: {OUTPUT}")
    OUTPUT.mkdir(parents=True)
    metric_columns = [
        "variant", "density", "seed", "case_count", "TP", "FP", "TN", "FN", "recall", "precision", "frr",
        "f1", "mcc", "eventual_malicious_vehicles", "eventually_revoked_vehicles", "time_to_first_revocation_p95_ms",
        "p95_e2e_ms", "p95_ledger_consistency_ms", "cpu_mean_s", "cpu_median_s", "cpu_min_s", "cpu_max_s",
        "cpu_stdev_s", "messages_per_case", "pdr", "trace_sha256",
    ]
    metrics[metric_columns].to_csv(OUTPUT / "paired_metrics_by_cell.csv", index=False)
    metrics.groupby(["variant", "density"], as_index=False).agg(
        **{column: (column, "mean") for column in metric_columns if column not in {"variant", "density", "seed", "trace_sha256"}},
        trace_sha256_count=("trace_sha256", "nunique"),
    ).to_csv(OUTPUT / "metrics_by_density.csv", index=False)
    opportunity.to_csv(OUTPUT / "opportunity_metrics_by_cell.csv", index=False)
    opportunity.groupby(["layout", "algorithm", "density"], as_index=False).agg(
        **{column: (column, "sum") for column in ("attack_opportunities", "observed_opportunities", "unobserved_opportunities",
            "detected_opportunities", "terminal_opportunities", "protected_opportunities")},
    ).to_csv(OUTPUT / "opportunity_counts_by_density.csv", index=False)
    audit.to_csv(OUTPUT / "b1_case_differences.csv", index=False)
    transitions.to_csv(OUTPUT / "b1_case_transitions.csv", index=False)
    profiles.to_csv(OUTPUT / "cprofile_stage_attribution.csv", index=False)
    manifest = {
        "base_commit": "96a7e903438c7316c25ed5e4b2e2cad433229224",
        "branch": "research/provenance-evidence-optimization",
        "analysis_type": "offline replay only; no SUMO traces regenerated",
        "variants": ["C1_B0", "C1_B1", "C3_B0", "C3_B1"],
        "paired_cells": 6,
        "completed_c3_100_seed_2102_source": "seed_2102_retry1",
        "paired_mobility_message_ground_truth_manifests": 6,
        "paired_manifests_sha256": sha256(paired_manifest_path),
        "input_config_sha256": sha256(ROOT.parent / "v10" / "results" / "post_seminar_phase2" / "phase2_effective_baseline_config.json"),
        "false_positive_cases_introduced_by_b1": 0,
        "summaries_only": True,
    }
    (OUTPUT / "analysis_manifest.json").write_text(json.dumps(manifest, indent=2) + "\n", encoding="utf-8")


if __name__ == "__main__":
    main()
