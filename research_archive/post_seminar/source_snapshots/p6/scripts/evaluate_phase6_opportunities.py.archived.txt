"""Evaluate fixed attack opportunities for the Phase 5 paired pilot."""
import json
from pathlib import Path

import pandas as pd

from vpuft.opportunity_evaluation import opportunity_frame, opportunity_metrics

ROOT = Path(__file__).resolve().parents[1]
BASE = ROOT / "results/post_seminar_phase2/baseline_regenerated/traces/urban_roundabout"
OUT = ROOT / "results/post_seminar_phase6"
P6 = ROOT / "results/post_seminar_phase6"


def observed_ids(path: Path) -> set[str]:
    ids = set()
    with path.open(encoding="utf-8") as source:
        for line in source:
            event = json.loads(line)
            if event["source_kind"] == "rsu":
                ids.add(event["message_id"])
    return ids


def main() -> None:
    OUT.mkdir(exist_ok=True)
    baseline_decisions = pd.read_csv(ROOT / "results/post_seminar_phase2/ablation_decisions.csv.gz")
    historical = pd.read_csv(ROOT / "results/post_seminar_phase2/ablation_metrics_by_seed.csv")
    phase6_metrics = pd.read_csv(P6 / "pilot_metrics.csv")
    frames, summaries = [], []
    for density in (20, 100):
        base = BASE / f"vehicles_{density}/seed_1007"
        new = P6 / f"pilot/vehicles_{density}/seed_1007"
        messages = pd.read_csv(base / "generated_messages.csv")
        malicious_vehicles = set(messages.loc[messages.ground_truth_malicious.astype(str).str.lower().isin(("true", "1")),
                                              "sender_vehicle_id"].astype(str))
        benign_vehicles = set(messages.sender_vehicle_id.astype(str)) - malicious_vehicles
        options = [
            ("C0_original_B0", base / "shared_detection_trace.jsonl",
             baseline_decisions[(baseline_decisions.vehicle_count == density) & (baseline_decisions.seed == 1007)
                                & (baseline_decisions.architecture == "B0_baseline")]),
            ("C1_placement_B0", new / "shared_detection_trace.jsonl",
             pd.read_csv(new / "C1_placement_B0_decisions.csv")),
            ("C2_placement_B1", new / "shared_detection_trace.jsonl",
             pd.read_csv(new / "C2_placement_B1_decisions.csv")),
        ]
        cell = []
        runtime_keys = []
        for name, trace, decisions in options:
            keys = decisions.case_id.astype(str).str.extract(r"-w(\d+)$")[0]
            runtime_keys.append(set(decisions.vehicle_id.astype(str) + "-w" + keys.fillna("-1").astype(str).str.zfill(4)))
            f = opportunity_frame(messages, decisions, observed_ids(trace))
            f["density"], f["seed"], f["variant"] = density, 1007, name
            row = {"density": density, "seed": 1007, "variant": name, **opportunity_metrics(f)}
            if name == "C0_original_B0":
                old = historical[(historical.density == density) & (historical.seed == 1007)
                                 & (historical.variant == "B0_baseline")].iloc[0]
            else:
                old = phase6_metrics[(phase6_metrics.density == density)
                                     & (phase6_metrics.variant == name)].iloc[0]
            row.update({"original_TP": int(old.TP), "original_FN": int(old.FN), "original_recall": float(old.recall),
                        "original_FP": int(old.FP), "original_TN": int(old.TN)})
            row.update({"original_precision": float(old.precision), "original_frr": float(old.frr),
                        "original_f1": float(old.f1), "original_mcc": float(old.mcc),
                        "cpu_time_seconds": float(old.cpu_time_seconds), "p95_e2e_ms": float(old.p95_e2e_ms),
                        "messages_per_case": float(old.messages_per_case), "pdr": float(old.pdr),
                        "ledger_consistency_delay_ms": float(old.p95_ledger_consistency_ms),
                        "eventual_vehicle_revocations": int(old.eventually_revoked_vehicles)})
            benign_false = decisions[(decisions.ground_truth_malicious == 0) & (decisions.committed == 1)
                                     & decisions.new_state.eq("revoked")
                                     & decisions.vehicle_id.astype(str).isin(benign_vehicles)]
            row["false_revoked_benign_vehicles"] = benign_false.vehicle_id.nunique()
            summaries.append(row)
            cell.append(f)
            frames.append(f)
        # Fixed opportunity universe is the union, which must equal each variant.
        universe = set(cell[0].opportunity_id)
        assert all(set(f.opportunity_id) == universe for f in cell)
        common_observed = set.intersection(*(set(f.loc[f.observed_opportunity, "opportunity_id"]) for f in cell))
        union_observed = set.union(*(set(f.loc[f.observed_opportunity, "opportunity_id"]) for f in cell))
        common_runtime = set.intersection(*runtime_keys) & universe
        union_runtime = set.union(*runtime_keys) & universe
        for row in summaries[-3:]:
            f = next(x for x in cell if x.variant.iloc[0] == row["variant"])
            common = f[f.opportunity_id.isin(common_observed)]
            union = f[f.opportunity_id.isin(union_observed)]
            row["common_observed_opportunities"] = len(common_observed)
            row["union_observed_opportunities"] = len(union_observed)
            row["common_case_recall"] = opportunity_metrics(common)["opportunity_recall"]
            row["union_case_recall"] = opportunity_metrics(union)["opportunity_recall"]
            row["common_case_protected_fraction"] = opportunity_metrics(common)["fixed_universe_protected_fraction"]
            row["union_case_protected_fraction"] = opportunity_metrics(union)["fixed_universe_protected_fraction"]
            row["common_runtime_attack_cases"] = len(common_runtime)
            row["union_runtime_attack_cases"] = len(union_runtime)
            row["common_runtime_protected_fraction"] = opportunity_metrics(
                f[f.opportunity_id.isin(common_runtime)])["fixed_universe_protected_fraction"]
            row["union_runtime_protected_fraction"] = opportunity_metrics(
                f[f.opportunity_id.isin(union_runtime)])["fixed_universe_protected_fraction"]
    pd.concat(frames, ignore_index=True).to_csv(OUT / "opportunity_cases_corrected.csv", index=False)
    pd.DataFrame(summaries).to_csv(OUT / "opportunity_pilot_comparison_corrected.csv", index=False)
    print(pd.DataFrame(summaries).to_string(index=False))


if __name__ == "__main__":
    main()
