"""Audit the paired 8-RSU pilot and apply the frozen security/resource gate."""
from __future__ import annotations

import json
from pathlib import Path

import pandas as pd

from run_phase6_eight_rsu_placement import OUT, DENSITIES, HELDOUT_SEEDS


def bool_col(values: pd.Series) -> pd.Series:
    return values.astype(str).str.lower().isin(("true", "1"))


def trace_cell(layout: str, density: int, seed: int) -> Path:
    parent = OUT / "pilot" / layout / f"vehicles_{density}"
    primary = parent / f"seed_{seed}" / "shared_detection_trace.jsonl"
    if primary.is_file() and (primary.parent / "scenario_manifest.json").is_file():
        return primary
    retries = sorted(path for path in parent.glob(f"seed_{seed}_retry*/shared_detection_trace.jsonl")
                     if (path.parent / "scenario_manifest.json").is_file())
    if retries:
        return retries[-1]
    raise FileNotFoundError(f"Missing completed trace for {layout}, density={density}, seed={seed}")


def evidence_inventory(layout: str, density: int, seed: int, case_ids: set[str]) -> dict[str, dict[str, set[str]]]:
    inventory = {case: {"supporting_sources": set(), "supporting_roots": set(), "supporting_cells": set(),
                        "opposing_sources": set(), "opposing_roots": set(), "opposing_cells": set(),
                        "neutral_sources": set(), "neutral_roots": set(), "neutral_cells": set()}
                 for case in case_ids}
    with trace_cell(layout, density, seed).open(encoding="utf-8") as stream:
        for line in stream:
            event = json.loads(line)
            case_id = str(event.get("case_id", ""))
            if case_id not in inventory or event.get("source_kind") != "rsu":
                continue
            direction = int(event.get("direction", 0))
            prefix = "supporting" if direction == 1 else "opposing" if direction == -1 else "neutral"
            inventory[case_id][f"{prefix}_sources"].add(str(event["detected_by"]))
            inventory[case_id][f"{prefix}_roots"].add(str(event["observation_root_id"]))
            inventory[case_id][f"{prefix}_cells"].add(str(event["geographic_cell"]))
    return inventory


def qualification_inventory(frame: pd.DataFrame) -> dict[str, int]:
    columns = {"roots": 0, "sources": 0, "zones": 0,
               "roots_meeting_requirement": 0, "sources_meeting_requirement": 0,
               "zones_meeting_requirement": 0, "active_malicious_cases": 0}
    active = frame[bool_col(frame.ground_truth_malicious)]
    active = active[~active.reason.eq("already_revoked_terminal_state")]
    columns["active_malicious_cases"] = len(active)
    for raw in active.metadata_json:
        metadata = json.loads(raw)
        for kind, key, required in (("roots", "independent_roots", "required_roots"),
                                    ("sources", "distinct_sources", "required_sources"),
                                    ("zones", "distinct_zones", "required_zones")):
            value = int(metadata.get(key, 0) or 0)
            need = int(metadata.get(required, 1) or 1)
            columns[kind] += value
            columns[f"{kind}_meeting_requirement"] += int(value >= need)
    return columns


def run() -> dict:
    gate = json.loads((OUT / "acceptance_gate_preregistered.json").read_text(encoding="utf-8"))
    cells = pd.read_csv(OUT / "pilot_metrics.csv")
    if len(cells) != 2 * len(DENSITIES) * len(HELDOUT_SEEDS):
        raise AssertionError("Expected exactly two architecture rows per paired held-out cell")
    key = ["density", "seed"]
    columns = ["recall", "precision", "frr", "f1", "mcc", "TP", "FP", "TN", "FN",
               "opportunity_detection_recall_fixed_denominator", "protected_opportunity_fraction_fixed_denominator",
               "observed_attack_opportunities", "malicious_messages_observed", "multi_observer_malicious_messages",
               "multi_cell_malicious_messages", "malicious_cases_with_two_independent_roots",
               "malicious_cases_with_two_supporting_sources", "malicious_cases_with_two_supporting_zones",
               "cpu_time_seconds", "p95_e2e_ms", "messages_per_case", "pdr", "p95_ledger_consistency_ms"]
    wide = cells.pivot(index=key, columns="variant", values=columns).reset_index()
    wide.columns = ["_".join(str(x) for x in col if x != "") if isinstance(col, tuple) else col for col in wide.columns]
    rename = {}
    for col in list(wide.columns):
        if col.endswith("_C1_B0"):
            rename[col] = col.replace("_C1_B0", "_C1")
        elif col.endswith("_C3_B0"):
            rename[col] = col.replace("_C3_B0", "_C3")
    wide = wide.rename(columns=rename)
    for metric in columns:
        left, right = f"{metric}_C1", f"{metric}_C3"
        if left not in wide or right not in wide:
            # pivot naming depends on pandas MultiIndex; normalize alternative ordering.
            alt_left, alt_right = f"C1_B0_{metric}", f"C3_B0_{metric}"
            if alt_left in wide and alt_right in wide:
                wide[left], wide[right] = wide[alt_left], wide[alt_right]
            else:
                raise KeyError(f"Missing paired metric columns for {metric}: {list(wide.columns)}")
        wide[f"delta_{metric}"] = wide[right] - wide[left]
    decisions = {}
    fp_sets = {}
    for layout in ("C1", "C3"):
        frame = pd.read_csv(OUT / f"pilot_{layout}_decisions.csv.gz")
        decisions[layout] = frame
        benign = ~bool_col(frame.ground_truth_malicious)
        revoked = bool_col(frame.predicted_revoked)
        fp_sets[layout] = set(zip(frame.loc[benign & revoked, "vehicle_count"].astype(int),
                                  frame.loc[benign & revoked, "seed"].astype(int),
                                  frame.loc[benign & revoked, "case_id"].astype(str),
                                  frame.loc[benign & revoked, "vehicle_id"].astype(str)))
    introduced = sorted(fp_sets["C3"] - fp_sets["C1"])
    removed = sorted(fp_sets["C1"] - fp_sets["C3"])
    fp_audit = pd.DataFrame([
        {"density": density, "seed": seed, "case_id": case_id, "vehicle_id": vehicle,
         "status": "introduced_by_C3"}
        for density, seed, case_id, vehicle in introduced
    ] + [
        {"density": density, "seed": seed, "case_id": case_id, "vehicle_id": vehicle,
         "status": "removed_by_C3"}
        for density, seed, case_id, vehicle in removed
    ], columns=["density", "seed", "case_id", "vehicle_id", "status"])
    fp_audit.to_csv(OUT / "false_positive_case_audit.csv", index=False)
    matched = decisions["C1"].merge(decisions["C3"], on=["vehicle_count", "seed", "case_id"],
                                     suffixes=("_C1", "_C3"), validate="one_to_one")
    label_disagreements = int((matched.ground_truth_malicious_C1 != matched.ground_truth_malicious_C3).sum())
    c1_terminal = matched.reason_C1.eq("already_revoked_terminal_state")
    c3_terminal = matched.reason_C3.eq("already_revoked_terminal_state")
    recovered_mask = (bool_col(matched.ground_truth_malicious_C1)
                      & bool_col(matched.ground_truth_malicious_C3)
                      & ~bool_col(matched.predicted_revoked_C1) & ~c1_terminal
                      & bool_col(matched.predicted_revoked_C3) & ~c3_terminal)
    recovered = matched.loc[recovered_mask].copy()
    c1_fn_mask = (bool_col(matched.ground_truth_malicious_C1)
                  & ~bool_col(matched.predicted_revoked_C1) & ~c1_terminal)
    c3_terminalized_fn = int((c1_fn_mask & c3_terminal).sum())
    c3_still_fn = int((c1_fn_mask & ~bool_col(matched.predicted_revoked_C3) & ~c3_terminal).sum())
    if label_disagreements:
        raise AssertionError(f"Paired state-aware case ground truth differs for {label_disagreements} case IDs")
    recovered_rows = []
    for (density, seed), group in recovered.groupby(["vehicle_count", "seed"]):
        case_ids = set(group.case_id.astype(str))
        inventories = {layout: evidence_inventory(layout, int(density), int(seed), case_ids) for layout in ("C1", "C3")}
        for row in group.itertuples(index=False):
            c1_meta = json.loads(row.metadata_json_C1)
            c3_meta = json.loads(row.metadata_json_C3)
            out = {"density": int(density), "seed": int(seed), "case_id": row.case_id,
                   "vehicle_id": row.vehicle_id_C1, "attack_type": row.attack_type_C1,
                   "C1_failure_reason": row.reason_C1, "C3_final_reason": row.reason_C3,
                   "C1_independent_roots": c1_meta.get("independent_roots"),
                   "C3_independent_roots": c3_meta.get("independent_roots"),
                   "C3_required_roots": c3_meta.get("required_roots"),
                   "C1_distinct_supporting_sources": c1_meta.get("distinct_sources"),
                   "C3_distinct_supporting_sources": c3_meta.get("distinct_sources"),
                   "C3_required_sources": c3_meta.get("required_sources"),
                   "C1_distinct_supporting_zones": c1_meta.get("distinct_zones"),
                   "C3_distinct_supporting_zones": c3_meta.get("distinct_zones"),
                   "C3_required_zones": c3_meta.get("required_zones"),
                   "C3_supporting_report_sources": "|".join(sorted(inventories["C3"][row.case_id]["supporting_sources"])),
                   "C3_supporting_report_roots": "|".join(sorted(inventories["C3"][row.case_id]["supporting_roots"])),
                   "C3_supporting_report_cells": "|".join(sorted(inventories["C3"][row.case_id]["supporting_cells"])),
                   "C3_opposing_report_sources": "|".join(sorted(inventories["C3"][row.case_id]["opposing_sources"])),
                   "C3_opposing_report_roots": "|".join(sorted(inventories["C3"][row.case_id]["opposing_roots"])),
                   "C3_opposing_report_cells": "|".join(sorted(inventories["C3"][row.case_id]["opposing_cells"])),
                   "C3_neutral_report_sources": "|".join(sorted(inventories["C3"][row.case_id]["neutral_sources"])),
                   "C3_neutral_report_roots": "|".join(sorted(inventories["C3"][row.case_id]["neutral_roots"])),
                   "C3_neutral_report_cells": "|".join(sorted(inventories["C3"][row.case_id]["neutral_cells"])),
                   "C3_root_requirement_satisfied": int(c3_meta.get("independent_roots", 0) >= c3_meta.get("required_roots", 1)),
                   "C3_source_requirement_satisfied": int(c3_meta.get("distinct_sources", 0) >= c3_meta.get("required_sources", 1)),
                   "C3_zone_requirement_satisfied": int(c3_meta.get("distinct_zones", 0) >= c3_meta.get("required_zones", 1)),
                   "C3_excluded_duplicate_roots": c3_meta.get("excluded_duplicate_roots", 0),
                   "C3_margin": c3_meta.get("qualification_margin"),
                   "C3_required_margin": c3_meta.get("required_margin")}
            recovered_rows.append(out)
    recovery_audit = pd.DataFrame(recovered_rows)
    recovery_audit.to_csv(OUT / "recovered_fn_case_audit.csv", index=False)
    active_common = matched[
        ~matched.reason_C1.eq("already_revoked_terminal_state")
        & ~matched.reason_C3.eq("already_revoked_terminal_state")
        & bool_col(matched.ground_truth_malicious_C1)
        & bool_col(matched.ground_truth_malicious_C3)
    ]
    active_rows = []
    for (density, seed), group in active_common.groupby(["vehicle_count", "seed"]):
        for layout in ("C1", "C3"):
            selected = group[["case_id", f"metadata_json_{layout}", f"ground_truth_malicious_{layout}", f"reason_{layout}"]].copy()
            selected.columns = ["case_id", "metadata_json", "ground_truth_malicious", "reason"]
            counts = qualification_inventory(selected)
            active_rows.append({"density": int(density), "seed": int(seed), "layout": layout, **counts})
    active_table = pd.DataFrame(active_rows)
    active_table.to_csv(OUT / "active_common_evidence_independence.csv", index=False)
    active_wide = active_table.pivot(index=["density", "seed"], columns="layout",
                                     values=["roots", "sources", "zones", "roots_meeting_requirement",
                                             "sources_meeting_requirement", "zones_meeting_requirement"])
    active_delta = {}
    for metric in ("roots", "sources", "zones", "roots_meeting_requirement",
                   "sources_meeting_requirement", "zones_meeting_requirement"):
        active_delta[metric] = int(active_wide[(metric, "C3")].sum() - active_wide[(metric, "C1")].sum())
    independence_gain = (
        active_delta["roots"] > 0
        and active_delta["roots_meeting_requirement"] >= 0
        and active_delta["sources"] > 0
        and active_delta["sources_meeting_requirement"] > 0
        and active_delta["zones"] > 0
        and active_delta["zones_meeting_requirement"] > 0
    )
    opp = pd.read_csv(OUT / "pilot_opportunity_comparison.csv")
    wide = wide.merge(opp, on=key, validate="one_to_one")
    # Verify observed-opportunity denominator did not decline in any paired cell.
    obs_nonloss = bool((wide.delta_observed_attack_opportunities >= 0).all())
    frr_nonincrease = bool((wide.delta_frr <= 0).all())
    precision_floor = bool((wide.delta_precision >= -float(gate["security_acceptance"]["candidate_precision_drop_max_absolute"])).all())
    protected_gains = wide.delta_protected_opportunity_fraction_fixed_denominator
    no_density_regression = bool((wide.groupby("density")["delta_protected_opportunity_fraction_fixed_denominator"].mean() >= 0).all())
    enough_cells = int((protected_gains > 0).sum()) >= int(gate["security_acceptance"]["minimum_cells_with_positive_fixed_protected_fraction_gain"])
    aggregate_gain = float(protected_gains.mean())
    gain_threshold = aggregate_gain >= float(gate["security_acceptance"]["fixed_universe_protected_fraction_gain_aggregate_min_absolute"])
    roots_gain = active_delta["roots"] > 0 and active_delta["roots_meeting_requirement"] >= 0
    sources_gain = active_delta["sources"] > 0 and active_delta["sources_meeting_requirement"] > 0
    zones_gain = active_delta["zones"] > 0 and active_delta["zones_meeting_requirement"] > 0
    independent_gain = roots_gain and sources_gain and zones_gain
    security = {
        "no_introduced_false_positive_case": len(introduced) == 0,
        "candidate_frr_not_above_c1_in_any_pair": frr_nonincrease,
        "precision_drop_within_preregistered_limit": precision_floor,
        "observed_attack_opportunities_not_reduced_in_any_pair": obs_nonloss,
        "fixed_protected_fraction_gain_at_least_5pp": gain_threshold,
        "no_density_mean_protected_fraction_regression": no_density_regression,
        "at_least_four_of_six_cells_improve": enough_cells,
        "eligible_independent_roots_sources_and_zones_increase_on_common_active_cases": independent_gain,
    }
    max_overheads = {}
    for metric, cap in (("cpu_time_seconds", "cpu_overhead_max_fraction"),
                        ("messages_per_case", "messages_per_case_overhead_max_fraction"),
                        ("p95_e2e_ms", "p95_e2e_overhead_max_fraction")):
        positive = wide[f"{metric}_C1"].replace(0, pd.NA)
        delta = wide[f"delta_{metric}"] / positive
        value = float(delta.mean())
        max_overheads[metric] = value
    resource = {
        "mean_cpu_overhead_within_cap": max_overheads["cpu_time_seconds"] <= gate["resource_review_caps"]["cpu_overhead_max_fraction"],
        "mean_messages_per_case_overhead_within_cap": max_overheads["messages_per_case"] <= gate["resource_review_caps"]["messages_per_case_overhead_max_fraction"],
        "mean_p95_e2e_overhead_within_cap": max_overheads["p95_e2e_ms"] <= gate["resource_review_caps"]["p95_e2e_overhead_max_fraction"],
    }
    overall = {
        "paired_cells": len(wide), "introduced_false_positive_cases": len(introduced),
        "removed_false_positive_cases": len(removed),
        "state_aware_FN_cases_recovered_as_TP": len(recovery_audit),
        "C1_nonterminal_FN_case_transition_counts": {
            "started_as_C1_FN": int(c1_fn_mask.sum()),
            "became_C3_TP": len(recovery_audit),
            "became_C3_terminal_after_earlier_revocation": c3_terminalized_fn,
            "remained_C3_nonterminal_FN": c3_still_fn,
        },
        "paired_case_ground_truth_disagreements": label_disagreements,
        "recovered_cases_meeting_C3_root_source_zone_requirements": {
            "roots": int(recovery_audit.C3_root_requirement_satisfied.sum()) if len(recovery_audit) else 0,
            "sources": int(recovery_audit.C3_source_requirement_satisfied.sum()) if len(recovery_audit) else 0,
            "zones": int(recovery_audit.C3_zone_requirement_satisfied.sum()) if len(recovery_audit) else 0,
        },
        "common_active_evidence_differences_C3_minus_C1": active_delta,
        "mean_fixed_protected_fraction_gain": aggregate_gain,
        "cells_improved_unchanged_worsened": {
            "improved": int((protected_gains > 0).sum()), "unchanged": int((protected_gains == 0).sum()),
            "worsened": int((protected_gains < 0).sum()),
        },
        "mean_resource_overheads": max_overheads,
        "security_gate_pass": all(security.values()),
        "resource_caps_pass": all(resource.values()),
        "decision": "GO_TO_LARGER_HELDOUT_ONLY" if all(security.values()) and all(resource.values()) else "NO_GO_REJECT_OR_REDESIGN",
    }
    summary = {"security_gates": security, "resource_gates": resource, "summary": overall}
    (OUT / "pilot_gate_result.json").write_text(json.dumps(summary, indent=2), encoding="utf-8")
    wide.to_csv(OUT / "pilot_paired_comparison.csv", index=False)
    density_summary = wide.groupby("density").agg({
        "delta_recall": ["mean", "median"], "delta_opportunity_detection_recall_fixed_denominator": ["mean", "median"],
        "delta_protected_opportunity_fraction_fixed_denominator": ["mean", "median"],
        "delta_TP": ["mean", "median"], "delta_FP": ["mean", "median"], "delta_frr": ["mean", "median"],
        "delta_cpu_time_seconds": ["mean", "median"], "delta_p95_e2e_ms": ["mean", "median"],
        "delta_messages_per_case": ["mean", "median"], "delta_malicious_cases_with_two_independent_roots": ["mean", "sum"],
    })
    density_summary.to_csv(OUT / "pilot_density_summary.csv")
    print(json.dumps(summary, indent=2))
    print(density_summary.to_string())
    return summary


if __name__ == "__main__":
    run()
