"""Build fixed opportunity and paired metric tables for seeds 1007-1010."""
import json
from pathlib import Path

import pandas as pd

from vpuft.opportunity_evaluation import opportunity_frame, opportunity_metrics

ROOT = Path(__file__).resolve().parents[1]
BASE = ROOT / "results/post_seminar_phase2/baseline_regenerated/traces/urban_roundabout"
OUT = ROOT / "results/post_seminar_phase6_final"
PILOT_ROOTS = [ROOT / "results/post_seminar_phase6/pilot", ROOT / "results/post_seminar_phase6_holdout/pilot", OUT / "pilot"]


def detected_ids(path):
    ids = set()
    with path.open(encoding="utf-8") as f:
        for line in f:
            row = json.loads(line)
            if row["source_kind"] == "rsu":
                ids.add(row["message_id"])
    return ids


def malicious_message_coverage(path, malicious_ids):
    observed = {}
    with path.open(encoding="utf-8") as f:
        for line in f:
            e = json.loads(line)
            if e["source_kind"] == "rsu" and e["message_id"] in malicious_ids:
                observed.setdefault(e["message_id"], {}).setdefault(e["detected_by"], set()).add(e["geographic_cell"])
    return len(observed), sum(len(v) >= 2 for v in observed.values()), sum(
        len(v) >= 2 and len(set().union(*v.values())) >= 2 for v in observed.values())


def candidate_cell(density, seed):
    for root in PILOT_ROOTS:
        cell = root / f"vehicles_{density}/seed_{seed}"
        if (cell / "C1_placement_B0_decisions.csv").is_file():
            return cell
    raise FileNotFoundError(f"Missing completed candidate cell density={density} seed={seed}")


def main():
    historical = pd.read_csv(ROOT / "results/post_seminar_phase2/ablation_metrics_by_seed.csv")
    phase_metrics = [pd.read_csv(ROOT / "results/post_seminar_phase6/pilot_metrics.csv"),
                     pd.read_csv(ROOT / "results/post_seminar_phase6_holdout/pilot_metrics.csv"),
                     pd.read_csv(OUT / "pilot_metrics.csv")]
    cand = pd.concat(phase_metrics, ignore_index=True)
    cand = cand[(cand.variant == "C1_placement_B0") & cand.seed.isin([1007,1008,1009,1010])]
    baseline = historical[(historical.variant == "B0_baseline") & historical.seed.isin([1007,1008,1009,1010])]
    all_baseline_decisions = pd.read_csv(ROOT / "results/post_seminar_phase2/ablation_decisions.csv.gz")
    rows, cases, false_positives = [], [], []
    for r in cand.itertuples():
        density, seed = int(r.density), int(r.seed)
        base = BASE / f"vehicles_{density}/seed_{seed}"
        candidate = candidate_cell(density, seed)
        messages = pd.read_csv(base / "generated_messages.csv")
        truth = messages.ground_truth_malicious.astype(str).str.lower().isin(("true","1"))
        malicious_ids = set(messages.loc[truth,"message_id"])
        baseline_dec = all_baseline_decisions[(all_baseline_decisions.vehicle_count==density)&(all_baseline_decisions.seed==seed)&(all_baseline_decisions.architecture=="B0_baseline")]
        cand_dec = pd.read_csv(candidate / "C1_placement_B0_decisions.csv")
        base_trace = base / "shared_detection_trace.jsonl"
        new_trace = candidate / "shared_detection_trace.jsonl"
        bopp=opportunity_frame(messages,baseline_dec,detected_ids(base_trace))
        copp=opportunity_frame(messages,cand_dec,detected_ids(new_trace))
        assert set(bopp.opportunity_id)==set(copp.opportunity_id)
        common=set(bopp.loc[bopp.observed_opportunity,"opportunity_id"]) & set(copp.loc[copp.observed_opportunity,"opportunity_id"])
        union=set(bopp.loc[bopp.observed_opportunity,"opportunity_id"]) | set(copp.loc[copp.observed_opportunity,"opportunity_id"])
        mb,bb,bc=malicious_message_coverage(base_trace,malicious_ids)
        mc,cb,cc=malicious_message_coverage(new_trace,malicious_ids)
        bm, cm = opportunity_metrics(bopp), opportunity_metrics(copp)
        old=baseline[(baseline.density==density)&(baseline.seed==seed)].iloc[0]
        def oprec(df,subset=None):
            x=df if subset is None else df[df.opportunity_id.isin(subset)]
            return opportunity_metrics(x)
        row={"density":density,"seed":seed,"ground_truth_opportunities":len(bopp),
             "baseline_terminal_opportunities":bm["terminal_opportunities"],"candidate_terminal_opportunities":cm["terminal_opportunities"],
             "baseline_opportunity_TP":bm["opportunity_TP"],"candidate_opportunity_TP":cm["opportunity_TP"],
             "baseline_opportunity_FN":bm["opportunity_FN"],"candidate_opportunity_FN":cm["opportunity_FN"],
             "baseline_fixed_protected_opportunities":bm["opportunity_TP"]+bm["terminal_opportunities"],
             "candidate_fixed_protected_opportunities":cm["opportunity_TP"]+cm["terminal_opportunities"],
             "baseline_observed_opportunities":int(bopp.observed_opportunity.sum()),
             "candidate_observed_opportunities":int(copp.observed_opportunity.sum()),
             "baseline_unobserved_opportunities":int((~bopp.observed_opportunity).sum()),
             "candidate_unobserved_opportunities":int((~copp.observed_opportunity).sum()),
             "baseline_opportunity_recall":bm["opportunity_recall"],
             "candidate_opportunity_recall":cm["opportunity_recall"],
             "baseline_fixed_protected_fraction":bm["fixed_universe_protected_fraction"],
             "candidate_fixed_protected_fraction":cm["fixed_universe_protected_fraction"],
             "common_observed_cases":len(common),"union_observed_cases":len(union),
             "baseline_common_protected":oprec(bopp,common)["fixed_universe_protected_fraction"],
             "candidate_common_protected":oprec(copp,common)["fixed_universe_protected_fraction"],
             "baseline_union_protected":oprec(bopp,union)["fixed_universe_protected_fraction"],
             "candidate_union_protected":oprec(copp,union)["fixed_universe_protected_fraction"],
             "baseline_TP":int(old.TP),"candidate_TP":int(r.TP),"baseline_FP":int(old.FP),"candidate_FP":int(r.FP),
             "baseline_TN":int(old.TN),"candidate_TN":int(r.TN),"baseline_FN":int(old.FN),"candidate_FN":int(r.FN),
             "baseline_recall":float(old.recall),"candidate_recall":float(r.recall),
             "baseline_frr":float(old.frr),"candidate_frr":float(r.frr),
             "baseline_precision":float(old.precision),"candidate_precision":float(r.precision),
             "baseline_f1":float(old.f1),"candidate_f1":float(r.f1),"baseline_mcc":float(old.mcc),"candidate_mcc":float(r.mcc),
             "baseline_cpu":float(old.cpu_time_seconds),"candidate_cpu":float(r.cpu_time_seconds),
             "baseline_e2e_ms":float(old.p95_e2e_ms),"candidate_e2e_ms":float(r.p95_e2e_ms),
             "baseline_messages_per_case":float(old.messages_per_case),"candidate_messages_per_case":float(r.messages_per_case),
             "baseline_pdr":float(old.pdr),"candidate_pdr":float(r.pdr),
             "baseline_ledger_delay_ms":float(old.p95_ledger_consistency_ms),"candidate_ledger_delay_ms":float(r.p95_ledger_consistency_ms),
             "baseline_vehicle_revocations":int(old.eventually_revoked_vehicles),"candidate_vehicle_revocations":int(r.eventually_revoked_vehicles),
             "baseline_malicious_messages_observed":mb,"candidate_malicious_messages_observed":mc,
             "baseline_multi_observer_messages":bb,"candidate_multi_observer_messages":cb,
             "baseline_multicell_messages":bc,"candidate_multicell_messages":cc}
        rows.append(row)
        def fp_ids(frame):
            benign = frame.ground_truth_malicious.astype(str).str.lower().isin(("false", "0"))
            revoked = frame.predicted_revoked.astype(str).str.lower().isin(("true", "1"))
            return set(frame.loc[benign & revoked, "case_id"].astype(str))
        bfp, cfp = fp_ids(baseline_dec), fp_ids(cand_dec)
        false_positives.append({"density": density, "seed": seed,
                                "baseline_fp_cases": "|".join(sorted(bfp)),
                                "candidate_fp_cases": "|".join(sorted(cfp)),
                                "introduced_fp_cases": "|".join(sorted(cfp - bfp)),
                                "removed_fp_cases": "|".join(sorted(bfp - cfp))})
        bo=set(bopp.loc[bopp.observed_opportunity,"opportunity_id"]);co=set(copp.loc[copp.observed_opportunity,"opportunity_id"])
        cases.append({"density":density,"seed":seed,"common_ids":"|".join(sorted(bo&co)),"union_ids":"|".join(sorted(bo|co)),
                      "baseline_only_ids":"|".join(sorted(bo-co)),"candidate_only_ids":"|".join(sorted(co-bo))})
    pd.DataFrame(rows).sort_values(["density","seed"]).to_csv(OUT/"final_paired_comparison.csv",index=False)
    pd.DataFrame(cases).sort_values(["density","seed"]).to_csv(OUT/"opportunity_case_unions.csv",index=False)
    pd.DataFrame(false_positives).sort_values(["density","seed"]).to_csv(OUT/"false_positive_case_audit.csv",index=False)
    print(pd.DataFrame(rows).groupby("density").mean(numeric_only=True)[["baseline_opportunity_recall","candidate_opportunity_recall","baseline_fixed_protected_fraction","candidate_fixed_protected_fraction","baseline_TP","candidate_TP","baseline_FP","candidate_FP","baseline_cpu","candidate_cpu","baseline_e2e_ms","candidate_e2e_ms","baseline_multi_observer_messages","candidate_multi_observer_messages"]].to_string())


if __name__=="__main__":main()
