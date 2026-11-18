"""Audit the completed Phase 4 files without replaying diagnostic cells."""
from __future__ import annotations

import csv
import hashlib
import json
import math
from collections import Counter, defaultdict
from pathlib import Path

import pandas as pd


ROOT = Path(__file__).resolve().parents[1]
BASE = ROOT / "results/post_seminar_phase4/baseline_diagnostics"
RSUS = json.loads((ROOT / "sumo/urban_roundabout/rsus.json").read_text())
RANGE_M = 450.0


def digest(path: Path) -> str:
    h = hashlib.sha256()
    with path.open("rb") as source:
        for block in iter(lambda: source.read(1024 * 1024), b""):
            h.update(block)
    return h.hexdigest()


def main() -> None:
    fn = pd.read_csv(BASE / "fn_cases_all_50.csv").fillna({"observing_rsus": ""})
    evidence = pd.read_csv(BASE / "fn_evidence_assignments_all_50.csv.gz")
    manifest = pd.read_csv(BASE / "trace_manifest_verified.csv")
    metrics = pd.read_csv(BASE / "baseline_metrics_by_cell.csv")
    assert len(fn) == 961 and len(manifest) == 50 and len(metrics) == 50
    assert not fn.duplicated(["density", "seed", "case_id"]).any()
    assert fn.groupby(["density", "seed"]).size().eq(
        metrics.set_index(["density", "seed"]).diagnosed_at_risk_malicious_fns
    ).all()
    for row in manifest.itertuples():
        trace = ROOT / row.trace_path
        checkpoint = json.loads((BASE / f"density_{row.density}_seed_{row.seed}" / "cell_complete.json").read_text())
        assert digest(trace) == row.sha256 == checkpoint["trace_sha256"]
        assert trace.stat().st_size == row.bytes == checkpoint["trace_bytes"]
        assert checkpoint["diagnosed_at_risk_malicious_fns"] == int(metrics.loc[
            (metrics.density == row.density) & (metrics.seed == row.seed), "FN"
        ].iloc[0])

    # The first three classes are counterfactual evaluations of the same fixed
    # signed reports; they do not infer observations from absent trace rows.
    def class_of(row) -> str:
        if row.b8_observer_match_delivered_qualified_diagnostic_only:
            return "algorithmic_representative_selection"
        if row.b8_observer_match_pretransport_qualified_diagnostic_only:
            return "routing"
        if row.physical_policy_shortfall_even_with_all_current_reports:
            return "current_eligible_evidence_shortfall"
        return "margin_or_contradiction"

    fn["evidence_class"] = fn.apply(class_of, axis=1)
    keys = ["density", "seed", "case_id"]
    per_case = evidence.groupby(keys + ["stage"]).agg(
        report_count=("attestation_id", "nunique"),
        source_count=("source_id", "nunique"),
        root_count=("observation_root_id", "nunique"),
    ).reset_index()
    stage_counts = per_case.pivot(index=keys, columns="stage", values="report_count").fillna(0)
    assert len(stage_counts) == 961
    assert (fn.not_delivered == 0).all()
    assert (fn.raw_detection_reports_in_trace_case == fn.available_before_transport).all()
    assert (fn.available_before_transport == fn.delivered).all()

    capabilities = {}
    detection_directions = {}
    emission_details = {}
    for row in manifest.itertuples():
        subset = fn[(fn.density == row.density) & (fn.seed == row.seed)]
        wanted = set(subset.case_id)
        case_messages = defaultdict(set)
        directions = defaultdict(lambda: defaultdict(Counter))
        with (ROOT / row.trace_path).open(encoding="utf-8") as source:
            for line in source:
                event = json.loads(line)
                cid = event["case_id"]
                if cid not in wanted or event["source_kind"] != "rsu":
                    continue
                case_messages[cid].add(event["message_id"])
                directions[cid][event["detected_by"]][str(event["direction"])] += 1
        message_to_case = {mid: cid for cid, mids in case_messages.items() for mid in mids}
        capable = defaultdict(set)
        emitted = defaultdict(list)
        messages_path = (ROOT / row.trace_path).parent / "generated_messages.csv"
        with messages_path.open(newline="", encoding="utf-8") as source:
            for message in csv.DictReader(source):
                cid = message_to_case.get(message["message_id"])
                if cid is None:
                    continue
                emitted[cid].append((message["message_id"], message["original_message_id"],
                                     message["observation_root_id"], message["message_type"]))
                x, y = float(message["true_x"]), float(message["true_y"])
                for rsu in RSUS:
                    if math.hypot(x - (rsu["x"] + 500), y - (rsu["y"] + 500)) <= RANGE_M:
                        capable[cid].add(rsu["id"])
        for cid in wanted:
            key = (row.density, row.seed, cid)
            capabilities[key] = capable[cid]
            detection_directions[key] = directions[cid]
            emission_details[key] = emitted[cid]

    fn["physically_in_range_rsus"] = fn.apply(
        lambda r: "|".join(sorted(capabilities[(r.density, r.seed, r.case_id)])), axis=1
    )
    fn["in_range_rsu_count"] = fn.physically_in_range_rsus.map(lambda s: len(s.split("|")) if s else 0)
    fn["detected_rsu_count"] = fn.observing_rsus.map(lambda s: len(s.split("|")) if s else 0)
    fn["detected_directions_json"] = fn.apply(
        lambda r: json.dumps(detection_directions[(r.density, r.seed, r.case_id)], sort_keys=True), axis=1
    )
    fn["emitted_message_ids"] = fn.apply(
        lambda r: "|".join(sorted(m[0] for m in emission_details[(r.density, r.seed, r.case_id)])), axis=1
    )
    fn["emitted_original_root_count"] = fn.apply(
        lambda r: len({m[2] for m in emission_details[(r.density, r.seed, r.case_id)]}), axis=1
    )
    fn["emitted_cam_count"] = fn.apply(
        lambda r: sum(m[3] == "CAM" for m in emission_details[(r.density, r.seed, r.case_id)]), axis=1
    )
    fn["emitted_denm_count"] = fn.apply(
        lambda r: sum(m[3] == "DENM" for m in emission_details[(r.density, r.seed, r.case_id)]), axis=1
    )
    assert fn.eval("emitted_cam_count + emitted_denm_count > 0").all()
    fn["in_range_but_not_detected_rsus"] = fn.apply(
        lambda r: "|".join(sorted(capabilities[(r.density, r.seed, r.case_id)] - set(r.observing_rsus.split("|")))), axis=1
    )
    assert fn.in_range_but_not_detected_rsus.eq("").all()
    assert fn.in_range_rsu_count.eq(fn.detected_rsu_count).all()
    assert evidence[["validity", "fresh"]].eq(1).all().all()
    fn["operational_category"] = fn.apply(
        lambda r: "algorithmic_representative_selection"
        if r.evidence_class == "algorithmic_representative_selection" else
        "margin_or_contradiction" if r.evidence_class == "margin_or_contradiction" else
        "requires_additional_sensing_for_current_window" if r.detected_rsu_count == 1 else
        "multiple_observers_but_no_second_eligible_support",
        axis=1,
    )
    assert fn.operational_category.value_counts().sum() == len(fn)
    fn.to_csv(BASE / "fn_lifecycle_classification.csv", index=False)
    fn.groupby(["operational_category", "density", "runtime_attack_type"]).size().rename("cases").reset_index().to_csv(
        BASE / "fn_exhaustive_categories_by_density_attack.csv", index=False
    )
    summary = {
        "cases": len(fn),
        "classes": fn.evidence_class.value_counts().to_dict(),
        "operational_categories": fn.operational_category.value_counts().to_dict(),
        "detected_rsu_counts": fn.detected_rsu_count.value_counts().sort_index().to_dict(),
        "in_range_rsu_counts": fn.in_range_rsu_count.value_counts().sort_index().to_dict(),
        "current_shortfall_with_multiple_detected_rsus": int(((fn.evidence_class == "current_eligible_evidence_shortfall") & (fn.detected_rsu_count >= 2)).sum()),
        "current_shortfall_with_multiple_in_range_rsus": int(((fn.evidence_class == "current_eligible_evidence_shortfall") & (fn.in_range_rsu_count >= 2)).sum()),
        "metrics_totals": metrics[["TP", "FP", "TN", "FN"]].sum().to_dict(),
        "all_50_trace_hashes_checkpoints_verified": True,
        "stage_report_counts": {str(k): int(v) for k, v in evidence.groupby("stage").size().items()},
    }
    (BASE / "phase4_existing_evidence_summary.json").write_text(json.dumps(summary, indent=2))
    print(json.dumps(summary, indent=2))


if __name__ == "__main__":
    main()
