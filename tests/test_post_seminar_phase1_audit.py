import json

import pandas as pd

from scripts.post_seminar_phase1_audit import build_report, classify_false_negatives


POLICIES = {
    "position_offset": {"required_roots": 2},
    "flood": {"required_roots": 2},
}


def _row(case_id, *, reason, roots, revoked=0, committed=0, arrived=4, attempted=4):
    return {
        "architecture": "distributed_density_honest",
        "vehicle_count": 20,
        "seed": 1001,
        "case_id": case_id,
        "vehicle_id": case_id.split("-")[-2],
        "attack_type": "position_offset",
        "ground_truth_malicious": 1,
        "predicted_revoked": revoked,
        "committed": committed,
        "reason": reason,
        "decision_margin": 0.4,
        "metadata_json": json.dumps({
            "independent_roots": roots,
            "arrived_attestations": arrived,
            "attempted_attestations": attempted,
            "expired_evidence": 0,
        }),
    }


def test_fn_audit_separates_at_risk_from_post_revocation_windows():
    rows = [
        _row("case-x-1001-veh1-w0000", reason="insufficient_independent_evidence_diversity", roots=1),
        _row("case-x-1001-veh1-w0001", reason="committed", roots=3, revoked=1, committed=1),
        _row("case-x-1001-veh1-w0002", reason="already_revoked_terminal_state", roots=0),
    ]
    audited = classify_false_negatives(pd.DataFrame(rows), POLICIES)
    report = build_report(audited)

    assert report["window_level_non_revoked_malicious_rows"] == 2
    assert report["post_revocation_terminal_windows"] == 1
    assert report["at_risk_false_negative_windows"] == 1
    assert report["cause_totals"] == {"insufficient_independent_roots": 1}
    assert report["vehicles_eventually_revoked"] == 1


def test_fn_audit_does_not_claim_source_or_zone_without_raw_evidence():
    rows = [
        _row(
            "case-x-1001-veh2-w0000",
            reason="insufficient_independent_evidence_diversity",
            roots=4,
        )
    ]
    audited = classify_false_negatives(pd.DataFrame(rows), POLICIES)
    assert audited.iloc[0]["fn_cause"] == "source_zone_or_modality_diversity_unresolved"
