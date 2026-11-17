import pandas as pd
import pytest

from scripts.analyze_final_scenario5_ablation import pooled_confusion, validate_complete
from scripts.run_final_scenario5_ablation import _persist_run_rows, _resume_reconciliation_hashes


def test_pooled_confusion_uses_summed_counts_and_retains_terminal_exclusions():
    frame = pd.DataFrame([
        {"TP": 2, "FP": 1, "TN": 8, "FN": 3, "excluded_post_revocation_cases": 4},
        {"TP": 1, "FP": 0, "TN": 7, "FN": 2, "excluded_post_revocation_cases": 2},
    ])
    result = pooled_confusion(frame)
    assert result["TP"] == 3
    assert result["FP"] == 1
    assert result["TN"] == 15
    assert result["FN"] == 5
    assert result["evaluated_windows"] == 24
    assert result["excluded_post_revocation_windows"] == 6
    assert result["pooled_state_aware_recall"] == pytest.approx(3 / 8)


def test_completion_validation_rejects_a_changed_fixed_opportunity_denominator():
    rows = []
    decision_rows = []
    opportunity_rows = []
    for variant in ("baseline", "A_report_mass", "C_no_diversity_gates"):
        for density in (20, 100):
            for seed in (7003, 7004, 7005, 7006):
                for architecture in ("C100", "Distributed"):
                    rows.append({"variant_id": variant, "density": density, "seed": seed, "architecture": architecture})
                    decision_rows.append({"variant_id": variant, "density": density, "seed": seed, "architecture": architecture, "case_id": "case-1"})
                    opportunity_rows.append({
                        "variant_id": variant, "density": density, "seed": seed, "architecture": architecture,
                        "attack_message_opportunities": 10, "observed_attack_messages": 8, "unobserved_attack_messages": 2,
                    })
    opportunities = pd.DataFrame(opportunity_rows)
    opportunities.loc[opportunities.index[-1], "attack_message_opportunities"] = 11
    with pytest.raises(ValueError, match="Fixed denominator"):
        validate_complete(pd.DataFrame(rows), pd.DataFrame(decision_rows), opportunities)


def test_completion_validation_rejects_case_population_drift():
    rows = []
    decision_rows = []
    opportunity_rows = []
    for variant in ("baseline", "A_report_mass", "C_no_diversity_gates"):
        for density in (20, 100):
            for seed in (7003, 7004, 7005, 7006):
                for architecture in ("C100", "Distributed"):
                    rows.append({"variant_id": variant, "density": density, "seed": seed, "architecture": architecture})
                    case = "case-candidate" if variant == "C_no_diversity_gates" else "case-1"
                    decision_rows.append({"variant_id": variant, "density": density, "seed": seed, "architecture": architecture, "case_id": case})
                    opportunity_rows.append({
                        "variant_id": variant, "density": density, "seed": seed, "architecture": architecture,
                        "attack_message_opportunities": 10, "observed_attack_messages": 8, "unobserved_attack_messages": 2,
                    })
    with pytest.raises(ValueError, match="Case population mismatch"):
        validate_complete(pd.DataFrame(rows), pd.DataFrame(decision_rows), pd.DataFrame(opportunity_rows))


def test_resume_reconciliation_marks_unrecorded_original_hash_as_unknown():
    path = "source/RUN_CONTEXT.json"
    result = _resume_reconciliation_hashes(
        {path},
        stored_hashes={},
        current_hashes={path: "current-hash"},
    )
    assert result["original_source_hashes"][path] is None
    assert result["current_source_hashes"][path] == "current-hash"


def test_resume_persists_metadata_even_when_no_cells_need_execution(tmp_path):
    rows = {
        "metrics": [{"variant_id": "baseline", "effective_config_sha256": "cfg"}],
        "decisions": [{"case_id": "case-1"}],
        "opportunities": [{"attack_message_opportunities": 10}],
        "manifest": [{"variant_id": "baseline", "runner_script_sha256": "runner"}],
    }
    _persist_run_rows(tmp_path, rows)
    assert pd.read_csv(tmp_path / "ABLATION_METRICS_BY_SEED.csv").loc[0, "effective_config_sha256"] == "cfg"
    assert pd.read_csv(tmp_path / "ABLATION_RUN_MANIFEST.csv").loc[0, "runner_script_sha256"] == "runner"
