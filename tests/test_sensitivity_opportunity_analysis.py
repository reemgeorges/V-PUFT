from __future__ import annotations

import math
import sys
from pathlib import Path

import pandas as pd
import pytest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from scripts.sensitivity_opportunities import (
    build_base_emission_times,
    emission_time_for_message,
    evaluate_attack_opportunities,
    first_committed_revocations,
    opportunity_case_id,
)
from scripts.run_final_scenario5_sensitivity_replication import (
    completed_cell_index,
    validate_cell_checkpoint,
)
from scripts.sensitivity_replication_analysis import expected_cell_keys, paired_t_summary
from scripts.build_sensitivity_closure_package import metric_row
from vpuft.state_aware_evaluation import state_aware_first_revocation_metrics


def test_case_mapping_uses_15_second_half_open_windows_and_clamps_negative_time():
    assert opportunity_case_id(7001, "veh_006", 14.999) == "case-urban_roundabout-7001-veh_006-w0000"
    assert opportunity_case_id(7001, "veh_006", 15.0) == "case-urban_roundabout-7001-veh_006-w0001"
    assert opportunity_case_id(7001, "veh_006", -2.0) == "case-urban_roundabout-7001-veh_006-w0000"
    with pytest.raises(ValueError):
        opportunity_case_id(7001, "veh_006", math.nan)


def test_ordinary_attack_uses_its_emission_timestamp():
    message = {
        "message_id": "cam-7001-veh_006-000014-f0",
        "seed": 7001,
        "sender_vehicle_id": "veh_006",
        "generated_at": 15.0,
    }
    assert emission_time_for_message(message, {}) == 15.0
    assert opportunity_case_id(7001, "veh_006", emission_time_for_message(message, {})).endswith("w0001")
    with pytest.raises(ValueError, match="seed/vehicle"):
        emission_time_for_message({**message, "seed": 7002}, {})


def test_replay_uses_current_transmission_id_not_replayed_payload_time():
    mobility = [
        {"vehicle_id": "veh_006", "simulation_time": 8.0},
        {"vehicle_id": "veh_006", "simulation_time": 9.0},
        {"vehicle_id": "veh_006", "simulation_time": 10.0},
        {"vehicle_id": "veh_006", "simulation_time": 11.0},
        {"vehicle_id": "veh_006", "simulation_time": 12.0},
    ]
    emission_map = build_base_emission_times(mobility, seed=7001)
    # Saved SUMO pilot rows use this replay identity. generated_at=8 is the
    # replayed payload's original time; suffix 000004 maps to current send t=12.
    message = {
        "message_id": "replay-cam-7001-veh_006-000004",
        "original_message_id": "cam-7001-veh_006-000000",
        "seed": 7001,
        "sender_vehicle_id": "veh_006",
        "generated_at": 8.0,
    }
    assert emission_time_for_message(message, emission_map) == 12.0
    assert opportunity_case_id(7001, "veh_006", 12.0).endswith("w0000")
    assert opportunity_case_id(7001, "veh_006", 15.0).endswith("w0001")


def test_replay_mapping_rejects_missing_or_cross_vehicle_base_ids():
    msg = {"message_id": "replay-cam-7001-veh_006-000004", "seed": 7001,
           "sender_vehicle_id": "veh_006", "generated_at": 8.0}
    with pytest.raises(ValueError, match="missing"):
        emission_time_for_message(msg, {})
    with pytest.raises(ValueError, match="does not match"):
        emission_time_for_message({**msg, "sender_vehicle_id": "veh_007"},
                                  {"cam-7001-veh_006-000004": 12.0})


def test_mobility_index_is_deterministic_and_rejects_duplicate_frames():
    rows = [
        {"vehicle_id": "veh_006", "simulation_time": 9.0},
        {"vehicle_id": "veh_006", "simulation_time": 8.0},
    ]
    assert build_base_emission_times(rows, seed=7001) == {
        "cam-7001-veh_006-000000": 8.0,
        "cam-7001-veh_006-000001": 9.0,
    }


def test_first_committed_revocation_is_earliest_and_requires_timestamp():
    rows = [
        {"vehicle_id": "veh_a", "committed": True, "new_state": "REVOKED", "finalized_at": 18.0},
        {"vehicle_id": "veh_a", "committed": 1, "new_state": "revoked", "finalized_at": 14.0},
        {"vehicle_id": "veh_b", "committed": False, "new_state": "revoked", "finalized_at": 4.0},
    ]
    assert first_committed_revocations(rows) == {"veh_a": 14.0}
    with pytest.raises(ValueError, match="timestamp"):
        first_committed_revocations([{"vehicle_id": "veh_a", "committed": True,
                                     "new_state": "revoked", "finalized_at": None}])


def test_detected_and_protected_opportunities_are_distinct_and_roots_do_not_multiply():
    messages = [
        {"message_id": "cam-7001-veh_a-000010", "seed": 7001,
         "sender_vehicle_id": "veh_a", "generated_at": 10.0, "ground_truth_malicious": True},
        {"message_id": "cam-7001-veh_a-000020", "seed": 7001,
         "sender_vehicle_id": "veh_a", "generated_at": 20.0, "ground_truth_malicious": True},
    ]
    observations = [
        {"message_id": messages[0]["message_id"], "case_id": "case-urban_roundabout-7001-veh_a-w0000",
         "seed": 7001, "vehicle_id": "veh_a", "detected_at": 11.0,
         "source_kind": "rsu", "observation_root_id": "root-1"},
        {"message_id": messages[0]["message_id"], "case_id": "case-urban_roundabout-7001-veh_a-w0000",
         "seed": 7001, "vehicle_id": "veh_a", "detected_at": 12.0,
         "source_kind": "rsu", "observation_root_id": "root-2"},
        {"message_id": messages[1]["message_id"], "case_id": "case-urban_roundabout-7001-veh_a-w0001",
         "seed": 7001, "vehicle_id": "veh_a", "detected_at": 21.0,
         "source_kind": "vehicle_witness", "observation_root_id": "root-3"},
    ]
    decisions = [
        {"case_id": "case-urban_roundabout-7001-veh_a-w0000", "vehicle_id": "veh_a",
         "committed": True, "new_state": "revoked", "finalized_at": 14.0},
    ]
    result = evaluate_attack_opportunities(messages, observations, decisions, {}, seed=7001)
    assert result["attack_message_opportunities"] == 2
    assert result["observed_attack_messages"] == 2
    assert result["successfully_detected_attack_messages"] == 1
    assert result["protected_attack_messages"] == 1
    assert result["opportunity_detection_recall"] == 0.5
    assert result["protected_opportunity_fraction"] == 0.5


def test_duplicate_messages_missing_timestamps_and_wrong_case_are_rejected():
    base = {"message_id": "cam-7001-veh_a-000001", "seed": 7001,
            "sender_vehicle_id": "veh_a", "generated_at": 15.0,
            "ground_truth_malicious": True}
    with pytest.raises(ValueError, match="duplicate"):
        evaluate_attack_opportunities([base, base], [], [], {}, seed=7001)
    with pytest.raises(ValueError, match="timestamp"):
        evaluate_attack_opportunities([{**base, "generated_at": None}], [], [], {}, seed=7001)
    obs = [{"message_id": base["message_id"], "case_id": "case-urban_roundabout-7001-veh_a-w0000",
            "seed": 7001, "vehicle_id": "veh_a", "detected_at": 15.0}]
    with pytest.raises(ValueError, match="case mismatch"):
        evaluate_attack_opportunities([base], obs, [], {}, seed=7001)
    with pytest.raises(ValueError, match="timestamp"):
        evaluate_attack_opportunities([base], [{**obs[0], "detected_at": None}], [], {}, seed=7001)


def test_detection_event_cannot_precede_the_emission_it_claims_to_observe():
    message = {"message_id": "cam-7001-veh_a-000001", "seed": 7001,
               "sender_vehicle_id": "veh_a", "generated_at": 15.0,
               "ground_truth_malicious": True}
    observation = {"message_id": message["message_id"],
                   "case_id": "case-urban_roundabout-7001-veh_a-w0001",
                   "seed": 7001, "vehicle_id": "veh_a", "detected_at": 14.999,
                   "source_kind": "rsu"}
    with pytest.raises(ValueError, match="precedes emission"):
        evaluate_attack_opportunities([message], [observation], [], {}, seed=7001)


def test_method_b_first_revocation_window_remains_eligible_later_windows_excluded():
    frame = pd.DataFrame([
        {"case_id": "case-urban_roundabout-7001-veh_a-w0000", "vehicle_id": "veh_a", "seed": 7001,
         "architecture": "C100", "ground_truth_malicious": 1, "committed": 1,
         "new_state": "revoked"},
        {"case_id": "case-urban_roundabout-7001-veh_a-w0001", "vehicle_id": "veh_a", "seed": 7001,
         "architecture": "C100", "ground_truth_malicious": 1, "committed": 0,
         "new_state": "revoked"},
        {"case_id": "case-urban_roundabout-7001-veh_a-w0002", "vehicle_id": "veh_a", "seed": 7001,
         "architecture": "C100", "ground_truth_malicious": 0, "committed": 0,
         "new_state": "normal"},
        {"case_id": "case-urban_roundabout-7001-veh_b-w0000", "vehicle_id": "veh_b", "seed": 7001,
         "architecture": "C100", "ground_truth_malicious": 0, "committed": 0,
         "new_state": "normal"},
    ])
    metric = state_aware_first_revocation_metrics(frame).iloc[0]
    assert (metric.TP, metric.FP, metric.TN, metric.FN) == (1, 0, 1, 0)
    assert metric.excluded_post_revocation_windows == 2
    assert metric.all_windows == 4


def test_resume_manifest_indexes_unique_completed_cells_and_rejects_duplicates():
    row = {"variant_id": "baseline", "density": 20, "seed": 7003,
           "architecture": "C100", "status": "completed", "attempt": 2}
    assert completed_cell_index([row, {**row, "status": "failed", "attempt": 3}]) == {
        ("baseline", 20, 7003, "C100"): 2
    }
    with pytest.raises(RuntimeError, match="Duplicate completed checkpoint"):
        completed_cell_index([row, {**row, "attempt": 3}])


def test_resume_accepts_only_a_complete_matching_cell_checkpoint():
    key = ("baseline", 20, 7003, "C100")
    manifest = [{"variant_id": "baseline", "density": 20, "seed": 7003,
                 "architecture": "C100", "status": "completed", "attempt": 2,
                 "case_count": 2, "trace_sha256": "trace-hash"}]
    metric = [{"variant_id": "baseline", "density": 20, "seed": 7003,
               "architecture": "C100", "attempt": 2, "trace_sha256": "trace-hash"}]
    opportunity = [{**metric[0]}]
    decisions = [{**metric[0], "case_id": f"case-{i}"} for i in range(2)]
    validate_cell_checkpoint(key, 2, manifest, metric, opportunity, decisions)
    with pytest.raises(RuntimeError, match="trace hash"):
        validate_cell_checkpoint(key, 2, manifest, metric,
                                 [{**opportunity[0], "trace_sha256": "other"}], decisions)
    with pytest.raises(RuntimeError, match="decision count"):
        validate_cell_checkpoint(key, 2, manifest, metric, opportunity, decisions[:1])


def test_registered_design_contains_exactly_120_unique_architecture_cells():
    cells = expected_cell_keys()
    assert len(cells) == 120
    assert len(set(cells)) == 120
    assert ("baseline", 20, 7003, "C100") in cells
    assert ("position_sources_1", 100, 7008, "Distributed") in cells


def test_paired_t_interval_uses_seed_level_sample_and_reports_small_n():
    result = paired_t_summary([1.0, 2.0, 3.0])
    assert result["n"] == 3
    assert result["mean"] == 2.0
    assert result["ci95_low"] == pytest.approx(-0.4841, abs=0.002)
    assert result["ci95_high"] == pytest.approx(4.4841, abs=0.002)
    one = paired_t_summary([0.25])
    assert one["n"] == 1
    assert math.isnan(one["ci95_low"])


def test_closure_table_uses_pooled_confusion_and_fixed_opportunity_denominators():
    metrics = [{
        "variant_id": "baseline", "density": "20", "architecture": "C100", "seed": "7001",
        "TP": "1", "FP": "1", "TN": "9", "FN": "3", "excluded_post_revocation_cases": "2",
        "malicious_revocation_recall": "0.25", "trust_precision": "0.5",
        "false_revocation_rate": "0.1", "trust_f1": "0.333333", "mcc": "0.25",
        "cpu_time_seconds": "1.5", "latency_p95_ms": "100", "messages_per_decision": "20",
        "bytes_per_decision": "500", "packet_delivery_ratio": "0.98",
        "ledger_consistency_delay_p95_ms": "3",
    }]
    opportunities = [{
        "variant_id": "baseline", "density": "20", "architecture": "C100", "seed": "7001",
        "attack_message_opportunities": "10", "observed_attack_messages": "8",
        "unobserved_attack_messages": "2", "successfully_detected_attack_messages": "4",
        "protected_attack_messages": "3",
    }]
    row = metric_row("pilot", 20, "baseline", "C100", metrics, opportunities)
    assert (row["TP"], row["FP"], row["TN"], row["FN"]) == (1, 1, 9, 3)
    assert row["pooled_precision"] == pytest.approx(0.5)
    assert row["pooled_state_aware_recall"] == pytest.approx(0.25)
    assert row["pooled_FRR"] == pytest.approx(0.1)
    assert row["fixed_denominator_opportunity_recall"] == pytest.approx(0.4)
    assert row["fixed_denominator_protected_fraction"] == pytest.approx(0.3)
