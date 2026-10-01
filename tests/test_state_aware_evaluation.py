import pandas as pd

from vpuft.state_aware_evaluation import (
    first_revocation_timing,
    persistent_revocation_state_metrics,
    prepare_state_aware_decisions,
    state_aware_first_revocation_metrics,
)


def _frame(rows):
    base = {
        "topology": "urban_roundabout",
        "vehicle_count": 20,
        "seed": 1001,
        "architecture": "distributed_density_honest",
        "backhaul_extra_latency_ms": None,
    }
    return pd.DataFrame([{**base, **row} for row in rows])


def test_post_revocation_malicious_window_is_excluded_not_tp_or_fn():
    frame = _frame([
        {
            "case_id": "case-test-1001-veh1-w0000",
            "vehicle_id": "veh1",
            "ground_truth_malicious": 1,
            "committed": 0,
            "new_state": "suspected",
            "finalized_at": None,
        },
        {
            "case_id": "case-test-1001-veh1-w0001",
            "vehicle_id": "veh1",
            "ground_truth_malicious": 1,
            "committed": 1,
            "new_state": "revoked",
            "finalized_at": 29.0,
        },
        {
            "case_id": "case-test-1001-veh1-w0002",
            "vehicle_id": "veh1",
            "ground_truth_malicious": 1,
            "committed": 1,
            "new_state": "revoked",
            "finalized_at": 44.0,
        },
    ])

    prepared = prepare_state_aware_decisions(frame)

    assert prepared["state_aware_label"].tolist() == [
        "FN",
        "TP",
        "EXCLUDED_POST_REVOCATION",
    ]

    metrics = state_aware_first_revocation_metrics(frame).iloc[0]

    assert metrics["TP"] == 1
    assert metrics["FN"] == 1
    assert metrics["excluded_post_revocation_windows"] == 1
    assert metrics["recall"] == 0.5


def test_false_revocation_is_counted_once_and_later_benign_window_excluded():
    frame = _frame([
        {
            "case_id": "case-test-1001-veh2-w0000",
            "vehicle_id": "veh2",
            "ground_truth_malicious": 0,
            "committed": 1,
            "new_state": "revoked",
            "finalized_at": 14.0,
        },
        {
            "case_id": "case-test-1001-veh2-w0001",
            "vehicle_id": "veh2",
            "ground_truth_malicious": 0,
            "committed": 1,
            "new_state": "revoked",
            "finalized_at": 29.0,
        },
    ])

    metrics = state_aware_first_revocation_metrics(frame).iloc[0]

    assert metrics["FP"] == 1
    assert metrics["excluded_post_revocation_windows"] == 1


def test_vehicle_without_revocation_remains_in_risk_set():
    frame = _frame([
        {
            "case_id": "case-test-1001-veh3-w0000",
            "vehicle_id": "veh3",
            "ground_truth_malicious": 1,
            "committed": 0,
            "new_state": "suspected",
            "finalized_at": None,
        },
        {
            "case_id": "case-test-1001-veh3-w0001",
            "vehicle_id": "veh3",
            "ground_truth_malicious": 1,
            "committed": 0,
            "new_state": "quarantined",
            "finalized_at": None,
        },
    ])

    metrics = state_aware_first_revocation_metrics(frame).iloc[0]

    assert metrics["FN"] == 2
    assert metrics["excluded_post_revocation_windows"] == 0


def test_persistent_state_is_descriptive_not_extra_tp():
    frame = _frame([
        {
            "case_id": "case-test-1001-veh4-w0000",
            "vehicle_id": "veh4",
            "ground_truth_malicious": 1,
            "committed": 1,
            "new_state": "revoked",
            "finalized_at": 14.0,
        },
        {
            "case_id": "case-test-1001-veh4-w0001",
            "vehicle_id": "veh4",
            "ground_truth_malicious": 1,
            "committed": 1,
            "new_state": "revoked",
            "finalized_at": 29.0,
        },
        {
            "case_id": "case-test-1001-veh4-w0002",
            "vehicle_id": "veh4",
            "ground_truth_malicious": 0,
            "committed": 0,
            "new_state": "revoked",
            "finalized_at": None,
        },
    ])

    persistence = persistent_revocation_state_metrics(frame).iloc[0]

    assert persistence["post_revocation_windows"] == 2
    assert persistence["malicious_post_revocation_windows"] == 1
    assert persistence["benign_post_revocation_windows"] == 1
    assert persistence["malicious_post_windows_in_revoked_state"] == 1
    assert persistence["benign_post_windows_in_revoked_state"] == 1
    assert persistence["repeated_committed_revocations_after_first"] == 1


def test_time_to_first_revocation_uses_first_malicious_case_start():
    frame = _frame([
        {
            "case_id": "case-test-1001-veh5-w0001",
            "vehicle_id": "veh5",
            "ground_truth_malicious": 1,
            "committed": 0,
            "new_state": "suspected",
            "finalized_at": None,
        },
        {
            "case_id": "case-test-1001-veh5-w0002",
            "vehicle_id": "veh5",
            "ground_truth_malicious": 1,
            "committed": 1,
            "new_state": "revoked",
            "finalized_at": 43.0,
        },
    ])

    timing = first_revocation_timing(frame).iloc[0]

    assert timing["first_malicious_case_start"] == 15.0
    assert timing["first_committed_revocation_at"] == 43.0
    assert timing["time_to_first_revocation_ms"] == 28000.0
