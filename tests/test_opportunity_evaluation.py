import pandas as pd

from vpuft.opportunity_evaluation import opportunity_frame, opportunity_metrics


def test_zero_observation_attack_is_a_miss_and_benign_message_is_not_attack():
    messages = pd.DataFrame([
        {"message_id": "a", "sender_vehicle_id": "veh-1", "generated_at": 1.0, "ground_truth_malicious": True},
        {"message_id": "b", "sender_vehicle_id": "veh-1", "generated_at": 2.0, "ground_truth_malicious": False},
    ])
    decisions = pd.DataFrame(columns=["vehicle_id", "case_id", "committed", "new_state"])
    result = opportunity_frame(messages, decisions, set())
    assert len(result) == 1
    assert not result.iloc[0].observed_opportunity
    assert result.iloc[0].missed_opportunity
    assert opportunity_metrics(result)["opportunity_recall"] == 0


def test_first_revocation_and_later_attack_are_separate():
    messages = pd.DataFrame([
        {"message_id": "a", "sender_vehicle_id": "veh-1", "generated_at": 1.0, "ground_truth_malicious": True},
        {"message_id": "b", "sender_vehicle_id": "veh-1", "generated_at": 16.0, "ground_truth_malicious": True},
    ])
    decisions = pd.DataFrame([{"vehicle_id": "veh-1", "case_id": "case-veh-1-w0000",
                               "committed": 1, "new_state": "revoked"}])
    result = opportunity_frame(messages, decisions, {"a"})
    assert result.detected_opportunity.tolist() == [True, False]
    assert result.terminal_after_revocation.tolist() == [False, True]
    assert opportunity_metrics(result)["opportunity_recall"] == 1
