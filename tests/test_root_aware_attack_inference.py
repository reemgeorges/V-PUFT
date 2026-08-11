from vpuft.domain import AttackType
from vpuft.inference import (
    infer_attack_type_from_reasons,
    infer_attack_type_from_root_reasons,
)


def test_flat_classifier_behavior_is_preserved():
    assert infer_attack_type_from_reasons(["flood_rate", "replay_nonce"]) == AttackType.FLOOD
    assert infer_attack_type_from_reasons(["replay_age", "replay_nonce"]) == AttackType.REPLAY
    assert infer_attack_type_from_reasons([
        "flood_rate", "replay_nonce", "position_inconsistency"
    ]) == AttackType.MIXED


def test_replay_kinematic_artifacts_on_same_root_are_not_mixed():
    attack = infer_attack_type_from_root_reasons([
        ["replay_age", "replay_nonce", "position_inconsistency", "speed_inconsistency"]
    ])
    assert attack == AttackType.REPLAY


def test_independent_position_root_still_makes_replay_plus_position_mixed():
    attack = infer_attack_type_from_root_reasons([
        ["replay_age", "replay_nonce", "position_inconsistency"],
        ["position_inconsistency"],
    ])
    assert attack == AttackType.MIXED


def test_independent_speed_root_still_makes_replay_plus_speed_mixed():
    attack = infer_attack_type_from_root_reasons([
        ["replay_age", "replay_nonce", "speed_inconsistency"],
        ["speed_inconsistency"],
    ])
    assert attack == AttackType.MIXED


def test_flood_nonce_semantics_are_preserved_per_root():
    assert infer_attack_type_from_root_reasons([
        ["flood_rate", "replay_nonce"]
    ]) == AttackType.FLOOD
