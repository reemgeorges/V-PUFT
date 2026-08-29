from dataclasses import replace

from vpuft.config import ResearchConfig
from vpuft.domain import AttackType, EvidenceDirection, MobilitySnapshot
from vpuft.inference import infer_attack_type_from_reasons
from vpuft.sumo.attacks import AttackInjector, AttackSchedule
from vpuft.sumo.detector import DetectionEngine, RSU
from vpuft.trace import sanitize_runtime_events


def snapshot(time: float = 10.0) -> MobilitySnapshot:
    return MobilitySnapshot(1001, time, "veh_1", 100.0, 0.0, 12.0, 0.0, "e01_0", 100.0, "e01")


def test_reason_classifier_distinguishes_flood_replay_and_mixed_without_labels():
    assert infer_attack_type_from_reasons(["flood_rate", "replay_nonce"]) == AttackType.FLOOD
    assert infer_attack_type_from_reasons(["replay_age", "replay_nonce"]) == AttackType.REPLAY
    assert infer_attack_type_from_reasons([
        "flood_rate", "replay_nonce", "position_inconsistency", "speed_inconsistency"
    ]) == AttackType.MIXED


def test_runtime_case_formation_ignores_legacy_case_id_and_attack_label():
    cfg = ResearchConfig()
    schedule = AttackSchedule("veh_1", AttackType.POSITION_OFFSET, 0.0, 30.0, {"position_offset_m": 60.0})
    injector = AttackInjector(1001, [schedule])
    detector = DetectionEngine(cfg.detector, cfg.security, 1001)
    rsu = RSU("rsu-1", 100.0, 0.0, "domain-1", 0.95)

    message = injector.generate(snapshot(10.0), 10.0)[0]
    event = detector.observe_rsu(message, rsu, 10.0, snapshot(10.0))

    # Counterfactual copy: change only evaluation-only labels and legacy case id.
    payload = dict(event.payload)
    payload["ground_truth_attack_type"] = AttackType.BENIGN.value
    counterfactual = replace(
        event,
        case_id="injected-case-label-changed",
        ground_truth_malicious=False,
        payload=payload,
    )

    a = sanitize_runtime_events([event], window_seconds=15.0)[0]
    b = sanitize_runtime_events([counterfactual], window_seconds=15.0)[0]

    assert a.case_id == b.case_id
    assert a.attack_type == b.attack_type == AttackType.POSITION_OFFSET
    assert a.direction == b.direction == EvidenceDirection.SUPPORTS


def test_runtime_case_boundaries_are_fixed_time_windows():
    cfg = ResearchConfig()
    detector = DetectionEngine(cfg.detector, cfg.security, 1001)
    rsu = RSU("rsu-1", 100.0, 0.0, "domain-1", 0.95)
    injector = AttackInjector(1001, [])

    e1 = detector.observe_rsu(injector.generate(snapshot(14.9), 14.9)[0], rsu, 14.9, snapshot(14.9))
    e2 = detector.observe_rsu(injector.generate(snapshot(15.1), 15.1)[0], rsu, 15.1, snapshot(15.1))
    runtime = sanitize_runtime_events([e1, e2], window_seconds=15.0)
    assert len({event.case_id for event in runtime}) == 2
    assert all("benign" not in event.case_id for event in runtime)


def test_detector_source_has_no_ground_truth_label_dependency():
    import inspect
    source = inspect.getsource(DetectionEngine)
    assert "message.attack_type" not in source
    assert "message.ground_truth_malicious" not in source
