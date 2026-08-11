from dataclasses import replace

from vpuft.config import ResearchConfig
from vpuft.domain import AttackType, MobilitySnapshot
from vpuft.sumo.attacks import AttackInjector, AttackSchedule
from vpuft.sumo.detector import DetectionEngine, RSU


def snapshot(time: float = 10.0) -> MobilitySnapshot:
    return MobilitySnapshot(1001, time, "veh_1", 100.0, 0.0, 12.0, 0.0, "e01_0", 100.0, "e01")


def test_position_attack_is_detected():
    cfg = ResearchConfig()
    schedule = AttackSchedule("veh_1", AttackType.POSITION_OFFSET, 0.0, 30.0, {"position_offset_m": 60.0})
    injector = AttackInjector(1001, [schedule])
    target = snapshot()
    message = injector.generate(target, 10.0)[0]
    detector = DetectionEngine(cfg.detector, cfg.security, 1001)
    event = detector.observe_rsu(message, RSU("rsu-1", 100.0, 0.0, "domain-1", 0.95), 10.0, target)
    assert int(event.direction) == 1
    assert "position_inconsistency" in event.reason_codes


def test_replay_keeps_original_observation_root():
    schedule = AttackSchedule("veh_1", AttackType.REPLAY, 3.0, 30.0, {"replay_delay_steps": 2})
    injector = AttackInjector(1001, [schedule])
    roots = []
    for t in [1.0, 2.0, 3.0]:
        roots.append(injector.generate(snapshot(t), t)[0].observation_root_id)
    assert roots[2] == roots[0]

