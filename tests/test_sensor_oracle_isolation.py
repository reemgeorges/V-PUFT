import inspect

from vpuft.config import ResearchConfig
from vpuft.domain import AttackType, MobilitySnapshot
from vpuft.sumo.attacks import AttackInjector, AttackSchedule
from vpuft.sumo.detector import DetectionEngine, RSU
from vpuft.sumo.sensors import emulate_kinematic_observation


def snapshot(time: float = 10.0, x: float = 100.0, speed: float = 12.0, accel: float = 0.0) -> MobilitySnapshot:
    return MobilitySnapshot(1001, time, "veh_1", x, 0.0, speed, accel, "e01_0", 100.0, "e01")


def test_detector_source_does_not_reference_message_oracle_kinematics():
    source = inspect.getsource(DetectionEngine)
    assert "message.true_x" not in source
    assert "message.true_y" not in source
    assert "message.true_speed_mps" not in source
    assert "message.true_acceleration_mps2" not in source


def test_sensor_observation_is_deterministic_and_observer_specific():
    cfg = ResearchConfig()
    injector = AttackInjector(1001, [])
    target = snapshot()
    message = injector.generate(target, target.simulation_time)[0]
    a1 = emulate_kinematic_observation(
        target=target, message=message, observer_id="rsu-1", source_kind=__import__('vpuft.domain', fromlist=['SourceKind']).SourceKind.RSU, config=cfg.detector
    )
    a2 = emulate_kinematic_observation(
        target=target, message=message, observer_id="rsu-1", source_kind=__import__('vpuft.domain', fromlist=['SourceKind']).SourceKind.RSU, config=cfg.detector
    )
    b = emulate_kinematic_observation(
        target=target, message=message, observer_id="rsu-2", source_kind=__import__('vpuft.domain', fromlist=['SourceKind']).SourceKind.RSU, config=cfg.detector
    )
    assert a1 == a2
    assert a1 != b


def test_position_attack_is_detected_against_noisy_observation_not_oracle_report_comparison():
    cfg = ResearchConfig()
    schedule = AttackSchedule("veh_1", AttackType.POSITION_OFFSET, 0.0, 30.0, {"position_offset_m": 60.0})
    injector = AttackInjector(1001, [schedule])
    target = snapshot()
    message = injector.generate(target, target.simulation_time)[0]
    detector = DetectionEngine(cfg.detector, cfg.security, 1001)
    rsu = RSU("rsu-1", 100.0, 0.0, "domain-1", 0.95)
    event = detector.observe_rsu(message, rsu, target.simulation_time, target)
    assert "position_inconsistency" in event.reason_codes
    assert "observed_x" in event.payload
    assert event.payload["observed_x"] != message.true_x


def test_replay_sensor_uses_reception_time_target_snapshot():
    cfg = ResearchConfig()
    schedule = AttackSchedule("veh_1", AttackType.REPLAY, 0.0, 30.0, {"replay_delay_steps": 1})
    injector = AttackInjector(1001, [schedule])
    first_target = snapshot(10.0, x=100.0, speed=10.0)
    injector.generate(first_target, 10.0)
    current_target = snapshot(11.0, x=130.0, speed=13.0)
    replay = injector.generate(current_target, 11.0)[0]
    # The replayed packet contains old simulator fields, but the sensor emulator
    # is intentionally driven by the reception-time mobility snapshot.
    obs = emulate_kinematic_observation(
        target=current_target,
        message=replay,
        observer_id="rsu-1",
        source_kind=__import__('vpuft.domain', fromlist=['SourceKind']).SourceKind.RSU,
        config=cfg.detector,
    )
    assert abs(obs.x - current_target.x) < 20.0
    assert abs(obs.x - replay.true_x) > 10.0
