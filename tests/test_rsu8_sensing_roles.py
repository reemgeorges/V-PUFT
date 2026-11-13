from dataclasses import replace

import pytest

from vpuft.architectures.distributed_extension import replica_membership
from vpuft.config import ResearchConfig
from vpuft.domain import AttackType, MobilitySnapshot
from vpuft.sumo.attacks import AttackInjector, AttackSchedule
from vpuft.sumo.detector import DetectionEngine, RSU
from vpuft.sumo.runner import witness_rsu_pool


def test_witness_routing_can_be_held_to_original_six_rsus():
    rsus = [RSU(f"rsu-{i}", float(i), 0.0, "domain-1", 0.9) for i in range(1, 9)]
    assert witness_rsu_pool(rsus) == rsus  # historical default uses every configured RSU
    pool = witness_rsu_pool(rsus, (f"rsu-{i}" for i in range(1, 7)))
    assert [rsu.rsu_id for rsu in pool] == [f"rsu-{i}" for i in range(1, 7)]


def test_witness_routing_rejects_unknown_or_empty_pools():
    rsus = [RSU("rsu-1", 0.0, 0.0, "domain-1", 0.9)]
    with pytest.raises(ValueError):
        witness_rsu_pool(rsus, ("rsu-7",))
    with pytest.raises(ValueError):
        witness_rsu_pool(rsus, ())


def test_sensing_only_nodes_are_not_pbft_validators_or_replicas():
    validators = ("rsu-1", "rsu-2", "rsu-3", "rsu-4")
    replicas = replica_membership(validators, 8, ("rsu-7", "rsu-8"))
    assert replicas == ("rsu-1", "rsu-2", "rsu-3", "rsu-4", "rsu-5", "rsu-6")
    config = ResearchConfig()
    c3_config = replace(config, simulation=replace(config.simulation, rsu_count=8),
                        distributed_extension=replace(config.distributed_extension,
                                                       sensing_only_rsu_ids=("rsu-7", "rsu-8")))
    assert c3_config.pbft.validators == config.pbft.validators == validators
    assert c3_config.distributed_extension.sensing_only_rsu_ids == ("rsu-7", "rsu-8")
    with pytest.raises(ValueError):
        replica_membership(validators, 8, ("rsu-1",))
    with pytest.raises(ValueError):
        replica_membership(validators, 8, ("rsu-9",))


def test_observer_identity_does_not_change_cam_observation_root():
    target = MobilitySnapshot(2101, 10.0, "veh-1", 100.0, 0.0, 12.0, 0.0, "lane", 10.0, "road")
    message = AttackInjector(2101, [AttackSchedule(
        "veh-1", AttackType.POSITION_OFFSET, 0.0, 20.0, {"position_offset_m": 60.0}
    )]).generate(target, 10.0)[0]
    detector = DetectionEngine(ResearchConfig().detector, ResearchConfig().security, 2101)
    a = detector.observe_rsu(message, RSU("rsu-1", 100.0, 0.0, "domain-1", 0.9), 10.0, target)
    b = detector.observe_rsu(message, RSU("rsu-7", 101.0, 0.0, "domain-3", 0.9), 10.0, target)
    assert a.observation_root_id == b.observation_root_id == message.observation_root_id
    assert a.detected_by != b.detected_by
