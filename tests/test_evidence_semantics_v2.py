from dataclasses import replace

from vpuft.config import ResearchConfig
from vpuft.crypto import KeyRegistry
from vpuft.domain import AttackType, EvidenceAttestation, EvidenceDirection, MobilitySnapshot
from vpuft.evidence import sign_attestation
from vpuft.sumo.attacks import AttackInjector, AttackSchedule
from vpuft.sumo.detector import DetectionEngine, RSU
from vpuft.trace import sanitize_runtime_events
from vpuft.weighting import case_evidence_masses, regularized_strengths


def snapshot(time: float = 10.0) -> MobilitySnapshot:
    return MobilitySnapshot(1001, time, "veh_1", 100.0, 0.0, 12.0, 0.0, "e01_0", 100.0, "e01")


def _att(keys, idx: int, direction: EvidenceDirection) -> EvidenceAttestation:
    source = "rsu-1" if idx % 2 == 0 else "rsu-2"
    att = EvidenceAttestation(
        attestation_id=f"att-{direction.value}-{idx}",
        case_id="case-1",
        observation_root_id=f"root-{direction.value}-{idx}",
        source_id=source,
        source_kind="rsu",
        validator_rsu_id=source,
        administrative_domain_id="d1",
        sensor_modality="cam",
        geographic_cell="z1" if idx % 2 == 0 else "z2",
        attack_type=AttackType.POSITION_OFFSET,
        direction=direction,
        detector_confidence=0.9,
        source_reliability=0.9,
        freshness=0.9,
        verifiability=0.9,
        independence=0.9,
        observed_at=1.0,
        evidence_hash=f"h-{direction.value}-{idx}",
        signature="",
        public_key_id="",
    )
    return sign_attestation(att, keys, source)


def test_false_denm_semantics_are_applied_by_inferred_runtime_case_not_truth_label():
    cfg = ResearchConfig()
    schedule = AttackSchedule("veh_1", AttackType.FALSE_DENM, 0.0, 30.0, {"denm_period_seconds": 5.0})
    injector = AttackInjector(1001, [schedule])
    detector = DetectionEngine(cfg.detector, cfg.security, 1001)
    rsu = RSU("rsu-1", 100.0, 0.0, "domain-1", 0.95)

    claim = injector.generate(snapshot(10.0), 10.0)[0]
    claim_event = detector.observe_rsu(claim, rsu, 10.0, snapshot(10.0))
    assert claim.denm_claimed
    assert claim_event.direction == EvidenceDirection.SUPPORTS
    assert claim_event.attack_type == AttackType.FALSE_DENM

    cam = injector.generate(snapshot(11.0), 11.0)[0]
    cam_event = detector.observe_rsu(cam, rsu, 11.0, snapshot(11.0))
    assert not cam.denm_claimed
    # Local detector does not consult the injected attack type.
    assert cam_event.direction == EvidenceDirection.OPPOSES
    assert cam_event.attack_type == AttackType.BENIGN

    runtime = sanitize_runtime_events([claim_event, cam_event], window_seconds=15.0)
    assert {event.attack_type for event in runtime} == {AttackType.FALSE_DENM}
    runtime_cam = next(event for event in runtime if event.message_id == cam.message_id)
    assert runtime_cam.direction == EvidenceDirection.NEUTRAL
    assert runtime_cam.reason_codes == ("not_applicable_observation",)
    assert "false_denm" not in runtime_cam.case_id


def test_log_evidence_mass_preserves_support_opposition_ratio():
    cfg = ResearchConfig()
    keys = KeyRegistry()
    atts = [_att(keys, i, EvidenceDirection.SUPPORTS) for i in range(8)]
    atts += [_att(keys, 100 + i, EvidenceDirection.OPPOSES) for i in range(2)]
    pos_mass, neg_mass, _ = case_evidence_masses(atts, cfg.weights)
    support, oppose, margin = regularized_strengths(pos_mass, neg_mass, 1.0)
    assert support > oppose
    assert margin > 0.45
