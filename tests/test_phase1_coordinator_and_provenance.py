from dataclasses import replace

from vpuft.architectures import DistributedRSUExtendedVPUFT
from vpuft.config import ResearchConfig
from vpuft.crypto import KeyRegistry
from vpuft.domain import AttackType, EvidenceAttestation, EvidenceCase, EvidenceDirection
from vpuft.evidence import sign_attestation
from vpuft.weighting import aggregate_by_root


def _attestation(keys, *, attestation_id, source, root="root-original-cam", observed_at=1.0):
    unsigned = EvidenceAttestation(
        attestation_id=attestation_id,
        case_id="case-simultaneous",
        observation_root_id=root,
        source_id=source,
        source_kind="rsu",
        validator_rsu_id=source,
        administrative_domain_id="domain-1",
        sensor_modality="rsu_cam_plausibility",
        geographic_cell="cell-1",
        attack_type=AttackType.POSITION_OFFSET,
        direction=EvidenceDirection.SUPPORTS,
        detector_confidence=0.9,
        source_reliability=0.9,
        freshness=0.9,
        verifiability=0.9,
        independence=0.9,
        observed_at=observed_at,
        evidence_hash=f"hash-{attestation_id}",
        signature="",
        public_key_id="",
    )
    return sign_attestation(unsigned, keys, source)


def test_simultaneous_observers_choose_same_coordinator_regardless_of_input_order():
    config = ResearchConfig()
    keys = KeyRegistry()
    architecture = DistributedRSUExtendedVPUFT(config, keys)
    first = _attestation(keys, attestation_id="att-b", source="rsu-2")
    second = _attestation(keys, attestation_id="att-a", source="rsu-1")
    base = EvidenceCase(
        "case-simultaneous", "veh-1", "pseudo-1", AttackType.POSITION_OFFSET, 0.0, True
    )
    case_a = replace(base, attestations=[first, second])
    case_b = replace(base, attestations=[second, first])

    assert architecture._select_coordinator(case_a) == "rsu-1"
    assert architecture._select_coordinator(case_b) == "rsu-1"


def test_reports_from_two_rsus_with_same_original_root_are_deduplicated():
    keys = KeyRegistry()
    reports = [
        _attestation(keys, attestation_id="att-a", source="rsu-1"),
        _attestation(keys, attestation_id="att-b", source="rsu-2"),
    ]
    roots = aggregate_by_root(reports, ResearchConfig().weights)

    assert len(roots) == 1
    assert roots[0].observation_root_id == "root-original-cam"
    assert roots[0].duplicate_count == 1
