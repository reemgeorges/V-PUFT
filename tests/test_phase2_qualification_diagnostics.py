from dataclasses import replace

from vpuft.config import ResearchConfig
from vpuft.crypto import KeyRegistry
from vpuft.domain import AttackType, EvidenceAttestation, EvidenceCase, EvidenceDirection
from vpuft.evidence import sign_attestation
from vpuft.qualification import VPUFTQualificationEngine


def _support(keys, index, *, source="rsu-1", zone="cell-a", observed_at=1.0):
    unsigned = EvidenceAttestation(
        attestation_id=f"att-{index}", case_id="case-diagnostics",
        observation_root_id=f"root-{index}", source_id=source, source_kind="rsu",
        validator_rsu_id=source, administrative_domain_id="domain-1",
        sensor_modality="rsu_cam_plausibility", geographic_cell=zone,
        attack_type=AttackType.POSITION_OFFSET, direction=EvidenceDirection.SUPPORTS,
        detector_confidence=0.95, source_reliability=0.95, freshness=0.95,
        verifiability=0.95, independence=0.95, observed_at=observed_at,
        evidence_hash=f"hash-{index}", signature="", public_key_id="",
    )
    return sign_attestation(unsigned, keys, source)


def test_qualification_records_every_failed_constraint_without_changing_reason():
    config = ResearchConfig()
    keys = KeyRegistry(config.security.deterministic_master_seed)
    case = EvidenceCase(
        "case-diagnostics", "veh-1", "pseudo-1", AttackType.POSITION_OFFSET, 0.0, True,
        [_support(keys, 1)],
    )

    result = VPUFTQualificationEngine(config).qualify(case, now=2.0)

    assert not result.qualified
    assert result.reason == "insufficient_independent_evidence_diversity"
    assert result.required_roots == 2
    assert result.required_sources == 2
    assert result.required_zones == 2
    assert result.required_modalities == 1
    assert result.required_margin == 0.45
    assert result.failed_constraints == ("independent_roots", "sources", "zones")
    assert result.evidence_observed_at == (1.0,)
    assert result.evidence_ages_seconds == (1.0,)
    assert result.excluded_duplicate_roots == 0


def test_diagnostics_report_margin_together_with_diversity_failures():
    config = ResearchConfig()
    keys = KeyRegistry(config.security.deterministic_master_seed)
    weak = replace(_support(keys, 1), detector_confidence=0.06)
    case = EvidenceCase(
        "case-diagnostics", "veh-1", "pseudo-1", AttackType.POSITION_OFFSET, 0.0, True,
        [weak],
    )

    result = VPUFTQualificationEngine(config).qualify(case, now=2.0)

    assert set(result.failed_constraints) == {"independent_roots", "sources", "zones", "margin"}
