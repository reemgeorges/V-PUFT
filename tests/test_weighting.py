from vpuft.config import ResearchConfig
from vpuft.crypto import KeyRegistry
from vpuft.domain import AttackType, EvidenceAttestation, EvidenceCase, EvidenceDirection
from vpuft.evidence import sign_attestation
from vpuft.qualification import VPUFTQualificationEngine
from vpuft.weighting import aggregate_by_root


def make_att(keys, att_id, root, source, direction=EvidenceDirection.SUPPORTS, independence=0.9):
    att = EvidenceAttestation(
        attestation_id=att_id,
        case_id="case-1",
        observation_root_id=root,
        source_id=source,
        source_kind="rsu",
        validator_rsu_id=source,
        administrative_domain_id="d1",
        sensor_modality="cam",
        geographic_cell="z1" if source == "rsu-1" else "z2",
        attack_type=AttackType.POSITION_OFFSET,
        direction=direction,
        detector_confidence=0.9,
        source_reliability=0.9,
        freshness=0.9,
        verifiability=0.9,
        independence=independence,
        observed_at=1.0,
        evidence_hash=att_id,
        signature="",
        public_key_id="",
    )
    return sign_attestation(att, keys, source)


def test_root_deduplication_counts_one_contribution():
    keys = KeyRegistry()
    a1 = make_att(keys, "a1", "root-1", "rsu-1")
    a2 = make_att(keys, "a2", "root-1", "rsu-2")
    roots = aggregate_by_root([a1, a2], ResearchConfig().weights)
    assert len(roots) == 1
    assert roots[0].duplicate_count == 1


def test_two_independent_roots_can_qualify():
    cfg = ResearchConfig()
    keys = KeyRegistry()
    case = EvidenceCase("case-1", "veh-1", "ps-1", AttackType.POSITION_OFFSET, 0.0, True)
    case.add(make_att(keys, "a1", "root-1", "rsu-1"))
    case.add(make_att(keys, "a2", "root-2", "rsu-2"))
    result = VPUFTQualificationEngine(cfg).qualify(case, 1.0)
    assert result.independent_roots == 2
    assert result.qualified
