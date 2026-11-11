from dataclasses import replace

from vpuft.config import ResearchConfig
from vpuft.crypto import KeyRegistry
from vpuft.domain import AttackType, EvidenceAttestation, EvidenceCase, EvidenceDirection
from vpuft.evidence import sign_attestation
from vpuft.qualification import VPUFTQualificationEngine


def _att(keys, root, source, zone, confidence, index):
    raw = EvidenceAttestation(
        f"att-{index}", "case-diverse", root, source, "rsu", source,
        f"domain-{source}", "cam", zone, AttackType.POSITION_OFFSET,
        EvidenceDirection.SUPPORTS, confidence, 0.99, 0.99, 0.99, 0.99,
        1.0, f"hash-{index}", "", "",
    )
    return sign_attestation(raw, keys, source)


def test_diversity_aware_assignment_uses_real_alternate_rsu_without_root_inflation():
    keys = KeyRegistry()
    base = ResearchConfig()
    improved = replace(
        base,
        distributed_extension=replace(
            base.distributed_extension, diversity_aware_root_assignment=True
        ),
    )
    case = EvidenceCase(
        "case-diverse", "veh-1", "p-1", AttackType.POSITION_OFFSET, 0.0, True,
        [
            _att(keys, "root-1", "rsu-1", "zone-1", 0.99, 1),
            _att(keys, "root-1", "rsu-2", "zone-2", 0.95, 2),
            _att(keys, "root-2", "rsu-1", "zone-1", 0.99, 3),
            _att(keys, "root-2", "rsu-2", "zone-2", 0.95, 4),
        ],
    )

    baseline = VPUFTQualificationEngine(base).qualify(case, now=2.0)
    candidate = VPUFTQualificationEngine(improved).qualify(case, now=2.0)

    assert not baseline.qualified
    assert candidate.qualified
    assert candidate.independent_roots == 2
    assert candidate.distinct_sources == 2
    assert candidate.distinct_zones == 2
    assert candidate.excluded_duplicate_roots == 2
