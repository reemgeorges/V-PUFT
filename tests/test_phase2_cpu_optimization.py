from dataclasses import replace

from vpuft.architectures import DistributedRSUExtendedVPUFT
from vpuft.config import DistributedExtensionConfig, NetworkConfig, ResearchConfig
from vpuft.crypto import KeyRegistry
from vpuft.domain import AttackType, EvidenceAttestation, EvidenceCase, EvidenceDirection
from vpuft.evidence import sign_attestation


def _case(keys):
    case = EvidenceCase("case-opt", "veh-1", "p-1", AttackType.POSITION_OFFSET, 0.0, True)
    for index, source in enumerate(("rsu-1", "rsu-2")):
        raw = EvidenceAttestation(
            f"att-{index}", case.case_id, f"root-{index}", source, "rsu", source,
            f"domain-{index}", "cam", f"zone-{index}", case.attack_type,
            EvidenceDirection.SUPPORTS, 0.99, 0.99, 0.99, 0.99, 0.99,
            float(index), f"hash-{index}", "", "",
        )
        case.add(sign_attestation(raw, keys, source))
    return case


def test_verified_bundle_cache_preserves_decision_and_avoids_repeated_sanitization():
    keys = KeyRegistry()
    base = ResearchConfig(network=NetworkConfig(packet_delivery_ratio=1.0))
    optimized = replace(
        base,
        distributed_extension=replace(
            base.distributed_extension, cache_verified_evidence_bundle=True
        ),
    )

    def run(config):
        architecture = DistributedRSUExtendedVPUFT(config, keys)
        original = architecture.sanitize_case
        calls = {"count": 0}
        def counted(case):
            calls["count"] += 1
            return original(case)
        architecture.sanitize_case = counted
        result = architecture.run([_case(keys)], 1001)
        return result, calls["count"]

    baseline, baseline_calls = run(base)
    candidate, candidate_calls = run(optimized)

    assert candidate_calls < baseline_calls
    assert (candidate.decisions[0].committed, candidate.decisions[0].new_state) == (
        baseline.decisions[0].committed, baseline.decisions[0].new_state
    )
    assert candidate.decisions[0].decision_margin == baseline.decisions[0].decision_margin
