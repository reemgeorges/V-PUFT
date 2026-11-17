from dataclasses import replace

from vpuft.architectures.centralized import CentralizedVPUFT
from vpuft.config import AttackPolicy, CentralServerConfig, NetworkConfig, ResearchConfig
from vpuft.crypto import KeyRegistry
from vpuft.domain import AttackType, EvidenceAttestation, EvidenceCase, EvidenceDirection
from vpuft.evidence import sign_attestation
from vpuft.qualification import VPUFTQualificationEngine
from scripts.final_scenario5_ablation_adapter import AblationQualificationAdapter, effective_variant_record


def _config():
    base = ResearchConfig(
        network=NetworkConfig(base_latency_ms=0.0, jitter_ms=0.0, packet_delivery_ratio=1.0, max_retries=0),
        central=CentralServerConfig(availability=1.0, service_time_ms=1.0),
    )
    policies = dict(base.policies)
    policies[AttackType.POSITION_OFFSET.value] = AttackPolicy(
        required_roots=2,
        required_sources=2,
        required_zones=2,
        required_modalities=1,
        margin_threshold=0.40,
    )
    return replace(base, policies=policies)


def _attestation(keys, *, att_id, root, source, direction=EvidenceDirection.SUPPORTS, factor=0.99):
    value = EvidenceAttestation(
        attestation_id=att_id,
        case_id="case-ablation-1",
        observation_root_id=root,
        source_id=source,
        source_kind="rsu",
        validator_rsu_id=source,
        administrative_domain_id=f"domain-{source}",
        sensor_modality="rsu_cam_plausibility",
        geographic_cell=f"cell-{source}",
        attack_type=AttackType.POSITION_OFFSET,
        direction=direction,
        detector_confidence=factor,
        source_reliability=factor,
        freshness=factor,
        verifiability=factor,
        independence=factor,
        observed_at=0.0,
        evidence_hash=f"hash-{att_id}",
        signature="",
        public_key_id="",
        validity=1,
        reason_codes=("position_inconsistency",),
    )
    return sign_attestation(value, keys, source)


def _case(*attestations):
    case = EvidenceCase(
        case_id="case-ablation-1",
        vehicle_id="veh-ablation-1",
        pseudonym="ps-ablation-1",
        attack_type=AttackType.POSITION_OFFSET,
        opened_at=0.0,
        ground_truth_malicious=True,
    )
    for attestation in attestations:
        case.add(attestation)
    return case


def test_baseline_adapter_is_exactly_the_production_engine():
    cfg = _config()
    keys = KeyRegistry()
    case = _case(_attestation(keys, att_id="a1", root="root-1", source="rsu-1"))
    production = VPUFTQualificationEngine(cfg).qualify(case, 0.1)
    baseline = AblationQualificationAdapter(cfg, "baseline").qualify(case, 0.1)
    assert baseline == production


def test_report_mass_ablation_changes_mass_but_never_inflates_root_counts():
    cfg = _config()
    keys = KeyRegistry()
    case = _case(
        _attestation(keys, att_id="a1", root="same-root", source="rsu-1"),
        _attestation(keys, att_id="a2", root="same-root", source="rsu-2"),
    )
    baseline = VPUFTQualificationEngine(cfg).qualify(case, 0.1)
    report_level = AblationQualificationAdapter(cfg, "A_report_mass").qualify(case, 0.1)
    assert report_level.decision_margin > baseline.decision_margin
    assert report_level.independent_roots == baseline.independent_roots == 1
    assert report_level.distinct_sources == baseline.distinct_sources == 1
    assert report_level.distinct_zones == baseline.distinct_zones == 1
    assert report_level.correlated_suppressed == baseline.correlated_suppressed == 1
    assert not report_level.qualified  # the independent-root gate remains active


def test_report_mass_ablation_retains_opposition_instead_of_hiding_it():
    cfg = _config()
    keys = KeyRegistry()
    case = _case(
        _attestation(keys, att_id="support", root="same-root", source="rsu-1"),
        _attestation(
            keys, att_id="oppose", root="same-root", source="rsu-2",
            direction=EvidenceDirection.OPPOSES,
        ),
    )
    result = AblationQualificationAdapter(cfg, "A_report_mass").qualify(case, 0.1)
    assert result.supporting_strength > 0
    assert result.opposing_strength > 0
    assert result.independent_roots == 0
    assert not result.qualified


def test_diversity_gate_ablation_changes_only_qualification_gate():
    cfg = _config()
    keys = KeyRegistry()
    case = _case(_attestation(keys, att_id="a1", root="root-1", source="rsu-1"))
    baseline = VPUFTQualificationEngine(cfg).qualify(case, 0.1)
    no_diversity = AblationQualificationAdapter(cfg, "C_no_diversity_gates").qualify(case, 0.1)
    assert not baseline.qualified
    assert no_diversity.qualified
    for field in (
        "supporting_strength", "opposing_strength", "decision_margin", "independent_roots",
        "distinct_sources", "distinct_zones", "distinct_modalities", "correlated_suppressed",
        "expired_evidence", "cryptographic_decisive",
    ):
        assert getattr(no_diversity, field) == getattr(baseline, field)


def test_architecture_execution_uses_injected_counterfactual_adapter():
    cfg = _config()
    keys = KeyRegistry()
    case = _case(_attestation(keys, att_id="a1", root="root-1", source="rsu-1"))
    baseline_arch = CentralizedVPUFT(cfg, keys)
    ablated_arch = CentralizedVPUFT(cfg, keys)
    ablated_arch.engine = AblationQualificationAdapter(cfg, "C_no_diversity_gates")
    baseline_decision = baseline_arch.run([case], seed=7003).decisions[0]
    ablated_decision = ablated_arch.run([case], seed=7003).decisions[0]
    assert not (baseline_decision.committed and baseline_decision.new_state.value == "revoked")
    assert ablated_decision.committed and ablated_decision.new_state.value == "revoked"


def test_effective_variant_record_is_explicit_and_hashed():
    cfg = _config()
    record = effective_variant_record(cfg, "A_report_mass")
    assert record["variant_id"] == "A_report_mass"
    assert record["security_status"] == "insecure_counterfactual_not_for_deployment"
    assert record["effective_config_sha256"]
    assert record["production_configuration_unchanged"] is True
