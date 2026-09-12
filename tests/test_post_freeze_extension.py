from dataclasses import replace

from vpuft.architectures import DistributedRSUExtendedVPUFT
from vpuft.config import DistributedExtensionConfig, NetworkConfig, PBFTConfig, ResearchConfig, SimulationConfig, TrustCacheConfig
from vpuft.consensus import PBFTConsensus
from vpuft.crypto import KeyRegistry
from vpuft.domain import AttackType, EvidenceAttestation, EvidenceCase, EvidenceDirection, TrustState
from vpuft.evidence import sign_attestation
from vpuft.extension_campaign import run_extension_campaign
from vpuft.network import SimulatedTransport
from vpuft.trust_cache import QuorumTrustTokenService


def _support(keys, index):
    source = f"rsu-{index}"
    unsigned = EvidenceAttestation(
        attestation_id=f"att-{index}",
        case_id="case-guard",
        observation_root_id=f"root-{index}",
        source_id=source,
        source_kind="rsu",
        validator_rsu_id=source,
        administrative_domain_id=f"domain-{index}",
        sensor_modality="cam",
        geographic_cell=f"zone-{index}",
        attack_type=AttackType.POSITION_OFFSET,
        direction=EvidenceDirection.SUPPORTS,
        detector_confidence=0.95,
        source_reliability=0.95,
        freshness=0.95,
        verifiability=0.95,
        independence=0.95,
        observed_at=1.0,
        evidence_hash=f"hash-{index}",
        signature="",
        public_key_id="",
    )
    return sign_attestation(unsigned, keys, source)


def test_quorum_token_is_time_bounded_and_requires_current_checkpoint():
    config = ResearchConfig()
    keys = KeyRegistry(config.security.deterministic_master_seed)
    service = QuorumTrustTokenService(config, keys)
    token = service.issue(
        subject_pseudonym="ps-vehicle-b",
        state=TrustState.TRUSTED,
        issued_at=10.0,
        ttl_seconds=5.0,
        ledger_height=7,
        checkpoint_hash="abc",
        decision_id="decision-7",
    )
    assert service.verify(token, now=14.9, minimum_ledger_height=7)
    assert not service.verify(token, now=15.1, minimum_ledger_height=7)
    assert not service.verify(token, now=14.9, minimum_ledger_height=8)


def test_invalid_leader_proposal_activates_fault_then_changes_view():
    pbft_config = PBFTConfig(validator_behaviors={"rsu-1": "propose_invalid"})
    config = ResearchConfig(pbft=pbft_config, network=NetworkConfig(packet_delivery_ratio=1.0))
    keys = KeyRegistry(config.security.deterministic_master_seed)
    consensus = PBFTConsensus(config.pbft, SimulatedTransport(config.network, 44), keys)
    outcome = consensus.finalize(
        case_id="case-1",
        payload={"requested_state": "revoked"},
        started_at=1.0,
        preferred_leader="rsu-1",
        validator_checks={validator: True for validator in config.pbft.validators},
    )
    assert outcome.committed
    assert outcome.fault_activated
    assert outcome.invalid_proposal_attempted
    assert outcome.view_changes == 1
    assert outcome.leader == "rsu-2"


def test_leave_one_source_out_guard_requires_redundancy_beyond_one_rsu():
    config = ResearchConfig(distributed_extension=DistributedExtensionConfig(
        leave_one_source_out_guard=True,
        guard_on_directional_conflict_only=False,
    ))
    keys = KeyRegistry(config.security.deterministic_master_seed)
    architecture = DistributedRSUExtendedVPUFT(config, keys)
    two_sources = EvidenceCase("case-guard", "veh-1", "ps-1", AttackType.POSITION_OFFSET, 0.0, True)
    two_sources.attestations.extend([_support(keys, 1), _support(keys, 2)])
    base = architecture.engine.qualify(two_sources, 1.0)
    guarded, _, stable = architecture._apply_evidence_source_guard(two_sources, base, 1.0)
    assert base.qualified
    assert not guarded.qualified
    assert not stable

    three_sources = EvidenceCase("case-guard", "veh-1", "ps-1", AttackType.POSITION_OFFSET, 0.0, True)
    three_sources.attestations.extend([_support(keys, 1), _support(keys, 2), _support(keys, 3)])
    base = architecture.engine.qualify(three_sources, 1.0)
    guarded, checks, stable = architecture._apply_evidence_source_guard(three_sources, base, 1.0)
    assert guarded.qualified
    assert stable
    assert checks == 3


def test_extension_campaign_does_not_rerun_centralized_near_edge(tmp_path):
    config = ResearchConfig(
        network=NetworkConfig(packet_delivery_ratio=1.0),
        simulation=SimulationConfig(seeds=(1001,), cases_per_seed=8, malicious_ratio=0.4, rsu_count=6),
        trust_cache=TrustCacheConfig(
            ttl_seconds=(0.0, 2.0),
            vehicle_counts=(8,),
            interactions_per_vehicle=3,
        ),
    )
    manifest = run_extension_campaign(config, tmp_path)
    assert manifest["centralized_near_edge_rerun"] is False
    assert all("centralized" not in name for name in manifest["variants"])
    assert (tmp_path / "extension_case_agreement.csv").exists()
    assert (tmp_path / "v2v_trust_cache_sensitivity.csv").exists()


def test_non_validator_rsus_receive_read_only_ledger_cache():
    config = ResearchConfig(
        network=NetworkConfig(packet_delivery_ratio=1.0),
        simulation=SimulationConfig(seeds=(1001,), cases_per_seed=8, malicious_ratio=0.4, rsu_count=6),
    )
    keys = KeyRegistry(config.security.deterministic_master_seed)
    architecture = DistributedRSUExtendedVPUFT(config, keys)
    case = EvidenceCase("case-guard", "veh-1", "ps-1", AttackType.POSITION_OFFSET, 0.0, True)
    case.attestations.extend([_support(keys, 1), _support(keys, 2), _support(keys, 3)])
    result = architecture.run([case], seed=1001)
    cache_sync_receivers = {
        message.receiver
        for message in result.messages
        if message.message_type == "RSU_READ_CACHE_SYNC"
    }
    assert cache_sync_receivers == {"rsu-5", "rsu-6"}
    assert result.ledger_consistent
    assert result.extension_metrics["writable_validator_replicas"] == 4
    assert result.extension_metrics["readable_rsu_replicas"] == 6
