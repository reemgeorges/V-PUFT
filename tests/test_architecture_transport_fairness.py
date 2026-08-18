from dataclasses import replace

from vpuft.architectures.ahmed_witness import AhmedInspiredWitnessVPUFT
from vpuft.architectures.centralized import CentralizedVPUFT
from vpuft.architectures.distributed_rsu import DistributedRSUVPUFT
from vpuft.config import ResearchConfig
from vpuft.crypto import KeyRegistry
from vpuft.domain import AttackType, EvidenceAttestation, EvidenceCase, EvidenceDirection
from vpuft.evidence import sign_attestation


def _config(pdr: float) -> ResearchConfig:
    cfg = ResearchConfig()
    return replace(
        cfg,
        network=replace(cfg.network, packet_delivery_ratio=pdr, max_retries=0),
        central=replace(cfg.central, availability=1.0),
    )


def _attestation(keys: KeyRegistry, *, idx: int, source: str, source_kind: str, validator: str) -> EvidenceAttestation:
    att = EvidenceAttestation(
        attestation_id=f"att-{idx}",
        case_id="case-1",
        observation_root_id=f"root-{idx}",
        source_id=source,
        source_kind=source_kind,
        validator_rsu_id=validator,
        administrative_domain_id=f"domain-{idx}",
        sensor_modality="rsu_cam_plausibility" if source_kind == "rsu" else "vehicle_witness_observation",
        geographic_cell=f"zone-{idx}",
        attack_type=AttackType.FLOOD,
        direction=EvidenceDirection.SUPPORTS,
        detector_confidence=0.99,
        source_reliability=0.99,
        freshness=0.99,
        verifiability=0.99,
        independence=0.99,
        observed_at=1.0 + idx * 0.01,
        evidence_hash=f"hash-{idx}",
        signature="",
        public_key_id="",
        validity=1,
        reason_codes=("flood_rate",),
    )
    return sign_attestation(att, keys, source)


def _rsu_case(keys: KeyRegistry) -> EvidenceCase:
    case = EvidenceCase("case-1", "veh-1", "ps-1", AttackType.FLOOD, 1.0, True)
    case.add(_attestation(keys, idx=1, source="rsu-1", source_kind="rsu", validator="rsu-1"))
    case.add(_attestation(keys, idx=2, source="rsu-2", source_kind="rsu", validator="rsu-2"))
    return case


def _witness_case(keys: KeyRegistry) -> EvidenceCase:
    case = EvidenceCase("case-1", "veh-1", "ps-1", AttackType.FLOOD, 1.0, True)
    case.add(_attestation(keys, idx=1, source="wit-1", source_kind="vehicle_witness", validator="rsu-1"))
    case.add(_attestation(keys, idx=2, source="wit-2", source_kind="vehicle_witness", validator="rsu-2"))
    return case


def test_centralized_qualification_uses_only_delivered_attestations():
    keys = KeyRegistry()
    delivered = CentralizedVPUFT(_config(1.0), keys).run([_rsu_case(keys)], 1001)
    dropped = CentralizedVPUFT(_config(0.0), keys).run([_rsu_case(keys)], 1001)
    assert delivered.decisions[0].committed is True
    assert dropped.decisions[0].committed is False
    assert len(delivered.evidence_rows) == 2
    assert len(dropped.evidence_rows) == 0


def test_distributed_exchanges_remote_rsu_evidence_before_qualification():
    keys = KeyRegistry()
    delivered = DistributedRSUVPUFT(_config(1.0), keys).run([_rsu_case(keys)], 1001)
    dropped = DistributedRSUVPUFT(_config(0.0), keys).run([_rsu_case(keys)], 1001)
    types = [m.message_type for m in delivered.messages]
    assert "RSU_EVIDENCE_EXCHANGE" in types
    assert delivered.decisions[0].committed is True
    assert dropped.decisions[0].committed is False
    assert len(delivered.evidence_rows) == 2
    assert len(dropped.evidence_rows) == 1  # coordinator-local evidence remains available


def test_ahmed_witness_requires_delivered_reports_and_forwards_remote_evidence():
    keys = KeyRegistry()
    delivered = AhmedInspiredWitnessVPUFT(_config(1.0), keys).run([_witness_case(keys)], 1001)
    dropped = AhmedInspiredWitnessVPUFT(_config(0.0), keys).run([_witness_case(keys)], 1001)
    types = [m.message_type for m in delivered.messages]
    assert "WITNESS_REPORT_TO_RSU" in types
    assert "RSU_WITNESS_EVIDENCE_FORWARD" in types
    assert delivered.decisions[0].committed is True
    assert dropped.decisions[0].committed is False
    assert delivered.decisions[0].metadata["independent_roots"] == 2
    assert dropped.decisions[0].metadata["independent_roots"] == 0
    assert len(delivered.evidence_rows) == 2
    assert len(dropped.evidence_rows) == 0
