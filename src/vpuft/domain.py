from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Mapping


class TrustState(str, Enum):
    PROVISIONAL = "provisional"
    TRUSTED = "trusted"
    SUSPECTED = "suspected"
    QUARANTINED = "quarantined"
    REVOCATION_PENDING = "revocation_pending"
    REVOKED = "revoked"


class EvidenceDirection(int, Enum):
    OPPOSES = -1
    NEUTRAL = 0
    SUPPORTS = 1


class AttackType(str, Enum):
    BENIGN = "benign"
    POSITION_OFFSET = "position_offset"
    SPEED_OFFSET = "speed_offset"
    REPLAY = "replay"
    CERTIFICATE_TAMPER = "certificate_tamper"
    FLOOD = "flood"
    FALSE_DENM = "false_denm"
    MIXED = "mixed"


class SourceKind(str, Enum):
    RSU = "rsu"
    VEHICLE_WITNESS = "vehicle_witness"


@dataclass(frozen=True, slots=True)
class MobilitySnapshot:
    seed: int
    simulation_time: float
    vehicle_id: str
    x: float
    y: float
    speed_mps: float
    acceleration_mps2: float
    lane_id: str
    lane_position_m: float
    road_id: str


@dataclass(frozen=True, slots=True)
class V2XMessage:
    message_id: str
    original_message_id: str
    case_id: str
    observation_root_id: str
    seed: int
    sender_vehicle_id: str
    pseudonym: str
    message_type: str
    generated_at: float
    true_x: float
    true_y: float
    true_speed_mps: float
    true_acceleration_mps2: float
    reported_x: float
    reported_y: float
    reported_speed_mps: float
    reported_acceleration_mps2: float
    nonce: str
    certificate_valid: bool
    denm_claimed: bool
    attack_type: AttackType
    ground_truth_malicious: bool
    retransmission_index: int = 0
    payload: Mapping[str, Any] = field(default_factory=dict)


@dataclass(frozen=True, slots=True)
class DetectionEvent:
    event_id: str
    case_id: str
    observation_root_id: str
    seed: int
    vehicle_id: str
    pseudonym: str
    message_id: str
    attack_type: AttackType
    detected_by: str
    source_kind: SourceKind
    validator_rsu_id: str
    detected_at: float
    ground_truth_malicious: bool
    direction: EvidenceDirection
    detector_confidence: float
    source_reliability: float
    freshness: float
    verifiability: float
    independence: float
    raw_evidence_hash: str
    geographic_cell: str
    administrative_domain_id: str
    sensor_modality: str
    reason_codes: tuple[str, ...] = ()
    payload: Mapping[str, Any] = field(default_factory=dict)


@dataclass(frozen=True, slots=True)
class EvidenceAttestation:
    attestation_id: str
    case_id: str
    observation_root_id: str
    source_id: str
    source_kind: str
    validator_rsu_id: str
    administrative_domain_id: str
    sensor_modality: str
    geographic_cell: str
    attack_type: AttackType
    direction: EvidenceDirection
    detector_confidence: float
    source_reliability: float
    freshness: float
    verifiability: float
    independence: float
    observed_at: float
    evidence_hash: str
    signature: str
    public_key_id: str
    validity: int = 1
    reason_codes: tuple[str, ...] = ()

    def factors(self) -> dict[str, float]:
        return {
            "C": self.detector_confidence,
            "rho": self.source_reliability,
            "F": self.freshness,
            "Q": self.verifiability,
            "eta": self.independence,
        }


@dataclass(slots=True)
class EvidenceCase:
    case_id: str
    vehicle_id: str
    pseudonym: str
    attack_type: AttackType
    opened_at: float
    ground_truth_malicious: bool
    attestations: list[EvidenceAttestation] = field(default_factory=list)

    def add(self, attestation: EvidenceAttestation) -> None:
        if attestation.case_id != self.case_id:
            raise ValueError("Attestation belongs to a different case")
        if attestation.attack_type != self.attack_type:
            raise ValueError("Attestation attack type does not match the evidence case")
        self.attestations.append(attestation)


@dataclass(frozen=True, slots=True)
class QualificationResult:
    case_id: str
    qualified: bool
    supporting_strength: float
    opposing_strength: float
    decision_margin: float
    independent_roots: int
    distinct_sources: int
    distinct_zones: int
    distinct_modalities: int
    correlated_suppressed: int
    expired_evidence: int
    reason: str
    cryptographic_decisive: bool = False


@dataclass(frozen=True, slots=True)
class TrustDecision:
    case_id: str
    vehicle_id: str
    architecture: str
    previous_state: TrustState
    new_state: TrustState
    detected_at: float | None
    qualified_at: float | None
    finalized_at: float | None
    ledger_available_at: float | None
    decision_margin: float
    committed: bool
    reason: str
    metadata: Mapping[str, Any] = field(default_factory=dict)


@dataclass(frozen=True, slots=True)
class NetworkMessage:
    message_id: str
    message_type: str
    sender: str
    receiver: str
    case_id: str
    sent_at: float
    size_bytes: int
    delivered_at: float | None
    dropped: bool
    retransmission: int = 0
    queue_delay_ms: float = 0.0


@dataclass(frozen=True, slots=True)
class ConsensusOutcome:
    case_id: str
    committed: bool
    view: int
    leader: str | None
    prepare_votes: int
    commit_votes: int
    started_at: float
    committed_at: float | None
    view_changes: int
    reason: str
    message_count: int
    bytes_sent: int
    safety_violation: bool = False
    semantic_proposal_valid: bool = True
    fault_activated: bool = False
    validator_rechecks: int = 0
    validator_recheck_failures: int = 0
    invalid_proposal_attempted: bool = False


@dataclass(frozen=True, slots=True)
class ArchitectureRunResult:
    architecture: str
    decisions: list[TrustDecision]
    messages: list[NetworkMessage]
    consensus: list[ConsensusOutcome]
    ledger_blocks: int
    evidence_rows: list[dict[str, Any]]
    runtime_seconds: float
    ledger_consistent: bool = True
    state_recoveries: int = 0
    extension_metrics: Mapping[str, Any] = field(default_factory=dict)
