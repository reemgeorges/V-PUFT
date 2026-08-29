from __future__ import annotations

from abc import ABC, abstractmethod
from dataclasses import replace

from ..config import ResearchConfig
from ..crypto import KeyRegistry
from ..domain import ArchitectureRunResult, EvidenceAttestation, EvidenceCase
from ..evidence import verify_attestation
from ..qualification import VPUFTQualificationEngine
from ..state_machine import TrustStateMachine


class Architecture(ABC):
    name: str

    def __init__(self, config: ResearchConfig, keys: KeyRegistry) -> None:
        self.config = config
        self.keys = keys
        self.engine = VPUFTQualificationEngine(config)
        self.state_machine = TrustStateMachine()

    def sanitize_case(self, case: EvidenceCase) -> EvidenceCase:
        clean = EvidenceCase(
            case_id=case.case_id,
            vehicle_id=case.vehicle_id,
            pseudonym=case.pseudonym,
            attack_type=case.attack_type,
            opened_at=case.opened_at,
            ground_truth_malicious=case.ground_truth_malicious,
        )
        seen_attestations: set[str] = set()
        for attestation in sorted(case.attestations, key=lambda a: (a.observed_at, a.attestation_id)):
            if attestation.attestation_id in seen_attestations:
                continue
            seen_attestations.add(attestation.attestation_id)
            validity = int(attestation.validity == 1 and verify_attestation(attestation, self.keys))
            if validity != attestation.validity:
                attestation = replace(attestation, validity=validity)
            clean.add(attestation)
        return clean

    def subset_case(self, case: EvidenceCase, attestations: list[EvidenceAttestation]) -> EvidenceCase:
        """Clone case metadata while retaining only attestations available at the decision point."""
        subset = EvidenceCase(
            case_id=case.case_id,
            vehicle_id=case.vehicle_id,
            pseudonym=case.pseudonym,
            attack_type=case.attack_type,
            opened_at=case.opened_at,
            ground_truth_malicious=case.ground_truth_malicious,
        )
        for attestation in attestations:
            subset.add(attestation)
        return subset

    def evidence_row(self, case: EvidenceCase, attestation: EvidenceAttestation, seed: int) -> dict:
        return {
            "architecture": self.name,
            "case_id": case.case_id,
            "observation_root_id": attestation.observation_root_id,
            "seed": seed,
            "attack_type": case.attack_type.value,
            "label": int(case.ground_truth_malicious),
            "validity": attestation.validity,
            "direction": int(attestation.direction),
            "source_id": attestation.source_id,
            "source_kind": attestation.source_kind,
            "validator_rsu_id": attestation.validator_rsu_id,
            "administrative_domain_id": attestation.administrative_domain_id,
            "geographic_cell": attestation.geographic_cell,
            "sensor_modality": attestation.sensor_modality,
            "detector_confidence": attestation.detector_confidence,
            "source_reliability": attestation.source_reliability,
            "freshness": attestation.freshness,
            "verifiability": attestation.verifiability,
            "independence": attestation.independence,
            "observed_at": attestation.observed_at,
            "reason_codes": "|".join(attestation.reason_codes),
        }

    @abstractmethod
    def run(self, cases: list[EvidenceCase], seed: int) -> ArchitectureRunResult:
        raise NotImplementedError
