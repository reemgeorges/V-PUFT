from __future__ import annotations

from dataclasses import replace
from hashlib import sha256
from statistics import median

from .crypto import KeyRegistry
from .domain import EvidenceAttestation, EvidenceCase, EvidenceDirection
from .evidence import sign_attestation


def inject_compromised_rsu_evidence(
    cases: list[EvidenceCase],
    *,
    keys: KeyRegistry,
    compromised_rsu: str,
    correlated_copies: int,
    mode: str,
) -> tuple[list[EvidenceCase], list[dict]]:
    """Inject validly signed but semantically false RSU reports.

    All copies share one observation root per case.  Therefore repetition tests
    root-level de-correlation rather than manufacturing fake independence.
    Ground truth is used by this experiment harness only to select the attack's
    direction; it never enters V-PUFT qualification.
    """

    attacked: list[EvidenceCase] = []
    audit: list[dict] = []
    known_source_reports = [
        attestation
        for case in cases
        for attestation in case.attestations
        if attestation.source_id == compromised_rsu
    ]
    source_reliability = median(
        [attestation.source_reliability for attestation in known_source_reports]
    ) if known_source_reports else 0.85
    source_independence = median(
        [attestation.independence for attestation in known_source_reports]
    ) if known_source_reports else 0.80
    for case in cases:
        clone = EvidenceCase(
            case_id=case.case_id,
            vehicle_id=case.vehicle_id,
            pseudonym=case.pseudonym,
            attack_type=case.attack_type,
            opened_at=case.opened_at,
            ground_truth_malicious=case.ground_truth_malicious,
            attestations=list(case.attestations),
        )
        should_attack = (
            (mode in {"false_accusation", "both"} and not case.ground_truth_malicious)
            or (mode in {"concealment", "both"} and case.ground_truth_malicious)
        )
        if not case.attestations or not should_attack:
            attacked.append(clone)
            continue
        template = min(case.attestations, key=lambda item: (item.observed_at, item.attestation_id))
        false_direction = (
            EvidenceDirection.OPPOSES if case.ground_truth_malicious
            else EvidenceDirection.SUPPORTS
        )
        root = f"forged-root-{sha256((case.case_id + compromised_rsu).encode()).hexdigest()[:20]}"
        for copy_index in range(correlated_copies):
            unsigned: EvidenceAttestation = replace(
                template,
                attestation_id=f"forged-{case.case_id}-{compromised_rsu}-{copy_index}",
                observation_root_id=root,
                source_id=compromised_rsu,
                source_kind="rsu",
                validator_rsu_id=compromised_rsu,
                administrative_domain_id=f"compromised-domain-{compromised_rsu}",
                sensor_modality="compromised_rsu_report",
                direction=false_direction,
                detector_confidence=0.99,
                # Reputation is verifier-owned state.  A compromised RSU cannot
                # grant itself a 0.99 reputation merely by signing that claim.
                source_reliability=source_reliability,
                freshness=0.99,
                # A valid RSU signature authenticates the false report's source;
                # it is not an independently checkable cryptographic proof of
                # the report's semantic truth.
                verifiability=min(template.verifiability, 0.90),
                independence=source_independence,
                observed_at=template.observed_at + copy_index * 0.0001,
                evidence_hash=sha256(f"{root}|{copy_index}|{int(false_direction)}".encode()).hexdigest(),
                signature="",
                public_key_id="",
                validity=1,
                reason_codes=("compromised_rsu_semantic_forgery", "correlated_copy"),
            )
            clone.add(sign_attestation(unsigned, keys, compromised_rsu))
            audit.append({
                "case_id": case.case_id,
                "vehicle_id": case.vehicle_id,
                "ground_truth_malicious": int(case.ground_truth_malicious),
                "compromised_rsu": compromised_rsu,
                "forged_attestation_id": unsigned.attestation_id,
                "forged_observation_root_id": root,
                "false_direction": int(false_direction),
                "assigned_source_reliability": source_reliability,
                "assigned_verifiability": min(template.verifiability, 0.90),
                "attack_mode": mode,
                "fault_activated": 1,
            })
        attacked.append(clone)
    return attacked, audit
