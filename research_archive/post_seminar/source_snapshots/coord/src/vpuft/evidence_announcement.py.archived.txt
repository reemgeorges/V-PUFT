"""Verifier primitives for quorum-authenticated V-PUFT evidence announcements.

This module does not implement announcement transport, durable inventory, or
certificate dissemination. Callers must supply certificates already stored in
the validator's independent local inventory. It is deliberately inert until a
future architecture integrates those network and persistence guarantees.
"""

from __future__ import annotations

import unicodedata
from dataclasses import asdict, dataclass

from .config import PBFTConfig
from .consensus import canonical_case_identity
from .crypto import KeyRegistry, digest_hex
from .domain import EvidenceAttestation
from .evidence import verify_attestation


@dataclass(frozen=True, slots=True)
class EvidenceAnnouncementReceipt:
    validator_id: str
    signature: str


@dataclass(frozen=True, slots=True)
class EvidenceAvailabilityCertificate:
    attestation: EvidenceAttestation
    receipts: tuple[EvidenceAnnouncementReceipt, ...]


@dataclass(frozen=True, slots=True)
class EvidenceReconciliationResult:
    accepted: bool
    missing_attestation_ids: tuple[str, ...] = ()
    reason: str = "reconciled"


def _receipt_payload(attestation: EvidenceAttestation, validator_id: str, config: PBFTConfig) -> dict:
    return {
        "protocol": "V-PUFT-EVIDENCE-ANNOUNCEMENT-V1",
        "membership_digest": config.membership_digest,
        "case_id": canonical_case_identity(attestation.case_id),
        "attestation_id": attestation.attestation_id,
        "attestation_digest": digest_hex(asdict(attestation)),
        "observation_root_id": attestation.observation_root_id,
        "source_id": attestation.source_id,
        "direction": int(attestation.direction),
        "evidence_hash": attestation.evidence_hash,
        "validator_id": validator_id,
    }


def create_announcement_receipt(
    attestation: EvidenceAttestation,
    validator_id: str,
    config: PBFTConfig,
    keys: KeyRegistry,
) -> EvidenceAnnouncementReceipt:
    """Sign a receipt only for a valid original source-signed attestation."""
    config.validate()
    if validator_id not in config.validators:
        raise ValueError("Announcement receipt signer is outside the fixed validator membership")
    if attestation.validity != 1 or not verify_attestation(attestation, keys):
        raise ValueError("Cannot receipt invalid or unsigned evidence")
    payload = _receipt_payload(attestation, validator_id, config)
    return EvidenceAnnouncementReceipt(validator_id, keys.sign(validator_id, payload))


def verify_announcement_certificate(
    certificate: EvidenceAvailabilityCertificate,
    config: PBFTConfig,
    keys: KeyRegistry,
) -> bool:
    """Verify q distinct validator receipts for the exact signed attestation."""
    try:
        config.validate()
        attestation = certificate.attestation
        if attestation.validity != 1 or not verify_attestation(attestation, keys):
            return False
        validators = {
            unicodedata.normalize("NFC", validator).strip()
            for validator in config.validators
        }
        signers: set[str] = set()
        for receipt in certificate.receipts:
            signer = unicodedata.normalize("NFC", receipt.validator_id).strip()
            if signer not in validators or signer in signers:
                return False
            if not keys.verify(receipt.validator_id, _receipt_payload(attestation, receipt.validator_id, config), receipt.signature):
                return False
            signers.add(signer)
        return len(signers) >= config.resolved_quorum
    except (AttributeError, TypeError, ValueError):
        return False


def reconcile_announced_evidence(
    proposed_bundle: list[EvidenceAttestation] | tuple[EvidenceAttestation, ...],
    locally_certified: list[EvidenceAvailabilityCertificate] | tuple[EvidenceAvailabilityCertificate, ...],
    config: PBFTConfig,
    keys: KeyRegistry,
) -> EvidenceReconciliationResult:
    """Reject a proposal that omits locally known quorum-certified evidence.

    The local certificate inventory must be independent of the coordinator's
    proposal. This check preserves support, opposition, and neutral direction;
    it neither reclassifies reports nor changes root-independence rules.
    """
    expected: dict[str, str] = {}
    case_ids: set[str] = set()
    for certificate in locally_certified:
        if not verify_announcement_certificate(certificate, config, keys):
            return EvidenceReconciliationResult(False, reason="invalid_local_announcement_certificate")
        attestation = certificate.attestation
        case_ids.add(canonical_case_identity(attestation.case_id))
        item_id = attestation.attestation_id
        item_digest = digest_hex(asdict(attestation))
        old_digest = expected.get(item_id)
        if old_digest is not None and old_digest != item_digest:
            return EvidenceReconciliationResult(False, reason="attestation_id_equivocation")
        expected[item_id] = item_digest

    proposed: dict[str, str] = {}
    for attestation in proposed_bundle:
        case_ids.add(canonical_case_identity(attestation.case_id))
        if attestation.validity != 1 or not verify_attestation(attestation, keys):
            return EvidenceReconciliationResult(False, reason="invalid_bundle_attestation")
        item_id = attestation.attestation_id
        item_digest = digest_hex(asdict(attestation))
        old_digest = proposed.get(item_id)
        if old_digest is not None and old_digest != item_digest:
            return EvidenceReconciliationResult(False, reason="attestation_id_equivocation")
        proposed[item_id] = item_digest

    if len(case_ids) > 1:
        return EvidenceReconciliationResult(False, reason="announcement_case_mismatch")
    missing = tuple(sorted(
        item_id for item_id, item_digest in expected.items()
        if proposed.get(item_id) != item_digest
    ))
    if missing:
        return EvidenceReconciliationResult(False, missing, "missing_announced_evidence")
    return EvidenceReconciliationResult(True)
