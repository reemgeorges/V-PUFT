"""Authenticated evidence-announcement identities and local reconciliation.

Transport and validator-local inventory population are implemented by the
V5 distributed architecture. A receipt is signed only after the receiving
validator has the complete original attestation and verifies its source
signature; the receipt alone is not a claim that other validators received it.
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
    membership_digest: str = ""
    case_id: str = ""
    attestation_id: str = ""
    attestation_digest: str = ""


@dataclass(frozen=True, slots=True)
class EvidenceAvailabilityCertificate:
    attestation: EvidenceAttestation
    receipts: tuple[EvidenceAnnouncementReceipt, ...]


@dataclass(frozen=True, slots=True)
class EvidenceReconciliationResult:
    accepted: bool
    missing_attestation_ids: tuple[str, ...] = ()
    reason: str = "reconciled"


def evidence_bundle_digest(
    case_id: str,
    attestations: list[EvidenceAttestation] | tuple[EvidenceAttestation, ...],
    certificates: list[EvidenceAvailabilityCertificate] | tuple[EvidenceAvailabilityCertificate, ...],
    config: PBFTConfig,
) -> str:
    """Canonical digest binding the exact evidence, receipts, case and epoch."""
    canonical_case = canonical_case_identity(case_id)
    item_records = []
    seen_items: dict[str, str] = {}
    for attestation in attestations:
        if canonical_case_identity(attestation.case_id) != canonical_case:
            raise ValueError("Evidence bundle contains a different case identity")
        item_digest = digest_hex(asdict(attestation))
        previous = seen_items.get(attestation.attestation_id)
        if previous is not None:
            if previous != item_digest:
                raise ValueError("Evidence bundle reuses an attestation ID with a different payload")
            raise ValueError("Evidence bundle contains a duplicate attestation ID")
        seen_items[attestation.attestation_id] = item_digest
        item_records.append({"attestation_id": attestation.attestation_id, "digest": item_digest})

    certificate_records = []
    seen_certificates: set[str] = set()
    for certificate in certificates:
        attestation = certificate.attestation
        if canonical_case_identity(attestation.case_id) != canonical_case:
            raise ValueError("Evidence certificate contains a different case identity")
        if attestation.attestation_id in seen_certificates:
            raise ValueError("Evidence bundle contains duplicate availability certificates")
        seen_certificates.add(attestation.attestation_id)
        if seen_items.get(attestation.attestation_id) != digest_hex(asdict(attestation)):
            raise ValueError("Availability certificate does not match the included evidence")
        receipt_records = [
            {
                "validator_id": receipt.validator_id,
                "membership_digest": receipt.membership_digest,
                "case_id": receipt.case_id,
                "attestation_id": receipt.attestation_id,
                "attestation_digest": receipt.attestation_digest,
                "signature": receipt.signature,
            }
            for receipt in sorted(certificate.receipts, key=lambda item: item.validator_id)
        ]
        certificate_records.append({"attestation_id": attestation.attestation_id, "receipts": receipt_records})

    return digest_hex({
        "protocol": "V-PUFT-EVIDENCE-BUNDLE-V1",
        "membership_digest": config.membership_digest,
        "case_id": canonical_case,
        "attestations": sorted(item_records, key=lambda item: item["attestation_id"]),
        "availability_certificates": sorted(certificate_records, key=lambda item: item["attestation_id"]),
    })


class ValidatorEvidenceInventory:
    """Separate in-memory evidence inventory owned by one modeled validator.

    It is populated only after modeled delivery of the original signed
    payload. This simulator object is neither durable storage nor process/key
    isolation.
    """

    def __init__(self, validator_id: str, config: PBFTConfig, keys: KeyRegistry) -> None:
        config.validate()
        if validator_id not in config.validators:
            raise ValueError("Evidence inventory owner must be a current validator")
        self.validator_id = validator_id
        self.config = config
        self.keys = keys
        self.membership_digest = config.membership_digest
        self._attestations: dict[tuple[str, str], EvidenceAttestation] = {}
        self._receipts: dict[tuple[str, str], dict[str, EvidenceAnnouncementReceipt]] = {}

    @staticmethod
    def _key(attestation: EvidenceAttestation) -> tuple[str, str]:
        return canonical_case_identity(attestation.case_id), attestation.attestation_id

    def store_payload(self, attestation: EvidenceAttestation) -> bool:
        if attestation.validity != 1 or not verify_attestation(attestation, self.keys):
            return False
        key = self._key(attestation)
        previous = self._attestations.get(key)
        if previous is not None and digest_hex(asdict(previous)) != digest_hex(asdict(attestation)):
            raise ValueError("Conflicting payload for an existing case/attestation identity")
        self._attestations[key] = attestation
        return True

    def store_receipt(self, receipt: EvidenceAnnouncementReceipt) -> bool:
        if receipt.membership_digest != self.membership_digest:
            return False
        key = (canonical_case_identity(receipt.case_id), receipt.attestation_id)
        attestation = self._attestations.get(key)
        # Digest-only receipts are not evidence. Verify them only after the
        # matching complete signed payload is locally available.
        if attestation is None or not verify_announcement_receipt(attestation, receipt, self.config, self.keys):
            return False
        bucket = self._receipts.setdefault(key, {})
        previous = bucket.get(receipt.validator_id)
        if previous is not None and previous != receipt:
            return False
        bucket[receipt.validator_id] = receipt
        return True

    def get(self, case_id: str, attestation_id: str) -> EvidenceAttestation | None:
        return self._attestations.get((canonical_case_identity(case_id), attestation_id))

    def receipts_for(self, attestation: EvidenceAttestation) -> tuple[EvidenceAnnouncementReceipt, ...]:
        bucket = self._receipts.get(self._key(attestation), {})
        return tuple(bucket[key] for key in sorted(bucket))

    def certified(self, attestation: EvidenceAttestation) -> EvidenceAvailabilityCertificate | None:
        certificate = EvidenceAvailabilityCertificate(attestation, self.receipts_for(attestation))
        if verify_announcement_certificate(certificate, self.config, self.keys):
            return certificate
        return None

    def attestations_for(self, case_id: str) -> tuple[EvidenceAttestation, ...]:
        canonical = canonical_case_identity(case_id)
        return tuple(self._attestations[key] for key in sorted(self._attestations) if key[0] == canonical)

    def certificates_for(self, case_id: str) -> tuple[EvidenceAvailabilityCertificate, ...]:
        result = []
        for attestation in self.attestations_for(case_id):
            certificate = self.certified(attestation)
            if certificate is not None:
                result.append(certificate)
        return tuple(result)


def verify_announcement_receipt(
    attestation: EvidenceAttestation,
    receipt: EvidenceAnnouncementReceipt,
    config: PBFTConfig,
    keys: KeyRegistry,
) -> bool:
    """Verify one validator's payload-receipt assertion for this exact item."""
    try:
        config.validate()
        validators = {
            unicodedata.normalize("NFC", validator).strip()
            for validator in config.validators
        }
        signer = unicodedata.normalize("NFC", receipt.validator_id).strip()
        return (
            signer in validators
            and receipt.membership_digest == config.membership_digest
            and receipt.case_id == canonical_case_identity(attestation.case_id)
            and receipt.attestation_id == attestation.attestation_id
            and receipt.attestation_digest == digest_hex(asdict(attestation))
            and attestation.validity == 1
            and verify_attestation(attestation, keys)
            and keys.verify(
                receipt.validator_id,
                _receipt_payload(attestation, receipt.validator_id, config),
                receipt.signature,
            )
        )
    except (AttributeError, TypeError, ValueError):
        return False


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
    return EvidenceAnnouncementReceipt(
        validator_id=validator_id,
        signature=keys.sign(validator_id, payload),
        membership_digest=config.membership_digest,
        case_id=canonical_case_identity(attestation.case_id),
        attestation_id=attestation.attestation_id,
        attestation_digest=digest_hex(asdict(attestation)),
    )


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
            if not verify_announcement_receipt(attestation, receipt, config, keys):
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
    locally_observed: list[EvidenceAttestation] | tuple[EvidenceAttestation, ...] = (),
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

    # A validator also reconciles evidence it personally received, even when
    # receipt gossip did not yet produce a quorum certificate. This is
    # conservative: a locally known omission can block voting, but it cannot
    # create evidence or change its provenance.
    for attestation in locally_observed:
        if attestation.validity != 1 or not verify_attestation(attestation, keys):
            return EvidenceReconciliationResult(False, reason="invalid_local_observation")
        item_id = attestation.attestation_id
        item_digest = digest_hex(asdict(attestation))
        old_digest = expected.get(item_id)
        if old_digest is not None and old_digest != item_digest:
            return EvidenceReconciliationResult(False, reason="attestation_id_equivocation")
        expected[item_id] = item_digest
        case_ids.add(canonical_case_identity(attestation.case_id))

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
