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
class EvidenceAnnouncementBatch:
    """Exact full-payload batch acknowledged by each signing validator."""

    case_id: str
    sender_id: str
    membership_digest: str
    collection_closed_at: float | None
    attestations: tuple[EvidenceAttestation, ...]
    batch_digest: str


@dataclass(frozen=True, slots=True)
class EvidenceBatchReceipt:
    validator_id: str
    membership_digest: str
    case_id: str
    batch_digest: str
    attestation_count: int
    signature: str


@dataclass(frozen=True, slots=True)
class EvidenceBatchAvailabilityCertificate:
    batch: EvidenceAnnouncementBatch
    receipts: tuple[EvidenceBatchReceipt, ...]


class EvidenceVerificationCache:
    """Run-local cache for exact immutable evidence and receipt objects.

    Each validator inventory owns its own cache. Keys include full frozen
    dataclass values and the membership digest where relevant; changing any
    signed field, receipt, or epoch therefore misses the cache.
    """

    def __init__(self, keys: KeyRegistry) -> None:
        self.keys = keys
        self._attestations: dict[EvidenceAttestation, bool] = {}
        self._receipts: dict[tuple[EvidenceAttestation, EvidenceAnnouncementReceipt, str], bool] = {}
        self._batches: dict[tuple[EvidenceAnnouncementBatch, str], bool] = {}
        self._batch_receipts: dict[tuple[EvidenceAnnouncementBatch, EvidenceBatchReceipt, str], bool] = {}

    def verify_attestation(self, attestation: EvidenceAttestation) -> bool:
        if attestation not in self._attestations:
            self._attestations[attestation] = attestation.validity == 1 and verify_attestation(attestation, self.keys)
        return self._attestations[attestation]

    def _get_receipt(self, key):
        return self._receipts.get(key)

    def _put_receipt(self, key, value: bool) -> bool:
        self._receipts[key] = value
        return value

    def _get_batch(self, key):
        return self._batches.get(key)

    def _put_batch(self, key, value: bool) -> bool:
        self._batches[key] = value
        return value

    def _get_batch_receipt(self, key):
        return self._batch_receipts.get(key)

    def _put_batch_receipt(self, key, value: bool) -> bool:
        self._batch_receipts[key] = value
        return value


def _verify_attestation(attestation: EvidenceAttestation, keys: KeyRegistry,
                        cache: EvidenceVerificationCache | None) -> bool:
    return cache.verify_attestation(attestation) if cache is not None else (
        attestation.validity == 1 and verify_attestation(attestation, keys)
    )


def evidence_announcement_batch_digest(
    case_id: str,
    sender_id: str,
    attestations: list[EvidenceAttestation] | tuple[EvidenceAttestation, ...],
    config: PBFTConfig,
    collection_closed_at: float | None = None,
) -> str:
    """Hash the complete, individually signed item list in one closed batch."""
    canonical_case = canonical_case_identity(case_id)
    records = []
    seen: set[str] = set()
    for attestation in attestations:
        if canonical_case_identity(attestation.case_id) != canonical_case:
            raise ValueError("Batch contains an attestation from a different case")
        if attestation.attestation_id in seen:
            raise ValueError("Batch contains a duplicate attestation ID")
        if collection_closed_at is not None and attestation.observed_at >= collection_closed_at:
            raise ValueError("Attestation observed after collection closure")
        seen.add(attestation.attestation_id)
        records.append({"attestation_id": attestation.attestation_id, "digest": digest_hex(asdict(attestation))})
    if not records:
        raise ValueError("Evidence batch must contain at least one complete attestation")
    return digest_hex({
        "protocol": "V-PUFT-EVIDENCE-ANNOUNCEMENT-BATCH-V1",
        "membership_digest": config.membership_digest,
        "case_id": canonical_case,
        "sender_id": unicodedata.normalize("NFC", sender_id).strip(),
        "collection_closed_at": collection_closed_at,
        "attestations": sorted(records, key=lambda record: record["attestation_id"]),
    })


def create_evidence_batch(
    case_id: str,
    sender_id: str,
    attestations: list[EvidenceAttestation] | tuple[EvidenceAttestation, ...],
    config: PBFTConfig,
    keys: KeyRegistry,
    *,
    collection_closed_at: float | None = None,
) -> EvidenceAnnouncementBatch:
    config.validate()
    canonical_case = canonical_case_identity(case_id)
    items = tuple(sorted(attestations, key=lambda item: item.attestation_id))
    for item in items:
        if item.validity != 1 or not verify_attestation(item, keys):
            raise ValueError("Batch contains invalid or unsigned evidence")
    batch_digest = evidence_announcement_batch_digest(
        canonical_case, sender_id, items, config, collection_closed_at
    )
    return EvidenceAnnouncementBatch(
        case_id=canonical_case,
        sender_id=unicodedata.normalize("NFC", sender_id).strip(),
        membership_digest=config.membership_digest,
        collection_closed_at=collection_closed_at,
        attestations=items,
        batch_digest=batch_digest,
    )


def _batch_receipt_payload(batch: EvidenceAnnouncementBatch, validator_id: str) -> dict:
    return {
        "protocol": "V-PUFT-EVIDENCE-BATCH-RECEIPT-V1",
        "membership_digest": batch.membership_digest,
        "case_id": batch.case_id,
        "sender_id": batch.sender_id,
        "batch_digest": batch.batch_digest,
        "attestation_count": len(batch.attestations),
        "validator_id": validator_id,
    }


def _valid_evidence_batch(batch: EvidenceAnnouncementBatch, config: PBFTConfig, keys: KeyRegistry,
                         cache: EvidenceVerificationCache | None = None) -> bool:
    try:
        config.validate()
        cache_key = (batch, config.membership_digest)
        if cache is not None:
            cached = cache._get_batch(cache_key)
            if cached is not None:
                return cached
        if batch.membership_digest != config.membership_digest:
            return cache._put_batch(cache_key, False) if cache is not None else False
        if batch.case_id != canonical_case_identity(batch.case_id):
            return cache._put_batch(cache_key, False) if cache is not None else False
        if not batch.attestations:
            return cache._put_batch(cache_key, False) if cache is not None else False
        if any(not _verify_attestation(item, keys, cache) for item in batch.attestations):
            return cache._put_batch(cache_key, False) if cache is not None else False
        valid = batch.batch_digest == evidence_announcement_batch_digest(
            batch.case_id, batch.sender_id, batch.attestations, config, batch.collection_closed_at
        )
        return cache._put_batch(cache_key, valid) if cache is not None else valid
    except (AttributeError, TypeError, ValueError):
        return False


def create_batch_receipt(
    batch: EvidenceAnnouncementBatch,
    validator_id: str,
    config: PBFTConfig,
    keys: KeyRegistry,
    *,
    cache: EvidenceVerificationCache | None = None,
) -> EvidenceBatchReceipt:
    config.validate()
    if validator_id not in config.validators:
        raise ValueError("Batch receipt signer is outside the fixed validator membership")
    if not _valid_evidence_batch(batch, config, keys, cache):
        raise ValueError("Cannot receipt an invalid or incomplete evidence batch")
    return EvidenceBatchReceipt(
        validator_id=validator_id,
        membership_digest=batch.membership_digest,
        case_id=batch.case_id,
        batch_digest=batch.batch_digest,
        attestation_count=len(batch.attestations),
        signature=keys.sign(validator_id, _batch_receipt_payload(batch, validator_id)),
    )


def verify_batch_receipt(
    batch: EvidenceAnnouncementBatch,
    receipt: EvidenceBatchReceipt,
    config: PBFTConfig,
    keys: KeyRegistry,
    *,
    cache: EvidenceVerificationCache | None = None,
) -> bool:
    try:
        config.validate()
        cache_key = (batch, receipt, config.membership_digest)
        if cache is not None:
            cached = cache._get_batch_receipt(cache_key)
            if cached is not None:
                return cached
        validators = {unicodedata.normalize("NFC", item).strip() for item in config.validators}
        signer = unicodedata.normalize("NFC", receipt.validator_id).strip()
        valid = (
            _valid_evidence_batch(batch, config, keys, cache)
            and signer in validators
            and receipt.membership_digest == config.membership_digest
            and receipt.case_id == batch.case_id
            and receipt.batch_digest == batch.batch_digest
            and receipt.attestation_count == len(batch.attestations)
            and keys.verify(receipt.validator_id, _batch_receipt_payload(batch, receipt.validator_id), receipt.signature)
        )
        return cache._put_batch_receipt(cache_key, valid) if cache is not None else valid
    except (AttributeError, TypeError, ValueError):
        return False


def verify_batch_availability_certificate(
    certificate: EvidenceBatchAvailabilityCertificate,
    config: PBFTConfig,
    keys: KeyRegistry,
    *,
    cache: EvidenceVerificationCache | None = None,
) -> bool:
    try:
        if not _valid_evidence_batch(certificate.batch, config, keys, cache):
            return False
        validators = {unicodedata.normalize("NFC", item).strip() for item in config.validators}
        signers: set[str] = set()
        for receipt in certificate.receipts:
            signer = unicodedata.normalize("NFC", receipt.validator_id).strip()
            if signer not in validators or signer in signers:
                return False
            if not verify_batch_receipt(certificate.batch, receipt, config, keys, cache=cache):
                return False
            signers.add(signer)
        return len(signers) >= config.resolved_quorum
    except (AttributeError, TypeError, ValueError):
        return False


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
    *,
    batch_certificates: list[EvidenceBatchAvailabilityCertificate] | tuple[EvidenceBatchAvailabilityCertificate, ...] = (),
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

    batch_certificate_records = []
    batch_certified_ids: set[str] = set()
    seen_batch_digests: set[str] = set()
    for certificate in batch_certificates:
        batch = certificate.batch
        if canonical_case_identity(batch.case_id) != canonical_case:
            raise ValueError("Evidence batch certificate contains a different case identity")
        if batch.batch_digest in seen_batch_digests:
            raise ValueError("Evidence bundle contains duplicate batch certificates")
        seen_batch_digests.add(batch.batch_digest)
        for attestation in batch.attestations:
            item_id = attestation.attestation_id
            item_digest = digest_hex(asdict(attestation))
            if seen_items.get(item_id) != item_digest:
                raise ValueError("Batch certificate does not match the included evidence")
            if item_id in batch_certified_ids:
                raise ValueError("Evidence item is covered by multiple batch certificates")
            batch_certified_ids.add(item_id)
        receipt_records = [
            {
                "validator_id": receipt.validator_id,
                "membership_digest": receipt.membership_digest,
                "case_id": receipt.case_id,
                "batch_digest": receipt.batch_digest,
                "attestation_count": receipt.attestation_count,
                "signature": receipt.signature,
            }
            for receipt in sorted(certificate.receipts, key=lambda item: item.validator_id)
        ]
        batch_certificate_records.append({"batch_digest": batch.batch_digest, "receipts": receipt_records})

    return digest_hex({
        "protocol": "V-PUFT-EVIDENCE-BUNDLE-V1",
        "membership_digest": config.membership_digest,
        "case_id": canonical_case,
        "attestations": sorted(item_records, key=lambda item: item["attestation_id"]),
        "availability_certificates": sorted(certificate_records, key=lambda item: item["attestation_id"]),
        "batch_availability_certificates": sorted(
            batch_certificate_records, key=lambda item: item["batch_digest"]
        ),
    })


class ValidatorEvidenceInventory:
    """Separate in-memory evidence inventory owned by one modeled validator.

    It is populated only after modeled delivery of the original signed
    payload. This simulator object is neither durable storage nor process/key
    isolation.
    """

    def __init__(self, validator_id: str, config: PBFTConfig, keys: KeyRegistry,
                 *, verification_cache_enabled: bool = False) -> None:
        config.validate()
        if validator_id not in config.validators:
            raise ValueError("Evidence inventory owner must be a current validator")
        self.validator_id = validator_id
        self.config = config
        self.keys = keys
        self.verification_cache = EvidenceVerificationCache(keys) if verification_cache_enabled else None
        self.membership_digest = config.membership_digest
        self._attestations: dict[tuple[str, str], EvidenceAttestation] = {}
        self._receipts: dict[tuple[str, str], dict[str, EvidenceAnnouncementReceipt]] = {}
        self._batches: dict[tuple[str, str], EvidenceAnnouncementBatch] = {}
        self._batch_receipts: dict[tuple[str, str], dict[str, EvidenceBatchReceipt]] = {}

    @staticmethod
    def _key(attestation: EvidenceAttestation) -> tuple[str, str]:
        return canonical_case_identity(attestation.case_id), attestation.attestation_id

    def store_payload(self, attestation: EvidenceAttestation) -> bool:
        if not _verify_attestation(attestation, self.keys, self.verification_cache):
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
        if attestation is None or not verify_announcement_receipt(
            attestation, receipt, self.config, self.keys, cache=self.verification_cache
        ):
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
        if verify_announcement_certificate(certificate, self.config, self.keys, cache=self.verification_cache):
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

    def store_batch(self, batch: EvidenceAnnouncementBatch) -> bool:
        if not _valid_evidence_batch(batch, self.config, self.keys, self.verification_cache):
            return False
        key = (canonical_case_identity(batch.case_id), batch.batch_digest)
        existing = self._batches.get(key)
        if existing is not None and existing != batch:
            return False
        for attestation in batch.attestations:
            item_key = self._key(attestation)
            previous = self._attestations.get(item_key)
            if previous is not None and digest_hex(asdict(previous)) != digest_hex(asdict(attestation)):
                raise ValueError("Conflicting payload for an existing case/attestation identity")
        self._batches[key] = batch
        for attestation in batch.attestations:
            self._attestations[self._key(attestation)] = attestation
        return True

    def store_batch_receipt(self, batch: EvidenceAnnouncementBatch, receipt: EvidenceBatchReceipt) -> bool:
        key = (canonical_case_identity(batch.case_id), batch.batch_digest)
        if self._batches.get(key) != batch or not verify_batch_receipt(
            batch, receipt, self.config, self.keys, cache=self.verification_cache
        ):
            return False
        bucket = self._batch_receipts.setdefault(key, {})
        previous = bucket.get(receipt.validator_id)
        if previous is not None and previous != receipt:
            return False
        bucket[receipt.validator_id] = receipt
        return True

    def certified_batches_for(self, case_id: str) -> tuple[EvidenceBatchAvailabilityCertificate, ...]:
        canonical = canonical_case_identity(case_id)
        result = []
        for key, batch in self._batches.items():
            if key[0] != canonical:
                continue
            certificate = EvidenceBatchAvailabilityCertificate(
                batch, tuple(self._batch_receipts.get(key, {}).values())
            )
            if verify_batch_availability_certificate(
                certificate, self.config, self.keys, cache=self.verification_cache
            ):
                result.append(certificate)
        return tuple(sorted(result, key=lambda item: item.batch.batch_digest))


def verify_announcement_receipt(
    attestation: EvidenceAttestation,
    receipt: EvidenceAnnouncementReceipt,
    config: PBFTConfig,
    keys: KeyRegistry,
    *,
    cache: EvidenceVerificationCache | None = None,
) -> bool:
    """Verify one validator's payload-receipt assertion for this exact item."""
    try:
        config.validate()
        cache_key = (attestation, receipt, config.membership_digest)
        if cache is not None:
            cached = cache._get_receipt(cache_key)
            if cached is not None:
                return cached
        validators = {
            unicodedata.normalize("NFC", validator).strip()
            for validator in config.validators
        }
        signer = unicodedata.normalize("NFC", receipt.validator_id).strip()
        valid = (
            signer in validators
            and receipt.membership_digest == config.membership_digest
            and receipt.case_id == canonical_case_identity(attestation.case_id)
            and receipt.attestation_id == attestation.attestation_id
            and receipt.attestation_digest == digest_hex(asdict(attestation))
            and attestation.validity == 1
            and _verify_attestation(attestation, keys, cache)
            and keys.verify(
                receipt.validator_id,
                _receipt_payload(attestation, receipt.validator_id, config),
                receipt.signature,
            )
        )
        return cache._put_receipt(cache_key, valid) if cache is not None else valid
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
    *,
    cache: EvidenceVerificationCache | None = None,
) -> EvidenceAnnouncementReceipt:
    """Sign a receipt only for a valid original source-signed attestation."""
    config.validate()
    if validator_id not in config.validators:
        raise ValueError("Announcement receipt signer is outside the fixed validator membership")
    if not _verify_attestation(attestation, keys, cache):
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
    *,
    cache: EvidenceVerificationCache | None = None,
) -> bool:
    """Verify q distinct validator receipts for the exact signed attestation."""
    try:
        config.validate()
        attestation = certificate.attestation
        if not _verify_attestation(attestation, keys, cache):
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
            if not verify_announcement_receipt(attestation, receipt, config, keys, cache=cache):
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
    *,
    locally_certified_batches: list[EvidenceBatchAvailabilityCertificate] | tuple[EvidenceBatchAvailabilityCertificate, ...] = (),
    cache: EvidenceVerificationCache | None = None,
) -> EvidenceReconciliationResult:
    """Reject a proposal that omits locally known quorum-certified evidence.

    The local certificate inventory must be independent of the coordinator's
    proposal. This check preserves support, opposition, and neutral direction;
    it neither reclassifies reports nor changes root-independence rules.
    """
    expected: dict[str, str] = {}
    case_ids: set[str] = set()
    for certificate in locally_certified:
        if not verify_announcement_certificate(certificate, config, keys, cache=cache):
            return EvidenceReconciliationResult(False, reason="invalid_local_announcement_certificate")
        attestation = certificate.attestation
        case_ids.add(canonical_case_identity(attestation.case_id))
        item_id = attestation.attestation_id
        item_digest = digest_hex(asdict(attestation))
        old_digest = expected.get(item_id)
        if old_digest is not None and old_digest != item_digest:
            return EvidenceReconciliationResult(False, reason="attestation_id_equivocation")
        expected[item_id] = item_digest

    for certificate in locally_certified_batches:
        if not verify_batch_availability_certificate(certificate, config, keys, cache=cache):
            return EvidenceReconciliationResult(False, reason="invalid_local_batch_certificate")
        for attestation in certificate.batch.attestations:
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
        if not _verify_attestation(attestation, keys, cache):
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
        if not _verify_attestation(attestation, keys, cache):
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
