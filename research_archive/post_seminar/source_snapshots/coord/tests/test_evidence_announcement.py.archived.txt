from pathlib import Path
from dataclasses import replace

import pytest

from vpuft.config import load_config
from vpuft.crypto import KeyRegistry
from vpuft.domain import AttackType, EvidenceAttestation, EvidenceDirection
from vpuft.evidence import sign_attestation
from vpuft.evidence_announcement import (
    EvidenceAvailabilityCertificate,
    create_announcement_receipt,
    reconcile_announced_evidence,
    verify_announcement_certificate,
)


ROOT = Path(__file__).resolve().parents[1]


def make_attestation(keys, attestation_id, root, source, direction):
    item = EvidenceAttestation(
        attestation_id, "case-evidence", root, source, "rsu", source,
        f"domain-{source}", "cam", f"cell-{source}", AttackType.POSITION_OFFSET,
        direction, .99, .95, .98, 1.0, 1.0, 10.0, f"hash-{attestation_id}", "", "",
    )
    return sign_attestation(item, keys, source)


def certificate(attestation, config, keys, validators=None):
    validators = validators or config.pbft.validators[:config.pbft.resolved_quorum]
    receipts = tuple(create_announcement_receipt(attestation, validator, config.pbft, keys) for validator in validators)
    return EvidenceAvailabilityCertificate(attestation=attestation, receipts=receipts)


def test_four_distinct_v5_validator_receipts_authenticate_original_signed_evidence():
    config = load_config(ROOT / "configs/extension_v5_coordinator_security.json")
    keys = KeyRegistry(config.security.deterministic_master_seed)
    attestation = make_attestation(keys, "att-1", "root-1", "rsu-7", EvidenceDirection.OPPOSES)
    cert = certificate(attestation, config, keys)

    assert verify_announcement_certificate(cert, config.pbft, keys)
    assert cert.attestation.observation_root_id == "root-1"
    assert cert.attestation.direction == EvidenceDirection.OPPOSES


def test_certificate_rejects_duplicate_or_insufficient_receipt_signers():
    config = load_config(ROOT / "configs/extension_v5_coordinator_security.json")
    keys = KeyRegistry(config.security.deterministic_master_seed)
    attestation = make_attestation(keys, "att-2", "root-2", "rsu-7", EvidenceDirection.SUPPORTS)
    three = certificate(attestation, config, keys, config.pbft.validators[:3])
    four = certificate(attestation, config, keys)
    duplicate = EvidenceAvailabilityCertificate(attestation, four.receipts[:3] + (four.receipts[0],))

    assert not verify_announcement_certificate(three, config.pbft, keys)
    assert not verify_announcement_certificate(duplicate, config.pbft, keys)


def test_receipt_signing_rejects_nonmember_and_invalid_source_evidence():
    config = load_config(ROOT / "configs/extension_v5_coordinator_security.json")
    keys = KeyRegistry(config.security.deterministic_master_seed)
    attestation = make_attestation(keys, "att-invalid", "root-invalid", "rsu-7", EvidenceDirection.SUPPORTS)
    tampered = replace(attestation, evidence_hash="tampered")

    with pytest.raises(ValueError, match="outside"):
        create_announcement_receipt(attestation, "rsu-6", config.pbft, keys)
    with pytest.raises(ValueError, match="invalid or unsigned"):
        create_announcement_receipt(tampered, "rsu-1", config.pbft, keys)


def test_certificate_is_bound_to_v5_membership_and_attestation_digest():
    config = load_config(ROOT / "configs/extension_v5_coordinator_security.json")
    keys = KeyRegistry(config.security.deterministic_master_seed)
    attestation = make_attestation(keys, "att-3", "root-3", "rsu-7", EvidenceDirection.SUPPORTS)
    cert = certificate(attestation, config, keys)
    changed_epoch = replace(config.pbft, membership_epoch="different-epoch")
    changed = replace(attestation, evidence_hash="substituted")

    assert not verify_announcement_certificate(cert, changed_epoch, keys)
    assert not verify_announcement_certificate(replace(cert, attestation=changed), config.pbft, keys)


def test_validator_reconciliation_rejects_omitted_announced_opposition():
    config = load_config(ROOT / "configs/extension_v5_coordinator_security.json")
    keys = KeyRegistry(config.security.deterministic_master_seed)
    support = make_attestation(keys, "support", "root-s", "rsu-1", EvidenceDirection.SUPPORTS)
    opposition = make_attestation(keys, "opposition", "root-o", "rsu-2", EvidenceDirection.OPPOSES)
    certs = (certificate(support, config, keys), certificate(opposition, config, keys))

    rejected = reconcile_announced_evidence([support], certs, config.pbft, keys)
    accepted = reconcile_announced_evidence([support, opposition], certs, config.pbft, keys)

    assert not rejected.accepted
    assert rejected.missing_attestation_ids == ("opposition",)
    assert accepted.accepted


def test_reconciliation_rejects_conflicting_reuse_of_an_attestation_id():
    config = load_config(ROOT / "configs/extension_v5_coordinator_security.json")
    keys = KeyRegistry(config.security.deterministic_master_seed)
    original = make_attestation(keys, "reused-id", "root-original", "rsu-1", EvidenceDirection.SUPPORTS)
    conflicting = make_attestation(keys, "reused-id", "root-other", "rsu-1", EvidenceDirection.OPPOSES)
    certs = (certificate(original, config, keys),)

    result = reconcile_announced_evidence([original, conflicting], certs, config.pbft, keys)

    assert not result.accepted
    assert result.reason == "attestation_id_equivocation"
