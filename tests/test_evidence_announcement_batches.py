from dataclasses import replace
from pathlib import Path

import pytest

from vpuft.config import load_config
from vpuft.crypto import KeyRegistry
from vpuft.domain import AttackType, EvidenceAttestation, EvidenceDirection
from vpuft.evidence import sign_attestation
from vpuft.evidence_announcement import (
    EvidenceAnnouncementBatch,
    EvidenceBatchAvailabilityCertificate,
    ValidatorEvidenceInventory,
    create_batch_receipt,
    create_evidence_batch,
    evidence_bundle_digest,
    reconcile_announced_evidence,
    verify_batch_availability_certificate,
    verify_batch_receipt,
)


ROOT = Path(__file__).resolve().parents[1]


def _attestation(keys, attestation_id, root, direction=EvidenceDirection.SUPPORTS):
    unsigned = EvidenceAttestation(
        attestation_id, "batch-case", root, "rsu-7", "rsu", "rsu-7",
        "domain-7", "cam", "cell-a", AttackType.POSITION_OFFSET, direction,
        .99, .95, .98, 1.0, 1.0, 10.0, f"hash-{attestation_id}", "", "",
    )
    return sign_attestation(unsigned, keys, "rsu-7")


def _fixture():
    config = load_config(ROOT / "configs/extension_v5_coordinator_security.json")
    keys = KeyRegistry(config.security.deterministic_master_seed)
    items = (
        _attestation(keys, "batch-support", "root-support"),
        _attestation(keys, "batch-opposition", "root-opposition", EvidenceDirection.OPPOSES),
    )
    batch = create_evidence_batch("batch-case", "rsu-7", items, config.pbft, keys)
    receipts = tuple(create_batch_receipt(batch, validator, config.pbft, keys)
                     for validator in config.pbft.validators[:config.pbft.resolved_quorum])
    return config, keys, items, batch, EvidenceBatchAvailabilityCertificate(batch, receipts)


def test_batch_certificate_authenticates_every_full_original_attestation():
    config, keys, items, batch, certificate = _fixture()

    assert verify_batch_availability_certificate(certificate, config.pbft, keys)
    assert {item.attestation_id for item in batch.attestations} == {item.attestation_id for item in items}
    assert {item.direction for item in batch.attestations} == {
        EvidenceDirection.SUPPORTS, EvidenceDirection.OPPOSES,
    }
    assert len(certificate.receipts) == 4


def test_batch_certificate_does_not_cover_a_missing_or_changed_payload():
    config, keys, _, batch, certificate = _fixture()
    incomplete = replace(batch, attestations=batch.attestations[:1])
    changed = replace(batch, attestations=(replace(batch.attestations[0], evidence_hash="tampered"),
                                           batch.attestations[1]))

    assert not verify_batch_availability_certificate(
        replace(certificate, batch=incomplete), config.pbft, keys
    )
    assert not verify_batch_availability_certificate(
        replace(certificate, batch=changed), config.pbft, keys
    )


def test_batch_receipt_rejects_epoch_case_and_membership_replay():
    config, keys, _, batch, certificate = _fixture()
    receipt = certificate.receipts[0]
    next_epoch = replace(config.pbft, membership_epoch="next-membership-epoch")
    other_case = replace(batch, case_id="other-case")
    other_epoch_batch = create_evidence_batch(
        "batch-case", "rsu-7", batch.attestations, next_epoch, keys
    )

    assert verify_batch_receipt(batch, receipt, config.pbft, keys)
    assert not verify_batch_receipt(batch, receipt, next_epoch, keys)
    assert not verify_batch_receipt(other_case, receipt, config.pbft, keys)
    assert not verify_batch_receipt(other_epoch_batch, receipt, config.pbft, keys)


def test_batch_certificate_rejects_duplicate_signers_and_batch_equivocation():
    config, keys, _, batch, certificate = _fixture()
    duplicate = replace(certificate, receipts=certificate.receipts[:3] + (certificate.receipts[0],))
    opposing_removed = create_evidence_batch(
        "batch-case", "rsu-7", batch.attestations[:1], config.pbft, keys
    )

    assert not verify_batch_availability_certificate(duplicate, config.pbft, keys)
    assert not verify_batch_availability_certificate(
        replace(certificate, batch=opposing_removed), config.pbft, keys
    )


def test_batch_creation_rejects_cross_case_and_duplicate_attestation_ids():
    config = load_config(ROOT / "configs/extension_v5_coordinator_security.json")
    keys = KeyRegistry(config.security.deterministic_master_seed)
    first = _attestation(keys, "same-id", "root-first")
    other_case = sign_attestation(replace(first, case_id="other-case", signature="", public_key_id=""), keys, "rsu-7")

    with pytest.raises(ValueError, match="different case"):
        create_evidence_batch("batch-case", "rsu-7", (first, other_case), config.pbft, keys)
    with pytest.raises(ValueError, match="duplicate attestation"):
        create_evidence_batch("batch-case", "rsu-7", (first, first), config.pbft, keys)


def test_batch_collection_rejects_attestations_after_case_window_close():
    config, keys, items, _, _ = _fixture()
    late = sign_attestation(replace(items[0], observed_at=25.0, signature="", public_key_id=""), keys, "rsu-7")

    with pytest.raises(ValueError, match="after collection closure"):
        create_evidence_batch("batch-case", "rsu-7", (late,), config.pbft, keys,
                              collection_closed_at=25.0)


def test_optimization_modes_are_opt_in_and_require_v5_availability():
    config = load_config(ROOT / "configs/extension_v5_coordinator_security.json")
    assert config.distributed_extension.evidence_announcement_batching is False
    assert config.distributed_extension.evidence_receipt_dissemination == "all_to_all"
    assert config.distributed_extension.evidence_verification_cache_enabled is False

    invalid = replace(
        config,
        distributed_extension=replace(
            config.distributed_extension,
            evidence_receipt_dissemination="coordinator_only",
        ),
    )
    with pytest.raises(ValueError, match="require the V5 availability protocol"):
        invalid.validate()


def test_validator_batch_inventory_certifies_only_full_payload_and_four_receipts():
    config, keys, items, batch, certificate = _fixture()
    inventory = ValidatorEvidenceInventory(config.pbft.validators[0], config.pbft, keys)

    assert inventory.store_batch(batch)
    assert inventory.store_batch_receipt(batch, certificate.receipts[0])
    assert inventory.certified_batches_for(batch.case_id) == ()
    for receipt in certificate.receipts[1:]:
        assert inventory.store_batch_receipt(batch, receipt)

    certified = inventory.certified_batches_for(batch.case_id)
    assert len(certified) == 1
    assert tuple(item.attestation_id for item in certified[0].batch.attestations) == tuple(
        item.attestation_id for item in batch.attestations
    )
    assert set(inventory.attestations_for(batch.case_id)) == set(items)


def test_batch_reconciliation_rejects_omitted_opposition_and_binds_batch_certificate():
    config, keys, items, batch, certificate = _fixture()
    support = items[0]
    full = evidence_bundle_digest(
        batch.case_id, items, (), config.pbft, batch_certificates=(certificate,)
    )
    omitted = evidence_bundle_digest(
        batch.case_id, (support,), (), config.pbft, batch_certificates=()
    )
    rejected = reconcile_announced_evidence(
        (support,), (), config.pbft, keys, locally_certified_batches=(certificate,)
    )
    accepted = reconcile_announced_evidence(
        items, (), config.pbft, keys, locally_certified_batches=(certificate,)
    )

    assert full != omitted
    assert not rejected.accepted
    assert rejected.missing_attestation_ids == ("batch-opposition",)
    assert accepted.accepted


def test_valid_subset_certificate_does_not_prove_source_batch_completeness():
    config, keys, items, _, _ = _fixture()
    support = items[0]
    subset = create_evidence_batch("batch-case", "rsu-7", (support,), config.pbft, keys)
    receipts = tuple(create_batch_receipt(subset, validator, config.pbft, keys)
                     for validator in config.pbft.validators[:config.pbft.resolved_quorum])
    subset_certificate = EvidenceBatchAvailabilityCertificate(subset, receipts)

    assert verify_batch_availability_certificate(subset_certificate, config.pbft, keys)
    reconciliation = reconcile_announced_evidence(
        (support,), (), config.pbft, keys, locally_observed=items,
    )
    assert not reconciliation.accepted
    assert reconciliation.missing_attestation_ids == ("batch-opposition",)
