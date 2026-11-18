from dataclasses import replace
from pathlib import Path

from vpuft.architectures import DistributedRSUExtendedVPUFT
from vpuft.config import load_config
from vpuft.crypto import KeyRegistry
from vpuft.domain import EvidenceDirection

from test_security_audit_phase6 import att, case


ROOT = Path(__file__).resolve().parents[1]


def _config():
    config = load_config(ROOT / "configs/extension_v5_coordinator_security.json")
    return replace(
        config,
        distributed_extension=replace(
            config.distributed_extension,
            evidence_availability_enabled=True,
        ),
    )


def test_opposing_evidence_reaches_validator_inventories_and_coordinator_omission_fails_closed():
    config = _config()
    keys = KeyRegistry(config.security.deterministic_master_seed)
    reports = [
        att(keys, "availability-case", "root-support-a", "rsu-1", "cell-a", at=1.0),
        att(keys, "availability-case", "root-support-b", "rsu-2", "cell-b", at=1.1),
        att(keys, "availability-case", "root-opposing", "rsu-3", "cell-c", at=1.2,
            direction=EvidenceDirection.OPPOSES),
    ]
    target = case("availability-case", reports)
    coordinator = DistributedRSUExtendedVPUFT(config, keys)._select_coordinator(target)
    config = replace(
        config,
        distributed_extension=replace(
            config.distributed_extension,
            coordinator_omit_opposing_evidence=True,
        ),
        pbft=replace(config.pbft, validator_behaviors={coordinator: "accept_invalid"}),
    )

    result = DistributedRSUExtendedVPUFT(config, keys).run([target], seed=7101)

    assert not any(outcome.committed for outcome in result.consensus)
    assert result.decisions[0].reason == "evidence_bundle_reconciliation_failed"
    assert result.decisions[0].metadata["evidence_availability_certificates"] == 3
    assert result.decisions[0].metadata["evidence_reconciliation_rejections"] >= 1
    assert sum(message.message_type == "EVIDENCE_ANNOUNCEMENT" for message in result.messages) >= 12
    assert sum(message.message_type == "EVIDENCE_ANNOUNCEMENT_RECEIPT" for message in result.messages) >= 12


def test_evidence_availability_protocol_disabled_preserves_historical_transport():
    config = load_config(ROOT / "configs/extension_v5_coordinator_security.json")
    keys = KeyRegistry(config.security.deterministic_master_seed)
    reports = [
        att(keys, "legacy-path", "root-a", "rsu-1", "cell-a", at=1.0),
        att(keys, "legacy-path", "root-b", "rsu-2", "cell-b", at=1.1),
    ]

    result = DistributedRSUExtendedVPUFT(config, keys).run([case("legacy-path", reports)], seed=7102)

    assert not any(message.message_type.startswith("EVIDENCE_ANNOUNCEMENT") for message in result.messages)
    assert result.decisions[0].metadata["evidence_availability_enabled"] is False


def test_full_payload_receipts_are_gossiped_and_do_not_inflate_independent_roots():
    config = _config()
    config = replace(config, network=replace(config.network, packet_delivery_ratio=1.0))
    keys = KeyRegistry(config.security.deterministic_master_seed)
    reports = [
        att(keys, "inventory-case", "root-a", "rsu-1", "cell-a", at=1.0),
        att(keys, "inventory-case", "root-b", "rsu-2", "cell-b", at=1.0),
    ]

    result = DistributedRSUExtendedVPUFT(config, keys).run([case("inventory-case", reports)], seed=7103)

    decision = result.decisions[0]
    assert decision.metadata["evidence_availability_certificates"] == 2
    assert decision.metadata["evidence_inventory_entries"] == 10
    assert decision.metadata["independent_roots"] == 2
    assert result.extension_metrics["evidence_announcement_messages"] >= 8
    assert result.extension_metrics["evidence_receipt_messages"] >= 16
    assert result.extension_metrics["evidence_retrieval_messages"] == 0


def test_coordinator_only_receipts_reduce_gossip_without_changing_certification():
    base = replace(_config(), network=replace(_config().network, packet_delivery_ratio=1.0))
    optimized = replace(
        base,
        distributed_extension=replace(
            base.distributed_extension,
            evidence_receipt_dissemination="coordinator_only",
        ),
    )
    keys = KeyRegistry(base.security.deterministic_master_seed)
    reports = [
        att(keys, "coordinator-receipts", "root-a", "rsu-1", "cell-a", at=1.0),
        att(keys, "coordinator-receipts", "root-b", "rsu-2", "cell-b", at=1.0),
    ]
    target = case("coordinator-receipts", reports)
    reference = DistributedRSUExtendedVPUFT(base, KeyRegistry(base.security.deterministic_master_seed)).run([target], 7118)
    candidate = DistributedRSUExtendedVPUFT(optimized, KeyRegistry(base.security.deterministic_master_seed)).run([target], 7118)

    assert candidate.decisions[0].committed == reference.decisions[0].committed
    assert candidate.decisions[0].reason == reference.decisions[0].reason
    assert candidate.decisions[0].metadata["evidence_availability_certificates"] == 2
    assert reference.extension_metrics["evidence_receipt_messages"] == 40
    assert candidate.extension_metrics["evidence_receipt_messages"] == 8


def test_independent_bundle_equivocation_is_rejected_by_local_inventories():
    config = _config()
    config = replace(
        config,
        distributed_extension=replace(config.distributed_extension, coordinator_equivocate_evidence_bundle=True),
    )
    keys = KeyRegistry(config.security.deterministic_master_seed)
    reports = [
        att(keys, "equivocating-case", "root-a", "rsu-1", "cell-a", at=1.0),
        att(keys, "equivocating-case", "root-b", "rsu-2", "cell-b", at=1.0),
        att(keys, "equivocating-case", "root-c", "rsu-3", "cell-c", at=1.0),
        att(keys, "equivocating-case", "root-d", "rsu-4", "cell-d", at=1.0),
        att(keys, "equivocating-case", "root-e", "rsu-5", "cell-e", at=1.0,
            direction=EvidenceDirection.OPPOSES),
    ]

    result = DistributedRSUExtendedVPUFT(config, keys).run([case("equivocating-case", reports)], seed=7104)

    assert result.decisions[0].reason == "evidence_bundle_reconciliation_failed"
    assert not any(outcome.committed for outcome in result.consensus)


def test_one_offline_noncoordinator_still_allows_four_validator_evidence_receipts():
    config = _config()
    keys = KeyRegistry(config.security.deterministic_master_seed)
    reports = [
        att(keys, "one-offline-case", f"root-{index}", f"rsu-{index}", f"cell-{index}", at=1.0 + index / 10)
        for index in (1, 2, 3)
    ]
    target = case("one-offline-case", reports)
    provisional = DistributedRSUExtendedVPUFT(config, keys)
    coordinator = provisional._select_coordinator(target)
    offline = next(validator for validator in config.pbft.validators if validator != coordinator)
    config = replace(config, pbft=replace(config.pbft, validator_behaviors={offline: "offline"}))

    result = DistributedRSUExtendedVPUFT(config, keys).run([target], seed=7105)

    assert result.decisions[0].metadata["evidence_availability_certificates"] == 3
    assert result.decisions[0].reason != "evidence_coordinator_unavailable_no_safe_takeover"
    assert result.decisions[0].committed
    assert sum(outcome.committed for outcome in result.consensus) == 1


def test_one_byzantine_validator_may_withhold_its_receipt_without_forging_evidence():
    config = _config()
    keys = KeyRegistry(config.security.deterministic_master_seed)
    reports = [
        att(keys, "withholding-validator-case", f"root-{index}", f"rsu-{index}", f"cell-{index}", at=1.0 + index / 10)
        for index in (1, 2, 3)
    ]
    target = case("withholding-validator-case", reports)
    coordinator = DistributedRSUExtendedVPUFT(config, keys)._select_coordinator(target)
    byzantine = next(validator for validator in config.pbft.validators if validator != coordinator)
    config = replace(config, pbft=replace(config.pbft, validator_behaviors={byzantine: "withhold_evidence"}))

    result = DistributedRSUExtendedVPUFT(config, keys).run([target], seed=7106)

    assert result.decisions[0].metadata["evidence_availability_certificates"] == 3
    assert result.decisions[0].metadata["evidence_inventory_entries"] >= 12


def test_forged_receipt_payload_is_rejected_over_modeled_receipt_transport():
    config = _config()
    keys = KeyRegistry(config.security.deterministic_master_seed)
    reports = [
        att(keys, "forged-receipt-case", f"root-{index}", f"rsu-{index}", f"cell-{index}", at=1.0 + index / 10)
        for index in (1, 2, 3)
    ]
    target = case("forged-receipt-case", reports)
    coordinator = DistributedRSUExtendedVPUFT(config, keys)._select_coordinator(target)
    forger = next(validator for validator in config.pbft.validators if validator != coordinator)
    config = replace(config, pbft=replace(config.pbft, validator_behaviors={forger: "forge_evidence_receipt"}))

    result = DistributedRSUExtendedVPUFT(config, keys).run([target], seed=7109)

    assert result.decisions[0].metadata["invalid_evidence_receipts"] > 0
    assert result.decisions[0].metadata["evidence_availability_certificates"] == 3


def test_forged_receipt_is_rejected_while_other_four_validators_can_certify():
    config = _config()
    keys = KeyRegistry(config.security.deterministic_master_seed)
    reports = [
        att(keys, "forged-receipt-case", f"root-{index}", f"rsu-{index}", f"cell-{index}", at=1.0 + index / 10)
        for index in (1, 2, 3)
    ]
    target = case("forged-receipt-case", reports)
    coordinator = DistributedRSUExtendedVPUFT(config, keys)._select_coordinator(target)
    forger = next(validator for validator in config.pbft.validators if validator != coordinator)
    config = replace(config, pbft=replace(config.pbft, validator_behaviors={forger: "forge_evidence_receipt"}))

    result = DistributedRSUExtendedVPUFT(config, keys).run([target], seed=7109)

    assert result.decisions[0].metadata["invalid_evidence_receipts"] > 0
    assert result.decisions[0].metadata["evidence_availability_certificates"] == 3


def test_tampered_original_attestation_never_receives_an_availability_certificate():
    from dataclasses import replace as dc_replace

    config = _config()
    keys = KeyRegistry(config.security.deterministic_master_seed)
    reports = [
        att(keys, "tampered-payload-case", "root-a", "rsu-1", "cell-a", at=1.0),
        att(keys, "tampered-payload-case", "root-b", "rsu-2", "cell-b", at=1.1),
    ]
    reports[1] = dc_replace(reports[1], evidence_hash="modified-after-signing")

    result = DistributedRSUExtendedVPUFT(config, keys).run([case("tampered-payload-case", reports)], seed=7110)

    assert result.decisions[0].metadata["evidence_availability_certificates"] == 1
    assert result.decisions[0].metadata["evidence_incomplete_attestations"] == 1


def test_availability_profile_rejects_unsafe_committee_parameters():
    import pytest

    config = _config()
    invalid = replace(config, pbft=replace(config.pbft, quorum_size=3))

    with pytest.raises(ValueError, match="fails Byzantine-safe certificate intersection"):
        invalid.validate()


def test_receipt_before_payload_triggers_modeled_retrieval_and_verification():
    config = _config()
    config = replace(
        config,
        network=replace(config.network, packet_delivery_ratio=0.45, max_retries=2),
    )
    keys = KeyRegistry(config.security.deterministic_master_seed)
    reports = [
        att(keys, "retrieval-case", f"root-{index}", f"rsu-{index}", f"cell-{index}", at=1.0)
        for index in (1, 2, 3)
    ]

    result = DistributedRSUExtendedVPUFT(config, keys).run([case("retrieval-case", reports)], seed=7117)

    assert result.extension_metrics["evidence_retrieval_messages"] > 0
    assert result.decisions[0].metadata["evidence_availability_certificates"] >= 1


def test_duplicate_announcements_are_idempotent_and_cannot_multiply_roots():
    config = _config()
    config = replace(
        config,
        distributed_extension=replace(config.distributed_extension, duplicate_evidence_announcements=True),
    )
    keys = KeyRegistry(config.security.deterministic_master_seed)
    reports = [
        att(keys, "duplicate-case", "same-root", "rsu-1", "cell-a", at=1.0),
        att(keys, "duplicate-case", "same-root", "rsu-1", "cell-a", at=1.0),
    ]

    result = DistributedRSUExtendedVPUFT(config, keys).run([case("duplicate-case", reports)], seed=7107)

    assert result.decisions[0].metadata["attempted_attestations"] == 1
    assert result.decisions[0].metadata["independent_roots"] <= 1
    assert result.extension_metrics["evidence_announcement_messages"] >= 8


def test_never_announced_observer_evidence_is_not_detectable_by_runtime():
    config = _config()
    keys = KeyRegistry(config.security.deterministic_master_seed)
    withheld = att(keys, "never-announced-case", "hidden-root", "rsu-4", "cell-hidden",
                   direction=EvidenceDirection.OPPOSES, at=1.0)
    announced = [
        att(keys, "never-announced-case", "root-a", "rsu-1", "cell-a", at=1.0),
        att(keys, "never-announced-case", "root-b", "rsu-2", "cell-b", at=1.0),
    ]

    result = DistributedRSUExtendedVPUFT(config, keys).run([case("never-announced-case", announced)], seed=7108)

    assert all(row["attestation_id"] != withheld.attestation_id for row in result.evidence_rows)
    assert result.decisions[0].metadata["evidence_availability_certificates"] == 2


def test_batched_coordinator_receipts_preserve_qualification_and_opposition_checks():
    base = replace(_config(), network=replace(_config().network, packet_delivery_ratio=1.0))
    optimized = replace(
        base,
        distributed_extension=replace(
            base.distributed_extension,
            evidence_announcement_batching=True,
            evidence_receipt_dissemination="coordinator_only",
        ),
    )
    keys = KeyRegistry(base.security.deterministic_master_seed)
    reports = [
        att(keys, "batched-case", f"root-a-{index}", "rsu-1", f"cell-a-{index}", at=1.0 + index)
        for index in range(6)
    ] + [
        att(keys, "batched-case", f"root-b-{index}", "rsu-2", f"cell-b-{index}", at=1.0 + index)
        for index in range(6)
    ] + [
        att(keys, "batched-case", "root-opposing", "rsu-3", "cell-o",
            direction=EvidenceDirection.OPPOSES, at=7.0),
    ]
    target = case("batched-case", reports)
    reference = DistributedRSUExtendedVPUFT(base, KeyRegistry(base.security.deterministic_master_seed)).run([target], 7120)
    candidate = DistributedRSUExtendedVPUFT(optimized, KeyRegistry(base.security.deterministic_master_seed)).run([target], 7120)

    assert (reference.decisions[0].committed, reference.decisions[0].reason,
            reference.decisions[0].metadata["independent_roots"]) == (
        candidate.decisions[0].committed, candidate.decisions[0].reason,
        candidate.decisions[0].metadata["independent_roots"],
    )
    assert candidate.decisions[0].metadata["evidence_availability_certificates"] == len(reports)
    assert candidate.decisions[0].metadata["evidence_batch_certificate_count"] == 3
    assert candidate.extension_metrics["evidence_announcement_batch_messages"] == 12
    assert candidate.extension_metrics["evidence_batch_receipt_messages"] == 12
    assert candidate.extension_metrics["evidence_receipt_messages"] == 0


def test_batched_opposing_report_cannot_be_removed_by_coordinator():
    base = replace(_config(), network=replace(_config().network, packet_delivery_ratio=1.0))
    coordinator = DistributedRSUExtendedVPUFT(base, KeyRegistry(base.security.deterministic_master_seed))._select_coordinator(
        case("batched-omission", ())
    )
    config = replace(
        base,
        distributed_extension=replace(
            base.distributed_extension,
            evidence_announcement_batching=True,
            evidence_receipt_dissemination="coordinator_only",
            coordinator_omit_opposing_evidence=True,
        ),
        pbft=replace(base.pbft, validator_behaviors={coordinator: "accept_invalid"}),
    )
    keys = KeyRegistry(config.security.deterministic_master_seed)
    reports = [
        att(keys, "batched-omission", "root-support-a", "rsu-1", "cell-a", at=1.0),
        att(keys, "batched-omission", "root-support-b", "rsu-2", "cell-b", at=2.0),
        att(keys, "batched-omission", "root-opposing", "rsu-3", "cell-o",
            direction=EvidenceDirection.OPPOSES, at=3.0),
    ]

    result = DistributedRSUExtendedVPUFT(config, keys).run([case("batched-omission", reports)], 7121)

    assert not any(outcome.committed for outcome in result.consensus)
    assert result.decisions[0].reason == "evidence_bundle_reconciliation_failed"


def test_batch_closure_excludes_late_observation_without_looking_ahead_or_crashing():
    config = replace(
        _config(),
        network=replace(_config().network, packet_delivery_ratio=1.0),
    )
    config = replace(
        config,
        distributed_extension=replace(
            config.distributed_extension,
            evidence_announcement_batching=True,
            evidence_receipt_dissemination="coordinator_only",
        ),
    )
    keys = KeyRegistry(config.security.deterministic_master_seed)
    timely = att(keys, "batch-late", "root-timely", "rsu-1", "cell-a", at=10.0)
    late = att(keys, "batch-late", "root-late", "rsu-2", "cell-b", at=16.0)

    result = DistributedRSUExtendedVPUFT(config, keys).run([case("batch-late", [timely, late])], 7122)

    assert result.decisions[0].metadata["attempted_attestations"] == 2
    assert {row["attestation_id"] for row in result.evidence_rows} == {"att-root-timely-rsu-1"}
    assert result.decisions[0].metadata["evidence_incomplete_attestations"] == 1


def test_batch_closure_keeps_case_collectors_isolated_across_cases():
    config = _config()
    config = replace(
        config,
        network=replace(config.network, packet_delivery_ratio=1.0),
        distributed_extension=replace(
            config.distributed_extension,
            evidence_announcement_batching=True,
            evidence_receipt_dissemination="coordinator_only",
        ),
    )
    keys = KeyRegistry(config.security.deterministic_master_seed)
    first = case("batch-case-one", [att(keys, "batch-case-one", "root-one", "rsu-1", "cell-one", at=1.0)])
    second = case("batch-case-two", [att(keys, "batch-case-two", "root-two", "rsu-2", "cell-two", at=2.0)])

    result = DistributedRSUExtendedVPUFT(config, keys).run([first, second], 7123)

    assert len(result.decisions) == 2
    assert {row["case_id"] for row in result.evidence_rows} == {"batch-case-one", "batch-case-two"}
