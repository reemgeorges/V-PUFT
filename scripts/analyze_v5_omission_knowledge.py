"""Reconstruct knowledge and freshness for the confirmed V5 omission test."""
from __future__ import annotations

import json
import sys
from dataclasses import replace
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "tests"))

from test_coordinator_security_v5 import _coordinator_config, _v5_signed_case  # noqa: E402
from vpuft.architectures import DistributedRSUExtendedVPUFT  # noqa: E402
from vpuft.crypto import KeyRegistry  # noqa: E402
from vpuft.domain import EvidenceDirection  # noqa: E402
from vpuft.evidence import verify_attestation  # noqa: E402


class CapturingWithholder(DistributedRSUExtendedVPUFT):
    known_by_coordinator = ()
    complete_delivered_case = None

    def subset_case(self, source, attestations):
        items = list(attestations)
        if source.case_id == self.target_case_id:
            self.known_by_coordinator = tuple(items)
            self.complete_delivered_case = super().subset_case(source, items)
            items = [item for item in items if item.direction != EvidenceDirection.OPPOSES]
        return super().subset_case(source, items)


def main() -> None:
    config = _coordinator_config()
    config = replace(
        config,
        network=replace(config.network, packet_delivery_ratio=1.0, jitter_ms=0.0),
        pbft=replace(config.pbft, single_view_safety_mode=True),
    )
    keys = KeyRegistry(config.security.deterministic_master_seed)
    _source_config, _source_keys, target = _v5_signed_case(opposing=True)
    architecture = CapturingWithholder(config, keys)
    architecture.target_case_id = target.case_id
    coordinator = architecture._select_coordinator(target)
    result = architecture.run([target], seed=2101)
    decision = result.decisions[0]
    close_at = decision.metadata["qualification_evaluated_at"]
    evidence_messages = [
        message for message in result.messages
        if message.message_type == "RSU_EVIDENCE_EXCHANGE"
    ]

    records = []
    for attestation in target.attestations:
        if attestation.validator_rsu_id == coordinator:
            arrival_at = attestation.observed_at
            transport_status = "local-coordinator-payload"
        else:
            match = next(
                message for message in evidence_messages
                if message.sender == attestation.validator_rsu_id
                and message.receiver == coordinator
                and abs(message.sent_at - attestation.observed_at) < 1e-9
            )
            arrival_at = match.delivered_at
            transport_status = "delivered" if arrival_at is not None else "dropped"
        records.append({
            "attestation_id": attestation.attestation_id,
            "source_id": attestation.source_id,
            "validator_rsu_id": attestation.validator_rsu_id,
            "direction": int(attestation.direction),
            "observation_root_id": attestation.observation_root_id,
            "observed_at": attestation.observed_at,
            "signature_valid": verify_attestation(attestation, keys),
            "full_payload_at_source": True,
            "full_payload_recipients_before_qualification": list(dict.fromkeys(
                [attestation.source_id, coordinator]
            )),
            "full_payload_at_coordinator_by": arrival_at,
            "transport_status_to_coordinator": transport_status,
            "age_at_qualification_seconds": close_at - attestation.observed_at,
            "delivered_before_qualification": arrival_at is not None and arrival_at <= close_at,
        })

    complete = architecture.engine.qualify(architecture.complete_delivered_case, close_at)
    print(json.dumps({
        "case_id": target.case_id,
        "coordinator": coordinator,
        "assumed_byzantine_participant": coordinator,
        "membership": list(config.pbft.validators),
        "membership_epoch": config.pbft.membership_epoch,
        "quorum": config.pbft.resolved_quorum,
        "fault_budget": config.pbft.max_byzantine,
        "attestation_count": len(records),
        "opposing_count": sum(item["direction"] < 0 for item in records),
        "coordinator_received_full_payload_count": len(architecture.known_by_coordinator),
        "non_origin_validators_received_full_opposing_payloads_by_transport": [],
        "honest_origin_validators_with_opposing_reports": sorted({
            item["validator_rsu_id"] for item in records
            if item["direction"] < 0 and item["validator_rsu_id"] != coordinator
        }),
        "opposing_items_known_only_to_byzantine_coordinator_at_qualification": sorted({
            item["attestation_id"] for item in records
            if item["direction"] < 0 and item["validator_rsu_id"] == coordinator
        }),
        "coordinator_has_local_inventory_model": False,
        "other_validators_have_local_inventory_model": False,
        "qualification_time": close_at,
        "incomplete_bundle_qualified": decision.metadata.get("qualification_outcome"),
        "incomplete_bundle_expired_count": decision.metadata.get("expired_evidence"),
        "incomplete_bundle_committed": decision.committed,
        "complete_bundle_qualified": complete.qualified,
        "complete_bundle_expired_count": complete.expired_evidence,
        "complete_bundle_max_evidence_age_seconds": max(complete.evidence_ages_seconds, default=0.0),
        "evidence_transport_messages": [
            {
                "sender": item.sender,
                "receiver": item.receiver,
                "sent_at": item.sent_at,
                "delivered_at": item.delivered_at,
                "dropped": item.dropped,
            }
            for item in evidence_messages
        ],
        "attestations": records,
        "decision": {
            "committed": decision.committed,
            "reason": decision.reason,
            "finalized_at": decision.finalized_at,
            "validator_checks_passed": decision.metadata.get("validator_checks_passed"),
            "validator_checks_total": decision.metadata.get("validator_checks_total"),
            "bundle_arrived_attestations": decision.metadata.get("arrived_attestations"),
            "bundle_attempted_attestations": decision.metadata.get("attempted_attestations"),
        },
    }, sort_keys=True))


if __name__ == "__main__":
    main()
