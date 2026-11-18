from __future__ import annotations

import time
from dataclasses import asdict, replace
from hashlib import sha256
import json
import unicodedata

from .base import Architecture
from ..consensus import PBFTConsensus, SimulatorFinalizationGuard, canonical_case_identity
from ..crypto import digest_hex
from ..des import Scheduler
from ..domain import ArchitectureRunResult, EvidenceCase, EvidenceDirection, TrustDecision, TrustState
from ..evidence import verify_attestation
from ..evidence_announcement import (
    EvidenceAnnouncementBatch,
    EvidenceBatchAvailabilityCertificate,
    EvidenceAvailabilityCertificate,
    ValidatorEvidenceInventory,
    create_batch_receipt,
    create_evidence_batch,
    create_announcement_receipt,
    evidence_bundle_digest,
    reconcile_announced_evidence,
    verify_announcement_receipt,
    verify_announcement_certificate,
    verify_batch_availability_certificate,
    verify_batch_receipt,
)
from ..ledger import Ledger
from ..network import SimulatedTransport, audit_link_order


def replica_membership(
    validators: tuple[str, ...],
    rsu_count: int,
    sensing_only_rsu_ids: tuple[str, ...] = (),
) -> tuple[str, ...]:
    """Resolve ledger replicas while keeping sensing-only RSUs out of consensus state."""
    rsu_nodes = tuple(f"rsu-{index}" for index in range(1, rsu_count + 1))
    if len(set(validators)) != len(validators):
        raise ValueError("Validator membership must contain unique identities")
    if len(set(sensing_only_rsu_ids)) != len(sensing_only_rsu_ids):
        raise ValueError("Sensing-only RSU identities must be unique")
    unknown = set(sensing_only_rsu_ids) - set(rsu_nodes)
    if unknown:
        raise ValueError(f"Unknown sensing-only RSU IDs: {sorted(unknown)}")
    overlap = set(sensing_only_rsu_ids) & set(validators)
    if overlap:
        raise ValueError(f"PBFT validators cannot be sensing-only: {sorted(overlap)}")
    return tuple(dict.fromkeys((*validators, *(node for node in rsu_nodes if node not in sensing_only_rsu_ids))))


class DistributedRSUExtendedVPUFT(Architecture):
    """Post-freeze distributed architecture with causal event-time scheduling."""

    name = "distributed_rsu_vpuft_extension"

    def _select_coordinator(self, case: EvidenceCase) -> str:
        validators = tuple(self.config.pbft.validators)
        coordinator_pool = tuple(self.config.distributed_extension.coordinator_pool) or validators
        strategy = self.config.distributed_extension.coordinator_strategy
        if strategy == "first_observer_then_hash":
            local = [att for att in case.attestations if att.validator_rsu_id in coordinator_pool]
            if local:
                return min(local, key=lambda att: (att.observed_at, att.attestation_id)).validator_rsu_id
        if strategy == "canonical_case_epoch_hash":
            case_key = canonical_case_identity(case.case_id)
            raw_epoch = self.config.distributed_extension.membership_epoch
            if not isinstance(raw_epoch, str):
                raise ValueError("membership_epoch must be a string")
            epoch = unicodedata.normalize("NFC", raw_epoch).strip()
            if not epoch:
                raise ValueError("membership_epoch must be non-empty")
            if any(not isinstance(validator, str) for validator in coordinator_pool):
                raise ValueError("Canonical coordinator validator identities must be strings")
            canonical_validators = sorted(
                unicodedata.normalize("NFC", validator).strip() for validator in coordinator_pool
            )
            if not canonical_validators or any(not validator for validator in canonical_validators):
                raise ValueError("Canonical coordinator mapping requires non-empty validators")
            if len(set(canonical_validators)) != len(canonical_validators):
                raise ValueError("Canonical coordinator mapping requires unique validators")
            encoded = json.dumps(
                [epoch, case_key, canonical_validators], ensure_ascii=False, separators=(",", ":")
            ).encode("utf-8")
            offset = int.from_bytes(sha256(encoded).digest(), "big") % len(canonical_validators)
            return canonical_validators[offset]
        offset = int(sha256(case.case_id.encode("utf-8")).hexdigest(), 16) % len(coordinator_pool)
        return coordinator_pool[offset]

    def _apply_evidence_source_guard(self, case: EvidenceCase, result, now: float):
        ext = self.config.distributed_extension
        if (
            not ext.leave_one_source_out_guard
            or ext.evidence_source_fault_budget == 0
            or not result.qualified
            or result.cryptographic_decisive
        ):
            return result, 0, True
        directions = {
            attestation.direction
            for attestation in case.attestations
            if attestation.validity == 1 and int(attestation.direction) != 0
        }
        if ext.guard_on_directional_conflict_only and len(directions) < 2:
            return result, 0, True
        if ext.evidence_source_fault_budget != 1:
            raise ValueError("The current extension implements an evidence-source fault budget of f=1")
        sources = sorted({attestation.source_id for attestation in case.attestations})
        checks = 0
        for omitted_source in sources:
            reduced = self.subset_case(
                case,
                [attestation for attestation in case.attestations if attestation.source_id != omitted_source],
            )
            checks += 1
            if not self.engine.qualify(reduced, now).qualified:
                return replace(result, qualified=False, reason="not_stable_after_one_rsu_source_removed"), checks, False
        return result, checks, True

    @staticmethod
    def _snapshot_ledger(source: Ledger) -> Ledger:
        snapshot = Ledger()
        snapshot.blocks = list(source.blocks)
        return snapshot

    @staticmethod
    def _copy_if_newer(target: Ledger, snapshot: Ledger) -> None:
        # Never let an older in-flight replication roll a replica backwards.
        if len(snapshot.blocks) > len(target.blocks):
            target.copy_from(snapshot)

    def run(self, cases: list[EvidenceCase], seed: int) -> ArchitectureRunResult:
        started = time.perf_counter()
        scheduler = Scheduler()
        transport = SimulatedTransport(self.config.network, seed + 31, scheduler=scheduler)
        cache_transport = SimulatedTransport(self.config.network, seed + 31031, scheduler=scheduler)
        finalization_guard = (
            SimulatorFinalizationGuard()
            if self.config.distributed_extension.simulator_finalization_guard_enabled
            else None
        )
        pbft_config = replace(
            self.config.pbft,
            membership_epoch=self.config.distributed_extension.membership_epoch,
        )
        pbft = PBFTConsensus(pbft_config, transport, self.keys, finalization_guard=finalization_guard)
        validators = tuple(self.config.pbft.validators)
        replica_nodes = replica_membership(
            validators,
            self.config.simulation.rsu_count,
            self.config.distributed_extension.sensing_only_rsu_ids,
        )
        ledgers = {node: Ledger() for node in replica_nodes}
        canonical_ledger = Ledger()

        decisions: list[TrustDecision] = []
        outcomes = []
        evidence_rows: list[dict] = []
        counters = {
            "recoveries": 0,
            "recheck_failures": 0,
            "evidence_guard_checks": 0,
            "evidence_guard_rejections": 0,
        }
        coordinator_counts = {validator: 0 for validator in validators}

        ordered_cases = sorted(cases, key=lambda item: (item.opened_at, item.case_id))
        case_order = {case.case_id: index for index, case in enumerate(ordered_cases)}

        def qualification_metadata(ctx: dict, result) -> dict:
            return {
                "independent_roots": result.independent_roots,
                "required_roots": result.required_roots,
                "distinct_sources": result.distinct_sources,
                "required_sources": result.required_sources,
                "distinct_zones": result.distinct_zones,
                "required_zones": result.required_zones,
                "distinct_modalities": result.distinct_modalities,
                "required_modalities": result.required_modalities,
                "supporting_strength": result.supporting_strength,
                "opposing_strength": result.opposing_strength,
                "qualification_margin": result.decision_margin,
                "required_margin": result.required_margin,
                "failed_constraints": list(result.failed_constraints),
                "qualification_outcome": bool(result.qualified),
                "qualification_reason": result.reason,
                "qualification_evaluated_at": ctx.get("qualified_at"),
                "evidence_observed_at": list(result.evidence_observed_at),
                "evidence_arrival_times": sorted(ctx.get("evidence_arrival_times", [])),
                "evidence_ages_seconds": list(result.evidence_ages_seconds),
                "excluded_duplicate_roots": result.excluded_duplicate_roots,
                "evidence_availability_enabled": self.config.distributed_extension.evidence_availability_enabled,
                "evidence_availability_certificates": ctx.get("availability_certificate_count", 0),
                "evidence_batch_certificate_count": ctx.get("availability_batch_certificate_count", 0),
                "evidence_batch_receipt_messages": ctx.get("evidence_batch_receipt_messages", 0),
                "evidence_reconciliation_rejections": ctx.get("reconciliation_rejections", 0),
                "evidence_incomplete_attestations": ctx.get("incomplete_attestations", 0),
                "invalid_evidence_receipts": ctx.get("invalid_evidence_receipts", 0),
                "evidence_inventory_entries": sum(len(inventory.attestations_for(ctx["case"].case_id)) for inventory in ctx.get("evidence_inventories", {}).values()),
            }

        def append_decision_after_ledger(
            *,
            ctx: dict,
            result,
            guard_checks: int,
            guard_stable: bool,
            checks: dict[str, bool],
            bundle_bytes: int,
            outcome,
            previous,
            final_state,
            ledger_time: float | None,
        ) -> None:
            case = ctx["case"]
            delivered_case = ctx["delivered_case"]
            decisions.append(TrustDecision(
                case_id=case.case_id,
                vehicle_id=case.vehicle_id,
                architecture=self.name,
                previous_state=previous,
                new_state=final_state,
                detected_at=ctx["detected_at"],
                qualified_at=ctx["qualified_at"],
                finalized_at=outcome.committed_at,
                ledger_available_at=ledger_time,
                decision_margin=result.decision_margin,
                committed=outcome.committed,
                reason=outcome.reason,
                metadata={
                    **qualification_metadata(ctx, result),
                    "evidence_coordinator": ctx["coordinator"],
                    "correlated_suppressed": result.correlated_suppressed,
                    "expired_evidence": result.expired_evidence,
                    "attempted_attestations": len(ctx["clean"].attestations),
                    "arrived_attestations": len(delivered_case.attestations),
                    "validator_requalification": True,
                    "validator_checks_passed": sum(checks.values()),
                    "validator_checks_total": len(checks),
                    "evidence_bundle_bytes": bundle_bytes,
                    "fault_activated": outcome.fault_activated,
                    "semantic_proposal_valid": outcome.semantic_proposal_valid,
                    "evidence_source_guard_enabled": self.config.distributed_extension.leave_one_source_out_guard,
                    "evidence_source_guard_checks": guard_checks,
                    "evidence_source_guard_stable": guard_stable,
                },
            ))

        def begin_replication(
            *,
            ctx: dict,
            result,
            guard_checks: int,
            guard_stable: bool,
            checks: dict[str, bool],
            bundle_bytes: int,
            outcome,
            previous,
            final_state,
        ) -> None:
            case = ctx["case"]
            index = ctx["index"]
            leader = outcome.leader or ctx["coordinator"]
            payload = ctx["payload"]

            # Commit order is defined by the global event schedule. The
            # canonical logical chain removes the previous Python-loop ordering
            # artifact while keeping a single blockchain history.
            canonical_ledger.append(case.case_id, payload, outcome.committed_at)
            ledgers[leader].copy_from(canonical_ledger)
            snapshot = self._snapshot_ledger(canonical_ledger)
            targets = replica_nodes if self.config.distributed_extension.replicate_read_cache_to_all_rsus else validators
            targets = tuple(replica for replica in targets if replica != leader)

            delivered_times: list[float] = []
            pending = {"count": len(targets)}

            def after_replication() -> None:
                lagging = [node for node, ledger in ledgers.items() if len(ledger.blocks) < len(snapshot.blocks)]
                if not self.config.pbft.state_recovery_enabled or not lagging:
                    ledger_time = max(delivered_times, default=outcome.committed_at)
                    append_decision_after_ledger(
                        ctx=ctx,
                        result=result,
                        guard_checks=guard_checks,
                        guard_stable=guard_stable,
                        checks=checks,
                        bundle_bytes=bundle_bytes,
                        outcome=outcome,
                        previous=previous,
                        final_state=final_state,
                        ledger_time=ledger_time,
                    )
                    return

                recovery_snapshot = self._snapshot_ledger(snapshot)
                recovery_times: list[float] = []
                remaining = {"count": len(lagging)}
                for replica in lagging:
                    recovery_transport = transport if replica in validators else cache_transport

                    def recovery_complete(message, _resolved_at, *, replica=replica) -> None:
                        if message.delivered_at is not None:
                            self._copy_if_newer(ledgers[replica], recovery_snapshot)
                            recovery_times.append(message.delivered_at)
                            counters["recoveries"] += 1
                        remaining["count"] -= 1
                        if remaining["count"] == 0:
                            ledger_time = max(
                                [outcome.committed_at, *delivered_times, *recovery_times]
                            )
                            append_decision_after_ledger(
                                ctx=ctx,
                                result=result,
                                guard_checks=guard_checks,
                                guard_stable=guard_stable,
                                checks=checks,
                                bundle_bytes=bundle_bytes,
                                outcome=outcome,
                                previous=previous,
                                final_state=final_state,
                                ledger_time=ledger_time,
                            )

                    recovery_transport.send_async(
                        message_type="STATE_RECOVERY",
                        sender=leader,
                        receiver=replica,
                        case_id=case.case_id,
                        sent_at=scheduler.now,
                        size_bytes=max(512, recovery_snapshot.estimated_storage_bytes()),
                        random_key=f"state-recovery:{case.case_id}:{leader}->{replica}:h={len(recovery_snapshot.blocks)}",
                        on_complete=recovery_complete,
                        case_order_index=index,
                        phase_rank=80,
                    )

            if not targets:
                after_replication()
                return

            for replica in targets:
                replica_transport = transport if replica in validators else cache_transport
                message_type = "LEDGER_REPLICATION" if replica in validators else "RSU_READ_CACHE_SYNC"

                def replication_complete(message, _resolved_at, *, replica=replica) -> None:
                    if message.delivered_at is not None:
                        self._copy_if_newer(ledgers[replica], snapshot)
                        delivered_times.append(message.delivered_at)
                    pending["count"] -= 1
                    if pending["count"] == 0:
                        scheduler.schedule(
                            scheduler.now,
                            after_replication,
                            phase_rank=78,
                            case_order_index=index,
                            key=f"replication-done:{case.case_id}",
                        )

                replica_transport.send_async(
                    message_type=message_type,
                    sender=leader,
                    receiver=replica,
                    case_id=case.case_id,
                    sent_at=outcome.committed_at,
                    size_bytes=1120,
                    random_key=f"{message_type}:{case.case_id}:{leader}->{replica}:h={len(snapshot.blocks)}",
                    on_complete=replication_complete,
                    case_order_index=index,
                    phase_rank=70,
                )

        def start_pbft(
            *,
            ctx: dict,
            result,
            guard_checks: int,
            guard_stable: bool,
            checks: dict[str, bool],
            bundle_bytes: int,
            previous,
        ) -> None:
            case = ctx["case"]
            index = ctx["index"]

            def pbft_complete(outcome, completed_at: float) -> None:
                outcomes.append(outcome)
                _, final_state = self.state_machine.finalize(case.vehicle_id, outcome.committed)
                if outcome.committed and outcome.reason == "idempotent_same_digest_retry":
                    append_decision_after_ledger(
                        ctx=ctx,
                        result=result,
                        guard_checks=guard_checks,
                        guard_stable=guard_stable,
                        checks=checks,
                        bundle_bytes=bundle_bytes,
                        outcome=outcome,
                        previous=previous,
                        final_state=final_state,
                        ledger_time=outcome.committed_at,
                    )
                    return
                if outcome.committed and outcome.committed_at is not None:
                    begin_replication(
                        ctx=ctx,
                        result=result,
                        guard_checks=guard_checks,
                        guard_stable=guard_stable,
                        checks=checks,
                        bundle_bytes=bundle_bytes,
                        outcome=outcome,
                        previous=previous,
                        final_state=final_state,
                    )
                else:
                    append_decision_after_ledger(
                        ctx=ctx,
                        result=result,
                        guard_checks=guard_checks,
                        guard_stable=guard_stable,
                        checks=checks,
                        bundle_bytes=bundle_bytes,
                        outcome=outcome,
                        previous=previous,
                        final_state=final_state,
                        ledger_time=None,
                    )

            pbft.finalize_async(
                scheduler=scheduler,
                case_id=case.case_id,
                payload=ctx["payload"],
                started_at=scheduler.now,
                preferred_leader=ctx["coordinator"],
                validator_checks=checks,
                case_order_index=index,
                on_complete=pbft_complete,
            )

        def begin_validator_checks(ctx: dict, result, guard_checks: int, guard_stable: bool, previous) -> None:
            case = ctx["case"]
            index = ctx["index"]
            delivered_case = ctx["delivered_case"]
            coordinator = ctx["coordinator"]
            expected = digest_hex(asdict(result))
            ext = self.config.distributed_extension
            bundle_bytes = ext.evidence_bundle_base_bytes + ext.evidence_bundle_bytes_per_attestation * len(delivered_case.attestations)
            if ext.evidence_availability_enabled:
                bundle_bytes += 256 * sum(len(cert.receipts) for cert in ctx.get("bundle_certificates", ()))
                bundle_bytes += 256 * sum(len(cert.receipts) for cert in ctx.get("bundle_batch_certificates", ()))
            checks: dict[str, bool] = {}
            remote = [validator for validator in validators if validator != coordinator]
            pending = {"count": len(remote)}

            verified_case = (
                self.sanitize_case(delivered_case)
                if ext.cache_verified_evidence_bundle
                else None
            )

            def validator_case():
                # The delivered case and its signed attestations are immutable.
                # Reuse only the signature-verified bundle; every validator
                # still independently executes the qualification computation.
                return verified_case if verified_case is not None else self.sanitize_case(delivered_case)

            def proposal_items_for(validator: str):
                items = list(delivered_case.attestations)
                if ext.coordinator_equivocate_evidence_bundle and validator != coordinator:
                    remote_index = remote.index(validator) if validator in remote else 0
                    if remote_index % 2 == 0:
                        items = [item for item in items if item.direction != EvidenceDirection.OPPOSES]
                return items

            def reconcile_and_qualify(validator: str, proposed_items):
                if not ext.evidence_availability_enabled:
                    checked_case = self.subset_case(ctx["clean"], proposed_items)
                    safe_case = self.sanitize_case(checked_case)
                    return self.engine.qualify(safe_case, ctx["qualified_at"]), True

                inventory = ctx["evidence_inventories"][validator]
                proposed_ids = {item.attestation_id for item in proposed_items}
                bundled_certificates = tuple(
                    cert for cert in ctx.get("bundle_certificates", ())
                    if cert.attestation.attestation_id in proposed_ids
                )
                cert_by_id = {
                    cert.attestation.attestation_id: cert
                    for cert in bundled_certificates
                    if verify_announcement_certificate(
                        cert, pbft_config, self.keys, cache=inventory.verification_cache
                    )
                }
                bundled_batch_certificates = tuple(
                    cert for cert in ctx.get("bundle_batch_certificates", ())
                    if {item.attestation_id for item in cert.batch.attestations} <= proposed_ids
                )
                batch_cert_by_id = {}
                for cert in bundled_batch_certificates:
                    if verify_batch_availability_certificate(
                        cert, pbft_config, self.keys, cache=inventory.verification_cache
                    ):
                        for item in cert.batch.attestations:
                            batch_cert_by_id[item.attestation_id] = cert
                for item in proposed_items:
                    cert = cert_by_id.get(item.attestation_id)
                    if cert is not None:
                        if digest_hex(asdict(cert.attestation)) != digest_hex(asdict(item)):
                            return None, False
                        continue
                    batch_cert = batch_cert_by_id.get(item.attestation_id)
                    if batch_cert is None or not any(
                        candidate.attestation_id == item.attestation_id
                        and digest_hex(asdict(candidate)) == digest_hex(asdict(item))
                        for candidate in batch_cert.batch.attestations
                    ):
                        return None, False
                try:
                    proposed_bundle_digest = evidence_bundle_digest(
                        case.case_id, proposed_items, bundled_certificates, pbft_config,
                        batch_certificates=bundled_batch_certificates,
                    )
                except ValueError:
                    return None, False
                if proposed_bundle_digest != ctx.get("bundle_digest"):
                    return None, False
                reconciliation = reconcile_announced_evidence(
                    proposed_items,
                    inventory.certificates_for(case.case_id),
                    pbft_config,
                    self.keys,
                    locally_observed=inventory.attestations_for(case.case_id),
                    locally_certified_batches=inventory.certified_batches_for(case.case_id),
                    cache=inventory.verification_cache,
                )
                if not reconciliation.accepted:
                    ctx["reconciliation_rejections"] += 1
                    return None, False
                proposed_case = self.subset_case(ctx["clean"], proposed_items)
                safe_case = self.sanitize_case(proposed_case)
                return self.engine.qualify(safe_case, ctx["qualified_at"]), True

            # Coordinator requalification is local and immediate.
            local_items = proposal_items_for(coordinator)
            if ext.evidence_availability_enabled:
                local_result, reconciled = reconcile_and_qualify(coordinator, local_items)
                if self.config.pbft.validator_behaviors.get(coordinator) == "accept_invalid":
                    # The Byzantine coordinator may sign its own incomplete
                    # proposal; honest validators still reconcile independently.
                    checks[coordinator] = True
                else:
                    checks[coordinator] = bool(reconciled and local_result is not None and digest_hex(asdict(local_result)) == expected)
            else:
                local_case = validator_case()
                local_result = self.engine.qualify(local_case, ctx["qualified_at"])
                checks[coordinator] = digest_hex(asdict(local_result)) == expected

            def bundles_done() -> None:
                counters["recheck_failures"] += sum(not value for value in checks.values())
                if ext.evidence_availability_enabled and sum(checks.values()) < self.config.pbft.resolved_quorum:
                    _, final_state = self.state_machine.finalize(case.vehicle_id, False)
                    decisions.append(TrustDecision(
                        case_id=case.case_id,
                        vehicle_id=case.vehicle_id,
                        architecture=self.name,
                        previous_state=previous,
                        new_state=final_state,
                        detected_at=ctx["detected_at"],
                        qualified_at=ctx["qualified_at"],
                        finalized_at=None,
                        ledger_available_at=None,
                        decision_margin=result.decision_margin,
                        committed=False,
                        reason="evidence_bundle_reconciliation_failed",
                        metadata={
                            **qualification_metadata(ctx, result),
                            "evidence_coordinator": coordinator,
                            "arrived_attestations": len(delivered_case.attestations),
                            "validator_requalification": True,
                            "validator_checks_passed": sum(checks.values()),
                            "validator_checks_total": len(checks),
                            "evidence_bundle_bytes": bundle_bytes,
                            "evidence_bundle_reconciliation_failed": True,
                        },
                    ))
                    return
                start_pbft(
                    ctx=ctx,
                    result=result,
                    guard_checks=guard_checks,
                    guard_stable=guard_stable,
                    checks=checks,
                    bundle_bytes=bundle_bytes,
                    previous=previous,
                )

            if not remote:
                bundles_done()
                return

            for validator in remote:
                proposed_items = proposal_items_for(validator)
                proposal_size = bundle_bytes
                if ext.evidence_availability_enabled:
                    proposal_size = ext.evidence_bundle_base_bytes + ext.evidence_bundle_bytes_per_attestation * len(proposed_items)
                    proposal_size += 256 * sum(len(cert.receipts) for cert in ctx.get("bundle_certificates", ()))
                    proposal_size += 256 * sum(len(cert.receipts) for cert in ctx.get("bundle_batch_certificates", ()))

                def bundle_complete(message, _resolved_at, *, validator=validator, proposed_items=proposed_items) -> None:
                    if message.delivered_at is None or self.config.pbft.validator_behaviors.get(validator) == "offline":
                        checks[validator] = False
                    else:
                        if ext.evidence_availability_enabled:
                            reproduced, reconciled = reconcile_and_qualify(validator, proposed_items)
                            checks[validator] = bool(reconciled and reproduced is not None and digest_hex(asdict(reproduced)) == expected)
                        else:
                            checked_case = validator_case()
                            reproduced = self.engine.qualify(checked_case, ctx["qualified_at"])
                            checks[validator] = digest_hex(asdict(reproduced)) == expected
                    pending["count"] -= 1
                    if pending["count"] == 0:
                        scheduler.schedule(
                            scheduler.now,
                            bundles_done,
                            phase_rank=45,
                            case_order_index=index,
                            key=f"bundle-done:{case.case_id}",
                        )

                transport.send_async(
                    message_type="VPUFT_EVIDENCE_BUNDLE",
                    sender=coordinator,
                    receiver=validator,
                    case_id=case.case_id,
                    sent_at=ctx["qualified_at"],
                    size_bytes=proposal_size,
                    random_key=f"bundle:{case.case_id}:{coordinator}->{validator}",
                    on_complete=bundle_complete,
                    case_order_index=index,
                    phase_rank=40,
                )

        def case_ready(ctx: dict) -> None:
            case = ctx["case"]
            clean = ctx["clean"]
            ext = self.config.distributed_extension
            if ext.evidence_availability_enabled:
                coordinator_inventory = ctx["evidence_inventories"][ctx["coordinator"]]
                if ext.evidence_announcement_batching:
                    batch_certificates = coordinator_inventory.certified_batches_for(case.case_id)
                    if ext.coordinator_omit_opposing_evidence:
                        batch_certificates = tuple(
                            certificate for certificate in batch_certificates
                            if not any(item.direction == EvidenceDirection.OPPOSES for item in certificate.batch.attestations)
                        )
                    certified_items = [
                        item for certificate in batch_certificates for item in certificate.batch.attestations
                    ]
                    ctx["bundle_certificates"] = ()
                    ctx["bundle_batch_certificates"] = tuple(batch_certificates)
                    ctx["availability_batch_certificate_count"] = len(batch_certificates)
                    ctx["availability_certificate_count"] = sum(
                        len(certificate.batch.attestations) for certificate in batch_certificates
                    )
                else:
                    certificates = coordinator_inventory.certificates_for(case.case_id)
                    ctx["availability_certificate_count"] = len(certificates)
                    certified_items = [certificate.attestation for certificate in certificates]
                    if ext.coordinator_omit_opposing_evidence:
                        certified_items = [item for item in certified_items if item.direction != EvidenceDirection.OPPOSES]
                    included_ids = {item.attestation_id for item in certified_items}
                    ctx["bundle_certificates"] = tuple(
                        certificate for certificate in certificates
                        if certificate.attestation.attestation_id in included_ids
                    )
                    ctx["bundle_batch_certificates"] = ()
                    ctx["availability_batch_certificate_count"] = 0
                included_ids = {item.attestation_id for item in certified_items}
                delivered_case = self.subset_case(clean, certified_items)
                ctx["bundle_digest"] = evidence_bundle_digest(
                    case.case_id, delivered_case.attestations, ctx["bundle_certificates"], pbft_config,
                    batch_certificates=ctx["bundle_batch_certificates"],
                )
                ctx["delivered_attestations"] = list(delivered_case.attestations)
                ctx["incomplete_attestations"] = max(0, len(clean.attestations) - len(included_ids))
            else:
                delivered_case = self.subset_case(clean, ctx["delivered_attestations"])
            ctx["delivered_case"] = delivered_case
            ctx["qualified_at"] = scheduler.now
            arrival_by_attestation = ctx.get("arrival_by_attestation", {})
            for attestation in delivered_case.attestations:
                row = self.evidence_row(case, attestation, seed)
                row["evidence_arrived_at"] = arrival_by_attestation.get(attestation.attestation_id)
                evidence_rows.append(row)

            # REVOKED is terminal. Keep the later evidence window in the audit
            # trail, but do not launch another validator bundle/PBFT round or
            # append another logical block for the same vehicle state.
            record = self.state_machine.get(case.vehicle_id)
            if record.state == TrustState.REVOKED:
                decisions.append(TrustDecision(
                    case_id=case.case_id,
                    vehicle_id=case.vehicle_id,
                    architecture=self.name,
                    previous_state=TrustState.REVOKED,
                    new_state=TrustState.REVOKED,
                    detected_at=ctx["detected_at"],
                    qualified_at=None,
                    finalized_at=None,
                    ledger_available_at=None,
                    decision_margin=record.last_margin,
                    committed=False,
                    reason="already_revoked_terminal_state",
                    metadata={
                        "evidence_coordinator": ctx["coordinator"],
                        "terminal_state_noop": True,
                        "excluded_post_revocation": True,
                        "expired_evidence": 0,
                        "attempted_attestations": len(clean.attestations),
                        "arrived_attestations": len(delivered_case.attestations),
                        "validator_requalification": False,
                        "evidence_source_guard_enabled": self.config.distributed_extension.leave_one_source_out_guard,
                        "evidence_source_guard_checks": 0,
                        "evidence_source_guard_stable": True,
                    },
                ))
                return

            result = self.engine.qualify(delivered_case, ctx["qualified_at"])
            result, guard_checks, guard_stable = self._apply_evidence_source_guard(
                delivered_case, result, ctx["qualified_at"]
            )
            counters["evidence_guard_checks"] += guard_checks
            if not guard_stable:
                counters["evidence_guard_rejections"] += 1
            previous, _ = self.state_machine.pre_finalize(case.vehicle_id, result)

            if not result.qualified:
                _, state = self.state_machine.finalize(case.vehicle_id, False)
                decisions.append(TrustDecision(
                    case_id=case.case_id,
                    vehicle_id=case.vehicle_id,
                    architecture=self.name,
                    previous_state=previous,
                    new_state=state,
                    detected_at=ctx["detected_at"],
                    qualified_at=None,
                    finalized_at=None,
                    ledger_available_at=None,
                    decision_margin=result.decision_margin,
                    committed=False,
                    reason=result.reason,
                    metadata={
                        **qualification_metadata(ctx, result),
                        "evidence_coordinator": ctx["coordinator"],
                        "correlated_suppressed": result.correlated_suppressed,
                        "expired_evidence": result.expired_evidence,
                        "attempted_attestations": len(clean.attestations),
                        "arrived_attestations": len(delivered_case.attestations),
                        "validator_requalification": False,
                        "evidence_source_guard_enabled": self.config.distributed_extension.leave_one_source_out_guard,
                        "evidence_source_guard_checks": guard_checks,
                        "evidence_source_guard_stable": guard_stable,
                    },
                ))
                return

            ctx["payload"] = {
                "vehicle_id": case.vehicle_id,
                "case_id": case.case_id,
                "attack_type": case.attack_type.value,
                "requested_state": "revoked",
                "qualification": asdict(result),
                "coordinator": ctx["coordinator"],
            }
            if ext.evidence_availability_enabled:
                ctx["payload"]["evidence_bundle_digest"] = ctx["bundle_digest"]
            begin_validator_checks(ctx, result, guard_checks, guard_stable, previous)

        def schedule_availability_ready(ctx: dict) -> None:
            if (
                ctx.get("availability_started")
                and ctx.get("availability_pending", 0) == 0
                and not ctx.get("availability_ready_scheduled")
            ):
                ctx["availability_ready_scheduled"] = True
                scheduler.schedule(
                    scheduler.now,
                    lambda ctx=ctx: case_ready(ctx),
                    phase_rank=30,
                    case_order_index=ctx["index"],
                    key=f"evidence-availability-closed:{ctx['case'].case_id}",
                )

        def send_availability_message(
            ctx: dict,
            *,
            message_type: str,
            sender: str,
            receiver: str,
            case_id: str,
            sent_at: float,
            size_bytes: int,
            random_key: str,
            phase_rank: int,
            on_complete,
        ) -> None:
            ctx["availability_pending"] += 1

            def complete(message, resolved_at):
                try:
                    on_complete(message, resolved_at)
                finally:
                    ctx["availability_pending"] -= 1
                    schedule_availability_ready(ctx)

            transport.send_async(
                message_type=message_type,
                sender=sender,
                receiver=receiver,
                case_id=case_id,
                sent_at=sent_at,
                size_bytes=size_bytes,
                random_key=random_key,
                random_stream_seed=seed,
                on_complete=complete,
                case_order_index=ctx["index"],
                phase_rank=phase_rank,
            )

        def receive_evidence_payload(ctx: dict, validator: str, attestation, received_at: float) -> None:
            if self.config.pbft.validator_behaviors.get(validator) == "offline":
                return
            inventory = ctx["evidence_inventories"][validator]
            try:
                accepted = inventory.store_payload(attestation)
            except ValueError:
                ctx["availability_conflict"] = True
                return
            if not accepted:
                ctx["availability_conflict"] = True
                return
            ctx["arrival_by_validator_attestation"][(validator, attestation.attestation_id)] = float(received_at)
            if validator == ctx["coordinator"]:
                ctx["arrival_by_attestation"][attestation.attestation_id] = float(received_at)
                ctx["evidence_arrival_times"].append(float(received_at))

            key = (canonical_case_identity(attestation.case_id), attestation.attestation_id)
            pending = ctx["pending_receipts"].get(validator, {}).pop(key, {})
            for receipt in pending.values():
                if not inventory.store_receipt(receipt):
                    ctx["invalid_evidence_receipts"] += 1

            behavior = self.config.pbft.validator_behaviors.get(validator)
            if behavior == "withhold_evidence":
                return
            sent_key = (validator, attestation.attestation_id)
            if sent_key in ctx["receipts_sent"]:
                return
            receipt = create_announcement_receipt(
                attestation, validator, pbft_config, self.keys,
                cache=inventory.verification_cache,
            )
            ctx["receipts_sent"].add(sent_key)
            inventory.store_receipt(receipt)
            receipt_to_broadcast = receipt
            if behavior == "forge_evidence_receipt":
                receipt_to_broadcast = replace(receipt, signature="invalid-signature")
            if self.config.distributed_extension.evidence_receipt_dissemination == "coordinator_only":
                receipt_recipients = () if validator == ctx["coordinator"] else (ctx["coordinator"],)
            else:
                receipt_recipients = tuple(item for item in validators if item != validator)
            for recipient in receipt_recipients:

                def receipt_complete(message, resolved_at, *, recipient=recipient, receipt=receipt_to_broadcast,
                                     attestation=attestation) -> None:
                    if message.delivered_at is None or self.config.pbft.validator_behaviors.get(recipient) == "offline":
                        return
                    recipient_inventory = ctx["evidence_inventories"][recipient]
                    if not verify_announcement_receipt(
                        attestation, receipt, pbft_config, self.keys,
                        cache=recipient_inventory.verification_cache,
                    ):
                        ctx["invalid_evidence_receipts"] += 1
                        return
                    receive_announcement_receipt(ctx, recipient, receipt, attestation, resolved_at)

                send_availability_message(
                    ctx,
                    message_type="EVIDENCE_ANNOUNCEMENT_RECEIPT",
                    sender=validator,
                    receiver=recipient,
                    case_id=attestation.case_id,
                    sent_at=received_at,
                    size_bytes=256,
                    random_key=f"evidence-receipt:{pbft_config.membership_digest}:{attestation.case_id}:{attestation.attestation_id}:{validator}->{recipient}",
                    phase_rank=18,
                    on_complete=receipt_complete,
                )

        def request_evidence_payload(ctx: dict, requester: str, receipt: object, sent_at: float) -> None:
            source = receipt.validator_id
            key = (requester, receipt.attestation_id, source)
            if key in ctx["retrieval_requests"]:
                return
            ctx["retrieval_requests"].add(key)

            def request_complete(message, resolved_at) -> None:
                if message.delivered_at is None or self.config.pbft.validator_behaviors.get(source) in {"offline", "withhold_evidence"}:
                    return
                source_inventory = ctx["evidence_inventories"][source]
                payload = source_inventory.get(receipt.case_id, receipt.attestation_id)
                if payload is None or digest_hex(asdict(payload)) != receipt.attestation_digest:
                    return

                def response_complete(response, response_at) -> None:
                    if response.delivered_at is None or self.config.pbft.validator_behaviors.get(requester) == "offline":
                        return
                    if (
                        digest_hex(asdict(payload)) != receipt.attestation_digest
                        or not verify_attestation(payload, self.keys)
                    ):
                        return
                    receive_evidence_payload(ctx, requester, payload, response_at)

                send_availability_message(
                    ctx,
                    message_type="EVIDENCE_RETRIEVAL_RESPONSE",
                    sender=source,
                    receiver=requester,
                    case_id=receipt.case_id,
                    sent_at=resolved_at,
                    size_bytes=704,
                    random_key=f"evidence-retrieval-response:{receipt.membership_digest}:{receipt.case_id}:{receipt.attestation_id}:{source}->{requester}",
                    phase_rank=28,
                    on_complete=response_complete,
                )

            send_availability_message(
                ctx,
                message_type="EVIDENCE_RETRIEVAL_REQUEST",
                sender=requester,
                receiver=source,
                case_id=receipt.case_id,
                sent_at=sent_at,
                size_bytes=160,
                random_key=f"evidence-retrieval-request:{receipt.membership_digest}:{receipt.case_id}:{receipt.attestation_id}:{requester}->{source}",
                phase_rank=23,
                on_complete=request_complete,
            )

        def request_pending_payloads(ctx: dict, validator: str, case_id: str, attestation_id: str, sent_at: float) -> None:
            inventory = ctx["evidence_inventories"][validator]
            if inventory.get(case_id, attestation_id) is not None:
                return
            key = (canonical_case_identity(case_id), attestation_id)
            pending = ctx["pending_receipts"].get(validator, {}).get(key, {})
            for receipt in tuple(pending.values()):
                request_evidence_payload(ctx, validator, receipt, sent_at)

        def receive_announcement_receipt(
            ctx: dict,
            validator: str,
            receipt,
            attestation,
            received_at: float,
        ) -> None:
            inventory = ctx["evidence_inventories"][validator]
            if inventory.get(receipt.case_id, receipt.attestation_id) is None:
                key = (canonical_case_identity(receipt.case_id), receipt.attestation_id)
                ctx["pending_receipts"].setdefault(validator, {}).setdefault(key, {})[receipt.validator_id] = receipt
                if ctx["announcement_inflight"].get((validator, receipt.attestation_id), 0) == 0:
                    request_pending_payloads(ctx, validator, receipt.case_id, receipt.attestation_id, received_at)
                return
            if not inventory.store_receipt(receipt):
                ctx["invalid_evidence_receipts"] += 1
                ctx["availability_conflict"] = True

        def announce_evidence(ctx: dict, attestation, sender: str, sent_at: float) -> None:
            for validator in validators:
                if validator == sender:
                    scheduler.schedule(
                        sent_at,
                        lambda ctx=ctx, validator=validator, attestation=attestation: receive_evidence_payload(
                            ctx, validator, attestation, scheduler.now
                        ),
                        phase_rank=15,
                        case_order_index=ctx["index"],
                        key=f"local-evidence-announcement:{ctx['case'].case_id}:{attestation.attestation_id}:{validator}",
                    )
                    continue

                def announcement_complete(message, resolved_at, *, validator=validator, attestation=attestation) -> None:
                    inflight_key = (validator, attestation.attestation_id)
                    ctx["announcement_inflight"][inflight_key] -= 1
                    if ctx["announcement_inflight"][inflight_key] <= 0:
                        ctx["announcement_inflight"].pop(inflight_key, None)
                    if message.delivered_at is not None:
                        receive_evidence_payload(ctx, validator, attestation, resolved_at)
                    elif inflight_key not in ctx["announcement_inflight"]:
                        request_pending_payloads(ctx, validator, attestation.case_id, attestation.attestation_id, resolved_at)

                inflight_key = (validator, attestation.attestation_id)
                ctx["announcement_inflight"][inflight_key] = ctx["announcement_inflight"].get(inflight_key, 0) + 1
                send_availability_message(
                    ctx,
                    message_type="EVIDENCE_ANNOUNCEMENT",
                    sender=sender,
                    receiver=validator,
                    case_id=attestation.case_id,
                    sent_at=sent_at,
                    size_bytes=704,
                    random_key=f"evidence-announcement:{pbft_config.membership_digest}:{attestation.case_id}:{attestation.attestation_id}:{sender}->{validator}",
                    phase_rank=8,
                    on_complete=announcement_complete,
                )
                if self.config.distributed_extension.duplicate_evidence_announcements:
                    ctx["announcement_inflight"][inflight_key] = ctx["announcement_inflight"].get(inflight_key, 0) + 1
                    send_availability_message(
                        ctx,
                        message_type="EVIDENCE_ANNOUNCEMENT",
                        sender=sender,
                        receiver=validator,
                        case_id=attestation.case_id,
                        sent_at=sent_at,
                        size_bytes=704,
                        random_key=f"evidence-announcement-duplicate:{pbft_config.membership_digest}:{attestation.case_id}:{attestation.attestation_id}:{sender}->{validator}",
                        phase_rank=9,
                        on_complete=announcement_complete,
                    )

        def request_evidence_batch(ctx: dict, requester: str, batch: EvidenceAnnouncementBatch,
                                   receipt, sent_at: float) -> None:
            source = receipt.validator_id
            request_key = (requester, batch.batch_digest, source)
            if request_key in ctx["batch_retrieval_requests"]:
                return
            ctx["batch_retrieval_requests"].add(request_key)

            def request_complete(message, resolved_at) -> None:
                if message.delivered_at is None or self.config.pbft.validator_behaviors.get(source) in {"offline", "withhold_evidence"}:
                    return
                source_batch = ctx["known_batches"].get(source, {}).get(batch.batch_digest)
                if source_batch is None or source_batch != batch:
                    return

                def response_complete(response, response_at) -> None:
                    if response.delivered_at is None or self.config.pbft.validator_behaviors.get(requester) == "offline":
                        return
                    # Retrieval authenticates the full batch against one genuine
                    # receipt. It does not manufacture or imply a quorum certificate.
                    requester_inventory = ctx["evidence_inventories"][requester]
                    if not verify_batch_receipt(
                        source_batch, receipt, pbft_config, self.keys,
                        cache=requester_inventory.verification_cache,
                    ):
                        return
                    receive_evidence_batch(ctx, requester, source_batch, response_at)

                send_availability_message(
                    ctx,
                    message_type="EVIDENCE_ANNOUNCEMENT_BATCH_RETRIEVAL_RESPONSE",
                    sender=source,
                    receiver=requester,
                    case_id=batch.case_id,
                    sent_at=resolved_at,
                    size_bytes=384 + 704 * len(batch.attestations),
                    random_key=f"evidence-batch-retrieval-response:{batch.membership_digest}:{batch.batch_digest}:{source}->{requester}",
                    phase_rank=28,
                    on_complete=response_complete,
                )

            send_availability_message(
                ctx,
                message_type="EVIDENCE_ANNOUNCEMENT_BATCH_RETRIEVAL_REQUEST",
                sender=requester,
                receiver=source,
                case_id=batch.case_id,
                sent_at=sent_at,
                size_bytes=160,
                random_key=f"evidence-batch-retrieval-request:{batch.membership_digest}:{batch.batch_digest}:{requester}->{source}",
                phase_rank=23,
                on_complete=request_complete,
            )

        def receive_evidence_batch_receipt(ctx: dict, validator: str, batch: EvidenceAnnouncementBatch,
                                           receipt, received_at: float) -> None:
            inventory = ctx["evidence_inventories"][validator]
            if (canonical_case_identity(batch.case_id), batch.batch_digest) not in inventory._batches:
                ctx["pending_batch_receipts"].setdefault(validator, {}).setdefault(batch.batch_digest, {})[
                    receipt.validator_id
                ] = (batch, receipt)
                if ctx["batch_announcement_inflight"].get((validator, batch.batch_digest), 0) == 0:
                    request_evidence_batch(ctx, validator, batch, receipt, received_at)
                return
            if not inventory.store_batch_receipt(batch, receipt):
                ctx["invalid_evidence_receipts"] += 1
                ctx["availability_conflict"] = True

        def receive_evidence_batch(ctx: dict, validator: str, batch: EvidenceAnnouncementBatch,
                                   received_at: float) -> None:
            if self.config.pbft.validator_behaviors.get(validator) == "offline":
                return
            inventory = ctx["evidence_inventories"][validator]
            if not inventory.store_batch(batch):
                ctx["availability_conflict"] = True
                ctx["incomplete_attestations"] += len(batch.attestations)
                return
            ctx["known_batches"].setdefault(validator, {})[batch.batch_digest] = batch
            for item in batch.attestations:
                ctx["arrival_by_validator_attestation"][(validator, item.attestation_id)] = float(received_at)
            if validator == ctx["coordinator"]:
                for item in batch.attestations:
                    ctx["arrival_by_attestation"][item.attestation_id] = float(received_at)
                    ctx["evidence_arrival_times"].append(float(received_at))

            pending = ctx["pending_batch_receipts"].get(validator, {}).pop(batch.batch_digest, {})
            for _, (pending_batch, receipt) in pending.items():
                receive_evidence_batch_receipt(ctx, validator, pending_batch, receipt, received_at)

            behavior = self.config.pbft.validator_behaviors.get(validator)
            receipt_key = (validator, batch.batch_digest)
            if behavior == "withhold_evidence" or receipt_key in ctx["batch_receipts_sent"]:
                return
            receipt = create_batch_receipt(
                batch, validator, pbft_config, self.keys,
                cache=inventory.verification_cache,
            )
            if not inventory.store_batch_receipt(batch, receipt):
                ctx["invalid_evidence_receipts"] += 1
                return
            ctx["batch_receipts_sent"].add(receipt_key)
            outgoing_receipt = receipt
            if behavior == "forge_evidence_receipt":
                outgoing_receipt = replace(receipt, signature="invalid-signature")
            if self.config.distributed_extension.evidence_receipt_dissemination == "coordinator_only":
                recipients = () if validator == ctx["coordinator"] else (ctx["coordinator"],)
            else:
                recipients = tuple(item for item in validators if item != validator)
            for recipient in recipients:
                def batch_receipt_complete(message, resolved_at, *, recipient=recipient,
                                           batch=batch, receipt=outgoing_receipt) -> None:
                    if message.delivered_at is None or self.config.pbft.validator_behaviors.get(recipient) == "offline":
                        return
                    recipient_inventory = ctx["evidence_inventories"][recipient]
                    if not verify_batch_receipt(
                        batch, receipt, pbft_config, self.keys,
                        cache=recipient_inventory.verification_cache,
                    ):
                        ctx["invalid_evidence_receipts"] += 1
                        return
                    receive_evidence_batch_receipt(ctx, recipient, batch, receipt, resolved_at)

                send_availability_message(
                    ctx,
                    message_type="EVIDENCE_ANNOUNCEMENT_BATCH_RECEIPT",
                    sender=validator,
                    receiver=recipient,
                    case_id=batch.case_id,
                    sent_at=received_at,
                    size_bytes=256,
                    random_key=f"evidence-batch-receipt:{batch.membership_digest}:{batch.batch_digest}:{validator}->{recipient}",
                    phase_rank=18,
                    on_complete=batch_receipt_complete,
                )

        def announce_evidence_batch(ctx: dict, batch: EvidenceAnnouncementBatch, sender: str, sent_at: float) -> None:
            for validator in validators:
                if validator == sender:
                    scheduler.schedule(
                        sent_at,
                        lambda ctx=ctx, validator=validator, batch=batch: receive_evidence_batch(
                            ctx, validator, batch, scheduler.now
                        ),
                        phase_rank=15,
                        case_order_index=ctx["index"],
                        key=f"local-evidence-batch:{batch.batch_digest}:{validator}",
                    )
                    continue

                key = (validator, batch.batch_digest)
                ctx["batch_announcement_inflight"][key] = ctx["batch_announcement_inflight"].get(key, 0) + 1

                def batch_announcement_complete(message, resolved_at, *, validator=validator, batch=batch) -> None:
                    inflight_key = (validator, batch.batch_digest)
                    ctx["batch_announcement_inflight"][inflight_key] -= 1
                    if ctx["batch_announcement_inflight"][inflight_key] <= 0:
                        ctx["batch_announcement_inflight"].pop(inflight_key, None)
                    if message.delivered_at is not None:
                        receive_evidence_batch(ctx, validator, batch, resolved_at)
                    elif inflight_key not in ctx["batch_announcement_inflight"]:
                        pending = ctx["pending_batch_receipts"].get(validator, {}).get(batch.batch_digest, {})
                        for pending_batch, receipt in tuple(pending.values()):
                            request_evidence_batch(ctx, validator, pending_batch, receipt, resolved_at)

                send_availability_message(
                    ctx,
                    message_type="EVIDENCE_ANNOUNCEMENT_BATCH",
                    sender=sender,
                    receiver=validator,
                    case_id=batch.case_id,
                    sent_at=sent_at,
                    size_bytes=384 + 704 * len(batch.attestations),
                    random_key=f"evidence-announcement-batch:{batch.membership_digest}:{batch.batch_digest}:{sender}->{validator}",
                    phase_rank=8,
                    on_complete=batch_announcement_complete,
                )

        for case in ordered_cases:
            index = case_order[case.case_id]
            clean = self.sanitize_case(case)
            coordinator = self._select_coordinator(clean)
            coordinator_counts[coordinator] += 1

            # The deterministic security profile has no safe coordinator
            # takeover certificate yet. If its assigned coordinator is known
            # offline before this case starts, fail closed instead of allowing
            # an unrelated PBFT view leader to act as an implicit replacement.
            if (
                self.config.distributed_extension.coordinator_strategy == "canonical_case_epoch_hash"
                and self.config.pbft.validator_behaviors.get(coordinator) == "offline"
            ):
                current = self.state_machine.get(case.vehicle_id)
                terminal = current.state == TrustState.REVOKED
                decisions.append(TrustDecision(
                    case_id=case.case_id,
                    vehicle_id=case.vehicle_id,
                    architecture=self.name,
                    previous_state=current.state,
                    new_state=current.state,
                    detected_at=min((att.observed_at for att in clean.attestations), default=case.opened_at),
                    qualified_at=None,
                    finalized_at=None,
                    ledger_available_at=None,
                    decision_margin=current.last_margin,
                    committed=False,
                    reason=(
                        "already_revoked_terminal_state"
                        if terminal
                        else "evidence_coordinator_unavailable_no_safe_takeover"
                    ),
                    metadata={
                        "evidence_coordinator": coordinator,
                        "coordinator_takeover_attempted": False,
                        "attempted_attestations": len(clean.attestations),
                        "arrived_attestations": 0,
                        "validator_requalification": False,
                        "terminal_state_noop": terminal,
                        "excluded_post_revocation": terminal,
                    },
                ))
                continue

            ctx = {
                "case": case,
                "clean": clean,
                "index": index,
                "coordinator": coordinator,
                "detected_at": min((att.observed_at for att in clean.attestations), default=case.opened_at),
                "pending": len(clean.attestations),
                "delivered_attestations": [],
                "evidence_arrival_times": [],
                "arrival_by_attestation": {},
                "availability_enabled": self.config.distributed_extension.evidence_availability_enabled,
                "availability_pending": 0,
                "availability_started": False,
                "availability_ready_scheduled": False,
                "availability_conflict": False,
                "evidence_inventories": {
                    validator: ValidatorEvidenceInventory(
                        validator, pbft_config, self.keys,
                        verification_cache_enabled=self.config.distributed_extension.evidence_verification_cache_enabled,
                    )
                    for validator in validators
                } if self.config.distributed_extension.evidence_availability_enabled else {},
                "pending_receipts": {validator: {} for validator in validators},
                "announcement_inflight": {},
                "pending_batch_receipts": {validator: {} for validator in validators},
                "batch_announcement_inflight": {},
                "known_batches": {validator: {} for validator in validators},
                "batch_receipts_sent": set(),
                "batch_retrieval_requests": set(),
                "receipts_sent": set(),
                "retrieval_requests": set(),
                "arrival_by_validator_attestation": {},
                "reconciliation_rejections": 0,
                "incomplete_attestations": 0,
                "invalid_evidence_receipts": 0,
                "availability_certificate_count": 0,
                "availability_batch_certificate_count": 0,
                "bundle_batch_certificates": (),
                "evidence_batch_receipt_messages": 0,
            }

            if not clean.attestations:
                scheduler.schedule(
                    case.opened_at,
                    lambda ctx=ctx: case_ready(ctx),
                    phase_rank=30,
                    case_order_index=index,
                    key=f"distributed-ready:{case.case_id}",
                )
                continue

            if self.config.distributed_extension.evidence_availability_enabled:
                if self.config.distributed_extension.evidence_announcement_batching:
                    collection_closed_at = case.opened_at + self.config.detector.case_window_seconds
                    collected_batches: dict[tuple[str, str, str], list] = {}
                    ctx["availability_started"] = True
                    ctx["availability_pending"] += 1

                    def collect_batch_item(
                        attestation, route: str, arrived_at: float, *, ctx=ctx,
                        collected_batches=collected_batches,
                        collection_closed_at=collection_closed_at,
                    ) -> None:
                        # Only reports delivered to their existing ingress route
                        # strictly before closure enter this case-level batch.
                        if arrived_at >= collection_closed_at:
                            return
                        key = (attestation.source_kind, attestation.source_id, route)
                        collected_batches.setdefault(key, []).append(attestation)

                    for attestation in clean.attestations:
                        if attestation.observed_at >= collection_closed_at:
                            continue
                        route = attestation.validator_rsu_id
                        if attestation.source_kind == "vehicle_witness":
                            def witness_batch_ingress(message, resolved_at, *, attestation=attestation,
                                                      route=route, collect=collect_batch_item) -> None:
                                if message.delivered_at is not None:
                                    collect(attestation, route, resolved_at)

                            send_availability_message(
                                ctx,
                                message_type="WITNESS_EVIDENCE_UPLINK",
                                sender=attestation.source_id,
                                receiver=route,
                                case_id=case.case_id,
                                sent_at=attestation.observed_at,
                                size_bytes=512,
                                random_key=f"witness-uplink:{attestation.attestation_id}",
                                phase_rank=6,
                                on_complete=witness_batch_ingress,
                            )
                        else:
                            scheduler.schedule(
                                attestation.observed_at,
                                lambda attestation=attestation, route=route, collect=collect_batch_item: collect(
                                    attestation, route, scheduler.now
                                ),
                                phase_rank=5,
                                case_order_index=index,
                                key=f"batch-ingress:{case.case_id}:{attestation.attestation_id}",
                            )

                    def case_collection_closed(ctx=ctx, collection_closed_at=collection_closed_at,
                                               case_id=case.case_id,
                                               collected_batches=collected_batches) -> None:
                        try:
                            batches_by_group = {
                                key: create_evidence_batch(
                                    case_id,
                                    key[2],
                                    items,
                                    pbft_config,
                                    self.keys,
                                    collection_closed_at=collection_closed_at,
                                )
                                for key, items in collected_batches.items()
                            }
                            for (_source_kind, _source_id, route), batch in sorted(batches_by_group.items()):
                                announce_evidence_batch(ctx, batch, route, collection_closed_at)
                        finally:
                            ctx["availability_pending"] -= 1
                            schedule_availability_ready(ctx)

                    scheduler.schedule(
                        collection_closed_at,
                        case_collection_closed,
                        phase_rank=7,
                        case_order_index=index,
                        key=f"evidence-case-window-closed:{case.case_id}",
                    )
                    continue

                for attestation in clean.attestations:
                    if attestation.source_kind == "vehicle_witness":
                        def witness_uplink_complete(message, _resolved_at, *, attestation=attestation) -> None:
                            if message.delivered_at is not None:
                                announce_evidence(ctx, attestation, attestation.validator_rsu_id, message.delivered_at)

                        send_availability_message(
                            ctx,
                            message_type="WITNESS_EVIDENCE_UPLINK",
                            sender=attestation.source_id,
                            receiver=attestation.validator_rsu_id,
                            case_id=case.case_id,
                            sent_at=attestation.observed_at,
                            size_bytes=512,
                            random_key=f"witness-uplink:{attestation.attestation_id}",
                            phase_rank=6,
                            on_complete=witness_uplink_complete,
                        )
                    else:
                        announce_evidence(ctx, attestation, attestation.validator_rsu_id, attestation.observed_at)
                ctx["availability_started"] = True
                schedule_availability_ready(ctx)
                continue

            def finish_attestation(ctx: dict, attestation, arrival_time: float | None) -> None:
                if arrival_time is not None:
                    ctx["delivered_attestations"].append(attestation)
                    ctx["evidence_arrival_times"].append(float(arrival_time))
                    ctx["arrival_by_attestation"][attestation.attestation_id] = float(arrival_time)
                ctx["pending"] -= 1
                if ctx["pending"] == 0:
                    scheduler.schedule(
                        scheduler.now,
                        lambda ctx=ctx: case_ready(ctx),
                        phase_rank=30,
                        case_order_index=ctx["index"],
                        key=f"distributed-ready:{ctx['case'].case_id}",
                    )

            def forward_from_validator(ctx: dict, attestation, sent_at: float) -> None:
                if attestation.validator_rsu_id == ctx["coordinator"]:
                    scheduler.schedule(
                        sent_at,
                        lambda ctx=ctx, attestation=attestation: finish_attestation(
                            ctx, attestation, scheduler.now
                        ),
                        phase_rank=15,
                        case_order_index=ctx["index"],
                        key=f"local-evidence:{attestation.attestation_id}",
                    )
                    return

                def evidence_complete(message, _resolved_at, *, ctx=ctx, attestation=attestation) -> None:
                    finish_attestation(ctx, attestation, message.delivered_at)

                transport.send_async(
                    message_type="RSU_EVIDENCE_EXCHANGE",
                    sender=attestation.validator_rsu_id,
                    receiver=ctx["coordinator"],
                    case_id=ctx["case"].case_id,
                    sent_at=sent_at,
                    size_bytes=704,
                    random_key=f"evidence-attestation:{attestation.attestation_id}",
                    random_stream_seed=seed,
                    on_complete=evidence_complete,
                    case_order_index=ctx["index"],
                    phase_rank=10,
                )

            for attestation in clean.attestations:
                if attestation.source_kind == "vehicle_witness":
                    def uplink_complete(message, _resolved_at, *, ctx=ctx, attestation=attestation) -> None:
                        if message.delivered_at is None:
                            finish_attestation(ctx, attestation, None)
                        else:
                            forward_from_validator(ctx, attestation, message.delivered_at)

                    transport.send_async(
                        message_type="WITNESS_EVIDENCE_UPLINK",
                        sender=attestation.source_id,
                        receiver=attestation.validator_rsu_id,
                        case_id=case.case_id,
                        sent_at=attestation.observed_at,
                        size_bytes=512,
                        random_key=f"witness-uplink:{attestation.attestation_id}",
                        random_stream_seed=seed,
                        on_complete=uplink_complete,
                        case_order_index=index,
                        phase_rank=8,
                    )
                    continue
                forward_from_validator(ctx, attestation, attestation.observed_at)

        scheduler.run()
        decisions.sort(key=lambda decision: case_order.get(decision.case_id, 10**9))
        outcomes.sort(key=lambda outcome: case_order.get(outcome.case_id, 10**9))
        valid_ledgers = all(ledger.validate() for ledger in ledgers.values()) and canonical_ledger.validate()
        hashes = {tuple(block.block_hash for block in ledger.blocks) for ledger in ledgers.values()}
        main_audit = audit_link_order(transport.messages, self.config.network.queue_rate_bytes_per_second)
        cache_audit = audit_link_order(cache_transport.messages, self.config.network.queue_rate_bytes_per_second)
        combined_messages = sorted(
            [*transport.messages, *cache_transport.messages],
            key=lambda message: (
                message.sent_at,
                message.sender,
                message.receiver,
                message.case_id,
                message.message_type,
                message.retransmission,
                message.message_id,
            ),
        )
        return ArchitectureRunResult(
            architecture=self.name,
            decisions=decisions,
            messages=combined_messages,
            consensus=outcomes,
            ledger_blocks=len(canonical_ledger.blocks),
            evidence_rows=evidence_rows,
            runtime_seconds=time.perf_counter() - started,
            ledger_consistent=valid_ledgers and len(hashes) <= 1,
            state_recoveries=counters["recoveries"],
            extension_metrics={
                "coordinator_counts": coordinator_counts,
                "validator_recheck_failures": counters["recheck_failures"],
                "evidence_availability_enabled": self.config.distributed_extension.evidence_availability_enabled,
                "evidence_announcement_messages": sum(message.message_type == "EVIDENCE_ANNOUNCEMENT" for message in combined_messages),
                "evidence_receipt_messages": sum(message.message_type == "EVIDENCE_ANNOUNCEMENT_RECEIPT" for message in combined_messages),
                "evidence_announcement_batch_messages": sum(message.message_type == "EVIDENCE_ANNOUNCEMENT_BATCH" for message in combined_messages),
                "evidence_batch_receipt_messages": sum(message.message_type == "EVIDENCE_ANNOUNCEMENT_BATCH_RECEIPT" for message in combined_messages),
                "evidence_retrieval_messages": sum(message.message_type.startswith("EVIDENCE_RETRIEVAL_") for message in combined_messages),
                "evidence_guard_checks": counters["evidence_guard_checks"],
                "evidence_guard_rejections": counters["evidence_guard_rejections"],
                "writable_validator_replicas": len(validators),
                "readable_rsu_replicas": len(replica_nodes),
                "transport_audit": main_audit,
                "cache_transport_audit": cache_audit,
            },
        )
