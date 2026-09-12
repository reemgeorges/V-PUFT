from __future__ import annotations

import time
from dataclasses import asdict, replace
from hashlib import sha256

from .base import Architecture
from ..consensus import PBFTConsensus
from ..crypto import digest_hex
from ..domain import ArchitectureRunResult, EvidenceCase, TrustDecision
from ..ledger import Ledger
from ..network import SimulatedTransport


class DistributedRSUExtendedVPUFT(Architecture):
    """Post-freeze opt-in architecture.

    The first validator that observed a case becomes its preferred coordinator;
    otherwise a stable case hash selects a validator.  Before PBFT voting, every
    validator must receive the evidence bundle and deterministically reproduce
    the coordinator's V-PUFT result.
    """

    name = "distributed_rsu_vpuft_extension"

    def _select_coordinator(self, case: EvidenceCase) -> str:
        validators = tuple(self.config.pbft.validators)
        strategy = self.config.distributed_extension.coordinator_strategy
        if strategy == "first_observer_then_hash":
            local = [
                att for att in case.attestations
                if att.validator_rsu_id in validators
            ]
            if local:
                return min(local, key=lambda att: (att.observed_at, att.attestation_id)).validator_rsu_id
        offset = int(sha256(case.case_id.encode("utf-8")).hexdigest(), 16) % len(validators)
        return validators[offset]

    def _validator_checks(
        self,
        case: EvidenceCase,
        result,
        now: float,
        coordinator: str,
        transport: SimulatedTransport,
    ) -> tuple[dict[str, bool], float, int]:
        checks: dict[str, bool] = {}
        latest = now
        expected = digest_hex(asdict(result))
        ext = self.config.distributed_extension
        bundle_bytes = ext.evidence_bundle_base_bytes + ext.evidence_bundle_bytes_per_attestation * len(case.attestations)
        for validator in self.config.pbft.validators:
            delivered = True
            if validator != coordinator:
                message = transport.send(
                    message_type="VPUFT_EVIDENCE_BUNDLE",
                    sender=coordinator,
                    receiver=validator,
                    case_id=case.case_id,
                    sent_at=now,
                    size_bytes=bundle_bytes,
                )
                delivered = message.delivered_at is not None
                if message.delivered_at is not None:
                    latest = max(latest, message.delivered_at)
            if not delivered:
                checks[validator] = False
                continue
            validator_case = self.sanitize_case(case)
            reproduced = self.engine.qualify(validator_case, now)
            checks[validator] = digest_hex(asdict(reproduced)) == expected
        return checks, latest, bundle_bytes

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
                return replace(
                    result,
                    qualified=False,
                    reason="not_stable_after_one_rsu_source_removed",
                ), checks, False
        return result, checks, True

    def run(self, cases: list[EvidenceCase], seed: int) -> ArchitectureRunResult:
        started = time.perf_counter()
        transport = SimulatedTransport(self.config.network, seed + 31)
        # Cache replication has its own deterministic radio stream. This keeps
        # the paired evidence/PBFT experiment unchanged when read caches are
        # enabled and prevents extra cache packets from changing later loss
        # draws on the security-critical path.
        cache_transport = SimulatedTransport(self.config.network, seed + 31031)
        pbft = PBFTConsensus(self.config.pbft, transport, self.keys)
        validators = tuple(self.config.pbft.validators)
        rsu_nodes = tuple(f"rsu-{index}" for index in range(1, self.config.simulation.rsu_count + 1))
        # Validators keep writable PBFT replicas. Other RSUs keep read-only
        # replicas so a nearby vehicle can query trust without a remote-ledger
        # round trip. Receiving a replica never grants an RSU voting rights.
        replica_nodes = tuple(dict.fromkeys((*validators, *rsu_nodes)))
        ledgers = {node: Ledger() for node in replica_nodes}
        decisions: list[TrustDecision] = []
        outcomes = []
        evidence_rows: list[dict] = []
        recoveries = 0
        coordinator_counts = {validator: 0 for validator in self.config.pbft.validators}
        recheck_failures = 0
        evidence_guard_checks = 0
        evidence_guard_rejections = 0

        for case in sorted(cases, key=lambda item: (item.opened_at, item.case_id)):
            clean = self.sanitize_case(case)
            coordinator = self._select_coordinator(clean)
            coordinator_counts[coordinator] += 1
            detected_at = min((att.observed_at for att in clean.attestations), default=case.opened_at)
            arrivals: list[float] = []
            delivered_attestations = []
            for attestation in clean.attestations:
                if attestation.validator_rsu_id == coordinator:
                    arrivals.append(attestation.observed_at)
                    delivered_attestations.append(attestation)
                    continue
                message = transport.send(
                    message_type="RSU_EVIDENCE_EXCHANGE",
                    sender=attestation.validator_rsu_id,
                    receiver=coordinator,
                    case_id=case.case_id,
                    sent_at=attestation.observed_at,
                    size_bytes=704,
                )
                if message.delivered_at is not None:
                    arrivals.append(message.delivered_at)
                    delivered_attestations.append(attestation)

            delivered_case = self.subset_case(clean, delivered_attestations)
            evidence_rows.extend(self.evidence_row(case, att, seed) for att in delivered_case.attestations)
            qualified_at = max(arrivals, default=case.opened_at)
            result = self.engine.qualify(delivered_case, qualified_at)
            result, guard_checks, guard_stable = self._apply_evidence_source_guard(
                delivered_case, result, qualified_at
            )
            evidence_guard_checks += guard_checks
            if not guard_stable:
                evidence_guard_rejections += 1
            previous, _ = self.state_machine.pre_finalize(case.vehicle_id, result)

            if not result.qualified:
                _, state = self.state_machine.finalize(case.vehicle_id, False)
                decisions.append(TrustDecision(
                    case_id=case.case_id,
                    vehicle_id=case.vehicle_id,
                    architecture=self.name,
                    previous_state=previous,
                    new_state=state,
                    detected_at=detected_at,
                    qualified_at=None,
                    finalized_at=None,
                    ledger_available_at=None,
                    decision_margin=result.decision_margin,
                    committed=False,
                    reason=result.reason,
                    metadata={
                        "evidence_coordinator": coordinator,
                        "independent_roots": result.independent_roots,
                        "correlated_suppressed": result.correlated_suppressed,
                        "attempted_attestations": len(clean.attestations),
                        "arrived_attestations": len(delivered_case.attestations),
                        "validator_requalification": False,
                        "evidence_source_guard_enabled": self.config.distributed_extension.leave_one_source_out_guard,
                        "evidence_source_guard_checks": guard_checks,
                        "evidence_source_guard_stable": guard_stable,
                    },
                ))
                continue

            payload = {
                "vehicle_id": case.vehicle_id,
                "case_id": case.case_id,
                "attack_type": case.attack_type.value,
                "requested_state": "revoked",
                "qualification": asdict(result),
                "coordinator": coordinator,
            }
            checks, consensus_start, bundle_bytes = self._validator_checks(
                delivered_case, result, qualified_at, coordinator, transport
            )
            recheck_failures += sum(not value for value in checks.values())
            outcome = pbft.finalize(
                case_id=case.case_id,
                payload=payload,
                started_at=consensus_start,
                preferred_leader=coordinator,
                validator_checks=checks,
            )
            outcomes.append(outcome)
            _, final_state = self.state_machine.finalize(case.vehicle_id, outcome.committed)
            ledger_time = None
            if outcome.committed and outcome.committed_at is not None:
                leader = outcome.leader or coordinator
                ledgers[leader].append(case.case_id, payload, outcome.committed_at)
                replication_times = []
                replication_nodes = (
                    replica_nodes
                    if self.config.distributed_extension.replicate_read_cache_to_all_rsus
                    else validators
                )
                for replica in replication_nodes:
                    if replica == leader:
                        continue
                    replica_transport = transport if replica in validators else cache_transport
                    message = replica_transport.send(
                        message_type=(
                            "LEDGER_REPLICATION"
                            if replica in validators
                            else "RSU_READ_CACHE_SYNC"
                        ),
                        sender=leader,
                        receiver=replica,
                        case_id=case.case_id,
                        sent_at=outcome.committed_at,
                        size_bytes=1120,
                    )
                    if message.delivered_at is not None:
                        ledgers[replica].copy_from(ledgers[leader])
                        replication_times.append(message.delivered_at)
                ledger_time = max(replication_times, default=outcome.committed_at)

                if self.config.pbft.state_recovery_enabled:
                    longest = max(ledgers.values(), key=lambda ledger: len(ledger.blocks))
                    for replica, ledger in ledgers.items():
                        if len(ledger.blocks) < len(longest.blocks) and ledger.recover_from(list(ledgers.values())):
                            recoveries += 1
                            recovery_transport = transport if replica in validators else cache_transport
                            sync = recovery_transport.send(
                                message_type="STATE_RECOVERY",
                                sender=leader,
                                receiver=replica,
                                case_id=case.case_id,
                                sent_at=ledger_time,
                                size_bytes=max(512, longest.estimated_storage_bytes()),
                            )
                            if sync.delivered_at is not None:
                                ledger_time = max(ledger_time, sync.delivered_at)

            decisions.append(TrustDecision(
                case_id=case.case_id,
                vehicle_id=case.vehicle_id,
                architecture=self.name,
                previous_state=previous,
                new_state=final_state,
                detected_at=detected_at,
                qualified_at=qualified_at,
                finalized_at=outcome.committed_at,
                ledger_available_at=ledger_time,
                decision_margin=result.decision_margin,
                committed=outcome.committed,
                reason=outcome.reason,
                metadata={
                    "evidence_coordinator": coordinator,
                    "independent_roots": result.independent_roots,
                    "correlated_suppressed": result.correlated_suppressed,
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

        valid_ledgers = all(ledger.validate() for ledger in ledgers.values())
        hashes = {tuple(block.block_hash for block in ledger.blocks) for ledger in ledgers.values()}
        return ArchitectureRunResult(
            architecture=self.name,
            decisions=decisions,
            messages=[*transport.messages, *cache_transport.messages],
            consensus=outcomes,
            ledger_blocks=max((len(ledger.blocks) for ledger in ledgers.values()), default=0),
            evidence_rows=evidence_rows,
            runtime_seconds=time.perf_counter() - started,
            ledger_consistent=valid_ledgers and len(hashes) <= 1,
            state_recoveries=recoveries,
            extension_metrics={
                "coordinator_counts": coordinator_counts,
                "validator_recheck_failures": recheck_failures,
                "evidence_guard_checks": evidence_guard_checks,
                "evidence_guard_rejections": evidence_guard_rejections,
                "writable_validator_replicas": len(validators),
                "readable_rsu_replicas": len(replica_nodes),
            },
        )
