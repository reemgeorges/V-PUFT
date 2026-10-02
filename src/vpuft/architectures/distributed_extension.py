from __future__ import annotations

import time
from dataclasses import asdict, replace
from hashlib import sha256

from .base import Architecture
from ..consensus import PBFTConsensus
from ..crypto import digest_hex
from ..des import Scheduler
from ..domain import ArchitectureRunResult, EvidenceCase, TrustDecision
from ..ledger import Ledger
from ..network import SimulatedTransport, audit_link_order


class DistributedRSUExtendedVPUFT(Architecture):
    """Post-freeze distributed architecture with causal event-time scheduling."""

    name = "distributed_rsu_vpuft_extension"

    def _select_coordinator(self, case: EvidenceCase) -> str:
        validators = tuple(self.config.pbft.validators)
        strategy = self.config.distributed_extension.coordinator_strategy
        if strategy == "first_observer_then_hash":
            local = [att for att in case.attestations if att.validator_rsu_id in validators]
            if local:
                return min(local, key=lambda att: (att.observed_at, att.attestation_id)).validator_rsu_id
        offset = int(sha256(case.case_id.encode("utf-8")).hexdigest(), 16) % len(validators)
        return validators[offset]

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
        pbft = PBFTConsensus(self.config.pbft, transport, self.keys)
        validators = tuple(self.config.pbft.validators)
        rsu_nodes = tuple(f"rsu-{index}" for index in range(1, self.config.simulation.rsu_count + 1))
        replica_nodes = tuple(dict.fromkeys((*validators, *rsu_nodes)))
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
                    "evidence_coordinator": ctx["coordinator"],
                    "independent_roots": result.independent_roots,
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
            checks: dict[str, bool] = {}
            remote = [validator for validator in validators if validator != coordinator]
            pending = {"count": len(remote)}

            # Coordinator requalification is local and immediate.
            local_case = self.sanitize_case(delivered_case)
            local_result = self.engine.qualify(local_case, ctx["qualified_at"])
            checks[coordinator] = digest_hex(asdict(local_result)) == expected

            def bundles_done() -> None:
                counters["recheck_failures"] += sum(not value for value in checks.values())
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
                def bundle_complete(message, _resolved_at, *, validator=validator) -> None:
                    if message.delivered_at is None:
                        checks[validator] = False
                    else:
                        validator_case = self.sanitize_case(delivered_case)
                        reproduced = self.engine.qualify(validator_case, ctx["qualified_at"])
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
                    size_bytes=bundle_bytes,
                    random_key=f"bundle:{case.case_id}:{coordinator}->{validator}",
                    on_complete=bundle_complete,
                    case_order_index=index,
                    phase_rank=40,
                )

        def case_ready(ctx: dict) -> None:
            case = ctx["case"]
            clean = ctx["clean"]
            delivered_case = self.subset_case(clean, ctx["delivered_attestations"])
            ctx["delivered_case"] = delivered_case
            ctx["qualified_at"] = scheduler.now
            evidence_rows.extend(self.evidence_row(case, att, seed) for att in delivered_case.attestations)
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
                        "evidence_coordinator": ctx["coordinator"],
                        "independent_roots": result.independent_roots,
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
            begin_validator_checks(ctx, result, guard_checks, guard_stable, previous)

        for case in ordered_cases:
            index = case_order[case.case_id]
            clean = self.sanitize_case(case)
            coordinator = self._select_coordinator(clean)
            coordinator_counts[coordinator] += 1
            ctx = {
                "case": case,
                "clean": clean,
                "index": index,
                "coordinator": coordinator,
                "detected_at": min((att.observed_at for att in clean.attestations), default=case.opened_at),
                "pending": len(clean.attestations),
                "delivered_attestations": [],
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

            for attestation in clean.attestations:
                if attestation.validator_rsu_id == coordinator:
                    def local_complete(*, ctx=ctx, attestation=attestation) -> None:
                        ctx["delivered_attestations"].append(attestation)
                        ctx["pending"] -= 1
                        if ctx["pending"] == 0:
                            scheduler.schedule(
                                scheduler.now,
                                lambda ctx=ctx: case_ready(ctx),
                                phase_rank=30,
                                case_order_index=ctx["index"],
                                key=f"distributed-ready:{ctx['case'].case_id}",
                            )

                    scheduler.schedule(
                        attestation.observed_at,
                        local_complete,
                        phase_rank=15,
                        case_order_index=index,
                        key=f"local-evidence:{attestation.attestation_id}",
                    )
                    continue

                def evidence_complete(message, _resolved_at, *, ctx=ctx, attestation=attestation) -> None:
                    if message.delivered_at is not None:
                        ctx["delivered_attestations"].append(attestation)
                    ctx["pending"] -= 1
                    if ctx["pending"] == 0:
                        scheduler.schedule(
                            scheduler.now,
                            lambda ctx=ctx: case_ready(ctx),
                            phase_rank=30,
                            case_order_index=ctx["index"],
                            key=f"distributed-ready:{ctx['case'].case_id}",
                        )

                transport.send_async(
                    message_type="RSU_EVIDENCE_EXCHANGE",
                    sender=attestation.validator_rsu_id,
                    receiver=coordinator,
                    case_id=case.case_id,
                    sent_at=attestation.observed_at,
                    size_bytes=704,
                    random_key=f"evidence-attestation:{attestation.attestation_id}",
                    random_stream_seed=seed,
                    on_complete=evidence_complete,
                    case_order_index=index,
                    phase_rank=10,
                )

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
                "evidence_guard_checks": counters["evidence_guard_checks"],
                "evidence_guard_rejections": counters["evidence_guard_rejections"],
                "writable_validator_replicas": len(validators),
                "readable_rsu_replicas": len(replica_nodes),
                "transport_audit": main_audit,
                "cache_transport_audit": cache_audit,
            },
        )
