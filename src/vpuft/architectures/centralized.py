from __future__ import annotations

import random
import time
from dataclasses import asdict

from .base import Architecture
from ..domain import ArchitectureRunResult, TrustDecision, TrustState
from ..ledger import Ledger
from ..network import SimulatedTransport


class CentralizedVPUFT(Architecture):
    name = "centralized_vpuft"

    def run(self, cases, seed: int) -> ArchitectureRunResult:
        started = time.perf_counter()
        rng = random.Random(seed + 911)
        transport = SimulatedTransport(self.config.network, seed + 17)
        ledger = Ledger()
        audit_replica = Ledger()
        decisions: list[TrustDecision] = []
        evidence_rows: list[dict] = []
        worker_free = [0.0] * self.config.central.workers

        for case in sorted(cases, key=lambda c: (c.opened_at, c.case_id)):
            clean = self.sanitize_case(case)
            detected_at = min((a.observed_at for a in clean.attestations), default=case.opened_at)
            arrivals: list[float] = []
            delivered_attestations = []
            for att in clean.attestations:
                msg = transport.send(
                    message_type="ATTESTATION_TO_SERVER",
                    sender=att.validator_rsu_id,
                    receiver="central-server",
                    case_id=case.case_id,
                    sent_at=att.observed_at,
                    size_bytes=704,
                    random_key=f"evidence-attestation:{att.attestation_id}",
                )
                if msg.delivered_at is not None:
                    arrivals.append(msg.delivered_at)
                    delivered_attestations.append(att)
            delivered_case = self.subset_case(clean, delivered_attestations)
            evidence_rows.extend(self.evidence_row(case, att, seed) for att in delivered_case.attestations)
            now = max(arrivals, default=case.opened_at)

            available = rng.random() <= self.config.central.availability
            if not available or not delivered_case.attestations:
                result = self.engine.qualify(delivered_case, now)
                previous, _ = self.state_machine.pre_finalize(case.vehicle_id, result)
                _, new_state = self.state_machine.finalize(case.vehicle_id, False)
                decisions.append(TrustDecision(
                    case_id=case.case_id,
                    vehicle_id=case.vehicle_id,
                    architecture=self.name,
                    previous_state=previous,
                    new_state=new_state,
                    detected_at=detected_at,
                    qualified_at=None,
                    finalized_at=None,
                    ledger_available_at=None,
                    decision_margin=result.decision_margin,
                    committed=False,
                    reason="central_server_unavailable",
                    metadata={
                        "queue_wait_ms": None,
                        "attempted_attestations": len(clean.attestations),
                        "arrived_attestations": len(delivered_case.attestations),
                        "dropped_attestations": len(clean.attestations) - len(delivered_case.attestations),
                    },
                ))
                continue

            worker_idx = min(range(len(worker_free)), key=worker_free.__getitem__)
            service_start = max(now, worker_free[worker_idx])
            queue_wait = max(0.0, service_start - now)
            max_queue_wait = (
                self.config.central.queue_capacity
                * self.config.central.service_time_ms
                / max(1, self.config.central.workers)
            ) / 1000.0
            if queue_wait > max_queue_wait:
                previous = self.state_machine.get(case.vehicle_id).state
                self.state_machine.get(case.vehicle_id).state = TrustState.QUARANTINED
                decisions.append(TrustDecision(
                    case_id=case.case_id,
                    vehicle_id=case.vehicle_id,
                    architecture=self.name,
                    previous_state=previous,
                    new_state=TrustState.QUARANTINED,
                    detected_at=detected_at,
                    qualified_at=None,
                    finalized_at=None,
                    ledger_available_at=None,
                    decision_margin=0.0,
                    committed=False,
                    reason="central_queue_overflow",
                    metadata={"queue_wait_ms": queue_wait * 1000.0},
                ))
                continue

            service_end = service_start + self.config.central.service_time_ms / 1000.0
            worker_free[worker_idx] = service_end
            result = self.engine.qualify(delivered_case, service_end)
            previous, _ = self.state_machine.pre_finalize(case.vehicle_id, result)
            committed = result.qualified
            reason = result.reason

            if self.config.central.compromised:
                mode = self.config.central.compromise_mode
                if mode == "false_revocation":
                    _, final_state = self.state_machine.force_false_revocation(case.vehicle_id)
                    committed = True
                    reason = "central_compromise_forced_false_revocation"
                elif mode == "censorship":
                    _, final_state = self.state_machine.finalize(case.vehicle_id, False)
                    committed = False
                    reason = "central_compromise_censored_decision"
                else:
                    _, final_state = self.state_machine.finalize(case.vehicle_id, committed)
            else:
                _, final_state = self.state_machine.finalize(case.vehicle_id, committed)

            ledger_time = service_end + 0.001
            if committed:
                payload = {
                    "architecture": self.name,
                    "vehicle_id": case.vehicle_id,
                    "state": final_state.value,
                    "qualification": asdict(result),
                    "reason": reason,
                }
                ledger.append(case.case_id, payload, ledger_time)
                if self.config.central.audit_replica_enabled:
                    audit_replica.copy_from(ledger)

            decisions.append(TrustDecision(
                case_id=case.case_id,
                vehicle_id=case.vehicle_id,
                architecture=self.name,
                previous_state=previous,
                new_state=final_state,
                detected_at=detected_at,
                qualified_at=service_end if result.qualified else None,
                finalized_at=service_end,
                ledger_available_at=ledger_time if committed else None,
                decision_margin=result.decision_margin,
                committed=committed,
                reason=reason,
                metadata={
                    "queue_wait_ms": queue_wait * 1000.0,
                    "supporting_strength": result.supporting_strength,
                    "opposing_strength": result.opposing_strength,
                    "independent_roots": result.independent_roots,
                    "correlated_suppressed": result.correlated_suppressed,
                    "attempted_attestations": len(clean.attestations),
                    "arrived_attestations": len(delivered_case.attestations),
                    "dropped_attestations": len(clean.attestations) - len(delivered_case.attestations),
                },
            ))

        consistent = ledger.validate() and (not self.config.central.audit_replica_enabled or audit_replica.validate())
        return ArchitectureRunResult(
            architecture=self.name,
            decisions=decisions,
            messages=transport.messages,
            consensus=[],
            ledger_blocks=len(ledger.blocks),
            evidence_rows=evidence_rows,
            runtime_seconds=time.perf_counter() - started,
            ledger_consistent=consistent,
            state_recoveries=0,
        )
