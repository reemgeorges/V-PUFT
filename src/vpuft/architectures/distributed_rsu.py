from __future__ import annotations

import time
from dataclasses import asdict

from .base import Architecture
from ..consensus import PBFTConsensus
from ..domain import ArchitectureRunResult, TrustDecision
from ..ledger import Ledger
from ..network import SimulatedTransport


class DistributedRSUVPUFT(Architecture):
    name = "distributed_rsu_vpuft"

    def run(self, cases, seed: int) -> ArchitectureRunResult:
        started = time.perf_counter()
        transport = SimulatedTransport(self.config.network, seed + 31)
        pbft = PBFTConsensus(self.config.pbft, transport, self.keys)
        ledgers = {validator: Ledger() for validator in self.config.pbft.validators}
        decisions, outcomes, evidence_rows = [], [], []
        recoveries = 0

        evidence_coordinator = self.config.pbft.validators[0]
        for case in sorted(cases, key=lambda c: (c.opened_at, c.case_id)):
            clean = self.sanitize_case(case)
            detected_at = min((a.observed_at for a in clean.attestations), default=case.opened_at)
            arrivals: list[float] = []
            delivered_attestations = []
            for att in clean.attestations:
                if att.validator_rsu_id == evidence_coordinator:
                    arrivals.append(att.observed_at)
                    delivered_attestations.append(att)
                    continue
                msg = transport.send(
                    message_type="RSU_EVIDENCE_EXCHANGE",
                    sender=att.validator_rsu_id,
                    receiver=evidence_coordinator,
                    case_id=case.case_id,
                    sent_at=att.observed_at,
                    size_bytes=704,
                )
                if msg.delivered_at is not None:
                    arrivals.append(msg.delivered_at)
                    delivered_attestations.append(att)
            delivered_case = self.subset_case(clean, delivered_attestations)
            evidence_rows.extend(self.evidence_row(case, att, seed) for att in delivered_case.attestations)
            qualified_at_candidate = max(arrivals, default=case.opened_at)
            result = self.engine.qualify(delivered_case, qualified_at_candidate)
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
                        "independent_roots": result.independent_roots,
                        "correlated_suppressed": result.correlated_suppressed,
                        "evidence_coordinator": evidence_coordinator,
                        "attempted_attestations": len(clean.attestations),
                        "arrived_attestations": len(delivered_case.attestations),
                        "dropped_attestations": len(clean.attestations) - len(delivered_case.attestations),
                    },
                ))
                continue

            payload = {
                "vehicle_id": case.vehicle_id,
                "case_id": case.case_id,
                "attack_type": case.attack_type.value,
                "requested_state": "revoked",
                "qualification": asdict(result),
            }
            outcome = pbft.finalize(case_id=case.case_id, payload=payload, started_at=qualified_at_candidate)
            outcomes.append(outcome)
            _, final_state = self.state_machine.finalize(case.vehicle_id, outcome.committed)
            ledger_time = None
            if outcome.committed and outcome.committed_at is not None:
                leader = outcome.leader or self.config.pbft.validators[0]
                ledgers[leader].append(case.case_id, payload, outcome.committed_at)
                replication_times = []
                for validator in self.config.pbft.validators:
                    if validator == leader:
                        continue
                    msg = transport.send(
                        message_type="LEDGER_REPLICATION",
                        sender=leader,
                        receiver=validator,
                        case_id=case.case_id,
                        sent_at=outcome.committed_at,
                        size_bytes=1120,
                    )
                    if msg.delivered_at is not None:
                        ledgers[validator].copy_from(ledgers[leader])
                        replication_times.append(msg.delivered_at)
                ledger_time = max(replication_times, default=outcome.committed_at)

                if self.config.pbft.state_recovery_enabled:
                    longest = max(ledgers.values(), key=lambda ledger: len(ledger.blocks))
                    for validator, ledger in ledgers.items():
                        if len(ledger.blocks) < len(longest.blocks) and ledger.recover_from(list(ledgers.values())):
                            recoveries += 1
                            sync = transport.send(
                                message_type="STATE_RECOVERY",
                                sender=leader,
                                receiver=validator,
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
                qualified_at=qualified_at_candidate,
                finalized_at=outcome.committed_at,
                ledger_available_at=ledger_time,
                decision_margin=result.decision_margin,
                committed=outcome.committed,
                reason=outcome.reason,
                metadata={
                    "view": outcome.view,
                    "view_changes": outcome.view_changes,
                    "prepare_votes": outcome.prepare_votes,
                    "commit_votes": outcome.commit_votes,
                    "independent_roots": result.independent_roots,
                    "correlated_suppressed": result.correlated_suppressed,
                    "evidence_coordinator": evidence_coordinator,
                    "attempted_attestations": len(clean.attestations),
                    "arrived_attestations": len(delivered_case.attestations),
                    "dropped_attestations": len(clean.attestations) - len(delivered_case.attestations),
                },
            ))

        consistent = all(ledger.validate() for ledger in ledgers.values())
        hashes = {tuple(block.block_hash for block in ledger.blocks) for ledger in ledgers.values()}
        consistent = consistent and len(hashes) <= 1
        max_ledger_blocks = max((len(ledger.blocks) for ledger in ledgers.values()), default=0)
        return ArchitectureRunResult(
            architecture=self.name,
            decisions=decisions,
            messages=transport.messages,
            consensus=outcomes,
            ledger_blocks=max_ledger_blocks,
            evidence_rows=evidence_rows,
            runtime_seconds=time.perf_counter() - started,
            ledger_consistent=consistent,
            state_recoveries=recoveries,
        )
