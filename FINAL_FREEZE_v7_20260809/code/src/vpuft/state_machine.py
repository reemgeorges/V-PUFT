from __future__ import annotations

from dataclasses import dataclass

from .domain import QualificationResult, TrustState


@dataclass
class VehicleTrustRecord:
    vehicle_id: str
    state: TrustState = TrustState.TRUSTED
    last_margin: float = 0.0
    transitions: int = 0


class TrustStateMachine:
    """Staged decision machine with hysteresis and irreversible final revocation."""

    def __init__(self, revoke_threshold: float = 0.50, recover_threshold: float = 0.20) -> None:
        if recover_threshold >= revoke_threshold:
            raise ValueError("recover_threshold must be lower than revoke_threshold")
        self.revoke_threshold = revoke_threshold
        self.recover_threshold = recover_threshold
        self.records: dict[str, VehicleTrustRecord] = {}

    def get(self, vehicle_id: str) -> VehicleTrustRecord:
        return self.records.setdefault(vehicle_id, VehicleTrustRecord(vehicle_id=vehicle_id))

    def pre_finalize(self, vehicle_id: str, result: QualificationResult) -> tuple[TrustState, TrustState]:
        record = self.get(vehicle_id)
        previous = record.state
        if record.state == TrustState.REVOKED:
            return previous, previous
        if result.qualified:
            record.state = TrustState.REVOCATION_PENDING
        elif result.decision_margin >= self.recover_threshold:
            record.state = TrustState.QUARANTINED
        elif result.supporting_strength > 0:
            record.state = TrustState.SUSPECTED
        elif record.state in {TrustState.SUSPECTED, TrustState.QUARANTINED} and result.decision_margin <= 0:
            record.state = TrustState.TRUSTED
        record.last_margin = result.decision_margin
        if previous != record.state:
            record.transitions += 1
        return previous, record.state

    def finalize(self, vehicle_id: str, committed: bool) -> tuple[TrustState, TrustState]:
        record = self.get(vehicle_id)
        previous = record.state
        if committed and record.state == TrustState.REVOCATION_PENDING:
            record.state = TrustState.REVOKED
        elif not committed and record.state == TrustState.REVOCATION_PENDING:
            record.state = TrustState.QUARANTINED
        if previous != record.state:
            record.transitions += 1
        return previous, record.state

    def force_false_revocation(self, vehicle_id: str) -> tuple[TrustState, TrustState]:
        record = self.get(vehicle_id)
        previous = record.state
        record.state = TrustState.REVOKED
        if previous != record.state:
            record.transitions += 1
        return previous, record.state
