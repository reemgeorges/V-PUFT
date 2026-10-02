from __future__ import annotations

from collections import defaultdict
from typing import Callable

from .des import Scheduler

from .config import PBFTConfig
from .crypto import KeyRegistry, digest_hex
from .domain import ConsensusOutcome
from .network import SimulatedTransport


class PBFTConsensus:
    """
    Signed PBFT-style finalizer with explicit recipient certificates, vote locks,
    network loss/retries, leader timeout and bounded view change.

    It is a research simulator, not a production PBFT implementation.
    """

    def __init__(
        self,
        config: PBFTConfig,
        transport: SimulatedTransport,
        keys: KeyRegistry,
        online: Callable[[str, float], bool] | None = None,
    ) -> None:
        self.config = config
        self.transport = transport
        self.keys = keys
        self.online = online or (lambda _validator, _time: True)
        self._vote_locks: dict[tuple[str, int, str, str], str] = {}
        for validator in config.validators:
            self.keys.ensure_identity(validator)

    @property
    def quorum(self) -> int:
        return 2 * self.config.max_byzantine + 1

    def _behavior(self, validator: str) -> str:
        return self.config.validator_behaviors.get(validator, "honest")

    def _can_vote(self, validator: str, valid_proposal: bool) -> bool:
        behavior = self._behavior(validator)
        if behavior == "offline":
            return False
        if behavior == "reject_valid":
            return not valid_proposal
        if behavior in {"accept_invalid", "equivocate"}:
            return True
        return valid_proposal

    def _lock_vote(self, validator: str, view: int, phase: str, case_id: str, digest: str) -> bool:
        key = (validator, view, phase, case_id)
        old = self._vote_locks.get(key)
        if old is not None and old != digest and self._behavior(validator) != "equivocate":
            return False
        self._vote_locks[key] = digest
        return True

    def _certificate_counts(
        self,
        *,
        phase: str,
        voters: list[str],
        validators: list[str],
        case_id: str,
        view: int,
        digest: str,
        sent_at: float,
    ) -> tuple[int, float]:
        received: dict[str, set[str]] = defaultdict(set)
        latest_time = sent_at
        for voter in voters:
            if not self._lock_vote(voter, view, phase, case_id, digest):
                continue
            vote = {"case_id": case_id, "view": view, "phase": phase, "digest": digest}
            signature = self.keys.sign(voter, vote)
            if not self.keys.verify(voter, vote, signature):
                continue
            received[voter].add(voter)
            messages = self.transport.broadcast(
                message_type=phase,
                sender=voter,
                receivers=[v for v in validators if v != voter],
                case_id=case_id,
                sent_at=sent_at,
                size_bytes=352,
            )
            for message in messages:
                if message.delivered_at is not None:
                    received[message.receiver].add(voter)
                    latest_time = max(latest_time, message.delivered_at)
        max_certificate = max((len(votes) for votes in received.values()), default=0)
        return max_certificate, latest_time

    def finalize(
        self,
        *,
        case_id: str,
        payload: dict,
        started_at: float,
        preferred_leader: str | None = None,
        semantic_proposal_valid: bool = True,
        validator_checks: dict[str, bool] | None = None,
    ) -> ConsensusOutcome:
        validators = list(self.config.validators)
        if preferred_leader in validators:
            validators = [preferred_leader, *[v for v in validators if v != preferred_leader]]
        payload_digest = digest_hex(payload)
        view_changes = 0
        total_message_start = len(self.transport.messages)
        last_prepare = 0
        last_commit = 0
        fault_activated = False
        invalid_proposal_attempted = False
        rechecks = validator_checks or {}

        for view in range(self.config.max_views):
            leader = validators[view % len(validators)]
            view_start = started_at + view * self.config.timeout_ms / 1000.0
            leader_behavior = self._behavior(leader)
            if not self.online(leader, view_start) or leader_behavior == "offline":
                fault_activated = fault_activated or leader_behavior == "offline"
                view_changes += 1
                continue

            proposal = {"case_id": case_id, "view": view, "leader": leader, "payload_digest": payload_digest}
            proposal_signature = self.keys.sign(leader, proposal)
            leader_semantic_valid = semantic_proposal_valid and leader_behavior != "propose_invalid"
            if leader_behavior == "propose_invalid":
                fault_activated = True
                invalid_proposal_attempted = True
            valid_proposal = self.keys.verify(leader, proposal, proposal_signature) and leader_semantic_valid
            eligible_voters: list[str] = []
            proposal_latest = view_start
            for validator in validators:
                if not self.online(validator, view_start):
                    continue
                if validator == leader:
                    delivered = True
                else:
                    message = self.transport.send(
                        message_type="PRE_PREPARE",
                        sender=leader,
                        receiver=validator,
                        case_id=case_id,
                        sent_at=view_start,
                        size_bytes=544,
                    )
                    delivered = message.delivered_at is not None
                    if message.delivered_at is not None:
                        proposal_latest = max(proposal_latest, message.delivered_at)
                behavior = self._behavior(validator)
                if behavior == "offline":
                    fault_activated = True
                if behavior == "reject_valid" and valid_proposal:
                    fault_activated = True
                if delivered and self._can_vote(validator, valid_proposal):
                    validator_check = rechecks.get(validator, True)
                    if behavior in {"accept_invalid", "equivocate"} and not valid_proposal:
                        fault_activated = True
                    if behavior in {"accept_invalid", "equivocate"} or validator_check:
                        eligible_voters.append(validator)

            last_prepare, prepare_latest = self._certificate_counts(
                phase="PREPARE",
                voters=eligible_voters,
                validators=validators,
                case_id=case_id,
                view=view,
                digest=payload_digest,
                sent_at=proposal_latest,
            )
            if last_prepare < self.quorum:
                view_changes += 1
                continue

            commit_voters = [v for v in eligible_voters if self.online(v, prepare_latest)]
            last_commit, commit_latest = self._certificate_counts(
                phase="COMMIT",
                voters=commit_voters,
                validators=validators,
                case_id=case_id,
                view=view,
                digest=payload_digest,
                sent_at=prepare_latest,
            )
            if last_commit >= self.quorum:
                relevant = self.transport.messages[total_message_start:]
                return ConsensusOutcome(
                    case_id=case_id,
                    committed=True,
                    view=view,
                    leader=leader,
                    prepare_votes=last_prepare,
                    commit_votes=last_commit,
                    started_at=started_at,
                    committed_at=commit_latest,
                    view_changes=view_changes,
                    reason="committed",
                    message_count=len(relevant),
                    bytes_sent=sum(m.size_bytes for m in relevant),
                    safety_violation=False,
                    semantic_proposal_valid=leader_semantic_valid,
                    fault_activated=fault_activated,
                    validator_rechecks=len(rechecks),
                    validator_recheck_failures=sum(not accepted for accepted in rechecks.values()),
                    invalid_proposal_attempted=invalid_proposal_attempted,
                )
            view_changes += 1

        relevant = self.transport.messages[total_message_start:]
        return ConsensusOutcome(
            case_id=case_id,
            committed=False,
            view=max(0, self.config.max_views - 1),
            leader=None,
            prepare_votes=last_prepare,
            commit_votes=last_commit,
            started_at=started_at,
            committed_at=None,
            view_changes=view_changes,
            reason="liveness_failure_after_max_views",
            message_count=len(relevant),
            bytes_sent=sum(m.size_bytes for m in relevant),
            safety_violation=False,
            semantic_proposal_valid=semantic_proposal_valid,
            fault_activated=fault_activated,
            validator_rechecks=len(rechecks),
            validator_recheck_failures=sum(not accepted for accepted in rechecks.values()),
            invalid_proposal_attempted=invalid_proposal_attempted,
        )

    def finalize_async(
        self,
        *,
        scheduler: Scheduler,
        case_id: str,
        payload: dict,
        started_at: float,
        on_complete: Callable[[ConsensusOutcome, float], None],
        preferred_leader: str | None = None,
        semantic_proposal_valid: bool = True,
        validator_checks: dict[str, bool] | None = None,
        case_order_index: int = 0,
    ) -> None:
        """Event-driven PBFT path used by the corrected Scenario 5 scheduler.

        Voting/quorum semantics mirror ``finalize``; only the timing/execution
        model changes so overlapping instances share the same event schedule.
        """
        validators = list(self.config.validators)
        if preferred_leader in validators:
            validators = [preferred_leader, *[v for v in validators if v != preferred_leader]]
        payload_digest = digest_hex(payload)
        rechecks = validator_checks or {}
        state = {
            "view_changes": 0,
            "last_prepare": 0,
            "last_commit": 0,
            "fault_activated": False,
            "invalid_proposal_attempted": False,
            "last_semantic_valid": semantic_proposal_valid,
        }
        pbft_types = {"PRE_PREPARE", "PREPARE", "COMMIT"}

        def message_stats() -> tuple[int, int]:
            relevant = [
                message for message in self.transport.messages
                if message.case_id == case_id and message.message_type in pbft_types
            ]
            return len(relevant), sum(message.size_bytes for message in relevant)

        def finish_failure() -> None:
            count, bytes_sent = message_stats()
            outcome = ConsensusOutcome(
                case_id=case_id,
                committed=False,
                view=max(0, self.config.max_views - 1),
                leader=None,
                prepare_votes=state["last_prepare"],
                commit_votes=state["last_commit"],
                started_at=started_at,
                committed_at=None,
                view_changes=state["view_changes"],
                reason="liveness_failure_after_max_views",
                message_count=count,
                bytes_sent=bytes_sent,
                safety_violation=False,
                semantic_proposal_valid=semantic_proposal_valid,
                fault_activated=state["fault_activated"],
                validator_rechecks=len(rechecks),
                validator_recheck_failures=sum(not accepted for accepted in rechecks.values()),
                invalid_proposal_attempted=state["invalid_proposal_attempted"],
            )
            on_complete(outcome, scheduler.now)

        def schedule_view(view: int, earliest: float) -> None:
            if view >= self.config.max_views:
                scheduler.schedule(
                    earliest,
                    finish_failure,
                    phase_rank=58,
                    case_order_index=case_order_index,
                    key=f"pbft-fail:{case_id}",
                )
                return
            nominal = started_at + view * self.config.timeout_ms / 1000.0
            when = max(float(earliest), nominal)
            scheduler.schedule(
                when,
                lambda view=view: start_view(view),
                phase_rank=50,
                case_order_index=case_order_index,
                key=f"pbft-view:{case_id}:{view}",
            )

        def start_view(view: int) -> None:
            leader = validators[view % len(validators)]
            view_start = scheduler.now
            leader_behavior = self._behavior(leader)
            if not self.online(leader, view_start) or leader_behavior == "offline":
                state["fault_activated"] = state["fault_activated"] or leader_behavior == "offline"
                state["view_changes"] += 1
                schedule_view(view + 1, scheduler.now)
                return

            proposal = {"case_id": case_id, "view": view, "leader": leader, "payload_digest": payload_digest}
            proposal_signature = self.keys.sign(leader, proposal)
            leader_semantic_valid = semantic_proposal_valid and leader_behavior != "propose_invalid"
            state["last_semantic_valid"] = leader_semantic_valid
            if leader_behavior == "propose_invalid":
                state["fault_activated"] = True
                state["invalid_proposal_attempted"] = True
            valid_proposal = self.keys.verify(leader, proposal, proposal_signature) and leader_semantic_valid

            delivered_to: dict[str, bool] = {leader: True}
            remote = [v for v in validators if v != leader and self.online(v, view_start)]
            pending = len(remote)

            def proposal_phase_done() -> None:
                eligible_voters: list[str] = []
                for validator in validators:
                    if not self.online(validator, view_start):
                        continue
                    delivered = delivered_to.get(validator, validator == leader)
                    behavior = self._behavior(validator)
                    if behavior == "offline":
                        state["fault_activated"] = True
                    if behavior == "reject_valid" and valid_proposal:
                        state["fault_activated"] = True
                    if delivered and self._can_vote(validator, valid_proposal):
                        validator_check = rechecks.get(validator, True)
                        if behavior in {"accept_invalid", "equivocate"} and not valid_proposal:
                            state["fault_activated"] = True
                        if behavior in {"accept_invalid", "equivocate"} or validator_check:
                            eligible_voters.append(validator)
                start_certificate_phase(view, leader, "PREPARE", eligible_voters, eligible_voters)

            if pending == 0:
                proposal_phase_done()
                return

            remaining = {"count": pending}
            for validator in remote:
                def complete(message, _resolved_at, *, validator=validator) -> None:
                    delivered_to[validator] = message.delivered_at is not None
                    remaining["count"] -= 1
                    if remaining["count"] == 0:
                        scheduler.schedule(
                            scheduler.now,
                            proposal_phase_done,
                            phase_rank=52,
                            case_order_index=case_order_index,
                            key=f"pbft-proposal-done:{case_id}:{view}",
                        )

                self.transport.send_async(
                    message_type="PRE_PREPARE",
                    sender=leader,
                    receiver=validator,
                    case_id=case_id,
                    sent_at=view_start,
                    size_bytes=544,
                    random_key=f"pbft:{case_id}:view={view}:PRE_PREPARE:{leader}->{validator}",
                    on_complete=complete,
                    case_order_index=case_order_index,
                    phase_rank=50,
                )

        def start_certificate_phase(
            view: int,
            leader: str,
            phase: str,
            voters: list[str],
            eligible_voters: list[str],
        ) -> None:
            phase_start = scheduler.now
            received: dict[str, set[str]] = defaultdict(set)
            sends: list[tuple[str, str]] = []
            for voter in voters:
                if not self._lock_vote(voter, view, phase, case_id, payload_digest):
                    continue
                vote = {"case_id": case_id, "view": view, "phase": phase, "digest": payload_digest}
                signature = self.keys.sign(voter, vote)
                if not self.keys.verify(voter, vote, signature):
                    continue
                received[voter].add(voter)
                for receiver in validators:
                    if receiver != voter:
                        sends.append((voter, receiver))

            def phase_done() -> None:
                max_certificate = max((len(votes) for votes in received.values()), default=0)
                if phase == "PREPARE":
                    state["last_prepare"] = max_certificate
                    if max_certificate < self.quorum:
                        state["view_changes"] += 1
                        schedule_view(view + 1, scheduler.now)
                        return
                    commit_voters = [v for v in eligible_voters if self.online(v, scheduler.now)]
                    start_certificate_phase(view, leader, "COMMIT", commit_voters, eligible_voters)
                    return

                state["last_commit"] = max_certificate
                if max_certificate >= self.quorum:
                    count, bytes_sent = message_stats()
                    committed_at = scheduler.now
                    outcome = ConsensusOutcome(
                        case_id=case_id,
                        committed=True,
                        view=view,
                        leader=leader,
                        prepare_votes=state["last_prepare"],
                        commit_votes=max_certificate,
                        started_at=started_at,
                        committed_at=committed_at,
                        view_changes=state["view_changes"],
                        reason="committed",
                        message_count=count,
                        bytes_sent=bytes_sent,
                        safety_violation=False,
                        semantic_proposal_valid=state["last_semantic_valid"],
                        fault_activated=state["fault_activated"],
                        validator_rechecks=len(rechecks),
                        validator_recheck_failures=sum(not accepted for accepted in rechecks.values()),
                        invalid_proposal_attempted=state["invalid_proposal_attempted"],
                    )
                    on_complete(outcome, scheduler.now)
                    return
                state["view_changes"] += 1
                schedule_view(view + 1, scheduler.now)

            if not sends:
                phase_done()
                return

            remaining = {"count": len(sends)}
            for voter, receiver in sends:
                def complete(message, _resolved_at, *, voter=voter, receiver=receiver) -> None:
                    if message.delivered_at is not None:
                        received[receiver].add(voter)
                    remaining["count"] -= 1
                    if remaining["count"] == 0:
                        scheduler.schedule(
                            scheduler.now,
                            phase_done,
                            phase_rank=56 if phase == "COMMIT" else 54,
                            case_order_index=case_order_index,
                            key=f"pbft-{phase.lower()}-done:{case_id}:{view}",
                        )

                self.transport.send_async(
                    message_type=phase,
                    sender=voter,
                    receiver=receiver,
                    case_id=case_id,
                    sent_at=phase_start,
                    size_bytes=352,
                    random_key=f"pbft:{case_id}:view={view}:{phase}:{voter}->{receiver}",
                    on_complete=complete,
                    case_order_index=case_order_index,
                    phase_rank=53 if phase == "PREPARE" else 55,
                )

        schedule_view(0, started_at)

