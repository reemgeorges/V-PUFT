from dataclasses import replace
from pathlib import Path

from vpuft.architectures import DistributedRSUExtendedVPUFT
from vpuft.config import load_config
from vpuft.crypto import KeyRegistry
from vpuft.consensus import PBFTConsensus
from vpuft.network import SimulatedTransport
from vpuft.config import NetworkConfig
from vpuft.domain import EvidenceDirection

from test_security_audit_phase6 import att, case

REPO_ROOT = Path(__file__).resolve().parents[1]


def _coordinator_config():
    return load_config(REPO_ROOT / "configs/extension_v5_coordinator_security.json")


def test_security_profile_uses_same_v5_committee_and_qe_base_as_historical_v5():
    historical = load_config(REPO_ROOT / "configs/extension_v5_validator.json")
    secured = _coordinator_config()
    assert secured.pbft.validators == historical.pbft.validators
    assert secured.pbft.resolved_quorum == historical.pbft.resolved_quorum == 4
    assert secured.pbft.max_byzantine == historical.pbft.max_byzantine == 1
    assert secured.policies == historical.policies
    assert secured.weights == historical.weights
    assert historical.distributed_extension.coordinator_pool == ("rsu-1", "rsu-2", "rsu-3", "rsu-4")
    assert secured.distributed_extension.coordinator_pool == secured.pbft.validators


def test_v5_coordinator_is_fixed_across_arrival_order_and_partial_evidence_views():
    config = _coordinator_config()
    keys = KeyRegistry(config.security.deterministic_master_seed)
    architecture = DistributedRSUExtendedVPUFT(config, keys)
    reports = [
        att(keys, "same-case", "root-a", "rsu-1", "cell-a", at=1.0),
        att(keys, "same-case", "root-b", "rsu-2", "cell-b", at=1.0),
        att(keys, "same-case", "root-c", "rsu-3", "cell-c", at=1.2),
    ]
    whole = case("same-case", reports)
    reversed_order = case("same-case", list(reversed(reports)))
    partial_left = case("same-case", reports[:1])
    partial_right = case("same-case", reports[1:])
    selected = architecture._select_coordinator(whole)

    assert selected in config.pbft.validators
    assert architecture._select_coordinator(reversed_order) == selected
    assert architecture._select_coordinator(partial_left) == selected
    assert architecture._select_coordinator(partial_right) == selected


def test_all_five_v5_validators_are_eligible_deterministic_coordinators():
    config = _coordinator_config()
    architecture = DistributedRSUExtendedVPUFT(config, KeyRegistry())
    selected = {
        architecture._select_coordinator(case(f"case-{index}"))
        for index in range(500)
    }
    assert selected == set(config.pbft.validators)


def test_initially_offline_deterministic_coordinator_fails_closed_without_takeover():
    config = _coordinator_config()
    keys = KeyRegistry(config.security.deterministic_master_seed)
    provisional = DistributedRSUExtendedVPUFT(config, keys)
    reports = [
        att(keys, "offline-case", "root-a", "rsu-1", "cell-a"),
        att(keys, "offline-case", "root-b", "rsu-2", "cell-b", at=1.1),
    ]
    target = case("offline-case", reports)
    coordinator = provisional._select_coordinator(target)
    offline_config = replace(
        config,
        pbft=replace(config.pbft, validator_behaviors={coordinator: "offline"}),
    )

    result = DistributedRSUExtendedVPUFT(offline_config, keys).run([target], seed=33)

    assert result.consensus == []
    assert len(result.decisions) == 1
    assert not result.decisions[0].committed
    assert result.decisions[0].reason == "evidence_coordinator_unavailable_no_safe_takeover"
    assert result.decisions[0].metadata["evidence_coordinator"] == coordinator


def test_v5_four_of_five_does_not_repair_cross_view_certificate_safety():
    config = _coordinator_config()
    keys = KeyRegistry(config.security.deterministic_master_seed)
    network = NetworkConfig(packet_delivery_ratio=1.0, base_latency_ms=1.0, jitter_ms=0.0)
    consensus = PBFTConsensus(config.pbft, SimulatedTransport(network, 98), keys)

    revoke = consensus.finalize(case_id="same-v5-case", payload={"decision": "revoke"}, started_at=0.0)
    retain = consensus.finalize(case_id="same-v5-case", payload={"decision": "retain"}, started_at=0.1)

    assert revoke.committed and revoke.view == 0 and revoke.commit_votes >= 4
    assert retain.committed and retain.view == 1 and retain.commit_votes >= 4
    assert config.pbft.validators == ("rsu-1", "rsu-2", "rsu-3", "rsu-4", "rsu-5")
    assert config.pbft.max_byzantine == 1 and config.pbft.resolved_quorum == 4
    assert config.pbft.membership_epoch == "v5-coordinator-security-fixed-epoch-v1"
    assert consensus._vote_locks[("rsu-1", 0, "PREPARE", "same-v5-case")] != consensus._vote_locks[("rsu-1", 1, "PREPARE", "same-v5-case")]


def test_v5_single_view_mode_commits_normally_then_rejects_conflicting_retry():
    config = _coordinator_config()
    pbft = replace(config.pbft, single_view_safety_mode=True)
    consensus = PBFTConsensus(pbft, SimulatedTransport(NetworkConfig(packet_delivery_ratio=1.0), 981),
                              KeyRegistry(config.security.deterministic_master_seed))
    first = consensus.finalize(case_id="safe-one-view", payload={"decision": "revoke"}, started_at=0.0)
    retry = consensus.finalize(case_id="safe-one-view", payload={"decision": "retain"}, started_at=0.1)
    assert first.committed and first.view == 0 and first.prepare_votes >= 4 and first.commit_votes >= 4
    assert not retry.committed and retry.reason == "single_view_safety_mode_no_verified_transition"
    assert retry.view == 0 and retry.commit_votes < 4


def test_v5_single_view_mode_fails_closed_when_initial_coordinator_is_offline():
    config = _coordinator_config()
    behaviors = {config.pbft.validators[0]: "offline"}
    pbft = replace(config.pbft, single_view_safety_mode=True, validator_behaviors=behaviors)
    consensus = PBFTConsensus(pbft, SimulatedTransport(NetworkConfig(packet_delivery_ratio=1.0), 982),
                              KeyRegistry(config.security.deterministic_master_seed))
    outcome = consensus.finalize(case_id="offline-one-view", payload={"decision": "revoke"},
                                 started_at=0.0, preferred_leader=config.pbft.validators[0])
    assert not outcome.committed
    assert outcome.reason == "single_view_safety_mode_no_verified_transition"
    assert outcome.view == 0


def test_v5_single_view_mode_async_timeout_does_not_advance_view():
    from vpuft.des import Scheduler

    config = _coordinator_config()
    behaviors = {config.pbft.validators[0]: "offline"}
    pbft = replace(config.pbft, single_view_safety_mode=True, validator_behaviors=behaviors)
    scheduler = Scheduler()
    consensus = PBFTConsensus(pbft, SimulatedTransport(NetworkConfig(packet_delivery_ratio=1.0), 983,
                                                        scheduler=scheduler),
                              KeyRegistry(config.security.deterministic_master_seed))
    outcomes = []
    consensus.finalize_async(
        scheduler=scheduler, case_id="async-offline-one-view", payload={"decision": "revoke"},
        started_at=0.0, preferred_leader=config.pbft.validators[0],
        on_complete=lambda outcome, _time: outcomes.append(outcome),
    )
    scheduler.run()
    assert len(outcomes) == 1
    assert not outcomes[0].committed
    assert outcomes[0].view == 0
    assert outcomes[0].reason == "single_view_safety_mode_no_verified_transition"


def test_v5_offline_pbft_leader_guarded_failure_contrasts_with_legacy_local_rotation():
    config = _coordinator_config()
    network = NetworkConfig(packet_delivery_ratio=1.0, base_latency_ms=1.0, jitter_ms=0.0)
    guarded = PBFTConsensus(
        replace(config.pbft, single_view_safety_mode=True, validator_behaviors={"rsu-1": "offline"}),
        SimulatedTransport(network, 986), KeyRegistry(config.security.deterministic_master_seed),
    ).finalize(case_id="leader-offline", payload={"decision": "revoke"}, started_at=0.0,
               preferred_leader="rsu-1")
    legacy = PBFTConsensus(
        replace(config.pbft, single_view_safety_mode=False, validator_behaviors={"rsu-1": "offline"}),
        SimulatedTransport(network, 986), KeyRegistry(config.security.deterministic_master_seed),
    ).finalize(case_id="leader-offline", payload={"decision": "revoke"}, started_at=0.0,
               preferred_leader="rsu-1")

    assert not guarded.committed and guarded.view == 0
    assert guarded.reason == "single_view_safety_mode_no_verified_transition"
    assert legacy.committed and legacy.view == 1


def _v5_signed_case(case_id="integrated-fault-case", opposing=False):
    config = _coordinator_config()
    keys = KeyRegistry(config.security.deterministic_master_seed)
    reports = [
        att(keys, case_id, f"support-root-{index}", f"rsu-{index}", f"cell-{index}", at=1 + index / 10)
        for index in range(1, 6)
    ]
    if opposing:
        reports.extend(
            att(keys, case_id, f"oppose-root-{index}", f"rsu-{index}", f"cell-{index}",
                direction=EvidenceDirection.OPPOSES, at=1.05 + index / 10)
            for index in range(1, 6)
        )
    return config, keys, case(case_id, reports)


def test_v5_architecture_keeps_four_of_five_available_validators_live_in_single_view():
    config, keys, target = _v5_signed_case()
    selector = DistributedRSUExtendedVPUFT(config, keys)
    leader = selector._select_coordinator(target)
    offline = next(validator for validator in config.pbft.validators if validator != leader)
    configured = replace(
        config,
        network=replace(config.network, packet_delivery_ratio=1.0, jitter_ms=0.0),
        pbft=replace(config.pbft, single_view_safety_mode=True, validator_behaviors={offline: "offline"}),
    )

    result = DistributedRSUExtendedVPUFT(configured, keys).run([target], seed=2101)

    assert len(result.consensus) == 1
    assert result.consensus[0].committed
    assert result.consensus[0].view == 0
    assert result.consensus[0].prepare_votes == result.consensus[0].commit_votes == 4
    assert result.decisions[0].committed


def test_v5_architecture_fails_closed_below_four_of_five_without_advancing_view():
    config, keys, target = _v5_signed_case()
    selector = DistributedRSUExtendedVPUFT(config, keys)
    leader = selector._select_coordinator(target)
    offline = [validator for validator in config.pbft.validators if validator != leader][:2]
    configured = replace(
        config,
        network=replace(config.network, packet_delivery_ratio=1.0, jitter_ms=0.0),
        pbft=replace(config.pbft, single_view_safety_mode=True,
                     validator_behaviors={validator: "offline" for validator in offline}),
    )

    result = DistributedRSUExtendedVPUFT(configured, keys).run([target], seed=2101)

    assert len(result.consensus) == 1
    outcome = result.consensus[0]
    assert not outcome.committed
    assert outcome.prepare_votes == 3
    assert outcome.commit_votes == 0
    assert outcome.view == 0
    assert outcome.view_changes == 1
    assert outcome.reason == "single_view_safety_mode_no_verified_transition"
    assert result.decisions[0].new_state.value != "revoked"
    assert result.decisions[0].finalized_at is None
    assert result.ledger_blocks == 0


def test_v5_architecture_guard_blocks_invalid_leader_proposal_but_legacy_advances():
    config, keys, target = _v5_signed_case()
    leader = DistributedRSUExtendedVPUFT(config, keys)._select_coordinator(target)
    network = replace(config.network, packet_delivery_ratio=1.0, jitter_ms=0.0)

    guarded_config = replace(
        config, network=network,
        pbft=replace(config.pbft, single_view_safety_mode=True,
                     validator_behaviors={leader: "propose_invalid"}),
    )
    legacy_config = replace(
        config, network=network,
        pbft=replace(config.pbft, single_view_safety_mode=False,
                     validator_behaviors={leader: "propose_invalid"}),
    )
    guarded = DistributedRSUExtendedVPUFT(guarded_config, keys).run([target], seed=2101)
    legacy = DistributedRSUExtendedVPUFT(legacy_config, keys).run([target], seed=2101)

    assert len(guarded.consensus) == len(legacy.consensus) == 1
    assert not guarded.consensus[0].committed
    assert guarded.consensus[0].view == 0
    assert guarded.consensus[0].invalid_proposal_attempted
    assert guarded.consensus[0].reason == "single_view_safety_mode_no_verified_transition"
    assert legacy.consensus[0].committed and legacy.consensus[0].view == 1
    assert guarded.decisions[0].new_state.value != "revoked"
    assert legacy.decisions[0].new_state.value == "revoked"


def test_v5_coordinator_withholding_known_opposing_evidence_is_not_detected_by_default_profile():
    config, keys, target = _v5_signed_case(opposing=True)
    network = replace(config.network, packet_delivery_ratio=1.0, jitter_ms=0.0)

    class WithholdingCoordinatorArchitecture(DistributedRSUExtendedVPUFT):
        known_by_coordinator = ()
        complete_delivered_case = None

        def subset_case(self, source, attestations):
            received = list(attestations)
            if source.case_id == target.case_id:
                self.known_by_coordinator = tuple(received)
                self.complete_delivered_case = super().subset_case(source, received)
                received = [item for item in received if item.direction != EvidenceDirection.OPPOSES]
            return super().subset_case(source, received)

    configured = replace(config, network=network,
                         pbft=replace(config.pbft, single_view_safety_mode=True))
    architecture = WithholdingCoordinatorArchitecture(configured, keys)
    result = architecture.run([target], seed=2101)

    assert any(item.direction == EvidenceDirection.OPPOSES for item in architecture.known_by_coordinator)
    assert result.decisions[0].metadata["arrived_attestations"] == 5
    assert result.decisions[0].metadata["attempted_attestations"] == 10
    evidence_transfers = [message for message in result.messages
                          if message.message_type == "RSU_EVIDENCE_EXCHANGE"]
    assert len(evidence_transfers) == 8
    assert all(message.delivered_at is not None for message in evidence_transfers)
    assert not architecture.engine.qualify(
        architecture.complete_delivered_case,
        result.decisions[0].metadata["qualification_evaluated_at"],
    ).qualified
    assert result.decisions[0].committed
    assert result.consensus[0].committed and result.consensus[0].commit_votes == 5
    assert not any(message.message_type in {"EVIDENCE_ANNOUNCEMENT", "EVIDENCE_RECONCILIATION"}
                   for message in result.messages)


def test_v5_architecture_offline_evidence_coordinator_fails_before_pbft_and_has_no_takeover():
    config, keys, target = _v5_signed_case()
    leader = DistributedRSUExtendedVPUFT(config, keys)._select_coordinator(target)
    configured = replace(
        config,
        pbft=replace(config.pbft, single_view_safety_mode=True,
                     validator_behaviors={leader: "offline"}),
    )

    result = DistributedRSUExtendedVPUFT(configured, keys).run([target], seed=2101)

    assert result.consensus == []
    assert len(result.decisions) == 1
    assert not result.decisions[0].committed
    assert result.decisions[0].reason == "evidence_coordinator_unavailable_no_safe_takeover"
    assert result.decisions[0].metadata["coordinator_takeover_attempted"] is False


def test_v5_single_view_rejects_concurrent_conflicting_proposals_from_one_byzantine_leader():
    from vpuft.des import Scheduler
    from vpuft.crypto import digest_hex

    config = _coordinator_config()
    config = replace(
        config,
        pbft=replace(config.pbft, single_view_safety_mode=True,
                     validator_behaviors={"rsu-1": "equivocate"}),
    )
    scheduler = Scheduler()
    consensus = PBFTConsensus(
        config.pbft,
        SimulatedTransport(replace(config.network, packet_delivery_ratio=1.0, jitter_ms=0.0),
                           984, scheduler=scheduler),
        KeyRegistry(config.security.deterministic_master_seed),
    )
    outcomes = []
    proposals = ({"decision": "revoke"}, {"decision": "retain"})
    assert digest_hex(proposals[0]) != digest_hex(proposals[1])
    for index, value in enumerate(proposals):
        consensus.finalize_async(
            scheduler=scheduler,
            case_id="integrated-overlap",
            payload=value,
            started_at=0.0,
            preferred_leader="rsu-1",
            case_order_index=index,
            on_complete=lambda outcome, _at, digest=digest_hex(value): outcomes.append((digest, outcome)),
        )
    scheduler.run()

    assert len(outcomes) == 2
    assert sum(outcome.committed for _digest, outcome in outcomes) == 1
    assert [digest for digest, outcome in outcomes if outcome.committed] == [digest_hex(proposals[0])]
    assert all(outcome.view == 0 for _digest, outcome in outcomes)
    assert all(outcome.reason != "committed" or outcome.commit_votes >= 4
               for _digest, outcome in outcomes)


def test_v5_one_equivocating_validator_cannot_supply_a_second_four_of_five_certificate():
    config = _coordinator_config()
    pbft = replace(
        config.pbft,
        single_view_safety_mode=True,
        validator_behaviors={"rsu-5": "equivocate"},
    )
    consensus = PBFTConsensus(
        pbft,
        SimulatedTransport(NetworkConfig(packet_delivery_ratio=1.0, jitter_ms=0.0), 985),
        KeyRegistry(config.security.deterministic_master_seed),
    )

    first = consensus.finalize(case_id="equivocation-case", payload={"decision": "revoke"}, started_at=0.0)
    second = consensus.finalize(case_id="equivocation-case", payload={"decision": "retain"}, started_at=0.1)

    assert first.committed and first.commit_votes == 5 and first.view == 0
    assert not second.committed and second.view == 0
    assert second.prepare_votes == 1
    assert second.reason == "single_view_safety_mode_no_verified_transition"
    assert consensus._vote_locks[("rsu-5", 0, "PREPARE", "equivocation-case")] != \
        consensus._vote_locks[("rsu-1", 0, "PREPARE", "equivocation-case")]
