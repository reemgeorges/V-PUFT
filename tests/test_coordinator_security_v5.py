from dataclasses import replace
from pathlib import Path

from vpuft.architectures import DistributedRSUExtendedVPUFT
from vpuft.config import load_config
from vpuft.crypto import KeyRegistry
from vpuft.consensus import PBFTConsensus
from vpuft.network import SimulatedTransport
from vpuft.config import NetworkConfig

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
