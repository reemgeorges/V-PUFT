from dataclasses import replace
from types import SimpleNamespace
from pathlib import Path

import pytest

from vpuft.config import NetworkConfig, PBFTConfig, ResearchConfig, load_config
from vpuft.architectures.distributed_extension import replica_membership
from vpuft.consensus import PBFTConsensus, SimulatorFinalizationGuard, consensus_vote_payload
from vpuft.crypto import KeyRegistry
from vpuft.des import Scheduler
from vpuft.network import SimulatedTransport
from vpuft.trust_cache import QuorumTrustTokenService
from vpuft.domain import TrustState


V4 = ("rsu-1", "rsu-2", "rsu-3", "rsu-4")
V5 = (*V4, "rsu-5")
REPO_ROOT = Path(__file__).resolve().parents[1]


def make_pbft(config, *, online=None, guard=None, scheduler=None, seed=55):
    network = NetworkConfig(packet_delivery_ratio=1.0, base_latency_ms=1.0, jitter_ms=0.0)
    keys = KeyRegistry()
    return PBFTConsensus(config, SimulatedTransport(network, seed, scheduler=scheduler), keys,
                         online=online, finalization_guard=guard), keys


def test_v4_default_quorum_is_historically_three_of_four():
    config = PBFTConfig(validators=V4, max_byzantine=1)
    config.validate()
    assert config.resolved_quorum == 3
    assert PBFTConsensus(config, SimulatedTransport(NetworkConfig(packet_delivery_ratio=1.0), 1), KeyRegistry()).quorum == 3


def test_v5_accepts_only_explicit_four_of_five_for_f_one():
    config = PBFTConfig(validators=V5, max_byzantine=1, quorum_size=4)
    config.validate()
    assert config.resolved_quorum == 4
    with pytest.raises(ValueError, match="intersection"):
        PBFTConfig(validators=V5, max_byzantine=1, quorum_size=3).validate()


def test_v5_quorum_must_be_available_with_f_unavailable_members():
    with pytest.raises(ValueError, match="availability"):
        PBFTConfig(validators=V5, max_byzantine=1, quorum_size=5).validate()


def test_membership_digest_is_order_independent_but_epoch_bound():
    a = PBFTConfig(validators=V5, max_byzantine=1, quorum_size=4, membership_epoch="epoch-a")
    b = PBFTConfig(validators=tuple(reversed(V5)), max_byzantine=1, quorum_size=4, membership_epoch="epoch-a")
    c = replace(a, membership_epoch="epoch-b")
    assert a.membership_digest == b.membership_digest
    assert a.membership_digest != c.membership_digest


def test_signed_vote_from_an_old_epoch_cannot_be_replayed_as_current_epoch():
    old = PBFTConfig(validators=V5, max_byzantine=1, quorum_size=4, membership_epoch="epoch-a")
    new = replace(old, membership_epoch="epoch-b")
    keys = KeyRegistry()
    old_vote = consensus_vote_payload(old, case_id="case-1", view=0, phase="COMMIT", digest="digest-a")
    new_vote = consensus_vote_payload(new, case_id="case-1", view=0, phase="COMMIT", digest="digest-a")
    signature = keys.sign("rsu-1", old_vote)
    assert keys.verify("rsu-1", old_vote, signature)
    assert not keys.verify("rsu-1", new_vote, signature)


def test_four_of_five_commits_with_one_missing_validator():
    config = PBFTConfig(validators=V5, max_byzantine=1, quorum_size=4,
                        validator_behaviors={"rsu-5": "offline"})
    pbft, _ = make_pbft(config)
    outcome = pbft.finalize(case_id="case-missing", payload={"decision": "revoke"}, started_at=0.0)
    assert outcome.committed and outcome.commit_votes == 4


def test_delayed_fifth_validator_recovers_at_later_view_but_two_unavailable_block_progress():
    config = PBFTConfig(validators=V5, max_byzantine=1, quorum_size=4,
                        validator_behaviors={"rsu-4": "offline"}, timeout_ms=120.0)
    pbft, _ = make_pbft(config, online=lambda node, now: node != "rsu-5" or now >= 0.12)
    outcome = pbft.finalize(case_id="case-delayed", payload={"decision": "revoke"}, started_at=0.0)
    assert outcome.committed and outcome.view >= 1
    unavailable = replace(config, validator_behaviors={"rsu-4": "offline", "rsu-5": "offline"})
    pbft, _ = make_pbft(unavailable)
    failed = pbft.finalize(case_id="case-no-progress", payload={"decision": "revoke"}, started_at=0.0)
    assert not failed.committed and failed.reason == "liveness_failure_after_max_views"


def test_vote_order_does_not_change_v5_commit_validity():
    outcomes = []
    for i, members in enumerate((V5, tuple(reversed(V5)))):
        config = PBFTConfig(validators=members, max_byzantine=1, quorum_size=4)
        pbft, _ = make_pbft(config, seed=70 + i)
        outcomes.append(pbft.finalize(case_id="case-order", payload={"decision": "retain"}, started_at=0.0))
    assert all(outcome.committed and outcome.commit_votes >= 4 for outcome in outcomes)


def test_byzantine_double_sign_cannot_form_two_same_view_v5_certificates_with_shared_vote_state():
    config = PBFTConfig(validators=V5, max_byzantine=1, quorum_size=4, max_views=1,
                        validator_behaviors={"rsu-1": "equivocate"})
    scheduler = Scheduler()
    pbft, _ = make_pbft(config, scheduler=scheduler)
    outcomes = []
    pbft.finalize_async(scheduler=scheduler, case_id="case-equivocate", payload={"decision": "revoke"},
                        started_at=0.0, preferred_leader="rsu-1", on_complete=lambda outcome, _t: outcomes.append(outcome))
    pbft.finalize_async(scheduler=scheduler, case_id="case-equivocate", payload={"decision": "retain"},
                        started_at=0.0, preferred_leader="rsu-1", on_complete=lambda outcome, _t: outcomes.append(outcome))
    scheduler.run()
    assert len(outcomes) == 2
    assert sum(outcome.committed for outcome in outcomes) == 1



def test_v5_config_has_exact_voter_and_sensing_only_roles_and_replica_separation():
    config = load_config(REPO_ROOT / "configs/extension_v5_validator.json")
    config.validate()
    assert config.pbft.validators == V5
    assert config.pbft.resolved_quorum == 4
    assert config.simulation.rsu_count == 8
    assert config.distributed_extension.sensing_only_rsu_ids == ("rsu-6", "rsu-7", "rsu-8")
    assert set(config.pbft.validators).isdisjoint(config.distributed_extension.sensing_only_rsu_ids)
    assert replica_membership(config.pbft.validators, 8, config.distributed_extension.sensing_only_rsu_ids) == V5


def test_v5_domain_mapping_does_not_imply_domain_level_f_one():
    import json
    from collections import Counter
    from pathlib import Path

    placement = json.loads((REPO_ROOT / "results/rsu8_pilot/placement_preregistered.json").read_text(encoding="utf-8"))
    domains = {item["id"]: item["domain"] for item in placement["candidate_rsus"]}
    counts = Counter(domains[validator] for validator in V5)
    assert counts == {"domain-1": 2, "domain-2": 2, "domain-3": 1}
    assert max(counts.values()) > 1


def test_v4_and_v5_can_hold_the_same_coordinator_pool():
    v5 = load_config(REPO_ROOT / "configs/extension_v5_validator.json")
    pool = ("rsu-1", "rsu-2", "rsu-3", "rsu-4")
    v4 = replace(
        ResearchConfig(),
        simulation=replace(ResearchConfig().simulation, rsu_count=8),
        distributed_extension=replace(ResearchConfig().distributed_extension, coordinator_pool=pool),
    )
    v5 = replace(v5, distributed_extension=replace(v5.distributed_extension, coordinator_pool=pool))
    case = SimpleNamespace(case_id="fixed-coordinator", attestations=[
        SimpleNamespace(validator_rsu_id="rsu-5", observed_at=0.0, attestation_id="a"),
        SimpleNamespace(validator_rsu_id="rsu-2", observed_at=1.0, attestation_id="b"),
    ])
    from vpuft.architectures import DistributedRSUExtendedVPUFT
    assert DistributedRSUExtendedVPUFT(v4, KeyRegistry())._select_coordinator(case) == "rsu-2"
    assert DistributedRSUExtendedVPUFT(v5, KeyRegistry())._select_coordinator(case) == "rsu-2"


def test_quorum_token_uses_four_signatures_and_rejects_other_epoch():
    config = load_config(REPO_ROOT / "configs/extension_v5_validator.json")
    keys = KeyRegistry(config.security.deterministic_master_seed)
    service = QuorumTrustTokenService(config, keys)
    token = service.issue(
        subject_pseudonym="subject",
        state=TrustState.TRUSTED,
        issued_at=1.0,
        ttl_seconds=30.0,
        ledger_height=4,
        checkpoint_hash="checkpoint",
        decision_id="decision",
    )
    assert service.quorum == 4 and len(token.signatures) == 4
    assert service.verify(token, now=2.0, minimum_ledger_height=4)
    other_epoch = replace(
        config,
        distributed_extension=replace(config.distributed_extension, membership_epoch="other-epoch"),
    )
    assert not QuorumTrustTokenService(other_epoch, keys).verify(
        token, now=2.0, minimum_ledger_height=4
    )


def test_vote_signature_is_bound_to_membership_not_only_epoch():
    old = PBFTConfig(validators=V5, max_byzantine=1, quorum_size=4, membership_epoch="epoch-a")
    changed_committee = PBFTConfig(validators=V4, max_byzantine=1, quorum_size=3, membership_epoch="epoch-a")
    keys = KeyRegistry()
    old_vote = consensus_vote_payload(old, case_id="case-1", view=0, phase="PREPARE", digest="d")
    changed_vote = consensus_vote_payload(
        changed_committee, case_id="case-1", view=0, phase="PREPARE", digest="d"
    )
    signature = keys.sign("rsu-1", old_vote)
    assert not keys.verify("rsu-1", changed_vote, signature)


def test_direct_pbft_constructor_rejects_unsafe_five_member_quorum():
    unsafe = PBFTConfig(validators=V5, max_byzantine=1, quorum_size=3)
    with pytest.raises(ValueError, match="intersection"):
        make_pbft(unsafe)


def test_finalization_guard_still_rejects_second_conflicting_application_decision():
    guard = SimulatorFinalizationGuard()
    config = PBFTConfig(validators=V5, max_byzantine=1, quorum_size=4)
    left, _ = make_pbft(config, guard=guard, seed=90)
    right, _ = make_pbft(config, guard=guard, seed=91)
    accepted = left.finalize(case_id="case-final", payload={"decision": "revoke"}, started_at=0.0)
    rejected = right.finalize(case_id="case-final", payload={"decision": "retain"}, started_at=0.0)
    assert accepted.committed and not rejected.committed
    assert rejected.reason == "simulator_conflicting_final_outcome_rejected"
