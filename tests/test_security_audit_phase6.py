from dataclasses import replace

import pytest

from vpuft.architectures import DistributedRSUExtendedVPUFT
from vpuft.config import NetworkConfig, PBFTConfig, ResearchConfig
from vpuft.consensus import PBFTConsensus, SimulatorFinalizationGuard
from vpuft.crypto import KeyRegistry, digest_hex
from vpuft.des import Scheduler
from vpuft.domain import AttackType, EvidenceAttestation, EvidenceCase, EvidenceDirection, MobilitySnapshot
from vpuft.evidence import sign_attestation, verify_attestation
from vpuft.network import SimulatedTransport
from vpuft.qualification import VPUFTQualificationEngine
from vpuft.sumo.attacks import AttackInjector, AttackSchedule
from vpuft.sumo.detector import DetectionEngine, RSU



def att(keys, cid, root, source, zone, direction=EvidenceDirection.SUPPORTS, at=1.0):
    item = EvidenceAttestation(f"att-{root}-{source}", cid, root, source, "rsu", source,
        f"domain-{source}", "cam", zone, AttackType.POSITION_OFFSET, direction,
        .99, .99, .99, .99, .99, at, f"evidence-{root}-{source}", "", "")
    return sign_attestation(item, keys, source)


def case(cid, reports=()):
    return EvidenceCase(cid, "veh-1", "ps-1", AttackType.POSITION_OFFSET, 0.0, True, list(reports))


def arch(strategy="first_observer_then_hash", validators=("rsu-1", "rsu-2", "rsu-3", "rsu-4"), behaviors=None):
    cfg = ResearchConfig()
    cfg = replace(cfg, pbft=replace(cfg.pbft, validators=validators, validator_behaviors=behaviors or {}),
        distributed_extension=replace(cfg.distributed_extension, coordinator_strategy=strategy))
    return DistributedRSUExtendedVPUFT(cfg, KeyRegistry())


def make_pbft(seed=1, scheduler=None, keys=None, config=None, finalization_guard=None):
    keys, config = keys or KeyRegistry(), config or PBFTConfig()
    network = NetworkConfig(packet_delivery_ratio=1.0, base_latency_ms=45.0, jitter_ms=10.0)
    transport = SimulatedTransport(network, seed, scheduler=scheduler)
    return PBFTConsensus(config, transport, keys, finalization_guard=finalization_guard), transport


def test_independent_pbft_objects_commit_conflicts_but_have_separate_state():
    keys = KeyRegistry()
    a, _ = make_pbft(101, keys=keys)
    b, _ = make_pbft(202, keys=keys)
    assert a._vote_locks is not b._vote_locks
    left = a.finalize(case_id="same", payload={"decision": "revoke"}, started_at=0)
    right = b.finalize(case_id="same", payload={"decision": "retain"}, started_at=.01)
    assert left.committed and right.committed and left.view == right.view == 0
    assert left.commit_votes >= 3 and right.commit_votes >= 3


def test_repeated_calls_on_shared_pbft_state_commit_conflicts_across_views():
    consensus, _ = make_pbft(303)
    da, db = digest_hex({"decision": "revoke"}), digest_hex({"decision": "retain"})
    first = consensus.finalize(case_id="shared", payload={"decision": "revoke"}, started_at=0)
    second = consensus.finalize(case_id="shared", payload={"decision": "retain"}, started_at=.1)
    assert first.committed and first.view == 0 and first.commit_votes >= 3
    assert second.committed and second.view == 1 and second.commit_votes >= 3
    assert all(consensus._vote_locks[(v, 0, "COMMIT", "shared")] == da for v in consensus.config.validators)
    assert all(consensus._vote_locks[(v, 1, "COMMIT", "shared")] == db for v in consensus.config.validators)


def test_overlapping_delayed_proposals_on_shared_pbft_context_can_both_commit():
    keys, scheduler = KeyRegistry(), Scheduler()
    consensus, _ = make_pbft(404, scheduler, keys=keys)
    outcomes = []
    consensus.finalize_async(scheduler=scheduler, case_id="overlap", payload={"decision": "revoke"}, started_at=0,
        preferred_leader="rsu-1", on_complete=lambda out, _time: outcomes.append(out), case_order_index=0)
    consensus.finalize_async(scheduler=scheduler, case_id="overlap", payload={"decision": "retain"}, started_at=0,
        preferred_leader="rsu-2", on_complete=lambda out, _time: outcomes.append(out), case_order_index=1)
    scheduler.run()
    assert len(outcomes) == 2 and all(out.committed and out.commit_votes >= 3 for out in outcomes)
    assert len({out.view for out in outcomes}) == 2


def test_first_observer_disagrees_on_local_subsets_but_case_hash_agrees():
    first = arch()
    one = case("subset", [att(first.keys, "subset", "r1", "rsu-1", "z1")])
    two = case("subset", [att(first.keys, "subset", "r2", "rsu-2", "z2")])
    assert first._select_coordinator(one) == "rsu-1" and first._select_coordinator(two) == "rsu-2"
    hashed = arch("case_hash")
    h1 = case("subset", [att(hashed.keys, "subset", "r1", "rsu-1", "z1")])
    h2 = case("subset", [att(hashed.keys, "subset", "r2", "rsu-2", "z2")])
    assert hashed._select_coordinator(h1) == hashed._select_coordinator(h2)


def test_case_hash_depends_on_member_order_and_raw_case_id_interpretation():
    fwd = arch("case_hash", ("rsu-1", "rsu-2", "rsu-3", "rsu-4"))
    rev = arch("case_hash", ("rsu-4", "rsu-3", "rsu-2", "rsu-1"))
    assert set(fwd.config.pbft.validators) == set(rev.config.pbft.validators)
    assert fwd._select_coordinator(case("case-a")) == "rsu-3"
    assert rev._select_coordinator(case("case-a")) == "rsu-2"
    assert fwd._select_coordinator(case("case-a:position_offset")) == "rsu-1"


def test_offline_selected_coordinator_is_not_failed_over_before_pbft():
    a = arch(behaviors={"rsu-1": "offline"})
    reports = [att(a.keys, "offline", "r1", "rsu-1", "z1"),
        att(a.keys, "offline", "r2", "rsu-2", "z2", at=1.1)]
    result = a.run([case("offline", reports)], seed=505)
    assert result.decisions[0].metadata["evidence_coordinator"] == "rsu-1"
    assert result.consensus[0].committed and result.consensus[0].view >= 1


def test_offline_coordinator_timeout_does_not_reserve_final_outcome_with_guard_enabled():
    base = ResearchConfig()
    cfg = replace(
        base,
        pbft=replace(base.pbft, validator_behaviors={"rsu-1": "offline"}),
        distributed_extension=replace(base.distributed_extension, simulator_finalization_guard_enabled=True),
    )
    a = DistributedRSUExtendedVPUFT(cfg, KeyRegistry())
    reports = [att(a.keys, "guard-offline", "r1", "rsu-1", "z1"),
        att(a.keys, "guard-offline", "r2", "rsu-2", "z2", at=1.1)]
    result = a.run([case("guard-offline", reports)], seed=812)
    assert result.decisions[0].metadata["evidence_coordinator"] == "rsu-1"
    assert result.consensus[0].committed and result.consensus[0].view >= 1


def test_enabled_guard_preserves_terminal_vehicle_revocation_semantics():
    from test_event_time_scheduler import _config, _window_case

    keys = KeyRegistry()
    base = _config()
    cfg = replace(base, distributed_extension=replace(
        base.distributed_extension, simulator_finalization_guard_enabled=True
    ))
    cases = [_window_case(keys, "guard-terminal", 0, 0.0),
        _window_case(keys, "guard-terminal", 1, 15.0)]
    result = DistributedRSUExtendedVPUFT(cfg, keys).run(cases, 813)
    first, second = result.decisions
    assert first.committed and first.new_state.value == "revoked"
    assert not second.committed and second.previous_state.value == "revoked"
    assert second.new_state.value == "revoked" and second.reason == "already_revoked_terminal_state"
    assert result.ledger_blocks == 1 and len(result.consensus) == 1


def test_omitting_opposition_can_make_incomplete_bundle_qualify_and_pass_recheck():
    keys = KeyRegistry()
    support = [att(keys, "omit", "s1", "rsu-1", "z1"), att(keys, "omit", "s2", "rsu-2", "z2")]
    oppose = [att(keys, "omit", "o1", "rsu-3", "z3", EvidenceDirection.OPPOSES),
        att(keys, "omit", "o2", "rsu-4", "z4", EvidenceDirection.OPPOSES)]
    engine = VPUFTQualificationEngine(ResearchConfig())
    complete = engine.qualify(case("omit", support + oppose), 2)
    partial_case = case("omit", support)
    partial = engine.qualify(partial_case, 2)
    assert all(verify_attestation(item, keys) for item in support + oppose)
    assert not complete.qualified and partial.qualified
    assert digest_hex(partial) == digest_hex(engine.qualify(partial_case, 2))
    # Feed the coordinator's selectively reduced view through the actual architecture path.
    cfg = ResearchConfig()
    cfg = replace(cfg, network=replace(cfg.network, packet_delivery_ratio=1.0))
    run = DistributedRSUExtendedVPUFT(cfg, keys).run([partial_case], seed=606)
    assert run.consensus[0].committed and run.consensus[0].commit_votes >= 3
    assert run.decisions[0].committed
    assert run.decisions[0].metadata["validator_checks_passed"] == 4
    assert run.decisions[0].metadata["arrived_attestations"] == 2


def test_one_supporting_rsu_withholding_causes_no_qualification_and_keeps_root_identity():
    keys = KeyRegistry()
    reports = [att(keys, "withhold", "root-a", "rsu-1", "zone-a"),
        att(keys, "withhold", "root-b", "rsu-2", "zone-b")]
    engine = VPUFTQualificationEngine(ResearchConfig())
    assert engine.qualify(case("withhold", reports), 2).qualified
    assert not engine.qualify(case("withhold", reports[:1]), 2).qualified
    assert reports[0].observation_root_id == "root-a" and verify_attestation(reports[0], keys)


def test_sole_observer_suppression_creates_no_pbft_attempt():
    result = DistributedRSUExtendedVPUFT(ResearchConfig(), KeyRegistry()).run([case("sole")], seed=707)
    assert result.consensus == [] and len(result.decisions) == 1
    assert not result.decisions[0].committed and result.decisions[0].metadata["arrived_attestations"] == 0


def test_network_drop_is_logged_while_suppression_before_send_is_not():
    lost = SimulatedTransport(NetworkConfig(packet_delivery_ratio=0, max_retries=0), seed=8)
    msg = lost.send(message_type="RSU_EVIDENCE_EXCHANGE", sender="rsu-2", receiver="rsu-1",
        case_id="loss", sent_at=1, size_bytes=704)
    silent = SimulatedTransport(NetworkConfig(packet_delivery_ratio=0, max_retries=0), seed=8)
    assert msg.dropped and len(lost.messages) == 1 and silent.messages == []


def test_compromised_rsu_mode_opposes_report_instead_of_suppressing_it():
    cfg = ResearchConfig()
    target = MobilitySnapshot(9, 10, "veh-1", 100, 0, 12, 0, "e1", 100, "e1")
    schedule = AttackSchedule("veh-1", AttackType.POSITION_OFFSET, 0, 30, {"position_offset_m": 80})
    message = AttackInjector(9, [schedule]).generate(target, 10)[0]
    rsu = RSU("rsu-1", 100, 0, "domain-1", .95)
    honest = DetectionEngine(cfg.detector, cfg.security, 9).observe_rsu(message, rsu, 10, target)
    bad_security = replace(cfg.security, compromised_rsus=("rsu-1",))
    bad = DetectionEngine(cfg.detector, bad_security, 9).observe_rsu(message, rsu, 10, target)
    assert honest.direction == EvidenceDirection.SUPPORTS
    assert bad.direction == EvidenceDirection.OPPOSES
    assert bad.reason_codes == ("compromised_rsu_false_attestation",)
    assert bad.observation_root_id == message.observation_root_id


def test_simulator_guard_allows_same_digest_retry_idempotently():
    guard = SimulatorFinalizationGuard()
    first_pbft, _ = make_pbft(801, keys=KeyRegistry(), finalization_guard=guard)
    retry_pbft, _ = make_pbft(802, keys=KeyRegistry(), finalization_guard=guard)
    payload = {"decision": "revoke", "case": "retry", "case_id": " retry "}
    retry_payload = {"decision": "revoke", "case": "retry", "case_id": "retry"}
    first = first_pbft.finalize(case_id="retry", payload=payload, started_at=0)
    retry = retry_pbft.finalize(case_id="retry", payload=retry_payload, started_at=1)
    assert first.committed and retry.committed
    assert retry.reason == "idempotent_same_digest_retry"
    assert guard.accepted_digest("retry") == digest_hex(retry_payload)


def test_simulator_guard_rejects_payload_with_a_different_case_identity():
    guard = SimulatorFinalizationGuard()
    consensus, _ = make_pbft(812, finalization_guard=guard)
    outcome = consensus.finalize(case_id="outer-case", payload={"case_id": "inner-case"}, started_at=0)
    assert not outcome.committed
    assert outcome.reason == "simulator_case_identity_mismatch_rejected"
    assert guard.accepted_digest("outer-case") is None


def test_simulator_guard_rejects_conflicting_digest_same_view_across_objects():
    guard = SimulatorFinalizationGuard()
    a, _ = make_pbft(803, finalization_guard=guard)
    b, _ = make_pbft(804, finalization_guard=guard)
    left = a.finalize(case_id="same-view", payload={"decision": "revoke"}, started_at=0)
    right = b.finalize(case_id="same-view", payload={"decision": "retain"}, started_at=0)
    assert left.committed and not right.committed
    assert right.reason == "simulator_conflicting_final_outcome_rejected"
    assert len(guard.conflicts) == 1


def test_simulator_guard_rejects_cross_view_conflict_but_failed_request_does_not_reserve():
    guard = SimulatorFinalizationGuard()
    consensus, _ = make_pbft(805, finalization_guard=guard)
    first = consensus.finalize(case_id="cross-view", payload={"decision": "revoke"}, started_at=0)
    second = consensus.finalize(case_id="cross-view", payload={"decision": "retain"}, started_at=.1)
    assert first.committed and not second.committed
    assert second.reason == "simulator_conflicting_final_outcome_rejected"

    offline_cfg = replace(PBFTConfig(), validator_behaviors={v: "offline" for v in PBFTConfig().validators})
    failed_pbft, _ = make_pbft(806, config=offline_cfg, finalization_guard=guard)
    failed = failed_pbft.finalize(case_id="recover", payload={"decision": "retain"}, started_at=0)
    recovery_pbft, _ = make_pbft(807, finalization_guard=guard)
    recovered = recovery_pbft.finalize(case_id="recover", payload={"decision": "revoke"}, started_at=1)
    assert not failed.committed and recovered.committed


def test_simulator_guard_serializes_concurrent_conflicts_and_rejects_stale_completion():
    keys, scheduler, guard = KeyRegistry(), Scheduler(), SimulatorFinalizationGuard()
    consensus, _ = make_pbft(808, scheduler, keys, finalization_guard=guard)
    outcomes = []
    consensus.finalize_async(scheduler=scheduler, case_id="race", payload={"decision": "revoke"},
        started_at=0, preferred_leader="rsu-1", on_complete=lambda out, _time: outcomes.append(out))
    consensus.finalize_async(scheduler=scheduler, case_id="race", payload={"decision": "retain"},
        started_at=0, preferred_leader="rsu-2", on_complete=lambda out, _time: outcomes.append(out))
    scheduler.run()
    assert sum(out.committed for out in outcomes) == 1
    assert sorted(out.reason for out in outcomes) == ["committed", "simulator_conflicting_final_outcome_rejected"]
    assert guard.accepted_digest("race") in {
        digest_hex({"decision": "revoke"}), digest_hex({"decision": "retain"})
    }


def test_guard_is_shared_by_separate_pbft_contexts_and_coordinator_failure_can_retry():
    guard = SimulatorFinalizationGuard()
    cfg = replace(PBFTConfig(), validator_behaviors={v: "offline" for v in PBFTConfig().validators})
    failed_pbft, _ = make_pbft(809, config=cfg, finalization_guard=guard)
    timed_out = failed_pbft.finalize(case_id="timeout", payload={"decision": "revoke"}, started_at=0)
    recovered_pbft, _ = make_pbft(810, finalization_guard=guard)
    recovered = recovered_pbft.finalize(case_id="timeout", payload={"decision": "revoke"}, started_at=2)
    conflict_pbft, _ = make_pbft(811, finalization_guard=guard)
    conflict = conflict_pbft.finalize(case_id="timeout", payload={"decision": "retain"}, started_at=3)
    assert not timed_out.committed and recovered.committed and not conflict.committed


def test_canonical_coordinator_ignores_evidence_order_and_validator_tuple_order():
    forward = arch("canonical_case_epoch_hash", ("rsu-1", "rsu-2", "rsu-3", "rsu-4"))
    reverse = arch("canonical_case_epoch_hash", ("rsu-4", "rsu-3", "rsu-2", "rsu-1"))
    items = [att(forward.keys, "canonical", "r1", "rsu-1", "z1"),
        att(forward.keys, "canonical", "r2", "rsu-2", "z2", at=1.1)]
    first = case("canonical", items)
    reversed_case = case("canonical", list(reversed(items)))
    assert forward._select_coordinator(first) == forward._select_coordinator(reversed_case)
    assert forward._select_coordinator(first) == reverse._select_coordinator(first)
    left_view, right_view = case("canonical", items[:1]), case("canonical", items[1:])
    assert forward._select_coordinator(left_view) == forward._select_coordinator(right_view)
    assert forward._select_coordinator(case(" canonical ")) == forward._select_coordinator(case("canonical"))


def test_canonical_coordinator_validates_case_and_membership_epoch():
    cfg = ResearchConfig()
    with pytest.raises(ValueError):
        replace(cfg, distributed_extension=replace(cfg.distributed_extension, coordinator_strategy="canonical_case_epoch_hash", membership_epoch=" ")).validate()
    strategy = "canonical_case_epoch_hash"
    a = replace(cfg, distributed_extension=replace(cfg.distributed_extension, coordinator_strategy=strategy, membership_epoch="epoch-a"))
    b = replace(cfg, distributed_extension=replace(cfg.distributed_extension, coordinator_strategy=strategy, membership_epoch="epoch-b"))
    with pytest.raises(ValueError):
        DistributedRSUExtendedVPUFT(a, KeyRegistry())._select_coordinator(case("  "))
    assert DistributedRSUExtendedVPUFT(a, KeyRegistry())._select_coordinator(case("case-epoch")) != DistributedRSUExtendedVPUFT(b, KeyRegistry())._select_coordinator(case("case-epoch"))
    invalid_members = replace(a, pbft=replace(a.pbft, validators=("rsu-1", 7, "rsu-3", "rsu-4")))
    with pytest.raises(ValueError):
        invalid_members.validate()
